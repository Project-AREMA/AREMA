"""The jadx read-only command table over an already-decompiled source tree.

``prepare_jadx`` runs the one expensive step -- ``jadx -d <out> <artifact>`` --
and everything here reads the result with ordinary file commands. That is why the
specs build argv directly instead of driving off ghidra's ``arg_template``: these
are ``cat``/``find``/``grep`` invocations over a directory, not
``<binary> <subcommand> <target>`` calls.

jadx opens ``.apk``/``.dex``/``.jar`` itself, so no unzip step precedes it. On a
real APK it decodes the binary ``AndroidManifest.xml`` back to readable XML and
writes ``sources/`` (decompiled Java, laid out by package) beside ``resources/``.
The manifest and string-table tools are therefore APK-only; on a JAR or bare DEX
those paths do not exist and the tool reports that rather than inventing an
answer. ``jadx_list_resources`` is not APK-only: jadx writes a ``resources/``
tree for a JAR too (its META-INF entries), so the listing is meaningful for every
container.

Agent-supplied values reach ``kubectl exec`` as single argv tokens and are never
shell-interpreted. Class names are additionally validated by
:func:`_source_path_for` because they are turned into a filesystem path -- a
rejected name raises :class:`InvalidClassNameError` before any argv is built.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from arema.registry.descriptors import OutputPolicy

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

# A fully-qualified Java class name: dot-separated identifiers, each starting
# with a letter/underscore/``$``. ``\Z`` (not ``$``) anchors the very end of the
# string so a trailing-newline injection cannot slip past. Anything with a path
# separator, whitespace, shell metacharacter, or an empty segment is rejected.
_CLASS_NAME_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*\Z")

# grep answers "no match" with exit 1; that is a result, not a failure.
_GREP_OK_EXIT_CODES = (0, 1)


class InvalidClassNameError(ValueError):
    """Raised when a class name is not a safe fully-qualified Java name."""


def _source_path_for(case_state: Mapping[str, str], class_name: str) -> str:
    """Map a fully-qualified class name to its decompiled ``.java`` path.

    Validates ``class_name`` against :data:`_CLASS_NAME_RE` before building any
    path, so a hostile value (traversal, absolute path, injection, newline, or
    blank) raises :class:`InvalidClassNameError` and never reaches ``kubectl
    exec``. A nested class (``Outer$Inner``) resolves to its outer source file.
    """
    candidate = class_name.strip()
    if not _CLASS_NAME_RE.match(candidate):
        raise InvalidClassNameError(
            f"'{class_name}' is not a fully-qualified Java class name "
            "(expected e.g. com.example.app.MainActivity)"
        )
    relative = candidate.replace(".", "/").split("$", 1)[0]
    return f"{case_state['out']}/sources/{relative}.java"


@dataclass(frozen=True, slots=True)
class JadxCommandSpec:
    """One read-only command over the decompiled tree, wrapped as a function tool.

    ``params`` names the tool's keyword parameters as the model sees them.
    ``build_argv`` receives the case state (pod, output dir) and the model's
    arguments, and returns the exact argv list -- every element a single token.
    """

    name: str
    description: str
    params: tuple[str, ...]
    build_argv: Callable[[Mapping[str, str], Mapping[str, str]], Sequence[str]]
    output_policy: OutputPolicy
    ok_exit_codes: tuple[int, ...] = (0,)
    # Paths that exist only for an APK (the manifest and the string table); used
    # to explain the failed read instead of leaking a raw ``cat`` error.
    android_only: bool = False
    # Reads the decompiled ``resources/`` tree. An APK and a JAR both get one, but
    # a bare DEX is code only and jadx writes no resources dir at all -- without
    # this the read leaks a raw ``find: ... No such file or directory``.
    reads_resources: bool = False


def _sources(case: Mapping[str, str]) -> str:
    return f"{case['out']}/sources"


def _resources(case: Mapping[str, str]) -> str:
    return f"{case['out']}/resources"


JADX_COMMANDS: tuple[JadxCommandSpec, ...] = (
    JadxCommandSpec(
        name="jadx_manifest",
        description=(
            "Read the decoded AndroidManifest.xml: package name, permissions, "
            "exported components, minSdk/targetSdk, and flags such as debuggable "
            "and usesCleartextTraffic. APK samples only."
        ),
        params=(),
        build_argv=lambda case, _kw: ["cat", f"{_resources(case)}/AndroidManifest.xml"],
        output_policy=OutputPolicy(max_chars=10_000),
        android_only=True,
    ),
    JadxCommandSpec(
        name="jadx_list_classes",
        description=(
            "List decompiled classes. Pass a package fragment (e.g. 'com.example') "
            "to narrow the listing; omit it to see everything."
        ),
        params=("package_filter",),
        build_argv=lambda case, kw: [
            "find",
            _sources(case),
            "-type",
            "f",
            "-name",
            "*.java",
            *(
                ["-path", f"*{kw['package_filter'].replace('.', '/')}*"]
                if kw.get("package_filter")
                else []
            ),
        ],
        output_policy=OutputPolicy(max_chars=8_000, max_list_items=60),
    ),
    JadxCommandSpec(
        name="jadx_class_source",
        description=(
            "Read the decompiled Java of one class by fully-qualified name "
            "(e.g. com.example.app.MainActivity). This is the main way to read code."
        ),
        params=("class_name",),
        build_argv=lambda _case, kw: ["cat", kw["_source_path"]],
        output_policy=OutputPolicy(max_chars=12_000),
    ),
    JadxCommandSpec(
        name="jadx_search_sources",
        description=(
            "Regex-search the decompiled Java across every class in one call. Use it "
            "for URLs, crypto calls, reflection, Runtime.exec, native loads, or any "
            "cross-cutting pattern. This is the power tool; prefer it over reading "
            "classes one by one."
        ),
        params=("pattern",),
        build_argv=lambda case, kw: [
            "grep",
            "-rnE",
            "--include=*.java",
            "-m",
            "5",
            "--",
            kw["pattern"],
            _sources(case),
        ],
        output_policy=OutputPolicy(max_chars=10_000, max_list_items=40),
        ok_exit_codes=_GREP_OK_EXIT_CODES,
    ),
    JadxCommandSpec(
        name="jadx_strings",
        description=(
            "Read the app's string resources (res/values/strings.xml): labels, URLs "
            "and endpoints often live here rather than in code. APK samples only."
        ),
        params=(),
        build_argv=lambda case, _kw: [
            "cat",
            f"{_resources(case)}/res/values/strings.xml",
        ],
        output_policy=OutputPolicy(max_chars=8_000),
        android_only=True,
    ),
    JadxCommandSpec(
        name="jadx_list_resources",
        description=(
            "List the non-code files bundled with the sample. Useful for spotting "
            "embedded payloads, native .so libraries, or unexpected assets. Works "
            "for any packaged container: on an APK this is res/ and assets/, on a "
            "JAR the META-INF entries. A bare DEX carries no resources."
        ),
        params=(),
        build_argv=lambda case, _kw: ["find", _resources(case), "-type", "f"],
        output_policy=OutputPolicy(max_chars=6_000, max_list_items=60),
        reads_resources=True,
    ),
)
