"""Unit tests for the jadx function-tool layer: command table + class-name security.

The jadx read commands (``cat``/``find``/``grep`` over an already-decompiled
source tree) build their argv directly. Every agent-supplied value reaches
``kubectl exec`` as a single argv token and is never shell-interpreted; class
names are additionally validated because they become a filesystem path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from arema.core.config import LLMProvider, Settings
from arema.runtime.agent_factory import ToolBuildContext
from arema.runtime.services import RuntimeServices
from arema.runtime.sessions import SessionKeys
from reverse_engineering.tools.jadx import commands, toolset
from reverse_engineering.tools.jadx.commands import JADX_COMMANDS

if TYPE_CHECKING:
    from collections.abc import Iterator

# The seven hostile class-name inputs: traversal, absolute paths, command
# injection, a newline split, and blank/whitespace names. Each must be rejected
# before any argv is built.
_HOSTILE = [
    "../../../../etc/passwd",
    "com.example/../../../etc/shadow",
    "/etc/passwd",
    "com.example.App; cat /etc/passwd",
    "com.example.App\n/etc/passwd",
    "",
    "   ",
]


@pytest.mark.parametrize("bad", _HOSTILE)
def test_class_name_rejected_before_any_command(bad: str) -> None:
    from reverse_engineering.tools.jadx.commands import (
        InvalidClassNameError,
        _source_path_for,
    )

    with pytest.raises(InvalidClassNameError):
        _source_path_for({"out": "/tmp/jadx_x"}, bad)


def test_class_name_maps_to_source_path() -> None:
    from reverse_engineering.tools.jadx.commands import _source_path_for

    assert (
        _source_path_for({"out": "/tmp/jadx_x"}, "com.example.app.Main")
        == "/tmp/jadx_x/sources/com/example/app/Main.java"
    )


def test_nested_class_resolves_to_outer_file() -> None:
    from reverse_engineering.tools.jadx.commands import _source_path_for

    assert (
        _source_path_for({"out": "/tmp/jadx_x"}, "com.x.Outer$Inner")
        == "/tmp/jadx_x/sources/com/x/Outer.java"
    )


def test_search_pattern_is_a_single_argv_token() -> None:
    spec = {s.name: s for s in JADX_COMMANDS}["jadx_search_sources"]
    argv = list(spec.build_argv({"out": "/tmp/jadx_x"}, {"pattern": "foo; rm -rf /"}))
    assert "foo; rm -rf /" in argv and argv[0] == "grep"


def test_only_manifest_and_strings_are_android_only() -> None:
    assert {s.name for s in JADX_COMMANDS if s.android_only} == {
        "jadx_manifest",
        "jadx_strings",
    }


# --- toolset (kubectl-exec wrapper) ------------------------------------------
#
# No real ``kubectl`` runs: ``kubectl_exec`` is monkeypatched on the toolset
# module. Case state is seeded directly (``prepare_jadx`` lands in T5). The
# fake context carries the sandbox case id in ADK-style ``state`` (a ``.get`` /
# ``__setitem__`` proxy, never a dict) so ``resolve_sandbox_case_id`` resolves it.

_CASE = "jadx-case"
# A path inside the sandbox pod, not on the host filesystem.
_OUT = "/tmp/jadx_abc123"


class _FakeState:
    def __init__(self, values: dict[str, str] | None = None) -> None:
        self._values = values or {}

    def get(self, key: str, default: str | None = None) -> str | None:
        return self._values.get(key, default)

    def __setitem__(self, key: str, value: str) -> None:
        self._values[key] = value


class _FakeToolContext:
    def __init__(self, values: dict[str, str] | None = None) -> None:
        self.state = _FakeState(values)


def _context() -> ToolBuildContext:
    settings = Settings(
        _env_file=None, llm_provider=LLMProvider.OLLAMA, sandbox_namespace="test-ns"
    )  # type: ignore[call-arg]
    return ToolBuildContext(
        settings=settings,
        services=RuntimeServices.default(),
        catalog=None,  # type: ignore[arg-type]
    )


def _spec(name: str) -> commands.JadxCommandSpec:
    return next(spec for spec in commands.JADX_COMMANDS if spec.name == name)


@pytest.fixture(autouse=True)
def _prepared_case() -> Iterator[None]:
    toolset._JADX_CASE_STATE[_CASE] = {
        "pod": "jadx-pod-1",
        "out": _OUT,
        "namespace": "test-ns",
        "format": "apk",
    }
    yield
    toolset._JADX_CASE_STATE.clear()


def _run(
    monkeypatch: pytest.MonkeyPatch,
    spec_name: str,
    stdout: str = "output",
    **kwargs: str,
) -> tuple[dict[str, Any], list[str]]:
    captured: list[str] = []

    def _fake_exec(argv: list[str], namespace: str, pod: str, **_kw: Any) -> str:  # noqa: ARG001
        captured.extend(argv)
        return stdout

    monkeypatch.setattr(toolset, "kubectl_exec", _fake_exec)
    tool = toolset.build_jadx_tool(_context(), _spec(spec_name))
    result = tool(_FakeToolContext({SessionKeys.SANDBOX_CASE_ID: _CASE}), **kwargs)
    return result, captured


def test_toolset_descriptor_ids_match_the_command_names() -> None:
    """The descriptor id must equal the tool's runtime name or its policy never binds."""
    descriptors = toolset.build_jadx_toolset()
    assert {d.id for d in descriptors} == {spec.name for spec in commands.JADX_COMMANDS}


def test_manifest_reads_the_decoded_android_manifest(monkeypatch: pytest.MonkeyPatch) -> None:
    result, argv = _run(monkeypatch, "jadx_manifest", stdout="<manifest/>")

    assert result["success"] is True
    assert argv == ["cat", f"{_OUT}/resources/AndroidManifest.xml"]


def test_class_source_maps_a_binary_name_onto_its_path(monkeypatch: pytest.MonkeyPatch) -> None:
    result, argv = _run(
        monkeypatch, "jadx_class_source", stdout="class X {}", class_name="com.example.app.Main"
    )

    assert result["success"] is True
    assert argv == ["cat", f"{_OUT}/sources/com/example/app/Main.java"]


def test_class_source_resolves_a_nested_class_to_its_outer_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """com.x.Outer$Inner lives in Outer.java, not a file of its own."""
    _result, argv = _run(
        monkeypatch, "jadx_class_source", stdout="x", class_name="com.x.Outer$Inner"
    )

    assert argv == ["cat", f"{_OUT}/sources/com/x/Outer.java"]


@pytest.mark.parametrize(
    "hostile",
    [
        "../../../../etc/passwd",
        "com.example/../../../etc/shadow",
        "/etc/passwd",
        "com.example.App; cat /etc/passwd",
        "com.example.App\n/etc/passwd",
        "",
        "   ",
    ],
)
def test_hostile_class_name_runs_no_command(monkeypatch: pytest.MonkeyPatch, hostile: str) -> None:
    """The class name becomes a path, so it is validated rather than sanitised."""
    result, argv = _run(monkeypatch, "jadx_class_source", class_name=hostile)

    assert result["success"] is False
    assert "fully-qualified" in str(result["error"])
    assert argv == [], "no command may run for a rejected class name"


def test_search_passes_the_pattern_as_one_argv_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """A model-supplied regex must never be shell-interpreted."""
    hostile = "foo; rm -rf /"
    _result, argv = _run(monkeypatch, "jadx_search_sources", stdout="hit", pattern=hostile)

    assert hostile in argv, "the pattern is a single argv entry, not a shell string"
    assert argv[0] == "grep"
    assert argv[-1] == f"{_OUT}/sources"


def test_list_classes_narrows_by_package_when_given_one(monkeypatch: pytest.MonkeyPatch) -> None:
    _result, argv = _run(
        monkeypatch, "jadx_list_classes", stdout="a.java", package_filter="com.example"
    )

    assert "-path" in argv
    assert "*com/example*" in argv


def test_list_classes_omits_the_filter_when_not_given(monkeypatch: pytest.MonkeyPatch) -> None:
    _result, argv = _run(monkeypatch, "jadx_list_classes", stdout="a.java", package_filter="")

    assert "-path" not in argv


def test_not_prepared_reports_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(toolset, "kubectl_exec", lambda *_a, **_k: "x")
    toolset._JADX_CASE_STATE.clear()
    tool = toolset.build_jadx_tool(_context(), _spec("jadx_manifest"))

    result = tool(_FakeToolContext({SessionKeys.SANDBOX_CASE_ID: _CASE}))

    assert result["success"] is False
    assert "not prepared" in str(result["error"])


def test_android_only_explains_itself_on_a_jar(monkeypatch: pytest.MonkeyPatch) -> None:
    """A JAR carries no AndroidManifest; say so rather than leaking a cat error."""
    toolset._JADX_CASE_STATE[_CASE]["format"] = "jar"

    def _boom(*_a: Any, **_k: Any) -> str:
        raise RuntimeError("kubectl exec failed (exit 1): No such file or directory")

    monkeypatch.setattr(toolset, "kubectl_exec", _boom)
    tool = toolset.build_jadx_tool(_context(), _spec("jadx_manifest"))

    result = tool(_FakeToolContext({SessionKeys.SANDBOX_CASE_ID: _CASE}))

    assert result["success"] is False
    assert "jar" in str(result["error"])
    assert "Android resources" in str(result["error"])


def test_list_resources_explains_itself_on_a_bare_dex(monkeypatch: pytest.MonkeyPatch) -> None:
    """A bare DEX is code only, so jadx writes no resources/ tree at all.

    An APK and a JAR are both archives and do get one, which is why this tool is
    not ``android_only``. On a DEX the read must explain itself rather than leak
    ``find: '.../resources': No such file or directory`` at the model.
    """
    toolset._JADX_CASE_STATE[_CASE]["format"] = "dex"

    def _boom(*_a: Any, **_k: Any) -> str:
        raise RuntimeError("kubectl exec failed (exit 1): find: No such file or directory")

    monkeypatch.setattr(toolset, "kubectl_exec", _boom)
    tool = toolset.build_jadx_tool(_context(), _spec("jadx_list_resources"))

    result = tool(_FakeToolContext({SessionKeys.SANDBOX_CASE_ID: _CASE}))

    assert result["success"] is False
    assert "dex" in str(result["error"])
    assert "find:" not in str(result["error"])


def test_list_resources_still_runs_on_a_jar(monkeypatch: pytest.MonkeyPatch) -> None:
    """The DEX stand-down must not regress the JAR case: a JAR has META-INF."""
    toolset._JADX_CASE_STATE[_CASE]["format"] = "jar"
    result, argv = _run(monkeypatch, "jadx_list_resources", stdout=f"{_OUT}/resources/META-INF\n")

    assert result["success"] is True
    assert argv[0] == "find"


def test_only_list_resources_reads_the_resources_tree_by_flag() -> None:
    """manifest/strings already stand down via android_only; only this one needs it."""
    assert {s.name for s in JADX_COMMANDS if s.reads_resources} == {"jadx_list_resources"}


def test_empty_output_is_degraded(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _argv = _run(monkeypatch, "jadx_manifest", stdout="   \n")

    assert result["success"] is False
    assert result["degraded"] is True


def test_tool_failure_degrades_instead_of_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: Any, **_k: Any) -> str:
        raise RuntimeError("pod is gone")

    monkeypatch.setattr(toolset, "kubectl_exec", _boom)
    tool = toolset.build_jadx_tool(_context(), _spec("jadx_search_sources"))

    result = tool(_FakeToolContext({SessionKeys.SANDBOX_CASE_ID: _CASE}), pattern="x")

    assert result["success"] is False
    assert "pod is gone" in str(result["error"])


def test_tools_expose_their_parameters_to_adk(monkeypatch: pytest.MonkeyPatch) -> None:
    """ADK builds the schema from the signature; a bare **kwargs would expose none."""
    monkeypatch.setattr(toolset, "kubectl_exec", lambda *_a, **_k: "x")
    import inspect

    tool = toolset.build_jadx_tool(_context(), _spec("jadx_class_source"))
    parameters = inspect.signature(tool).parameters

    assert "tool_context" in parameters
    assert "class_name" in parameters
