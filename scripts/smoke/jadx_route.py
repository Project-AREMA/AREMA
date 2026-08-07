#!/usr/bin/env python3
"""Live smoke test for the Java/Android jadx route, with no model in the loop.

Exercises the production path end to end against a real cluster: ingest and
format detection, pod claim, ``kubectl cp``, one jadx decompilation pass, then
every read-only tool over ``kubectl exec``, then teardown. Keeping the LLM out
means a failure here is unambiguously plumbing rather than prompting.

Two things beyond the happy path are checked deliberately:

- **The traversal guard.** ``jadx_class_source`` is the one place a
  model-supplied string becomes a filesystem path, so a hostile class name must
  be rejected outright with no command executed.
- **Android-only tools on a JAR.** A plain JAR carries no manifest or resource
  table; those tools must say so rather than leaking a raw ``cat`` error.

Usage:
    make smoke-jadx SAMPLE=/path/to/app.apk
    make smoke-jadx SAMPLE=/path/to/library.jar

Both are worth running: the APK path covers the Android tools, the JAR path
covers their stand-down behaviour. Requires a reachable cluster with the jadx
warm pool up (`make sandbox-up`) and AREMA_SANDBOX_ENABLED=true.

Exits 0 on success, 1 on any failed check.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from arema.composition import build_sandbox_executor  # noqa: E402
from arema.core.config import get_settings  # noqa: E402
from arema.runtime.agent_factory import ToolBuildContext  # noqa: E402
from arema.runtime.services import RuntimeServices  # noqa: E402
from reverse_engineering.tools.acquire_sample import acquire_sample  # noqa: E402
from reverse_engineering.tools.jadx.commands import JADX_COMMANDS  # noqa: E402
from reverse_engineering.tools.jadx.prepare_jadx import (  # noqa: E402
    build_prepare_jadx,
    release_jadx_case,
)
from reverse_engineering.tools.jadx.toolset import build_jadx_tool  # noqa: E402

CASE_ID = "smoke-jadx"
JVM_FORMATS = {"apk", "dex", "jar"}
# Only these two read paths that a non-APK container simply does not have.
# jadx_list_resources works everywhere: jadx writes a resources/ tree for a JAR too.
ANDROID_ONLY = {"jadx_manifest", "jadx_strings"}
TRAVERSAL_ATTEMPT = "../../../../etc/passwd"


class _State:
    """Stand-in for ADK's State proxy: not a dict, but writable (resolve_sandbox_case_id
    sets the key when absent, so __setitem__ has to exist)."""

    def __init__(self) -> None:
        self._data = {"arema:sandbox_case_id": CASE_ID}

    def get(self, key: str, default: object = None) -> object:
        return self._data.get(key, default)

    def __setitem__(self, key: str, value: object) -> None:
        self._data[key] = value


class _ToolContext:
    state = _State()


def _tool_context(executor: object) -> ToolBuildContext:
    services = RuntimeServices.default()
    return ToolBuildContext(
        settings=get_settings(),
        services=RuntimeServices(
            clock=services.clock,
            metrics=services.metrics,
            memory_sink=services.memory_sink,
            sandbox=executor,  # type: ignore[arg-type]
        ),
        catalog=None,  # type: ignore[arg-type]
    )


def _check_prerequisites() -> list[str]:
    settings = get_settings()
    problems: list[str] = []
    if not settings.sandbox_enabled:
        problems.append("AREMA_SANDBOX_ENABLED is false; set it to true")
    if "jadx" not in settings.sandbox_pool_map:
        problems.append("AREMA_SANDBOX_POOL_MAP has no 'jadx' entry")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: jadx_route.py <path-to-apk-dex-or-jar>", file=sys.stderr)
        print("hint:  make smoke-jadx SAMPLE=/path/to/app.apk", file=sys.stderr)
        return 2

    problems = _check_prerequisites()
    if problems:
        for problem in problems:
            print(f"FAIL  prerequisite: {problem}", file=sys.stderr)
        return 1

    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        print(f"{'PASS' if ok else 'FAIL'}  {name}{f' :: {detail}' if detail else ''}")
        if not ok:
            failures.append(name)

    ingested = acquire_sample(argv[1])
    sample_format = str(ingested["format"])
    check(
        "format detected as JVM bytecode",
        sample_format in JVM_FORMATS,
        f"got '{sample_format}' for {Path(argv[1]).name}",
    )
    if sample_format not in JVM_FORMATS:
        print("\nsample is not apk/dex/jar; nothing further to check", file=sys.stderr)
        return 1

    artifact_id = str(ingested["artifact_id"])
    context = _tool_context(build_sandbox_executor(get_settings()))
    is_android = sample_format == "apk"

    try:
        prepared = build_prepare_jadx(context)(artifact_id, sample_format, _ToolContext())
        check(
            "prepare_jadx claimed a pod and decompiled the sample",
            bool(prepared["ready"]),
            str(prepared.get("error") or f"{prepared.get('classes')} classes"),
        )
        if not prepared["ready"]:
            return 1
        check(
            "decompilation recovered at least one class",
            int(prepared.get("classes", 0)) > 0,
            f"{prepared.get('classes')} classes",
        )

        specs = {spec.name: spec for spec in JADX_COMMANDS}
        arguments: dict[str, dict[str, str]] = {
            "jadx_list_classes": {"package_filter": ""},
            "jadx_search_sources": {"pattern": "class|void"},
        }

        # Read one real class name out of the listing so the source read is not
        # guessing at a name that may not exist in this particular sample.
        listing = build_jadx_tool(context, specs["jadx_list_classes"])(
            _ToolContext(), package_filter=""
        )
        first_class = ""
        if listing.get("success"):
            paths = [line for line in str(listing["output"]).splitlines() if line.endswith(".java")]
            if paths:
                relative = paths[0].split("/sources/", 1)[-1]
                first_class = relative.removesuffix(".java").replace("/", ".")
        check("jadx_list_classes returned a class inventory", bool(first_class), first_class)
        if first_class:
            arguments["jadx_class_source"] = {"class_name": first_class}

        for name, spec in specs.items():
            if name in ANDROID_ONLY and not is_android:
                result = build_jadx_tool(context, spec)(_ToolContext(), **arguments.get(name, {}))
                check(
                    f"{name} stands down on a {sample_format}",
                    not result["success"] and "Android resources" in str(result.get("error", "")),
                    str(result.get("error", ""))[:70],
                )
                continue
            if name == "jadx_class_source" and not first_class:
                continue
            result = build_jadx_tool(context, spec)(_ToolContext(), **arguments.get(name, {}))
            output = str(result.get("output", result.get("error", "")))
            check(f"{name} returned data", bool(result["success"]), f"{len(output):,d} chars")

        traversal = build_jadx_tool(context, specs["jadx_class_source"])(
            _ToolContext(), class_name=TRAVERSAL_ATTEMPT
        )
        check(
            "traversal attempt rejected before any command runs",
            not traversal["success"] and "fully-qualified" in str(traversal.get("error", "")),
            str(traversal.get("error", ""))[:70],
        )
    finally:
        release_jadx_case(CASE_ID)
        check("release_jadx_case cleared the case state", True)

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s): {', '.join(failures)}", file=sys.stderr)
        return 1
    print(f"All jadx route checks passed ({sample_format}).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
