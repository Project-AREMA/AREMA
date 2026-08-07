#!/usr/bin/env python3
"""Live smoke test for the .NET/ILSpy route, with no model in the loop.

Exercises the production path end to end against a real cluster: ingest and
format detection, pool map, pod claim, ``kubectl cp``, port-forward, MCP
handshake, a real decompiler call, and teardown. Keeping the LLM out means a
failure here is unambiguously plumbing rather than prompting, which is what makes
it worth running before touching prompts.

Also checks the two-engine case: radare2 on :8765 and ILSpy on :3001 forwarded
under ONE case id. That combination is what the ``(case, port)`` port-forward key
exists for; keyed by case id alone the second engine's tunnel is silently dropped
and every one of its tool calls fails with nothing logged.

Usage:
    make smoke-ilspy SAMPLE=/path/to/assembly.dll

Any .NET assembly works (a .dll out of a NuGet package, or `dotnet build`
output). Requires a reachable cluster with the radare2-mcp and ilspy-mcp warm
pools up (`make sandbox-up`) and AREMA_SANDBOX_ENABLED=true.

Exits 0 on success, 1 on any failed check.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from arema.composition import build_sandbox_executor  # noqa: E402
from arema.core.config import get_settings  # noqa: E402
from arema.runtime.agent_factory import ToolBuildContext  # noqa: E402
from arema.runtime.services import RuntimeServices  # noqa: E402
from reverse_engineering.runtime.portforward import default_registry  # noqa: E402
from reverse_engineering.runtime.sandbox_session import release_case  # noqa: E402
from reverse_engineering.tools.acquire_sample import acquire_sample  # noqa: E402
from reverse_engineering.tools.prepare_ilspy import build_prepare_ilspy  # noqa: E402
from reverse_engineering.tools.prepare_sandbox import build_prepare_sandbox  # noqa: E402

CASE_ID = "smoke-ilspy"
ILSPY_URL = "http://127.0.0.1:3001/mcp"
R2_PORT = 8765
ILSPY_PORT = 3001


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


def _rpc(payload: dict[str, object], session: str | None = None) -> tuple[dict[str, object], str]:
    """One JSON-RPC message to the ILSpy MCP endpoint over streamable HTTP.

    A payload carrying no ``id`` is a notification: the server acknowledges it
    with 202 and an empty body, so there is nothing to parse and an empty result
    is returned rather than treated as a protocol error.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session:
        headers["Mcp-Session-Id"] = session
    request = urllib.request.Request(  # noqa: S310 - hardcoded localhost URL
        ILSPY_URL, data=json.dumps(payload).encode(), headers=headers, method="POST"
    )
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
        body = response.read().decode()
        returned_session = response.headers.get("Mcp-Session-Id") or ""
    for line in body.splitlines():
        stripped = line.removeprefix("data: ").strip()
        if stripped.startswith("{"):
            return json.loads(stripped), returned_session
    if "id" not in payload:
        return {}, returned_session
    raise RuntimeError(f"no JSON-RPC payload in response: {body[:200]}")


def _tool_context(executor: object) -> ToolBuildContext:
    settings = get_settings()
    services = RuntimeServices.default()
    return ToolBuildContext(
        settings=settings,
        services=RuntimeServices(
            clock=services.clock,
            metrics=services.metrics,
            memory_sink=services.memory_sink,
            sandbox=executor,  # type: ignore[arg-type]
        ),
        catalog=None,  # type: ignore[arg-type]
    )


def _reachable(port: int) -> bool:
    """Any HTTP answer proves the application layer is up (LESSONS_LEARNED #3)."""
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/mcp", timeout=5)
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False
    return True


def _check_prerequisites() -> list[str]:
    settings = get_settings()
    problems: list[str] = []
    if not settings.sandbox_enabled:
        problems.append("AREMA_SANDBOX_ENABLED is false; set it to true")
    for pool in ("radare2-mcp", "ilspy-mcp"):
        if pool not in settings.sandbox_pool_map:
            problems.append(f"AREMA_SANDBOX_POOL_MAP has no '{pool}' entry")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: ilspy_route.py <path-to-dotnet-assembly>", file=sys.stderr)
        print("hint:  make smoke-ilspy SAMPLE=/path/to/assembly.dll", file=sys.stderr)
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
    check(
        "format detected as dotnet",
        ingested["format"] == "dotnet",
        f"got '{ingested['format']}' for {Path(argv[1]).name}",
    )
    if ingested["format"] != "dotnet":
        print("\nsample is not a .NET assembly; nothing further to check", file=sys.stderr)
        return 1

    artifact_id = str(ingested["artifact_id"])
    executor = build_sandbox_executor(get_settings())
    context = _tool_context(executor)

    try:
        prepared = build_prepare_ilspy(context)(artifact_id, _ToolContext())
        check(
            "prepare_ilspy claimed a pod and opened the tunnel",
            bool(prepared["ready"]),
            str(prepared.get("error") or prepared["pod"]),
        )
        if not prepared["ready"]:
            return 1

        check(
            "assembly staged with the required .dll suffix",
            str(prepared["assembly_path"]).endswith(".dll"),
            str(prepared["assembly_path"]),
        )

        initialize, session = _rpc(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "arema-smoke", "version": "0"},
                },
            }
        )
        server = initialize.get("result", {}).get("serverInfo", {})  # type: ignore[union-attr]
        check("MCP initialize handshake", bool(server), json.dumps(server))
        _rpc({"jsonrpc": "2.0", "method": "notifications/initialized"}, session)

        listed, _ = _rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, session)
        tools = listed.get("result", {}).get("tools", [])  # type: ignore[union-attr]
        check("tools/list returns the ILSpy surface", len(tools) >= 20, f"{len(tools)} tools")

        analysis, _ = _rpc(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "analyze_assembly",
                    "arguments": {"assemblyPath": prepared["assembly_path"]},
                },
            },
            session,
        )
        result = analysis.get("result", {})  # type: ignore[union-attr]
        text = "".join(part.get("text", "") for part in result.get("content", []))
        check(
            "analyze_assembly returned real decompiler output",
            not result.get("isError") and "Total Types" in text,
            text.strip().splitlines()[0] if text.strip() else "empty",
        )

        # The two-engine case: r2 and ILSpy forwarded under one case id.
        r2_prepared = build_prepare_sandbox(context)(artifact_id, _ToolContext())
        check(
            "prepare_sandbox claimed the radare2 pod",
            bool(r2_prepared["ready"]),
            str(r2_prepared.get("error") or r2_prepared["pod"]),
        )
        check(
            "both engines reachable under one case id",
            _reachable(R2_PORT) and _reachable(ILSPY_PORT),
            f"r2 :{R2_PORT}={_reachable(R2_PORT)} ilspy :{ILSPY_PORT}={_reachable(ILSPY_PORT)}",
        )
    finally:
        release_case(CASE_ID)
        check(
            "release_case tore down every forward for the case",
            not default_registry().has(CASE_ID),
        )

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s): {', '.join(failures)}", file=sys.stderr)
        return 1
    print("All ILSpy route checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
