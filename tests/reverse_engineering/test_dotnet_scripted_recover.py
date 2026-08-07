from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from google.adk.agents import BaseAgent

from arema.registry.errors import InvalidCapabilityDescriptorError
from reverse_engineering.agents.dotnet_scripted_recover import (
    _DotnetScriptedRecoverGate,
    build_dotnet_scripted_recover,
)
from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY
from reverse_engineering.tools.deobfuscation.state import (
    CURRENT_ARTIFACT_KEY,
    DE4DOT_RESULT_KEY,
    DNLIB_ROUNDTRIP_RESULT_KEY,
    DOTNET_DEEP_ATTEMPTED_KEY,
    SCRIPTED_ATTEMPTED_KEY,
)
from reverse_engineering.tools.workbench.state import (
    WORKBENCH_EXEC_COUNT_KEY,
    WORKBENCH_MAX_EXECUTIONS,
)

_ran: list[str] = []


class _FakeWorker(BaseAgent):
    async def run_async(self, _parent_context: object):  # type: ignore[override]
        _ran.append(self.name)
        yield SimpleNamespace(author=self.name)


def _gate() -> _DotnetScriptedRecoverGate:
    return _DotnetScriptedRecoverGate(
        name="dotnet_scripted_recover",
        sub_agents=[_FakeWorker(name="dotnet_analyst")],
        worker="dotnet_analyst",
    )


def _base_state(**over: object) -> dict[str, object]:
    sha = "a" * 64
    state: dict[str, object] = {
        SAMPLE_FORMAT_KEY: "dotnet",
        CURRENT_ARTIFACT_KEY: sha,
        DE4DOT_RESULT_KEY: {
            "success": True,
            "applicable": True,
            "degraded": True,
            "changed": False,
            "error_code": "de4dot_failed",
            "error": "de4dot could not process the assembly.",
            "tool_version": "de4dot-cex-4.0.0",
        },
        WORKBENCH_EXEC_COUNT_KEY: 0,
    }
    state.update(over)
    return state


def _run(state: dict[str, object]) -> list[object]:
    _ran.clear()
    ctx = SimpleNamespace(
        session=SimpleNamespace(state=state),
        invocation_id="inv-1",
        branch=None,
    )

    async def collect() -> list[object]:
        return [event async for event in _gate()._run_async_impl(ctx)]  # type: ignore[arg-type]

    return asyncio.run(collect())


def test_runs_for_unrecovered_dotnet_within_budget() -> None:
    events = _run(_base_state())
    assert _ran == ["dotnet_analyst"]
    # An attempt marker event with the state delta precedes the worker's events; it
    # sets the shared scripted marker and records THIS layer's artifact id as the
    # per-layer deep-pass marker.
    deltas = [getattr(getattr(e, "actions", None), "state_delta", {}) for e in events]
    assert any(d.get(SCRIPTED_ATTEMPTED_KEY) is True for d in deltas)
    assert any(d.get(DOTNET_DEEP_ATTEMPTED_KEY) == "a" * 64 for d in deltas)


def test_skips_when_de4dot_recovered() -> None:
    _run(
        _base_state(
            **{
                DE4DOT_RESULT_KEY: {
                    "success": True,
                    "applicable": True,
                    "degraded": False,
                    "changed": True,
                    "error_code": None,
                    "error": None,
                    "tool_version": "de4dot-cex-4.0.0",
                }
            }
        )
    )
    assert _ran == []


def test_runs_after_dnlib_roundtrip_to_go_deeper() -> None:
    # The dnlib round-trip only makes the assembly LOADABLE; the deep agent must
    # STILL run on that loadable artifact to unpack compressor layers, reverse
    # string encryption, and deobfuscate further -- a round-trip must NOT skip it.
    _run(
        _base_state(
            **{
                DNLIB_ROUNDTRIP_RESULT_KEY: {
                    "success": True,
                    "applicable": True,
                    "degraded": False,
                    "changed": True,
                    "method": "dnlib_metadata_roundtrip",
                    "tool_version": "dnlib-4.4.0",
                }
            }
        )
    )
    assert _ran == ["dotnet_analyst"]


def test_skips_when_deep_pass_already_attempted_on_this_layer() -> None:
    # Per-layer marker: the deep pass does not re-run on the SAME artifact it already
    # attempted (marker == current artifact), so a later loop iteration with no new
    # inner layer does not re-run the expensive agent.
    _run(_base_state(**{DOTNET_DEEP_ATTEMPTED_KEY: "a" * 64}))
    assert _ran == []


def test_reruns_on_a_new_inner_layer() -> None:
    # After an earlier pass registered a recovered inner layer, CURRENT_ARTIFACT
    # advances, so the marker (an OLD artifact id) no longer matches the current one
    # and the deep pass re-runs on the new layer -- multi-layer recovery.
    _run(_base_state(**{DOTNET_DEEP_ATTEMPTED_KEY: "b" * 64}))
    assert _ran == ["dotnet_analyst"]


def test_skips_for_native_format() -> None:
    _run(_base_state(**{SAMPLE_FORMAT_KEY: "pe"}))
    assert _ran == []


def test_skips_when_budget_exhausted() -> None:
    _run(_base_state(**{WORKBENCH_EXEC_COUNT_KEY: WORKBENCH_MAX_EXECUTIONS}))
    assert _ran == []


def test_build_rejects_unknown_worker() -> None:
    context = SimpleNamespace(
        descriptor=SimpleNamespace(
            name="dotnet_scripted_recover",
            description="gate",
            metadata={"worker": "does_not_exist"},
        ),
        sub_agents=[_FakeWorker(name="dotnet_analyst")],
        after_agent=(),
    )
    with pytest.raises(InvalidCapabilityDescriptorError, match="worker"):
        build_dotnet_scripted_recover(context)  # type: ignore[arg-type]
