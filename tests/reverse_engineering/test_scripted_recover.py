from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from google.adk.agents import BaseAgent

from arema.registry.errors import InvalidCapabilityDescriptorError
from reverse_engineering.agents.scripted_recover import (
    _ScriptedRecoverGate,
    build_scripted_recover,
)
from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY
from reverse_engineering.tools.deobfuscation.state import (
    CLASSIFICATION_KEY,
    CURRENT_ARTIFACT_KEY,
    FLOSS_COUNT_KEY,
    SCRIPTED_ATTEMPTED_KEY,
    UPX_CHANGED_KEY,
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


def _gate() -> _ScriptedRecoverGate:
    return _ScriptedRecoverGate(
        name="scripted_recover",
        sub_agents=[_FakeWorker(name="packer_analyst")],
        worker="packer_analyst",
    )


def _base_state(**over: object) -> dict[str, object]:
    sha = "a" * 64
    state: dict[str, object] = {
        SAMPLE_FORMAT_KEY: "pe",
        CURRENT_ARTIFACT_KEY: sha,
        CLASSIFICATION_KEY: {
            "artifact_id": sha,
            "deobf_plan": {"upx": False, "floss": False},
            "pcode_preferred": False,
            "obf_class": "packed-other",
            "pre_snapshot": {
                "size": 0,
                "function_count": 0,
                "import_count": 0,
                "string_count": 0,
                "section_count": 0,
            },
        },
        UPX_CHANGED_KEY: False,
        FLOSS_COUNT_KEY: 0,
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


def test_runs_and_marks_attempt_for_native_packed_other_with_budget() -> None:
    events = _run(_base_state())
    assert _ran == ["packer_analyst"]
    # An attempt marker event with the state delta precedes the worker's events.
    deltas = [getattr(getattr(e, "actions", None), "state_delta", {}) for e in events]
    assert any(d.get(SCRIPTED_ATTEMPTED_KEY) is True for d in deltas)


@pytest.mark.parametrize(
    ("over", "why"),
    [
        ({SAMPLE_FORMAT_KEY: "dotnet"}, "managed .NET is the Phase 2 path"),
        ({UPX_CHANGED_KEY: True}, "a cheap tool already unpacked this round"),
        ({FLOSS_COUNT_KEY: 3}, "FLOSS recovered strings this round"),
        ({WORKBENCH_EXEC_COUNT_KEY: WORKBENCH_MAX_EXECUTIONS}, "budget exhausted"),
    ],
)
def test_skips_when_a_precondition_fails(over: dict[str, object], why: str) -> None:
    _run(_base_state(**over))
    assert _ran == [], why


def test_skips_when_not_packed_other() -> None:
    state = _base_state()
    classification = dict(state[CLASSIFICATION_KEY])  # type: ignore[arg-type]
    classification["obf_class"] = "upx"
    state[CLASSIFICATION_KEY] = classification
    _run(state)
    assert _ran == []


def test_skips_safely_on_malformed_classification() -> None:
    state = _base_state()
    state[CLASSIFICATION_KEY] = "not json {"
    _run(state)
    assert _ran == []


def test_build_rejects_worker_not_among_sub_agents() -> None:
    context = SimpleNamespace(
        descriptor=SimpleNamespace(
            name="scripted_recover",
            description="gate",
            metadata={"worker": "does_not_exist"},
        ),
        sub_agents=[_FakeWorker(name="packer_analyst")],
        after_agent=(),
    )
    with pytest.raises(InvalidCapabilityDescriptorError, match="worker"):
        build_scripted_recover(context)  # type: ignore[arg-type]
