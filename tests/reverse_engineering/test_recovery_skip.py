"""The recovery_skip agent emits an empty complete recovery envelope for JVM samples."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from reverse_engineering.agents.recovery_skip import (
    RECOVERY_SKIP_DESCRIPTOR,
    _RecoverySkip,
    build_recovery_skip,
)
from reverse_engineering.tools.deobfuscation.state import (
    CURRENT_ARTIFACT_KEY,
    RECOVERY_EVIDENCE_KEY,
)

_SHA = "b" * 64


def _run(state: dict[str, object]) -> list[object]:
    ctx = SimpleNamespace(
        session=SimpleNamespace(state=state),
        invocation_id="inv-1",
        branch=None,
    )

    async def collect() -> list[object]:
        agent = _RecoverySkip(name="recovery_skip")
        return [event async for event in agent._run_async_impl(ctx)]  # type: ignore[arg-type]

    return asyncio.run(collect())


def _deltas(events: list[object]) -> list[dict[str, object]]:
    return [getattr(getattr(e, "actions", None), "state_delta", {}) for e in events]


def test_emits_empty_complete_recovery_envelope() -> None:
    events = _run({CURRENT_ARTIFACT_KEY: _SHA})
    deltas = _deltas(events)
    envelope = next(d[RECOVERY_EVIDENCE_KEY] for d in deltas if RECOVERY_EVIDENCE_KEY in d)
    assert envelope["artifact_id"] == _SHA
    assert envelope["coverage"]["status"] == "complete"
    assert envelope["coverage"]["surfaces"] == []
    assert envelope["coverage"]["limitations"] == []
    assert envelope["findings"] == []


def test_emits_nothing_without_a_current_artifact() -> None:
    # No CURRENT_ARTIFACT_KEY -> nothing emitted; the critic tolerates the absence.
    assert _run({}) == []


def test_emits_nothing_for_a_malformed_artifact_id() -> None:
    # A non-SHA-256 id cannot build a valid envelope; emit nothing, never crash.
    assert _run({CURRENT_ARTIFACT_KEY: "not-a-sha"}) == []


def test_descriptor_is_a_deterministic_leaf() -> None:
    d = RECOVERY_SKIP_DESCRIPTOR
    assert d.id == d.name == "recovery_skip"
    assert d.factory is build_recovery_skip
    assert d.prompt_id is None
    assert d.sub_agent_ids == ()
    assert d.tool_ids == ()
    assert d.mcp_server_ids == ()
