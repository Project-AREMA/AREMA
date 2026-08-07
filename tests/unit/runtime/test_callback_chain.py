"""Ordering and construction tests for the neutral runtime callback chain."""

from __future__ import annotations

import asyncio
import dataclasses
import json
from types import SimpleNamespace
from typing import Any

import pytest

from arema.memory import (
    CheckpointRecord,
    EventRecord,
    InMemoryStore,
    MemoryQuery,
    MemoryScope,
)
from arema.memory.service import MemoryService, default_core_codec_registry
from arema.registry.descriptors import (
    ContextMode,
    OutputPolicy,
    RuntimeProfile,
    ToolDescriptor,
    ToolLifecycleCallbacks,
)
from arema.runtime.callbacks.capture_request import capture_request
from arema.runtime.callbacks.chain import (
    CallbackChain,
    CallbackOrderError,
    build_callback_chain,
    callback_names,
    compose_after_tool,
    validate_callback_chain,
)
from arema.runtime.services import (
    ModelCallEvent,
    RuntimeServices,
    ToolEvent,
    build_memory_backed_services,
    make_checkpoint_recorder,
)
from arema.runtime.sessions import SessionKeys

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeClock:
    """A deterministic, advanceable monotonic clock."""

    def __init__(self, start: float = 1_000.0) -> None:
        self._now = start

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


class FakeMetricsSink:
    """Metrics sink that records every event it receives."""

    def __init__(self) -> None:
        self.model_calls: list[ModelCallEvent] = []
        self.tool_events: list[ToolEvent] = []

    def record_model_call(self, event: ModelCallEvent) -> None:
        self.model_calls.append(event)

    def record_tool_event(self, event: ToolEvent) -> None:
        self.tool_events.append(event)


class FakeMemoryEventSink:
    """Memory event sink that records every tool event it receives."""

    def __init__(self) -> None:
        self.tool_events: list[ToolEvent] = []

    def record_tool_event(self, event: ToolEvent) -> None:
        self.tool_events.append(event)


def fake_services() -> RuntimeServices:
    """Build a fully fake-able RuntimeServices for chain construction."""
    return RuntimeServices(
        clock=FakeClock(),
        metrics=FakeMetricsSink(),
        memory_sink=FakeMemoryEventSink(),
    )


def _tool_descriptor_with_memory() -> ToolDescriptor:
    def _after(
        tool: object,
        args: dict[str, Any],
        tool_context: object,
        tool_response: dict[str, Any],
    ) -> dict[str, Any] | None:
        del tool, args, tool_context, tool_response
        return None

    return ToolDescriptor(
        id="lookup",
        description="lookup tool",
        tool=lambda: object(),
        callbacks=ToolLifecycleCallbacks(after=(_after,)),
        memory_codec_ids=("codec",),
    )


def invalid_chain() -> CallbackChain:
    """A chain whose output compactor is not the last after-tool callback."""
    valid = build_callback_chain(
        RuntimeProfile.safe_default(),
        services=fake_services(),
        tools={},
    )

    def _extra(
        tool: object,
        args: dict[str, Any],
        tool_context: object,
        tool_response: dict[str, Any],
    ) -> dict[str, Any] | None:
        del tool, args, tool_context, tool_response
        return None

    return dataclasses.replace(valid, after_tool=(*valid.after_tool, _extra))


def callback_fixture(*, user_text: str) -> tuple[SimpleNamespace, SimpleNamespace]:
    """Build a fake CallbackContext and LlmRequest carrying one user turn."""
    part = SimpleNamespace(text=user_text)
    content = SimpleNamespace(role="user", parts=[part])
    context = SimpleNamespace(state={}, agent_name="agent")
    request = SimpleNamespace(contents=[content])
    return context, request


# ---------------------------------------------------------------------------
# Ordering
# ---------------------------------------------------------------------------


def test_safe_default_chain_has_stable_order() -> None:
    chain = build_callback_chain(
        RuntimeProfile.safe_default(),
        services=fake_services(),
        tools={},
    )
    assert callback_names(chain.before_model) == [
        "capture_request",
        "throttle_model_calls",
        "enforce_turn_limit",
        "enforce_context_budget",
        "record_model_usage",
    ]
    assert callback_names(chain.before_tool)[0] == "registered_tool_guard"
    assert callback_names(chain.after_tool) == [
        "record_tool_event",
        "compact_tool_output",
    ]


def test_chain_rejects_callback_after_compactor() -> None:
    with pytest.raises(CallbackOrderError, match="compactor must be last"):
        validate_callback_chain(invalid_chain())


def test_chain_returns_immutable_tuples() -> None:
    chain = build_callback_chain(
        RuntimeProfile.safe_default(),
        services=fake_services(),
        tools={},
    )
    assert isinstance(chain.before_model, tuple)
    assert isinstance(chain.before_tool, tuple)
    assert isinstance(chain.after_tool, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        chain.after_tool = ()  # type: ignore[misc]


def test_disabled_flags_drop_callbacks() -> None:
    profile = RuntimeProfile(
        id="bare",
        context_mode=ContextMode.ISOLATED,
        capture_request=False,
        throttle_model=False,
        retry_model=False,
        enforce_turn_limit=False,
        enforce_context_budget=False,
        record_metrics=False,
        guard_tools=False,
        record_memory=False,
        compact_tool_output=False,
        recover_tool_errors=False,
    )
    chain = build_callback_chain(profile, services=fake_services(), tools={})
    assert chain.before_model == ()
    assert chain.before_tool == ()
    assert chain.after_tool == ()
    assert chain.on_tool_error == ()
    assert chain.on_model_error == ()


def test_extra_callbacks_are_appended_before_metrics() -> None:
    async def _extra_before_model(callback_context: object, llm_request: object) -> None:
        del callback_context, llm_request
        return None

    profile = RuntimeProfile(
        id="with-extra",
        extra_before_model=(_extra_before_model,),
    )
    chain = build_callback_chain(profile, services=fake_services(), tools={})
    names = callback_names(chain.before_model)
    assert names[-1] == "record_model_usage"
    assert "_extra_before_model" in names
    assert names.index("_extra_before_model") < names.index("record_model_usage")


def test_memory_recorder_added_when_tools_and_record_memory() -> None:
    tools = {"lookup": _tool_descriptor_with_memory()}
    chain = build_callback_chain(
        RuntimeProfile.safe_default(),
        services=fake_services(),
        tools=tools,
    )
    names = callback_names(chain.after_tool)
    assert names[0] == "record_tool_event"
    assert names[-1] == "compact_tool_output"
    assert "record_tool_memory" in names
    assert names.index("record_tool_memory") < names.index("compact_tool_output")


def test_memory_recorder_absent_when_record_memory_disabled() -> None:
    tools = {"lookup": _tool_descriptor_with_memory()}
    profile = RuntimeProfile(id="no-memory", record_memory=False)
    chain = build_callback_chain(profile, services=fake_services(), tools=tools)
    assert "record_tool_memory" not in callback_names(chain.after_tool)


def test_on_error_handlers_wired_for_guarded_profile() -> None:
    chain = build_callback_chain(
        RuntimeProfile.safe_default(),
        services=fake_services(),
        tools={},
    )
    assert callback_names(chain.on_tool_error) == ["registered_tool_guard", "recover_tool_error"]
    assert callback_names(chain.on_model_error) == ["recover_model_json_error"]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_validate_accepts_safe_default_chain() -> None:
    chain = build_callback_chain(
        RuntimeProfile.safe_default(),
        services=fake_services(),
        tools={},
    )
    assert validate_callback_chain(chain) is None


def test_validate_rejects_guard_not_first() -> None:
    valid = build_callback_chain(
        RuntimeProfile.safe_default(),
        services=fake_services(),
        tools={},
    )

    def _pre(
        tool: object,
        args: dict[str, Any],
        tool_context: object,
    ) -> dict[str, Any] | None:
        del tool, args, tool_context
        return None

    reordered = dataclasses.replace(valid, before_tool=(_pre, *valid.before_tool))
    with pytest.raises(CallbackOrderError, match="guard must be first"):
        validate_callback_chain(reordered)


# ---------------------------------------------------------------------------
# capture_request
# ---------------------------------------------------------------------------


async def test_capture_request_stores_latest_user_text() -> None:
    context, request = callback_fixture(user_text="hello AREMA")
    await capture_request(context, request)  # type: ignore[arg-type]
    assert context.state[SessionKeys.USER_REQUEST] == "hello AREMA"


async def test_capture_request_prefers_last_user_turn() -> None:
    part_old = SimpleNamespace(text="first turn text")
    part_new = SimpleNamespace(text="latest turn text")
    contents = [
        SimpleNamespace(role="user", parts=[part_old]),
        SimpleNamespace(role="model", parts=[SimpleNamespace(text="ack")]),
        SimpleNamespace(role="user", parts=[part_new]),
    ]
    context = SimpleNamespace(state={}, agent_name="agent")
    request = SimpleNamespace(contents=contents)
    await capture_request(context, request)  # type: ignore[arg-type]
    assert context.state[SessionKeys.USER_REQUEST] == "latest turn text"


async def test_capture_request_does_not_overwrite() -> None:
    context, request = callback_fixture(user_text="new text")
    context.state[SessionKeys.USER_REQUEST] = "existing"
    await capture_request(context, request)  # type: ignore[arg-type]
    assert context.state[SessionKeys.USER_REQUEST] == "existing"


async def test_capture_request_tolerates_missing_state() -> None:
    context = SimpleNamespace(state=None, agent_name="agent")
    request = SimpleNamespace(contents=[])
    assert await capture_request(context, request) is None  # type: ignore[arg-type]


def test_output_policy_default_is_reused() -> None:
    # Sanity that ToolDescriptor default output policy is a valid OutputPolicy.
    tool = _tool_descriptor_with_memory()
    assert isinstance(tool.output_policy, OutputPolicy)


# ---------------------------------------------------------------------------
# Memory service integration (real service over InMemoryStore)
# ---------------------------------------------------------------------------


def _memory_service() -> MemoryService:
    store = InMemoryStore()
    store.initialize()
    return MemoryService(store=store, codecs=default_core_codec_registry())


def _run_after_tool_chain(
    chain: CallbackChain,
    *,
    tool: object,
    tool_context: object,
    tool_response: dict[str, Any],
) -> dict[str, Any]:
    """Run the after-tool chain exactly as production does.

    Delegates to the production ``compose_after_tool`` -- the single callback
    ``build_llm_agent`` hands ADK -- rather than walking ``chain.after_tool`` by
    hand. A hand-rolled walk would faithfully run every step and so could never
    catch a short-circuit in the real ADK-facing callback.
    """
    original = dict(tool_response)
    composite = compose_after_tool(chain.after_tool)
    if composite is None:
        return original
    result = asyncio.run(
        composite(
            tool=tool,  # type: ignore[arg-type]
            args={},
            tool_context=tool_context,  # type: ignore[arg-type]
            tool_response=original,
        )
    )
    return result if result is not None else original


def test_compose_after_tool_runs_all_steps_and_does_not_short_circuit() -> None:
    """A transforming step (returns a value) must NOT stop later steps -- the exact
    ADK short-circuit that silently killed compaction behind the sanitizer."""
    order: list[str] = []

    def transform(*, tool: object, args: object, tool_context: object, tool_response: dict) -> dict:
        del tool, args, tool_context
        order.append("transform")
        return {**tool_response, "transformed": True}

    def compactor(*, tool: object, args: object, tool_context: object, tool_response: dict) -> dict:
        del tool, args, tool_context
        order.append("compactor")
        # Reached only if `transform` did not short-circuit the chain.
        return {"compacted": True, "saw_transform": tool_response.get("transformed", False)}

    composite = compose_after_tool((transform, compactor))
    assert composite is not None
    result = asyncio.run(
        composite(tool=object(), args={}, tool_context=object(), tool_response={"raw": "x"})
    )

    assert order == ["transform", "compactor"], "later steps must run after a transform"
    assert result == {"compacted": True, "saw_transform": True}


def test_compose_after_tool_returns_none_when_every_step_abstains() -> None:
    def abstain(*, tool: object, args: object, tool_context: object, tool_response: object) -> None:
        del tool, args, tool_context, tool_response
        return None

    composite = compose_after_tool((abstain, abstain))
    assert composite is not None
    result = asyncio.run(
        composite(tool=object(), args={}, tool_context=object(), tool_response={"a": 1})
    )

    assert result is None  # None means "leave the response unchanged"


def test_compose_after_tool_empty_chain_wires_no_callback() -> None:
    assert compose_after_tool(()) is None


def test_memory_recorder_persists_sanitized_event_before_compaction() -> None:
    service = _memory_service()
    scope = service.create_scope(MemoryScope(scope_type="run"))
    services = build_memory_backed_services(service, clock=FakeClock(), metrics=FakeMetricsSink())

    descriptor = ToolDescriptor(
        id="lookup",
        description="lookup tool",
        tool=lambda: object(),
        output_policy=OutputPolicy(drop_fields=("raw",)),
    )
    chain = build_callback_chain(
        RuntimeProfile.safe_default(),
        services=services,
        tools={"lookup": descriptor},
    )

    original = {"success": True, "raw": "x" * 500, "count": 3}
    pre_compaction_size = len(json.dumps(original, default=str))
    state = {
        SessionKeys.MEMORY_SCOPE_ID: scope.id,
        SessionKeys.RUN_ID: "run-1",
    }
    tool = SimpleNamespace(name="lookup")
    tool_context = SimpleNamespace(state=state, function_call_id="call-1")

    final = _run_after_tool_chain(
        chain, tool=tool, tool_context=tool_context, tool_response=original
    )

    # Output compaction (last in the chain) dropped the bulky raw field.
    assert "raw" not in final

    result = service.retrieve_bounded(MemoryQuery(scope_id=scope.id))
    assert len(result.records) == 1
    envelope = result.envelopes[0]
    assert envelope.namespace == "arema.core"
    assert envelope.kind == "event"

    record = result.records[0]
    assert isinstance(record, EventRecord)
    assert record.name == "tool_call"
    # Only neutral lifecycle metadata -- never the raw output or arguments.
    assert set(record.attributes) == {
        "tool_id",
        "success",
        "elapsed_seconds",
        "output_size",
        "run_id",
    }
    assert record.attributes["tool_id"] == "lookup"
    assert record.attributes["success"] is True
    assert record.attributes["run_id"] == "run-1"
    assert "raw" not in json.dumps(record.attributes)
    # The recorded size is the pre-compaction size: the event was persisted
    # before output compaction shrank the response.
    assert record.attributes["output_size"] == pre_compaction_size


def test_memory_recorder_skips_write_without_scope() -> None:
    service = _memory_service()
    services = build_memory_backed_services(service, clock=FakeClock(), metrics=FakeMetricsSink())
    descriptor = ToolDescriptor(id="lookup", description="lookup tool", tool=lambda: object())
    chain = build_callback_chain(
        RuntimeProfile.safe_default(),
        services=services,
        tools={"lookup": descriptor},
    )
    tool = SimpleNamespace(name="lookup")
    tool_context = SimpleNamespace(state={}, function_call_id="call-1")

    _run_after_tool_chain(
        chain, tool=tool, tool_context=tool_context, tool_response={"success": True}
    )
    assert service.retrieve_bounded(MemoryQuery()).records == ()


def test_after_agent_recorder_writes_checkpoint_before_scope_closes() -> None:
    service = _memory_service()
    scope = service.create_scope(MemoryScope(scope_type="run"))
    recorder = make_checkpoint_recorder(service)
    context = SimpleNamespace(
        state={
            SessionKeys.MEMORY_SCOPE_ID: scope.id,
            SessionKeys.CONTEXT_CHECKPOINT: {
                "label": "turn-3",
                "sequence": 3,
                "state": {"model_calls": 3, "tool_calls": 5},
            },
        }
    )

    recorder(context)  # type: ignore[arg-type]

    result = service.retrieve_bounded(MemoryQuery(scope_id=scope.id))
    assert len(result.records) == 1
    checkpoint = result.records[0]
    assert isinstance(checkpoint, CheckpointRecord)
    assert checkpoint.label == "turn-3"
    assert checkpoint.sequence == 3
    assert checkpoint.state == {"model_calls": 3, "tool_calls": 5}
    assert result.envelopes[0].kind == "checkpoint"


def test_after_agent_recorder_is_noop_without_checkpoint() -> None:
    service = _memory_service()
    scope = service.create_scope(MemoryScope(scope_type="run"))
    recorder = make_checkpoint_recorder(service)
    context = SimpleNamespace(state={SessionKeys.MEMORY_SCOPE_ID: scope.id})

    recorder(context)  # type: ignore[arg-type]

    assert service.retrieve_bounded(MemoryQuery(scope_id=scope.id)).records == ()


def test_empty_chain_has_no_callbacks_and_validates() -> None:
    from arema.runtime.callbacks.chain import CallbackChain, validate_callback_chain

    chain = CallbackChain.empty()

    assert chain.before_model == ()
    assert chain.before_tool == ()
    assert chain.after_tool == ()
    assert chain.on_tool_error == ()
    assert chain.on_model_error == ()
    # An empty chain trivially satisfies the ordering invariants (no guard, no
    # compactor) and is what composite agents (no model, no tools) carry.
    validate_callback_chain(chain)
