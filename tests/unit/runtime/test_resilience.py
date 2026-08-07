"""Resilience and fail-open tests for neutral runtime callbacks."""

from __future__ import annotations

import dataclasses
from json import JSONDecodeError
from types import SimpleNamespace
from typing import Any
from unittest import mock

import pytest
from google.adk.models.llm_response import LlmResponse

import arema.runtime.callbacks.throttle as throttle_mod
from arema.runtime.callbacks.memory import make_tool_memory_recorder
from arema.runtime.callbacks.metrics import make_model_usage_recorder, make_tool_event_recorder
from arema.runtime.callbacks.model_error import _repair_json, recover_model_json_error
from arema.runtime.callbacks.throttle import throttle_model_calls
from arema.runtime.callbacks.tool_guard import (
    recover_tool_exception,
    registered_tool_error_handler,
    registered_tool_guard,
)
from arema.runtime.callbacks.turn_limit import enforce_turn_limit
from arema.runtime.services import ModelCallEvent, RuntimeServices, ToolEvent
from arema.runtime.sessions import SessionKeys

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeClock:
    def __init__(self, start: float = 500.0) -> None:
        self._now = start

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


class RecordingMetricsSink:
    def __init__(self) -> None:
        self.model_calls: list[ModelCallEvent] = []
        self.tool_events: list[ToolEvent] = []

    def record_model_call(self, event: ModelCallEvent) -> None:
        self.model_calls.append(event)

    def record_tool_event(self, event: ToolEvent) -> None:
        self.tool_events.append(event)


class FailingMetricsSink:
    def record_model_call(self, event: ModelCallEvent) -> None:
        del event
        raise RuntimeError("metrics down")

    def record_tool_event(self, event: ToolEvent) -> None:
        del event
        raise RuntimeError("metrics down")


class RecordingMemorySink:
    def __init__(self) -> None:
        self.tool_events: list[ToolEvent] = []

    def record_tool_event(self, event: ToolEvent) -> None:
        self.tool_events.append(event)


class FailingMemorySink:
    def record_tool_event(self, event: ToolEvent) -> None:
        del event
        raise RuntimeError("memory down")


def _services(*, metrics: object, memory: object, clock: FakeClock) -> RuntimeServices:
    return RuntimeServices(
        clock=clock,  # type: ignore[arg-type]
        metrics=metrics,  # type: ignore[arg-type]
        memory_sink=memory,  # type: ignore[arg-type]
    )


def _tool(name: str, func_name: str | None = None) -> SimpleNamespace:
    if func_name is None:
        return SimpleNamespace(name=name)
    return SimpleNamespace(name=name, func=SimpleNamespace(__name__=func_name))


def _tool_context(state: dict[str, Any] | None = None, call_id: str = "call-1") -> SimpleNamespace:
    return SimpleNamespace(state=state if state is not None else {}, function_call_id=call_id)


# ---------------------------------------------------------------------------
# Throttle timing
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_throttle() -> Any:
    throttle_mod._last_call_time = 0.0
    yield
    throttle_mod._last_call_time = 0.0


async def test_throttle_is_noop_when_interval_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_sleep = mock.AsyncMock()
    monkeypatch.setattr(throttle_mod.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(
        throttle_mod, "get_settings", lambda: SimpleNamespace(llm_min_call_interval=0.0)
    )
    ctx = SimpleNamespace(agent_name="a", state={})
    req = SimpleNamespace()
    assert await throttle_model_calls(ctx, req) is None  # type: ignore[arg-type]
    fake_sleep.assert_not_awaited()


async def test_throttle_sleeps_when_calls_too_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_sleep = mock.AsyncMock()
    monkeypatch.setattr(throttle_mod.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(
        throttle_mod, "get_settings", lambda: SimpleNamespace(llm_min_call_interval=0.3)
    )
    ctx = SimpleNamespace(agent_name="a", state={})
    req = SimpleNamespace()

    assert await throttle_model_calls(ctx, req) is None  # type: ignore[arg-type]  # first call
    fake_sleep.assert_not_awaited()

    assert await throttle_model_calls(ctx, req) is None  # type: ignore[arg-type]  # too fast
    assert fake_sleep.await_count == 1
    slept_for = fake_sleep.await_args.args[0]
    assert slept_for > 0


async def test_throttle_survives_settings_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom() -> object:
        raise RuntimeError("no settings")

    monkeypatch.setattr(throttle_mod, "get_settings", _boom)
    ctx = SimpleNamespace(agent_name="a", state={})
    req = SimpleNamespace()
    assert await throttle_model_calls(ctx, req) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Per-agent turn limits
# ---------------------------------------------------------------------------


def _turn_settings(**agent_limits: int) -> SimpleNamespace:
    return SimpleNamespace(agent_turn_limits=dict(agent_limits), default_turn_limit=100)


async def test_turn_limit_below_limit_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "arema.runtime.callbacks.turn_limit.get_settings",
        lambda: _turn_settings(recon=8),
    )
    state = {f"{SessionKeys.TURN_COUNT}:recon": 2}
    ctx = SimpleNamespace(agent_name="recon", state=state)
    req = SimpleNamespace(config=SimpleNamespace(system_instruction="base"))
    result = await enforce_turn_limit(ctx, req)  # type: ignore[arg-type]
    assert result is None
    assert state[f"{SessionKeys.TURN_COUNT}:recon"] == 3
    assert req.config.system_instruction == "base"


async def test_turn_limit_soft_stop_injects_directive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "arema.runtime.callbacks.turn_limit.get_settings",
        lambda: _turn_settings(recon=8),
    )
    state = {f"{SessionKeys.TURN_COUNT}:recon": 7}
    ctx = SimpleNamespace(agent_name="recon", state=state)
    req = SimpleNamespace(config=SimpleNamespace(system_instruction="base"))
    result = await enforce_turn_limit(ctx, req)  # type: ignore[arg-type]
    assert result is None
    assert "TURN LIMIT" in req.config.system_instruction
    assert "8/8" in req.config.system_instruction


async def test_turn_limit_hard_stop_returns_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "arema.runtime.callbacks.turn_limit.get_settings",
        lambda: _turn_settings(recon=8),
    )
    state = {f"{SessionKeys.TURN_COUNT}:recon": 9}
    ctx = SimpleNamespace(agent_name="recon", state=state)
    req = SimpleNamespace(config=SimpleNamespace(system_instruction="base"))
    result = await enforce_turn_limit(ctx, req)  # type: ignore[arg-type]
    assert isinstance(result, LlmResponse)
    assert result.content is not None
    text = result.content.parts[0].text
    assert text is not None
    assert "recon" in text
    assert "8" in text


async def test_turn_limit_uses_default_for_unlisted_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "arema.runtime.callbacks.turn_limit.get_settings",
        lambda: SimpleNamespace(agent_turn_limits={}, default_turn_limit=5),
    )
    state = {f"{SessionKeys.TURN_COUNT}:other": 4}
    ctx = SimpleNamespace(agent_name="other", state=state)
    req = SimpleNamespace(config=SimpleNamespace(system_instruction="base"))
    result = await enforce_turn_limit(ctx, req)  # type: ignore[arg-type]
    assert result is None
    assert "TURN LIMIT" in req.config.system_instruction  # reached default limit of 5


async def test_turn_limit_counters_are_independent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "arema.runtime.callbacks.turn_limit.get_settings",
        lambda: _turn_settings(recon=8, exploit=8),
    )
    state = {
        f"{SessionKeys.TURN_COUNT}:recon": 5,
        f"{SessionKeys.TURN_COUNT}:exploit": 2,
    }
    ctx_recon = SimpleNamespace(agent_name="recon", state=state)
    ctx_exploit = SimpleNamespace(agent_name="exploit", state=state)
    req = SimpleNamespace(config=SimpleNamespace(system_instruction="base"))
    await enforce_turn_limit(ctx_recon, req)  # type: ignore[arg-type]
    await enforce_turn_limit(ctx_exploit, req)  # type: ignore[arg-type]
    assert state[f"{SessionKeys.TURN_COUNT}:recon"] == 6
    assert state[f"{SessionKeys.TURN_COUNT}:exploit"] == 3


# ---------------------------------------------------------------------------
# Tool lookup recovery
# ---------------------------------------------------------------------------


def test_guard_allows_registered_tool() -> None:
    tool = _tool("lookup", func_name="lookup")
    result = registered_tool_guard(tool, {}, _tool_context())  # type: ignore[arg-type]
    assert result is None


def test_guard_blocks_unknown_stub() -> None:
    tool = _tool("ghost_tool", func_name="_unknown_tool_ghost_tool")
    result = registered_tool_guard(tool, {}, _tool_context())  # type: ignore[arg-type]
    assert result is not None
    assert result["success"] is False
    assert "ghost_tool" in result["error"]
    assert "tool_name" in result


def test_guard_tolerates_tool_without_func() -> None:
    tool = SimpleNamespace(name="lookup")
    result = registered_tool_guard(tool, {}, _tool_context())  # type: ignore[arg-type]
    assert result is None


def test_guard_error_handler_recovers_value_error() -> None:
    tool = _tool("ghost_tool")
    result = registered_tool_error_handler(
        tool,  # type: ignore[arg-type]
        {},
        _tool_context(),
        ValueError("not registered"),
    )
    assert result is not None
    assert result["success"] is False
    assert "ghost_tool" in result["error"]


def test_guard_error_handler_passes_through_other_errors() -> None:
    tool = _tool("lookup")
    result = registered_tool_error_handler(
        tool,  # type: ignore[arg-type]
        {},
        _tool_context(),
        RuntimeError("boom"),
    )
    assert result is None


def test_recover_tool_exception_returns_error_for_generic_exception() -> None:
    """A non-ValueError tool error (e.g. an MCP McpError when an r2 precondition
    like open_file is unmet) must not crash the run. recover_tool_exception
    converts it to a structured error response the model can recover from."""
    tool = _tool("list_functions")
    result = recover_tool_exception(
        tool,  # type: ignore[arg-type]
        {},
        _tool_context(),
        RuntimeError("Use the open_file method before calling any other method"),
    )
    assert result is not None
    assert result["success"] is False
    assert "list_functions" in result["error"]
    assert "open_file" in result["error"]


def test_recover_tool_exception_never_returns_none() -> None:
    """The last-resort handler always recovers -- returning None would let ADK
    re-raise and crash the event_generator. It must convert every exception."""
    tool = _tool("any_tool")
    for err in [ValueError("v"), RuntimeError("r"), TimeoutError("t"), Exception("generic")]:
        result = recover_tool_exception(
            tool,  # type: ignore[arg-type]
            {},
            _tool_context(),
            err,
        )
        assert result is not None, f"returned None for {type(err).__name__}"
        assert result["success"] is False


def test_guard_error_is_domain_neutral() -> None:
    tool = _tool("browser_navigate", func_name="_unknown_tool_browser_navigate")
    result = registered_tool_guard(tool, {}, _tool_context())  # type: ignore[arg-type]
    assert result is not None
    assert "browser_login_and_save_credentials" not in result["error"]
    assert "Playwright" not in result["error"]


# ---------------------------------------------------------------------------
# Model-error sanitization
# ---------------------------------------------------------------------------


def test_repair_json_fixes_trailing_comma() -> None:
    assert _repair_json('{"a": 1,}') == '{"a": 1}'


def test_model_error_passes_through_non_json_errors() -> None:
    ctx = SimpleNamespace(agent_name="a", state={})
    req = SimpleNamespace()
    assert recover_model_json_error(ctx, req, RuntimeError("boom")) is None  # type: ignore[arg-type]


def test_model_error_returns_recovery_response() -> None:
    ctx = SimpleNamespace(agent_name="a", state={})
    req = SimpleNamespace()
    err = JSONDecodeError("bad", '{"ok": true,}', 12)
    result = recover_model_json_error(ctx, req, err)  # type: ignore[arg-type]
    assert result is not None
    assert result.content is not None
    assert result.content.role == "model"
    assert result.content.parts[0].text


def test_model_error_does_not_leak_raw_document() -> None:
    ctx = SimpleNamespace(agent_name="a", state={})
    req = SimpleNamespace()
    err = JSONDecodeError("bad", '{"password": "hunter2",}', 23)
    result = recover_model_json_error(ctx, req, err)  # type: ignore[arg-type]
    assert result is not None
    text = result.content.parts[0].text
    assert "hunter2" not in text


# ---------------------------------------------------------------------------
# Metrics: fail-open and minimal payloads
# ---------------------------------------------------------------------------


def test_tool_event_records_only_neutral_fields() -> None:
    clock = FakeClock()
    metrics = RecordingMetricsSink()
    services = _services(metrics=metrics, memory=RecordingMemorySink(), clock=clock)
    recorder = make_tool_event_recorder(services)

    state = {
        "_runtime:tool_start:call-1": clock.now(),
        SessionKeys.RUN_ID: "run-9",
        SessionKeys.MEMORY_SCOPE_ID: "scope-9",
    }
    clock.advance(1.5)
    tool = _tool("scan")
    ctx = _tool_context(state=state, call_id="call-1")
    response = {"secret": "should-not-be-sent", "findings": [1, 2, 3]}

    result = recorder(tool, {"password": "hunter2"}, ctx, response)  # type: ignore[arg-type]

    assert result is None
    assert len(metrics.tool_events) == 1
    event = metrics.tool_events[0]
    field_names = {f.name for f in dataclasses.fields(event)}
    assert field_names == {
        "tool_id",
        "success",
        "elapsed_seconds",
        "output_size",
        "run_id",
        "scope_id",
    }
    assert event.tool_id == "scan"
    assert event.run_id == "run-9"
    assert event.scope_id == "scope-9"
    assert event.elapsed_seconds == pytest.approx(1.5)
    assert event.output_size > 0


def test_tool_event_recorder_is_fail_open() -> None:
    services = _services(
        metrics=FailingMetricsSink(), memory=RecordingMemorySink(), clock=FakeClock()
    )
    recorder = make_tool_event_recorder(services)
    tool = _tool("scan")
    response = {"ok": True}
    result = recorder(tool, {}, _tool_context(), response)  # type: ignore[arg-type]
    assert result is None  # never mutates the response


def test_model_usage_recorder_is_fail_open() -> None:
    services = _services(
        metrics=FailingMetricsSink(), memory=RecordingMemorySink(), clock=FakeClock()
    )
    recorder = make_model_usage_recorder(services)
    ctx = SimpleNamespace(agent_name="a", state={})
    req = SimpleNamespace()

    async def _run() -> object:
        return await recorder(ctx, req)  # type: ignore[arg-type]

    import asyncio

    assert asyncio.run(_run()) is None


def test_model_usage_recorder_counts_calls() -> None:
    metrics = RecordingMetricsSink()
    services = _services(metrics=metrics, memory=RecordingMemorySink(), clock=FakeClock())
    recorder = make_model_usage_recorder(services)
    state: dict[str, Any] = {}
    ctx = SimpleNamespace(agent_name="recon", state=state)
    req = SimpleNamespace()

    import asyncio

    asyncio.run(recorder(ctx, req))  # type: ignore[arg-type]
    asyncio.run(recorder(ctx, req))  # type: ignore[arg-type]

    assert state[SessionKeys.MODEL_CALLS] == 2
    assert len(metrics.model_calls) == 2
    assert metrics.model_calls[-1].call_count == 2


# ---------------------------------------------------------------------------
# Memory sink: fail-open
# ---------------------------------------------------------------------------


def test_memory_recorder_writes_event() -> None:
    memory = RecordingMemorySink()
    services = _services(metrics=RecordingMetricsSink(), memory=memory, clock=FakeClock())
    recorder = make_tool_memory_recorder(services)
    tool = _tool("scan")
    response = {"ok": True}
    result = recorder(tool, {}, _tool_context(), response)  # type: ignore[arg-type]
    assert result is None
    assert len(memory.tool_events) == 1
    assert memory.tool_events[0].tool_id == "scan"


def test_memory_recorder_is_fail_open() -> None:
    services = _services(
        metrics=RecordingMetricsSink(), memory=FailingMemorySink(), clock=FakeClock()
    )
    recorder = make_tool_memory_recorder(services)
    tool = _tool("scan")
    response = {"ok": True}
    result = recorder(tool, {}, _tool_context(), response)  # type: ignore[arg-type]
    assert result is None  # never mutates the response
