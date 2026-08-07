"""Neutral token/tool metrics callbacks.

Three fail-open callbacks record run activity without ever touching tool
arguments or raw output:

* ``record_model_usage`` (before-model) counts model calls per run.
* ``record_tool_start`` (before-tool) stamps a monotonic start time so tool
  latency can be measured.
* ``record_tool_event`` (after-tool) emits a :class:`ToolEvent` carrying only
  the tool id, an outcome flag, the elapsed time, the run/scope ids, and the
  serialized output size.

Every callback catches and logs its own failures and always returns ``None``,
so a metrics backend outage never mutates a tool response or aborts a run.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Final

from arema.core.logging import get_logger
from arema.runtime.callbacks.roles import (
    ROLE_RECORD_MODEL_TOKENS,
    ROLE_RECORD_MODEL_USAGE,
    ROLE_RECORD_TOOL_EVENT,
    ROLE_RECORD_TOOL_START,
    with_role,
)
from arema.runtime.services import ModelCallEvent, ToolEvent
from arema.runtime.sessions import SessionKeys
from arema.runtime.token_usage import accumulate_usage, usage_sample_from_metadata

if TYPE_CHECKING:
    from google.adk.agents.callback_context import CallbackContext
    from google.adk.models.llm_request import LlmRequest
    from google.adk.models.llm_response import LlmResponse
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext

    from arema.registry.descriptors import (
        AfterModelCallback,
        AfterToolCallback,
        BeforeModelCallback,
        BeforeToolCallback,
    )
    from arema.runtime.services import Clock, RuntimeServices

logger = get_logger(__name__)

_TOOL_START_PREFIX: Final = "_runtime:tool_start:"
# The before->after model handoff is scoped per agent (mirroring the per-call
# tool-start slots above). A ParallelAgent runs its branches concurrently over
# one shared ``session.state``; a single unscoped slot would let a sibling
# branch's before-model overwrite this branch's model during its model-call
# await, mis-attributing the returned usage. Keying by agent name keeps each
# concurrent branch's model in its own slot.
_CURRENT_MODEL_PREFIX: Final = f"{SessionKeys.CURRENT_MODEL}:"


def _tool_start_key(tool: BaseTool, tool_context: ToolContext) -> str:
    call_id = getattr(tool_context, "function_call_id", None) or getattr(tool, "name", "tool")
    return f"{_TOOL_START_PREFIX}{call_id}"


def _current_model_key(callback_context: CallbackContext) -> str:
    """Return the per-agent session-state slot for the model handoff."""
    agent = getattr(callback_context, "agent_name", None)
    return f"{_CURRENT_MODEL_PREFIX}{agent if isinstance(agent, str) else ''}"


def _run_scope(callback_context: CallbackContext, state: object) -> str | None:
    """Resolve the id the token accumulator resets on when it changes.

    ``SessionKeys.RUN_ID`` is seeded only by the neutral-core runner
    (``run_single_query``). The ``adk run`` / ``adk web`` path drives the
    pipeline through ADK's own ``Runner``, which never sets it, so we fall back
    to the ADK ``invocation_id`` -- a fresh value per user turn that is constant
    across every stage of one pipeline invocation. Without this fallback the
    scope is ``None`` on every turn, the reset never fires, and a reused session
    double-counts a second analysis onto the first.
    """
    run_id = _state_str(state, SessionKeys.RUN_ID)
    if run_id is not None:
        return run_id
    invocation_id = getattr(callback_context, "invocation_id", None)
    return invocation_id if isinstance(invocation_id, str) and invocation_id else None


def _derive_success(response: object) -> bool:
    if isinstance(response, dict):
        if "success" in response:
            return bool(response["success"])
        if response.get("error"):
            return False
    return True


def _response_size(response: object) -> int:
    try:
        return len(json.dumps(response, default=str))
    except (TypeError, ValueError):
        return len(str(response))


def _state_str(state: object, key: str) -> str | None:
    getter = getattr(state, "get", None)
    value = getter(key) if callable(getter) else None
    return value if isinstance(value, str) else None


def build_tool_event(
    tool: BaseTool,
    tool_context: ToolContext,
    tool_response: object,
    clock: Clock,
) -> ToolEvent:
    """Build a neutral :class:`ToolEvent` from a completed tool call.

    Reads the start stamp left by ``record_tool_start`` to compute elapsed
    time (defaulting to zero when absent) and the run/scope ids from state.
    Deliberately never reads the tool arguments or the output content -- only
    its serialized size.
    """
    state = getattr(tool_context, "state", None)
    start = state.get(_tool_start_key(tool, tool_context)) if state is not None else None
    elapsed = max(0.0, clock.now() - start) if isinstance(start, (int, float)) else 0.0
    return ToolEvent(
        tool_id=getattr(tool, "name", "tool"),
        success=_derive_success(tool_response),
        elapsed_seconds=elapsed,
        output_size=_response_size(tool_response),
        run_id=_state_str(state, SessionKeys.RUN_ID),
        scope_id=_state_str(state, SessionKeys.MEMORY_SCOPE_ID),
    )


def make_model_usage_recorder(services: RuntimeServices) -> BeforeModelCallback:
    """Build a before-model callback that counts model calls for a run."""

    @with_role(ROLE_RECORD_MODEL_USAGE)
    async def record_model_usage(
        callback_context: CallbackContext,
        llm_request: LlmRequest,
    ) -> LlmResponse | None:
        try:
            state = callback_context.state
            if state is None:
                return None
            model = getattr(llm_request, "model", None)
            if isinstance(model, str) and model:
                state[_current_model_key(callback_context)] = model
            count = int(state.get(SessionKeys.MODEL_CALLS, 0)) + 1
            state[SessionKeys.MODEL_CALLS] = count
            services.metrics.record_model_call(
                ModelCallEvent(
                    agent_id=getattr(callback_context, "agent_name", "") or "",
                    call_count=count,
                    run_id=_state_str(state, SessionKeys.RUN_ID),
                    scope_id=_state_str(state, SessionKeys.MEMORY_SCOPE_ID),
                )
            )
        except Exception:
            logger.warning("record_model_usage failed - continuing", exc_info=True)
        return None

    return record_model_usage


def make_model_usage_token_recorder(services: RuntimeServices) -> AfterModelCallback:
    """Build an after-model callback that folds token usage into the accumulator."""
    del services  # accumulation is state-only; sink emission is a future extension

    @with_role(ROLE_RECORD_MODEL_TOKENS)
    async def record_model_tokens(
        callback_context: CallbackContext,
        llm_response: LlmResponse,
    ) -> LlmResponse | None:
        try:
            state = getattr(callback_context, "state", None)
            if state is None:
                return None
            sample = usage_sample_from_metadata(getattr(llm_response, "usage_metadata", None))
            model = _state_str(state, _current_model_key(callback_context))
            if sample is None or model is None:
                return None
            accumulate_usage(state, model, sample, _run_scope(callback_context, state))
        except Exception:
            logger.warning("record_model_tokens failed - continuing", exc_info=True)
        return None

    return record_model_tokens


def make_tool_call_timer(clock: Clock) -> BeforeToolCallback:
    """Build a before-tool callback that stamps a tool's start time."""

    @with_role(ROLE_RECORD_TOOL_START)
    def record_tool_start(
        tool: BaseTool,
        args: dict[str, Any],
        tool_context: ToolContext,
    ) -> dict[str, Any] | None:
        del args
        try:
            state = tool_context.state
            if state is not None:
                state[_tool_start_key(tool, tool_context)] = clock.now()
        except Exception:
            logger.warning("record_tool_start failed - continuing", exc_info=True)
        return None

    return record_tool_start


def make_tool_event_recorder(services: RuntimeServices) -> AfterToolCallback:
    """Build an after-tool callback that emits a neutral tool metric."""

    @with_role(ROLE_RECORD_TOOL_EVENT)
    def record_tool_event(
        tool: BaseTool,
        args: dict[str, Any],
        tool_context: ToolContext,
        tool_response: dict[str, Any],
    ) -> dict[str, Any] | None:
        del args  # arguments are never recorded
        try:
            state = getattr(tool_context, "state", None)
            if state is not None:
                state[SessionKeys.TOOL_CALLS] = int(state.get(SessionKeys.TOOL_CALLS, 0)) + 1
            event = build_tool_event(tool, tool_context, tool_response, services.clock)
            services.metrics.record_tool_event(event)
        except Exception:
            logger.warning("record_tool_event failed - continuing", exc_info=True)
        return None

    return record_tool_event
