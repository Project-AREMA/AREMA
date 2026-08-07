"""Construction and invariant validation of neutral runtime callback chains.

:func:`build_callback_chain` turns a :class:`RuntimeProfile` plus injected
:class:`RuntimeServices` and the agent's tool descriptors into an immutable
:class:`CallbackChain` whose before-model, before-tool, and after-tool tuples
follow one approved order. :func:`validate_callback_chain` re-checks the
invariants that order guarantees, using identity-based role markers rather than
function names so wrapping or renaming a callback cannot silently defeat them.

Approved before-tool order: the registered-tool guard (always first, so the
guard-first invariant holds), then the metrics start-timer, then profile
``extra_before_tool`` and per-tool ``ToolDescriptor.callbacks.before``
additions -- symmetric with the after-tool per-tool additions, so a tool can
attach a loop-level ``before_tool`` guard that actually reaches the agent.

Approved after-tool order for a completed tool call: the outcome event, then
profile and per-tool ``ToolDescriptor.callbacks.after`` additions, then the
codec-backed per-tool memory additions and the memory-event recorder, and
finally output compaction, which must always be last.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from arema.core.logging import get_logger
from arema.runtime.callbacks.capture_request import capture_request
from arema.runtime.callbacks.memory import make_tool_memory_recorder
from arema.runtime.callbacks.metrics import (
    make_model_usage_recorder,
    make_model_usage_token_recorder,
    make_tool_call_timer,
    make_tool_event_recorder,
)
from arema.runtime.callbacks.model_error import recover_model_json_error
from arema.runtime.callbacks.roles import (
    ROLE_COMPACT_TOOL_OUTPUT,
    ROLE_ENFORCE_CONTEXT_BUDGET,
    ROLE_REGISTERED_TOOL_GUARD,
    callback_names,
    callback_role,
    tag_role,
)
from arema.runtime.callbacks.throttle import throttle_model_calls
from arema.runtime.callbacks.tool_guard import (
    recover_tool_exception,
    registered_tool_error_handler,
    registered_tool_guard,
)
from arema.runtime.callbacks.turn_limit import enforce_turn_limit
from arema.runtime.context.budget import enforce_context_budget
from arema.runtime.context.compactor import make_output_compactor

if TYPE_CHECKING:
    from collections.abc import Awaitable, Mapping, Sequence

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
        RuntimeProfile,
        ToolDescriptor,
        ToolErrorCallback,
    )
    from arema.runtime.services import RuntimeServices

logger = get_logger(__name__)

__all__ = [
    "CallbackChain",
    "CallbackOrderError",
    "ModelErrorCallback",
    "build_callback_chain",
    "callback_names",
    "compose_after_tool",
    "validate_callback_chain",
]

# ``enforce_context_budget`` is a shared Task-5 callback; tag it once with its
# stable role so the chain can identify it without a name comparison.
_context_budget_callback = tag_role(enforce_context_budget, ROLE_ENFORCE_CONTEXT_BUDGET)


class CallbackOrderError(RuntimeError):
    """Raised when a callback chain violates a required ordering invariant."""


class ModelErrorCallback(Protocol):
    """An ADK on-model-error callback, synchronous or asynchronous."""

    def __call__(
        self,
        callback_context: CallbackContext,
        llm_request: LlmRequest,
        error: Exception,
    ) -> Awaitable[LlmResponse | None] | LlmResponse | None:
        """Optionally recover from a failed model call."""
        ...


@dataclass(frozen=True, slots=True)
class CallbackChain:
    """An immutable, ordered set of callbacks wired onto one agent."""

    before_model: tuple[BeforeModelCallback, ...]
    after_model: tuple[AfterModelCallback, ...]
    before_tool: tuple[BeforeToolCallback, ...]
    after_tool: tuple[AfterToolCallback, ...]
    on_tool_error: tuple[ToolErrorCallback, ...]
    on_model_error: tuple[ModelErrorCallback, ...]

    @classmethod
    def empty(cls) -> CallbackChain:
        """Return an empty chain for composite agents (no model, no tools).

        Composite agents carry no model and no tools, so neither the
        registered-tool guard nor the output compactor engage; an empty chain
        trivially satisfies the ordering invariants validated by
        :func:`validate_callback_chain`.
        """
        return cls(
            before_model=(),
            after_model=(),
            before_tool=(),
            after_tool=(),
            on_tool_error=(),
            on_model_error=(),
        )


def compose_after_tool(callbacks: Sequence[AfterToolCallback]) -> AfterToolCallback | None:
    """Fold the validated after-tool list into ONE callback for ADK.

    ADK walks its after-tool list and stops at the first callback returning a
    truthy value (``functions.py``: ``if altered_function_response: break``). That
    is fatal to this chain's central invariant. A callback that *transforms* the
    response -- the SanitizationMembrane, for one -- returns a value by
    construction, so every later step was skipped, including output compaction,
    which is deliberately placed last so metrics and memory observe the
    untruncated response. The effect was exactly inverted: compaction died for
    precisely the binary-origin tools it exists to bound.

    Handing ADK a single callback restores the documented semantics: every step
    runs in order, each sees the previous step's result, and ``None`` means "leave
    it unchanged". The chain itself stays an ordered, validated tuple, so
    :func:`validate_callback_chain` and the identity role markers keep working on
    the real list. Returns ``None`` for an empty chain so no callback is wired.
    """
    steps = tuple(callbacks)
    if not steps:
        return None

    async def run_after_tool_chain(
        tool: BaseTool,
        args: dict[str, Any],
        tool_context: ToolContext,
        tool_response: dict[str, Any],
    ) -> dict[str, Any] | None:
        current = tool_response
        altered = False
        for step in steps:
            result = step(tool=tool, args=args, tool_context=tool_context, tool_response=current)
            if inspect.isawaitable(result):
                result = await result
            if result is not None:
                current = result
                altered = True
        # ADK ignores a falsy replacement (`if altered_function_response`), so a
        # policy that drops every field would leave the original in context. There
        # is no way to express "replace with empty" across that boundary; no
        # shipped OutputPolicy empties a response, so revisit only if one ever does.
        return current if altered else None

    return run_after_tool_chain


def _make_compactor(tools: Mapping[str, ToolDescriptor]) -> AfterToolCallback:
    policies = {tool_id: descriptor.output_policy for tool_id, descriptor in tools.items()}
    return tag_role(make_output_compactor(policies), ROLE_COMPACT_TOOL_OUTPUT)


def build_callback_chain(
    profile: RuntimeProfile,
    *,
    services: RuntimeServices,
    tools: Mapping[str, ToolDescriptor],
) -> CallbackChain:
    """Assemble the validated callback chain for one agent runtime.

    Includes only the callbacks the *profile* enables, in the single approved
    order, and validates the result before returning it.
    """
    before_model: list[BeforeModelCallback] = []
    if profile.capture_request:
        before_model.append(capture_request)
    if profile.throttle_model:
        before_model.append(throttle_model_calls)
    if profile.enforce_turn_limit:
        before_model.append(enforce_turn_limit)
    if profile.enforce_context_budget:
        before_model.append(_context_budget_callback)
    before_model.extend(profile.extra_before_model)
    if profile.record_metrics:
        before_model.append(make_model_usage_recorder(services))

    after_model: list[AfterModelCallback] = []
    if profile.record_metrics:
        after_model.append(make_model_usage_token_recorder(services))

    before_tool: list[BeforeToolCallback] = []
    if profile.guard_tools:
        before_tool.append(registered_tool_guard)
    if profile.record_metrics:
        before_tool.append(make_tool_call_timer(services.clock))
    before_tool.extend(profile.extra_before_tool)
    # Per-tool before-tool additions, symmetric with the .after/.memory/.on_error
    # handling below. Appended AFTER registered_tool_guard so the guard-first
    # invariant re-checked by validate_callback_chain still holds; without this a
    # ToolDescriptor's before callback (e.g. a loop-level resource governor) would
    # be dead wiring -- set on the descriptor but never reaching the agent.
    for descriptor in tools.values():
        before_tool.extend(descriptor.callbacks.before)

    after_tool: list[AfterToolCallback] = []
    if profile.record_metrics:
        after_tool.append(make_tool_event_recorder(services))
    after_tool.extend(profile.extra_after_tool)
    for descriptor in tools.values():
        after_tool.extend(descriptor.callbacks.after)
    if profile.record_memory:
        for descriptor in tools.values():
            after_tool.extend(descriptor.callbacks.memory)
        if tools:
            after_tool.append(make_tool_memory_recorder(services))
    if profile.compact_tool_output:
        after_tool.append(_make_compactor(tools))

    on_tool_error: list[ToolErrorCallback] = []
    if profile.guard_tools:
        on_tool_error.append(registered_tool_error_handler)
    for descriptor in tools.values():
        on_tool_error.extend(descriptor.callbacks.on_error)
    if profile.recover_tool_errors:
        # Last-resort: convert any remaining tool exception into a recoverable
        # error response so a tool failure (e.g. an MCP McpError) degrades
        # gracefully instead of crashing the run. Must be last so tool-specific
        # handlers get first crack; never returns None.
        on_tool_error.append(recover_tool_exception)

    on_model_error: list[ModelErrorCallback] = []
    if profile.retry_model:
        on_model_error.append(recover_model_json_error)

    chain = CallbackChain(
        before_model=tuple(before_model),
        after_model=tuple(after_model),
        before_tool=tuple(before_tool),
        after_tool=tuple(after_tool),
        on_tool_error=tuple(on_tool_error),
        on_model_error=tuple(on_model_error),
    )
    validate_callback_chain(chain)
    return chain


def validate_callback_chain(chain: CallbackChain) -> None:
    """Assert the chain's ordering invariants, raising on any violation.

    * The registered-tool guard, when present, is first in ``before_tool``.
    * Output compaction, when present, is the single last ``after_tool`` step,
      so every memory and capability callback precedes it.
    """
    guard_positions = [
        index
        for index, callback in enumerate(chain.before_tool)
        if callback_role(callback) == ROLE_REGISTERED_TOOL_GUARD
    ]
    if guard_positions and guard_positions[0] != 0:
        raise CallbackOrderError(
            "registered tool guard must be first in before_tool: "
            f"found at index {guard_positions[0]} in {callback_names(chain.before_tool)}"
        )

    compactor_positions = [
        index
        for index, callback in enumerate(chain.after_tool)
        if callback_role(callback) == ROLE_COMPACT_TOOL_OUTPUT
    ]
    if len(compactor_positions) > 1:
        raise CallbackOrderError(
            "output compactor must be last in after_tool: found multiple compactors at "
            f"{compactor_positions}"
        )
    if compactor_positions and compactor_positions[0] != len(chain.after_tool) - 1:
        raise CallbackOrderError(
            "output compactor must be last in after_tool: "
            f"found at index {compactor_positions[0]} in {callback_names(chain.after_tool)}"
        )
