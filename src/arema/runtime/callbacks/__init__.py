"""Domain-neutral, one-responsibility runtime callbacks and chain wiring."""

from arema.runtime.callbacks.capture_request import capture_request
from arema.runtime.callbacks.chain import (
    CallbackChain,
    CallbackOrderError,
    ModelErrorCallback,
    build_callback_chain,
    callback_names,
    validate_callback_chain,
)
from arema.runtime.callbacks.memory import make_tool_memory_recorder
from arema.runtime.callbacks.metrics import (
    build_tool_event,
    make_model_usage_recorder,
    make_tool_call_timer,
    make_tool_event_recorder,
)
from arema.runtime.callbacks.model_error import recover_model_json_error
from arema.runtime.callbacks.roles import callback_role, tag_role, with_role
from arema.runtime.callbacks.throttle import throttle_model_calls
from arema.runtime.callbacks.tool_guard import (
    registered_tool_error_handler,
    registered_tool_guard,
)
from arema.runtime.callbacks.turn_limit import enforce_turn_limit

__all__ = [
    "CallbackChain",
    "CallbackOrderError",
    "ModelErrorCallback",
    "build_callback_chain",
    "build_tool_event",
    "callback_names",
    "callback_role",
    "capture_request",
    "enforce_turn_limit",
    "make_model_usage_recorder",
    "make_tool_call_timer",
    "make_tool_event_recorder",
    "make_tool_memory_recorder",
    "recover_model_json_error",
    "registered_tool_error_handler",
    "registered_tool_guard",
    "tag_role",
    "throttle_model_calls",
    "validate_callback_chain",
    "with_role",
]
