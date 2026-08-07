"""Identity-based role markers for runtime callback wrappers.

Chain validation and ordering must not depend on fragile ``__name__``
comparisons: a wrapped, decorated, or renamed callback would silently defeat
them. Instead every callback that participates in a validated chain carries an
explicit role marker attribute. :func:`callback_role` reads that marker (with a
defensive ``__name__`` fallback), and validation compares against the role
constants below.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Final, TypeVar

_RUNTIME_ROLE_ATTR: Final = "__arema_runtime_role__"

_Callable = TypeVar("_Callable", bound=Callable[..., object])

# Before-model roles.
ROLE_CAPTURE_REQUEST: Final = "capture_request"
ROLE_THROTTLE_MODEL: Final = "throttle_model_calls"
ROLE_ENFORCE_TURN_LIMIT: Final = "enforce_turn_limit"
ROLE_ENFORCE_CONTEXT_BUDGET: Final = "enforce_context_budget"
ROLE_RECORD_MODEL_USAGE: Final = "record_model_usage"

# After-model roles.
ROLE_RECORD_MODEL_TOKENS: Final = "record_model_tokens"

# Before-tool roles.
ROLE_REGISTERED_TOOL_GUARD: Final = "registered_tool_guard"
ROLE_RECORD_TOOL_START: Final = "record_tool_start"

# After-tool roles.
ROLE_RECORD_TOOL_EVENT: Final = "record_tool_event"
ROLE_RECORD_TOOL_MEMORY: Final = "record_tool_memory"
ROLE_COMPACT_TOOL_OUTPUT: Final = "compact_tool_output"

# Error-handler roles.
ROLE_RECOVER_MODEL_ERROR: Final = "recover_model_json_error"
ROLE_RECOVER_TOOL_ERROR: Final = "recover_tool_error"


def tag_role(func: _Callable, role: str) -> _Callable:
    """Attach *role* to *func* and return it unchanged."""
    setattr(func, _RUNTIME_ROLE_ATTR, role)
    return func


def with_role(role: str) -> Callable[[_Callable], _Callable]:
    """Return a decorator that tags a callback with *role*."""

    def decorator(func: _Callable) -> _Callable:
        return tag_role(func, role)

    return decorator


def callback_role(func: object) -> str:
    """Return *func*'s role marker, falling back to its name."""
    role = getattr(func, _RUNTIME_ROLE_ATTR, None)
    if isinstance(role, str):
        return role
    name = getattr(func, "__name__", None)
    return name if isinstance(name, str) else "unknown"


def callback_names(callbacks: Iterable[object]) -> list[str]:
    """Return the ordered role names for *callbacks*."""
    return [callback_role(callback) for callback in callbacks]
