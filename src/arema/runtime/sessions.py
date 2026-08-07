"""Neutral session-state keys shared by AREMA runtime callbacks.

These keys name the small amount of cross-callback state a run needs: the
captured user request, run and memory-scope identifiers, the stable sandbox
case id, and the per-run counters that the throttle, turn-limit, and metrics
callbacks maintain. Internal runtime counters are namespaced under
``_runtime:``; app-visible identifiers are bare (``run_id`` etc.) or
``arema:``-prefixed (``arema:sandbox_case_id``), so they never collide with each
other or with arbitrary application state written by tools or agents.
"""

from __future__ import annotations

from enum import StrEnum
from hashlib import sha256


class SessionKeys(StrEnum):
    """Canonical, domain-neutral keys for ``CallbackContext.state`` access."""

    USER_REQUEST = "user_request"
    RUN_ID = "run_id"
    MEMORY_SCOPE_ID = "memory_scope_id"
    SANDBOX_CASE_ID = "arema:sandbox_case_id"
    TURN_COUNT = "_runtime:turn_count"
    MODEL_CALLS = "_runtime:model_calls"
    TOOL_CALLS = "_runtime:tool_calls"
    CONTEXT_CHECKPOINT = "_runtime:context_checkpoint"
    CURRENT_MODEL = "_runtime:current_model"
    MODEL_USAGE = "_runtime:model_usage"
    TOKEN_USAGE_RECORD = "token_usage_json"


class SandboxIdentityError(RuntimeError):
    """Raised when an ADK context cannot identify a sandbox lifecycle."""


def resolve_sandbox_case_id(context: object) -> str:
    """Resolve and persist the stable sandbox key for one ADK invocation."""
    try:
        state = getattr(context, "state", None)
        getter = getattr(state, "get", None)
        setter = getattr(state, "__setitem__", None)
    except Exception as exc:
        raise SandboxIdentityError("sandbox identity access failed") from exc
    if not callable(getter) or not callable(setter):
        raise SandboxIdentityError("sandbox identity requires writable context state")

    try:
        case_id = getter(SessionKeys.SANDBOX_CASE_ID, None)
    except Exception as exc:
        raise SandboxIdentityError("sandbox identity access failed") from exc
    if isinstance(case_id, str) and case_id.strip():
        return case_id

    try:
        invocation_id = getattr(context, "invocation_id", None)
    except Exception as exc:
        raise SandboxIdentityError("sandbox identity access failed") from exc
    if not isinstance(invocation_id, str) or not invocation_id.strip():
        raise SandboxIdentityError("sandbox identity requires an invocation id")

    invocation_digest = sha256(invocation_id.encode("utf-8")).hexdigest()
    resolved = f"inv-{invocation_digest[:32]}"
    try:
        setter(SessionKeys.SANDBOX_CASE_ID, resolved)
    except Exception as exc:
        raise SandboxIdentityError("sandbox state is not writable") from exc
    return resolved
