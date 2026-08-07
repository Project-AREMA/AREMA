"""Guards against calls to tools that are not registered on an agent.

When an LLM hallucinates a tool name, ADK resolves it to an internal stub
whose wrapped callable is named ``_unknown_tool_<name>`` and, if dispatched,
raises ``ValueError`` from ``_get_tool`` *before* the before-tool callback
fires. Two hooks close that gap:

* :func:`registered_tool_guard` (before-tool) short-circuits recognized stubs
  with a descriptive error dict so the model can self-correct.
* :func:`registered_tool_error_handler` (on-tool-error) catches the
  ``ValueError`` ADK raises for genuinely unresolved names, which the
  before-tool hook cannot intercept.

Both return a structured error dict instead of letting the run crash. The
messages are domain-neutral.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from arema.core.logging import get_logger
from arema.runtime.callbacks.roles import (
    ROLE_RECOVER_TOOL_ERROR,
    ROLE_REGISTERED_TOOL_GUARD,
    with_role,
)

if TYPE_CHECKING:
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext

logger = get_logger(__name__)

_UNKNOWN_TOOL_PREFIX = "_unknown_tool_"


def _build_error(tool_name: str) -> dict[str, Any]:
    """Build a neutral structured error for an unregistered tool call."""
    guidance = (
        f"Tool '{tool_name}' is not registered on this agent. "
        "Choose a tool from this agent's available tool list instead."
    )
    logger.warning("blocked call to unregistered tool", tool_name=tool_name)
    return {
        "success": False,
        "error": guidance,
        "tool_name": tool_name,
        "available_hint": "Call only tools listed for this agent.",
    }


@with_role(ROLE_REGISTERED_TOOL_GUARD)
def registered_tool_guard(
    tool: BaseTool,
    args: dict[str, Any],
    tool_context: ToolContext,
) -> dict[str, Any] | None:
    """Return an error dict for an unregistered tool call, else ``None``.

    Detects ADK's ``_unknown_tool_<name>`` stub by the wrapped callable's
    name. Returning a dict prevents dispatch; returning ``None`` proceeds.
    """
    del args, tool_context  # detection depends only on the resolved tool
    func = getattr(tool, "func", None) or getattr(tool, "_func", None)
    func_name = getattr(func, "__name__", "") if func is not None else ""

    if isinstance(func_name, str) and func_name.startswith(_UNKNOWN_TOOL_PREFIX):
        requested = func_name.removeprefix(_UNKNOWN_TOOL_PREFIX) or tool.name
        return _build_error(requested)

    return None


@with_role(ROLE_REGISTERED_TOOL_GUARD)
def registered_tool_error_handler(
    tool: BaseTool,
    args: dict[str, Any],
    tool_context: ToolContext,
    error: Exception,
) -> dict[str, Any] | None:
    """Recover from the ``ValueError`` ADK raises for an unresolved tool.

    Returns a structured error dict for ``ValueError`` so the model can
    self-correct; returns ``None`` for any other error so ADK re-raises it.
    """
    del args, tool_context
    if not isinstance(error, ValueError):
        return None

    logger.warning(
        "recovered from unresolved tool dispatch",
        tool_name=tool.name,
        error=str(error)[:200],
    )
    return _build_error(tool.name)


def _build_recover_error(tool_name: str, error: Exception) -> dict[str, Any]:
    """Build a neutral structured error for a tool that raised at run time."""
    logger.warning(
        "tool raised - returning degraded error response",
        tool_name=tool_name,
        error_type=type(error).__name__,
        error=str(error)[:200],
    )
    return {
        "success": False,
        "error": f"Tool '{tool_name}' failed: {type(error).__name__}: {error}",
        "tool_name": tool_name,
        "recover_hint": "Retry, adjust the arguments, or report the failure in your output.",
    }


@with_role(ROLE_RECOVER_TOOL_ERROR)
def recover_tool_exception(
    tool: BaseTool,
    args: dict[str, Any],
    tool_context: ToolContext,
    error: Exception,
) -> dict[str, Any] | None:
    """Last-resort recovery: convert any tool exception into a structured error.

    A tool that raises at run time (e.g. an MCP ``McpError`` when a precondition
    such as r2's ``open_file`` is unmet) must not crash the run. This catches
    every exception the more specific handlers did not recover and returns a
    structured error response so the model can self-correct or report, instead of
    ADK re-raising and killing the event generator. Wired LAST in the
    ``on_tool_error`` chain so tool-specific handlers run first; never returns
    ``None``.
    """
    del args, tool_context
    return _build_recover_error(tool.name, error)
