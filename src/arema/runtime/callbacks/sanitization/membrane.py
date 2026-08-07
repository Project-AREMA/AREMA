"""The after_tool callback that applies an OutputSanitizer to untrusted tools.

Returns the sanitized dict (replacing the tool result) for tools whose names
are in the supplied set; returns None (passthrough) for all others. Fail-open:
a sanitizer exception is swallowed and the original response passes through
unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from arema.core.logging import get_logger

if TYPE_CHECKING:
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext

    from arema.registry.descriptors import AfterToolCallback
    from arema.runtime.callbacks.sanitization.protocol import OutputSanitizer

logger = get_logger(__name__)


def make_sanitizing_after_tool(
    sanitizer: OutputSanitizer,
    binary_origin_tools: frozenset[str],
) -> AfterToolCallback:
    """Build an after_tool callback that sanitizes only untrusted-origin tool output.

    *binary_origin_tools* is the set of tool names whose output originates from
    an untrusted source (e.g. a binary under analysis). Only those tool
    responses are sanitized; all others pass through untouched.
    """

    def _sanitize_tool_output(
        tool: BaseTool,
        args: dict[str, Any],
        tool_context: ToolContext,
        tool_response: dict[str, Any],
    ) -> dict[str, Any] | None:
        del args, tool_context  # sanitization only needs the tool's identity + response
        name = getattr(tool, "name", "")
        if name not in binary_origin_tools:
            return None
        try:
            return sanitizer.sanitize(name, tool_response)
        except Exception as exc:
            logger.warning(
                "sanitizer failed - passthrough",
                error_type=type(exc).__name__,
                tool_name=name,
                exc_info=True,
            )
            return None

    return _sanitize_tool_output
