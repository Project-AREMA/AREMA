"""After-tool callback that persists neutral tool events to working memory.

The recorder depends only on the :class:`MemoryEventSink` interface, never on
a concrete store, so persistence backends stay swappable and tests use a
recording fake. It writes the same neutral :class:`ToolEvent` the metrics
layer builds -- tool id, outcome, elapsed time, run/scope ids, and output
size -- and never the tool arguments or raw output.

The callback is fail-open: a sink outage is caught, logged, and swallowed, and
the tool response is never mutated. When persistent memory is disabled the
chain wires a no-op sink here, so the callback's presence and position stay
identical regardless of whether memory is on.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from arema.core.logging import get_logger
from arema.runtime.callbacks.metrics import build_tool_event
from arema.runtime.callbacks.roles import ROLE_RECORD_TOOL_MEMORY, with_role

if TYPE_CHECKING:
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext

    from arema.registry.descriptors import AfterToolCallback
    from arema.runtime.services import RuntimeServices

logger = get_logger(__name__)


def make_tool_memory_recorder(services: RuntimeServices) -> AfterToolCallback:
    """Build an after-tool callback that persists a neutral tool event."""

    @with_role(ROLE_RECORD_TOOL_MEMORY)
    def record_tool_memory(
        tool: BaseTool,
        args: dict[str, Any],
        tool_context: ToolContext,
        tool_response: dict[str, Any],
    ) -> dict[str, Any] | None:
        del args  # arguments are never persisted
        try:
            event = build_tool_event(tool, tool_context, tool_response, services.clock)
            services.memory_sink.record_tool_event(event)
        except Exception:
            logger.warning("record_tool_memory failed - continuing", exc_info=True)
        return None

    return record_tool_memory
