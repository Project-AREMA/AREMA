"""Per-case ``run_python`` execution budget -- the loop-level resource governor.

This is the second, loop-level layer of the §4.5 two-layer governor. The first
layer is enforced by the sandbox itself (per-exec timeout, memory cgroup, output
cap); this layer bounds *how many* times the agent may run a script at all, across
the whole case. The count is a **global** session-state counter so it spans every
deobfuscation-loop round rather than resetting per iteration -- a hard sample that
nests many packer layers cannot escape the cap by re-entering the loop.

It is wired as a ``before_tool`` callback on ``run_python``: ADK invokes it before
the tool runs, so once the cap is reached the guard returns a short-circuit result
and the sandbox is never touched again. The returned dict mirrors ``run_python``'s
result shape (a before_tool return value *is* the tool response) with a
finalize-now advisory, so the agent degrades gracefully -- dumping the best
artifact it has -- instead of being cut off mid-experiment by a silent hard kill.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from reverse_engineering.tools.workbench.state import (
    RUN_PYTHON_TOOL_NAME,
    WORKBENCH_EXEC_COUNT_KEY,
    WORKBENCH_MAX_EXECUTIONS,
)

if TYPE_CHECKING:
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext


def run_python_budget_guard(
    tool: BaseTool, args: dict[str, object], tool_context: ToolContext
) -> dict[str, object] | None:
    """Cap total ``run_python`` executions per case; short-circuit when exhausted.

    Returns ``None`` to let the call proceed (after charging one execution), or a
    ``run_python``-shaped result dict once the per-case cap is reached, which ADK
    surfaces as the tool response without ever invoking the sandbox.
    """
    del args  # part of the ADK before_tool contract; unused by the governor
    # build_callback_chain flattens every tool's `before` callbacks into ONE
    # agent-global list ADK runs before EVERY tool call, so this guard -- like the
    # SanitizationMembrane's after_tool callback -- must self-scope to the one tool
    # it governs, or it would charge run_python's budget for cheap radare2/register
    # calls and short-circuit them with a nonsensical run_python-shaped response.
    if getattr(tool, "name", "") != RUN_PYTHON_TOOL_NAME:
        return None
    state = tool_context.state
    # ADK's State is a proxy (not a dict/Mapping), so duck-type on .get/__setitem__
    # rather than isinstance -- and degrade to a no-op if either is unavailable.
    getter = getattr(state, "get", None)
    setter = getattr(state, "__setitem__", None)
    if not callable(getter) or not callable(setter):
        return None
    raw_used = getter(WORKBENCH_EXEC_COUNT_KEY)
    used = raw_used if isinstance(raw_used, int) and not isinstance(raw_used, bool) else 0
    if used >= WORKBENCH_MAX_EXECUTIONS:
        return {
            "exit_code": 1,
            "stdout": "",
            "stderr": (
                f"run_python budget exhausted ({WORKBENCH_MAX_EXECUTIONS} executions); "
                "finalize the best artifact you have and report."
            ),
            "truncated": False,
            "spilled_artifact_id": "",
        }
    setter(WORKBENCH_EXEC_COUNT_KEY, used + 1)
    return None
