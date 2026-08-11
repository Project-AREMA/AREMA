"""Per-case ``run_python`` execution budget -- the loop-level resource governor.

This is the second, loop-level layer of the §4.5 two-layer governor. The first
layer is enforced by the sandbox itself (per-exec timeout, memory cgroup, output
cap); this layer bounds what the agent may spend across the whole case, along
**two** axes:

* *how many* scripts it may run, and
* *what those scripts cost in tokens*.

Both counters are **global** session state so they span every deobfuscation-loop
round rather than resetting per iteration -- a hard sample that nests many packer
layers cannot escape either cap by re-entering the loop.

The token axis exists because the count alone was a proxy that was wrong by two
orders of magnitude. Measured on one sample across two runs: 49 executions cost
5.19M tokens, then 91 cost 11.6M. Neither hit the 100-execution cap, and the
second still doubled. What ends a run is not the number of scripts but the
conversation they grow, which every later stage inherits -- LESSONS_LEARNED #20
records the ILSpy stage being killed before its first tool call for exactly this
reason, while the stage that had spent the budget looked perfectly successful.

The token budget is measured from this stage's own first script, not from the
start of the run, so a sample with an expensive triage does not arrive at the
workbench with its allowance already gone.

It is wired as a ``before_tool`` callback on ``run_python``: ADK invokes it before
the tool runs, so once the cap is reached the guard returns a short-circuit result
and the sandbox is never touched again. The returned dict mirrors ``run_python``'s
result shape (a before_tool return value *is* the tool response) with a
finalize-now advisory, so the agent degrades gracefully -- dumping the best
artifact it has -- instead of being cut off mid-experiment by a silent hard kill.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from arema.runtime.sessions import SessionKeys
from reverse_engineering.tools.workbench.state import (
    RUN_PYTHON_TOOL_NAME,
    WORKBENCH_EXEC_COUNT_KEY,
    WORKBENCH_MAX_EXECUTIONS,
    WORKBENCH_MAX_TOKENS,
    WORKBENCH_TOKEN_BASELINE_KEY,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext


def _tokens_spent(getter: Callable[..., object]) -> int:
    """Total tokens this run has accumulated so far, or 0 when unknown.

    Reads the same accumulator the usage report renders from
    (``SessionKeys.MODEL_USAGE``), so the governor and the report can never
    disagree about what a run cost. Degrades to 0 rather than raising: a budget
    that cannot read usage must let work through, never block it.
    """
    acc = getter(SessionKeys.MODEL_USAGE, None)
    if not isinstance(acc, dict):
        return 0
    by_model = acc.get("by_model")
    if not isinstance(by_model, dict):
        return 0
    total = 0
    for row in by_model.values():
        if isinstance(row, dict):
            total += sum(v for v in row.values() if isinstance(v, int) and not isinstance(v, bool))
    return total


def _exhausted_result(reason: str) -> dict[str, object]:
    """A ``run_python``-shaped result telling the agent to finalize, not retry."""
    return {
        "exit_code": 1,
        "stdout": "",
        "stderr": f"run_python budget exhausted ({reason}); finalize the best artifact you have and report.",
        "truncated": False,
        "spilled_artifact_id": "",
    }


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
        return _exhausted_result(f"{WORKBENCH_MAX_EXECUTIONS} executions")

    # The token ceiling, measured from this stage's own first script rather than
    # from the start of the run -- an expensive triage must not spend the
    # workbench's allowance before it has run anything.
    spent = _tokens_spent(getter)
    raw_baseline = getter(WORKBENCH_TOKEN_BASELINE_KEY)
    if isinstance(raw_baseline, int) and not isinstance(raw_baseline, bool):
        if spent - raw_baseline >= WORKBENCH_MAX_TOKENS:
            return _exhausted_result(f"{WORKBENCH_MAX_TOKENS:,} tokens")
    else:
        setter(WORKBENCH_TOKEN_BASELINE_KEY, spent)

    setter(WORKBENCH_EXEC_COUNT_KEY, used + 1)
    return None
