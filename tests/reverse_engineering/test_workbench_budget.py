"""The per-case run_python execution budget guard (the resource governor).

The guard is the loop-level half of the §4.5 two-layer governor: a before_tool
callback on a global session-state counter that caps total ``run_python``
executions per case and, once the cap is reached, short-circuits the tool with a
finalize advisory instead of ever running the sandbox again. These tests pin the
count-then-block behavior, that the descriptor carries the guard, that the guard
actually reaches the agent's composed ``before_tool`` chain (not merely the
descriptor) and short-circuits the over-budget call end-to-end, and that both
workbench tools are inside the SanitizationMembrane's binary-origin set.
"""

from __future__ import annotations

from arema.runtime.sessions import SessionKeys
from reverse_engineering.tools.workbench.budget import run_python_budget_guard
from reverse_engineering.tools.workbench.state import (
    WORKBENCH_EXEC_COUNT_KEY,
    WORKBENCH_MAX_EXECUTIONS,
    WORKBENCH_MAX_TOKENS,
    WORKBENCH_TOKEN_BASELINE_KEY,
)


class _State(dict[str, object]):
    """A minimal ADK-State stand-in: duck-typed on .get / __setitem__."""


def test_guard_counts_and_then_short_circuits() -> None:
    state = _State()
    ctx = type("C", (), {"state": state})()
    tool = type("T", (), {"name": "run_python"})()
    for _ in range(WORKBENCH_MAX_EXECUTIONS):
        assert run_python_budget_guard(tool, {}, ctx) is None
    blocked = run_python_budget_guard(tool, {}, ctx)
    assert isinstance(blocked, dict)
    assert "budget" in str(blocked["stderr"]).lower()
    # The block never increments past the cap: the last call short-circuited.
    assert state[WORKBENCH_EXEC_COUNT_KEY] == WORKBENCH_MAX_EXECUTIONS


def test_short_circuit_matches_run_python_result_shape() -> None:
    state = _State()
    state[WORKBENCH_EXEC_COUNT_KEY] = WORKBENCH_MAX_EXECUTIONS
    ctx = type("C", (), {"state": state})()
    tool = type("T", (), {"name": "run_python"})()
    blocked = run_python_budget_guard(tool, {}, ctx)
    assert isinstance(blocked, dict)
    # A before_tool short-circuit becomes the tool response verbatim, so it must
    # carry every key the model expects from a real run_python result.
    assert set(blocked) == {"exit_code", "stdout", "stderr", "truncated", "spilled_artifact_id"}


def test_guard_ignores_foreign_tools() -> None:
    """The guard is per-tool: attached to run_python but flattened into the agent's
    ONE before_tool chain (which ADK runs before every tool), it must leave calls
    to OTHER tools uncounted and un-short-circuited -- or run_python's budget would
    be consumed by cheap register/radare2 calls and a non-run_python call would get
    a nonsensical run_python-shaped response."""
    state = _State()
    # Pre-charge the counter to the cap: a foreign tool must STILL not be blocked.
    state[WORKBENCH_EXEC_COUNT_KEY] = WORKBENCH_MAX_EXECUTIONS
    ctx = type("C", (), {"state": state})()
    for name in ("register_unpacked_artifact", "list_strings", "ghidra_decompile"):
        foreign = type("T", (), {"name": name})()
        for _ in range(WORKBENCH_MAX_EXECUTIONS + 3):
            assert run_python_budget_guard(foreign, {}, ctx) is None
    # No foreign call charged or moved the counter.
    assert state[WORKBENCH_EXEC_COUNT_KEY] == WORKBENCH_MAX_EXECUTIONS


def test_run_python_descriptor_has_the_budget_guard() -> None:
    from reverse_engineering.tools.workbench.run_python import RUN_PYTHON_TOOL

    assert run_python_budget_guard in RUN_PYTHON_TOOL.callbacks.before


def test_budget_guard_reaches_the_agents_before_tool_chain() -> None:
    """The guard is a before_tool callback only if the runtime actually consumes
    ``ToolDescriptor.callbacks.before``. Attaching it to the descriptor is not
    enough -- this composes the REAL chain the agent runs and asserts the guard
    lands in ``before_tool`` (and the guard-first invariant still holds)."""
    from arema.runtime.callbacks.chain import build_callback_chain
    from arema.runtime.callbacks.tool_guard import registered_tool_guard
    from arema.runtime.services import RuntimeServices
    from reverse_engineering.profiles import RE_GUARDED_PROFILE
    from reverse_engineering.tools.workbench.run_python import RUN_PYTHON_TOOL

    chain = build_callback_chain(
        RE_GUARDED_PROFILE,
        services=RuntimeServices.default(),
        tools={RUN_PYTHON_TOOL.id: RUN_PYTHON_TOOL},
    )
    assert run_python_budget_guard in chain.before_tool
    # The registered-tool guard must stay first; the budget guard is appended after.
    assert chain.before_tool[0] is registered_tool_guard


def test_composed_before_tool_chain_refuses_the_over_budget_call() -> None:
    """Drive the REAL composed before_tool chain (as ADK does: walk it, stop at
    the first non-None return, which becomes the tool response without invoking
    the tool). The (cap+1)th call must short-circuit with the finalize advisory,
    proving the governor is enforced end-to-end -- not merely attached."""
    from types import SimpleNamespace

    from arema.runtime.callbacks.chain import build_callback_chain
    from arema.runtime.services import RuntimeServices
    from reverse_engineering.profiles import RE_GUARDED_PROFILE
    from reverse_engineering.tools.workbench.run_python import RUN_PYTHON_TOOL

    chain = build_callback_chain(
        RE_GUARDED_PROFILE,
        services=RuntimeServices.default(),
        tools={RUN_PYTHON_TOOL.id: RUN_PYTHON_TOOL},
    )
    state = _State()
    tool = SimpleNamespace(name="run_python")
    ctx = SimpleNamespace(state=state, function_call_id="call-1")

    def drive() -> object:
        for callback in chain.before_tool:
            result = callback(tool=tool, args={}, tool_context=ctx)
            if result is not None:
                return result
        return None

    for _ in range(WORKBENCH_MAX_EXECUTIONS):
        assert drive() is None
    blocked = drive()
    assert isinstance(blocked, dict)
    assert "budget" in str(blocked["stderr"]).lower()
    # The over-budget call short-circuited before charging a 41st execution.
    assert state[WORKBENCH_EXEC_COUNT_KEY] == WORKBENCH_MAX_EXECUTIONS


def test_workbench_tools_are_sanitized() -> None:
    from reverse_engineering.profiles import _BINARY_ORIGIN_TOOLS

    assert {"run_python", "register_unpacked_artifact"} <= _BINARY_ORIGIN_TOOLS


# --- the token axis -----------------------------------------------------------
#
# The execution cap counts scripts and says nothing about what they cost, which
# is a proxy that was wrong by two orders of magnitude. Measured on one sample
# across two runs: 49 executions cost 5.19M tokens, then 91 cost 11.6M. Neither
# hit the 100-execution cap. What ends a run is the conversation those scripts
# grow, which every later stage inherits -- LESSONS_LEARNED #20.


def _usage(total: int) -> dict[str, object]:
    """A MODEL_USAGE accumulator carrying `total` tokens, in the real shape."""
    return {
        "run_id": "r1",
        "by_model": {"m": {"input": total, "cached": 0, "output": 0, "thinking": 0}},
    }


def _ctx(state: _State) -> object:
    return type("C", (), {"state": state})()


_TOOL = type("T", (), {"name": "run_python"})()


def test_the_first_script_snapshots_a_baseline_rather_than_charging_the_run() -> None:
    """An expensive triage must not arrive at the workbench having already spent
    its allowance -- the ceiling measures this stage's own work."""
    state = _State({SessionKeys.MODEL_USAGE: _usage(3_000_000)})

    assert run_python_budget_guard(_TOOL, {}, _ctx(state)) is None
    assert state[WORKBENCH_TOKEN_BASELINE_KEY] == 3_000_000


def test_spend_below_the_ceiling_proceeds() -> None:
    state = _State({SessionKeys.MODEL_USAGE: _usage(1_000_000)})
    run_python_budget_guard(_TOOL, {}, _ctx(state))  # baseline at 1M

    state[SessionKeys.MODEL_USAGE] = _usage(1_000_000 + WORKBENCH_MAX_TOKENS - 1)

    assert run_python_budget_guard(_TOOL, {}, _ctx(state)) is None


def test_spend_at_the_ceiling_short_circuits() -> None:
    state = _State({SessionKeys.MODEL_USAGE: _usage(1_000_000)})
    run_python_budget_guard(_TOOL, {}, _ctx(state))

    state[SessionKeys.MODEL_USAGE] = _usage(1_000_000 + WORKBENCH_MAX_TOKENS)
    blocked = run_python_budget_guard(_TOOL, {}, _ctx(state))

    assert blocked is not None
    assert "tokens" in str(blocked["stderr"])
    assert "finalize" in str(blocked["stderr"])


def test_the_token_block_matches_run_python_result_shape() -> None:
    """A before_tool return value IS the tool response, so a wrong shape would
    reach the model as a malformed result rather than an advisory."""
    state = _State({SessionKeys.MODEL_USAGE: _usage(0)})
    run_python_budget_guard(_TOOL, {}, _ctx(state))
    state[SessionKeys.MODEL_USAGE] = _usage(WORKBENCH_MAX_TOKENS)
    blocked = run_python_budget_guard(_TOOL, {}, _ctx(state))

    assert set(blocked) == {"exit_code", "stdout", "stderr", "truncated", "spilled_artifact_id"}
    assert blocked["exit_code"] == 1


def test_both_observed_healthy_runs_stay_under_the_ceiling() -> None:
    """The ceiling is a backstop, not a routine limit. Truncating work that was
    going to succeed would be a worse failure than the one being fixed."""
    for measured in (5_190_000, 11_642_265):
        state = _State({SessionKeys.MODEL_USAGE: _usage(0)})
        run_python_budget_guard(_TOOL, {}, _ctx(state))
        state[SessionKeys.MODEL_USAGE] = _usage(measured)

        assert run_python_budget_guard(_TOOL, {}, _ctx(state)) is None, measured


def test_a_runaway_beyond_the_next_doubling_is_stopped() -> None:
    """11.6M doubling again is the case this exists for."""
    state = _State({SessionKeys.MODEL_USAGE: _usage(0)})
    run_python_budget_guard(_TOOL, {}, _ctx(state))
    state[SessionKeys.MODEL_USAGE] = _usage(11_642_265 * 2)

    assert run_python_budget_guard(_TOOL, {}, _ctx(state)) is not None


def test_unreadable_usage_lets_work_through_rather_than_blocking_it() -> None:
    """A governor that cannot read usage must fail open. Blocking on missing
    telemetry would turn an observability gap into a stalled analysis."""
    for acc in (None, "junk", {}, {"by_model": "junk"}, {"by_model": {"m": "junk"}}):
        state = _State({SessionKeys.MODEL_USAGE: acc})
        assert run_python_budget_guard(_TOOL, {}, _ctx(state)) is None


def test_the_execution_cap_still_applies_independently() -> None:
    """Two axes, either of which can stop the stage."""
    state = _State(
        {SessionKeys.MODEL_USAGE: _usage(0), WORKBENCH_EXEC_COUNT_KEY: WORKBENCH_MAX_EXECUTIONS}
    )
    blocked = run_python_budget_guard(_TOOL, {}, _ctx(state))

    assert blocked is not None
    assert "executions" in str(blocked["stderr"])


def test_a_foreign_tool_neither_charges_nor_snapshots() -> None:
    state = _State({SessionKeys.MODEL_USAGE: _usage(9_000_000)})
    other = type("T", (), {"name": "ghidra_decompile"})()

    assert run_python_budget_guard(other, {}, _ctx(state)) is None
    assert WORKBENCH_TOKEN_BASELINE_KEY not in state
    assert WORKBENCH_EXEC_COUNT_KEY not in state
