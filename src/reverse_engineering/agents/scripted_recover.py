"""Deterministic gate that runs the scripted packer-analysis agent when — and only
when — the current artifact is a native ``packed-other`` sample the cheap
deterministic tools did not recover this round, and the global ``run_python``
budget remains. Modeled on :mod:`reverse_engineering.agents.format_router`: a
``BaseAgent`` reads session state and conditionally delegates to one sub-agent, so
the LLM never decides whether recovery runs (spec §11.3). When it opens, it records
``SCRIPTED_ATTEMPTED_KEY`` via a tracked state delta so ``deobf_gate`` can emit an
honest ``recovery:scripted_unavailable`` limitation if nothing is recovered.
"""

from __future__ import annotations

from contextlib import aclosing
from typing import TYPE_CHECKING

from google.adk.agents import BaseAgent
from google.adk.events import Event, EventActions

from arema.registry.descriptors import AgentDescriptor
from arema.registry.errors import InvalidCapabilityDescriptorError
from reverse_engineering.agents.format_router import MANAGED_FORMATS
from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY
from reverse_engineering.tools.deobfuscation.state import (
    FLOSS_COUNT_KEY,
    SCRIPTED_ATTEMPTED_KEY,
    UPX_CHANGED_KEY,
    parse_current_classification,
)
from reverse_engineering.tools.workbench.state import (
    WORKBENCH_EXEC_COUNT_KEY,
    WORKBENCH_MAX_EXECUTIONS,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from google.adk.agents.invocation_context import InvocationContext

    from arema.runtime.agent_factory import AgentBuildContext

__all__ = ["SCRIPTED_RECOVER_DESCRIPTOR", "build_scripted_recover"]


def _int(value: object) -> int:
    """A nonnegative-int reading that treats junk (and bool) as zero."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _should_run(state: object) -> bool:
    """All four gate preconditions (spec §11.3), failing safe on malformed state."""
    getter = getattr(state, "get", None)
    if not callable(getter):
        return False
    # Native formats only; .NET/CLR is the Phase 2 companion path.
    if getter(SAMPLE_FORMAT_KEY) in MANAGED_FORMATS:
        return False
    # Only a native ``packed-other`` classification; skip safely on bad state.
    try:
        plan = parse_current_classification(state)
    except ValueError:
        return False
    if plan.obf_class != "packed-other":
        return False
    # Only when the cheap deterministic tools recovered nothing this round —
    # otherwise let the loop recurse and re-classify the recovered artifact first.
    if getter(UPX_CHANGED_KEY) is True or _int(getter(FLOSS_COUNT_KEY)) > 0:
        return False
    # Only while the global run_python execution budget remains.
    return _int(getter(WORKBENCH_EXEC_COUNT_KEY)) < WORKBENCH_MAX_EXECUTIONS


class _ScriptedRecoverGate(BaseAgent):
    """Run the worker agent iff the scripted-recovery preconditions hold."""

    worker: str  # the sub-agent name to delegate to when the gate opens

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        if not _should_run(ctx.session.state):
            return
        # Record the attempt before the worker runs, via a tracked state delta, so
        # deobf_gate can distinguish "scripted tried and failed" from "never tried".
        yield Event(
            author=self.name,
            invocation_id=ctx.invocation_id,
            branch=ctx.branch,
            actions=EventActions(state_delta={SCRIPTED_ATTEMPTED_KEY: True}),
        )
        worker = next(agent for agent in self.sub_agents if agent.name == self.worker)
        async with aclosing(worker.run_async(ctx)) as stream:
            async for event in stream:
                yield event


def build_scripted_recover(context: AgentBuildContext) -> BaseAgent:
    """Construct the deterministic scripted-recovery gate from a build context."""
    worker = context.descriptor.metadata.get("worker")
    if not isinstance(worker, str):
        raise InvalidCapabilityDescriptorError(
            "scripted_recover requires a 'worker' (str) metadata"
        )
    names = {agent.name for agent in context.sub_agents}
    if worker not in names:
        raise InvalidCapabilityDescriptorError(
            f"scripted_recover worker is not among sub-agents: {worker}"
        )
    return _ScriptedRecoverGate(
        name=context.descriptor.name,
        description=context.descriptor.description,
        sub_agents=list(context.sub_agents),
        worker=worker,
        after_agent_callback=list(context.after_agent),
    )


SCRIPTED_RECOVER_DESCRIPTOR = AgentDescriptor(
    id="scripted_recover",
    name="scripted_recover",
    description=(
        "Conditionally run the scripted packer-analysis agent on a native "
        "packed-other artifact the cheap tools did not recover, within budget."
    ),
    prompt_id=None,
    factory=build_scripted_recover,
    sub_agent_ids=("packer_analyst",),
    metadata={"worker": "packer_analyst"},
)
