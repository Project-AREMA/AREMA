"""Deterministic gate that runs the managed agentic analyst on a .NET sample de4dot
did not fully deobfuscate, within the run_python budget. The deterministic dnlib
round-trip only makes the assembly loadable, so a successful round-trip does NOT
skip this: the deep agent then runs on that loadable artifact to unpack the
compressor, reverse the string decryptor, undo obfuscation, and extract config. A
per-artifact DOTNET_DEEP_ATTEMPTED_KEY marker bounds it to one pass per LAYER: when
a pass registers a recovered inner layer, CURRENT_ARTIFACT advances and the loop
re-runs the deep pass on the new layer (multi-layer recovery). Format-exclusive
sibling of scripted_recover (spec §13.5); shares the SCRIPTED_ATTEMPTED_KEY /
evidence rail.
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
    CURRENT_ARTIFACT_KEY,
    DE4DOT_RESULT_KEY,
    DOTNET_DEEP_ATTEMPTED_KEY,
    SCRIPTED_ATTEMPTED_KEY,
)
from reverse_engineering.tools.workbench.state import (
    WORKBENCH_EXEC_COUNT_KEY,
    WORKBENCH_MAX_EXECUTIONS,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from google.adk.agents.invocation_context import InvocationContext

    from arema.runtime.agent_factory import AgentBuildContext

__all__ = ["DOTNET_SCRIPTED_RECOVER_DESCRIPTOR", "build_dotnet_scripted_recover"]


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _de4dot_recovered(raw: object) -> bool:
    """True iff de4dot fully deobfuscated the sample this round (renamed + decrypted),
    in which case there is nothing left for the deep agent to do."""
    return (
        isinstance(raw, dict)
        and raw.get("success") is True
        and raw.get("applicable") is True
        and raw.get("degraded") is False
        and raw.get("changed") is True
    )


def _should_run(state: object) -> bool:
    getter = getattr(state, "get", None)
    if not callable(getter):
        return False
    # Managed (.NET) samples only.
    if getter(SAMPLE_FORMAT_KEY) not in MANAGED_FORMATS:
        return False
    current = getter(CURRENT_ARTIFACT_KEY)
    if not isinstance(current, str):
        return False
    # Run the deep agentic pass once PER LAYER, not once per analysis: skip only if
    # it already ran on THIS artifact. When an earlier pass registered a recovered
    # inner layer, CURRENT_ARTIFACT advanced, so this re-runs on the new layer and
    # the loop drives multi-layer recovery (unpack -> retriage -> unpack again),
    # bounded by the global run_python budget and the loop's iteration cap.
    if getter(DOTNET_DEEP_ATTEMPTED_KEY) == current:
        return False
    # Skip only when de4dot already fully deobfuscated it. A dnlib metadata
    # round-trip does NOT skip this: it only makes the assembly loadable, so the
    # deep agent still runs on that loadable artifact to unpack the compressor,
    # reverse the string decryptor, undo control-flow/proxy obfuscation, and
    # extract config -- the depth a plain round-trip cannot reach.
    if _de4dot_recovered(getter(DE4DOT_RESULT_KEY)):
        return False
    # Only while the global run_python budget remains.
    return _int(getter(WORKBENCH_EXEC_COUNT_KEY)) < WORKBENCH_MAX_EXECUTIONS


class _DotnetScriptedRecoverGate(BaseAgent):
    worker: str

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        state = ctx.session.state
        if not _should_run(state):
            return
        # Mark THIS layer (the current artifact) deep-attempted, so a later loop
        # iteration re-runs the deep pass only after a new inner layer is admitted.
        getter = getattr(state, "get", None)
        current = getter(CURRENT_ARTIFACT_KEY) if callable(getter) else None
        yield Event(
            author=self.name,
            invocation_id=ctx.invocation_id,
            branch=ctx.branch,
            actions=EventActions(
                state_delta={SCRIPTED_ATTEMPTED_KEY: True, DOTNET_DEEP_ATTEMPTED_KEY: current}
            ),
        )
        worker = next(agent for agent in self.sub_agents if agent.name == self.worker)
        async with aclosing(worker.run_async(ctx)) as stream:
            async for event in stream:
                yield event


def build_dotnet_scripted_recover(context: AgentBuildContext) -> BaseAgent:
    worker = context.descriptor.metadata.get("worker")
    if not isinstance(worker, str):
        raise InvalidCapabilityDescriptorError(
            "dotnet_scripted_recover requires a 'worker' (str) metadata"
        )
    names = {agent.name for agent in context.sub_agents}
    if worker not in names:
        raise InvalidCapabilityDescriptorError(
            f"dotnet_scripted_recover worker is not among sub-agents: {worker}"
        )
    return _DotnetScriptedRecoverGate(
        name=context.descriptor.name,
        description=context.descriptor.description,
        sub_agents=list(context.sub_agents),
        worker=worker,
        after_agent_callback=list(context.after_agent),
    )


DOTNET_SCRIPTED_RECOVER_DESCRIPTOR = AgentDescriptor(
    id="dotnet_scripted_recover",
    name="dotnet_scripted_recover",
    description=(
        "Run the managed .NET agentic analyst once for a dotnet sample de4dot did "
        "not fully deobfuscate, to go DEEPER than the loadability-only dnlib "
        "round-trip (reverse the string decryptor, undo obfuscation, extract "
        "config), within budget."
    ),
    prompt_id=None,
    factory=build_dotnet_scripted_recover,
    sub_agent_ids=("dotnet_analyst",),
    metadata={"worker": "dotnet_analyst"},
)
