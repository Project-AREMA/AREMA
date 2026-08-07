"""Fall back to Ghidra when the managed decompiler produced nothing.

A .NET assembly is a real PE file. That is not a technicality -- it is the whole
justification for this stage:

    "native methods, while not visible in a .NET decompiler, [are] perfectly
    visible in any other native decompiler and debugger"
    -- washi.dev, "Common misconceptions about .NET binaries"

Mixed-mode assemblies (C++/CLI) and protectors that move method bodies to native
code (ConfuserEx among them) put real behaviour where ILSpy cannot look, by
construction rather than by failure. So Ghidra reaching a managed sample is not a
consolation prize for a broken decompiler; it is the only tool that can see that
layer at all.

The pivot is deterministic and it fires on *evidence*, not on a model's opinion.
Three reasons the managed leg can come back empty, and all three want the same
answer -- look at the bytes:

1. ILSpy was never attached (the MCP server was unreachable, so the toolset
   resolved to an empty list and the agent had nothing to call);
2. ILSpy ran and the assembly resisted it (packed, protected, corrupt metadata);
3. the stage was cut short before it called anything, which is what a context
   budget exhausted by an earlier agentic stage looks like from here.

A sample the managed leg handled cleanly skips this entirely, so the common case
costs nothing.

The native leg writes its own ``native_evidence_json`` stage rather than
overwriting ``deep_evidence_json``. Same reasoning as
``android_native_analysis``: the critic unions every stage, so an ILSpy envelope
that carried *some* evidence keeps it, and the two legs never contend for one
slot.
"""

from __future__ import annotations

from contextlib import aclosing
from typing import TYPE_CHECKING

from google.adk.agents import BaseAgent

from arema.core.logging import get_logger
from arema.registry.descriptors import AgentDescriptor
from arema.registry.errors import InvalidCapabilityDescriptorError
from arema.runtime.agent_factory import build_sequential_agent
from reverse_engineering.evidence_envelope import parse_evidence_envelope
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY
from reverse_engineering.tools.ghidra.coverage import DEEP_EVIDENCE_KEY

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from google.adk.agents.invocation_context import InvocationContext
    from google.adk.events import Event

    from arema.runtime.agent_factory import AgentBuildContext

logger = get_logger(__name__)

__all__ = [
    "DOTNET_DEEP_ANALYSIS_DESCRIPTOR",
    "DOTNET_NATIVE_PIVOT_DESCRIPTOR",
    "build_dotnet_native_pivot",
    "managed_evidence_is_empty",
]


def managed_evidence_is_empty(state: object) -> bool:
    """Whether the managed leg left anything worth having. Never raises.

    Fails *toward* the pivot: unreadable or absent evidence means Ghidra runs.
    The cost of a needless native pass is some tokens; the cost of skipping it
    when it was needed is a report that says the sample could not be analysed
    while an untouched PE sits in the store.
    """
    getter = getattr(state, "get", None)
    if not callable(getter):
        return True
    raw = getter(DEEP_EVIDENCE_KEY)
    if raw is None or raw == "":
        return True
    artifact_id = getter(CURRENT_ARTIFACT_KEY)
    if not isinstance(artifact_id, str) or not artifact_id:
        return True
    try:
        envelope = parse_evidence_envelope(raw, artifact_id=artifact_id)
    except Exception:
        return True
    return not envelope.findings


class _DotnetNativePivotGate(BaseAgent):
    """Stream the native worker only when the managed leg came back empty."""

    worker: str

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        if not managed_evidence_is_empty(ctx.session.state):
            return
        logger.info("managed decompilation produced no findings; pivoting to native analysis")
        worker = next(agent for agent in self.sub_agents if agent.name == self.worker)
        async with aclosing(worker.run_async(ctx)) as stream:
            async for event in stream:
                yield event


def build_dotnet_native_pivot(context: AgentBuildContext) -> BaseAgent:
    """Build the pivot gate, validating its worker against the sub-agent set."""
    worker = context.descriptor.metadata.get("worker")
    if not isinstance(worker, str):
        raise InvalidCapabilityDescriptorError(
            "dotnet_native_pivot requires a 'worker' (str) metadata"
        )
    names = {agent.name for agent in context.sub_agents}
    if worker not in names:
        raise InvalidCapabilityDescriptorError(
            f"dotnet_native_pivot worker is not among sub-agents: {worker}"
        )
    return _DotnetNativePivotGate(
        name=context.descriptor.name,
        description=context.descriptor.description,
        sub_agents=list(context.sub_agents),
        worker=worker,
        after_agent_callback=list(context.after_agent),
    )


DOTNET_NATIVE_PIVOT_DESCRIPTOR = AgentDescriptor(
    id="dotnet_native_pivot",
    name="dotnet_native_pivot",
    description=(
        "Run Ghidra over a .NET assembly as a PE when the managed decompiler "
        "produced no findings -- ILSpy unavailable, defeated by a protector, or "
        "cut short. Skips entirely when managed evidence exists."
    ),
    prompt_id=None,
    factory=build_dotnet_native_pivot,
    sub_agent_ids=("dotnet_native_analysis",),
    metadata={"worker": "dotnet_native_analysis"},
)

DOTNET_DEEP_ANALYSIS_DESCRIPTOR = AgentDescriptor(
    id="dotnet_deep_analysis",
    name="dotnet_deep_analysis",
    description=(
        "Composite .NET deep analysis: ILSpy over the managed metadata, then "
        "Ghidra over the PE when the managed leg produced nothing."
    ),
    prompt_id=None,
    factory=build_sequential_agent,
    runtime_profile_id="safe_default",
    sub_agent_ids=("dotnet_decompile", "dotnet_native_pivot"),
)
