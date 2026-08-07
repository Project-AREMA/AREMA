"""Deterministic deep-analysis engine router, keyed on the sample's format.

A native binary (``pe`` / ``elf`` / ``macho`` / ``unknown``) decompiles through
Ghidra (the ``deep_analysis`` loop); a managed .NET/CIL assembly decompiles
through ILSpy (``dotnet_decompile``); a JVM/Android container (``apk`` / ``dex`` /
``jar``) goes to the composite ``java_deep_analysis`` route (jadx over the DEX,
then Ghidra over one ABI's native ``.so``). The container format is
decided deterministically at ingest (:data:`SAMPLE_FORMAT_KEY`) and read from
session state here, so exactly one engine runs. No model call is spent standing
the other engines down, and the Ghidra loop never spins to its cap on a sample it
cannot read. Every engine writes the same ``deep_evidence_json`` slot, so each
downstream stage is engine-agnostic.

The routing table is a ``format -> engine`` map plus a ``default_engine`` for any
format not named, so a new engine is added by extending the map -- never by
threading another branch through the run loop.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import aclosing
from typing import TYPE_CHECKING

from google.adk.agents import BaseAgent

from arema.registry.descriptors import AgentDescriptor
from arema.registry.errors import InvalidCapabilityDescriptorError
from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from google.adk.agents.invocation_context import InvocationContext
    from google.adk.events import Event

    from arema.runtime.agent_factory import AgentBuildContext

__all__ = [
    "DEEP_ENGINE_ROUTER_DESCRIPTOR",
    "JVM_FORMATS",
    "MANAGED_FORMATS",
    "build_format_router",
]

# The container formats that decompile as managed code (ILSpy), not native
# machine code (Ghidra). Public so sibling stages (e.g. scripted_recover) share
# one "is managed" source. Extend alongside a new managed engine, never per sample.
MANAGED_FORMATS = frozenset({"dotnet"})

# The container formats that decompile as JVM bytecode / Android packages (jadx).
JVM_FORMATS = frozenset({"apk", "dex", "jar"})


class _FormatRouter(BaseAgent):
    """Run exactly one sub-agent, chosen by the sample format in session state."""

    format_engines: dict[str, str]  # sample format -> sub-agent name
    default_engine: str  # sub-agent name for any format not in the map

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        state = ctx.session.state
        getter = getattr(state, "get", None)
        sample_format = getter(SAMPLE_FORMAT_KEY) if callable(getter) else None
        target = self.default_engine
        if isinstance(sample_format, str):
            target = self.format_engines.get(sample_format, self.default_engine)
        engine = next(agent for agent in self.sub_agents if agent.name == target)
        async with aclosing(engine.run_async(ctx)) as stream:
            async for event in stream:
                yield event


def _coerce_engine_map(raw: object) -> dict[str, str]:
    """Read a ``format -> engine`` mapping from descriptor metadata, or raise."""
    if not isinstance(raw, Mapping) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in raw.items()
    ):
        raise InvalidCapabilityDescriptorError(
            "format router requires a 'format_engines' mapping of str -> str metadata"
        )
    return {str(key): str(value) for key, value in raw.items()}


def build_format_router(context: AgentBuildContext) -> BaseAgent:
    """Construct the deterministic format router from a resolved build context.

    ``metadata`` carries a ``format_engines`` map (sample format -> sub-agent name)
    and a ``default_engine`` naming the fallback engine. Every named engine -- the
    mapped ones and the default -- must be among the built sub-agents, or the
    descriptor is invalid.
    """
    metadata = context.descriptor.metadata
    format_engines = _coerce_engine_map(metadata.get("format_engines"))
    default_engine = metadata.get("default_engine")
    if not isinstance(default_engine, str):
        raise InvalidCapabilityDescriptorError(
            "format router requires a 'default_engine' (str) metadata value"
        )
    names = {agent.name for agent in context.sub_agents}
    referenced = set(format_engines.values()) | {default_engine}
    unknown = referenced - names
    if unknown:
        raise InvalidCapabilityDescriptorError(
            f"format router routes to unknown sub-agents: {sorted(unknown)}"
        )
    return _FormatRouter(
        name=context.descriptor.name,
        description=context.descriptor.description,
        sub_agents=list(context.sub_agents),
        format_engines=format_engines,
        default_engine=default_engine,
        after_agent_callback=list(context.after_agent),
    )


DEEP_ENGINE_ROUTER_DESCRIPTOR = AgentDescriptor(
    id="deep_engine_router",
    name="deep_engine_router",
    description=(
        "Route deep analysis to Ghidra (native binaries), ILSpy (managed .NET "
        "assemblies), or jadx (JVM/Android packages) according to the container "
        "format decided at ingest."
    ),
    prompt_id=None,
    factory=build_format_router,
    sub_agent_ids=("deep_analysis", "dotnet_deep_analysis", "java_deep_analysis"),
    metadata={
        "format_engines": {
            "dotnet": "dotnet_deep_analysis",
            "apk": "java_deep_analysis",
            "dex": "java_deep_analysis",
            "jar": "java_deep_analysis",
        },
        "default_engine": "deep_analysis",
    },
)
