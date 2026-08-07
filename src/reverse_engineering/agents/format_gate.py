"""A deterministic format gate: run its sub-agents iff the sample format applies.

Sibling of :mod:`reverse_engineering.agents.format_router`. Where the router picks
*exactly one* engine by format, a gate runs its children *only when* the sample's
``SAMPLE_FORMAT_KEY`` is one it applies to, and yields nothing otherwise -- so no
model call is spent standing down a recovery tool that cannot apply to this
technology. Used to confine the .NET-specific deterministic recovery (de4dot,
dnlib) to managed assemblies, leaving the PE-universal tools (upx, floss) to run
for every PE as ``deobf_gate`` requires.
"""

from __future__ import annotations

from collections.abc import Iterable
from contextlib import aclosing
from typing import TYPE_CHECKING

from google.adk.agents import BaseAgent

from arema.registry.descriptors import AgentDescriptor
from arema.registry.errors import InvalidCapabilityDescriptorError
from reverse_engineering.agents.format_router import MANAGED_FORMATS
from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from google.adk.agents.invocation_context import InvocationContext
    from google.adk.events import Event

    from arema.runtime.agent_factory import AgentBuildContext

__all__ = ["DOTNET_RECOVER_DESCRIPTOR", "build_format_gate"]


class _FormatGate(BaseAgent):
    """Run every sub-agent, in order, iff the sample format is in ``applicable_formats``."""

    applicable_formats: frozenset[str]

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        getter = getattr(ctx.session.state, "get", None)
        sample_format = getter(SAMPLE_FORMAT_KEY) if callable(getter) else None
        if not isinstance(sample_format, str) or sample_format not in self.applicable_formats:
            return
        for agent in self.sub_agents:
            async with aclosing(agent.run_async(ctx)) as stream:
                async for event in stream:
                    yield event


def build_format_gate(context: AgentBuildContext) -> BaseAgent:
    """Construct the format gate from a resolved build context.

    ``metadata`` carries an ``applicable_formats`` iterable of sample-format
    strings; the gate opens only for those formats.
    """
    raw = context.descriptor.metadata.get("applicable_formats")
    if not isinstance(raw, Iterable) or isinstance(raw, str | bytes):
        raise InvalidCapabilityDescriptorError(
            "format gate requires an 'applicable_formats' iterable of str metadata"
        )
    formats = tuple(raw)
    if not formats or not all(isinstance(item, str) for item in formats):
        raise InvalidCapabilityDescriptorError(
            "format gate 'applicable_formats' must be a non-empty iterable of str"
        )
    return _FormatGate(
        name=context.descriptor.name,
        description=context.descriptor.description,
        sub_agents=list(context.sub_agents),
        applicable_formats=frozenset(item for item in formats if isinstance(item, str)),
        after_agent_callback=list(context.after_agent),
    )


# The .NET-specific deterministic recovery tools. de4dot deobfuscates a managed
# assembly and the dnlib metadata round-trip makes it loadable; both self-gate on
# `SAMPLE_FORMAT_KEY == "dotnet"`, so on any other format they would only no-op
# after their model turn. This gate skips them for non-managed samples entirely.
# The PE-universal tools (upx, floss) stay direct children of `recover` -- a
# UPX-packed .NET assembly still needs upx, and deobf_gate mandates upx+floss ran.
DOTNET_RECOVER_DESCRIPTOR = AgentDescriptor(
    id="dotnet_recover",
    name="dotnet_recover",
    description=(
        "Run the .NET-specific deterministic recovery (de4dot, then dnlib) only for "
        "a managed .NET assembly; native and other formats skip it."
    ),
    prompt_id=None,
    factory=build_format_gate,
    sub_agent_ids=("de4dot_deobfuscate", "dnlib_roundtrip"),
    metadata={"applicable_formats": sorted(MANAGED_FORMATS)},
)
