"""Descriptor for fixed-order binary recovery."""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_sequential_agent

# upx and floss are PE-universal (upx unpacks any UPX-packed PE, incl. a UPX-packed
# .NET assembly; floss recovers strings from any PE), so they are direct children
# that run for every sample -- deobf_gate mandates both ran each iteration. The
# .NET-specific tools (de4dot, dnlib) sit behind the `dotnet_recover` format gate,
# which runs them only for a managed assembly and skips them (no model turn) for
# native samples. Effective order for a .NET assembly is unchanged: upx, floss,
# de4dot, dnlib.
RECOVER_DESCRIPTOR = AgentDescriptor(
    id="recover",
    name="recover",
    description="Run PE recovery (UPX, FLOSS) then .NET-gated recovery (de4dot, dnlib).",
    prompt_id=None,
    factory=build_sequential_agent,
    sub_agent_ids=("upx_unpack", "floss_decode", "dotnet_recover"),
)
