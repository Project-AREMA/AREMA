"""Descriptor for the UPX recovery-tool invocation agent."""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.prompts.loader import load_domain_prompt

UPX_UNPACK_DESCRIPTOR = AgentDescriptor(
    id="upx_unpack",
    name="upx_unpack",
    description="Invoke the guarded UPX unpacking recovery tool once.",
    prompt_id="upx_unpack",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    tool_ids=("upx_unpack",),
)
