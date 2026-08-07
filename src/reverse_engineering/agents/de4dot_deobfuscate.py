"""Descriptor for the de4dot .NET-deobfuscation recovery-tool agent."""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.prompts.loader import load_domain_prompt

DE4DOT_DEOBFUSCATE_DESCRIPTOR = AgentDescriptor(
    id="de4dot_deobfuscate",
    name="de4dot_deobfuscate",
    description="Invoke the guarded de4dot .NET-deobfuscation recovery tool once.",
    prompt_id="de4dot_deobfuscate",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    tool_ids=("de4dot_deobfuscate",),
)
