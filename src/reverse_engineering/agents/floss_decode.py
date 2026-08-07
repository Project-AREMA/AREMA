"""Descriptor for the FLOSS recovery-tool invocation agent."""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.prompts.loader import load_domain_prompt

FLOSS_DECODE_DESCRIPTOR = AgentDescriptor(
    id="floss_decode",
    name="floss_decode",
    description="Invoke the guarded FLOSS decoding recovery tool once.",
    prompt_id="floss_decode",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    tool_ids=("floss_decode",),
)
