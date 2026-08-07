"""Descriptor for rebuilding a post-recovery reverse-engineering snapshot."""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.prompts.loader import load_domain_prompt
from reverse_engineering.tools.deobfuscation.state import RETRIAGE_SNAPSHOT_KEY

RETRIAGE_DESCRIPTOR = AgentDescriptor(
    id="retriage",
    name="retriage",
    description="Re-triage the current recovered artifact into a bounded snapshot.",
    prompt_id="retriage",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    tool_ids=("prepare_sandbox",),
    mcp_server_ids=("radare2_mcp",),
    output_key=RETRIAGE_SNAPSHOT_KEY,
)
