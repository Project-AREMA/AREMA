"""Descriptor for the scripted static-unpacking agent."""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.prompts.loader import load_domain_prompt

PACKER_ANALYST_DESCRIPTOR = AgentDescriptor(
    id="packer_analyst",
    name="packer_analyst",
    description=(
        "Statically reverse-engineer a native packer's unpacking stub and "
        "reimplement its transform in Python to recover the original payload."
    ),
    prompt_id="packer_analyst",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    # prepare_sandbox for the same reason triage_recon carries it: this stage
    # runs deep in the deobfuscation loop, minutes after intake opened the
    # radare2 tunnel, and must be able to re-establish it rather than silently
    # losing its toolset (LESSONS_LEARNED #6).
    tool_ids=("prepare_sandbox", "run_python", "register_unpacked_artifact"),
    mcp_server_ids=("radare2_mcp",),
)
