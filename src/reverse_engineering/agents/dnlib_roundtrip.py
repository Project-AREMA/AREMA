"""Descriptor for the deterministic dnlib metadata-roundtrip recovery-tool agent.

First-pass .NET recovery in the recover chain, after de4dot: it invokes the
guarded ``dnlib_roundtrip`` tool once. The tool does the deterministic work (no
model writes code), so the agentic ``dotnet_analyst`` is left only for the harder
protections the round-trip does not resolve.
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.prompts.loader import load_domain_prompt

DNLIB_ROUNDTRIP_DESCRIPTOR = AgentDescriptor(
    id="dnlib_roundtrip",
    name="dnlib_roundtrip",
    description="Invoke the guarded dnlib metadata-roundtrip .NET recovery tool once.",
    prompt_id="dnlib_roundtrip",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    tool_ids=("dnlib_roundtrip",),
)
