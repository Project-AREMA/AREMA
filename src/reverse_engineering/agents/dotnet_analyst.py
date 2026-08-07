"""Descriptor for the managed (.NET) agentic-deobfuscation analyst."""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.prompts.loader import load_domain_prompt

DOTNET_ANALYST_DESCRIPTOR = AgentDescriptor(
    id="dotnet_analyst",
    name="dotnet_analyst",
    description=(
        "Reason about a protected .NET/CLR assembly and use de4dot + dnlib in the "
        "workbench to recover a loadable, deobfuscated assembly."
    ),
    prompt_id="dotnet_analyst",
    factory=build_llm_agent,
    runtime_profile_id="re_deep_agentic",
    prompt_loader=load_domain_prompt,
    tool_ids=("run_python", "register_unpacked_artifact"),
)
