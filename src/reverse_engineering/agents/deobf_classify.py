"""Descriptor for tool-less deobfuscation classification."""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.prompts.loader import load_domain_prompt
from reverse_engineering.tools.deobfuscation.state import CLASSIFICATION_KEY

DEOBF_CLASSIFY_DESCRIPTOR = AgentDescriptor(
    id="deobf_classify",
    name="deobf_classify",
    description="Classify likely obfuscation from prior triage findings.",
    prompt_id="deobf_classify",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    output_key=CLASSIFICATION_KEY,
)
