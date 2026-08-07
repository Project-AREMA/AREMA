"""The ReportGenerator agent descriptor.

ReportGenerator renders the final report strictly from the evidence-backed
findings produced by TriageRecon. It holds no tools of its own and never
invents findings.
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.prompts.loader import load_domain_prompt

REPORT_GENERATOR_DESCRIPTOR = AgentDescriptor(
    id="report_generator",
    name="report_generator",
    description=(
        "Evidence-ledger report agent that renders the final reverse-engineering "
        "report strictly from the findings produced by TriageRecon."
    ),
    prompt_id="report_generator",
    factory=build_llm_agent,
    runtime_profile_id="safe_default",
    prompt_loader=load_domain_prompt,
)
