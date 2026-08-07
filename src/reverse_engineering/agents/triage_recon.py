"""The TriageRecon agent descriptor.

TriageRecon drives radare2 through the attached ``radare2_mcp`` toolset against
the artifact whose id it is given. It follows a strict open_file -> analyze ->
gather sequence and emits evidence-backed findings for the report generator.

It carries no ``output_schema``: schema coercion combined with tool use is an
unreliable ADK combination -- on a tool-using turn the model tends to emit
free-form (often fenced) text that coercion silently drops. Instead the
after-agent evidence normalizer parses the model's raw text through the
robust JSON-boundary loader.
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.agents.evidence_output import evidence_output_callback
from reverse_engineering.prompts.loader import load_domain_prompt

TRIAGE_EVIDENCE_KEY = "triage_evidence_json"

TRIAGE_RECON_DESCRIPTOR = AgentDescriptor(
    id="triage_recon",
    name="triage_recon",
    description=(
        "Reverse-engineering recon agent that drives radare2 through the "
        "radare2_mcp toolset to triage a binary and emit evidence-backed "
        "findings."
    ),
    prompt_id="triage_recon",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    mcp_server_ids=("radare2_mcp",),
    output_key=TRIAGE_EVIDENCE_KEY,
    after_agent_callbacks=(
        evidence_output_callback(output_key=TRIAGE_EVIDENCE_KEY, stage="triage"),
    ),
)
