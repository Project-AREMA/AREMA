"""The EvidenceCritic agent descriptor.

EvidenceCritic is the consistency gate near the end of the analysis chain. It
receives triage, deobfuscation-retriage, and deep-decompilation findings,
rejects findings that cite no real tool or invent evidence, validates recovery
provenance, and passes only the supported subset to the report generator. It
holds no tools of its own.

It carries no ``output_schema``. This is the same constraint LESSONS_LEARNED #13
records for tool-using agents, but the cause is not tool use: the provider fences
its JSON (```json ...```) even when ADK sets ``response_mime_type`` to
``application/json`` and passes a ``response_schema``. ADK coerces the raw text
with ``model_validate_json``, which cannot see through a fence, so the stage's
output was dropped and its evidence became ``<stage>:evidence_envelope_invalid``.
The after-agent normalizer below parses the model text through the robust
``loads_model_json`` boundary, which handles fences, so it owns parsing instead.
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.agents.evidence_output import (
    VALIDATED_EVIDENCE_KEY,
    normalize_critic_output,
)
from reverse_engineering.prompts.loader import load_domain_prompt

EVIDENCE_CRITIC_DESCRIPTOR = AgentDescriptor(
    id="evidence_critic",
    name="evidence_critic",
    description=(
        "Consistency gate that validates every finding cites a real tool and is "
        "supported by its cited evidence. Rejects unsupported claims and merges "
        "every upstream limitation into coverage before the report is rendered."
    ),
    prompt_id="evidence_critic",
    factory=build_llm_agent,
    runtime_profile_id="evidence_isolated",
    prompt_loader=load_domain_prompt,
    output_key=VALIDATED_EVIDENCE_KEY,
    after_agent_callbacks=(normalize_critic_output,),
)
