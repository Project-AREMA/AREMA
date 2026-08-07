"""The AndroidTriage agent descriptor.

AndroidTriage triages an ``apk`` / ``dex`` / ``jar`` sample by driving androguard
through the attached ``android_triage_scan`` tool (one sandboxed androguard pass,
never in the AREMA process). It mirrors :mod:`triage_recon` -- the native/.NET
recon agent -- writing to the same ``triage_evidence_json`` slot through the same
``evidence_output_callback(stage="triage")``, so the format-routed ``triage_router``
can select either engine transparently.

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
from reverse_engineering.agents.triage_recon import TRIAGE_EVIDENCE_KEY
from reverse_engineering.prompts.loader import load_domain_prompt

ANDROID_TRIAGE_DESCRIPTOR = AgentDescriptor(
    id="android_triage",
    name="android_triage",
    description=(
        "Android/JVM triage agent that drives androguard through the "
        "android_triage_scan tool to triage an apk/dex/jar sample and emit "
        "evidence-backed findings."
    ),
    prompt_id="android_triage",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    tool_ids=("android_triage_scan",),
    output_key=TRIAGE_EVIDENCE_KEY,
    after_agent_callbacks=(
        evidence_output_callback(output_key=TRIAGE_EVIDENCE_KEY, stage="triage"),
    ),
)
