"""Deterministic triage engine router, keyed on the sample's container format.

A native binary or managed .NET assembly (``pe`` / ``elf`` / ``macho`` /
``dotnet`` / ``unknown``) triages through radare2 (``triage_recon``); a
JVM/Android container (``apk`` / ``dex`` / ``jar``) triages through androguard
(``android_triage``). The container format is decided deterministically at ingest
(:data:`SAMPLE_FORMAT_KEY`) and read from session state by the router, so exactly
one engine runs. Both engines write the same ``triage_evidence_json`` slot, so the
downstream deobfuscation and IOC stages are engine-agnostic.

The router reuses Slice 1a's generalized :func:`build_format_router` -- a
``format -> engine`` map plus a ``default_engine`` -- so a new triage engine is
added by extending the map, never by threading another branch through the
pipeline.
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from reverse_engineering.agents.format_router import build_format_router

TRIAGE_ROUTER_DESCRIPTOR = AgentDescriptor(
    id="triage_router",
    name="triage_router",
    description=(
        "Route triage to radare2 (native/.NET) or androguard (Android/JVM) by container format."
    ),
    prompt_id=None,
    factory=build_format_router,
    runtime_profile_id="safe_default",
    sub_agent_ids=("triage_recon", "android_triage"),
    metadata={
        "format_engines": {
            "apk": "android_triage",
            "dex": "android_triage",
            "jar": "android_triage",
        },
        "default_engine": "triage_recon",
    },
)
