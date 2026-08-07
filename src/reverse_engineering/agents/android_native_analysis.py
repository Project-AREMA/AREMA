"""The android_native_analysis worker descriptor.

An APK ships its JNI code as bundled ``lib/<abi>/*.so`` native libraries that
Dalvik decompilation (jadx) never reaches. This worker extracts one ABI's ``.so``
from the APK (``extract_android_native_libs``, in the deobfuscation sandbox pod)
and then drives **Ghidra** over each extracted native library exactly as
``deep_decompile_worker`` does over a native binary -- it REUSES ``prepare_ghidra``
and the ``ghidra_*`` toolset verbatim, and the ghidra tools are already registered
binary-origin so their ``.so`` output is already sanitized.

It is a separate evidence stage from ``deep``: it writes its own
``native_evidence_json`` envelope, which the critic unions alongside ``deep``
(never a second writer to ``deep_evidence_json``). The APK stays the current
artifact throughout -- the extracted ``.so`` are a fan-out *alongside* it, not a
replacement, so the jadx (DEX) leg keeps analysing the APK.

It runs under ``re_guarded`` (its tools produce binary-origin output) and carries
no ``output_schema``: schema coercion combined with tool use is an unreliable ADK
combination -- on a tool-using turn the model tends to emit free-form (often
fenced) text that coercion silently drops. Instead a deterministic after-agent
callback normalizes the model's raw text into a validated ``EvidenceEnvelope``
before any checkpoint observes it.
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.agents.evidence_output import evidence_output_callback
from reverse_engineering.prompts.loader import load_domain_prompt
from reverse_engineering.tools.ghidra.coverage import NATIVE_EVIDENCE_KEY

ANDROID_NATIVE_ANALYSIS_DESCRIPTOR = AgentDescriptor(
    id="android_native_analysis",
    name="android_native_analysis",
    description=(
        "Model-directed Ghidra worker over an APK's bundled native libraries. "
        "Extracts one ABI's .so from the APK (deobfuscation sandbox), then drives "
        "ghidra-rpc to decompile JNI_OnLoad and notable exports, emitting a "
        "validated evidence envelope for the native stage. Reuses prepare_ghidra "
        "and the ghidra toolset; runs only for apk samples (self-gates otherwise)."
    ),
    prompt_id="android_native_analysis",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    tool_ids=(
        "extract_android_native_libs",
        "prepare_ghidra",
        "ghidra_metadata",
        "ghidra_list_functions",
        "ghidra_decompile",
        "ghidra_search_decompiled",
        "ghidra_basic_blocks",
        "ghidra_xrefs_to",
        "ghidra_imports",
        "ghidra_strings",
        "ghidra_pcode",
    ),
    output_key=NATIVE_EVIDENCE_KEY,
    after_agent_callbacks=(
        evidence_output_callback(output_key=NATIVE_EVIDENCE_KEY, stage="native"),
    ),
)
