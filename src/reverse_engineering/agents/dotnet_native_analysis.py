"""Ghidra over a .NET assembly, read as the PE file it actually is.

Reached only through :mod:`reverse_engineering.agents.dotnet_native_pivot`, and
only when the managed leg produced no findings. It reuses ``prepare_ghidra`` and
the ``ghidra_*`` toolset verbatim -- the same tools ``deep_decompile_worker``
drives over a native binary -- because a managed assembly needs no special
handling to be read as a PE. That is the point.

It writes ``native_evidence_json``, its own stage, exactly as
``android_native_analysis`` does. The critic unions every stage, so whatever the
managed leg did manage to record survives alongside this.

No ``output_schema``: schema coercion combined with tool use is an unreliable ADK
combination -- on a tool-using turn the model tends to emit free-form (often
fenced) text that coercion silently drops. The after-agent normalizer parses the
raw text instead.
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.agents.evidence_output import evidence_output_callback
from reverse_engineering.prompts.loader import load_domain_prompt
from reverse_engineering.tools.ghidra.coverage import NATIVE_EVIDENCE_KEY

DOTNET_NATIVE_ANALYSIS_DESCRIPTOR = AgentDescriptor(
    id="dotnet_native_analysis",
    name="dotnet_native_analysis",
    description=(
        "Drive Ghidra over a .NET assembly as a PE file when managed "
        "decompilation produced nothing: PE structure, native stubs, mixed-mode "
        "method bodies, embedded resources and byte-level strings that a managed "
        "decompiler cannot reach. Writes the native evidence stage."
    ),
    prompt_id="dotnet_native_analysis",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    tool_ids=(
        "prepare_ghidra",
        "ghidra_metadata",
        "ghidra_list_functions",
        "ghidra_decompile",
        "ghidra_search_decompiled",
        "ghidra_imports",
        "ghidra_strings",
        "ghidra_xrefs_to",
        "ghidra_pcode",
    ),
    output_key=NATIVE_EVIDENCE_KEY,
    after_agent_callbacks=(
        evidence_output_callback(output_key=NATIVE_EVIDENCE_KEY, stage="native"),
    ),
)
