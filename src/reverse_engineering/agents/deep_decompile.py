"""The deep_decompile worker descriptor.

The worker drives Ghidra (via ghidra-rpc function tools) for deep
decompilation, semantic search, and control-flow analysis inside the bounded
deep-analysis loop. It runs under ``re_guarded`` (its tools produce
binary-origin output) and writes to the named deep-evidence key. It carries
no ``output_schema``: schema coercion combined with tool use is an unreliable
ADK combination -- on a tool-using turn the model tends to emit free-form
(often fenced) text that coercion silently drops. Instead a deterministic
after-agent callback normalizes the model's raw text into a validated
``EvidenceEnvelope`` before any checkpoint observes it.
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.agents.evidence_output import evidence_output_callback
from reverse_engineering.prompts.loader import load_domain_prompt
from reverse_engineering.tools.ghidra.coverage import DEEP_EVIDENCE_KEY

DEEP_DECOMPILE_WORKER_DESCRIPTOR = AgentDescriptor(
    id="deep_decompile_worker",
    name="deep_decompile_worker",
    description=(
        "Model-directed Ghidra worker inside the bounded deep-analysis loop. "
        "Drives ghidra-rpc for pseudo-C decompilation, semantic search across "
        "the binary, and control-flow analysis, emitting a validated evidence "
        "envelope for the deep stage."
    ),
    prompt_id="deep_decompile",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    tool_ids=(
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
    output_key=DEEP_EVIDENCE_KEY,
    # This worker runs inside the deep-analysis LoopAgent, so it is re-invoked
    # after it has already emitted a valid envelope; a later pass often degrades
    # into an empty envelope or prose. `accumulate` merges each pass into the
    # stage's running-best so a degrading worker cannot erase an earlier
    # validated finding (the observed native `deep:evidence_envelope_invalid`).
    after_agent_callbacks=(
        evidence_output_callback(output_key=DEEP_EVIDENCE_KEY, stage="deep", accumulate=True),
    ),
)
