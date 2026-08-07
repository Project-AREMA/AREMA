"""The dotnet_decompile agent descriptor (managed-code deep analysis via ILSpy).

Where ``deep_decompile`` reconstructs pseudo-C from native machine code through
Ghidra, ``dotnet_decompile`` reconstructs near-original C# from .NET/CIL metadata
through ILSpy. The ``deep_engine_router`` runs exactly one of the two per sample
by container format, so this agent never has to gate itself. It writes the shared
``deep_evidence_json`` slot through the same after-agent evidence normalizer as
every other evidence stage.

It carries the ``ilspy_mcp`` toolset plus ``prepare_ilspy``. ``sample_intake``
pre-claims the ILSpy pod (an MCP engine must be listening when ADK resolves this
agent's toolset), but that copies the *original* sample; after a deobfuscation
recovery the current artifact differs, so this agent re-runs ``prepare_ilspy`` on
the current artifact id to copy the RECOVERED assembly into the same pod and then
decompiles that -- mirroring how ``deep_decompile`` calls ``prepare_ghidra`` on
the recovered id. Without this it would always analyse the protected original.

It has no ``output_schema``: ``output_schema`` combined with tool use is an
unreliable ADK combination -- on a tool-using turn the model tends to emit
free-form (often fenced) text that schema coercion silently drops. Instead the
after-agent evidence normalizer parses the model's raw text through the
robust JSON-boundary loader.
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.agents.evidence_output import evidence_output_callback
from reverse_engineering.prompts.loader import load_domain_prompt
from reverse_engineering.tools.ghidra.coverage import DEEP_EVIDENCE_KEY

DOTNET_DECOMPILE_DESCRIPTOR = AgentDescriptor(
    id="dotnet_decompile",
    name="dotnet_decompile",
    description=(
        "Managed-code deep-analysis agent that drives ILSpy through the ilspy_mcp "
        "toolset to reconstruct C# from a .NET/CIL assembly. Run only for .NET "
        "samples by the deep_engine_router; writes the shared deep-evidence slot."
    ),
    prompt_id="dotnet_decompile",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    tool_ids=("prepare_ilspy",),
    mcp_server_ids=("ilspy_mcp",),
    output_key=DEEP_EVIDENCE_KEY,
    after_agent_callbacks=(evidence_output_callback(output_key=DEEP_EVIDENCE_KEY, stage="deep"),),
)
