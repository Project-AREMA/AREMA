"""The sample_intake pipeline-stage agent descriptor.

sample_intake is the first stage of the reverse_engineer pipeline: it ingests
the user-supplied sample (acquire_sample, which classifies the container format),
always prepares the radare2 sandbox (prepare_sandbox), and prepares the ILSpy pod
(prepare_ilspy) for a .NET sample so the ilspy_mcp toolset has a listening server
when dotnet_decompile resolves it (an MCP engine must exist at toolset-resolution
time, an earlier stage than the decompiler). It emits the artifact_id that
downstream stages analyze, never analyzes a binary itself, and is reached only via
the SequentialAgent shell -- never via a model transfer (LESSONS_LEARNED #1, #6).
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.prompts.loader import load_domain_prompt

SAMPLE_INTAKE_DESCRIPTOR = AgentDescriptor(
    id="sample_intake",
    name="sample_intake",
    description=(
        "First pipeline stage of the reverse-engineering domain: acquires the "
        "sample, classifies its format, and prepares the sandboxed engines "
        "(radare2 always; ILSpy for a .NET sample) for downstream analysis."
    ),
    prompt_id="sample_intake",
    factory=build_llm_agent,
    runtime_profile_id="safe_default",
    prompt_loader=load_domain_prompt,
    tool_ids=(
        "acquire_sample",
        "acquire_sample_by_hash",
        "prepare_sandbox",
        "prepare_ilspy",
    ),
)
