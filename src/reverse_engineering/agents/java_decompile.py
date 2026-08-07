"""The java_decompile agent descriptor.

java_decompile is the JVM-bytecode third of the format route. An APK, DEX or JAR
carries Dalvik or Java bytecode, which decompiles near-source just as CIL does,
so it goes to jadx rather than to the native consensus path
(``deep_decompile``/Ghidra) or the .NET path (``dotnet_decompile``/ILSpy). The
``deep_engine_router`` runs exactly one of the three per sample by container
format, so this agent never has to gate itself; it writes the shared
``deep_evidence_json`` slot through the same after-agent evidence normalizer as
every other evidence stage.

Unlike the MCP engines, jadx is exec-backed, so ``prepare_jadx`` can live on this
agent: nothing needs to be listening when ADK resolves the tools. That matches
``deep_decompile`` holding ``prepare_ghidra``.

It has no ``output_schema``: ``output_schema`` combined with tool use is an
unreliable ADK combination -- on a tool-using turn the model tends to emit
free-form (often fenced) text that schema coercion silently drops. Instead the
after-agent evidence normalizer parses the model's raw text through the robust
JSON-boundary loader.

Uses re_guarded (its tools produce binary-origin output).
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineering.agents.evidence_output import evidence_output_callback
from reverse_engineering.prompts.loader import load_domain_prompt
from reverse_engineering.tools.ghidra.coverage import DEEP_EVIDENCE_KEY

JAVA_DECOMPILE_DESCRIPTOR = AgentDescriptor(
    id="java_decompile",
    name="java_decompile",
    description=(
        "Java/Android decompilation engine driving jadx over the sandbox CLI to "
        "reconstruct Java source from an APK, DEX or JAR, and to read the decoded "
        "Android manifest and resources. Run only for JVM-bytecode samples by the "
        "deep_engine_router; writes the shared deep-evidence slot."
    ),
    prompt_id="java_decompile",
    factory=build_llm_agent,
    runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    tool_ids=(
        "prepare_jadx",
        "jadx_manifest",
        "jadx_list_classes",
        "jadx_class_source",
        "jadx_search_sources",
        "jadx_strings",
        "jadx_list_resources",
    ),
    output_key=DEEP_EVIDENCE_KEY,
    after_agent_callbacks=(evidence_output_callback(output_key=DEEP_EVIDENCE_KEY, stage="deep"),),
)
