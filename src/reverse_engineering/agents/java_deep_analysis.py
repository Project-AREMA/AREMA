"""The composite ``java_deep_analysis`` route descriptor.

An APK is two things at once: Dalvik (DEX) bytecode that jadx decompiles near to
source, and bundled ``lib/<abi>/*.so`` native libraries that only Ghidra reaches.
Neither leg subsumes the other, so ``java_deep_analysis`` runs both in a fixed
order as a ``SequentialAgent`` -- ``java_decompile`` (jadx, DEX) first, then
``android_native_analysis`` (Ghidra over one ABI's ``.so``).

The two legs write *different* evidence stages: ``java_decompile`` the shared
``deep_evidence_json`` slot, ``android_native_analysis`` its own
``native_evidence_json`` envelope. The critic unions every stage, so both land in
the report. ``android_native_analysis`` self-gates on the ``apk`` format, so a
bare ``dex``/``jar`` routed here decompiles through jadx and the native leg
no-ops with a single cited skip finding.

This is a pure composition: it reuses ``build_sequential_agent`` (no new
orchestration code) and carries no prompt of its own -- its sub-agents each carry
theirs.
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_sequential_agent

JAVA_DEEP_ANALYSIS_DESCRIPTOR = AgentDescriptor(
    id="java_deep_analysis",
    name="java_deep_analysis",
    description=("Composite JVM/Android deep analysis: jadx (DEX) then Ghidra over native .so."),
    prompt_id=None,
    factory=build_sequential_agent,
    runtime_profile_id="safe_default",
    sub_agent_ids=("java_decompile", "android_native_analysis"),
)
