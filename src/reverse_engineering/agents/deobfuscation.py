"""Descriptors for the deobfuscation stage: a format router over the bounded
native/.NET recovery loop and a JVM/Android recovery skip."""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_loop_agent
from reverse_engineering.agents.format_router import JVM_FORMATS, build_format_router
from reverse_engineering.tools.deobfuscation.state import DEOBF_MAX_ITERATIONS

DEOBFUSCATION_LOOP_DESCRIPTOR = AgentDescriptor(
    id="deobfuscation_loop",
    name="deobfuscation_loop",
    description="Classify, recover, retriage, and gate obfuscated native/.NET artifacts.",
    prompt_id=None,
    factory=build_loop_agent,
    sub_agent_ids=(
        "deobf_classify",
        "recover",
        "scripted_recover",
        "dotnet_scripted_recover",
        "retriage",
        "deobf_gate",
    ),
    metadata={"max_iterations": DEOBF_MAX_ITERATIONS},
)

# The recovery loop is a native/.NET machine (its classification schema, its tools,
# its radare2 retriage, and deobf_gate's mandatory UPX+FLOSS all target native or
# managed code). A JVM/Android package has no recovery cell -- jadx opens the
# container directly -- so route those formats to ``recovery_skip`` rather than
# spend the whole loop reaching an all-no-op result. Same format-routing pattern
# used for triage (triage_router) and deep decompile (deep_engine_router): the
# engine that does not apply is never stood up. New JVM formats extend JVM_FORMATS,
# never here.
DEOBFUSCATION_DESCRIPTOR = AgentDescriptor(
    id="deobfuscation",
    name="deobfuscation",
    description=(
        "Route to the native/.NET recovery loop, or skip recovery for a JVM/Android "
        "package that has no unpacking step."
    ),
    prompt_id=None,
    factory=build_format_router,
    sub_agent_ids=("deobfuscation_loop", "recovery_skip"),
    metadata={
        "format_engines": dict.fromkeys(sorted(JVM_FORMATS), "recovery_skip"),
        "default_engine": "deobfuscation_loop",
    },
)
