"""Descriptor for the bounded deep-analysis loop.

A capped ``LoopAgent`` runs the model-directed Ghidra worker followed by a
deterministic completion gate. The gate exits only when preparation, semantic
search, and targeted decompile/p-code coverage are all satisfied, or after the
third pass with a durable incomplete limitation. The malware root references
only this shell, never the worker or gate directly.
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_loop_agent

DEEP_ANALYSIS_DESCRIPTOR = AgentDescriptor(
    id="deep_analysis",
    name="deep_analysis",
    description="Bounded Ghidra worker and deterministic completion gate.",
    prompt_id=None,
    factory=build_loop_agent,
    sub_agent_ids=("deep_decompile_worker", "deep_analysis_gate"),
    metadata={"max_iterations": 3},
)
