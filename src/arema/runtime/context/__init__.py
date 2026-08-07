"""Context-window budgeting and descriptor-driven output compaction."""

from arema.runtime.context.budget import (
    CHECKPOINT_STATE_KEY,
    ContextPressure,
    classify_pressure,
    enforce_context_budget,
    estimate_tokens,
)
from arema.runtime.context.compactor import compact_response, make_output_compactor

__all__ = [
    "CHECKPOINT_STATE_KEY",
    "ContextPressure",
    "classify_pressure",
    "compact_response",
    "enforce_context_budget",
    "estimate_tokens",
    "make_output_compactor",
]
