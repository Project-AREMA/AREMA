"""The deep_decompile worker descriptor + prompt resolve correctly."""

from __future__ import annotations

from reverse_engineering.agents.deep_decompile import DEEP_DECOMPILE_WORKER_DESCRIPTOR
from reverse_engineering.prompts.loader import load_domain_prompt
from reverse_engineering.tools.ghidra.coverage import DEEP_EVIDENCE_KEY


def test_deep_decompile_worker_descriptor_well_formed() -> None:
    assert DEEP_DECOMPILE_WORKER_DESCRIPTOR.id == "deep_decompile_worker"
    assert DEEP_DECOMPILE_WORKER_DESCRIPTOR.name == "deep_decompile_worker"
    assert DEEP_DECOMPILE_WORKER_DESCRIPTOR.prompt_id == "deep_decompile"
    assert DEEP_DECOMPILE_WORKER_DESCRIPTOR.runtime_profile_id == "re_guarded"
    assert DEEP_DECOMPILE_WORKER_DESCRIPTOR.sub_agent_ids == ()
    assert DEEP_DECOMPILE_WORKER_DESCRIPTOR.output_key == DEEP_EVIDENCE_KEY
    assert len(DEEP_DECOMPILE_WORKER_DESCRIPTOR.after_agent_callbacks) == 1


def test_deep_decompile_worker_has_no_output_schema_but_normalizes_via_callback() -> None:
    """output_schema + tools is an unreliable ADK combination; this agent relies
    on its after-agent evidence normalizer to parse the model's raw text instead."""
    assert DEEP_DECOMPILE_WORKER_DESCRIPTOR.output_schema is None


def test_deep_decompile_prompt_loads() -> None:
    text = load_domain_prompt("deep_decompile")
    assert "deep_decompile" in text
    assert "search-decompiled" in text
    assert "pcode" in text
    assert "{deep_missing_surfaces?}" in text
