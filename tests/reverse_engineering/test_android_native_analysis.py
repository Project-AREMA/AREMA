"""The android_native_analysis agent descriptor + prompt resolve correctly."""

from __future__ import annotations

from reverse_engineering.agents.android_native_analysis import (
    ANDROID_NATIVE_ANALYSIS_DESCRIPTOR,
)
from reverse_engineering.prompts.loader import load_domain_prompt


def test_descriptor_well_formed() -> None:
    d = ANDROID_NATIVE_ANALYSIS_DESCRIPTOR
    assert d.id == d.name == "android_native_analysis"
    assert d.runtime_profile_id == "re_guarded"
    assert d.output_key == "native_evidence_json"
    assert d.tool_ids[0] == "extract_android_native_libs"
    assert "prepare_ghidra" in d.tool_ids and "ghidra_decompile" in d.tool_ids
    assert d.output_schema is None
    assert d.sub_agent_ids == () and d.mcp_server_ids == ()
    assert len(d.after_agent_callbacks) == 1


def test_prompt_gates_and_bounds() -> None:
    t = load_domain_prompt("android_native_analysis").lower()
    assert "extract_android_native_libs" in load_domain_prompt("android_native_analysis")
    assert "jni_onload" in t and "apk" in t and "skip" in t
    assert "transfer to" not in t
