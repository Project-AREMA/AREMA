"""The android_triage agent descriptor + prompt contract.

android_triage mirrors triage_recon (the native/.NET recon agent) but drives
androguard through the ``android_triage_scan`` tool instead of radare2 through
the ``radare2_mcp`` toolset. Same output slot, same evidence callback, same
no-``output_schema`` discipline (schema coercion + tool use is an unreliable ADK
combination).
"""

from __future__ import annotations

from reverse_engineering.agents.android_triage import ANDROID_TRIAGE_DESCRIPTOR
from reverse_engineering.prompts.loader import load_domain_prompt


def test_descriptor_well_formed() -> None:
    d = ANDROID_TRIAGE_DESCRIPTOR
    assert d.id == d.name == "android_triage"
    assert d.runtime_profile_id == "re_guarded"
    assert d.tool_ids == ("android_triage_scan",)
    assert d.mcp_server_ids == () and d.output_key == "triage_evidence_json"
    assert d.output_schema is None


def test_prompt_covers_android_triage_signals() -> None:
    text = load_domain_prompt("android_triage").lower()
    for token in ("permission", "exported", "receiver", "packer", "native", "manifest"):
        assert token in text
    assert "android_triage_scan" in load_domain_prompt("android_triage")
    assert "transfer to" not in text
