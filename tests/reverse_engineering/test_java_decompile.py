"""The java_decompile agent descriptor + prompt resolve correctly."""

from __future__ import annotations

from reverse_engineering.agents.java_decompile import JAVA_DECOMPILE_DESCRIPTOR
from reverse_engineering.prompts.loader import load_domain_prompt


def test_descriptor_well_formed() -> None:
    d = JAVA_DECOMPILE_DESCRIPTOR
    assert d.id == d.name == "java_decompile"
    assert d.runtime_profile_id == "re_guarded"
    assert d.sub_agent_ids == () and d.mcp_server_ids == ()
    assert d.output_key == "deep_evidence_json"


def test_agent_holds_prepare_jadx_first_then_every_jadx_tool() -> None:
    ids = JAVA_DECOMPILE_DESCRIPTOR.tool_ids
    assert ids[0] == "prepare_jadx"
    assert set(ids) == {
        "prepare_jadx",
        "jadx_manifest",
        "jadx_list_classes",
        "jadx_class_source",
        "jadx_search_sources",
        "jadx_strings",
        "jadx_list_resources",
    }


def test_prompt_gates_on_format_and_prepares_first() -> None:
    text = load_domain_prompt("java_decompile").lower()
    assert "format gate" in text and all(f in text for f in ("apk", "dex", "jar"))
    assert "prepare_jadx(artifact_id, sample_format)" in load_domain_prompt("java_decompile")
    assert "no unpacking step" in text and "directly" in text
    assert "transfer to" not in text


def test_prompt_mandates_json_envelope_output_not_prose() -> None:
    # Regression (found by the in-cluster APK smoke test): java_decompile must emit
    # the evidence-envelope JSON that normalize_evidence_output/parse_evidence_envelope
    # consumes -- exactly like deep_decompile. The ported PR#2 prompt asked for
    # free-text "FINDING:" blocks, so the agent wrote a Markdown report, the
    # normalizer threw JSONDecodeError, and the entire deep analysis was dropped
    # (deep:evidence_envelope_invalid).
    text = load_domain_prompt("java_decompile")
    lower = text.lower()
    assert "json only" in lower or "single json object" in lower
    assert "no markdown" in lower and "no code fences" in lower
    # The envelope contract the normalizer parses:
    for key in ('"coverage"', '"findings"', '"artifact_id"', '"status"', '"kind"'):
        assert key in text, f"prompt missing envelope key {key}"
    # The old free-text FINDING-block format must be gone.
    assert "FINDING:\n" not in text
