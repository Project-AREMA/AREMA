"""Unit tests for the ``triage_router`` format-routed triage descriptor.

``triage_router`` reuses Slice 1a's generalized :func:`build_format_router` to
route an ``apk``/``dex``/``jar`` sample to the androguard ``android_triage``
engine and every other format to the radare2 ``triage_recon`` engine. It replaces
``triage_recon`` at index 1 of the malware pipeline, so both engines feed the same
``triage_evidence_json`` slot transparently.
"""

from __future__ import annotations


def test_triage_router_routes_by_format() -> None:
    from reverse_engineering.agents.triage_router import TRIAGE_ROUTER_DESCRIPTOR

    d = TRIAGE_ROUTER_DESCRIPTOR
    assert d.factory.__name__ == "build_format_router"
    assert set(d.sub_agent_ids) == {"triage_recon", "android_triage"}
    assert d.metadata["format_engines"]["apk"] == "android_triage"
    assert d.metadata["default_engine"] == "triage_recon"


def test_pipeline_uses_triage_router_at_position_two() -> None:
    from malware_analyst.agents.malware_analyst import MALWARE_ANALYST_DESCRIPTOR

    assert MALWARE_ANALYST_DESCRIPTOR.sub_agent_ids[1] == "triage_router"
    assert "triage_recon" not in MALWARE_ANALYST_DESCRIPTOR.sub_agent_ids
