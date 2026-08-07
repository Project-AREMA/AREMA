"""A fenced (```json) envelope must parse into real findings, not fail-close."""

from __future__ import annotations

from reverse_engineering.evidence_envelope import parse_evidence_envelope

_AID = "9d23916206a4749f6d69876e9e9dad4cbe8e6b9a26d0d5a14b7ac964a6e5c43b"


def test_fenced_evidence_envelope_parses():
    raw = (
        "```json\n"
        '{"artifact_id": "' + _AID + '",'
        ' "coverage": {"status": "complete", "surfaces": ["dotnet_decompile"], "limitations": []},'
        ' "findings": []}\n'
        "```"
    )
    env = parse_evidence_envelope(raw, artifact_id=_AID)
    assert env.artifact_id == _AID
    assert env.coverage.status.value == "complete"
