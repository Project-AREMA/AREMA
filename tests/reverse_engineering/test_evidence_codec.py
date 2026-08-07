"""Tests for the evidence/finding memory codec.

A :class:`FindingRecord` is one evidence-backed claim about an artifact. It is
the substrate the ReportGenerator renders from: the model cannot invent a claim
with no artifact behind it. ``FINDING_CODEC`` binds it to the
``evidence/finding`` envelope kind so it round-trips through the memory codec
registry.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from arema.memory.codecs import RecordCodecRegistry
from reverse_engineering.evidence import FINDING_CODEC, FindingRecord


def _sample_record() -> FindingRecord:
    return FindingRecord(
        artifact_id="abc123def456",
        claim="imports libc",
        tool="list_imports",
        confidence=0.9,
        detail="sym.imp.libc",
    )


def test_finding_record_round_trips_through_codec_registry() -> None:
    registry = RecordCodecRegistry()
    registry.register(FINDING_CODEC)
    original = _sample_record()

    envelope = registry.encode(original, scope_id="scope-1", source="test")
    decoded = registry.decode(envelope)

    assert decoded == original


def test_encoded_envelope_carries_evidence_finding_routing_metadata() -> None:
    registry = RecordCodecRegistry()
    registry.register(FINDING_CODEC)

    envelope = registry.encode(_sample_record(), scope_id="scope-1", source="test")

    assert envelope.namespace == "evidence"
    assert envelope.kind == "finding"
    assert envelope.schema_version == 1
    assert len(envelope.content_hash) == 64
    assert all(c in "0123456789abcdef" for c in envelope.content_hash)


def test_codec_ids_lists_evidence_finding() -> None:
    registry = RecordCodecRegistry()
    registry.register(FINDING_CODEC)

    assert registry.codec_ids() == frozenset({"evidence/finding"})


@pytest.mark.parametrize("invalid_confidence", [-0.1, 1.5])
def test_finding_record_rejects_out_of_range_confidence(invalid_confidence: float) -> None:
    with pytest.raises(ValidationError):
        FindingRecord(
            artifact_id="abc",
            claim="x",
            tool="list_imports",
            confidence=invalid_confidence,
        )


def test_finding_record_is_frozen() -> None:
    record = _sample_record()

    with pytest.raises(ValidationError):
        record.confidence = 0.1  # type: ignore[misc]


def test_finding_codec_metadata_is_correct() -> None:
    assert FINDING_CODEC.key == ("evidence", "finding")
    assert FINDING_CODEC.schema_version == 1
    assert FINDING_CODEC.upgrade_from_previous is None


def test_finding_record_detail_defaults_to_empty() -> None:
    record = FindingRecord(
        artifact_id="abc",
        claim="x",
        tool="list_imports",
        confidence=0.5,
    )

    assert record.detail == ""
