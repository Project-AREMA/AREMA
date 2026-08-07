"""Tests for domain-neutral memory envelope and payload models.

These exercise real behaviour: UTC-awareness of default timestamps, frozen
immutability, positive-integer invariants, and the artifact integrity-digest
requirement (an artifact record must never be constructed without a digest,
and never carries raw bytes).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from arema.memory import (
    ArtifactRecord,
    CheckpointRecord,
    EventRecord,
    MemoryEnvelope,
    MemoryPage,
    MemoryQuery,
    MemoryRelation,
    MemoryScope,
    NoteRecord,
    utc_now,
)

VALID_SHA256 = "a" * 64


def make_envelope(**overrides: object) -> MemoryEnvelope:
    """Build a valid envelope, applying keyword overrides for one field."""
    fields: dict[str, object] = {
        "scope_id": "scope-1",
        "namespace": "core",
        "kind": "note",
        "schema_version": 1,
        "source": "unit-test",
        "payload": {"text": "x"},
        "content_hash": "0" * 64,
    }
    fields.update(overrides)
    return MemoryEnvelope(**fields)


def test_utc_now_is_timezone_aware() -> None:
    now = utc_now()
    assert now.tzinfo is not None
    assert now.utcoffset() == datetime.now(UTC).utcoffset()


def test_memory_scope_defaults_are_utc_aware() -> None:
    scope = MemoryScope(scope_type="run")
    assert scope.created_at.tzinfo is UTC
    assert scope.closed_at is None
    assert scope.parent_id is None
    assert scope.metadata == {}
    assert scope.id  # a non-empty generated identifier


def test_memory_scope_is_frozen() -> None:
    scope = MemoryScope(scope_type="run")
    with pytest.raises(ValidationError):
        scope.scope_type = "changed"  # type: ignore[misc]


def test_memory_scope_generates_unique_ids() -> None:
    first = MemoryScope(scope_type="run")
    second = MemoryScope(scope_type="run")
    assert first.id != second.id


def test_memory_envelope_defaults_are_utc_aware() -> None:
    envelope = make_envelope()
    assert envelope.created_at.tzinfo is UTC
    assert envelope.updated_at.tzinfo is UTC
    assert envelope.revision == 1
    assert envelope.expires_at is None


def test_memory_envelope_requires_content_hash() -> None:
    with pytest.raises(ValidationError):
        MemoryEnvelope(
            scope_id="scope-1",
            namespace="core",
            kind="note",
            schema_version=1,
            source="unit-test",
            payload={"text": "x"},
        )


def test_memory_envelope_rejects_non_positive_schema_version() -> None:
    with pytest.raises(ValidationError):
        make_envelope(schema_version=0)


def test_memory_envelope_rejects_non_positive_revision() -> None:
    with pytest.raises(ValidationError):
        make_envelope(revision=0)


def test_memory_envelope_is_frozen() -> None:
    envelope = make_envelope()
    with pytest.raises(ValidationError):
        envelope.namespace = "other"  # type: ignore[misc]


def test_artifact_payload_requires_integrity_digest() -> None:
    with pytest.raises(ValidationError):
        ArtifactRecord(uri="file:///tmp/sample.bin", media_type="application/octet-stream")


def test_artifact_record_accepts_valid_digest() -> None:
    record = ArtifactRecord(
        uri="file:///tmp/sample.bin",
        media_type="application/octet-stream",
        byte_size=1024,
        sha256=VALID_SHA256,
    )
    assert record.byte_size == 1024
    assert record.sha256 == VALID_SHA256


def test_artifact_record_rejects_malformed_digest() -> None:
    with pytest.raises(ValidationError):
        ArtifactRecord(
            uri="file:///tmp/sample.bin",
            media_type="application/octet-stream",
            byte_size=1,
            sha256="not-a-real-sha256",
        )


def test_artifact_record_never_stores_bytes() -> None:
    with pytest.raises(ValidationError):
        ArtifactRecord(
            uri="file:///tmp/sample.bin",
            media_type="application/octet-stream",
            byte_size=1,
            sha256=VALID_SHA256,
            data=b"raw-bytes",  # type: ignore[call-arg]
        )


def test_artifact_record_rejects_negative_byte_size() -> None:
    with pytest.raises(ValidationError):
        ArtifactRecord(
            uri="file:///tmp/sample.bin",
            media_type="application/octet-stream",
            byte_size=-1,
            sha256=VALID_SHA256,
        )


def test_note_record_requires_author() -> None:
    with pytest.raises(ValidationError):
        NoteRecord(text="hello")  # type: ignore[call-arg]


def test_note_record_round_trip() -> None:
    note = NoteRecord(text="hello", author="ada")
    assert note.text == "hello"
    assert note.author == "ada"


def test_event_record_occurred_at_is_utc_aware() -> None:
    event = EventRecord(name="scope.opened", attributes={"count": 3})
    assert event.occurred_at.tzinfo is UTC
    assert event.attributes == {"count": 3}


def test_checkpoint_record_requires_non_negative_sequence() -> None:
    with pytest.raises(ValidationError):
        CheckpointRecord(label="stage-1", sequence=-1)


def test_checkpoint_record_defaults() -> None:
    checkpoint = CheckpointRecord(label="stage-1", sequence=0)
    assert checkpoint.state == {}
    assert checkpoint.created_at.tzinfo is UTC


def test_memory_relation_generates_id_and_utc_timestamp() -> None:
    relation = MemoryRelation(
        source_id="a",
        target_id="b",
        relation_type="derived_from",
    )
    assert relation.id
    assert relation.created_at.tzinfo is UTC
    assert relation.relation_type == "derived_from"


def test_memory_query_rejects_non_positive_limit() -> None:
    with pytest.raises(ValidationError):
        MemoryQuery(limit=0)


def test_memory_query_defaults() -> None:
    query = MemoryQuery()
    assert query.limit >= 1
    assert query.cursor is None
    assert query.include_expired is False
    assert query.namespace is None
    assert query.tags == ()


def test_memory_query_coerces_tags_list_to_tuple() -> None:
    query = MemoryQuery(tags=["alpha", "beta"])
    assert query.tags == ("alpha", "beta")
    assert isinstance(query.tags, tuple)


def test_memory_page_holds_envelopes() -> None:
    envelope = make_envelope()
    page = MemoryPage(items=(envelope,), next_cursor="cursor-2")
    assert page.items == (envelope,)
    assert page.next_cursor == "cursor-2"


def test_memory_page_defaults_to_empty() -> None:
    page = MemoryPage()
    assert page.items == ()
    assert page.next_cursor is None
