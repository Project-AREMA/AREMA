"""Tests for versioned memory record codecs and the codec registry.

These cover the canonical content hash (deterministic, key-order independent),
the v1->v2 upgrade chain, raw passthrough of unknown records, and the
registration guards that reject duplicate keys and broken version chains.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pydantic import BaseModel, ConfigDict

from arema.memory import (
    CodecRegistrationError,
    JsonValue,
    MemoryEnvelope,
    NoteRecord,
    RecordCodec,
    RecordCodecRegistry,
    UpgradeFn,
    canonical_content_hash,
)
from arema.memory.service import default_core_codec_registry

if TYPE_CHECKING:
    from collections.abc import Mapping


class NoteRecordV1(BaseModel):
    """The legacy note payload, before the author field was introduced."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    text: str


def note_v1_codec() -> RecordCodec[NoteRecordV1]:
    return RecordCodec(
        namespace="core",
        kind="note",
        schema_version=1,
        payload_type=NoteRecordV1,
    )


def upgrade_note_v1(payload: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """Backfill the author field introduced in schema version 2."""
    return {**payload, "author": "unknown"}


def note_v2_codec(*, upgrade_from_previous: UpgradeFn) -> RecordCodec[NoteRecord]:
    return RecordCodec(
        namespace="core",
        kind="note",
        schema_version=2,
        payload_type=NoteRecord,
        upgrade_from_previous=upgrade_from_previous,
    )


def envelope(
    *,
    namespace: str = "core",
    kind: str = "note",
    schema_version: int = 1,
    payload: dict[str, JsonValue],
) -> MemoryEnvelope:
    return MemoryEnvelope(
        scope_id="scope-1",
        namespace=namespace,
        kind=kind,
        schema_version=schema_version,
        source="unit-test",
        payload=payload,
        content_hash=canonical_content_hash(payload),
    )


def test_canonical_hash_is_key_order_independent() -> None:
    left = canonical_content_hash({"a": 1, "b": {"c": 2, "d": 3}})
    right = canonical_content_hash({"b": {"d": 3, "c": 2}, "a": 1})
    assert left == right


def test_canonical_hash_changes_with_values() -> None:
    assert canonical_content_hash({"a": 1}) != canonical_content_hash({"a": 2})


def test_canonical_hash_is_sha256_hex() -> None:
    digest = canonical_content_hash({"a": 1})
    assert len(digest) == 64
    assert set(digest) <= set("0123456789abcdef")


def test_codec_upgrades_v1_payload_to_v2() -> None:
    registry = RecordCodecRegistry()
    registry.register(note_v1_codec())
    registry.register(note_v2_codec(upgrade_from_previous=upgrade_note_v1))
    decoded = registry.decode(envelope(kind="note", schema_version=1, payload={"text": "x"}))
    assert decoded == NoteRecord(text="x", author="unknown")


def test_decode_current_version_needs_no_upgrade() -> None:
    registry = RecordCodecRegistry()
    registry.register(note_v1_codec())
    registry.register(note_v2_codec(upgrade_from_previous=upgrade_note_v1))
    decoded = registry.decode(
        envelope(kind="note", schema_version=2, payload={"text": "y", "author": "ada"})
    )
    assert decoded == NoteRecord(text="y", author="ada")


def test_unknown_record_remains_raw() -> None:
    envelope_value = envelope(namespace="extension", kind="unknown", payload={"x": 1})
    assert RecordCodecRegistry().decode(envelope_value) == envelope_value


def test_decode_future_version_passes_through_raw() -> None:
    registry = RecordCodecRegistry()
    registry.register(note_v1_codec())
    # Only version 1 is registered; a version-2 envelope cannot be upgraded downward.
    future = envelope(kind="note", schema_version=2, payload={"text": "z"})
    assert registry.decode(future) == future


def test_register_rejects_duplicate_version() -> None:
    registry = RecordCodecRegistry()
    registry.register(note_v1_codec())
    with pytest.raises(CodecRegistrationError):
        registry.register(note_v1_codec())


def test_register_rejects_broken_chain() -> None:
    registry = RecordCodecRegistry()
    registry.register(note_v1_codec())
    v3 = RecordCodec(
        namespace="core",
        kind="note",
        schema_version=3,
        payload_type=NoteRecord,
        upgrade_from_previous=upgrade_note_v1,
    )
    with pytest.raises(CodecRegistrationError):
        registry.register(v3)


def test_register_rejects_missing_base_version() -> None:
    registry = RecordCodecRegistry()
    with pytest.raises(CodecRegistrationError):
        registry.register(note_v2_codec(upgrade_from_previous=upgrade_note_v1))


def test_register_rejects_version_one_with_upgrade() -> None:
    registry = RecordCodecRegistry()
    bad = RecordCodec(
        namespace="core",
        kind="note",
        schema_version=1,
        payload_type=NoteRecordV1,
        upgrade_from_previous=upgrade_note_v1,
    )
    with pytest.raises(CodecRegistrationError):
        registry.register(bad)


def test_register_rejects_version_above_one_without_upgrade() -> None:
    registry = RecordCodecRegistry()
    registry.register(note_v1_codec())
    bad = RecordCodec(
        namespace="core",
        kind="note",
        schema_version=2,
        payload_type=NoteRecord,
    )
    with pytest.raises(CodecRegistrationError):
        registry.register(bad)


def test_encode_builds_envelope_with_canonical_hash() -> None:
    registry = RecordCodecRegistry()
    registry.register(
        RecordCodec(
            namespace="core",
            kind="memo",
            schema_version=1,
            payload_type=NoteRecord,
        )
    )
    record = NoteRecord(text="hi", author="ada")
    built = registry.encode(record, scope_id="scope-1", source="unit-test")
    assert built.namespace == "core"
    assert built.kind == "memo"
    assert built.schema_version == 1
    assert built.payload == {"text": "hi", "author": "ada"}
    assert built.content_hash == canonical_content_hash({"text": "hi", "author": "ada"})


def test_encode_round_trips_through_decode() -> None:
    registry = RecordCodecRegistry()
    registry.register(
        RecordCodec(
            namespace="core",
            kind="memo",
            schema_version=1,
            payload_type=NoteRecord,
        )
    )
    record = NoteRecord(text="hi", author="ada")
    built = registry.encode(record, scope_id="scope-1", source="unit-test")
    assert registry.decode(built) == record


def test_encode_rejects_unregistered_payload_type() -> None:
    registry = RecordCodecRegistry()
    with pytest.raises(CodecRegistrationError):
        registry.encode(NoteRecord(text="x", author="y"), scope_id="scope-1", source="unit-test")


def test_codec_ids_is_empty_for_a_fresh_registry() -> None:
    assert RecordCodecRegistry().codec_ids() == frozenset()


class MemoRecordV1(BaseModel):
    """A second, unrelated payload used to prove chains stay independent."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    text: str


def test_codec_ids_lists_registered_namespace_kind_pairs() -> None:
    registry = RecordCodecRegistry()
    registry.register(note_v1_codec())
    registry.register(note_v2_codec(upgrade_from_previous=upgrade_note_v1))
    registry.register(
        RecordCodec(
            namespace="core",
            kind="memo",
            schema_version=1,
            payload_type=MemoRecordV1,
        )
    )
    assert registry.codec_ids() == frozenset({"core/note", "core/memo"})


def test_default_core_codec_registry_exposes_event_and_checkpoint_ids() -> None:
    ids = default_core_codec_registry().codec_ids()
    assert "arema.core/event" in ids
    assert "arema.core/checkpoint" in ids
