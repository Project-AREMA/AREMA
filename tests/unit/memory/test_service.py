"""Behavioural tests for :class:`arema.memory.service.MemoryService`.

The service is the typed seam between callers and a raw
:class:`~arema.memory.store.MemoryStore`: it encodes typed payloads through a
codec registry, decodes retrieved pages back into records, bounds what may enter
model context, and degrades open when a write fails. These tests exercise that
behaviour over the reference :class:`~arema.memory.backends.InMemoryStore`, plus
a deliberately failing store to prove the fail-open path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from arema.memory import (
    ArtifactRecord,
    CheckpointRecord,
    EventRecord,
    InMemoryStore,
    MemoryEnvelope,
    MemoryQuery,
    MemoryScope,
    MemoryStoreError,
    NoteRecord,
    StoreHealth,
    canonical_content_hash,
)
from arema.memory.service import (
    BoundedRetrieval,
    MemoryService,
    default_core_codec_registry,
)

if TYPE_CHECKING:
    from arema.memory.store import MemoryStore


# ---------------------------------------------------------------------------
# Fakes / helpers
# ---------------------------------------------------------------------------


class _FailingStore:
    """A store whose writes always fail, to exercise the fail-open path."""

    def __init__(self) -> None:
        self._delegate = InMemoryStore()
        self._delegate.initialize()

    def insert_record(self, record: MemoryEnvelope) -> MemoryEnvelope:
        del record
        raise MemoryStoreError("write failed")

    def create_scope(self, scope: MemoryScope) -> MemoryScope:
        return self._delegate.create_scope(scope)

    def health(self) -> StoreHealth:
        return StoreHealth(healthy=True)


def build_service() -> MemoryService:
    store = InMemoryStore()
    store.initialize()
    return MemoryService(store=store, codecs=default_core_codec_registry())


class _ToolEvent:
    """A structural stand-in for the runtime ToolEvent (no runtime import)."""

    def __init__(
        self,
        *,
        tool_id: str,
        success: bool,
        elapsed_seconds: float,
        output_size: int,
        run_id: str | None,
        scope_id: str | None,
    ) -> None:
        self.tool_id = tool_id
        self.success = success
        self.elapsed_seconds = elapsed_seconds
        self.output_size = output_size
        self.run_id = run_id
        self.scope_id = scope_id


# ---------------------------------------------------------------------------
# Codec registry seam
# ---------------------------------------------------------------------------


def test_default_registry_encodes_core_records() -> None:
    registry = default_core_codec_registry()
    envelope = registry.encode(
        EventRecord(name="tool_call"),
        scope_id="scope-1",
        source="unit-test",
    )
    assert (envelope.namespace, envelope.kind, envelope.schema_version) == (
        "arema.core",
        "event",
        1,
    )
    checkpoint = registry.encode(
        CheckpointRecord(label="c", sequence=1),
        scope_id="scope-1",
        source="unit-test",
    )
    assert (checkpoint.namespace, checkpoint.kind) == ("arema.core", "checkpoint")
    note = registry.encode(NoteRecord(text="t", author="a"), scope_id="s", source="u")
    assert note.kind == "note"
    artifact = registry.encode(
        ArtifactRecord(uri="s3://x", media_type="text/plain", byte_size=1, sha256="0" * 64),
        scope_id="s",
        source="u",
    )
    assert artifact.kind == "artifact"


# ---------------------------------------------------------------------------
# append / append_event
# ---------------------------------------------------------------------------


def test_append_event_persists_core_event_envelope() -> None:
    service = build_service()
    scope = service.create_scope(MemoryScope(scope_type="run"))
    stored = service.append_event(
        scope.id,
        EventRecord(name="tool_call", attributes={"tool_id": "lookup"}),
        source="lookup",
    )
    assert stored.namespace == "arema.core"
    assert stored.kind == "event"
    assert stored.content_hash == canonical_content_hash(stored.payload)


def test_append_rejects_namespace_kind_mismatch() -> None:
    service = build_service()
    scope = service.create_scope(MemoryScope(scope_type="run"))
    with pytest.raises(MemoryStoreError):
        service.append(
            scope.id,
            EventRecord(name="tool_call"),
            namespace="wrong",
            kind="event",
            source="lookup",
        )


def test_append_checkpoint_persists_core_checkpoint_envelope() -> None:
    service = build_service()
    scope = service.create_scope(MemoryScope(scope_type="run"))
    stored = service.append_checkpoint(
        scope.id,
        CheckpointRecord(label="turn-3", sequence=3, state={"tool_calls": 5}),
        source="arema.runtime",
    )
    assert stored.namespace == "arema.core"
    assert stored.kind == "checkpoint"


# ---------------------------------------------------------------------------
# safe_append_event / append_event failure semantics
# ---------------------------------------------------------------------------


def test_safe_append_event_returns_true_on_success() -> None:
    service = build_service()
    scope = service.create_scope(MemoryScope(scope_type="run"))
    assert service.safe_append_event(scope.id, EventRecord(name="ok"), source="unit") is True
    assert service.health().healthy is True


def test_safe_append_event_returns_false_and_degrades_on_failure() -> None:
    store: MemoryStore = _FailingStore()  # type: ignore[assignment]
    service = MemoryService(store=store, codecs=default_core_codec_registry())
    result = service.safe_append_event(
        "scope-1",
        EventRecord(name="boom"),
        source="unit",
    )
    assert result is False
    assert service.health().healthy is False


def test_append_event_raises_strictly_on_failure() -> None:
    store: MemoryStore = _FailingStore()  # type: ignore[assignment]
    service = MemoryService(store=store, codecs=default_core_codec_registry())
    with pytest.raises(MemoryStoreError):
        service.append_event("scope-1", EventRecord(name="boom"), source="unit")


# ---------------------------------------------------------------------------
# record_tool_event (MemoryEventSink structural satisfaction)
# ---------------------------------------------------------------------------


def test_record_tool_event_writes_sanitized_event() -> None:
    service = build_service()
    scope = service.create_scope(MemoryScope(scope_type="run"))
    service.record_tool_event(
        _ToolEvent(
            tool_id="lookup",
            success=True,
            elapsed_seconds=1.5,
            output_size=42,
            run_id="run-1",
            scope_id=scope.id,
        )
    )
    page = service.retrieve_bounded(MemoryQuery(scope_id=scope.id))
    assert len(page.records) == 1
    record = page.records[0]
    assert isinstance(record, EventRecord)
    assert record.attributes == {
        "tool_id": "lookup",
        "success": True,
        "elapsed_seconds": 1.5,
        "output_size": 42,
        "run_id": "run-1",
    }


def test_record_tool_event_without_scope_is_a_noop() -> None:
    service = build_service()
    service.record_tool_event(
        _ToolEvent(
            tool_id="lookup",
            success=True,
            elapsed_seconds=0.1,
            output_size=1,
            run_id="run-1",
            scope_id=None,
        )
    )
    # Nothing was attributed to any scope; a broad query returns nothing.
    assert service.retrieve_bounded(MemoryQuery()).records == ()


def test_record_tool_event_satisfies_runtime_event_sink() -> None:
    from arema.runtime.services import MemoryEventSink, ToolEvent

    service = build_service()
    assert isinstance(service, MemoryEventSink)
    scope = service.create_scope(MemoryScope(scope_type="run"))
    service.record_tool_event(
        ToolEvent(
            tool_id="lookup",
            success=False,
            elapsed_seconds=0.2,
            output_size=7,
            run_id="run-1",
            scope_id=scope.id,
        )
    )
    assert len(service.retrieve_bounded(MemoryQuery(scope_id=scope.id)).records) == 1


# ---------------------------------------------------------------------------
# retrieve_bounded
# ---------------------------------------------------------------------------


def test_retrieve_bounded_decodes_known_and_passes_through_unknown() -> None:
    service = build_service()
    store = service.store
    scope = service.create_scope(MemoryScope(scope_type="run"))
    service.append_event(scope.id, EventRecord(name="known"), source="unit")
    raw_payload = {"blob": "x"}
    store.insert_record(
        MemoryEnvelope(
            scope_id=scope.id,
            namespace="extension",
            kind="unknown",
            schema_version=1,
            source="unit",
            payload=raw_payload,
            content_hash=canonical_content_hash(raw_payload),
        )
    )
    result = service.retrieve_bounded(MemoryQuery(scope_id=scope.id))
    kinds = {type(record).__name__ for record in result.records}
    assert "EventRecord" in kinds
    assert "MemoryEnvelope" in kinds


def test_retrieve_bounded_caps_record_count() -> None:
    service = build_service()
    scope = service.create_scope(MemoryScope(scope_type="run"))
    for index in range(5):
        service.append_event(scope.id, EventRecord(name=f"e{index}"), source="unit")
    result = service.retrieve_bounded(MemoryQuery(scope_id=scope.id), max_records=2)
    assert len(result.records) == 2
    assert result.truncated is True


def test_retrieve_bounded_caps_token_budget() -> None:
    service = build_service()
    scope = service.create_scope(MemoryScope(scope_type="run"))
    big = "x" * 400  # ~100 estimated tokens per record
    for index in range(5):
        service.append_event(
            scope.id,
            EventRecord(name=f"e{index}", attributes={"blob": big}),
            source="unit",
        )
    result = service.retrieve_bounded(
        MemoryQuery(scope_id=scope.id),
        max_records=50,
        token_limit=150,
    )
    assert len(result.records) < 5
    assert result.estimated_tokens <= 150
    assert result.truncated is True


def test_retrieve_bounded_uses_settings_defaults() -> None:
    service = build_service()
    scope = service.create_scope(MemoryScope(scope_type="run"))
    service.append_event(scope.id, EventRecord(name="only"), source="unit")
    result = service.retrieve_bounded(MemoryQuery(scope_id=scope.id))
    assert isinstance(result, BoundedRetrieval)
    assert len(result.records) == 1
    assert result.truncated is False


# ---------------------------------------------------------------------------
# health / scope passthrough
# ---------------------------------------------------------------------------


def test_health_reflects_store_health() -> None:
    store = InMemoryStore()  # not initialised -> unhealthy
    service = MemoryService(store=store, codecs=default_core_codec_registry())
    assert service.health().healthy is False


def test_close_scope_defaults_to_now() -> None:
    service = build_service()
    scope = service.create_scope(MemoryScope(scope_type="run"))
    closed = service.close_scope(scope.id)
    assert closed.closed_at is not None
