"""A backend-agnostic contract for :class:`arema.memory.store.MemoryStore`.

Every store implementation must behave identically from a caller's point of
view: the same insert/get/update semantics, the same optimistic-concurrency
rules, the same deterministic ordering, the same cursor pagination, and the
same transactional rollback guarantee. Rather than duplicate that expectation
per backend, the whole contract lives here as :class:`BackendContract` -- a mixin
of test methods driven by a single ``store`` fixture.

A concrete backend module (for example ``test_memory_store.py``) subclasses the
mixin and supplies a ``store`` fixture returning an initialised instance. The
SQLite backend added later reuses the identical mixin by supplying its own
fixture, so the two backends are proven interchangeable by construction.

The mixin class is deliberately named ``BackendContract`` (not ``Test*``) so
pytest never collects it on its own -- it only runs through a backend subclass
that provides the fixture.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from arema.memory import (
    InvalidCursorError,
    MemoryEnvelope,
    MemoryQuery,
    MemoryRelation,
    MemoryScope,
    RecordNotFoundError,
    RelationIntegrityError,
    RevisionConflictError,
    canonical_content_hash,
    utc_now,
)
from arema.memory.store import MemoryStore

if TYPE_CHECKING:
    from arema.memory.models import JsonValue


def note_envelope(scope_id: str, text: str, **overrides: object) -> MemoryEnvelope:
    """Build a valid note envelope for ``scope_id``, applying field overrides."""
    payload: dict[str, JsonValue] = {"text": text}
    fields: dict[str, object] = {
        "scope_id": scope_id,
        "namespace": "core",
        "kind": "note",
        "schema_version": 1,
        "source": "contract-test",
        "payload": payload,
        "content_hash": canonical_content_hash(payload),
    }
    fields.update(overrides)
    return MemoryEnvelope(**fields)


class BackendContract:
    """Behavioural contract shared by every :class:`MemoryStore` backend."""

    # -- Protocol conformance -------------------------------------------------

    def test_backend_satisfies_runtime_protocol(self, store: MemoryStore) -> None:
        assert isinstance(store, MemoryStore)

    def test_health_signals_ready_after_initialize(self, store: MemoryStore) -> None:
        health = store.health()
        assert health.healthy is True

    # -- Scopes ---------------------------------------------------------------

    def test_create_and_get_scope_round_trip(self, store: MemoryStore) -> None:
        created = store.create_scope(MemoryScope(scope_type="run"))
        fetched = store.get_scope(created.id)
        assert fetched is not None
        assert fetched.id == created.id
        assert fetched.scope_type == "run"

    def test_get_missing_scope_returns_none(self, store: MemoryStore) -> None:
        assert store.get_scope("does-not-exist") is None

    def test_nested_scopes_track_parent(self, store: MemoryStore) -> None:
        parent = store.create_scope(MemoryScope(scope_type="run"))
        child = store.create_scope(
            MemoryScope(scope_type="task", parent_id=parent.id),
        )
        stored_child = store.get_scope(child.id)
        assert stored_child is not None
        assert stored_child.parent_id == parent.id

    def test_close_scope_sets_closed_at(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        assert scope.closed_at is None
        moment = utc_now()
        closed = store.close_scope(scope.id, moment)
        assert closed.closed_at == moment
        persisted = store.get_scope(scope.id)
        assert persisted is not None
        assert persisted.closed_at == moment

    def test_close_missing_scope_raises(self, store: MemoryStore) -> None:
        with pytest.raises(RecordNotFoundError):
            store.close_scope("does-not-exist", utc_now())

    # -- Records --------------------------------------------------------------

    def test_insert_and_get_record_round_trip(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        inserted = store.insert_record(note_envelope(scope.id, "hello"))
        fetched = store.get_record(inserted.id)
        assert fetched is not None
        assert fetched.payload == {"text": "hello"}
        assert fetched.revision == 1

    def test_get_missing_record_returns_none(self, store: MemoryStore) -> None:
        assert store.get_record("does-not-exist") is None

    def test_reads_return_defensive_copies(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        inserted = store.insert_record(note_envelope(scope.id, "hello"))
        first = store.get_record(inserted.id)
        second = store.get_record(inserted.id)
        assert first == second
        # Distinct object identities prove the store hands out copies, not the
        # internally retained instance.
        assert first is not second

    def test_update_bumps_revision_and_updated_at(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        record = store.insert_record(note_envelope(scope.id, "first"))
        updated = store.update_record(
            record.model_copy(update={"payload": {"text": "second"}}),
            expected_revision=1,
        )
        assert updated.revision == 2
        assert updated.payload == {"text": "second"}
        assert updated.updated_at >= record.updated_at
        # created_at is preserved across updates.
        assert updated.created_at == record.created_at

    def test_update_rejects_stale_revision(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        record = store.insert_record(note_envelope(scope.id, "first"))
        store.update_record(
            record.model_copy(update={"payload": {"text": "second"}}),
            expected_revision=1,
        )
        with pytest.raises(RevisionConflictError):
            store.update_record(record, expected_revision=1)

    def test_update_missing_record_raises(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        orphan = note_envelope(scope.id, "orphan")
        with pytest.raises(RecordNotFoundError):
            store.update_record(orphan, expected_revision=1)

    # -- Query filters --------------------------------------------------------

    def test_query_filters_by_namespace_kind_and_source(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        wanted = store.insert_record(
            note_envelope(scope.id, "wanted", namespace="core", kind="note", source="a"),
        )
        store.insert_record(
            note_envelope(scope.id, "other-kind", namespace="core", kind="event", source="a"),
        )
        store.insert_record(
            note_envelope(scope.id, "other-source", namespace="core", kind="note", source="b"),
        )
        page = store.query_records(
            MemoryQuery(scope_id=scope.id, namespace="core", kind="note", source="a"),
        )
        assert [item.id for item in page.items] == [wanted.id]

    def test_query_filters_require_every_tag(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        both = store.insert_record(
            note_envelope(scope.id, "both", metadata={"tags": ["alpha", "beta"]}),
        )
        store.insert_record(
            note_envelope(scope.id, "partial", metadata={"tags": ["alpha"]}),
        )
        store.insert_record(note_envelope(scope.id, "untagged"))
        page = store.query_records(
            MemoryQuery(scope_id=scope.id, tags=("alpha", "beta")),
        )
        ids = [item.id for item in page.items]
        assert ids == [both.id]

    def test_query_ignores_non_list_tags_metadata(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        store.insert_record(
            note_envelope(scope.id, "bad-tags", metadata={"tags": "alpha"}),
        )
        page = store.query_records(
            MemoryQuery(scope_id=scope.id, tags=("alpha",)),
        )
        assert page.items == ()

    def test_query_without_tags_does_not_filter_on_tags(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        tagged = store.insert_record(
            note_envelope(scope.id, "tagged", metadata={"tags": ["alpha"]}),
        )
        untagged = store.insert_record(note_envelope(scope.id, "untagged"))
        page = store.query_records(MemoryQuery(scope_id=scope.id))
        ids = {item.id for item in page.items}
        assert ids == {tagged.id, untagged.id}

    # -- Expiry ---------------------------------------------------------------

    def test_query_excludes_expired_records_by_default(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        expired = store.insert_record(
            note_envelope(scope.id, "old", expires_at=utc_now() - timedelta(hours=1)),
        )
        live = store.insert_record(note_envelope(scope.id, "new"))
        default_ids = {
            item.id for item in store.query_records(MemoryQuery(scope_id=scope.id)).items
        }
        assert live.id in default_ids
        assert expired.id not in default_ids
        included_ids = {
            item.id
            for item in store.query_records(
                MemoryQuery(scope_id=scope.id, include_expired=True),
            ).items
        }
        assert expired.id in included_ids

    # -- Ordering and pagination ---------------------------------------------

    def test_query_orders_by_created_at_then_id(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        base = utc_now()
        # Two records share a created_at so the id tie-breaker is exercised.
        low_id = store.insert_record(
            note_envelope(scope.id, "tie-a", id="aaaa", created_at=base),
        )
        high_id = store.insert_record(
            note_envelope(scope.id, "tie-b", id="bbbb", created_at=base),
        )
        later = store.insert_record(
            note_envelope(scope.id, "later", created_at=base + timedelta(seconds=1)),
        )
        page = store.query_records(MemoryQuery(scope_id=scope.id, limit=1000))
        assert [item.id for item in page.items] == [low_id.id, high_id.id, later.id]

    def test_cursor_pagination_walks_every_record_once(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        base = utc_now()
        expected = [
            store.insert_record(
                note_envelope(scope.id, f"n{index}", created_at=base + timedelta(seconds=index)),
            ).id
            for index in range(5)
        ]
        collected: list[str] = []
        cursor: str | None = None
        for _ in range(10):  # generous upper bound to guard against a stuck cursor
            page = store.query_records(
                MemoryQuery(scope_id=scope.id, limit=2, cursor=cursor),
            )
            collected.extend(item.id for item in page.items)
            cursor = page.next_cursor
            if cursor is None:
                break
        assert collected == expected

    def test_final_page_has_no_next_cursor(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        store.insert_record(note_envelope(scope.id, "only"))
        page = store.query_records(MemoryQuery(scope_id=scope.id, limit=10))
        assert page.next_cursor is None

    def test_malformed_cursor_raises_invalid_cursor(self, store: MemoryStore) -> None:
        with pytest.raises(InvalidCursorError):
            store.query_records(MemoryQuery(cursor="%%%not-a-valid-cursor%%%"))

    # -- Relations ------------------------------------------------------------

    def test_create_relation_requires_existing_source(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        target = store.insert_record(note_envelope(scope.id, "target"))
        with pytest.raises(RelationIntegrityError):
            store.create_relation(
                MemoryRelation(
                    source_id="missing",
                    target_id=target.id,
                    relation_type="derived_from",
                ),
            )

    def test_create_relation_requires_existing_target(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        source = store.insert_record(note_envelope(scope.id, "source"))
        with pytest.raises(RelationIntegrityError):
            store.create_relation(
                MemoryRelation(
                    source_id=source.id,
                    target_id="missing",
                    relation_type="derived_from",
                ),
            )

    def test_list_relations_returns_incident_edges(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        left = store.insert_record(note_envelope(scope.id, "left"))
        right = store.insert_record(note_envelope(scope.id, "right"))
        other = store.insert_record(note_envelope(scope.id, "other"))
        edge = store.create_relation(
            MemoryRelation(
                source_id=left.id,
                target_id=right.id,
                relation_type="derived_from",
            ),
        )
        assert [rel.id for rel in store.list_relations(left.id)] == [edge.id]
        assert [rel.id for rel in store.list_relations(right.id)] == [edge.id]
        assert store.list_relations(other.id) == ()

    # -- Transactions ---------------------------------------------------------

    def test_transaction_commits_on_clean_exit(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        with store.transaction():
            kept = store.insert_record(note_envelope(scope.id, "kept"))
        assert store.get_record(kept.id) is not None

    def test_transaction_rolls_back_on_exception(self, store: MemoryStore) -> None:
        scope = store.create_scope(MemoryScope(scope_type="run"))
        baseline = store.insert_record(note_envelope(scope.id, "baseline"))
        with pytest.raises(RuntimeError, match="boom"), store.transaction():
            store.insert_record(note_envelope(scope.id, "discarded"))
            raise RuntimeError("boom")
        remaining = [item.id for item in store.query_records(MemoryQuery(scope_id=scope.id)).items]
        assert remaining == [baseline.id]
