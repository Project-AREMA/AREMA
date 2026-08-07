"""The SQLite backend, verified against the shared store contract.

``TestSQLiteStore`` inherits every behavioural case from
:class:`BackendContract`; the ``store`` fixture is the only backend-specific
wiring, proving the durable backend is interchangeable with the in-memory one.
The extra tests below cover behaviour unique to the SQLite backend -- repeatable
initialisation, once-only migration bookkeeping, foreign-key enforcement, WAL
journalling, and a single winner under concurrent optimistic updates -- that the
neutral contract does not prescribe.
"""

from __future__ import annotations

import sqlite3
import threading
from typing import TYPE_CHECKING

import pytest
from store_contract import BackendContract, note_envelope

from arema.memory.backends.sqlite import SQLiteStore
from arema.memory.errors import MemoryStoreError, RelationIntegrityError, RevisionConflictError
from arema.memory.models import MemoryRelation, MemoryScope

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture
def store(tmp_path: Path) -> Iterator[SQLiteStore]:
    value = SQLiteStore(tmp_path / "arema.db")
    value.initialize()
    yield value
    value.close()


class TestSQLiteStore(BackendContract):
    """Runs the full neutral contract against :class:`SQLiteStore`."""


# -- Backend-specific behaviour ----------------------------------------------


def test_health_is_unready_before_initialize(tmp_path: Path) -> None:
    backend = SQLiteStore(tmp_path / "arema.db")
    assert backend.health().healthy is False
    backend.close()


def test_initialize_is_repeatable(store: SQLiteStore) -> None:
    # The fixture already initialised once; a second and third call must not
    # fail, re-run migrations, or corrupt the schema.
    store.initialize()
    store.initialize()
    assert store.health().healthy is True


def test_migration_is_recorded_exactly_once(store: SQLiteStore, tmp_path: Path) -> None:
    store.initialize()  # a redundant call must not add a second migration row
    raw = sqlite3.connect(tmp_path / "arema.db")
    try:
        versions = [row[0] for row in raw.execute("SELECT version FROM schema_migrations")]
    finally:
        raw.close()
    assert versions == [1]


def test_wal_mode_is_enabled(store: SQLiteStore, tmp_path: Path) -> None:
    del store  # the fixture's initialisation set the persistent WAL journal mode
    raw = sqlite3.connect(tmp_path / "arema.db")
    try:
        mode = raw.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        raw.close()
    assert mode.lower() == "wal"


def test_insert_record_rejects_missing_scope(store: SQLiteStore) -> None:
    # No scope is created; the foreign key on scope_id must reject the record.
    with pytest.raises(MemoryStoreError):
        store.insert_record(note_envelope("does-not-exist", "orphan"))


def test_relation_rejects_missing_record(store: SQLiteStore) -> None:
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


def test_concurrent_optimistic_update_has_one_winner(store: SQLiteStore) -> None:
    scope = store.create_scope(MemoryScope(scope_type="run"))
    record = store.insert_record(note_envelope(scope.id, "v1"))

    winners: list[str] = []
    losers: list[str] = []
    ready = threading.Barrier(2)

    def worker(label: str) -> None:
        ready.wait()
        try:
            store.update_record(
                record.model_copy(update={"payload": {"text": label}}),
                expected_revision=1,
            )
            winners.append(label)
        except RevisionConflictError:
            losers.append(label)

    threads = [threading.Thread(target=worker, args=(f"t{index}",)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(winners) == 1
    assert len(losers) == 1
    persisted = store.get_record(record.id)
    assert persisted is not None
    assert persisted.revision == 2
    assert persisted.payload == {"text": winners[0]}
