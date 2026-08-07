"""Ordered, forward-only schema migrations for the SQLite memory backend.

Each :class:`Migration` bundles a version with the DDL statements that advance
the schema to it. :func:`apply_migrations` bootstraps a ``schema_migrations``
ledger, then applies every not-yet-recorded migration inside its own
``BEGIN IMMEDIATE`` transaction, recording the version only once all of its
statements have committed. Because the ledger is consulted first and every
statement uses ``IF NOT EXISTS`` where a re-run could otherwise conflict,
applying the set is idempotent: a second call is a no-op.

The stored vocabulary is deliberately backend-neutral. Timestamps are ISO-8601
UTC text so they sort lexicographically in chronological order; payload and
metadata are JSON text; and every cross-row reference is a real foreign key so
the database -- not application code -- guarantees referential integrity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from arema.memory.models import utc_now

if TYPE_CHECKING:
    import sqlite3

_BOOTSTRAP_LEDGER = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
)
"""

_CREATE_SCOPES = """
CREATE TABLE memory_scopes (
    id TEXT PRIMARY KEY,
    parent_id TEXT,
    scope_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    closed_at TEXT,
    metadata TEXT NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES memory_scopes(id)
)
"""

_CREATE_RECORDS = """
CREATE TABLE memory_records (
    id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    source TEXT NOT NULL,
    payload TEXT NOT NULL,
    metadata TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT,
    FOREIGN KEY (scope_id) REFERENCES memory_scopes(id)
)
"""

_CREATE_RELATIONS = """
CREATE TABLE memory_relations (
    id TEXT PRIMARY KEY,
    scope_id TEXT,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    metadata TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scope_id) REFERENCES memory_scopes(id),
    FOREIGN KEY (source_id) REFERENCES memory_records(id),
    FOREIGN KEY (target_id) REFERENCES memory_records(id)
)
"""

_INDEX_SCOPE_KIND = """
CREATE INDEX idx_memory_records_scope_kind
ON memory_records(scope_id, namespace, kind, created_at, id)
"""

_INDEX_SOURCE = """
CREATE INDEX idx_memory_records_source
ON memory_records(source, created_at, id)
"""

_INDEX_EXPIRY = """
CREATE INDEX idx_memory_records_expiry
ON memory_records(expires_at)
"""


@dataclass(frozen=True, slots=True)
class Migration:
    """One versioned, atomically applied set of schema statements."""

    version: int
    statements: tuple[str, ...]


MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=1,
        statements=(
            _CREATE_SCOPES,
            _CREATE_RECORDS,
            _CREATE_RELATIONS,
            _INDEX_SCOPE_KIND,
            _INDEX_SOURCE,
            _INDEX_EXPIRY,
        ),
    ),
)


def _applied_versions(connection: sqlite3.Connection) -> frozenset[int]:
    rows = connection.execute("SELECT version FROM schema_migrations").fetchall()
    return frozenset(int(row[0]) for row in rows)


def apply_migrations(connection: sqlite3.Connection) -> None:
    """Apply every unrecorded migration in order, one transaction each.

    The migration ledger is bootstrapped idempotently, then each pending
    migration runs inside its own ``BEGIN IMMEDIATE`` and is recorded only
    after all of its statements succeed; any failure rolls the whole migration
    back and leaves the ledger untouched.
    """
    connection.execute(_BOOTSTRAP_LEDGER)
    applied = _applied_versions(connection)

    for migration in MIGRATIONS:
        if migration.version in applied:
            continue
        connection.execute("BEGIN IMMEDIATE")
        try:
            for statement in migration.statements:
                connection.execute(statement)
            connection.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (migration.version, utc_now().isoformat()),
            )
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
