"""A durable, WAL-journalled :class:`~arema.memory.store.MemoryStore`.

This backend is the persistent sibling of the in-memory reference store and is
proven interchangeable with it by the same shared contract. It holds a single
SQLite connection (usable across threads) guarded by a reentrant lock, so every
operation is serialised into a consistent order -- which is exactly what makes
optimistic concurrency deterministic: two writers racing an
``update_record`` against the same revision resolve to one winner and one
:class:`~arema.memory.errors.RevisionConflictError`.

Three design points carry the correctness weight:

* **Explicit units of work.** The connection runs in autocommit mode
  (``isolation_level=None``); a depth-counting :meth:`_unit` opens a single
  ``BEGIN IMMEDIATE`` for the outermost write and commits (or rolls back) only
  when it closes, so :meth:`transaction` and the individual write methods
  compose without nested transactions.
* **Lexicographically ordered timestamps.** Every instant is stored as a
  microsecond-precision ISO-8601 UTC string, so ``ORDER BY created_at, id`` in
  SQL yields the same total order the contract's ``(created_at, id)`` key
  produces in Python, and expiry comparisons stay chronological.
* **Database-enforced integrity.** Foreign keys are enabled, so a record with an
  unknown scope or a relation with an unknown end is rejected by SQLite and
  translated into a typed memory error rather than silently corrupting the graph.

Optimistic updates are expressed as ``WHERE id = ? AND revision = ?``; when that
affects no rows a follow-up existence probe distinguishes a missing record from a
stale revision. All values are bound as parameters -- SQL text is composed only
from fixed, literal identifiers.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from arema.memory.errors import (
    BackendInitError,
    BackendUnavailableError,
    InvalidCursorError,
    MemoryStoreError,
    RecordNotFoundError,
    RelationIntegrityError,
    RevisionConflictError,
)
from arema.memory.migrations import apply_migrations
from arema.memory.models import (
    JsonValue,
    MemoryEnvelope,
    MemoryPage,
    MemoryQuery,
    MemoryRelation,
    MemoryScope,
    utc_now,
)
from arema.memory.store import StoreHealth

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

_SortKey = tuple[datetime, str]

_DEFAULT_BUSY_TIMEOUT_MS = 5_000

# Fixed statements. Every value is bound as a parameter; the only text ever
# assembled at runtime is the dynamic WHERE in ``_select_rows`` (see below).
_INSERT_SCOPE = (
    "INSERT INTO memory_scopes "
    "(id, parent_id, scope_type, created_at, closed_at, metadata) "
    "VALUES (?, ?, ?, ?, ?, ?)"
)
_SELECT_SCOPE = (
    "SELECT id, parent_id, scope_type, created_at, closed_at, metadata "
    "FROM memory_scopes WHERE id = ?"
)
_UPDATE_SCOPE_CLOSED = "UPDATE memory_scopes SET closed_at = ? WHERE id = ?"

_INSERT_RECORD = (
    "INSERT INTO memory_records "
    "(id, scope_id, namespace, kind, schema_version, revision, source, "
    "payload, metadata, content_hash, created_at, updated_at, expires_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
_SELECT_RECORD = (
    "SELECT id, scope_id, namespace, kind, schema_version, revision, source, "
    "payload, metadata, content_hash, created_at, updated_at, expires_at "
    "FROM memory_records WHERE id = ?"
)
_UPDATE_RECORD = (
    "UPDATE memory_records SET "
    "scope_id = ?, namespace = ?, kind = ?, schema_version = ?, "
    "source = ?, payload = ?, metadata = ?, content_hash = ?, "
    "expires_at = ?, revision = revision + 1, updated_at = ? "
    "WHERE id = ? AND revision = ?"
)
_SELECT_RECORD_REVISION = "SELECT revision FROM memory_records WHERE id = ?"
_SELECT_RECORDS_PREFIX = (
    "SELECT id, scope_id, namespace, kind, schema_version, revision, source, "
    "payload, metadata, content_hash, created_at, updated_at, expires_at "
    "FROM memory_records "
)
_INSERT_RELATION = (
    "INSERT INTO memory_relations "
    "(id, scope_id, source_id, target_id, relation_type, metadata, created_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?)"
)
_SELECT_RELATIONS = (
    "SELECT id, scope_id, source_id, target_id, relation_type, metadata, created_at "
    "FROM memory_relations WHERE source_id = ? OR target_id = ? "
    "ORDER BY created_at, id"
)


def _to_text(value: datetime) -> str:
    """Serialise an instant as a normalised, sortable UTC ISO-8601 string."""
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _from_text(value: str) -> datetime:
    """Parse a stored ISO-8601 timestamp back into an aware datetime."""
    return datetime.fromisoformat(value)


class SQLiteStore:
    """A single-file, WAL-journalled SQLite memory store."""

    def __init__(
        self,
        path: Path | str,
        *,
        busy_timeout_ms: int = _DEFAULT_BUSY_TIMEOUT_MS,
    ) -> None:
        self._path = Path(path)
        self._busy_timeout_ms = busy_timeout_ms
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._depth = 0
        self._initialized = False

    # -- Lifecycle ------------------------------------------------------------

    def initialize(self) -> None:
        """Open the database, enable pragmas, and apply migrations idempotently."""
        with self._lock:
            if self._initialized:
                return
            try:
                self._connect()
                apply_migrations(self._require_conn())
            except sqlite3.Error as exc:
                raise BackendInitError(f"SQLite initialisation failed: {exc}") from exc
            self._initialized = True

    def close(self) -> None:
        """Close the underlying connection; safe to call more than once."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
            self._initialized = False

    def health(self) -> StoreHealth:
        """Return readiness -- healthy only when the connection answers a probe."""
        with self._lock:
            if not self._initialized or self._conn is None:
                return StoreHealth(healthy=False, detail="store not initialized")
            try:
                self._conn.execute("SELECT 1")
            except sqlite3.Error as exc:
                return StoreHealth(healthy=False, detail=str(exc))
            return StoreHealth(healthy=True)

    def _connect(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=" + str(int(self._busy_timeout_ms)))
        self._conn = conn

    def _require_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise BackendUnavailableError("SQLite store is not initialized")
        return self._conn

    # -- Transactions ---------------------------------------------------------

    @contextmanager
    def _unit(self) -> Iterator[sqlite3.Connection]:
        """Run a write inside the outermost ``BEGIN IMMEDIATE`` unit of work."""
        with self._lock:
            conn = self._require_conn()
            opened = self._depth == 0
            if opened:
                conn.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield conn
            except BaseException:
                self._depth -= 1
                if opened:
                    conn.execute("ROLLBACK")
                raise
            else:
                self._depth -= 1
                if opened:
                    conn.execute("COMMIT")

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Return an atomic unit of work that rolls back on any exception."""
        with self._unit():
            yield

    # -- Scopes ---------------------------------------------------------------

    def create_scope(self, scope: MemoryScope) -> MemoryScope:
        with self._unit() as conn:
            try:
                conn.execute(
                    _INSERT_SCOPE,
                    (
                        scope.id,
                        scope.parent_id,
                        scope.scope_type,
                        _to_text(scope.created_at),
                        _to_text(scope.closed_at) if scope.closed_at is not None else None,
                        json.dumps(scope.metadata),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise MemoryStoreError(f"scope parent {scope.parent_id!r} does not exist") from exc
        return scope.model_copy()

    def get_scope(self, scope_id: str) -> MemoryScope | None:
        with self._lock:
            row = self._require_conn().execute(_SELECT_SCOPE, (scope_id,)).fetchone()
        return self._row_to_scope(row) if row is not None else None

    def close_scope(self, scope_id: str, closed_at: datetime) -> MemoryScope:
        with self._unit() as conn:
            cursor = conn.execute(_UPDATE_SCOPE_CLOSED, (_to_text(closed_at), scope_id))
            if cursor.rowcount == 0:
                raise RecordNotFoundError(f"scope {scope_id!r} does not exist")
            row = conn.execute(_SELECT_SCOPE, (scope_id,)).fetchone()
        return self._row_to_scope(row)

    # -- Records --------------------------------------------------------------

    def insert_record(self, record: MemoryEnvelope) -> MemoryEnvelope:
        with self._unit() as conn:
            try:
                conn.execute(_INSERT_RECORD, self._record_params(record))
            except sqlite3.IntegrityError as exc:
                raise MemoryStoreError(f"record scope {record.scope_id!r} does not exist") from exc
        return record.model_copy()

    def get_record(self, record_id: str) -> MemoryEnvelope | None:
        with self._lock:
            row = self._require_conn().execute(_SELECT_RECORD, (record_id,)).fetchone()
        return self._row_to_envelope(row) if row is not None else None

    def update_record(
        self,
        record: MemoryEnvelope,
        expected_revision: int,
    ) -> MemoryEnvelope:
        with self._unit() as conn:
            expires = _to_text(record.expires_at) if record.expires_at is not None else None
            cursor = conn.execute(
                _UPDATE_RECORD,
                (
                    record.scope_id,
                    record.namespace,
                    record.kind,
                    record.schema_version,
                    record.source,
                    json.dumps(record.payload),
                    json.dumps(record.metadata),
                    record.content_hash,
                    expires,
                    _to_text(utc_now()),
                    record.id,
                    expected_revision,
                ),
            )
            if cursor.rowcount == 0:
                existing = conn.execute(_SELECT_RECORD_REVISION, (record.id,)).fetchone()
                if existing is None:
                    raise RecordNotFoundError(f"record {record.id!r} does not exist")
                raise RevisionConflictError(
                    f"record {record.id!r} is at revision {existing[0]}, "
                    f"not the expected {expected_revision}"
                )
            row = conn.execute(_SELECT_RECORD, (record.id,)).fetchone()
        return self._row_to_envelope(row)

    def query_records(self, query: MemoryQuery) -> MemoryPage:
        with self._lock:
            records = [self._row_to_envelope(row) for row in self._select_rows(query)]
            now = utc_now()
            if not query.include_expired:
                records = [
                    record
                    for record in records
                    if record.expires_at is None or record.expires_at > now
                ]
            if query.tags:
                records = [record for record in records if self._has_all_tags(record, query.tags)]
            if query.cursor is not None:
                after = self._decode_cursor(query.cursor)
                records = [record for record in records if self._sort_key(record) > after]

            page_items = records[: query.limit]
            has_more = len(records) > query.limit
            next_cursor = self._encode_cursor(page_items[-1]) if has_more and page_items else None
            return MemoryPage(items=tuple(page_items), next_cursor=next_cursor)

    # -- Relations ------------------------------------------------------------

    def create_relation(self, relation: MemoryRelation) -> MemoryRelation:
        with self._unit() as conn:
            try:
                conn.execute(
                    _INSERT_RELATION,
                    (
                        relation.id,
                        relation.scope_id,
                        relation.source_id,
                        relation.target_id,
                        relation.relation_type,
                        json.dumps(relation.metadata),
                        _to_text(relation.created_at),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RelationIntegrityError(
                    f"relation {relation.source_id!r} -> {relation.target_id!r} "
                    "references a record that does not exist"
                ) from exc
        return relation.model_copy()

    def list_relations(self, record_id: str) -> tuple[MemoryRelation, ...]:
        with self._lock:
            rows = (
                self._require_conn().execute(_SELECT_RELATIONS, (record_id, record_id)).fetchall()
            )
        return tuple(self._row_to_relation(row) for row in rows)

    # -- Internal helpers -----------------------------------------------------

    def _select_rows(self, query: MemoryQuery) -> list[Sequence[object]]:
        clauses: list[str] = []
        params: list[object] = []
        for column, value in (
            ("scope_id = ?", query.scope_id),
            ("namespace = ?", query.namespace),
            ("kind = ?", query.kind),
            ("source = ?", query.source),
        ):
            if value is not None:
                clauses.append(column)
                params.append(value)
        where = ("WHERE " + " AND ".join(clauses) + " ") if clauses else ""
        # Only fixed literal fragments are concatenated here (the projection
        # constant and the ``column = ?`` clauses above); every value is bound
        # via ``params``, so no caller data reaches the SQL text.
        sql = _SELECT_RECORDS_PREFIX + where + "ORDER BY created_at, id"
        return self._require_conn().execute(sql, params).fetchall()

    @staticmethod
    def _record_params(record: MemoryEnvelope) -> tuple[object, ...]:
        return (
            record.id,
            record.scope_id,
            record.namespace,
            record.kind,
            record.schema_version,
            record.revision,
            record.source,
            json.dumps(record.payload),
            json.dumps(record.metadata),
            record.content_hash,
            _to_text(record.created_at),
            _to_text(record.updated_at),
            _to_text(record.expires_at) if record.expires_at is not None else None,
        )

    @staticmethod
    def _row_to_envelope(row: Sequence[object]) -> MemoryEnvelope:
        expires = row[12]
        return MemoryEnvelope(
            id=str(row[0]),
            scope_id=str(row[1]),
            namespace=str(row[2]),
            kind=str(row[3]),
            schema_version=int(str(row[4])),
            revision=int(str(row[5])),
            source=str(row[6]),
            payload=json.loads(str(row[7])),
            metadata=json.loads(str(row[8])),
            content_hash=str(row[9]),
            created_at=_from_text(str(row[10])),
            updated_at=_from_text(str(row[11])),
            expires_at=_from_text(str(expires)) if expires is not None else None,
        )

    @staticmethod
    def _row_to_scope(row: Sequence[object]) -> MemoryScope:
        closed = row[4]
        return MemoryScope(
            id=str(row[0]),
            parent_id=str(row[1]) if row[1] is not None else None,
            scope_type=str(row[2]),
            created_at=_from_text(str(row[3])),
            closed_at=_from_text(str(closed)) if closed is not None else None,
            metadata=json.loads(str(row[5])),
        )

    @staticmethod
    def _row_to_relation(row: Sequence[object]) -> MemoryRelation:
        return MemoryRelation(
            id=str(row[0]),
            scope_id=str(row[1]) if row[1] is not None else None,
            source_id=str(row[2]),
            target_id=str(row[3]),
            relation_type=str(row[4]),
            metadata=json.loads(str(row[5])),
            created_at=_from_text(str(row[6])),
        )

    @staticmethod
    def _sort_key(record: MemoryEnvelope) -> _SortKey:
        return (record.created_at, record.id)

    @staticmethod
    def _has_all_tags(record: MemoryEnvelope, tags: tuple[str, ...]) -> bool:
        raw_tags = record.metadata.get("tags")
        record_tags: list[JsonValue] = raw_tags if isinstance(raw_tags, list) else []
        return all(tag in record_tags for tag in tags)

    @staticmethod
    def _encode_cursor(record: MemoryEnvelope) -> str:
        token = json.dumps(
            {"created_at": record.created_at.isoformat(), "id": record.id},
            separators=(",", ":"),
        )
        return base64.urlsafe_b64encode(token.encode("utf-8")).decode("ascii")

    @staticmethod
    def _decode_cursor(cursor: str) -> _SortKey:
        try:
            raw = base64.urlsafe_b64decode(cursor.encode("ascii"))
            payload = json.loads(raw)
            created_at = datetime.fromisoformat(payload["created_at"])
            record_id = payload["id"]
        except (ValueError, KeyError, TypeError) as exc:
            raise InvalidCursorError(f"cursor {cursor!r} is not decodable") from exc
        if not isinstance(record_id, str):
            raise InvalidCursorError(f"cursor {cursor!r} carries a non-string id")
        return (created_at, record_id)


if TYPE_CHECKING:
    # Compile-time guarantee that the concrete backend satisfies the port.
    from arema.memory.store import MemoryStore

    _protocol_check: MemoryStore = SQLiteStore(Path("unused"))
