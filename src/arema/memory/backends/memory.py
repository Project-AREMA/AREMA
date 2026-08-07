"""An in-process, thread-safe :class:`~arema.memory.store.MemoryStore`.

This backend keeps scopes, records, and relations in plain dictionaries guarded
by a single reentrant lock. It is the reference implementation the shared store
contract is written against and the default backend for tests and ephemeral
runs; the durable SQLite backend is layered on the same contract later.

Two design points carry the weight of correctness:

* **Transactions are snapshot-and-restore.** :meth:`InMemoryStore.transaction`
  takes the reentrant lock for the whole unit of work and shallow-copies every
  dictionary on entry. Because the stored values are frozen Pydantic models,
  mutation only ever happens by rebinding a dict entry, so restoring the three
  snapshot dicts on exception is a complete, atomic rollback. Holding the lock
  across the ``yield`` serialises writers and makes nested transactions
  (reentrant on the same thread) compose correctly.

* **Cursors are opaque, self-describing tokens.** A cursor is the URL-safe
  base64 of compact JSON carrying the last row's ``(created_at, id)``. Paging
  resumes at the first row strictly greater than that pair under the canonical
  ``(created_at, id)`` ordering, which keeps pagination stable even when two
  records share a timestamp. Any token that fails to decode raises
  :class:`~arema.memory.errors.InvalidCursorError`.
"""

from __future__ import annotations

import base64
import json
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import TYPE_CHECKING

from arema.memory.errors import (
    InvalidCursorError,
    RecordNotFoundError,
    RelationIntegrityError,
    RevisionConflictError,
)
from arema.memory.models import (
    MemoryEnvelope,
    MemoryPage,
    MemoryQuery,
    MemoryRelation,
    MemoryScope,
    utc_now,
)
from arema.memory.store import StoreHealth

if TYPE_CHECKING:
    from collections.abc import Iterator

# The canonical sort key for records: creation instant, then id as a stable
# tie-breaker so equal timestamps still yield a total order.
_SortKey = tuple[datetime, str]


class InMemoryStore:
    """A thread-safe, dictionary-backed memory store."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._initialized = False
        self._scopes: dict[str, MemoryScope] = {}
        self._records: dict[str, MemoryEnvelope] = {}
        self._relations: dict[str, MemoryRelation] = {}

    # -- Lifecycle ------------------------------------------------------------

    def initialize(self) -> None:
        """Mark the backend ready. Idempotent; the in-memory store never fails."""
        with self._lock:
            self._initialized = True

    def health(self) -> StoreHealth:
        """Expose readiness -- healthy only once :meth:`initialize` has run."""
        with self._lock:
            if self._initialized:
                return StoreHealth(healthy=True)
            return StoreHealth(healthy=False, detail="store not initialized")

    # -- Transactions ---------------------------------------------------------

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Run an atomic unit of work, rolling every dict back on exception."""
        with self._lock:
            scopes_snapshot = dict(self._scopes)
            records_snapshot = dict(self._records)
            relations_snapshot = dict(self._relations)
            try:
                yield
            except BaseException:
                self._scopes = scopes_snapshot
                self._records = records_snapshot
                self._relations = relations_snapshot
                raise

    # -- Scopes ---------------------------------------------------------------

    def create_scope(self, scope: MemoryScope) -> MemoryScope:
        with self._lock:
            stored = scope.model_copy()
            self._scopes[stored.id] = stored
            return stored.model_copy()

    def get_scope(self, scope_id: str) -> MemoryScope | None:
        with self._lock:
            stored = self._scopes.get(scope_id)
            return stored.model_copy() if stored is not None else None

    def close_scope(self, scope_id: str, closed_at: datetime) -> MemoryScope:
        with self._lock:
            stored = self._scopes.get(scope_id)
            if stored is None:
                raise RecordNotFoundError(f"scope {scope_id!r} does not exist")
            closed = stored.model_copy(update={"closed_at": closed_at})
            self._scopes[scope_id] = closed
            return closed.model_copy()

    # -- Records --------------------------------------------------------------

    def insert_record(self, record: MemoryEnvelope) -> MemoryEnvelope:
        with self._lock:
            stored = record.model_copy()
            self._records[stored.id] = stored
            return stored.model_copy()

    def get_record(self, record_id: str) -> MemoryEnvelope | None:
        with self._lock:
            stored = self._records.get(record_id)
            return stored.model_copy() if stored is not None else None

    def update_record(
        self,
        record: MemoryEnvelope,
        expected_revision: int,
    ) -> MemoryEnvelope:
        with self._lock:
            existing = self._records.get(record.id)
            if existing is None:
                raise RecordNotFoundError(f"record {record.id!r} does not exist")
            if existing.revision != expected_revision:
                raise RevisionConflictError(
                    f"record {record.id!r} is at revision {existing.revision}, "
                    f"not the expected {expected_revision}",
                )
            updated = record.model_copy(
                update={
                    "revision": existing.revision + 1,
                    "updated_at": utc_now(),
                    "created_at": existing.created_at,
                },
            )
            self._records[record.id] = updated
            return updated.model_copy()

    def query_records(self, query: MemoryQuery) -> MemoryPage:
        with self._lock:
            now = utc_now()
            matches = [
                record for record in self._records.values() if self._matches(record, query, now)
            ]
            matches.sort(key=self._sort_key)

            if query.cursor is not None:
                after = self._decode_cursor(query.cursor)
                matches = [record for record in matches if self._sort_key(record) > after]

            page_items = matches[: query.limit]
            has_more = len(matches) > query.limit
            next_cursor = self._encode_cursor(page_items[-1]) if has_more and page_items else None
            return MemoryPage(
                items=tuple(record.model_copy() for record in page_items),
                next_cursor=next_cursor,
            )

    # -- Relations ------------------------------------------------------------

    def create_relation(self, relation: MemoryRelation) -> MemoryRelation:
        with self._lock:
            if relation.source_id not in self._records:
                raise RelationIntegrityError(
                    f"relation source {relation.source_id!r} does not exist",
                )
            if relation.target_id not in self._records:
                raise RelationIntegrityError(
                    f"relation target {relation.target_id!r} does not exist",
                )
            stored = relation.model_copy()
            self._relations[stored.id] = stored
            return stored.model_copy()

    def list_relations(self, record_id: str) -> tuple[MemoryRelation, ...]:
        with self._lock:
            incident = [
                relation
                for relation in self._relations.values()
                if record_id in (relation.source_id, relation.target_id)
            ]
            incident.sort(key=lambda relation: (relation.created_at, relation.id))
            return tuple(relation.model_copy() for relation in incident)

    # -- Internal helpers -----------------------------------------------------

    @staticmethod
    def _sort_key(record: MemoryEnvelope) -> _SortKey:
        return (record.created_at, record.id)

    @staticmethod
    def _matches(record: MemoryEnvelope, query: MemoryQuery, now: datetime) -> bool:
        if query.scope_id is not None and record.scope_id != query.scope_id:
            return False
        if query.namespace is not None and record.namespace != query.namespace:
            return False
        if query.kind is not None and record.kind != query.kind:
            return False
        if query.source is not None and record.source != query.source:
            return False
        if not query.include_expired and record.expires_at is not None:
            if record.expires_at <= now:
                return False
        if query.tags:
            raw_tags = record.metadata.get("tags")
            record_tags = raw_tags if isinstance(raw_tags, list) else []
            if not all(tag in record_tags for tag in query.tags):
                return False
        return True

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

    _protocol_check: MemoryStore = InMemoryStore()
