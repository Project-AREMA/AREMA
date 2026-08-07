"""The backend-neutral store protocol and its health value.

:class:`MemoryStore` is the single port every persistence backend implements.
It is a :func:`~typing.runtime_checkable` :class:`~typing.Protocol` -- structural,
not nominal -- so a backend need only match the shape; it does not inherit from
this module. That keeps the storage layer a true hexagonal adapter: the domain
depends on the port, and each backend (in-memory, SQLite, ...) is an
interchangeable plug validated by one shared contract test.

:class:`StoreHealth` is the small, frozen value returned by
:meth:`MemoryStore.health` -- a liveness signal a supervisor can poll without
reaching into backend internals.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from contextlib import AbstractContextManager
    from datetime import datetime

    from arema.memory.models import (
        MemoryEnvelope,
        MemoryPage,
        MemoryQuery,
        MemoryRelation,
        MemoryScope,
    )


class StoreHealth(BaseModel):
    """A backend liveness signal: a ready flag plus optional human detail."""

    model_config = ConfigDict(frozen=True)

    healthy: bool
    detail: str | None = None


@runtime_checkable
class MemoryStore(Protocol):
    """The port every memory backend implements.

    All methods are synchronous and operate on frozen value objects. Reads
    return defensive copies so a caller can never mutate persisted state, and
    every backend enforces the same optimistic-concurrency, ordering, and
    pagination guarantees exercised by the shared store contract.
    """

    def initialize(self) -> None:
        """Prepare the backend for use, raising ``BackendInitError`` on failure."""
        ...

    def transaction(self) -> AbstractContextManager[None]:
        """Return an atomic unit of work that rolls back on any exception."""
        ...

    def create_scope(self, scope: MemoryScope) -> MemoryScope:
        """Persist ``scope`` and return the stored copy."""
        ...

    def get_scope(self, scope_id: str) -> MemoryScope | None:
        """Return the scope with ``scope_id``, or ``None`` when absent."""
        ...

    def close_scope(self, scope_id: str, closed_at: datetime) -> MemoryScope:
        """Mark a scope closed, raising ``RecordNotFoundError`` when absent."""
        ...

    def insert_record(self, record: MemoryEnvelope) -> MemoryEnvelope:
        """Persist ``record`` and return the stored copy."""
        ...

    def get_record(self, record_id: str) -> MemoryEnvelope | None:
        """Return the record with ``record_id``, or ``None`` when absent."""
        ...

    def update_record(
        self,
        record: MemoryEnvelope,
        expected_revision: int,
    ) -> MemoryEnvelope:
        """Update a record under an optimistic-concurrency revision check.

        Raises ``RecordNotFoundError`` when the id is absent and
        ``RevisionConflictError`` when the stored revision differs from
        ``expected_revision``. On success the revision and ``updated_at`` are
        bumped and the stored copy is returned.
        """
        ...

    def query_records(self, query: MemoryQuery) -> MemoryPage:
        """Return one deterministically ordered page of matching records."""
        ...

    def create_relation(self, relation: MemoryRelation) -> MemoryRelation:
        """Persist a relation, raising ``RelationIntegrityError`` for missing ends."""
        ...

    def list_relations(self, record_id: str) -> tuple[MemoryRelation, ...]:
        """Return every relation where ``record_id`` is the source or target."""
        ...

    def health(self) -> StoreHealth:
        """Return the backend's current liveness signal."""
        ...
