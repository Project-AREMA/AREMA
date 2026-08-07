"""The typed memory service: the seam between callers and a raw store.

:class:`MemoryService` wraps a backend-neutral :class:`~arema.memory.store.MemoryStore`
with a :class:`~arema.memory.codecs.RecordCodecRegistry` so callers speak in typed
payload records instead of hand-built envelopes. It encodes typed records on the
way in, decodes retrieved pages on the way out, bounds what may enter model
context, and -- crucially -- degrades open: a failed lifecycle write is caught,
logged without sensitive detail, and surfaced through :meth:`health` rather than
aborting the run that produced it.

The service never imports the runtime layer (that would invert the dependency
and create a cycle). Instead it accepts a structural :class:`ToolEventLike` for
:meth:`record_tool_event`, which is exactly the shape of the runtime's neutral
``ToolEvent``; that makes a :class:`MemoryService` a drop-in ``MemoryEventSink``
without either side importing the other's concrete type. Only neutral lifecycle
metadata is ever persisted -- identities, an outcome flag, timings, counts, and
bounded checkpoint state -- never prompts, tool arguments, model text, or output.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from arema.core.config import get_settings
from arema.core.logging import get_logger
from arema.memory.codecs import RecordCodec, RecordCodecRegistry
from arema.memory.errors import MemoryStoreError
from arema.memory.models import (
    ArtifactRecord,
    CheckpointRecord,
    EventRecord,
    MemoryScope,
    NoteRecord,
    utc_now,
)
from arema.memory.store import StoreHealth

if TYPE_CHECKING:
    from datetime import datetime

    from pydantic import BaseModel

    from arema.core.config import Settings
    from arema.memory.models import (
        JsonValue,
        MemoryEnvelope,
        MemoryPage,
        MemoryQuery,
    )
    from arema.memory.store import MemoryStore

logger = get_logger(__name__)

CORE_NAMESPACE = "arema.core"
_EVENT_NAME_TOOL_CALL = "tool_call"
_CHARS_PER_TOKEN = 4


@runtime_checkable
class ToolEventLike(Protocol):
    """The neutral shape of a completed tool call the service can persist.

    This mirrors the runtime ``ToolEvent`` field-for-field so a runtime event is
    accepted here without the memory layer importing the runtime package.
    """

    @property
    def tool_id(self) -> str: ...
    @property
    def success(self) -> bool: ...
    @property
    def elapsed_seconds(self) -> float: ...
    @property
    def output_size(self) -> int: ...
    @property
    def run_id(self) -> str | None: ...
    @property
    def scope_id(self) -> str | None: ...


@dataclass(frozen=True, slots=True)
class BoundedRetrieval:
    """A record page bounded for model context, plus what was left out.

    ``records`` are decoded payloads (or the raw envelope when no codec matches);
    ``envelopes`` are the corresponding raw rows; ``truncated`` is ``True`` when
    either cap, or more pages, left additional matching records unreturned.
    """

    records: tuple[BaseModel | MemoryEnvelope, ...]
    envelopes: tuple[MemoryEnvelope, ...]
    estimated_tokens: int
    truncated: bool


def default_core_codec_registry() -> RecordCodecRegistry:
    """Build the ``arema.core`` codec registry shared across composition roots.

    Registers the four neutral core payloads at schema version 1 so both the
    service and any downstream composition can encode and decode them
    identically. Kept as a factory (not a module singleton) so each owner holds
    an isolated registry it may extend with domain codecs.
    """
    registry = RecordCodecRegistry()
    registry.register(
        RecordCodec(
            namespace=CORE_NAMESPACE,
            kind="event",
            schema_version=1,
            payload_type=EventRecord,
        )
    )
    registry.register(
        RecordCodec(
            namespace=CORE_NAMESPACE,
            kind="checkpoint",
            schema_version=1,
            payload_type=CheckpointRecord,
        )
    )
    registry.register(
        RecordCodec(
            namespace=CORE_NAMESPACE,
            kind="note",
            schema_version=1,
            payload_type=NoteRecord,
        )
    )
    registry.register(
        RecordCodec(
            namespace=CORE_NAMESPACE,
            kind="artifact",
            schema_version=1,
            payload_type=ArtifactRecord,
        )
    )
    return registry


class MemoryService:
    """Encode, persist, retrieve, and bound typed memory records over a store."""

    def __init__(
        self,
        *,
        store: MemoryStore,
        codecs: RecordCodecRegistry,
        settings: Settings | None = None,
    ) -> None:
        self._store = store
        self._codecs = codecs
        self._settings = settings if settings is not None else get_settings()
        self._degraded = False

    @property
    def store(self) -> MemoryStore:
        """Return the underlying store (for direct, un-encoded access in tests)."""
        return self._store

    # -- Scopes ---------------------------------------------------------------

    def create_scope(self, scope: MemoryScope) -> MemoryScope:
        """Persist a new scope and return the stored copy."""
        return self._store.create_scope(scope)

    def get_scope(self, scope_id: str) -> MemoryScope | None:
        """Return the scope with ``scope_id``, or ``None`` when absent."""
        return self._store.get_scope(scope_id)

    def close_scope(self, scope_id: str, closed_at: datetime | None = None) -> MemoryScope:
        """Close a scope, defaulting ``closed_at`` to the current instant."""
        return self._store.close_scope(scope_id, closed_at if closed_at is not None else utc_now())

    # -- Writes ---------------------------------------------------------------

    def append(
        self,
        scope_id: str,
        payload: BaseModel,
        *,
        namespace: str,
        kind: str,
        source: str,
        metadata: dict[str, JsonValue] | None = None,
    ) -> MemoryEnvelope:
        """Encode ``payload`` through the registry and persist it.

        The ``namespace``/``kind`` the caller declares must match the codec bound
        to the payload type; a mismatch is a wiring error and raises so it cannot
        silently persist under the wrong routing key.
        """
        envelope = self._codecs.encode(
            payload,
            scope_id=scope_id,
            source=source,
            metadata=metadata,
        )
        if envelope.namespace != namespace or envelope.kind != kind:
            raise MemoryStoreError(
                f"codec for {type(payload).__name__!r} produced "
                f"{envelope.namespace}/{envelope.kind}, expected {namespace}/{kind}"
            )
        return self._store.insert_record(envelope)

    def append_event(self, scope_id: str, event: EventRecord, *, source: str) -> MemoryEnvelope:
        """Persist a neutral event; raises strictly on any store failure."""
        return self.append(
            scope_id,
            event,
            namespace=CORE_NAMESPACE,
            kind="event",
            source=source,
        )

    def safe_append_event(self, scope_id: str, event: EventRecord, *, source: str) -> bool:
        """Persist an event fail-open: return ``False`` and degrade on failure."""
        try:
            self.append_event(scope_id, event, source=source)
        except MemoryStoreError as exc:
            logger.warning("memory event write failed", error_type=type(exc).__name__)
            self._degraded = True
            return False
        return True

    def append_checkpoint(
        self,
        scope_id: str,
        checkpoint: CheckpointRecord,
        *,
        source: str,
    ) -> MemoryEnvelope:
        """Persist a bounded progress checkpoint for ``scope_id``."""
        return self.append(
            scope_id,
            checkpoint,
            namespace=CORE_NAMESPACE,
            kind="checkpoint",
            source=source,
        )

    def record_tool_event(self, event: ToolEventLike) -> None:
        """Persist a neutral tool-call event (satisfies the runtime event sink).

        Only lifecycle metadata is recorded -- the tool identity, an outcome
        flag, elapsed time, output size, and run id -- never the tool arguments
        or output. A tool event without a scope has nowhere to be attributed and
        is dropped. The write is fail-open via :meth:`safe_append_event`.
        """
        scope_id = event.scope_id
        if scope_id is None:
            return
        record = EventRecord(
            name=_EVENT_NAME_TOOL_CALL,
            attributes={
                "tool_id": event.tool_id,
                "success": event.success,
                "elapsed_seconds": event.elapsed_seconds,
                "output_size": event.output_size,
                "run_id": event.run_id,
            },
        )
        self.safe_append_event(scope_id, record, source=event.tool_id)

    # -- Reads ----------------------------------------------------------------

    def retrieve_bounded(
        self,
        query: MemoryQuery,
        *,
        max_records: int | None = None,
        token_limit: int | None = None,
    ) -> BoundedRetrieval:
        """Return a page bounded by both record count and estimated tokens.

        Caps default to the conservative settings values. Records are admitted in
        the store's deterministic order until either cap would be exceeded; the
        result flags whether anything was left out so a caller can decide what to
        do -- nothing here is ever injected into an agent instruction implicitly.
        """
        record_cap = (
            max_records if max_records is not None else self._settings.memory_retrieval_max_records
        )
        token_cap = (
            token_limit if token_limit is not None else self._settings.memory_retrieval_token_limit
        )
        effective_limit = max(1, min(record_cap, 1000))

        page: MemoryPage = self._store.query_records(
            query.model_copy(update={"limit": effective_limit})
        )

        envelopes: list[MemoryEnvelope] = []
        used_tokens = 0
        budget_exceeded = False
        for envelope in page.items:
            if len(envelopes) >= record_cap:
                break
            cost = self._estimate_tokens(envelope)
            if used_tokens + cost > token_cap:
                budget_exceeded = True
                break
            envelopes.append(envelope)
            used_tokens += cost

        truncated = (
            budget_exceeded or page.next_cursor is not None or len(page.items) > len(envelopes)
        )
        records = tuple(self._codecs.decode(envelope) for envelope in envelopes)
        return BoundedRetrieval(
            records=records,
            envelopes=tuple(envelopes),
            estimated_tokens=used_tokens,
            truncated=truncated,
        )

    # -- Health ---------------------------------------------------------------

    def health(self) -> StoreHealth:
        """Return the store's health, signalling degraded after a write failure."""
        if self._degraded:
            return StoreHealth(healthy=False, detail="degraded: a memory write failed")
        return self._store.health()

    # -- Internal helpers -----------------------------------------------------

    @staticmethod
    def _estimate_tokens(envelope: MemoryEnvelope) -> int:
        serialized = json.dumps(envelope.payload, default=str, separators=(",", ":"))
        return max(1, len(serialized) // _CHARS_PER_TOKEN)
