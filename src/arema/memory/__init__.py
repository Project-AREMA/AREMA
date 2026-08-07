"""Domain-neutral memory envelopes, payload records, codecs, and storage."""

from arema.memory.backends import InMemoryStore
from arema.memory.codecs import (
    RecordCodec,
    RecordCodecRegistry,
    UpgradeFn,
    canonical_content_hash,
)
from arema.memory.errors import (
    BackendInitError,
    BackendUnavailableError,
    CodecRegistrationError,
    InvalidCursorError,
    MemoryStoreError,
    RecordNotFoundError,
    RelationIntegrityError,
    RevisionConflictError,
)
from arema.memory.models import (
    ArtifactRecord,
    CheckpointRecord,
    EventRecord,
    JsonValue,
    MemoryEnvelope,
    MemoryPage,
    MemoryQuery,
    MemoryRelation,
    MemoryScope,
    NoteRecord,
    utc_now,
)
from arema.memory.store import MemoryStore, StoreHealth

__all__ = [
    # Models
    "ArtifactRecord",
    "CheckpointRecord",
    "EventRecord",
    "JsonValue",
    "MemoryEnvelope",
    "MemoryPage",
    "MemoryQuery",
    "MemoryRelation",
    "MemoryScope",
    "NoteRecord",
    "utc_now",
    # Codecs
    "RecordCodec",
    "RecordCodecRegistry",
    "UpgradeFn",
    "canonical_content_hash",
    # Store
    "InMemoryStore",
    "MemoryStore",
    "StoreHealth",
    # Errors
    "BackendInitError",
    "BackendUnavailableError",
    "CodecRegistrationError",
    "InvalidCursorError",
    "MemoryStoreError",
    "RecordNotFoundError",
    "RelationIntegrityError",
    "RevisionConflictError",
]
