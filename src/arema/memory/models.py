"""Domain-neutral memory envelope and payload record models.

These models are the storage-agnostic vocabulary of the memory subsystem. An
envelope wraps an opaque JSON payload with routing metadata (scope, namespace,
kind, schema version) and a content hash; the payload record models describe
the concrete shapes an envelope can carry once a codec decodes it.

Every model is a strict Pydantic v2 value object. Timestamps are always
UTC-aware -- there are no naive datetimes anywhere in the subsystem -- and the
scope and envelope models are frozen so an identity, once minted, cannot be
mutated in place.

:data:`JsonValue` is a recursive alias built with :class:`TypeAliasType`
rather than a bare ``TypeAlias`` union: Pydantic v2 cannot generate a schema
for an implicitly recursive plain alias (it recurses until the interpreter's
stack is exhausted), so a named PEP 695-style alias is required to give the
recursion a resolvable reference.
"""

from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field
from typing_extensions import TypeAliasType

JsonValue = TypeAliasType(
    "JsonValue",
    "str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]",
)
"""Any value expressible as JSON, including nested lists and objects."""

_SHA256_PATTERN = r"^[0-9a-f]{64}$"


def utc_now() -> datetime:
    """Return the current instant as a UTC-aware :class:`datetime`."""
    return datetime.now(tz=UTC)


class MemoryScope(BaseModel):
    """A bounded lifetime that owns a set of memory envelopes and relations."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: uuid4().hex)
    parent_id: str | None = None
    scope_type: str
    created_at: datetime = Field(default_factory=utc_now)
    closed_at: datetime | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class MemoryEnvelope(BaseModel):
    """A routed, content-addressed wrapper around an opaque JSON payload."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: uuid4().hex)
    scope_id: str
    namespace: str
    kind: str
    schema_version: int = Field(ge=1)
    revision: int = Field(default=1, ge=1)
    source: str
    payload: dict[str, JsonValue]
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    content_hash: str
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None


class MemoryRelation(BaseModel):
    """A directed, typed link between two memory envelopes."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=lambda: uuid4().hex)
    scope_id: str | None = None
    source_id: str
    target_id: str
    relation_type: str
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class MemoryQuery(BaseModel):
    """A read request that filters envelopes and drives cursor pagination."""

    model_config = ConfigDict(frozen=True)

    scope_id: str | None = None
    namespace: str | None = None
    kind: str | None = None
    source: str | None = None
    tags: tuple[str, ...] = ()
    limit: int = Field(default=50, ge=1, le=1000)
    cursor: str | None = None
    include_expired: bool = False


class MemoryPage(BaseModel):
    """One page of envelopes plus an optional cursor for the next page."""

    model_config = ConfigDict(frozen=True)

    items: tuple[MemoryEnvelope, ...] = ()
    next_cursor: str | None = None


class EventRecord(BaseModel):
    """A neutral, timestamped event with free-form attributes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    attributes: dict[str, JsonValue] = Field(default_factory=dict)
    occurred_at: datetime = Field(default_factory=utc_now)


class ArtifactRecord(BaseModel):
    """A reference to an external artifact -- never its bytes.

    The record captures where the artifact lives (``uri``), what it is
    (``media_type``), how large it is (``byte_size``), and a SHA-256 integrity
    digest. The digest is required: an artifact reference without one cannot
    be trusted, so omitting it raises a validation error. ``extra="forbid"``
    guarantees no caller can smuggle raw content into the record.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    uri: str
    media_type: str
    byte_size: int = Field(ge=0)
    sha256: str = Field(pattern=_SHA256_PATTERN)


class NoteRecord(BaseModel):
    """A free-text note attributed to an author."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    text: str
    author: str


class CheckpointRecord(BaseModel):
    """A durable marker of progress with an ordered sequence and saved state."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    label: str
    sequence: int = Field(ge=0)
    state: dict[str, JsonValue] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
