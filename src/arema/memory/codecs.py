"""Versioned payload codecs and a registry that resolves them.

A :class:`RecordCodec` binds a ``(namespace, kind, schema_version)`` triple to
a concrete Pydantic payload model, plus -- for every version after the first
-- a pure function that upgrades the *previous* version's payload dict into
this version's shape. The :class:`RecordCodecRegistry` collects codecs into
contiguous version chains and uses them to encode records into envelopes and
decode envelopes back into records.

Two design points are worth calling out:

* **Canonical content hash.** Encoding hashes the payload with
  :func:`canonical_content_hash`, which serialises with ``sort_keys=True`` and
  compact separators. Sorting every key at every depth makes the digest
  independent of dict insertion order, so two semantically identical payloads
  always hash to the same value.

* **Upgrade chains.** Registration enforces that versions arrive contiguously
  starting at 1, that version 1 carries no upgrade function, and that every
  later version carries exactly one. Decoding then walks the chain from the
  envelope's ``schema_version`` up to the current version, applying each
  upgrade in order, and validates only the final payload against the current
  model. An envelope whose ``(namespace, kind)`` has no registered chain -- or
  whose version is newer than any registered codec -- is returned unchanged as
  a raw passthrough.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Generic, TypeAlias, TypeVar

from pydantic import BaseModel

from arema.memory.errors import CodecRegistrationError
from arema.memory.models import JsonValue, MemoryEnvelope

# The payload type is only ever *read* from a codec (as ``type[PayloadT]``),
# never consumed as an argument, so the type variable is covariant. This lets
# a ``RecordCodec[NoteRecord]`` be stored where a ``RecordCodec[BaseModel]`` is
# expected without any cast.
PayloadT = TypeVar("PayloadT", bound=BaseModel, covariant=True)

UpgradeFn: TypeAlias = Callable[[Mapping[str, JsonValue]], "dict[str, JsonValue]"]
"""Transforms one schema version's payload dict into the next version's."""


def canonical_content_hash(payload: Mapping[str, JsonValue]) -> str:
    """Return the SHA-256 of ``payload`` serialised as canonical JSON.

    Keys are sorted at every level and separators are compact, so the digest
    depends only on the payload's content, never on dict ordering.
    """
    serialised = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class RecordCodec(Generic[PayloadT]):
    """Binds a versioned envelope kind to a Pydantic payload model."""

    namespace: str
    kind: str
    schema_version: int
    payload_type: type[PayloadT]
    upgrade_from_previous: UpgradeFn | None = None

    @property
    def key(self) -> tuple[str, str]:
        """Return the ``(namespace, kind)`` chain key for this codec."""
        return (self.namespace, self.kind)


class RecordCodecRegistry:
    """Resolves versioned codecs and (de)serialises envelope payloads."""

    def __init__(self) -> None:
        self._chains: dict[tuple[str, str], dict[int, RecordCodec[BaseModel]]] = {}
        self._by_payload_type: dict[type[BaseModel], RecordCodec[BaseModel]] = {}

    def register(self, codec: RecordCodec[BaseModel]) -> None:
        """Register ``codec``, rejecting duplicates and broken version chains."""
        chain = self._chains.setdefault(codec.key, {})
        version = codec.schema_version

        if version in chain:
            raise CodecRegistrationError(
                f"codec for {codec.key!r} version {version} is already registered"
            )

        expected = max(chain) + 1 if chain else 1
        if version != expected:
            raise CodecRegistrationError(
                f"codec for {codec.key!r} version {version} breaks the chain; "
                f"expected version {expected}"
            )

        if version == 1 and codec.upgrade_from_previous is not None:
            raise CodecRegistrationError(
                f"codec for {codec.key!r} version 1 must not define an upgrade function"
            )
        if version > 1 and codec.upgrade_from_previous is None:
            raise CodecRegistrationError(
                f"codec for {codec.key!r} version {version} requires an upgrade function"
            )

        if codec.payload_type in self._by_payload_type:
            raise CodecRegistrationError(
                f"payload type {codec.payload_type.__name__!r} is already registered"
            )

        chain[version] = codec
        self._by_payload_type[codec.payload_type] = codec

    def codec_ids(self) -> frozenset[str]:
        """Return the ``namespace/kind`` ids this registry can resolve."""
        return frozenset(f"{namespace}/{kind}" for namespace, kind in self._chains)

    def encode(
        self,
        payload: BaseModel,
        *,
        scope_id: str,
        source: str,
        revision: int = 1,
        metadata: dict[str, JsonValue] | None = None,
    ) -> MemoryEnvelope:
        """Wrap a registered payload model in a content-addressed envelope."""
        codec = self._by_payload_type.get(type(payload))
        if codec is None:
            raise CodecRegistrationError(
                f"no codec registered for payload type {type(payload).__name__!r}"
            )

        payload_json: dict[str, JsonValue] = payload.model_dump(mode="json")
        return MemoryEnvelope(
            scope_id=scope_id,
            namespace=codec.namespace,
            kind=codec.kind,
            schema_version=codec.schema_version,
            revision=revision,
            source=source,
            payload=payload_json,
            metadata=metadata if metadata is not None else {},
            content_hash=canonical_content_hash(payload_json),
        )

    def decode(self, envelope: MemoryEnvelope) -> BaseModel | MemoryEnvelope:
        """Decode ``envelope`` into its current payload model, or pass it through.

        The envelope is returned unchanged when its ``(namespace, kind)`` has
        no registered chain, or when its ``schema_version`` is newer than the
        current registered version (there is no model to validate it against).
        """
        chain = self._chains.get((envelope.namespace, envelope.kind))
        if chain is None:
            return envelope

        current_version = max(chain)
        if envelope.schema_version > current_version:
            return envelope

        payload: dict[str, JsonValue] = dict(envelope.payload)
        version = envelope.schema_version
        while version < current_version:
            version += 1
            upgrade = chain[version].upgrade_from_previous
            if upgrade is None:  # pragma: no cover - guaranteed by register()
                raise CodecRegistrationError(
                    f"codec for {(envelope.namespace, envelope.kind)!r} version "
                    f"{version} is missing its upgrade function"
                )
            payload = upgrade(payload)

        return chain[current_version].payload_type.model_validate(payload)
