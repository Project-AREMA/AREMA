"""Typed errors raised by the AREMA memory subsystem.

The base class is deliberately named :class:`MemoryStoreError` rather than
``MemoryError`` -- the latter is a Python built-in that signals an allocation
failure, and shadowing it would silently swallow real out-of-memory
conditions. Every memory-store failure derives from this single base so
callers can catch the whole family with one ``except`` clause.
"""


class MemoryStoreError(Exception):
    """Base class for every memory-store failure."""


class BackendInitError(MemoryStoreError):
    """Raised when a memory backend cannot complete initialisation."""


class BackendUnavailableError(MemoryStoreError):
    """Raised when a previously initialised backend becomes unreachable."""


class RecordNotFoundError(MemoryStoreError):
    """Raised when a requested record does not exist."""


class RevisionConflictError(MemoryStoreError):
    """Raised when an optimistic-concurrency revision check fails."""


class InvalidCursorError(MemoryStoreError):
    """Raised when a pagination cursor is malformed or expired."""


class CodecRegistrationError(MemoryStoreError):
    """Raised when a codec registration is a duplicate or breaks a chain."""


class RelationIntegrityError(MemoryStoreError):
    """Raised when a relation references a record that does not exist."""
