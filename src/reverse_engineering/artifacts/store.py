"""A content-addressed directory store for immutable sample bytes."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

_CHUNK_SIZE = 64 * 1024


def default_artifacts_root() -> Path:
    """Resolve the default artifact store root under the AREMA home directory.

    ``get_settings`` is imported lazily so importing this module never triggers
    ``Settings`` construction (which reads environment variables / ``.env``).
    The store is colocated with memory and sandbox under ``~/.arema/artifacts``.
    """
    from arema.core.config import get_settings

    return get_settings().memory_path.parent / "artifacts"


class ArtifactStore:
    """Store artifact bytes keyed by their SHA-256 digest.

    Each artifact is written to ``<root>/<sha256>`` where ``sha256`` is the hex
    SHA-256 of its bytes. Acquiring identical content is idempotent: the bytes
    are hashed, and if the destination already exists it is left untouched.
    """

    def __init__(self, root: Path) -> None:
        self.root = root

    def acquire(self, src_path: str | Path) -> str:
        """Hash ``src_path`` into the store and return its hex SHA-256 id.

        The file is streamed through a fixed-size hashing buffer so large
        binaries are never fully resident in memory. Identical content is
        idempotent: when ``<root>/<sha256>`` already exists the copy is skipped
        and the existing artifact is left untouched.
        """
        resolved = Path(src_path)
        digest = hashlib.sha256()
        with resolved.open("rb") as source:
            while True:
                chunk = source.read(_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
        sha256 = digest.hexdigest()

        self.root.mkdir(parents=True, exist_ok=True)
        dest = self.root / sha256
        if not dest.exists():
            shutil.copyfile(resolved, dest)
        return sha256

    def acquire_bytes(self, data: bytes) -> str:
        """Store immutable bytes under their SHA-256 digest and return the digest."""
        sha256 = hashlib.sha256(data).hexdigest()
        self.root.mkdir(parents=True, exist_ok=True)
        dest = self.root / sha256
        if not dest.exists():
            dest.write_bytes(data)
        return sha256

    def path_for(self, artifact_id: str) -> Path:
        """Return the resolved path of an artifact by its id."""
        return self.root / artifact_id
