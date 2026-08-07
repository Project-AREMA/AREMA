"""Content-addressed artifact custody for the reverse-engineer domain."""

from __future__ import annotations

from reverse_engineering.artifacts.store import ArtifactStore, default_artifacts_root

__all__ = ["ArtifactStore", "default_artifacts_root"]
