"""Shared fixtures for arema component tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from arema.core.config import clear_settings_cache

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _credential_free_provider(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Force a provider that never requires API keys so ``get_settings()`` works.

    Several component tests exercise the real composition path
    (``get_default_composition()`` / ``get_settings()``), whose ``Settings()``
    validates provider credentials at construction time. Left unpinned, that
    path reads the ambient (untracked) ``.env``. Pinning the provider to
    ``ollama`` keeps these tests self-contained and decoupled from ``.env``.
    """
    monkeypatch.setenv("AREMA_LLM_PROVIDER", "ollama")
    clear_settings_cache()
    yield
    clear_settings_cache()
