"""Shared fixtures for arema.runtime tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from arema.core.config import clear_settings_cache

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _credential_free_provider(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Force a provider that never requires API keys so ``get_settings()`` works.

    ``Settings()`` validates provider credentials at construction time. Tests in
    this package call ``classify_pressure`` and other functions with the module
    default (``settings=None``), which falls back to the process-wide cached
    ``get_settings()``. Pinning the provider to ``ollama`` here keeps that
    fallback path deterministic regardless of the ambient shell environment.
    """
    monkeypatch.setenv("AREMA_LLM_PROVIDER", "ollama")
    clear_settings_cache()
    yield
    clear_settings_cache()
