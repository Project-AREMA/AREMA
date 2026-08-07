"""Shared fixtures for arema.memory tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from arema.core.config import clear_settings_cache

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _credential_free_provider(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Force a provider that never requires API keys so ``get_settings()`` works.

    ``MemoryService`` falls back to the process-wide cached ``get_settings()``
    when no ``settings`` are passed, and ``Settings()`` validates provider
    credentials at construction time. Several tests here build a service without
    injecting settings, so pinning the provider to ``ollama`` keeps that fallback
    path deterministic and decoupled from the ambient ``.env``.
    """
    monkeypatch.setenv("AREMA_LLM_PROVIDER", "ollama")
    clear_settings_cache()
    yield
    clear_settings_cache()
