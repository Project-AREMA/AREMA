"""Shared fixtures for the reverse_engineering capability test package.

The malware_analyst composition (which registers the shared RE infrastructure)
resolves settings via ``get_settings()``, which reads the ambient ``.env`` --
exactly like the neutral core's default composition. Pinning the provider to
``ollama`` (which never requires API keys) keeps these tests self-contained and
decoupled from ``.env``, mirroring ``tests/component/conftest.py``. Both the
settings cache and the ``@lru_cache``-backed composition getter are cleared
around each test so the pin takes effect.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from arema.core.config import clear_settings_cache

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _credential_free_provider(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    from malware_analyst.composition import get_malware_analyst_composition

    monkeypatch.setenv("AREMA_LLM_PROVIDER", "ollama")
    clear_settings_cache()
    get_malware_analyst_composition.cache_clear()
    try:
        yield
    finally:
        clear_settings_cache()
        get_malware_analyst_composition.cache_clear()
