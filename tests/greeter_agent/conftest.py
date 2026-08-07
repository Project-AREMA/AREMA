"""Shared fixtures for the greeter_agent test package.

The greeter resolves settings via ``get_settings()`` (and builds each registered
domain -- malware_analyst -- which does too), so pin a credential-free provider
to keep these tests hermetic, mirroring ``tests/malware_analyst/conftest.py``.
Each domain's lru-cached composition is also cleared around every test so a
rebuilt greeter never re-attaches an already-parented domain root.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from arema.core.config import clear_settings_cache

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _credential_free_provider(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    from greeter_agent.composition import get_greeter_agent
    from malware_analyst.composition import get_malware_analyst_composition

    monkeypatch.setenv("AREMA_LLM_PROVIDER", "ollama")
    clear_settings_cache()
    get_greeter_agent.cache_clear()
    get_malware_analyst_composition.cache_clear()
    try:
        yield
    finally:
        clear_settings_cache()
        get_greeter_agent.cache_clear()
        get_malware_analyst_composition.cache_clear()
