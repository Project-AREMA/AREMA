"""The in-memory backend, verified against the shared store contract.

``TestInMemoryStore`` inherits every behavioural case from
:class:`BackendContract`; the ``store`` fixture is the only backend-specific
wiring. The extra tests below cover behaviour unique to the in-memory backend
(initialisation lifecycle and health signalling) that the neutral contract does
not prescribe.
"""

from __future__ import annotations

import pytest
from store_contract import BackendContract

from arema.memory.backends import InMemoryStore


@pytest.fixture
def store() -> InMemoryStore:
    backend = InMemoryStore()
    backend.initialize()
    return backend


class TestInMemoryStore(BackendContract):
    """Runs the full neutral contract against :class:`InMemoryStore`."""


def test_health_is_unready_before_initialize() -> None:
    backend = InMemoryStore()
    assert backend.health().healthy is False


def test_health_becomes_ready_after_initialize() -> None:
    backend = InMemoryStore()
    backend.initialize()
    assert backend.health().healthy is True


def test_initialize_is_idempotent() -> None:
    backend = InMemoryStore()
    backend.initialize()
    backend.initialize()
    assert backend.health().healthy is True
