"""Session-wide fixtures for the AREMA test suite.

A session-scoped, autouse fixture redirects ``HOME`` (and ``USERPROFILE``,
for parity on Windows) to a throwaway temporary directory for the entire test
session. ``Settings.memory_path`` defaults to
``Path.home() / ".arema" / "memory" / "arema.db"``, and the default
composition builds a real SQLite store at that path on first use -- without
this redirect, any test that triggers the default composition (for example,
calling ``get_default_composition()`` without an override) would create that
database under the developer's real home
directory instead of a disposable one.

Because both the production code and the Task 2 default-value assertions in
``tests/unit/core/test_config.py`` call ``Path.home()`` only *after*
this redirect is already active (fixtures run before any test body, and the
whole suite shares this one session-scoped fixture), both sides observe the
same temporary home and stay consistent -- the assertions never drift from
what the code actually resolves.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "k8s: requires a live Kind cluster (opt-in)")


@pytest.fixture(autouse=True)
def _default_local_sandbox_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit tests run with the local sandbox backend; no cluster needed."""
    monkeypatch.setenv("AREMA_SANDBOX_BACKEND", "local")


@pytest.fixture(autouse=True)
def _no_reputation_lookups(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the suite offline whatever the developer's ``.env`` holds.

    ``IntelSettings.active_sources`` already returns nothing without a key, so a
    fresh checkout never reaches the network. A developer who has configured a
    real key is a different matter: pydantic-settings reads the project ``.env``,
    so without this pin their keys would switch enrichment on inside the test
    run. An environment variable outranks the file, and an empty value reads as
    unset. A test that wants a source on sets it explicitly.
    """
    monkeypatch.setenv("AREMA_VIRUSTOTAL_API_KEY", "")
    monkeypatch.setenv("AREMA_MALWAREBAZAAR_API_KEY", "")


@pytest.fixture(scope="session", autouse=True)
def _redirect_home(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Point ``HOME``/``USERPROFILE`` at a session-scoped temporary directory."""
    home = tmp_path_factory.mktemp("arema-home")
    previous_home = os.environ.get("HOME")
    previous_userprofile = os.environ.get("USERPROFILE")
    os.environ["HOME"] = str(home)
    os.environ["USERPROFILE"] = str(home)
    try:
        yield home
    finally:
        if previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = previous_home
        if previous_userprofile is None:
            os.environ.pop("USERPROFILE", None)
        else:
            os.environ["USERPROFILE"] = previous_userprofile
