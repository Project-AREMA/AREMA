"""Configuration for reputation lookups, and the switch that keeps them off.

Domain-local rather than a field on :class:`arema.core.config.Settings`: the
neutral core must not name a threat-intelligence vendor, and
``tests/unit/core/test_config.py`` asserts by name that it does not. ``Settings``
declares ``extra="ignore"``, so a second ``BaseSettings`` reading the same
``AREMA_`` prefix coexists with it cleanly, and reusing its resolved ``env_file``
keeps both reading the one ``.env`` the project already found.

:meth:`IntelSettings.active_sources` is the whole feature switch. With no
credential configured it returns an empty tuple and no source runs, including
the keyless one -- so a fresh checkout makes no outbound request, the test suite
is offline without a conftest pin, and enabling enrichment is a deliberate act
rather than a default someone inherits.
"""

from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from arema.core.config import Settings
from reverse_engineering.intel.models import (
    HASHLOOKUP_SOURCE,
    MALWAREBAZAAR_SOURCE,
    VIRUSTOTAL_SOURCE,
)

__all__ = [
    "IntelSettings",
    "clear_intel_settings_cache",
    "get_intel_settings",
]


class IntelSettings(BaseSettings):
    """Credentials and bounds for hash-reputation enrichment."""

    model_config = SettingsConfigDict(
        env_prefix="arema_",
        env_file=Settings.model_config.get("env_file"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        populate_by_name=True,
        extra="ignore",
    )

    virustotal_api_key: SecretStr | None = None
    malwarebazaar_api_key: SecretStr | None = None

    # Per-source ceiling. The lookups sit on the intake critical path, so a dead
    # endpoint must cost a few seconds, never a stalled run.
    intel_timeout_seconds: float = 5.0

    # Downloading a sample is a transfer rather than a question, so it gets its
    # own, larger budget. The reputation timeout would abort most real samples.
    fetch_timeout_seconds: float = 60.0

    @property
    def active_sources(self) -> tuple[str, ...]:
        """Sources to query, empty when nothing is configured.

        A source needing a key is skipped without it. The keyless source rides
        along once any key has switched enrichment on, so "no keys set" means no
        outbound request at all.
        """
        keyed = tuple(
            source
            for source, key in (
                (VIRUSTOTAL_SOURCE, self.virustotal_api_key),
                (MALWAREBAZAAR_SOURCE, self.malwarebazaar_api_key),
            )
            if key is not None and key.get_secret_value().strip()
        )
        if not keyed:
            return ()
        return (HASHLOOKUP_SOURCE, *keyed)


@lru_cache
def get_intel_settings() -> IntelSettings:
    """Return the cached enrichment settings instance."""
    return IntelSettings()


def clear_intel_settings_cache() -> None:
    """Clear the cached enrichment settings instance."""
    get_intel_settings.cache_clear()
