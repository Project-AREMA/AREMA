"""Where reports are written, and in what formats.

Domain-local rather than fields on :class:`arema.core.config.Settings`: the
neutral core must not know that this domain produces reports, and
``tests/unit/core/test_config.py`` asserts ``report_output_dir`` is absent from
``Settings`` by name.

``REPORT_OUTPUT_DIR`` and ``REPORT_FORMATS`` have sat in ``.env.example`` since
the legacy security domain was removed, read by nothing. These are those keys,
made real -- so an existing ``.env`` starts working rather than needing an edit.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from arema.core.config import Settings

# Formats this writer can actually produce. The legacy keys list docx and json
# too; naming one that is not implemented should not fail a run, so unknown
# entries are dropped rather than rejected.
SUPPORTED_FORMATS = ("md", "html")

__all__ = [
    "SUPPORTED_FORMATS",
    "ReportSettings",
    "clear_report_settings_cache",
    "get_report_settings",
]


class ReportSettings(BaseSettings):
    """Report persistence, off unless an output directory is configured."""

    model_config = SettingsConfigDict(
        env_file=Settings.model_config.get("env_file"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        populate_by_name=True,
        extra="ignore",
    )

    # Un-prefixed, matching the keys already present in .env.example.
    report_output_dir: str = ""
    report_formats: str = "md,html"

    @field_validator("report_output_dir")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()

    @property
    def enabled(self) -> bool:
        """Whether reports are written at all."""
        return bool(self.report_output_dir) and bool(self.formats)

    @property
    def directory(self) -> Path:
        """The configured output directory, with ``~`` expanded."""
        return Path(self.report_output_dir).expanduser()

    @property
    def formats(self) -> tuple[str, ...]:
        """The supported formats named in configuration, in a stable order.

        Unknown names are dropped: a legacy value of ``json,md,html,docx`` should
        write what it can rather than fail on the two this writer does not
        produce.
        """
        named = {part.strip().lower() for part in self.report_formats.split(",")}
        return tuple(fmt for fmt in SUPPORTED_FORMATS if fmt in named)


@lru_cache
def get_report_settings() -> ReportSettings:
    """Return the cached report settings instance."""
    return ReportSettings()


def clear_report_settings_cache() -> None:
    """Clear the cached report settings instance."""
    get_report_settings.cache_clear()
