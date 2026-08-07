"""Hash-reputation enrichment: what the outside world already knows about a sample.

Every other evidence surface in this domain derives its findings from the bytes
of the artifact. This package does not: it asks third parties what they have
already recorded about a SHA-256, which is the only way to reach facts static
analysis cannot produce on its own -- that a hash is a known distribution file,
or that it already has a malware family name.

Two properties hold throughout, and both are load-bearing:

**Only the digest leaves the host.** No filename, no path, no bytes. A hash
lookup asks whether a fingerprint has been seen; an upload publishes the sample
permanently to the receiving service's partners and cannot be undone. Nothing
here uploads, not behind a flag.

**No credential means no request.** :meth:`IntelSettings.active_sources` returns
an empty tuple when nothing is configured, so an unconfigured checkout performs
no network I/O at all -- including to the keyless source.
"""

from __future__ import annotations

from reverse_engineering.intel.config import (
    IntelSettings,
    clear_intel_settings_cache,
    get_intel_settings,
)
from reverse_engineering.intel.models import (
    MAX_SUMMARY_CHARS,
    IntelResult,
    IntelStatus,
    sanitize_summary,
)

__all__ = [
    "MAX_SUMMARY_CHARS",
    "IntelResult",
    "IntelSettings",
    "IntelStatus",
    "clear_intel_settings_cache",
    "get_intel_settings",
    "sanitize_summary",
]
