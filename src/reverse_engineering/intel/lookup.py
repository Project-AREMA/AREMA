"""Query the configured sources and render one line a prompt can read.

The whole subsystem's entry point. :func:`gather` returns an empty tuple when
nothing is configured, and that is the common case: no key, no request, no line.

Every source is queried independently and a failing one is recorded rather than
raising, so a dead endpoint costs its own timeout and nothing else. The caller
sits on the intake critical path, so :data:`_TOTAL_BUDGET_SECONDS` bounds the
whole sweep as well: once it is spent, remaining sources are marked unavailable
without being tried.

:func:`render_intel_line` produces the single string the prompts consume. Its
one job beyond formatting is to keep ``not present`` legible as absence. A
digest missing from every corpus is a common, uninteresting result that must
never read as a clean bill of health, so misses are printed rather than dropped
and the word "clean" appears nowhere in this module.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from arema.core.logging import get_logger
from reverse_engineering.intel.config import get_intel_settings
from reverse_engineering.intel.hashlookup import lookup_hashlookup
from reverse_engineering.intel.malwarebazaar import lookup_malwarebazaar
from reverse_engineering.intel.models import (
    HASHLOOKUP_SOURCE,
    MALWAREBAZAAR_SOURCE,
    VIRUSTOTAL_SOURCE,
    IntelRelation,
    IntelResult,
    IntelStatus,
    sanitize_summary,
)
from reverse_engineering.intel.relations import fetch_relations
from reverse_engineering.intel.virustotal import lookup_virustotal

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pydantic import SecretStr

    from reverse_engineering.intel.config import IntelSettings

logger = get_logger(__name__)

# The sweep sits between "the file was hashed" and "the pipeline starts", so its
# worst case is a user-visible pause. Per-source timeouts already bound each
# call; this bounds their sum when several endpoints are simultaneously sick.
_TOTAL_BUDGET_SECONDS = 15.0

MAX_INTEL_LINE_CHARS = 700

# Relations are a list rather than a verdict, so they need more room -- but a
# report is not a threat feed, and an unbounded block would crowd out the
# analysis it is meant to support.
MAX_RELATIONS_LINE_CHARS = 2_000

# How each disposition reads in the injected line. KNOWN_BAD is shouted because
# it is the one result that should change what an analyst does next.
_STATUS_WORDS = {
    IntelStatus.KNOWN_GOOD: "known file",
    IntelStatus.KNOWN_BAD: "FLAGGED MALICIOUS",
    IntelStatus.NOT_PRESENT: "not present",
    IntelStatus.UNAVAILABLE: "unavailable",
}

__all__ = [
    "MAX_INTEL_LINE_CHARS",
    "MAX_RELATIONS_LINE_CHARS",
    "gather",
    "gather_relations",
    "render_intel_line",
    "render_relations_block",
]


def _secret(key: SecretStr | None) -> str:
    """Unwrap a credential at the moment of use, never before."""
    return key.get_secret_value() if key is not None else ""


def _lookup_one(
    source: str, sha256: str, *, timeout: float, settings: IntelSettings
) -> IntelResult:
    """Dispatch to one source. An unknown name degrades rather than raising.

    A keyed source is only reachable here because ``active_sources`` found its
    key, so the unwrapping below cannot yield an empty string in practice; the
    fallback exists so a future change to the gate degrades rather than sending
    an unauthenticated request.
    """
    if source == HASHLOOKUP_SOURCE:
        return lookup_hashlookup(sha256, timeout=timeout)
    if source == VIRUSTOTAL_SOURCE:
        return lookup_virustotal(
            sha256, timeout=timeout, api_key=_secret(settings.virustotal_api_key)
        )
    if source == MALWAREBAZAAR_SOURCE:
        return lookup_malwarebazaar(
            sha256, timeout=timeout, api_key=_secret(settings.malwarebazaar_api_key)
        )
    logger.warning("no lookup is wired for this reputation source", source=source)
    return IntelResult(source=source, status=IntelStatus.UNAVAILABLE)


def gather(sha256: str, *, settings: IntelSettings | None = None) -> tuple[IntelResult, ...]:
    """Query every configured source for one digest. Never raises.

    Returns an empty tuple when no credential is configured, which is the
    property that keeps an unconfigured checkout off the network entirely.
    """
    resolved = settings if settings is not None else get_intel_settings()
    sources = resolved.active_sources
    if not sources:
        return ()

    per_source = resolved.intel_timeout_seconds
    remaining = _TOTAL_BUDGET_SECONDS
    results: list[IntelResult] = []
    for source in sources:
        if remaining <= 0:
            logger.warning("reputation budget exhausted before this source", source=source)
            results.append(IntelResult(source=source, status=IntelStatus.UNAVAILABLE))
            continue
        timeout = min(per_source, remaining)
        result = _lookup_one(source, sha256, timeout=timeout, settings=resolved)
        if result.status is IntelStatus.UNAVAILABLE:
            # Only a failure can have consumed the timeout; a hit or a miss
            # answered fast enough that charging the budget would be wrong.
            remaining -= timeout
        results.append(result)
    return tuple(results)


def render_intel_line(results: Iterable[IntelResult]) -> str:
    """Render the sources' answers as one bounded, template-safe line.

    Misses are printed, never dropped. "not present in every corpus" is a real
    and common answer, and an analyst who sees the sources listed knows they
    were asked; an analyst who sees nothing cannot tell absence from an outage.
    """
    parts = [
        f"{result.source}: {_STATUS_WORDS[result.status]}"
        + (f" ({result.summary})" if result.summary else "")
        for result in results
    ]
    if not parts:
        return ""
    return sanitize_summary("; ".join(parts), limit=MAX_INTEL_LINE_CHARS)


def gather_relations(
    sha256: str, *, settings: IntelSettings | None = None
) -> tuple[IntelRelation, ...]:
    """Indicators a third party associates with the digest. Never raises.

    Same gate as the reputation sweep: with no credential configured, nothing is
    queried. Relationships are a VirusTotal capability, so a run without a
    VirusTotal key returns nothing here and loses none of the sweep.
    """
    resolved = settings if settings is not None else get_intel_settings()
    if VIRUSTOTAL_SOURCE not in resolved.active_sources:
        return ()
    return fetch_relations(sha256, settings=resolved, timeout=resolved.intel_timeout_seconds)


def render_relations_block(relations: Iterable[IntelRelation]) -> str:
    """Render associated indicators as one bounded, template-safe line.

    Every entry carries its detection ratio, because the alternative presents a
    live C2 and an analysis VM's Office traffic as the same kind of fact.
    """
    parts: list[str] = []
    for relation in relations:
        ratio = f" [{relation.ratio}]" if relation.ratio else ""
        name = f" ({relation.name})" if relation.name else ""
        parts.append(f"{relation.kind}: {relation.value}{name}{ratio}")
    if not parts:
        return ""
    return sanitize_summary("; ".join(parts), limit=MAX_RELATIONS_LINE_CHARS)
