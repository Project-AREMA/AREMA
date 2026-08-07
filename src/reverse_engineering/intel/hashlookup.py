"""CIRCL hashlookup: is this digest a file somebody has already catalogued?

A free, keyless, documented REST API over ~6.4 billion hashes (``/info`` reports
``stat:hashlookup_total_keys`` 6_413_766_630 against NSRL RDS 2023.09.2). It
aggregates the NIST NSRL, Windows distributions, Linux distribution packages,
CDNJS and the Snap store, and carries a ``KnownMalicious`` marker sourced from
third-party corpora. Its answer is the cheapest one available: a single GET that
can establish in milliseconds what static analysis of a stock system binary
otherwise reconstructs over hundreds of thousands of tokens.

Two things measured against the live service shape this parser, and neither is
obvious from the documentation:

**``hashlookup:trust`` is not a safety score.** A digest flagged
``"KnownMalicious": "malshare.com"`` came back with ``hashlookup:trust`` 100,
identical to a clean NSRL entry. The field reflects corroboration across source
databases, not disposition. It is deliberately not carried into the summary,
because a reader who sees "trust 100" next to a malicious file has been actively
misled. ``KnownMalicious`` is the disposition signal.

**``FileName`` is an example, never an identity.** Hashes collide on content, so
the empty file resolves to a random ``requires.txt`` from a Python package and
the four bytes ``test`` resolve to a cargo test fixture. The name is one arbitrary
member of the set of files with those bytes, and the summary says so.
"""

from __future__ import annotations

import httpx

from arema.core.logging import get_logger
from reverse_engineering.intel.models import (
    HASHLOOKUP_SOURCE,
    IntelResult,
    IntelStatus,
    sanitize_summary,
)

logger = get_logger(__name__)

_LOOKUP_URL = "https://hashlookup.circl.lu/lookup/sha256/{sha256}"

# One example filename is useful context and a long one is noise; NSRL carries
# 100+ character Windows component manifest names.
_MAX_NAME_CHARS = 72

__all__ = ["HASHLOOKUP_SOURCE", "lookup_hashlookup", "parse_hashlookup"]


def _corpus(payload: dict[str, object]) -> str:
    """Name the database the entry came from, preferring the specific one."""
    for key in ("source", "db"):
        label = sanitize_summary(payload.get(key), limit=48)
        if label:
            return label
    return ""


def _example_name(payload: dict[str, object]) -> str:
    """One example filename, marked when it had to be cut.

    Measured live: NSRL paths routinely exceed the cap, and a silent trim turns
    ``requires.txt`` into ``requires.tx``, which reads as a real filename rather
    than a truncated one. The whole point of this field is that it is an example,
    so a reader must be able to tell an abbreviated example from an exact one.
    """
    name = sanitize_summary(payload.get("FileName"), limit=_MAX_NAME_CHARS + 1)
    if len(name) > _MAX_NAME_CHARS:
        return name[:_MAX_NAME_CHARS].rstrip() + "..."
    return name


def parse_hashlookup(payload: object) -> IntelResult:
    """Turn one hashlookup response body into a result. Never raises.

    A ``KnownMalicious`` marker outranks presence in a known-file corpus: being
    catalogued and being safe are different claims, and this API answers both.
    """
    if not isinstance(payload, dict):
        return IntelResult(source=HASHLOOKUP_SOURCE, status=IntelStatus.NOT_PRESENT)

    malicious = sanitize_summary(payload.get("KnownMalicious"), limit=48)
    corpus = _corpus(payload)
    name = _example_name(payload)

    parts: list[str] = []
    if malicious:
        parts.append(f"flagged malicious by {malicious}")
    if corpus:
        parts.append(f"catalogued in {corpus}")
    if name:
        parts.append(f"example name {name}")
    if not parts:
        # A 200 with nothing recognizable in it is still a hit: the digest is
        # present. Say only that.
        parts.append("present, no descriptive fields returned")

    return IntelResult(
        source=HASHLOOKUP_SOURCE,
        status=IntelStatus.KNOWN_BAD if malicious else IntelStatus.KNOWN_GOOD,
        summary=sanitize_summary("; ".join(parts)),
    )


def lookup_hashlookup(sha256: str, *, timeout: float) -> IntelResult:
    """Query hashlookup for one digest, degrading to a result on any failure.

    The digest is the only thing sent. A 404 means the hash is absent from every
    database hashlookup aggregates, which is not the same as clean, so it maps to
    ``NOT_PRESENT`` and never to a verdict.
    """
    try:
        response = httpx.get(_LOOKUP_URL.format(sha256=sha256), timeout=timeout)
    except Exception as error:  # fail open: a lookup must never stall intake
        logger.warning(
            "reputation lookup failed", source=HASHLOOKUP_SOURCE, error_type=type(error).__name__
        )
        return IntelResult(source=HASHLOOKUP_SOURCE, status=IntelStatus.UNAVAILABLE)

    if response.status_code == httpx.codes.NOT_FOUND:
        return IntelResult(source=HASHLOOKUP_SOURCE, status=IntelStatus.NOT_PRESENT)
    if response.status_code != httpx.codes.OK:
        logger.warning(
            "reputation lookup returned an error status",
            source=HASHLOOKUP_SOURCE,
            status_code=response.status_code,
        )
        return IntelResult(source=HASHLOOKUP_SOURCE, status=IntelStatus.UNAVAILABLE)

    try:
        payload = response.json()
    except ValueError:
        logger.warning("reputation response was not JSON", source=HASHLOOKUP_SOURCE)
        return IntelResult(source=HASHLOOKUP_SOURCE, status=IntelStatus.UNAVAILABLE)

    return parse_hashlookup(payload)
