"""Indicators VirusTotal already associates with a digest.

The reputation sweep answers *is this known and what is it called*. This answers
*what else is it connected to*, and that turns out to be the part static analysis
structurally cannot reach.

Measured on a QuasarRAT sample: ``itw_urls`` returned
``http://floneimf.ydns.eu/webcontents/…/contents.exe`` at 16/49 malicious. That
URL is nowhere in the sample's bytes. It is where the sample came *from*, a fact
about the world rather than about the file, and no amount of decompilation would
have produced it.

Two design constraints, both learned from the same measurement:

**Detection counts travel with every indicator.** The same sample's
``contacted_ips`` were all Microsoft Teams endpoints at 0/91 — sandbox background
traffic, not command and control. A bare list of addresses would present those
identically to the C2. Carrying the ratio lets the report show ``16/49`` beside
one and ``0/91`` beside the other.

**``contacted_*`` is excluded by default.** Those are dynamic sandbox
observations of a whole detonation, and on this sample every one of them was
Office traffic. The relationships kept here describe the sample itself or its
distribution: what it embeds, what it drops, what carried it, and where it was
served from.

Everything here is *reported*, never *asserted*. The report must say VirusTotal
associates this URL with the digest, not that the sample contacts it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

from arema.core.logging import get_logger
from reverse_engineering.intel.models import (
    VIRUSTOTAL_SOURCE,
    IntelRelation,
    sanitize_summary,
)

if TYPE_CHECKING:
    from reverse_engineering.intel.config import IntelSettings

logger = get_logger(__name__)

_RELATION_URL = "https://www.virustotal.com/api/v3/files/{sha256}/{relation}"

# The relationships that describe the sample or its distribution. Each maps to
# the short label the report prints.
#
# contacted_domains / contacted_ips / contacted_urls are deliberately absent:
# they are observations of a whole sandbox detonation, and measured on a real
# sample every one was the analysis VM's own Office background traffic.
RELATIONS: tuple[tuple[str, str], ...] = (
    ("itw_urls", "in-the-wild URL"),
    ("embedded_urls", "embedded URL"),
    ("embedded_domains", "embedded domain"),
    ("embedded_ips", "embedded IP"),
    ("dropped_files", "dropped file"),
    ("bundled_files", "bundled file"),
    ("execution_parents", "execution parent"),
)

# Per relationship. A sample with hundreds of bundled files is a container, and
# listing all of them tells an analyst nothing the count does not.
MAX_ITEMS_PER_RELATION = 10
MAX_VALUE_CHARS = 180
MAX_NAME_CHARS = 60

__all__ = [
    "MAX_ITEMS_PER_RELATION",
    "RELATIONS",
    "fetch_relations",
    "parse_relation",
]


def _value_of(item: dict[str, object]) -> str:
    """The indicator itself, which lives in a different place per object type.

    Measured: a URL object's ``id`` is a hash and the URL is in
    ``attributes.url``; a file object's ``id`` *is* its SHA-256; a domain or IP
    object's ``id`` is the name or address. Reading ``id`` uniformly would put
    opaque hashes in the report where URLs belong.
    """
    attributes = item.get("attributes")
    attributes = attributes if isinstance(attributes, dict) else {}
    if item.get("type") == "url":
        return sanitize_summary(attributes.get("url"), limit=MAX_VALUE_CHARS)
    return sanitize_summary(item.get("id"), limit=MAX_VALUE_CHARS)


def _detections(item: dict[str, object]) -> tuple[int, int]:
    """``(malicious, total)`` from ``last_analysis_stats``, summing every bucket.

    Same convention as the file report: the denominator is what the API actually
    returned rather than a guessed subset, so the ratio is reproducible from the
    response alone.
    """
    attributes = item.get("attributes")
    raw = attributes.get("last_analysis_stats") if isinstance(attributes, dict) else None
    if not isinstance(raw, dict):
        return (0, 0)
    total = 0
    malicious = 0
    for bucket, count in raw.items():
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            continue
        total += count
        if bucket == "malicious":
            malicious = count
    return (malicious, total)


def _name_of(item: dict[str, object]) -> str:
    """A dropped or bundled file's name, when it has one.

    Submitter-influenced text, so it is sanitized and short-capped -- but a
    dropped filename is a genuine host indicator and worth the handling.
    """
    attributes = item.get("attributes")
    if not isinstance(attributes, dict):
        return ""
    return sanitize_summary(attributes.get("meaningful_name"), limit=MAX_NAME_CHARS)


def parse_relation(payload: object, *, kind: str) -> tuple[IntelRelation, ...]:
    """Turn one relationship response into bounded records. Never raises."""
    if not isinstance(payload, dict):
        return ()
    data = payload.get("data")
    if not isinstance(data, list):
        return ()
    out: list[IntelRelation] = []
    for item in data[:MAX_ITEMS_PER_RELATION]:
        if not isinstance(item, dict):
            continue
        value = _value_of(item)
        if not value:
            continue
        malicious, total = _detections(item)
        try:
            out.append(
                IntelRelation(
                    source=VIRUSTOTAL_SOURCE,
                    kind=kind,
                    value=value,
                    name=_name_of(item),
                    malicious=malicious,
                    total=total,
                )
            )
        except ValueError:  # a bound this module did not anticipate
            continue
    return tuple(out)


def fetch_relations(
    sha256: str, *, settings: IntelSettings, timeout: float
) -> tuple[IntelRelation, ...]:
    """Fetch every configured relationship for one digest. Never raises.

    Only the digest is sent. A relationship that fails is skipped rather than
    escalated: this is enrichment on top of an analysis that already stands on
    its own.
    """
    key = settings.virustotal_api_key
    api_key = key.get_secret_value() if key is not None else ""
    if not api_key.strip():
        return ()

    out: list[IntelRelation] = []
    for relation, kind in RELATIONS:
        try:
            response = httpx.get(
                _RELATION_URL.format(sha256=sha256, relation=relation),
                headers={"x-apikey": api_key},
                params={"limit": MAX_ITEMS_PER_RELATION},
                timeout=timeout,
            )
        except Exception as error:  # fail open: enrichment must never stall a run
            logger.warning(
                "relationship lookup failed",
                source=VIRUSTOTAL_SOURCE,
                relation=relation,
                error_type=type(error).__name__,
            )
            continue
        if response.status_code != httpx.codes.OK:
            logger.info(
                "relationship unavailable",
                source=VIRUSTOTAL_SOURCE,
                relation=relation,
                status_code=response.status_code,
            )
            continue
        try:
            payload = response.json()
        except ValueError:
            continue
        out.extend(parse_relation(payload, kind=kind))
    return tuple(out)
