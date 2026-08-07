"""VirusTotal: how many engines have an opinion about this digest, and what is it?

The broadest of the three sources, and the only one where presence and detection
are separate questions. hashlookup answers "is this a catalogued file" and
MalwareBazaar holds malware exclusively, so for both, presence settles
disposition. VirusTotal holds everything anyone ever submitted, so a record with
zero detections is a real and useful answer that is not the same as absence and
is also not a clean bill of health.

A 404 means the digest is not in the dataset. That is the expected answer for
anything freshly built, freshly packed, or targeted at one victim, and it is
never evidence of anything.

Two operational constraints belong with the code that depends on them. The free
public tier allows 4 requests per minute and 500 per day, which this stays well
inside at one request per run. And its terms state the public API "must not be
used in commercial products or services" and "must not be used in business
workflows that do not contribute new files" -- a hash-only workflow is precisely
that second case, so a free key makes this a personal-research posture. A
premium key removes both constraints.

Nothing here uploads. ``GET /files/{id}`` asks whether a fingerprint has been
seen; submitting the file would store it permanently, distribute it to VT's
antivirus partners, and make it downloadable by premium customers, and it cannot
be undone.

``meaningful_name`` is deliberately never carried: it is the filename whoever
submitted the sample chose, which makes it attacker-controlled text arriving
through a trusted-looking API, and it identifies nothing the analysis needs.
"""

from __future__ import annotations

import httpx

from arema.core.logging import get_logger
from reverse_engineering.intel.models import (
    VIRUSTOTAL_SOURCE,
    IntelResult,
    IntelStatus,
    sanitize_summary,
)

logger = get_logger(__name__)

_FILE_URL = "https://www.virustotal.com/api/v3/files/{sha256}"

__all__ = ["VIRUSTOTAL_SOURCE", "lookup_virustotal", "parse_virustotal"]


def _attributes(payload: object) -> dict[str, object] | None:
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    attributes = data.get("attributes")
    return attributes if isinstance(attributes, dict) else None


def _counts(raw: object) -> tuple[int, int]:
    """Return ``(malicious, total)`` from ``last_analysis_stats``.

    The denominator is the sum of every bucket the API returned rather than a
    hand-picked subset. VT's own interface shows a ratio whose denominator
    convention is not documented, and guessing at it would put an invented
    number in a report; summing what was actually sent is reproducible from the
    response alone.
    """
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


def _label(raw: object) -> str:
    """The suggested threat label, when VT assigned one."""
    if not isinstance(raw, dict):
        return ""
    return sanitize_summary(raw.get("suggested_threat_label"), limit=48)


def parse_virustotal(payload: object) -> IntelResult:
    """Turn one VirusTotal file report into a result. Never raises.

    A record with no detections is reported as a known file with its count, not
    as clean: the number is the fact, and how to read it is the analyst's call.
    """
    attributes = _attributes(payload)
    if attributes is None:
        return IntelResult(source=VIRUSTOTAL_SOURCE, status=IntelStatus.UNAVAILABLE)

    malicious, total = _counts(attributes.get("last_analysis_stats"))
    parts = [f"{malicious} of {total} engines flagged it" if total else "no engine results"]

    label = _label(attributes.get("popular_threat_classification"))
    if label:
        parts.append(f"suggested label {label}")
    file_type = sanitize_summary(attributes.get("type_description"), limit=32)
    if file_type:
        parts.append(f"type {file_type}")

    return IntelResult(
        source=VIRUSTOTAL_SOURCE,
        status=IntelStatus.KNOWN_BAD if malicious else IntelStatus.KNOWN_GOOD,
        summary=sanitize_summary("; ".join(parts)),
    )


def lookup_virustotal(sha256: str, *, timeout: float, api_key: str) -> IntelResult:
    """Query VirusTotal for one digest, degrading to a result on any failure.

    The digest is the only thing sent, and it is sent by lookup, never upload.
    """
    try:
        response = httpx.get(
            _FILE_URL.format(sha256=sha256),
            headers={"x-apikey": api_key},
            timeout=timeout,
        )
    except Exception as error:  # fail open: a lookup must never stall intake
        logger.warning(
            "reputation lookup failed", source=VIRUSTOTAL_SOURCE, error_type=type(error).__name__
        )
        return IntelResult(source=VIRUSTOTAL_SOURCE, status=IntelStatus.UNAVAILABLE)

    if response.status_code == httpx.codes.NOT_FOUND:
        return IntelResult(source=VIRUSTOTAL_SOURCE, status=IntelStatus.NOT_PRESENT)
    if response.status_code != httpx.codes.OK:
        # 401 is a bad key and 429 is the quota; both mean VT was never
        # consulted, which is an outage from the report's point of view and
        # never an absence.
        logger.warning(
            "reputation lookup returned an error status",
            source=VIRUSTOTAL_SOURCE,
            status_code=response.status_code,
        )
        return IntelResult(source=VIRUSTOTAL_SOURCE, status=IntelStatus.UNAVAILABLE)

    try:
        payload = response.json()
    except ValueError:
        logger.warning("reputation response was not JSON", source=VIRUSTOTAL_SOURCE)
        return IntelResult(source=VIRUSTOTAL_SOURCE, status=IntelStatus.UNAVAILABLE)

    return parse_virustotal(payload)
