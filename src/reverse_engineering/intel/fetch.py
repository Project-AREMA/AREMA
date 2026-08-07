"""Retrieve a sample's bytes by digest, one direction only.

This module can pull a sample down. It cannot push one up, and the constraint is
structural rather than a promise: nothing here opens a file, imports the artifact
store, or has any route to the bytes of a local sample. A function here takes a
64-character digest and returns bytes; there is no function that takes bytes and
makes a request. ``tests/architecture/test_no_sample_upload.py`` enforces that by
parsing this package rather than trusting the description.

The reason is the one an analyst cares about most. Submitting an unknown sample
to a public service publishes it: it is stored permanently, distributed to that
service's antivirus partners, and made downloadable by their paying customers,
and it cannot be withdrawn. For anyone holding a client's incident sample that is
a disclosure event, and "the tool did it automatically while looking for a
report" is not a defence. So the tool cannot do it at all.

What each source can actually give you differs sharply from what it can tell you:

- **MalwareBazaar** serves samples to any free Auth-Key. It is the workable
  download source. Samples arrive AES-128 zipped under the password ``infected``,
  which the standard library cannot open -- ``zipfile`` implements ZipCrypto only
  and raises ``NotImplementedError: compression type 99`` on these -- hence
  ``pyzipper``.
- **VirusTotal** requires a premium key for ``/files/{id}/download``. A free key
  gets HTTP 403, which is reported as "this key cannot download" rather than as
  the sample being absent.
- **hashlookup** holds no samples at all. It answers questions about digests and
  is not consulted here.
"""

from __future__ import annotations

import hashlib
import io
import zipfile
from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx
import pyzipper

from arema.core.logging import get_logger
from reverse_engineering.intel.config import get_intel_settings
from reverse_engineering.intel.malwarebazaar import MALWAREBAZAAR_SOURCE
from reverse_engineering.intel.models import VIRUSTOTAL_SOURCE

if TYPE_CHECKING:
    from pydantic import SecretStr

    from reverse_engineering.intel.config import IntelSettings

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class FetchOutcome:
    """Bytes and where they came from, or nothing and why not."""

    payload: bytes | None = None
    source: str = ""
    reason: str = ""


_BAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
_VT_DOWNLOAD_URL = "https://www.virustotal.com/api/v3/files/{sha256}/download"

# abuse.ch's fixed archive password, published in their API documentation.
_ARCHIVE_PASSWORD = b"infected"

# The local file header signature every ZIP starts with. Used to tell a served
# sample from a JSON "not held" answer, both of which arrive as HTTP 200.
_ZIP_MAGIC = b"PK\x03\x04"

# A sample large enough to exceed this is not something to pull onto a
# workstation unattended. Applied to the transfer and again to the expansion,
# so an archive that decompresses far beyond its download size is refused.
MAX_SAMPLE_BYTES = 128 * 1024 * 1024

# Sources that can serve bytes, in the order they are tried.
#
# VirusTotal first: it is the broadest repository of the three by a wide margin,
# holding everything ever submitted rather than a curated corpus, so with a key
# that can download it is the one most likely to have any given digest.
# MalwareBazaar is the fallback and is far from redundant -- it carries samples
# VirusTotal will not serve, and it serves them to a free key.
#
# hashlookup is absent from this list entirely: it answers questions about
# digests and holds no samples at all.
DOWNLOAD_SOURCES: tuple[str, ...] = (VIRUSTOTAL_SOURCE, MALWAREBAZAAR_SOURCE)

__all__ = [
    "DOWNLOAD_SOURCES",
    "MAX_SAMPLE_BYTES",
    "FetchOutcome",
    "download_malwarebazaar",
    "download_virustotal",
    "fetch_sample",
    "sha256_of",
    "unwrap_archive",
]


def unwrap_archive(payload: bytes) -> bytes | None:
    """Return the single member of an AES-encrypted archive, or ``None``.

    Bounded against an archive that expands far beyond its transfer size: the
    declared size is checked before extracting, and the extracted length after,
    since a declared size is a claim made by the file being opened.
    """
    try:
        with pyzipper.AESZipFile(io.BytesIO(payload)) as archive:
            archive.setpassword(_ARCHIVE_PASSWORD)
            members = archive.infolist()
            if len(members) != 1:
                logger.warning("sample archive did not hold exactly one file", members=len(members))
                return None
            if members[0].file_size > MAX_SAMPLE_BYTES:
                logger.warning("sample archive declares an oversized member")
                return None
            extracted = archive.read(members[0])
    except (RuntimeError, ValueError, zipfile.BadZipFile, pyzipper.BadZipFile) as error:
        logger.warning("sample archive could not be opened", error_type=type(error).__name__)
        return None

    if len(extracted) > MAX_SAMPLE_BYTES:
        logger.warning("sample archive expanded beyond the ceiling")
        return None
    return bytes(extracted)


def _oversized(response: httpx.Response, source: str) -> bool:
    if len(response.content) > MAX_SAMPLE_BYTES:
        logger.warning("sample download exceeded the size ceiling", source=source)
        return True
    return False


def download_malwarebazaar(sha256: str, *, timeout: float, api_key: str) -> bytes | None:
    """Fetch one sample from MalwareBazaar, or ``None``. Never raises.

    The digest and the key are the only things sent.

    Measured live: ``get_file`` answers 200 either way. A hit is a ZIP; a miss is
    a JSON body, ``{"query_status": "file_not_found"}``. Both are normal, so the
    body is checked for the archive signature before unwrapping. Feeding the JSON
    to the archive reader would log a ``BadZipFile`` warning about corruption on
    the entirely routine path of asking for a sample abuse.ch does not hold.
    """
    try:
        response = httpx.post(
            _BAZAAR_URL,
            data={"query": "get_file", "sha256_hash": sha256},
            headers={"Auth-Key": api_key},
            timeout=timeout,
        )
    except Exception as error:  # fail open: a fetch must never take down the run
        logger.warning(
            "sample download failed", source=MALWAREBAZAAR_SOURCE, error_type=type(error).__name__
        )
        return None

    if response.status_code != httpx.codes.OK or _oversized(response, MALWAREBAZAAR_SOURCE):
        logger.warning(
            "sample download was refused",
            source=MALWAREBAZAAR_SOURCE,
            status_code=response.status_code,
        )
        return None
    if not response.content.startswith(_ZIP_MAGIC):
        logger.info("sample is not held by this source", source=MALWAREBAZAAR_SOURCE)
        return None
    return unwrap_archive(response.content)


def download_virustotal(sha256: str, *, timeout: float, api_key: str) -> bytes | None:
    """Fetch one sample from VirusTotal, or ``None``. Never raises.

    ``/files/{id}/download`` is a premium endpoint. A free key is refused with
    403, which is logged as a key privilege rather than as an absent sample, so
    the caller can tell "VirusTotal will not give me this" from "VirusTotal does
    not have this".
    """
    try:
        response = httpx.get(
            _VT_DOWNLOAD_URL.format(sha256=sha256),
            headers={"x-apikey": api_key},
            timeout=timeout,
            follow_redirects=True,
        )
    except Exception as error:  # fail open: a fetch must never take down the run
        logger.warning(
            "sample download failed", source=VIRUSTOTAL_SOURCE, error_type=type(error).__name__
        )
        return None

    if response.status_code == httpx.codes.FORBIDDEN:
        logger.warning(
            "sample download needs a premium key", source=VIRUSTOTAL_SOURCE, status_code=403
        )
        return None
    if response.status_code != httpx.codes.OK or _oversized(response, VIRUSTOTAL_SOURCE):
        logger.warning(
            "sample download was refused",
            source=VIRUSTOTAL_SOURCE,
            status_code=response.status_code,
        )
        return None
    return bytes(response.content)


def sha256_of(payload: bytes) -> str:
    """The lowercase digest of these bytes."""
    return hashlib.sha256(payload).hexdigest()


def fetch_sample(sha256: str, *, settings: IntelSettings | None = None) -> FetchOutcome:
    """Try each configured download source for one digest. Never raises.

    Returns empty-handed when no credential is configured, the same gate the
    reputation sweep uses: without a key nothing is queried and nothing is
    fetched.

    What comes back is verified against what was asked for. A source that
    returns bytes with a different digest is refused outright rather than
    stored: content addressing is the pipeline's identity, so accepting a
    mismatch would anchor an entire analysis to a sample nobody requested.
    """
    resolved = settings if settings is not None else get_intel_settings()
    available = [source for source in DOWNLOAD_SOURCES if source in resolved.active_sources]
    if not available:
        return FetchOutcome(reason="no download source is configured")

    timeout = resolved.fetch_timeout_seconds
    tried: list[str] = []
    for source in available:
        payload = _download_one(source, sha256, timeout=timeout, settings=resolved)
        tried.append(source)
        if payload is None:
            continue
        actual = sha256_of(payload)
        if actual != sha256:
            logger.warning(
                "downloaded sample did not match the requested digest",
                source=source,
                requested=sha256,
                received=actual,
            )
            continue
        return FetchOutcome(payload=payload, source=source)

    return FetchOutcome(reason=f"not served by {', '.join(tried)}")


def _download_one(
    source: str, sha256: str, *, timeout: float, settings: IntelSettings
) -> bytes | None:
    if source == MALWAREBAZAAR_SOURCE:
        return download_malwarebazaar(
            sha256, timeout=timeout, api_key=_secret(settings.malwarebazaar_api_key)
        )
    if source == VIRUSTOTAL_SOURCE:
        return download_virustotal(
            sha256, timeout=timeout, api_key=_secret(settings.virustotal_api_key)
        )
    return None


def _secret(key: SecretStr | None) -> str:
    """Unwrap a credential at the moment of use, never before."""
    return key.get_secret_value() if key is not None else ""
