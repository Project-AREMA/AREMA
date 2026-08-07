"""Ingest a sample identified by digest rather than by path.

``acquire_sample`` answers "analyze this file". This answers "analyze this
hash", which is how a sample is usually named in a report, a ticket, or a threat
feed, and the analyst may or may not already hold a copy.

Resolution order, and the rule that matters most is the one about paths:

1. **A path is never resolved here.** When the user supplied a path, the intake
   prompt routes to ``acquire_sample`` and this tool is not called at all. A
   path that does not exist is an error to report, never a reason to go looking
   on the internet for something with a similar name.
2. **Local first.** A file named for the digest, in the given directory or the
   working directory, is used as-is with no network access whatsoever. The same
   digest under a suffix (``<sha256>.bin``, ``<sha256>.exe``) counts: it is
   still a file named for the hash, and it is how sample collections on disk
   almost always look.
3. **Only then, external.** With no local copy and at least one credential
   configured, the download sources are tried in order. With no credential, the
   answer is that the sample was not found, not a request to anybody.

Nothing is ever sent out but the digest. See
:mod:`reverse_engineering.intel.fetch` for why that is structural rather than a
promise, and ``tests/architecture/test_no_sample_upload.py`` for its enforcement.
"""

from __future__ import annotations

import re
from pathlib import Path

from google.adk.tools.tool_context import ToolContext  # noqa: TC002 - ADK resolves annotations

from arema.core.logging import get_logger
from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from reverse_engineering.artifacts import ArtifactStore, default_artifacts_root
from reverse_engineering.intel.fetch import fetch_sample
from reverse_engineering.tools.acquire_sample import acquire_sample

logger = get_logger(__name__)

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

__all__ = ["ACQUIRE_SAMPLE_BY_HASH_TOOL", "acquire_sample_by_hash", "find_local_sample"]


def find_local_sample(sha256: str, search_dir: str = "") -> Path | None:
    """The file named for this digest in ``search_dir``, or ``None``.

    Exact name first, then the same stem under any suffix, so a collection
    holding ``<sha256>.bin`` is not passed over in favour of a download.
    """
    root = Path(search_dir).expanduser() if search_dir else Path.cwd()
    if not root.is_dir():
        return None
    exact = root / sha256
    if exact.is_file():
        return exact
    for candidate in sorted(root.glob(f"{sha256}.*")):
        if candidate.is_file():
            return candidate
    return None


def acquire_sample_by_hash(
    sha256: str, search_dir: str = "", tool_context: ToolContext | None = None
) -> dict[str, str | int]:
    """Ingest a sample by its SHA-256, from disk if present or from a configured
    reputation source if not, and return the same fields as ``acquire_sample``.

    ``sha256`` is the 64-character lowercase digest of the sample to analyze.
    ``search_dir`` optionally names the directory to look in; the working
    directory is used when it is empty. A file named for the digest, with or
    without a suffix, is used directly and no network request is made. Only when
    no such file exists are the configured external sources asked, by digest
    alone -- the sample itself is never sent anywhere, under any circumstances.

    Returns ``artifact_id``, ``sha256``, ``size``, ``format``, ``packer`` and the
    ``origin`` the bytes came from (``local`` or the source name). On failure it
    returns ``error`` explaining whether the sample was absent locally, absent
    externally, or whether no source was configured to ask.
    """
    digest = sha256.strip().lower()
    if _SHA256_PATTERN.fullmatch(digest) is None:
        return {"error": "sha256 must be a 64-character hex digest", "sha256": ""}

    local = find_local_sample(digest, search_dir)
    if local is not None:
        result = acquire_sample(str(local), tool_context)
        return {**result, "origin": "local"}

    outcome = fetch_sample(digest)
    if outcome.payload is None:
        logger.warning("sample could not be resolved", reason=outcome.reason)
        return {
            "error": f"no local file named for the digest, and {outcome.reason}",
            "sha256": digest,
        }

    store = ArtifactStore(default_artifacts_root())
    artifact_id = store.acquire_bytes(outcome.payload)
    result = acquire_sample(str(store.path_for(artifact_id)), tool_context)
    return {**result, "origin": outcome.source}


ACQUIRE_SAMPLE_BY_HASH_TOOL = ToolDescriptor(
    id="acquire_sample_by_hash",
    description=(
        "Ingest a sample identified by its SHA-256 digest: use a file named for "
        "the digest in the given or working directory when one exists, and "
        "otherwise download it from a configured reputation source by digest "
        "alone. Never uploads or transmits the sample itself. Use this only when "
        "the user supplied a hash; use acquire_sample when they supplied a path."
    ),
    tool=acquire_sample_by_hash,
    output_policy=OutputPolicy(max_chars=2_000, max_list_items=10),
)
