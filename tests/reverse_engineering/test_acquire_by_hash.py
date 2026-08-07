"""Ingest by digest: local first, external only if configured, never upward.

The resolution order carries the whole safety argument. A path the user typed is
never resolved here at all. A digest resolves against disk before the network. A
digest with no local copy and no credential resolves to "not found", not to a
request. And nothing in any branch sends the sample anywhere, which
``tests/architecture/test_no_sample_upload.py`` enforces structurally.
"""

from __future__ import annotations

import hashlib
import io
from typing import TYPE_CHECKING

import pytest
import pyzipper
from pydantic import SecretStr

from reverse_engineering.intel import fetch as fetch_module
from reverse_engineering.intel.config import IntelSettings
from reverse_engineering.intel.fetch import (
    DOWNLOAD_SOURCES,
    MAX_SAMPLE_BYTES,
    FetchOutcome,
    download_malwarebazaar,
    download_virustotal,
    fetch_sample,
    unwrap_archive,
)
from reverse_engineering.intel.models import MALWAREBAZAAR_SOURCE, VIRUSTOTAL_SOURCE
from reverse_engineering.prompts.loader import load_domain_prompt
from reverse_engineering.tools import acquire_by_hash
from reverse_engineering.tools.acquire_by_hash import (
    ACQUIRE_SAMPLE_BY_HASH_TOOL,
    acquire_sample_by_hash,
    find_local_sample,
)

if TYPE_CHECKING:
    from pathlib import Path

SAMPLE = b"MZ" + b"\x00" * 128
DIGEST = hashlib.sha256(SAMPLE).hexdigest()
OTHER = "b" * 64


class _FakeState(dict[str, object]):
    """Duck-typed ADK State stand-in, deliberately not a State subclass."""


class _FakeToolContext:
    def __init__(self) -> None:
        self.state = _FakeState()


class _Response:
    def __init__(self, status_code: int, content: bytes = b"") -> None:
        self.status_code = status_code
        self.content = content


def _aes_zip(name: str, payload: bytes) -> bytes:
    """An archive shaped like the ones MalwareBazaar serves: AES, "infected"."""
    buffer = io.BytesIO()
    with pyzipper.AESZipFile(
        buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as archive:
        archive.setpassword(b"infected")
        archive.writestr(name, payload)
    return buffer.getvalue()


def _keyed() -> IntelSettings:
    return IntelSettings(malwarebazaar_api_key=SecretStr("k"), virustotal_api_key=None)


def _unkeyed() -> IntelSettings:
    return IntelSettings(malwarebazaar_api_key=None, virustotal_api_key=None)


def _set_root(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    for module in ("acquire_by_hash", "acquire_sample"):
        monkeypatch.setattr(
            f"reverse_engineering.tools.{module}.default_artifacts_root", lambda r=root: r
        )


# --- local resolution: the network is not involved -----------------------------


def test_a_file_named_for_the_digest_is_found(tmp_path: Path) -> None:
    (tmp_path / DIGEST).write_bytes(SAMPLE)

    assert find_local_sample(DIGEST, str(tmp_path)) == tmp_path / DIGEST


@pytest.mark.parametrize("suffix", [".bin", ".exe", ".malware", ".sample"])
def test_the_digest_under_a_suffix_still_counts(tmp_path: Path, suffix: str) -> None:
    """A collection on disk almost always looks like <sha256>.bin. That is still
    a file named for the hash, and passing it over to download would be absurd."""
    (tmp_path / f"{DIGEST}{suffix}").write_bytes(SAMPLE)

    assert find_local_sample(DIGEST, str(tmp_path)) is not None


def test_a_different_digest_is_not_a_match(tmp_path: Path) -> None:
    (tmp_path / OTHER).write_bytes(SAMPLE)

    assert find_local_sample(DIGEST, str(tmp_path)) is None


def test_a_directory_named_for_the_digest_is_not_a_sample(tmp_path: Path) -> None:
    (tmp_path / DIGEST).mkdir()

    assert find_local_sample(DIGEST, str(tmp_path)) is None


def test_a_missing_search_directory_is_not_an_error(tmp_path: Path) -> None:
    assert find_local_sample(DIGEST, str(tmp_path / "nope")) is None


def test_a_local_hit_never_reaches_the_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The point of looking locally first, asserted with a landmine rather than
    a call count."""
    _set_root(monkeypatch, tmp_path / "artifacts")
    (tmp_path / DIGEST).write_bytes(SAMPLE)

    def _explode(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a local sample must never trigger a download")

    monkeypatch.setattr(acquire_by_hash, "fetch_sample", _explode)
    result = acquire_sample_by_hash(DIGEST, str(tmp_path), _FakeToolContext())  # type: ignore[arg-type]

    assert result["artifact_id"] == DIGEST
    assert result["origin"] == "local"


# --- no credential: an absence, not a request ---------------------------------


def test_no_credential_yields_not_found_rather_than_a_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_root(monkeypatch, tmp_path / "artifacts")

    def _explode(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("fetch must not reach the network without a credential")

    monkeypatch.setattr(fetch_module.httpx, "post", _explode)
    monkeypatch.setattr(fetch_module.httpx, "get", _explode)
    result = acquire_sample_by_hash(DIGEST, str(tmp_path), _FakeToolContext())  # type: ignore[arg-type]

    assert "no download source is configured" in str(result["error"])
    assert "artifact_id" not in result


def test_fetch_returns_empty_handed_without_a_credential() -> None:
    outcome = fetch_sample(DIGEST, settings=_unkeyed())

    assert outcome.payload is None
    assert outcome.reason == "no download source is configured"


# --- the download path --------------------------------------------------------


def test_a_bazaar_archive_is_unwrapped() -> None:
    assert unwrap_archive(_aes_zip("sample.bin", SAMPLE)) == SAMPLE


@pytest.mark.parametrize(
    "payload", [b"", b"not a zip at all", b"PK\x03\x04 truncated", b"\x00" * 64]
)
def test_an_unusable_archive_degrades_rather_than_raising(payload: bytes) -> None:
    assert unwrap_archive(payload) is None


def test_an_archive_of_many_members_is_refused() -> None:
    """A sample archive holds one sample. More than that is not the shape we
    asked for, and picking one arbitrarily would be a guess."""
    buffer = io.BytesIO()
    with pyzipper.AESZipFile(buffer, "w", encryption=pyzipper.WZ_AES) as archive:
        archive.setpassword(b"infected")
        archive.writestr("one.bin", SAMPLE)
        archive.writestr("two.bin", SAMPLE)

    assert unwrap_archive(buffer.getvalue()) is None


def test_an_archive_that_expands_past_the_ceiling_is_refused() -> None:
    """A zip bomb: small on the wire, enormous once opened."""
    assert unwrap_archive(_aes_zip("huge.bin", b"\x00" * (MAX_SAMPLE_BYTES + 1))) is None


def test_a_bazaar_download_sends_the_digest_and_the_key_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def _capture(url: str, **kwargs: object) -> _Response:
        seen["url"] = url
        seen.update(kwargs)
        return _Response(200, _aes_zip("s.bin", SAMPLE))

    monkeypatch.setattr(fetch_module.httpx, "post", _capture)

    assert download_malwarebazaar(DIGEST, timeout=60.0, api_key="secret") == SAMPLE
    assert seen["data"] == {"query": "get_file", "sha256_hash": DIGEST}
    assert seen["headers"] == {"Auth-Key": "secret"}
    assert "files" not in seen
    assert "content" not in seen


def test_a_virustotal_download_on_a_free_key_is_a_privilege_problem(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """/files/{id}/download is premium-only, so a free key gets 403. That is not
    the sample being absent, and must not be reported as one."""
    monkeypatch.setattr(fetch_module.httpx, "get", lambda *_a, **_k: _Response(403))

    assert download_virustotal(DIGEST, timeout=60.0, api_key="free-key") is None


@pytest.mark.parametrize("status_code", [401, 404, 429, 500])
def test_a_refused_download_degrades(monkeypatch: pytest.MonkeyPatch, status_code: int) -> None:
    monkeypatch.setattr(fetch_module.httpx, "post", lambda *_a, **_k: _Response(status_code))

    assert download_malwarebazaar(DIGEST, timeout=60.0, api_key="k") is None


def test_an_oversized_transfer_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        fetch_module.httpx,
        "post",
        lambda *_a, **_k: _Response(200, b"\x00" * (MAX_SAMPLE_BYTES + 1)),
    )

    assert download_malwarebazaar(DIGEST, timeout=60.0, api_key="k") is None


def test_a_transport_failure_degrades(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*_args: object, **_kwargs: object) -> object:
        raise OSError("network unreachable")

    monkeypatch.setattr(fetch_module.httpx, "post", _raise)

    assert download_malwarebazaar(DIGEST, timeout=60.0, api_key="k") is None


# --- what comes back must be what was asked for -------------------------------


def test_bytes_whose_digest_does_not_match_are_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Content addressing is the pipeline's identity. Accepting a mismatch would
    anchor an entire analysis to a sample nobody requested."""
    monkeypatch.setattr(
        fetch_module,
        "download_malwarebazaar",
        lambda *_a, **_k: b"entirely different bytes",
    )
    outcome = fetch_sample(DIGEST, settings=_keyed())

    assert outcome.payload is None
    assert MALWAREBAZAAR_SOURCE in outcome.reason


def test_matching_bytes_are_returned_with_their_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fetch_module, "download_malwarebazaar", lambda *_a, **_k: SAMPLE)
    outcome = fetch_sample(DIGEST, settings=_keyed())

    assert outcome.payload == SAMPLE
    assert outcome.source == MALWAREBAZAAR_SOURCE


def test_virustotal_is_the_primary_download_source() -> None:
    """The broadest repository of the three: everything ever submitted, rather
    than a curated corpus. With a key that can download it is the one most
    likely to hold any given digest, so it is asked first."""
    assert DOWNLOAD_SOURCES[0] == VIRUSTOTAL_SOURCE
    assert DOWNLOAD_SOURCES == (VIRUSTOTAL_SOURCE, MALWAREBAZAAR_SOURCE)


def test_the_primary_source_serves_without_consulting_the_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the fallback must not be asked once the primary served")

    monkeypatch.setattr(fetch_module, "download_virustotal", lambda *_a, **_k: SAMPLE)
    monkeypatch.setattr(fetch_module, "download_malwarebazaar", _must_not_run)
    settings = IntelSettings(
        malwarebazaar_api_key=SecretStr("k"), virustotal_api_key=SecretStr("j")
    )

    assert fetch_sample(DIGEST, settings=settings).source == VIRUSTOTAL_SOURCE


def test_a_source_that_does_not_serve_it_falls_through_to_the_next(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MalwareBazaar is far from redundant: it carries samples VirusTotal will
    not serve, and it serves them to a free key."""
    monkeypatch.setattr(fetch_module, "download_virustotal", lambda *_a, **_k: None)
    monkeypatch.setattr(fetch_module, "download_malwarebazaar", lambda *_a, **_k: SAMPLE)
    settings = IntelSettings(
        malwarebazaar_api_key=SecretStr("k"), virustotal_api_key=SecretStr("j")
    )
    outcome = fetch_sample(DIGEST, settings=settings)

    assert outcome.source == MALWAREBAZAAR_SOURCE


def test_the_reason_names_every_source_that_was_asked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fetch_module, "download_malwarebazaar", lambda *_a, **_k: None)
    monkeypatch.setattr(fetch_module, "download_virustotal", lambda *_a, **_k: None)
    settings = IntelSettings(
        malwarebazaar_api_key=SecretStr("k"), virustotal_api_key=SecretStr("j")
    )

    reason = fetch_sample(DIGEST, settings=settings).reason
    assert MALWAREBAZAAR_SOURCE in reason
    assert VIRUSTOTAL_SOURCE in reason


def test_a_downloaded_sample_is_stored_and_ingested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_root(monkeypatch, tmp_path / "artifacts")
    monkeypatch.setattr(
        acquire_by_hash,
        "fetch_sample",
        lambda _d: FetchOutcome(payload=SAMPLE, source=MALWAREBAZAAR_SOURCE),
    )
    context = _FakeToolContext()

    result = acquire_sample_by_hash(DIGEST, str(tmp_path), context)  # type: ignore[arg-type]

    assert result["artifact_id"] == DIGEST
    assert result["origin"] == MALWAREBAZAAR_SOURCE
    assert (tmp_path / "artifacts" / DIGEST).read_bytes() == SAMPLE


# --- input handling -----------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["", "not-a-hash", "a" * 63, "a" * 65, "g" * 64, "/path/to/file", "../etc/passwd"],
)
def test_a_value_that_is_not_a_digest_is_refused(value: str) -> None:
    """The tool takes a digest. A path arriving here means the model routed
    wrongly, and resolving it would defeat the path-is-never-external rule."""
    result = acquire_sample_by_hash(value)

    assert "64-character hex digest" in str(result["error"])


def test_an_uppercase_digest_is_normalized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _set_root(monkeypatch, tmp_path / "artifacts")
    (tmp_path / DIGEST).write_bytes(SAMPLE)

    result = acquire_sample_by_hash(DIGEST.upper(), str(tmp_path), _FakeToolContext())  # type: ignore[arg-type]

    assert result["artifact_id"] == DIGEST


def test_the_tool_descriptor_id_matches_the_function_name() -> None:
    assert ACQUIRE_SAMPLE_BY_HASH_TOOL.id == acquire_sample_by_hash.__name__


def test_the_tool_descriptor_says_it_never_uploads() -> None:
    """The description is what the model reads when deciding. It should not be
    possible to read it as offering submission."""
    assert "Never uploads" in ACQUIRE_SAMPLE_BY_HASH_TOOL.description


# --- the routing rules live in the prompt, so pin them there -------------------


def _intake_prompt() -> str:
    return load_domain_prompt("sample_intake")


def test_prompt_routes_a_path_away_from_the_hash_tool() -> None:
    """The rule the user cares about most: a path is resolved locally or not at
    all. A model that falls back to a download on a missing path would defeat it."""
    prompt = _intake_prompt()

    assert "`acquire_sample(path)`. **Never** `acquire_sample_by_hash`" in prompt
    assert "never a reason to go looking for the sample externally" in prompt


def test_prompt_forbids_turning_a_failed_path_into_a_hash_lookup() -> None:
    prompt = _intake_prompt()

    assert "must not convert a failed path into a hash lookup" in prompt
    assert "even when the filename happens to look like a digest" in prompt


def test_prompt_names_both_ingest_tools_and_when_each_applies() -> None:
    prompt = _intake_prompt()

    assert "acquire_sample_by_hash(sha256)" in prompt
    assert "bare 64-character hex digest" in prompt


def test_prompt_forbids_offering_to_upload() -> None:
    """A model that cannot upload could still suggest it, which is its own kind
    of harm when the user is holding a client's incident sample."""
    prompt = _intake_prompt()

    assert "Never suggest uploading the sample anywhere" in prompt
    assert "nothing in this system transmits a sample" in prompt


def test_prompt_requires_reporting_where_the_bytes_came_from() -> None:
    assert "Report the `origin` field" in _intake_prompt()


def test_prompt_refuses_to_ingest_two_samples_in_one_run() -> None:
    """43 call sites hang off a single CURRENT_ARTIFACT_KEY, and the reset
    docstring says the new id is the only authority retained. A second ingest
    would silently replace the first and report on a sample nobody asked about."""
    prompt = _intake_prompt()

    assert "This pipeline analyzes one sample per run." in prompt
    assert "Never ingest both" in prompt


# --- measured against the live services ---------------------------------------

# Measured: get_file for a digest abuse.ch does not hold. HTTP 200, JSON body.
MB_FILE_NOT_FOUND = b'{\n    "query_status": "file_not_found"\n}'


def test_a_bazaar_miss_is_recognized_before_the_archive_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_file answers 200 whether or not it holds the sample, so the body has
    to be checked for the archive signature first. Feeding the JSON to the
    archive reader logs a BadZipFile corruption warning on the entirely routine
    path of asking for something abuse.ch does not have."""
    monkeypatch.setattr(
        fetch_module.httpx, "post", lambda *_a, **_k: _Response(200, MB_FILE_NOT_FOUND)
    )

    assert download_malwarebazaar(DIGEST, timeout=60.0, api_key="k") is None


def test_a_non_archive_body_is_not_reported_as_a_corrupt_archive(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A miss is a normal outcome and must not read as a defect in the log."""
    monkeypatch.setattr(
        fetch_module.httpx, "post", lambda *_a, **_k: _Response(200, MB_FILE_NOT_FOUND)
    )
    download_malwarebazaar(DIGEST, timeout=60.0, api_key="k")

    assert "BadZipFile" not in capsys.readouterr().out


def test_a_stored_sample_carries_no_execute_bit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A downloaded sample is malware sitting on an analyst's disk. Nothing in
    this pipeline executes it, and the file it lands in should not invite it."""
    _set_root(monkeypatch, tmp_path / "artifacts")
    monkeypatch.setattr(
        acquire_by_hash,
        "fetch_sample",
        lambda _d: FetchOutcome(payload=SAMPLE, source=MALWAREBAZAAR_SOURCE),
    )
    acquire_sample_by_hash(DIGEST, str(tmp_path), _FakeToolContext())  # type: ignore[arg-type]

    mode = (tmp_path / "artifacts" / DIGEST).stat().st_mode
    assert not mode & 0o111, "a stored sample must not be executable"
