"""The sweep across sources, and the one line the prompts read.

Two properties dominate. Nothing configured means nothing queried, asserted with
a fetch that raises if it is called at all rather than with a count. And a miss
is printed rather than dropped, because "absent from every corpus" is a real
answer that must stay distinguishable from "we never asked".
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from reverse_engineering.intel import lookup
from reverse_engineering.intel.config import IntelSettings
from reverse_engineering.intel.lookup import (
    MAX_INTEL_LINE_CHARS,
    gather,
    render_intel_line,
)
from reverse_engineering.intel.models import (
    HASHLOOKUP_SOURCE,
    MALWAREBAZAAR_SOURCE,
    VIRUSTOTAL_SOURCE,
    IntelResult,
    IntelStatus,
)

AID = "a" * 64


@pytest.fixture(autouse=True)
def _no_live_keyed_lookups(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make an unstubbed keyed lookup a loud failure, not a live request.

    These tests are the only ones in the suite that configure a credential, so
    they are the only ones that can reach a keyed source. Before this fixture
    existed they did: wiring VirusTotal into the dispatch turned three of them
    into real requests to virustotal.com that still passed, because a bogus key
    returns 401 and 401 degrades to unavailable exactly as a stub would.
    """
    for name in ("lookup_virustotal", "lookup_malwarebazaar"):

        def _landmine(*_args: object, _name: str = name, **_kwargs: object) -> object:
            raise AssertionError(f"{_name} was called for real; stub it in the test")

        monkeypatch.setattr(lookup, name, _landmine)


def _off() -> IntelSettings:
    return IntelSettings(virustotal_api_key=None, malwarebazaar_api_key=None)


def _on() -> IntelSettings:
    return IntelSettings(virustotal_api_key=SecretStr("k"), malwarebazaar_api_key=None)


def _result(source: str, status: IntelStatus, summary: str = "") -> IntelResult:
    return IntelResult(source=source, status=status, summary=summary)


def _stub(monkeypatch: pytest.MonkeyPatch, name: str, result: IntelResult) -> None:
    """Replace one source's lookup with a constant answer."""
    monkeypatch.setattr(lookup, name, lambda *_a, **_k: result)


def _stub_keyed(monkeypatch: pytest.MonkeyPatch, status: IntelStatus) -> None:
    """Replace both keyed sources, whose fixture default is a landmine."""
    _stub(monkeypatch, "lookup_virustotal", _result(VIRUSTOTAL_SOURCE, status))
    _stub(monkeypatch, "lookup_malwarebazaar", _result(MALWAREBAZAAR_SOURCE, status))


# --- nothing configured, nothing queried --------------------------------------


def test_an_unconfigured_checkout_makes_no_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """Proven, not assumed: the fetch raises if it is reached at all."""

    def _explode(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("gather must not reach the network without a credential")

    monkeypatch.setattr(lookup, "lookup_hashlookup", _explode)

    assert gather(AID, settings=_off()) == ()


def test_the_rendered_line_is_empty_when_nothing_was_queried() -> None:
    assert render_intel_line(gather(AID, settings=_off())) == ""


def test_settings_default_to_the_cached_instance(monkeypatch: pytest.MonkeyPatch) -> None:
    """The suite pins both keys empty, so the default path is the off path."""

    def _explode(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("gather must not reach the network without a credential")

    monkeypatch.setattr(lookup, "lookup_hashlookup", _explode)

    assert gather(AID) == ()


# --- the sweep ----------------------------------------------------------------


def test_a_configured_source_is_queried_with_its_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def _capture(sha256: str, *, timeout: float) -> IntelResult:
        seen["sha256"] = sha256
        seen["timeout"] = timeout
        return _result(HASHLOOKUP_SOURCE, IntelStatus.KNOWN_GOOD, "catalogued in nsrl_legacy")

    monkeypatch.setattr(lookup, "lookup_hashlookup", _capture)
    _stub_keyed(monkeypatch, IntelStatus.NOT_PRESENT)
    results = gather(AID, settings=_on())

    assert seen["sha256"] == AID
    assert seen["timeout"] == 5.0
    assert [result.source for result in results] == [HASHLOOKUP_SOURCE, VIRUSTOTAL_SOURCE]


def test_a_source_with_no_wired_lookup_degrades() -> None:
    """Unreachable through gather, since active_sources only ever emits known
    names. It exists so adding a source to the gate and forgetting to wire it
    reports unavailable rather than raising into the acquire."""
    result = lookup._lookup_one("some_future_source", AID, timeout=1.0, settings=_off())

    assert result.status is IntelStatus.UNAVAILABLE
    assert result.source == "some_future_source"


def test_one_failing_source_does_not_suppress_the_others(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub(monkeypatch, "lookup_hashlookup", _result(HASHLOOKUP_SOURCE, IntelStatus.UNAVAILABLE))
    _stub_keyed(monkeypatch, IntelStatus.KNOWN_BAD)
    results = gather(AID, settings=_on())

    assert len(results) == 2
    assert results[1].status is IntelStatus.KNOWN_BAD


def test_a_lookup_that_raises_is_not_swallowed_into_silence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each source module owns its own fail-open. A leak past that is a defect,
    so gather must not paper over it with a bare except."""

    def _raise(*_args: object, **_kwargs: object) -> IntelResult:
        raise RuntimeError("leaked past the source module")

    monkeypatch.setattr(lookup, "lookup_hashlookup", _raise)

    with pytest.raises(RuntimeError, match="leaked past"):
        gather(AID, settings=_on())


def test_the_total_budget_bounds_a_sweep_of_sick_endpoints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per-source timeouts bound one call; this bounds their sum."""
    settings = IntelSettings(
        virustotal_api_key=SecretStr("k"),
        malwarebazaar_api_key=SecretStr("j"),
        intel_timeout_seconds=20.0,
    )
    charged: list[float] = []

    def _slow(_sha256: str, *, timeout: float) -> IntelResult:
        charged.append(timeout)
        return _result(HASHLOOKUP_SOURCE, IntelStatus.UNAVAILABLE)

    monkeypatch.setattr(lookup, "lookup_hashlookup", _slow)
    results = gather(AID, settings=settings)

    assert charged == [15.0]
    assert len(results) == 3
    assert all(result.status is IntelStatus.UNAVAILABLE for result in results)


def test_a_fast_answer_does_not_consume_the_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """Charging a hit against the budget would starve later sources for time
    nobody spent."""
    settings = IntelSettings(
        virustotal_api_key=SecretStr("k"),
        malwarebazaar_api_key=SecretStr("j"),
        intel_timeout_seconds=20.0,
    )
    _stub(monkeypatch, "lookup_hashlookup", _result(HASHLOOKUP_SOURCE, IntelStatus.KNOWN_GOOD))
    _stub_keyed(monkeypatch, IntelStatus.KNOWN_GOOD)

    assert len(gather(AID, settings=settings)) == 3


# --- the rendered line --------------------------------------------------------


def test_a_miss_is_printed_rather_than_dropped() -> None:
    """An analyst who sees the source listed knows it was asked. One who sees
    nothing cannot tell absence from an outage."""
    line = render_intel_line(
        [
            _result(HASHLOOKUP_SOURCE, IntelStatus.NOT_PRESENT),
            _result(VIRUSTOTAL_SOURCE, IntelStatus.NOT_PRESENT),
        ]
    )

    assert line == "hashlookup: not present; virustotal: not present"


def test_the_line_never_says_clean() -> None:
    for status in IntelStatus:
        line = render_intel_line([_result(HASHLOOKUP_SOURCE, status)])
        assert "clean" not in line.lower()
        assert "safe" not in line.lower()


def test_a_flagged_digest_is_shouted() -> None:
    line = render_intel_line(
        [_result(HASHLOOKUP_SOURCE, IntelStatus.KNOWN_BAD, "flagged malicious by malshare.com")]
    )

    assert line == "hashlookup: FLAGGED MALICIOUS (flagged malicious by malshare.com)"


def test_an_outage_reads_as_an_outage_not_as_absence() -> None:
    line = render_intel_line([_result(VIRUSTOTAL_SOURCE, IntelStatus.UNAVAILABLE)])

    assert line == "virustotal: unavailable"
    assert "not present" not in line


def test_every_source_appears_in_a_full_sweep() -> None:
    line = render_intel_line(
        [
            _result(HASHLOOKUP_SOURCE, IntelStatus.KNOWN_GOOD, "catalogued in nsrl_legacy"),
            _result(VIRUSTOTAL_SOURCE, IntelStatus.NOT_PRESENT),
            _result(MALWAREBAZAAR_SOURCE, IntelStatus.UNAVAILABLE),
        ]
    )

    for source in (HASHLOOKUP_SOURCE, VIRUSTOTAL_SOURCE, MALWAREBAZAAR_SOURCE):
        assert source in line


def test_the_line_is_bounded_even_at_every_source_maximum() -> None:
    results = [
        _result(source, IntelStatus.KNOWN_BAD, "x" * 200)
        for source in (HASHLOOKUP_SOURCE, VIRUSTOTAL_SOURCE, MALWAREBAZAAR_SOURCE)
    ]

    assert len(render_intel_line(results)) <= MAX_INTEL_LINE_CHARS


def test_the_line_stays_safe_for_an_instruction_template() -> None:
    line = render_intel_line(
        [_result(HASHLOOKUP_SOURCE, IntelStatus.KNOWN_GOOD, "name {sample_intel?} here")]
    )

    assert "{" not in line
    assert "}" not in line
    assert "\n" not in line


def test_an_empty_sweep_renders_nothing() -> None:
    assert render_intel_line([]) == ""
