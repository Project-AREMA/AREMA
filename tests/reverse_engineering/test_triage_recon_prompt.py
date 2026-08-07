"""The triage_recon prompt must carry the .NET/CIL routing guardrails.

Measured against the live engine: r2 ``analyze`` returns ~2 MB (~538k tokens) on
an 18 KB .NET assembly vs 367 bytes for a 142 KB native ELF, so ``analyze`` must
be conditional on the format -- and the format itself must be recorded as a
finding, because it routes the pipeline to Ghidra (native) or ILSpy (managed).
"""

from __future__ import annotations

import pytest

from reverse_engineering.evidence_envelope import FindingKind
from reverse_engineering.intel.models import (
    HASHLOOKUP_SOURCE,
    MALWAREBAZAAR_SOURCE,
    VIRUSTOTAL_SOURCE,
)
from reverse_engineering.prompts.loader import load_domain_prompt
from reverse_engineering.tools.acquire_sample import (
    SAMPLE_INTEL_PROMPT_KEY,
    SAMPLE_PACKER_PROMPT_KEY,
)
from reverse_engineering.tools.detect_it_easy import DIE_TOOL_NAME, SAMPLE_DIE_PROMPT_KEY


@pytest.fixture
def triage_prompt() -> str:
    return load_domain_prompt("triage_recon")


def test_prompt_forbids_analyze_on_dotnet(triage_prompt: str) -> None:
    assert "NEVER call `analyze` on a .NET assembly" in triage_prompt


def test_prompt_makes_the_analyze_step_conditional(triage_prompt: str) -> None:
    """An unconditional 'then call analyze' is what blew the context budget."""
    assert "MUST NOT call `analyze`" in triage_prompt
    assert "`format` is `dotnet`" in triage_prompt


def test_prompt_lists_the_cheap_tools_that_work_without_analyze(triage_prompt: str) -> None:
    for tool_name in ("show_info", "list_strings", "list_imports", "list_functions"):
        assert f"`{tool_name}`" in triage_prompt


def test_prompt_requires_the_format_to_be_recorded_as_a_finding(triage_prompt: str) -> None:
    """The format routes the pipeline to Ghidra or ILSpy, so triage must emit it."""
    lowered = triage_prompt.lower()
    assert "confirm the format" in lowered
    assert "must record it" in lowered


def test_prompt_reads_the_alias_acquire_sample_actually_writes(triage_prompt: str) -> None:
    """The placeholder and the state key it resolves from must stay one name."""
    assert f"{{{SAMPLE_PACKER_PROMPT_KEY}?}}" in triage_prompt


def test_prompt_forbids_reading_an_empty_packer_as_unpacked(triage_prompt: str) -> None:
    """A watermark scan is precision-first, so silence is "not named", not "clean"."""
    assert "not** a finding that the sample is unpacked" in triage_prompt


def test_the_critic_accepts_the_tools_the_packer_findings_cite(triage_prompt: str) -> None:
    """Triage cites acquire_sample and detect_it_easy; the critic rejects any tool
    off its allowlist.

    Without the pairing the packer finding is emitted and then silently dropped
    before the report, which is the same invisibility the detection exists to fix.
    """
    critic = load_domain_prompt("evidence_critic")
    assert "`tool` exactly `acquire_sample`" in triage_prompt
    assert f"exactly `{DIE_TOOL_NAME}`" in triage_prompt
    assert "`acquire_sample`" in critic
    assert f"`{DIE_TOOL_NAME}`" in critic


def test_prompt_reads_the_die_alias_prepare_sandbox_actually_writes(
    triage_prompt: str,
) -> None:
    """The placeholder and the state key it resolves from must stay one name."""
    assert f"{{{SAMPLE_DIE_PROMPT_KEY}?}}" in triage_prompt


def test_prompt_separates_the_packer_name_from_the_marker(triage_prompt: str) -> None:
    """Observed in a live run: the report's metadata table rendered
    "Packer | UPX!" because the injected line "UPX (matched: UPX!)" left it
    ambiguous which part was the name. UPX! is a magic string, not a packer."""
    assert "The packer name is the family, never a marker." in triage_prompt


def test_prompt_keeps_the_two_detectors_separately_citable(triage_prompt: str) -> None:
    """They look at different things, so a disagreement is information, not an
    error for the model to resolve by picking one."""
    assert "do not adjudicate" in triage_prompt
    assert "Never cite one for the other's result." in triage_prompt


# --- third-party reputation ---------------------------------------------------


def test_prompt_reads_the_intel_alias_acquire_sample_actually_writes(
    triage_prompt: str,
) -> None:
    """ADK resolves ``{name?}`` from state by exact identifier, so a prompt
    reading the colon-form canonical key would silently never resolve."""
    assert f"{{{SAMPLE_INTEL_PROMPT_KEY}?}}" in triage_prompt
    assert SAMPLE_INTEL_PROMPT_KEY.isidentifier()


def test_the_intel_placeholder_appears_exactly_once(triage_prompt: str) -> None:
    """ADK substitutes every occurrence, so a placeholder mentioned twice pastes
    the whole reputation line twice."""
    assert triage_prompt.count(f"{{{SAMPLE_INTEL_PROMPT_KEY}?}}") == 1


def test_reputation_findings_use_the_intel_kind_not_metadata(triage_prompt: str) -> None:
    """The kind is what lets the report separate somebody else's scanner from
    evidence AREMA derived from the bytes."""
    assert "`kind` exactly `intel`" in triage_prompt
    assert FindingKind.INTEL.value in triage_prompt


def test_prompt_forbids_reading_a_reputation_miss_as_clean(triage_prompt: str) -> None:
    """The single most dangerous misreading: absent from a corpus is the normal
    answer for anything freshly built, packed, or targeted."""
    assert "`not present` is not clean" in triage_prompt
    assert "never emit a finding saying the sample is safe" in triage_prompt.lower()


def test_prompt_keeps_an_outage_distinct_from_an_absence(triage_prompt: str) -> None:
    assert "`unavailable` is not `not present`" in triage_prompt


def test_prompt_forbids_reading_an_empty_intel_line_as_clean(triage_prompt: str) -> None:
    """Empty means nobody was asked or nobody answered, which is further from
    evidence of a clean sample than a recorded miss."""
    assert "Empty means nobody was asked" in triage_prompt


def test_prompt_forbids_restating_third_party_claims_as_observations(
    triage_prompt: str,
) -> None:
    assert "This is not your evidence" in triage_prompt
    assert "Never carry it into a claim about what the code does." in triage_prompt


def test_the_critic_accepts_the_tools_the_reputation_findings_cite() -> None:
    """Same pairing the packer findings need: a tool off the critic's allowlist
    is emitted and then silently dropped before the report."""
    critic = load_domain_prompt("evidence_critic")
    for source in (HASHLOOKUP_SOURCE, MALWAREBAZAAR_SOURCE, VIRUSTOTAL_SOURCE):
        assert f"`{source}`" in critic


def test_the_critic_does_not_demand_a_code_path_from_an_intel_finding() -> None:
    """Rule 2 is written for artifact-derived claims. Applied to a reputation
    result it would reject every one of them, since none has a code path."""
    critic = load_domain_prompt("evidence_critic")

    assert "`intel` findings are judged differently" in critic
    assert "do not demand code, addresses, or a source-to-sink path" in critic


def test_the_critic_rejects_a_miss_restated_as_a_clean_verdict() -> None:
    critic = load_domain_prompt("evidence_critic")

    assert '"not present" turned into "clean"' in critic
