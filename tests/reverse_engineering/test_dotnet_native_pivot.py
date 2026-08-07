"""When the managed decompiler comes back empty, Ghidra gets a turn.

A live QuasarRAT run reported that the sample could not be decompiled. The stated
cause was wrong: ILSpy never ran. An earlier agentic stage had spent the run's
context, so `dotnet_decompile` was killed on arrival before its first tool call,
and the .NET route -- alone among the three deep routes -- had no second leg to
fall through to.

The pivot fires on evidence rather than on a diagnosis, because the three ways
the managed leg can come back empty (never attached, defeated by a protector, cut
short) are indistinguishable from here and all want the same answer: read the
bytes.
"""

from __future__ import annotations

import json

import pytest

from reverse_engineering.agents.dotnet_decompile import DOTNET_DECOMPILE_DESCRIPTOR
from reverse_engineering.agents.dotnet_native_analysis import (
    DOTNET_NATIVE_ANALYSIS_DESCRIPTOR,
)
from reverse_engineering.agents.dotnet_native_pivot import (
    DOTNET_DEEP_ANALYSIS_DESCRIPTOR,
    DOTNET_NATIVE_PIVOT_DESCRIPTOR,
    managed_evidence_is_empty,
)
from reverse_engineering.agents.format_router import DEEP_ENGINE_ROUTER_DESCRIPTOR
from reverse_engineering.evidence_envelope import failed_evidence_envelope
from reverse_engineering.prompts.loader import load_domain_prompt
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY
from reverse_engineering.tools.ghidra.coverage import DEEP_EVIDENCE_KEY, NATIVE_EVIDENCE_KEY

ARTIFACT = "a" * 64


class _State(dict[str, object]):
    """Duck-typed ADK State stand-in, deliberately not a State subclass."""


def _state(**extra: object) -> _State:
    return _State({CURRENT_ARTIFACT_KEY: ARTIFACT, **extra})


def _envelope(*findings: dict[str, object]) -> str:
    return json.dumps(
        {
            "artifact_id": ARTIFACT,
            "coverage": {"status": "complete", "surfaces": ["ilspy"], "limitations": []},
            "findings": list(findings),
        }
    )


_FINDING = {
    "artifact_id": ARTIFACT,
    "claim": "Assembly references System.Net.Sockets.",
    "tool": "analyze_assembly",
    "confidence": 0.9,
    "detail": "AssemblyRef row: System.Net.Sockets",
    "kind": "metadata",
}


# --- when the pivot fires -----------------------------------------------------


def test_an_empty_managed_envelope_pivots() -> None:
    """ILSpy ran and the assembly resisted it: findings are empty."""
    assert managed_evidence_is_empty(_state(**{DEEP_EVIDENCE_KEY: _envelope()}))


def test_a_failed_stage_envelope_pivots() -> None:
    """What the normalizer writes when the model emitted nothing usable, which
    is also what a stage killed before its first tool call leaves behind."""
    failed = failed_evidence_envelope(
        artifact_id=ARTIFACT, stage="deep", code="evidence_envelope_invalid"
    ).model_dump(mode="json")

    assert managed_evidence_is_empty(_state(**{DEEP_EVIDENCE_KEY: failed}))


@pytest.mark.parametrize("raw", [None, "", "Ghidra timed out.", "{not json", [], 7, {}])
def test_unusable_or_absent_evidence_pivots(raw: object) -> None:
    """Fails toward the pivot. A needless native pass costs tokens; a skipped
    one costs a report that says the sample could not be analysed while an
    untouched PE sits in the store."""
    assert managed_evidence_is_empty(_state(**{DEEP_EVIDENCE_KEY: raw}))


def test_a_missing_artifact_id_pivots() -> None:
    state = _State({DEEP_EVIDENCE_KEY: _envelope(_FINDING)})

    assert managed_evidence_is_empty(state)


def test_a_state_without_get_pivots() -> None:
    assert managed_evidence_is_empty(object())


def test_an_envelope_bound_to_another_artifact_pivots() -> None:
    """A mismatched anchor means this evidence is not about this sample."""
    other = json.dumps(
        {
            "artifact_id": "b" * 64,
            "coverage": {"status": "complete", "surfaces": [], "limitations": []},
            "findings": [{**_FINDING, "artifact_id": "b" * 64}],
        }
    )

    assert managed_evidence_is_empty(_state(**{DEEP_EVIDENCE_KEY: other}))


# --- when it does not ---------------------------------------------------------


def test_managed_findings_skip_the_pivot() -> None:
    """The common case costs nothing: ILSpy answered, so Ghidra is not run."""
    assert not managed_evidence_is_empty(_state(**{DEEP_EVIDENCE_KEY: _envelope(_FINDING)}))


def test_a_single_finding_is_enough_to_skip() -> None:
    """One real finding is evidence. The pivot is for nothing at all, not for
    'less than we hoped' -- the model already judges sufficiency downstream."""
    partial = json.dumps(
        {
            "artifact_id": ARTIFACT,
            "coverage": {
                "status": "partial",
                "surfaces": [],
                "limitations": ["deep:assembly_load_failed"],
            },
            "findings": [_FINDING],
        }
    )

    assert not managed_evidence_is_empty(_state(**{DEEP_EVIDENCE_KEY: partial}))


def test_a_dumped_envelope_object_is_read_as_well_as_a_string() -> None:
    """The normalizer writes a dict; a model writes a string. Both must parse."""
    payload = json.loads(_envelope(_FINDING))

    assert not managed_evidence_is_empty(_state(**{DEEP_EVIDENCE_KEY: payload}))


# --- the wiring ---------------------------------------------------------------


def test_the_dotnet_route_points_at_the_composite() -> None:
    engines = DEEP_ENGINE_ROUTER_DESCRIPTOR.metadata["format_engines"]

    assert engines["dotnet"] == "dotnet_deep_analysis"
    assert "dotnet_deep_analysis" in DEEP_ENGINE_ROUTER_DESCRIPTOR.sub_agent_ids


def test_the_composite_runs_ilspy_first_then_the_pivot() -> None:
    """Order is the contract: the pivot reads what the managed leg wrote."""
    assert DOTNET_DEEP_ANALYSIS_DESCRIPTOR.sub_agent_ids == (
        "dotnet_decompile",
        "dotnet_native_pivot",
    )


def test_the_pivot_names_a_worker_that_is_one_of_its_sub_agents() -> None:
    worker = DOTNET_NATIVE_PIVOT_DESCRIPTOR.metadata["worker"]

    assert worker in DOTNET_NATIVE_PIVOT_DESCRIPTOR.sub_agent_ids


def test_the_native_leg_writes_its_own_stage_not_the_managed_one() -> None:
    """Same reasoning as android_native_analysis: the critic unions every stage,
    so an ILSpy envelope that carried some evidence keeps it and the two legs
    never contend for one slot."""
    assert DOTNET_NATIVE_ANALYSIS_DESCRIPTOR.output_key == NATIVE_EVIDENCE_KEY
    assert DOTNET_DECOMPILE_DESCRIPTOR.output_key == DEEP_EVIDENCE_KEY
    assert DOTNET_NATIVE_ANALYSIS_DESCRIPTOR.output_key != DOTNET_DECOMPILE_DESCRIPTOR.output_key


def test_the_native_leg_drives_ghidra_and_prepares_it_first() -> None:
    tools = DOTNET_NATIVE_ANALYSIS_DESCRIPTOR.tool_ids

    assert "prepare_ghidra" in tools
    assert {"ghidra_imports", "ghidra_strings", "ghidra_decompile"} <= set(tools)
    assert not DOTNET_NATIVE_ANALYSIS_DESCRIPTOR.mcp_server_ids


def test_the_native_leg_is_sanitized_like_other_binary_origin_agents() -> None:
    """Its tools return decompiled output from an untrusted binary."""
    assert DOTNET_NATIVE_ANALYSIS_DESCRIPTOR.runtime_profile_id == "re_guarded"


# --- the prompt ---------------------------------------------------------------


def _prompt() -> str:
    return load_domain_prompt("dotnet_native_analysis")


def test_prompt_explains_why_a_native_read_of_a_managed_file_is_legitimate() -> None:
    """Not a consolation prize: mixed-mode and native-body protectors put real
    behaviour where a managed decompiler cannot look, by construction."""
    prompt = _prompt()

    assert "by construction" in prompt
    assert "PE" in prompt


def test_prompt_forbids_reading_no_native_malice_as_benign() -> None:
    """It sees one layer of a sample whose main layer was unreadable."""
    prompt = _prompt()

    assert "Never conclude the sample is benign" in prompt


def test_prompt_treats_a_bare_corexemain_import_table_as_a_finding() -> None:
    """A tiny native surface is a real, reportable fact about where the sample's
    resistance lives -- not an empty result to pad out."""
    prompt = _prompt()

    assert "_CorExeMain" in prompt
    assert "A small native surface is not" in prompt


def test_prompt_bounds_the_sweep() -> None:
    """A fallback stage running after an expensive one is exactly where an
    unbounded sweep ends a run with no report at all."""
    prompt = _prompt()

    assert "at most 5" in prompt.lower()
    assert "15 findings" in prompt


def test_prompt_forbids_restating_managed_evidence() -> None:
    assert "Never restate managed evidence" in _prompt()


# --- the managed prompt must distinguish its own failure modes ----------------


def _managed_prompt() -> str:
    return load_domain_prompt("dotnet_decompile")


def test_managed_prompt_checks_for_its_tools_before_anything_else() -> None:
    """When the ILSpy MCP server is unreachable its tools are silently absent and
    nothing tells the agent why. The live log shows this firing repeatedly:
    `Optional MCP server unavailable descriptor_id=ilspy_mcp`."""
    prompt = _managed_prompt()

    assert "FIRST — do you actually have ILSpy tools?" in prompt
    assert prompt.index("do you actually have ILSpy tools") < prompt.index(
        "A failed ILSpy call has two very different meanings"
    )


def test_managed_prompt_forbids_inferring_anything_without_tools() -> None:
    prompt = _managed_prompt()

    assert "You have not looked at it." in prompt
    assert "Do not describe the assembly." in prompt


def test_managed_prompt_tells_the_agent_a_native_stage_follows() -> None:
    """The distinction it draws is load-bearing downstream: 'I saw nothing' and
    'I looked and found nothing' route differently."""
    prompt = _managed_prompt()

    assert "reads the same file natively" in prompt
    assert "Those are different facts" in prompt


def test_managed_prompt_still_treats_a_load_error_as_a_finding() -> None:
    """The regression guard: a protected assembly that ILSpy answered about is
    evidence, and must not be turned into an outage by the new branch above."""
    prompt = _managed_prompt()

    assert "This is a FINDING, not an outage" in prompt
    assert "deep:assembly_load_failed" in prompt
