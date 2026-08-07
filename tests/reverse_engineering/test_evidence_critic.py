"""The evidence_critic descriptor, judgment schema, deterministic carry-forward, and prompt."""

from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from reverse_engineering.agents.evidence_critic import EVIDENCE_CRITIC_DESCRIPTOR
from reverse_engineering.agents.evidence_output import (
    CRITIC_STAGE_KEYS,
    EXECUTION_FLOW_MERMAID_KEY,
    SAMPLE_VERDICT_KEY,
    SAMPLE_VERDICT_RATIONALE_KEY,
    UPSTREAM_EVIDENCE_KEYS,
    VALIDATED_EVIDENCE_KEY,
    normalize_critic_output,
)
from reverse_engineering.evidence_envelope import (
    CriticEnvelope,
    parse_critic_envelope,
    parse_critic_judgment,
)
from reverse_engineering.prompts.loader import load_domain_prompt
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY

ARTIFACT = "a" * 64
PRIOR_ARTIFACT = "b" * 64  # pre-recovery artifact triage legitimately binds to
_STAGE_KEY = dict(CRITIC_STAGE_KEYS)


def _finding(
    kind: str,
    tool: str,
    *,
    claim: str = "claim",
    detail: str = "detail",
    confidence: float = 0.9,
    artifact_id: str = ARTIFACT,
) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "claim": claim,
        "tool": tool,
        "confidence": confidence,
        "detail": detail,
        "kind": kind,
    }


def _env(
    *findings: dict[str, object],
    status: str = "complete",
    surfaces: list[str] | None = None,
    limitations: list[str] | None = None,
    artifact_id: str = ARTIFACT,
) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "coverage": {
            "status": status,
            "surfaces": surfaces or [],
            "limitations": limitations or [],
        },
        "findings": list(findings),
    }


def _judgment(
    rejected: list[dict[str, object]] | None = None,
    qualified: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {"artifact_id": ARTIFACT, "rejected": rejected or [], "qualified": qualified or []}


def _full_state(judgment: object) -> dict[str, object]:
    """A complete set of upstream envelopes with a mix of findings, plus a judgment."""
    return {
        CURRENT_ARTIFACT_KEY: ARTIFACT,
        _STAGE_KEY["triage"]: _env(_finding("metadata", "show_info")),
        _STAGE_KEY["recovery"]: _env(),
        _STAGE_KEY["deep"]: _env(_finding("behavior", "ghidra_decompile")),
        _STAGE_KEY["host"]: _env(_finding("host_ioc", "ghidra_imports")),
        _STAGE_KEY["network"]: _env(
            _finding("network_ioc", "floss_decode", detail="https://c2.example.test"),
            _finding("network_ioc", "floss_decode", detail="winhttp.dll"),
        ),
        _STAGE_KEY["behavior"]: _env(_finding("behavior", "ghidra_search_decompiled")),
        _STAGE_KEY["attack"]: _env(_finding("attack", "ghidra_decompile")),
        _STAGE_KEY["native"]: _env(),
        VALIDATED_EVIDENCE_KEY: judgment,
    }


def _validated(state: dict[str, object]) -> CriticEnvelope:
    return CriticEnvelope.model_validate(state[VALIDATED_EVIDENCE_KEY])


# --- native evidence stage ----------------------------------------------------


def test_critic_unions_native_evidence_stage() -> None:
    assert ("native", "native_evidence_json") in CRITIC_STAGE_KEYS
    assert "native_evidence_json" in UPSTREAM_EVIDENCE_KEYS


def test_native_evidence_finding_lands_in_accepted() -> None:
    state = _full_state(_judgment())
    state[_STAGE_KEY["native"]] = _env(
        _finding("behavior", "ghidra_decompile", claim="JNI_OnLoad hooks strings")
    )

    normalize_critic_output(SimpleNamespace(state=state))

    validated = _validated(state)
    assert any(f.claim == "JNI_OnLoad hooks strings" for f in validated.accepted)


def test_absent_native_stage_is_not_flagged_invalid() -> None:
    """A native/.NET sample never runs the Android ``.so`` fan-out, so
    ``native_evidence_json`` is simply absent. An absent stage never ran -- it is
    not a malformed envelope, so the critic must neither add
    ``critic:native_evidence_json:invalid`` nor downgrade coverage on its account.
    """
    state = _full_state(_judgment())
    del state[_STAGE_KEY["native"]]  # native/.NET: the .so fan-out did not run

    normalize_critic_output(SimpleNamespace(state=state))

    validated = _validated(state)
    assert "critic:native_evidence_json:invalid" not in validated.coverage.limitations
    assert validated.coverage.status == "complete"  # absent stage did not fail the pass
    assert len(validated.accepted) == 7  # every real finding still carried forward


def test_absent_stage_does_not_mask_a_genuinely_malformed_one() -> None:
    """Skipping *absent* stages must not weaken the fail-closed guarantee for a
    *present but malformed* one: a native sample (native absent) whose host stage
    is malformed still surfaces ``critic:host_ioc_evidence_json:invalid``."""
    state = _full_state(_judgment())
    del state[_STAGE_KEY["native"]]
    state[_STAGE_KEY["host"]] = {  # present but missing artifact_id -> malformed
        "coverage": {"status": "complete", "surfaces": [], "limitations": []},
        "findings": [],
    }

    normalize_critic_output(SimpleNamespace(state=state))

    validated = _validated(state)
    assert "critic:native_evidence_json:invalid" not in validated.coverage.limitations
    assert "critic:host_ioc_evidence_json:invalid" in validated.coverage.limitations


# --- descriptor ---------------------------------------------------------------


def test_evidence_critic_descriptor_well_formed() -> None:
    assert EVIDENCE_CRITIC_DESCRIPTOR.id == "evidence_critic"
    assert EVIDENCE_CRITIC_DESCRIPTOR.runtime_profile_id == "evidence_isolated"
    assert EVIDENCE_CRITIC_DESCRIPTOR.output_key == VALIDATED_EVIDENCE_KEY
    assert len(EVIDENCE_CRITIC_DESCRIPTOR.after_agent_callbacks) == 1
    assert EVIDENCE_CRITIC_DESCRIPTOR.tool_ids == ()


def test_evidence_critic_carries_no_output_schema() -> None:
    """The provider fences its JSON even under ``response_mime_type``
    ``application/json``; ADK's ``model_validate_json`` cannot see through a fence
    and the judgment was silently dropped. ``normalize_critic_output`` parses it
    through ``loads_model_json`` instead, which handles fences."""
    assert EVIDENCE_CRITIC_DESCRIPTOR.output_schema is None


# --- judgment schema ----------------------------------------------------------


def test_parse_critic_judgment_binds_artifact() -> None:
    judgment = parse_critic_judgment(
        _judgment(rejected=[{"source_stage": "host", "source_index": 0, "reason": "x"}]),
        artifact_id=ARTIFACT,
    )
    assert judgment.rejected[0].source_stage == "host"

    with pytest.raises(ValueError):
        parse_critic_judgment({**_judgment(), "artifact_id": "b" * 64}, artifact_id=ARTIFACT)


# --- deterministic carry-forward (the regression the funnel bug needs) --------


def test_all_upstream_findings_survive_without_a_judgment() -> None:
    state = _full_state(_judgment())

    normalize_critic_output(SimpleNamespace(state=state))

    validated = _validated(state)
    # 1 triage + 0 recovery + 1 deep + 1 host + 2 network + 1 behavior + 1 attack = 7
    assert len(validated.accepted) == 7
    assert sum(f.kind == "network_ioc" for f in validated.accepted) == 2  # IOCs did NOT vanish
    assert validated.coverage.status == "complete"


def test_rejected_finding_is_dropped_and_others_survive() -> None:
    state = _full_state(
        _judgment(rejected=[{"source_stage": "network", "source_index": 0, "reason": "invented"}])
    )

    normalize_critic_output(SimpleNamespace(state=state))

    validated = _validated(state)
    assert len(validated.accepted) == 6
    assert sum(f.kind == "network_ioc" for f in validated.accepted) == 1
    assert validated.rejected[0].source_stage == "network"


def test_qualified_finding_is_kept_downgraded_not_dropped() -> None:
    state = _full_state(
        _judgment(
            qualified=[{"source_stage": "behavior", "source_index": 0, "reason": "primitive"}]
        )
    )

    normalize_critic_output(SimpleNamespace(state=state))

    validated = _validated(state)
    assert len(validated.accepted) == 6
    assert len(validated.qualified) == 1
    assert validated.qualified[0].confidence <= 0.5
    assert "qualified: primitive" in validated.qualified[0].detail


def test_invalid_judgment_still_accepts_all_findings() -> None:
    state = _full_state("not json at all")

    normalize_critic_output(SimpleNamespace(state=state))

    validated = _validated(state)
    assert len(validated.accepted) == 7  # a broken judgment never drops evidence


def test_identical_findings_across_stages_are_deduplicated() -> None:
    """A fact emitted identically by several stages is carried once, not padded.

    The same claim tagged with a different ``kind`` is a distinct categorization
    the report needs (IOC table vs limitations), so it survives -- only fully
    identical findings collapse.
    """
    packed_limitation = _finding(
        "limitation", "analyze_assembly", claim="assembly is packed", detail="load failed"
    )
    packed_ioc = _finding(
        "host_ioc", "analyze_assembly", claim="assembly is packed", detail="load failed"
    )
    state = {
        CURRENT_ARTIFACT_KEY: ARTIFACT,
        _STAGE_KEY["triage"]: _env(_finding("metadata", "show_info", claim="dotnet")),
        _STAGE_KEY["recovery"]: _env(),
        _STAGE_KEY["deep"]: _env(dict(packed_limitation)),
        _STAGE_KEY["host"]: _env(dict(packed_ioc)),
        _STAGE_KEY["network"]: _env(),
        _STAGE_KEY["behavior"]: _env(dict(packed_limitation)),  # identical to deep's
        _STAGE_KEY["attack"]: _env(),
        _STAGE_KEY["native"]: _env(),
        VALIDATED_EVIDENCE_KEY: _judgment(),
    }

    normalize_critic_output(SimpleNamespace(state=state))

    accepted = _validated(state).accepted
    limits = [f for f in accepted if f.kind == "limitation" and f.claim == "assembly is packed"]
    iocs = [f for f in accepted if f.kind == "host_ioc" and f.claim == "assembly is packed"]
    assert len(limits) == 1  # deep + behavior emitted the identical limitation -> kept once
    assert len(iocs) == 1  # same claim, different kind -> a distinct categorization, kept
    assert any(f.claim == "dotnet" for f in accepted)
    assert len(accepted) == 3  # dotnet + one limitation + one host_ioc


def test_prior_artifact_triage_evidence_is_rebound_not_rejected() -> None:
    """``triage_evidence_json`` is legitimately bound to the pre-recovery artifact,
    not the current (possibly recovered) one. The critic aggregation must rebind
    it to the current artifact rather than discard it as
    ``critic:triage_evidence_json:invalid``.
    """
    state = _full_state(_judgment())
    state[_STAGE_KEY["triage"]] = _env(
        _finding("metadata", "show_info", claim="original packer id", artifact_id=PRIOR_ARTIFACT),
        artifact_id=PRIOR_ARTIFACT,
    )

    normalize_critic_output(SimpleNamespace(state=state))

    validated = _validated(state)
    assert "critic:triage_evidence_json:invalid" not in validated.coverage.limitations
    triage_findings = [f for f in validated.accepted if f.claim == "original packer id"]
    assert len(triage_findings) == 1
    assert triage_findings[0].artifact_id == ARTIFACT  # re-anchored to the current artifact


def test_malformed_upstream_envelope_still_fails_closed() -> None:
    """A genuinely malformed envelope -- no ``artifact_id`` to even attempt
    rebinding against -- must still fail closed to ``critic:{key}:invalid``.
    Rebinding only ever rescues a *valid* envelope bound to a prior artifact.
    """
    state = _full_state(_judgment())
    state[_STAGE_KEY["host"]] = {
        "coverage": {"status": "complete", "surfaces": [], "limitations": []},
        "findings": [],
    }

    normalize_critic_output(SimpleNamespace(state=state))

    validated = _validated(state)
    assert "critic:host_ioc_evidence_json:invalid" in validated.coverage.limitations


def test_upstream_limitations_are_retained_and_lower_coverage() -> None:
    state = _full_state(_judgment())
    state[_STAGE_KEY["deep"]] = _env(
        _finding("behavior", "ghidra_decompile"),
        status="partial",
        limitations=["deep:analysis_incomplete"],
    )

    normalize_critic_output(SimpleNamespace(state=state))

    validated = _validated(state)
    assert "deep:analysis_incomplete" in validated.coverage.limitations
    assert validated.coverage.status == "partial"
    assert validated.accepted  # findings still carried


# --- stored-envelope parser (still validates the report's input shape) --------


def test_parse_critic_envelope_rejects_cross_artifact_finding() -> None:
    payload = {
        "artifact_id": ARTIFACT,
        "coverage": {"status": "complete", "surfaces": [], "limitations": []},
        "accepted": [{**_finding("behavior", "ghidra_decompile"), "artifact_id": "b" * 64}],
        "qualified": [],
        "rejected": [],
    }
    with pytest.raises(ValueError):
        parse_critic_envelope(payload, artifact_id=ARTIFACT)


# --- prompt contract ----------------------------------------------------------


def test_evidence_critic_prompt_loads() -> None:
    text = load_domain_prompt("evidence_critic")
    assert "evidence_critic" in text
    assert "Reject" in text


def test_critic_names_every_upstream_envelope() -> None:
    text = load_domain_prompt("evidence_critic")
    for alias in (
        "{triage_evidence_json?}",
        "{recovery_summary_json?}",
        "{recovery_evidence_json?}",
        "{deep_evidence_json?}",
        "{host_ioc_evidence_json?}",
        "{network_ioc_evidence_json?}",
        "{behavior_evidence_json?}",
        "{attack_evidence_json?}",
    ):
        assert alias in text


# --- the execution diagram is filtered by surviving evidence -------------------

_FLOW = {
    "nodes": [
        {"id": "entry", "label": "Entry stub", "tool": "ghidra_search_decompiled"},
        {"id": "c2", "label": "Beacon to the C2 host", "tool": "floss_decode"},
        {"id": "ghost", "label": "Step nobody evidenced", "tool": "ida_pro"},
    ],
    "edges": [
        {"src": "entry", "dst": "c2", "label": "after unpack"},
        {"src": "c2", "dst": "ghost"},
    ],
}


def _rendered(state: dict[str, object]) -> str:
    normalize_critic_output(SimpleNamespace(state=state))
    mermaid = state[EXECUTION_FLOW_MERMAID_KEY]
    assert isinstance(mermaid, str)
    return mermaid


def test_the_diagram_renders_from_the_behavior_stage_flow() -> None:
    state = _full_state(_judgment())
    state[_STAGE_KEY["behavior"]] = {
        **_env(_finding("behavior", "ghidra_search_decompiled")),
        "flow": _FLOW,
    }

    mermaid = _rendered(state)

    assert mermaid.startswith("```mermaid\nflowchart TD\n")
    assert '    n0["Entry stub (ghidra_search_decompiled)"]' in mermaid


def test_a_step_whose_tool_has_no_surviving_finding_is_not_drawn() -> None:
    """``ida_pro`` is cited by no accepted finding, so its step never appears --
    the diagram cannot introduce evidence the report does not carry."""
    state = _full_state(_judgment())
    state[_STAGE_KEY["behavior"]] = {
        **_env(_finding("behavior", "ghidra_search_decompiled")),
        "flow": _FLOW,
    }

    mermaid = _rendered(state)

    assert "Step nobody evidenced" not in mermaid
    assert "ida_pro" not in mermaid
    assert mermaid.count("-->") == 1  # the edge into the dropped step went with it


def test_a_rejected_finding_takes_its_step_out_of_the_diagram() -> None:
    """Rejecting the only ``floss_decode`` findings must remove the C2 step."""
    network_key = _STAGE_KEY["network"]
    state = _full_state(
        _judgment(
            rejected=[
                {"source_stage": "network", "source_index": 0, "reason": "unsupported"},
                {"source_stage": "network", "source_index": 1, "reason": "unsupported"},
            ]
        )
    )
    state[_STAGE_KEY["behavior"]] = {
        **_env(_finding("behavior", "ghidra_search_decompiled")),
        "flow": _FLOW,
    }
    assert network_key in state

    mermaid = _rendered(state)

    assert "Beacon to the C2 host" not in mermaid
    assert "Entry stub" in mermaid


def test_a_qualified_finding_keeps_its_step() -> None:
    """Qualified evidence is kept, downgraded -- so its step stays drawn."""
    state = _full_state(
        _judgment(qualified=[{"source_stage": "network", "source_index": 0, "reason": "thin"}])
    )
    state[_STAGE_KEY["behavior"]] = {
        **_env(_finding("behavior", "ghidra_search_decompiled")),
        "flow": _FLOW,
    }

    assert "Beacon to the C2 host" in _rendered(state)


def test_no_declared_flow_leaves_the_key_empty_rather_than_absent() -> None:
    """The report omits the section on an empty string; an absent key would leave
    the placeholder unresolved."""
    assert _rendered(_full_state(_judgment())) == ""


def test_a_flow_declared_by_any_other_stage_is_ignored() -> None:
    """One author keeps the diagram a summary rather than a merge of partial
    views that no stage ever asserted together."""
    state = _full_state(_judgment())
    state[_STAGE_KEY["deep"]] = {
        **_env(_finding("behavior", "ghidra_decompile")),
        "flow": _FLOW,
    }

    assert _rendered(state) == ""


def test_a_stale_diagram_from_a_previous_sample_is_cleared() -> None:
    state = _full_state(_judgment())
    state[EXECUTION_FLOW_MERMAID_KEY] = '```mermaid\nflowchart TD\n    n0["stale"]\n```'

    assert _rendered(state) == ""


def test_a_malformed_flow_never_costs_the_behavior_stage_its_findings() -> None:
    state = _full_state(_judgment())
    state[_STAGE_KEY["behavior"]] = {
        **_env(_finding("behavior", "ghidra_search_decompiled", claim="real behavior")),
        "flow": {"nodes": "not a list"},
    }

    mermaid = _rendered(state)
    validated = _validated(state)

    assert mermaid == ""
    assert any(finding.claim == "real behavior" for finding in validated.accepted)


# --- the verdict is carried from behavior, or defaults to UNDETERMINED --------

_VERDICT = {"classification": "benign", "rationale": "Stock coreutils ls; no dangerous sinks."}


def _decided(state: dict[str, object]) -> tuple[str, str]:
    normalize_critic_output(SimpleNamespace(state=state))
    label, rationale = state[SAMPLE_VERDICT_KEY], state[SAMPLE_VERDICT_RATIONALE_KEY]
    assert isinstance(label, str) and isinstance(rationale, str)
    return label, rationale


def test_the_behavior_stage_verdict_reaches_the_report() -> None:
    state = _full_state(_judgment())
    state[_STAGE_KEY["behavior"]] = {
        **_env(_finding("behavior", "ghidra_search_decompiled")),
        "verdict": _VERDICT,
    }

    assert _decided(state) == ("BENIGN", "Stock coreutils ls; no dangerous sinks.")


def test_no_declared_verdict_reads_undetermined_not_benign() -> None:
    """Silence must never be rendered as safety."""
    assert _decided(_full_state(_judgment())) == ("UNDETERMINED", "")


def test_a_verdict_from_any_other_stage_is_ignored() -> None:
    state = _full_state(_judgment())
    state[_STAGE_KEY["deep"]] = {
        **_env(_finding("behavior", "ghidra_decompile")),
        "verdict": {"classification": "malicious", "rationale": "not behavior's call"},
    }

    assert _decided(state) == ("UNDETERMINED", "")


def test_a_verdict_with_no_surviving_evidence_is_downgraded() -> None:
    """A disposition nobody can check is not a disposition. Rejecting every
    finding must take the verdict with it."""
    rejections = [
        {"source_stage": stage, "source_index": 0, "reason": "unsupported"}
        for stage in ("triage", "deep", "host", "network", "behavior", "attack")
    ] + [{"source_stage": "network", "source_index": 1, "reason": "unsupported"}]
    state = _full_state(_judgment(rejected=rejections))
    state[_STAGE_KEY["behavior"]] = {
        **_env(_finding("behavior", "ghidra_search_decompiled")),
        "verdict": _VERDICT,
    }

    label, rationale = _decided(state)

    assert label == "UNDETERMINED"
    assert rationale == ""
    assert _validated(state).accepted == ()  # nothing survived, so nothing to judge


@pytest.mark.parametrize(
    "verdict", [None, "benign", {"classification": "clean", "rationale": "x"}, {}]
)
def test_a_malformed_verdict_reads_undetermined_and_keeps_the_findings(verdict: object) -> None:
    state = _full_state(_judgment())
    state[_STAGE_KEY["behavior"]] = {
        **_env(_finding("behavior", "ghidra_search_decompiled", claim="real behavior")),
        "verdict": verdict,
    }

    assert _decided(state) == ("UNDETERMINED", "")
    validated = _validated(state)
    assert any(f.claim == "real behavior" for f in validated.accepted)


def test_a_stale_verdict_from_a_previous_sample_is_cleared() -> None:
    state = _full_state(_judgment())
    state[SAMPLE_VERDICT_KEY] = "MALICIOUS"
    state[SAMPLE_VERDICT_RATIONALE_KEY] = "left over from another run"

    assert _decided(state) == ("UNDETERMINED", "")


# --- third-party evidence must not wear a first-party citation ----------------
#
# Measured on a live QuasarRAT run. The critic accepted all 88 findings, and
# three of them laundered a VirusTotal association into a first-party
# observation: a `network_ioc` naming a C2 host, and an `attack` mapping T1071
# Command and Control, both citing `search_strings` -- a tool whose own detail
# recorded "0 total matches". Both reached the report, the ATT&CK row beside
# five techniques that were genuinely derived from code.


def _critic_prompt() -> str:
    return load_domain_prompt("evidence_critic")


def test_the_intel_qualify_rule_covers_any_third_party_value() -> None:
    """It named only a family name, and the model read that literally: a
    third-party URL carried into a claim about the code is the same violation."""
    prompt = _critic_prompt()

    assert "carries **any** third-party value" in prompt
    assert "a URL, a domain, an IP, a dropped-file hash" in prompt


def test_the_critic_catches_intel_wearing_a_first_party_citation() -> None:
    """The reverse direction, and the dangerous one: rule 4 governs findings
    already marked `intel`, so nothing governed a `network_ioc` whose evidence
    was really VirusTotal's."""
    prompt = _critic_prompt()

    assert "Third-party evidence wearing a first-party citation" in prompt
    assert "launders an association into an observation" in prompt


def test_the_critic_is_told_the_tell_for_laundered_intel() -> None:
    """A rule the model cannot operationalize is decoration. This one names the
    exact signature: a reputation service in the detail, a binary reader in the
    tool field."""
    prompt = _critic_prompt()

    assert "per VirusTotal intel" in prompt
    assert "A tool that reads the binary cannot have produced a fact about" in prompt


def test_a_negative_result_cannot_support_a_positive_claim() -> None:
    prompt = _critic_prompt()

    assert "A negative result cannot support a positive claim" in prompt
    assert "`0 matches`" in prompt


def test_a_technique_mapping_on_a_negative_result_is_rejected_not_qualified() -> None:
    """A mapping asserts the sample does something. "The tool found nothing" is
    not weak evidence for that -- it is evidence of the opposite."""
    prompt = _critic_prompt()

    assert "Reject** a technique mapping (`kind` `attack`) built on a negative result" in prompt


def test_a_claim_purely_about_absence_is_still_accepted() -> None:
    """The guard must not swallow the legitimate case. "No cleartext URL
    literals exist" is exactly what a 0-match search proves."""
    prompt = _critic_prompt()

    assert "unless the claim is purely about the absence itself" in prompt
    assert "must be accepted" in prompt


def test_self_admitted_inference_is_treated_as_inference() -> None:
    """The live finding said "so the C2 channel is inferred" and was accepted at
    full strength anyway."""
    assert "has told you it is an inference" in _critic_prompt()


def test_the_rules_are_numbered_uniquely() -> None:
    """Two rules sharing a number gives the model two things to call rule 5."""
    numbers = re.findall(r"^(\d+)\. \*\*", _critic_prompt(), re.M)

    assert numbers == sorted(numbers, key=int)
    assert len(numbers) == len(set(numbers))
