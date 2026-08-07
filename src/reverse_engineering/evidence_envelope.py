"""Strict, bounded evidence envelopes exchanged through ADK session state."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictInt,
    StrictStr,
    model_validator,
)

from reverse_engineering.execution_flow import ExecutionFlow, sanitize_execution_flow
from reverse_engineering.model_json import loads_model_json
from reverse_engineering.verdict import SampleVerdict, sanitize_verdict

MAX_FINDINGS = 200
MAX_SURFACES = 64
MAX_LIMITATIONS = 64
MAX_CLAIM_CHARS = 1_000
MAX_DETAIL_CHARS = 8_000
MAX_SURFACE_CHARS = 128
MAX_LIMITATION_CHARS = 500
MAX_TOOL_CHARS = 128

# ``ensure_ascii=True`` encodes an astral code point as two six-character
# surrogate escapes (``\ud800\udc00``), the maximum JSON expansion of any
# bounded string code point.
MAX_JSON_CHARS_PER_CODEPOINT = 12
MAX_EVIDENCE_STRING_CODEPOINTS = (
    64  # envelope artifact id
    + len("complete")  # longest coverage status
    + MAX_SURFACES * MAX_SURFACE_CHARS
    + MAX_LIMITATIONS * MAX_LIMITATION_CHARS
    + MAX_FINDINGS
    * (
        64  # finding artifact id
        + MAX_CLAIM_CHARS
        + MAX_TOOL_CHARS
        + MAX_DETAIL_CHARS
        + len("network_ioc")  # longest finding kind
    )
)

_EMPTY_ENVELOPE_JSON_CHARS = len(
    json.dumps(
        {
            "artifact_id": "",
            "coverage": {"status": "", "surfaces": [], "limitations": []},
            "findings": [],
        }
    )
)
_EMPTY_FINDING_JSON_CHARS = len(
    json.dumps(
        {
            "artifact_id": "",
            "claim": "",
            "tool": "",
            "confidence": 0.0,
            "detail": "",
            "kind": "",
        }
    )
)
_JSON_EMPTY_STRING_CHARS = len(json.dumps(""))
_JSON_ARRAY_SEPARATOR_CHARS = len(", ")
_JSON_ZERO_FLOAT_CHARS = len(json.dumps(0.0))
_MAX_JSON_FLOAT_CHARS = 24
MAX_ENVELOPE_JSON_STRUCTURE_CHARS = (
    _EMPTY_ENVELOPE_JSON_CHARS
    + MAX_SURFACES * _JSON_EMPTY_STRING_CHARS
    + (MAX_SURFACES - 1) * _JSON_ARRAY_SEPARATOR_CHARS
    + MAX_LIMITATIONS * _JSON_EMPTY_STRING_CHARS
    + (MAX_LIMITATIONS - 1) * _JSON_ARRAY_SEPARATOR_CHARS
    + MAX_FINDINGS * (_EMPTY_FINDING_JSON_CHARS - _JSON_ZERO_FLOAT_CHARS + _MAX_JSON_FLOAT_CHARS)
    + (MAX_FINDINGS - 1) * _JSON_ARRAY_SEPARATOR_CHARS
)
MAX_RAW_EVIDENCE_JSON_CHARS = (
    MAX_EVIDENCE_STRING_CODEPOINTS * MAX_JSON_CHARS_PER_CODEPOINT
    + MAX_ENVELOPE_JSON_STRUCTURE_CHARS
)

_ARTIFACT_ID_PATTERN = re.compile(r"[0-9a-f]{64}")

_SurfaceName = Annotated[StrictStr, Field(min_length=1, max_length=MAX_SURFACE_CHARS)]
_Limitation = Annotated[StrictStr, Field(min_length=1, max_length=MAX_LIMITATION_CHARS)]


class CoverageStatus(StrEnum):
    """The extent to which an analysis stage covered its intended surfaces."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class FindingKind(StrEnum):
    """The constrained taxonomy for artifact-bound analysis claims.

    ``INTEL`` is the one member that does not describe the artifact. Every other
    kind labels something a tool observed in the sample's own bytes; an intel
    finding records what a third party already had on file about the digest,
    which is the only way to reach a malware family name or a known-distribution
    match that static analysis cannot derive from one file.

    The distinction is structural rather than a convention about wording,
    because three downstream rules depend on it: the critic must not demand a
    source-to-sink path from a claim that never had one, the report keeps
    third-party attestation in its own section, and the stage that decides the
    verdict may weigh intel while being forbidden to restate it as a fact about
    the code.
    """

    METADATA = "metadata"
    HOST_IOC = "host_ioc"
    NETWORK_IOC = "network_ioc"
    BEHAVIOR = "behavior"
    ATTACK = "attack"
    LIMITATION = "limitation"
    INTEL = "intel"


class EvidenceCoverage(BaseModel):
    """Bounded coverage statement emitted by a single analysis stage."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    status: CoverageStatus
    surfaces: tuple[_SurfaceName, ...] = Field(max_length=MAX_SURFACES)
    limitations: tuple[_Limitation, ...] = Field(max_length=MAX_LIMITATIONS)


class EvidenceFinding(BaseModel):
    """A bounded claim supported by one tool about one canonical artifact."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    artifact_id: Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
    claim: Annotated[StrictStr, Field(min_length=1, max_length=MAX_CLAIM_CHARS)]
    tool: Annotated[StrictStr, Field(min_length=1, max_length=MAX_TOOL_CHARS)]
    confidence: Annotated[StrictFloat, Field(ge=0.0, le=1.0)]
    detail: Annotated[StrictStr, Field(max_length=MAX_DETAIL_CHARS)]
    kind: FindingKind


class EvidenceEnvelope(BaseModel):
    """The only evidence bus payload persisted between analysis stages."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    artifact_id: Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
    coverage: EvidenceCoverage
    findings: tuple[EvidenceFinding, ...] = Field(max_length=MAX_FINDINGS)
    # Optional and never load-bearing. A stage has exactly one output_key, so the
    # execution diagram has to ride in the same object as the findings -- but it
    # is popped and sanitized before strict validation (see `_split_judgements`), so a
    # malformed diagram can never cost the stage its evidence.
    flow: ExecutionFlow | None = None
    # The sample's disposition. Optional and popped before strict validation for
    # the same reason as `flow`: a judgement the model got wrong in *shape* must
    # not cost the stage the evidence it got right.
    verdict: SampleVerdict | None = None

    @model_validator(mode="after")
    def _findings_match_envelope_artifact(self) -> EvidenceEnvelope:
        if any(finding.artifact_id != self.artifact_id for finding in self.findings):
            raise ValueError("finding artifact_id must match envelope artifact_id")
        return self


# --- Wire schemas -------------------------------------------------------------
# Given to an LlmAgent as ``output_schema`` so ADK/LiteLLM coerce the model into
# emitting schema-valid structured output (a set_model_response function call for
# tool-using agents, native JSON mode otherwise) -- never free-form text that can
# be fenced or truncated. Deliberately lenient (plain str/float, extra ignored,
# no cross-field validator) so the provider-generated JSON always validates here;
# the strict EvidenceEnvelope above is then reconstructed, fail-open, by the
# after-agent normalizer, which is where bounds and artifact authority are
# enforced.


class _FindingInput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    artifact_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    claim: str = Field(max_length=MAX_CLAIM_CHARS)
    tool: str = Field(max_length=MAX_TOOL_CHARS)
    confidence: float = Field(ge=0.0, le=1.0)
    detail: str = Field(default="", max_length=MAX_DETAIL_CHARS)
    kind: FindingKind


class _CoverageInput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: CoverageStatus
    surfaces: list[str] = Field(default_factory=list, max_length=MAX_SURFACES)
    limitations: list[str] = Field(default_factory=list, max_length=MAX_LIMITATIONS)


class EvidenceEnvelopeInput(BaseModel):
    """Coercion-friendly wire form of :class:`EvidenceEnvelope` for output_schema."""

    model_config = ConfigDict(extra="ignore")

    artifact_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    coverage: _CoverageInput
    findings: list[_FindingInput] = Field(default_factory=list, max_length=MAX_FINDINGS)


class RejectedFinding(BaseModel):
    """A critic-rejected upstream finding, cited by stage and zero-based index."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    source_stage: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    source_index: Annotated[StrictInt, Field(ge=0, le=MAX_FINDINGS - 1)]
    reason: Annotated[StrictStr, Field(min_length=1, max_length=MAX_LIMITATION_CHARS)]


class QualifiedFinding(BaseModel):
    """A critic-qualified upstream finding, cited by stage and zero-based index."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    source_stage: Annotated[StrictStr, Field(min_length=1, max_length=64)]
    source_index: Annotated[StrictInt, Field(ge=0, le=MAX_FINDINGS - 1)]
    reason: Annotated[StrictStr, Field(min_length=1, max_length=MAX_LIMITATION_CHARS)]


class CriticJudgment(BaseModel):
    """The critic model's judgment over upstream findings.

    The critic never re-transcribes findings (an LLM asked to re-emit dozens of
    findings silently drops most of them). It only names the ones to *reject* or
    *qualify* by ``(source_stage, source_index)``. Every other upstream finding
    is carried forward verbatim by ``normalize_critic_output``. ``extra='ignore'``
    tolerates a model that redundantly echoes coverage/accepted so a stray field
    never collapses the judgment (which would over-accept, never drop evidence).
    """

    model_config = ConfigDict(frozen=True, extra="ignore", revalidate_instances="always")

    artifact_id: Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
    rejected: tuple[RejectedFinding, ...] = Field(default=(), max_length=MAX_FINDINGS)
    qualified: tuple[QualifiedFinding, ...] = Field(default=(), max_length=MAX_FINDINGS)


class CriticEnvelope(BaseModel):
    """The validated evidence the critic passes to the report generator."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    artifact_id: Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{64}$")]
    coverage: EvidenceCoverage
    accepted: tuple[EvidenceFinding, ...] = Field(max_length=MAX_FINDINGS)
    qualified: tuple[EvidenceFinding, ...] = Field(max_length=MAX_FINDINGS)
    rejected: tuple[RejectedFinding, ...] = Field(max_length=MAX_FINDINGS)

    @model_validator(mode="after")
    def _critic_findings_match_artifact(self) -> CriticEnvelope:
        if any(
            finding.artifact_id != self.artifact_id for finding in (*self.accepted, *self.qualified)
        ):
            raise ValueError("critic finding artifact_id must match envelope artifact_id")
        return self


# The critic carries accepted + qualified evidence plus bounded rejections, so
# its raw JSON can be several times an evidence envelope's; bound generously.
MAX_RAW_CRITIC_JSON_CHARS = MAX_RAW_EVIDENCE_JSON_CHARS * 3


def _require_canonical_artifact(artifact_id: str) -> None:
    if _ARTIFACT_ID_PATTERN.fullmatch(artifact_id) is None:
        raise ValueError("artifact_id must be a lowercase SHA-256")


def _sole_object_with(data: object, *keys: str) -> object:
    """Pick the one object carrying every ``keys`` entry when decoding gave a list.

    A model turn does not always contain exactly one JSON value. When the final
    text holds the envelope plus anything else -- a second object, a stray array,
    a repeated emission -- ``json_repair`` recovers them all and returns a *list*,
    and validating a list against an object model fails at the root. Measured
    across live runs, that discarded whole stages' findings (``payload_type=list``,
    ``rejected_fields=[':model_type']``) while a perfectly good envelope sat in the
    list.

    Selection is by SHAPE, never by content or position, and it is deliberately
    all-or-nothing: zero candidates or more than one leaves the value untouched so
    validation rejects it. Guessing between two envelopes would be worse than
    failing, because the wrong pick is silently wrong evidence.
    """
    if not isinstance(data, list):
        return data
    candidates = [
        item for item in data if isinstance(item, Mapping) and all(key in item for key in keys)
    ]
    return candidates[0] if len(candidates) == 1 else data


_JUDGEMENT_KEYS = ("flow", "verdict")


def _split_judgements(raw: object) -> tuple[object, dict[str, object]]:
    """Take the optional diagram and verdict out before strict validation.

    ``extra='forbid'`` would otherwise make one bad node, or one unrecognized
    disposition, cost the stage every finding it produced -- the exact failure
    ``salvage_evidence_envelope`` exists to undo. Both sanitizers absorb their
    own defects rather than raising, so an unusable one simply is not there.
    """
    if not isinstance(raw, Mapping) or not any(key in raw for key in _JUDGEMENT_KEYS):
        return raw, {}
    remainder = {key: value for key, value in raw.items() if key not in _JUDGEMENT_KEYS}
    attached: dict[str, object] = {}
    if (flow := sanitize_execution_flow(raw.get("flow"))) is not None:
        attached["flow"] = flow
    if (verdict := sanitize_verdict(raw.get("verdict"))) is not None:
        attached["verdict"] = verdict
    return remainder, attached


def parse_evidence_envelope(raw: object, *, artifact_id: str) -> EvidenceEnvelope:
    """Parse strict model output and bind it to session artifact authority."""
    _require_canonical_artifact(artifact_id)
    raw = loads_model_json(raw, max_chars=MAX_RAW_EVIDENCE_JSON_CHARS)
    raw = _sole_object_with(raw, "coverage", "findings")
    raw, attached = _split_judgements(raw)
    envelope = EvidenceEnvelope.model_validate(raw)
    if envelope.artifact_id != artifact_id:
        raise ValueError("evidence envelope artifact_id does not match current artifact")
    return envelope.model_copy(update=attached) if attached else envelope


def _bounded_strings(values: object, *, max_chars: int, cap: int) -> tuple[str, ...]:
    """Keep only the entries that already satisfy the strict per-item bounds."""
    if not isinstance(values, list):
        return ()
    kept = [item for item in values if isinstance(item, str) and 1 <= len(item) <= max_chars]
    return tuple(kept[:cap])


def salvage_evidence_envelope(
    raw: object, *, artifact_id: str
) -> tuple[EvidenceEnvelope, int, bool]:
    """Recover the well-formed findings from a strictly-invalid envelope.

    ``EvidenceEnvelope`` is all-or-nothing by design: ``extra='forbid'``,
    ``StrictFloat``, a closed ``kind`` enum, and an exact artifact match. One
    malformed finding therefore costs an entire stage its evidence -- an omitted
    ``detail``, a stray key on any level, or a ``kind`` outside the enum is
    enough, and a live run lost every Ghidra finding that way. This is the
    fail-open reconstruction the strict model's own design note promises.

    Every step is a SUBTRACTION or a normalization -- a malformed finding is
    dropped, an unknown key ignored, a null ``detail`` read as omitted. Nothing
    is ever repaired into a claim the model did not make, and every survivor is
    re-validated against the strict model before it is returned.

    Returns ``(envelope, dropped, rebound)``. Raises ``ValueError`` when nothing
    survives, so the caller's failed-envelope path is unchanged; a legitimately
    empty envelope parses strictly and never reaches here.
    """
    _require_canonical_artifact(artifact_id)
    raw = loads_model_json(raw, max_chars=MAX_RAW_EVIDENCE_JSON_CHARS)
    raw = _sole_object_with(raw, "coverage", "findings")
    if not isinstance(raw, Mapping):
        raise ValueError("evidence envelope is not a JSON object")

    own_id = raw.get("artifact_id")
    anchor = (
        own_id
        if isinstance(own_id, str) and _ARTIFACT_ID_PATTERN.fullmatch(own_id) is not None
        else artifact_id
    )

    raw_findings = raw.get("findings")
    raw_findings = raw_findings if isinstance(raw_findings, list) else []
    dropped = max(0, len(raw_findings) - MAX_FINDINGS)
    findings: list[EvidenceFinding] = []
    for item in raw_findings[:MAX_FINDINGS]:
        try:
            # An explicit `"detail": null` means the same thing as omitting the
            # key, but only omission reaches the field default. Stripping nulls
            # makes the two spellings equivalent; a required field spelled null
            # still fails below, exactly as a missing one does.
            if isinstance(item, Mapping):
                item = {key: value for key, value in item.items() if value is not None}
            coerced = _FindingInput.model_validate(item)
            # A finding naming a different artifact than its own envelope is a
            # genuine inconsistency, not a formatting slip: drop it rather than
            # relabel it, which would silently reattribute someone else's bytes.
            if coerced.artifact_id != anchor:
                raise ValueError("finding artifact_id does not match the envelope anchor")
            findings.append(EvidenceFinding.model_validate(coerced.model_dump()))
        except (TypeError, ValueError):
            dropped += 1
    if not findings:
        raise ValueError("no findings could be salvaged from the evidence envelope")

    # Read the coverage block field by field rather than through _CoverageInput:
    # its `list[str]` rejects the whole block when a single entry is the wrong
    # type, which would silently discard the surfaces that were perfectly good.
    raw_coverage = raw.get("coverage")
    coverage: Mapping[str, object] = raw_coverage if isinstance(raw_coverage, Mapping) else {}
    raw_status = coverage.get("status")
    try:
        status = (
            CoverageStatus(raw_status) if isinstance(raw_status, str) else CoverageStatus.PARTIAL
        )
    except ValueError:
        status = CoverageStatus.PARTIAL
    surfaces = _bounded_strings(
        coverage.get("surfaces"), max_chars=MAX_SURFACE_CHARS, cap=MAX_SURFACES
    )
    limitations = _bounded_strings(
        coverage.get("limitations"), max_chars=MAX_LIMITATION_CHARS, cap=MAX_LIMITATIONS
    )
    if dropped and status is CoverageStatus.COMPLETE:
        status = CoverageStatus.PARTIAL

    envelope = EvidenceEnvelope(
        artifact_id=anchor,
        coverage=EvidenceCoverage(status=status, surfaces=surfaces, limitations=limitations),
        findings=tuple(findings),
        flow=sanitize_execution_flow(raw.get("flow")),
        verdict=sanitize_verdict(raw.get("verdict")),
    )
    return (
        rebind_evidence_envelope(envelope, artifact_id=artifact_id),
        dropped,
        anchor != artifact_id,
    )


def rebind_evidence_envelope(envelope: EvidenceEnvelope, *, artifact_id: str) -> EvidenceEnvelope:
    """Re-anchor an envelope (and every finding) to a new canonical artifact.

    A recovery loop treats the *current* artifact as the single evidence anchor and
    rebuilds each round's findings bound to it. When a recovering round advances the
    current artifact, the loop's own cumulative evidence from prior rounds is still
    bound to the pre-advance id; re-anchoring it to the new tip lets multi-layer
    recovery accumulate findings instead of fail-closing on the id mismatch. Only
    the anchor id changes -- each finding's claim/detail (which already name their
    own source and destination) is preserved verbatim.
    """
    _require_canonical_artifact(artifact_id)
    if envelope.artifact_id == artifact_id:
        return envelope
    return EvidenceEnvelope(
        artifact_id=artifact_id,
        coverage=envelope.coverage,
        findings=tuple(
            finding.model_copy(update={"artifact_id": artifact_id}) for finding in envelope.findings
        ),
        flow=envelope.flow,
        verdict=envelope.verdict,
    )


def failed_evidence_envelope(*, artifact_id: str, stage: str, code: str) -> EvidenceEnvelope:
    """Build the bounded failed-coverage envelope used for unusable model output."""
    _require_canonical_artifact(artifact_id)
    return EvidenceEnvelope.model_validate(
        {
            "artifact_id": artifact_id,
            "coverage": {
                "status": CoverageStatus.FAILED,
                "surfaces": [],
                "limitations": [f"{stage}:{code}"],
            },
            "findings": [],
        },
    )


def parse_critic_envelope(raw: object, *, artifact_id: str) -> CriticEnvelope:
    """Parse strict critic output and bind it to session artifact authority."""
    _require_canonical_artifact(artifact_id)
    raw = loads_model_json(raw, max_chars=MAX_RAW_CRITIC_JSON_CHARS)
    envelope = CriticEnvelope.model_validate(raw)
    if envelope.artifact_id != artifact_id:
        raise ValueError("critic envelope artifact_id does not match current artifact")
    return envelope


def parse_critic_judgment(raw: object, *, artifact_id: str) -> CriticJudgment:
    """Parse the critic model's reject/qualify judgment, bound to the artifact."""
    _require_canonical_artifact(artifact_id)
    raw = loads_model_json(raw, max_chars=MAX_RAW_CRITIC_JSON_CHARS)
    raw = _sole_object_with(raw, "rejected", "qualified")
    judgment = CriticJudgment.model_validate(raw)
    if judgment.artifact_id != artifact_id:
        raise ValueError("critic judgment artifact_id does not match current artifact")
    return judgment
