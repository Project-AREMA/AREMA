"""After-agent normalization of model-authored evidence state."""

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from arema.core.logging import get_logger
from reverse_engineering.evidence_envelope import (
    MAX_DETAIL_CHARS,
    MAX_FINDINGS,
    MAX_LIMITATIONS,
    MAX_SURFACES,
    CoverageStatus,
    CriticEnvelope,
    EvidenceCoverage,
    EvidenceEnvelope,
    EvidenceFinding,
    failed_evidence_envelope,
    parse_critic_judgment,
    parse_evidence_envelope,
    rebind_evidence_envelope,
    salvage_evidence_envelope,
)
from reverse_engineering.execution_flow import (
    ExecutionFlow,
    filter_flow_by_cited_tools,
    render_mermaid,
)
from reverse_engineering.model_json import loads_model_json
from reverse_engineering.tools.deobfuscation.state import (
    CURRENT_ARTIFACT_KEY,
    RECOVERY_SUMMARY_KEY,
)
from reverse_engineering.tools.ghidra.coverage import NATIVE_EVIDENCE_KEY
from reverse_engineering.verdict import SampleVerdict, verdict_label

VALIDATED_EVIDENCE_KEY = "validated_evidence_json"

# The report's execution diagram, pre-rendered so the report model pastes it
# rather than drawing one. Identifier-safe, because ADK instruction templating
# resolves ``{execution_flow_mermaid?}`` from session state by that exact name.
EXECUTION_FLOW_MERMAID_KEY = "execution_flow_mermaid"

# The sample's disposition and its one-line reason, both pre-resolved so the
# report leads with a validated value rather than a sentence it improvised.
SAMPLE_VERDICT_KEY = "sample_verdict"
SAMPLE_VERDICT_RATIONALE_KEY = "sample_verdict_rationale"

# The one stage allowed to declare the flow. It is the synthesis lens: it already
# reads deep + host + network evidence, so it is the only stage that can see the
# sample's behaviour end to end. Every other stage's flow is ignored.
FLOW_AUTHOR_STAGE = "behavior"

# The critic re-validates every upstream evidence envelope; a failure or
# non-complete status in any of them lowers the validated coverage. The stage
# name is the identity the critic model uses to reject/qualify a finding by its
# zero-based index within that envelope's ``findings`` array.
CRITIC_STAGE_KEYS: tuple[tuple[str, str], ...] = (
    ("triage", "triage_evidence_json"),
    ("recovery", "recovery_evidence_json"),
    ("deep", "deep_evidence_json"),
    ("native", NATIVE_EVIDENCE_KEY),
    ("host", "host_ioc_evidence_json"),
    ("network", "network_ioc_evidence_json"),
    ("behavior", "behavior_evidence_json"),
    ("attack", "attack_evidence_json"),
)
UPSTREAM_EVIDENCE_KEYS = tuple(key for _stage, key in CRITIC_STAGE_KEYS)

if TYPE_CHECKING:
    from google.adk.agents.callback_context import CallbackContext

    from arema.registry.descriptors import AfterAgentCallback

logger = get_logger(__name__)


def _payload_type(raw: object) -> str:
    """Name the type the model's text decoded to -- never its content.

    A ``str`` here means the text never parsed; ``list`` means it decoded to
    several JSON values (or a bare array) where an object was required.
    """
    try:
        return type(loads_model_json(raw)).__name__ if isinstance(raw, str) else type(raw).__name__
    except Exception:
        return f"unparsable:{type(raw).__name__}"


def _rejected_fields(exc: Exception) -> list[str]:
    """``field.path:failure_kind`` for a pydantic error -- never the offending value.

    The value is model-controlled and must never reach the log. The *location* and
    the *kind* of failure are facts about our own schema, and they are what
    separates "the model invented an enum member" from "a required field was
    missing" -- a distinction the exception type alone cannot make, which left a
    real evidence loss undiagnosable across several live runs. Bounded, and
    degrades to ``[]`` rather than turning a diagnostic into a second failure.
    """
    errors = getattr(exc, "errors", None)
    if not callable(errors):
        return []
    try:
        return sorted(
            {
                f"{'.'.join(str(part) for part in error.get('loc', ()))}:{error.get('type', '?')}"
                for error in errors()
            }
        )[:10]
    except Exception:
        return []


def _log_normalization_failure(
    *, stage: str, exc: Exception, payload_type: str | None = None
) -> None:
    """Record only stable diagnostics; model output is never safe to log.

    ``payload_type`` is the Python type the model's text decoded to. A type name
    carries no model content, and it is what separates "the envelope is malformed"
    from "the model emitted something that is not an object at all" -- a
    distinction a root-level ``model_type`` rejection cannot make on its own.
    """
    logger.warning(
        "evidence output normalization failed",
        stage=stage,
        error_type=type(exc).__name__,
        rejected_fields=_rejected_fields(exc),
        payload_type=payload_type,
    )


# The running-best evidence for a looped stage lives under this per-invocation
# temp key (ADK clears ``temp:`` state between invocations, so it never bleeds
# across samples). Only the ghidra deep-analysis LoopAgent opts into it; every
# single-shot stage stays last-write-wins.
_ACCUMULATOR_KEY_PREFIX = "temp:evidence_accum:"


def _bounded_union(first: tuple[str, ...], second: tuple[str, ...], cap: int) -> tuple[str, ...]:
    """Order-preserving de-duplicated union of two bounded string tuples."""
    merged: list[str] = []
    for item in (*first, *second):
        if item not in merged:
            merged.append(item)
    return tuple(merged[:cap])


def _dedupe_identity(finding: EvidenceFinding) -> tuple[str, str, str, str]:
    """What makes two findings the same fact.

    ``kind`` is part of the identity on purpose, and it was worth re-deriving:
    one live run re-emitted a single ``search_strings`` result under
    ``behavior``, ``host_ioc`` and ``network_ioc``, which looks like padding.
    But the same claim under a different kind is often a real re-categorization
    the report needs -- an assembly that will not load is simultaneously a host
    indicator and a coverage limitation, and it belongs in both sections.
    Nothing mechanical separates the two cases, and collapsing on
    ``(tool, claim, detail)`` would silently drop the legitimate one to tidy the
    count of the other.
    """
    return (finding.tool, finding.claim, finding.detail, finding.kind)


def _merge_evidence_envelopes(prior: EvidenceEnvelope, new: EvidenceEnvelope) -> EvidenceEnvelope:
    """Union prior + new evidence: findings de-duplicated by identity, coverage
    surfaces/limitations unioned. Both envelopes are already anchored to the same
    artifact, so the merged envelope's artifact invariant holds. The coverage
    ``status`` is the latest self-assessment -- the deep-analysis gate re-derives
    the authoritative final status from its own surface tracking at loop exit."""
    findings = list(prior.findings)
    seen = {_dedupe_identity(f) for f in findings}
    for finding in new.findings:
        identity = _dedupe_identity(finding)
        if identity not in seen:
            seen.add(identity)
            findings.append(finding)
    return new.model_copy(
        update={
            "coverage": EvidenceCoverage(
                status=new.coverage.status,
                surfaces=_bounded_union(
                    prior.coverage.surfaces, new.coverage.surfaces, MAX_SURFACES
                ),
                limitations=_bounded_union(
                    prior.coverage.limitations, new.coverage.limitations, MAX_LIMITATIONS
                ),
            ),
            "findings": tuple(findings[:MAX_FINDINGS]),
        }
    )


def _accumulate_stage_evidence(
    getter: object,
    setter: object,
    *,
    output_key: str,
    artifact_id: str,
    new_envelope: EvidenceEnvelope,
    new_is_valid: bool,
) -> EvidenceEnvelope:
    """Preserve the running-best evidence across LoopAgent iterations.

    A looped worker (the ghidra deep-analysis loop) is re-invoked after it has
    already emitted a valid envelope; a later pass often emits an empty envelope
    or prose. ADK's ``output_key`` overwrites last-write-wins, so without this a
    degrading worker erases an earlier validated finding (the observed native
    ``deep:evidence_envelope_invalid``). A valid emission unions into the running
    best; an invalid one never advances (nor poisons) it. Returns the envelope to
    store at ``output_key``.
    """
    accumulator_key = _ACCUMULATOR_KEY_PREFIX + output_key
    prior: EvidenceEnvelope | None = None
    raw_prior = getter(accumulator_key)  # type: ignore[operator]
    if raw_prior is not None:
        try:
            prior = parse_evidence_envelope(raw_prior, artifact_id=artifact_id)
        except Exception:
            prior = None  # a stale/foreign accumulator resets rather than corrupts
    if not new_is_valid:
        # A garbage emission neither advances nor poisons the accumulator: keep
        # the prior best if we have one, else surface the failed envelope while
        # leaving the accumulator clean for a later valid pass to merge into.
        return prior if prior is not None else new_envelope
    merged = new_envelope if prior is None else _merge_evidence_envelopes(prior, new_envelope)
    setter(accumulator_key, merged.model_dump(mode="json"))  # type: ignore[operator]
    return merged


def _with_limitations(envelope: EvidenceEnvelope, extra: list[str]) -> EvidenceEnvelope:
    """Append bounded, de-duplicated limitation codes to an envelope's coverage."""
    limitations = list(envelope.coverage.limitations)
    limitations.extend(code for code in extra if code not in limitations)
    return envelope.model_copy(
        update={
            "coverage": EvidenceCoverage(
                status=envelope.coverage.status,
                surfaces=envelope.coverage.surfaces,
                limitations=tuple(limitations[:MAX_LIMITATIONS]),
            )
        }
    )


def _salvaged(raw: object, *, artifact_id: str, stage: str, cause: Exception) -> EvidenceEnvelope:
    """Recover the findings the strict parse rejected, or re-raise.

    What was dropped or re-anchored is recorded as a limitation rather than
    absorbed silently: a reader who is shown fewer findings than the stage
    produced is entitled to know the count, and a stage whose evidence named a
    different artifact than the session's is anomalous enough to surface.
    """
    envelope, dropped, rebound = salvage_evidence_envelope(raw, artifact_id=artifact_id)
    codes: list[str] = []
    if dropped:
        codes.append(f"{stage}:findings_dropped:{dropped}")
    if rebound:
        codes.append(f"{stage}:evidence_rebound")
    logger.warning(
        "evidence output salvaged after strict rejection",
        stage=stage,
        error_type=type(cause).__name__,
        rejected_fields=_rejected_fields(cause),
        dropped=dropped,
        rebound=rebound,
        kept=len(envelope.findings),
    )
    return _with_limitations(envelope, codes)


def normalize_evidence_output(
    callback_context: CallbackContext,
    *,
    output_key: str,
    stage: str,
    accumulate: bool = False,
) -> None:
    """Normalize evidence state and return ``None`` so later callbacks still run.

    With ``accumulate`` (the looped deep worker), the normalized envelope is
    merged into the stage's running-best across loop iterations so a later empty
    or unparseable emission cannot erase an earlier validated finding.
    """
    try:
        state = callback_context.state
        getter = getattr(state, "get", None)
        setter = getattr(state, "__setitem__", None)
        if not callable(getter) or not callable(setter):
            raise TypeError("callback state is not readable and writable")
        artifact_id = getter(CURRENT_ARTIFACT_KEY)
        raw = getter(output_key)
    except Exception as exc:
        _log_normalization_failure(stage=stage, exc=exc)
        return

    # Without a valid artifact id nothing can anchor an envelope; leave state as-is
    # (matches normalize_critic_output rather than routing a None through parsing).
    if not isinstance(artifact_id, str):
        return

    # `raw` is model-controlled: a hostile mapping can raise arbitrary exceptions
    # while being parsed. Catch broadly (not just TypeError/ValueError) and replace
    # it with a bounded failed envelope; `_log_normalization_failure` records the
    # exception type only, never the raw value.
    new_is_valid = True
    unusable: Exception | None = None
    try:
        envelope = parse_evidence_envelope(raw, artifact_id=artifact_id)
    except Exception as exc:
        try:
            envelope = _salvaged(raw, artifact_id=artifact_id, stage=stage, cause=exc)
        except Exception:
            new_is_valid = False
            try:
                envelope = failed_evidence_envelope(
                    artifact_id=artifact_id,
                    stage=stage,
                    code="evidence_envelope_invalid",
                )
            except Exception as artifact_exc:
                _log_normalization_failure(stage=stage, exc=artifact_exc)
                return
            # Deferred: whether this is a failure at all depends on the
            # accumulator below. Logging here would cry wolf on the benign case.
            unusable = exc

    if accumulate:
        # Accumulation is best-effort: a failure here must never lose the write,
        # so fall through to store the un-accumulated envelope.
        try:
            envelope = _accumulate_stage_evidence(
                getter,
                setter,
                output_key=output_key,
                artifact_id=artifact_id,
                new_envelope=envelope,
                new_is_valid=new_is_valid,
            )
        except Exception as exc:
            _log_normalization_failure(stage=stage, exc=exc)

    if unusable is not None:
        if envelope.findings:
            # A looped worker that has already emitted its envelope narrates on a
            # later pass ("Analysis complete. Pipeline may terminate.") instead of
            # repeating it -- observed live on two of three deep passes. The
            # accumulator kept the earlier evidence, so nothing was lost and this
            # is not a failure. Saying otherwise buries the real signal, which is
            # the mistake LESSONS_LEARNED #17 ends on.
            logger.info(
                "stage produced no envelope this pass; keeping the evidence it already emitted",
                stage=stage,
                error_type=type(unusable).__name__,
                kept=len(envelope.findings),
            )
        else:
            _log_normalization_failure(stage=stage, exc=unusable, payload_type=_payload_type(raw))

    try:
        setter(output_key, envelope.model_dump(mode="json"))
    except Exception as exc:
        _log_normalization_failure(stage=stage, exc=exc)


def evidence_output_callback(
    *, output_key: str, stage: str, accumulate: bool = False
) -> AfterAgentCallback:
    """Return a stable non-short-circuiting after-agent callback for a descriptor."""
    return partial(
        normalize_evidence_output, output_key=output_key, stage=stage, accumulate=accumulate
    )


def _raw_artifact_id(raw: object) -> str:
    """The artifact id a raw (unvalidated) upstream evidence envelope is bound to.

    Read so the envelope can be parsed against its own embedded authority before
    being re-anchored to the current artifact -- the same two-step
    parse-then-rebind pattern ``deobf_gate._evidence_artifact_id`` uses on the
    recovery loop's own cumulative evidence. A stage like ``triage`` legitimately
    binds to the *pre-recovery* artifact rather than the current one, so its
    envelope must be validated against its own id first, never rejected outright
    for naming a different (but internally consistent) artifact. Raises
    ``ValueError`` when the raw payload has no string ``artifact_id`` to anchor
    against -- a genuinely malformed envelope still fails closed.
    """
    data = loads_model_json(raw)
    if isinstance(data, dict):
        candidate = data.get("artifact_id")
        if isinstance(candidate, str):
            return candidate
    raise ValueError("evidence envelope missing artifact_id")


def _qualify_finding(finding: EvidenceFinding, reason: str) -> EvidenceFinding:
    """Carry a qualified finding forward verbatim, lowering confidence + noting why."""
    # Reserve room for the marker so a near-max-length detail can never truncate the
    # qualification itself away -- the reason is the whole point of qualifying.
    suffix = f" [qualified: {reason}]"
    detail = (finding.detail[: max(0, MAX_DETAIL_CHARS - len(suffix))] + suffix)[:MAX_DETAIL_CHARS]
    return finding.model_copy(update={"confidence": min(finding.confidence, 0.5), "detail": detail})


def normalize_critic_output(callback_context: CallbackContext) -> None:
    """Build the validated envelope deterministically from the critic's judgment.

    The critic model only names which upstream findings to reject or qualify (by
    ``source_stage`` + zero-based ``source_index``); every other upstream finding
    is carried forward verbatim here. This makes evidence survival deterministic
    instead of depending on an LLM to re-transcribe dozens of findings (which
    silently drops most of them). A missing, invalid, or non-``complete``
    upstream envelope still lowers the validated coverage so the report can never
    treat an incomplete pass as exhaustive.
    """
    try:
        state = callback_context.state
        getter = getattr(state, "get", None)
        setter = getattr(state, "__setitem__", None)
        if not callable(getter) or not callable(setter):
            raise TypeError("callback state is not readable and writable")
        artifact_id = getter(CURRENT_ARTIFACT_KEY)
        if not isinstance(artifact_id, str):
            return
    except Exception as exc:
        _log_normalization_failure(stage="critic", exc=exc)
        return

    # A missing/invalid judgment yields no rejections/qualifications, so every
    # upstream finding is accepted -- over-inclusive, never evidence-dropping.
    try:
        judgment = parse_critic_judgment(getter(VALIDATED_EVIDENCE_KEY), artifact_id=artifact_id)
        rejected = tuple(judgment.rejected)
        rejected_keys = {(r.source_stage, r.source_index) for r in judgment.rejected}
        qualify_reasons = {(q.source_stage, q.source_index): q.reason for q in judgment.qualified}
    except (TypeError, ValueError) as exc:
        rejected = ()
        rejected_keys = set()
        qualify_reasons = {}
        _log_normalization_failure(stage="critic", exc=exc)

    accepted: list[EvidenceFinding] = []
    qualified: list[EvidenceFinding] = []
    # Identity of accepted findings already carried forward, so a finding several
    # stages emit identically (e.g. the same "assembly is packed" limitation
    # surfaced independently by deep and behavior) is kept once rather than
    # padding the evidence -- and deduplicated BEFORE the MAX_FINDINGS cut so
    # duplicates can never crowd distinct findings out of a rich report. `kind` is
    # part of the identity on purpose: the same claim tagged differently (e.g.
    # once as a host_ioc, once as a limitation) is categorized differently by the
    # report, so those are kept apart -- only truly identical findings collapse.
    seen_accepted: set[tuple[str, str, str, str]] = set()
    limitations: set[str] = set()
    surfaces: set[str] = set()
    upstream_failed = False
    declared_flow: ExecutionFlow | None = None
    declared_verdict: SampleVerdict | None = None
    for stage, key in CRITIC_STAGE_KEYS:
        raw = getter(key)
        if raw is None:
            # An absent stage never produced evidence for this sample's format --
            # e.g. the Android `.so` fan-out writes native_evidence_json only for
            # JVM samples, so native/.NET samples never reach it. Absent is not a
            # malformed envelope: skip it without a `critic:{key}:invalid`
            # limitation or an upstream-failed flag, exactly as a legitimately
            # skipped stage should behave. A present-but-unparseable envelope
            # (below) still fails closed.
            continue
        try:
            own_id = _raw_artifact_id(raw)
            envelope = rebind_evidence_envelope(
                parse_evidence_envelope(raw, artifact_id=own_id),
                artifact_id=artifact_id,
            )
        except (TypeError, ValueError, KeyError):
            limitations.add(f"critic:{key}:invalid")
            upstream_failed = True
            continue
        limitations.update(envelope.coverage.limitations)
        surfaces.update(envelope.coverage.surfaces)
        upstream_failed = upstream_failed or envelope.coverage.status is not CoverageStatus.COMPLETE
        if stage == FLOW_AUTHOR_STAGE:
            declared_flow = envelope.flow
            declared_verdict = envelope.verdict
        for index, finding in enumerate(envelope.findings):
            marker = (stage, index)
            if marker in rejected_keys:
                continue
            reason = qualify_reasons.get(marker)
            if reason is not None:
                qualified.append(_qualify_finding(finding, reason))
                continue
            identity = _dedupe_identity(finding)
            if identity in seen_accepted:
                continue
            seen_accepted.add(identity)
            accepted.append(finding)

    recovery_summary = getter(RECOVERY_SUMMARY_KEY)
    if isinstance(recovery_summary, dict):
        recovery_limitations = recovery_summary.get("limitations", [])
        if isinstance(recovery_limitations, list):
            limitations.update(item for item in recovery_limitations if isinstance(item, str))

    status = CoverageStatus.COMPLETE
    if upstream_failed or limitations:
        status = CoverageStatus.PARTIAL if (accepted or qualified) else CoverageStatus.FAILED

    # Written unconditionally, so a previous sample's diagram can never linger in
    # state and be rendered against this one's evidence.
    try:
        cited = {finding.tool for finding in (*accepted, *qualified)}
        setter(
            EXECUTION_FLOW_MERMAID_KEY,
            render_mermaid(filter_flow_by_cited_tools(declared_flow, cited)),
        )
        # A verdict with nothing behind it is not a verdict. When every finding
        # was rejected there is no evidence to have judged, so the report says
        # UNDETERMINED rather than repeating a confidence nobody can check.
        surviving = declared_verdict if (accepted or qualified) else None
        setter(SAMPLE_VERDICT_KEY, verdict_label(surviving))
        setter(SAMPLE_VERDICT_RATIONALE_KEY, surviving.rationale if surviving is not None else "")
    except Exception as exc:
        _log_normalization_failure(stage="critic", exc=exc)

    try:
        validated = CriticEnvelope(
            artifact_id=artifact_id,
            coverage=EvidenceCoverage(
                status=status,
                surfaces=tuple(sorted(surfaces)[:MAX_SURFACES]),
                limitations=tuple(sorted(limitations)[:MAX_LIMITATIONS]),
            ),
            accepted=tuple(accepted[:MAX_FINDINGS]),
            qualified=tuple(qualified[:MAX_FINDINGS]),
            rejected=rejected[:MAX_FINDINGS],
        )
        setter(VALIDATED_EVIDENCE_KEY, validated.model_dump(mode="json"))
    except Exception as exc:
        _log_normalization_failure(stage="critic", exc=exc)
