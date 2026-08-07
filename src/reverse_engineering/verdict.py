"""The sample's disposition, as a structured value rather than a sentence.

A report that maps ATT&CK techniques and lists "indicators of compromise" for
every sample has no way to say "this is fine". Run against UPX-packed GNU
coreutils ``ls`` the pipeline dutifully produced T1027.002 (the container is
packed) and T1083 (``ls`` calls ``readdir``) -- both true, both meaningless,
because ATT&CK techniques describe what code *can do*, never intent.

The verdict is the missing judgement. It is declared once, by the synthesis
stage that reads deep, host and network evidence together, and carried to the
report deterministically -- the same path the execution diagram takes, for the
same reason: the single most consequential line in the report should be a
validated value, not free prose the report model improvises.

It changes how findings are *framed*, never whether they are produced. A benign
verdict can be wrong, so the analyst still gets every endpoint, technique and
indicator the pipeline extracted; on a benign sample they are simply labelled
observations rather than compromise.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StrictStr

MAX_RATIONALE_CHARS = 400

# The rationale is injected into an ADK instruction template, where a brace
# would be read as a state placeholder.
_UNSAFE_CHARS = "{}`"
_TRANSLATION = str.maketrans(dict.fromkeys(_UNSAFE_CHARS, " "))
_WHITESPACE = re.compile(r"\s+")

__all__ = [
    "MAX_RATIONALE_CHARS",
    "SampleVerdict",
    "VerdictClass",
    "sanitize_verdict",
    "verdict_label",
]


class VerdictClass(StrEnum):
    """The dispositions a sample can be given.

    ``UNDETERMINED`` is never declared by a model -- it is what the pipeline
    records when no verdict was emitted or none survived validation, so the
    report says so plainly instead of leaving the reader to infer safety from
    silence.
    """

    BENIGN = "benign"
    GRAYWARE = "grayware"
    MALICIOUS = "malicious"
    UNDETERMINED = "undetermined"


class SampleVerdict(BaseModel):
    """A bounded disposition and the one-line reason for it."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    classification: VerdictClass
    rationale: Annotated[StrictStr, Field(min_length=1, max_length=MAX_RATIONALE_CHARS)]


def _clean(value: object) -> str:
    """Reduce model text to a bounded, single-line, template-safe rationale."""
    if not isinstance(value, str):
        return ""
    stripped = "".join(
        char if char.isascii() and char.isprintable() else " "
        for char in value.translate(_TRANSLATION)
    )
    return _WHITESPACE.sub(" ", stripped).strip()[:MAX_RATIONALE_CHARS].strip()


def sanitize_verdict(raw: object) -> SampleVerdict | None:
    """Recover a usable verdict from model output, or ``None``. Never raises.

    ``UNDETERMINED`` is rejected here on purpose: it is the pipeline's own
    marker for "nobody decided", so a model must not be able to claim it and
    thereby dodge the question while looking like it answered.
    """
    if not isinstance(raw, Mapping):
        return None
    classification = raw.get("classification")
    if not isinstance(classification, str):
        return None
    try:
        parsed = VerdictClass(classification.strip().lower())
    except ValueError:
        return None
    if parsed is VerdictClass.UNDETERMINED:
        return None
    rationale = _clean(raw.get("rationale"))
    if not rationale:
        return None
    try:
        return SampleVerdict(classification=parsed, rationale=rationale)
    except ValueError:
        return None


def verdict_label(verdict: SampleVerdict | None) -> str:
    """The uppercase word the report leads with, defaulting to UNDETERMINED."""
    classification = VerdictClass.UNDETERMINED if verdict is None else verdict.classification
    return classification.value.upper()
