"""The shape every reputation source normalizes into.

One bounded record per source, so the renderer and the prompts never have to
know which service produced a line. The fields are deliberately few: a source
name, a disposition, and one sanitized sentence. Anything a source returns that
does not fit those three is dropped at parse time rather than carried in a
schema that only one provider populates.

:data:`IntelStatus.NOT_PRESENT` is the value most likely to be misread. It means
the digest is absent from that corpus and nothing more. It is not a clean bill
of health, and every consumer -- renderer, prompt, report -- has to say so.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StrictStr

MAX_SUMMARY_CHARS = 200
MAX_SOURCE_CHARS = 32
MAX_RELATION_VALUE_CHARS = 180

# The name each source is known by: the key in the settings gate, the label in
# the rendered line, and the string a finding cites as its ``tool``. One
# definition, so those three can never drift apart.
HASHLOOKUP_SOURCE = "hashlookup"
MALWAREBAZAAR_SOURCE = "malwarebazaar"
VIRUSTOTAL_SOURCE = "virustotal"

# The summary is injected into an ADK instruction template, where a brace would
# be resolved as a state placeholder. Same reasoning, and the same character
# set, as the verdict rationale in reverse_engineering.verdict.
_UNSAFE_CHARS = "{}`"
_TRANSLATION = str.maketrans(dict.fromkeys(_UNSAFE_CHARS, " "))
_WHITESPACE = re.compile(r"\s+")

__all__ = [
    "HASHLOOKUP_SOURCE",
    "MAX_RELATION_VALUE_CHARS",
    "MALWAREBAZAAR_SOURCE",
    "MAX_SOURCE_CHARS",
    "MAX_SUMMARY_CHARS",
    "VIRUSTOTAL_SOURCE",
    "IntelRelation",
    "IntelResult",
    "IntelStatus",
    "sanitize_summary",
]


class IntelStatus(StrEnum):
    """What a source said about the digest.

    ``UNAVAILABLE`` is kept distinct from ``NOT_PRESENT`` on purpose: a source
    that timed out has told us nothing, while a source that answered "absent"
    has told us something small but real. Collapsing the two would let an
    outage read as evidence.
    """

    KNOWN_GOOD = "known_good"
    KNOWN_BAD = "known_bad"
    NOT_PRESENT = "not_present"
    UNAVAILABLE = "unavailable"


class IntelResult(BaseModel):
    """One source's answer about one digest."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    source: Annotated[StrictStr, Field(min_length=1, max_length=MAX_SOURCE_CHARS)]
    status: IntelStatus
    summary: Annotated[StrictStr, Field(max_length=MAX_SUMMARY_CHARS)] = ""

    @property
    def is_hit(self) -> bool:
        """Whether the source recognized the digest at all."""
        return self.status in (IntelStatus.KNOWN_GOOD, IntelStatus.KNOWN_BAD)


class IntelRelation(BaseModel):
    """One indicator a third party associates with the digest.

    ``malicious``/``total`` travel with the value because without them a report
    presents a live C2 and an analysis VM's Office traffic identically. Measured
    on one sample: an in-the-wild URL at 16/49 alongside contacted IPs at 0/91.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    source: Annotated[StrictStr, Field(min_length=1, max_length=MAX_SOURCE_CHARS)]
    kind: Annotated[StrictStr, Field(min_length=1, max_length=MAX_SOURCE_CHARS)]
    value: Annotated[StrictStr, Field(min_length=1, max_length=MAX_RELATION_VALUE_CHARS)]
    name: Annotated[StrictStr, Field(max_length=MAX_SOURCE_CHARS * 2)] = ""
    malicious: Annotated[int, Field(ge=0)] = 0
    total: Annotated[int, Field(ge=0)] = 0

    @property
    def ratio(self) -> str:
        """``16/49``, or an empty string when no engine result was returned."""
        return f"{self.malicious}/{self.total}" if self.total else ""


def sanitize_summary(value: object, *, limit: int = MAX_SUMMARY_CHARS) -> str:
    """Reduce third-party text to a bounded, single-line, template-safe string.

    Applied to every value that reaches a prompt. Some of it is written by
    whoever submitted the sample -- a filename chosen at upload time is
    attacker-controlled text arriving through a trusted-looking API.
    """
    if not isinstance(value, str):
        return ""
    stripped = "".join(
        char if char.isascii() and char.isprintable() else " "
        for char in value.translate(_TRANSLATION)
    )
    return _WHITESPACE.sub(" ", stripped).strip()[:limit].strip()
