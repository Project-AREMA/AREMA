"""Evidence-backed findings: the substrate the ReportGenerator renders from.

A :class:`FindingRecord` is one evidence-backed claim about an artifact. It is
versioned under the ``evidence/finding`` codec so findings persist in the memory
store as addressable evidence the report agent reads from, never invents.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from arema.memory.codecs import RecordCodec


class FindingRecord(BaseModel):
    """One evidence-backed claim about an artifact.

    ``artifact_id`` is the SHA-256 the finding concerns, ``tool`` is the
    citation that produced it (e.g. ``list_imports``), and ``detail`` carries
    an optional supporting evidence excerpt. The model is frozen and rejects
    unknown fields so a finding, once minted, cannot be silently mutated or
    widened.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_id: str
    claim: str
    tool: str
    confidence: float = Field(ge=0.0, le=1.0)
    detail: str = ""


FINDING_CODEC: RecordCodec[FindingRecord] = RecordCodec(
    namespace="evidence",
    kind="finding",
    schema_version=1,
    payload_type=FindingRecord,
)
