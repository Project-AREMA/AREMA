"""Deterministic recovery-stage skip for JVM/Android packages.

The deobfuscation recovery loop (UPX/FLOSS/de4dot/dnlib + the agentic analysts,
plus a radare2 retriage) is a native/.NET recovery machine: its classification
schema, its tools, and its retriage all target native or managed code, and
``deobf_gate`` mandates that the native UPX+FLOSS pair ran every iteration. A
JVM/Android package (``apk``/``dex``/``jar``) has *no* recovery cell -- jadx opens
the container directly, so there is nothing to unpack -- so the ``deobfuscation``
format router sends those formats here instead of spending a full loop (six
agents, a radare2 call that cannot even read the container) to reach an all-no-op
result. This mirrors format routing already used for triage and deep decompile:
the engine that does not apply is never stood up.

It emits the same empty, complete recovery-evidence envelope the loop produces for
a clean sample, so downstream stages (the critic, network-coverage enforcement)
see an explicit "recovery examined nothing to recover" rather than an absence.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from google.adk.agents import BaseAgent
from google.adk.events import Event, EventActions

from arema.registry.descriptors import AgentDescriptor, AgentKind
from reverse_engineering.evidence_envelope import (
    CoverageStatus,
    EvidenceCoverage,
    EvidenceEnvelope,
)
from reverse_engineering.tools.deobfuscation.state import (
    CURRENT_ARTIFACT_KEY,
    RECOVERY_EVIDENCE_KEY,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from google.adk.agents.invocation_context import InvocationContext

    from arema.runtime.agent_factory import AgentBuildContext

__all__ = ["RECOVERY_SKIP_DESCRIPTOR", "build_recovery_skip"]


class _RecoverySkip(BaseAgent):
    """Emit an empty, complete recovery envelope and return -- no recovery to run."""

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        getter = getattr(ctx.session.state, "get", None)
        artifact_id = getter(CURRENT_ARTIFACT_KEY) if callable(getter) else None
        if not isinstance(artifact_id, str):
            return
        try:
            envelope = EvidenceEnvelope(
                artifact_id=artifact_id,
                coverage=EvidenceCoverage(
                    status=CoverageStatus.COMPLETE, surfaces=(), limitations=()
                ),
                findings=(),
            )
        except ValueError:
            # A malformed artifact id yields no envelope; the critic tolerates the
            # absence (it skips an unparseable/missing recovery slot).
            return
        yield Event(
            author=self.name,
            invocation_id=ctx.invocation_id,
            branch=ctx.branch,
            actions=EventActions(
                state_delta={RECOVERY_EVIDENCE_KEY: envelope.model_dump(mode="json")}
            ),
        )


def build_recovery_skip(context: AgentBuildContext) -> BaseAgent:
    """Construct the deterministic recovery-skip agent from a build context."""
    return _RecoverySkip(
        name=context.descriptor.name,
        description=context.descriptor.description,
        after_agent_callback=list(context.after_agent),
    )


RECOVERY_SKIP_DESCRIPTOR = AgentDescriptor(
    id="recovery_skip",
    name="recovery_skip",
    description=(
        "Skip the native/.NET recovery loop for a JVM/Android package (jadx opens "
        "the container directly), emitting an empty complete recovery envelope."
    ),
    prompt_id=None,
    factory=build_recovery_skip,
    kind=AgentKind.DETERMINISTIC,
    sub_agent_ids=(),
)
