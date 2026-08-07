"""Injectable runtime services and event types for AREMA callbacks.

The callback layer never talks to a clock, a metrics backend, or a persistent
memory store directly. Instead it depends on the small interfaces defined
here, bundled into an immutable :class:`RuntimeServices` value. Production
wiring supplies real implementations; tests supply fakes with a controllable
clock and recording sinks. This keeps the neutral callbacks free of any
dependency on SQLite, telemetry vendors, or wall-clock time.

Only neutral, non-sensitive facts ever cross these interfaces. A
:class:`ToolEvent` carries the tool identity, an outcome flag, an elapsed
time, the run/scope identifiers, and the serialized output size -- never the
tool arguments or the raw output payload. The optional checkpoint recorder
persists only bounded lifecycle state (a label, an ordered sequence, and small
scalar counters), never prompts, tool arguments, model text, or tool output.

This module may depend on :mod:`arema.memory` (the lower layer) but never the
reverse: the memory service satisfies :class:`MemoryEventSink` and
:class:`MemoryCheckpointSink` structurally, so neither side imports the other's
concrete type.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from arema.core.logging import get_logger
from arema.memory.models import CheckpointRecord
from arema.runtime.sessions import SessionKeys

if TYPE_CHECKING:
    from collections.abc import Callable

    from google.adk.agents.callback_context import CallbackContext

    from arema.memory.models import JsonValue, MemoryEnvelope
    from arema.memory.service import MemoryService
    from arema.runtime.sandbox.port import SandboxExecutor

logger = get_logger(__name__)

_CHECKPOINT_SOURCE = "arema.runtime"


@dataclass(frozen=True, slots=True)
class ToolEvent:
    """A minimal, non-sensitive record of one completed tool call."""

    tool_id: str
    success: bool
    elapsed_seconds: float
    output_size: int
    run_id: str | None = None
    scope_id: str | None = None


@dataclass(frozen=True, slots=True)
class ModelCallEvent:
    """A minimal record of one model invocation for a run."""

    agent_id: str
    call_count: int
    run_id: str | None = None
    scope_id: str | None = None


@runtime_checkable
class Clock(Protocol):
    """A monotonic time source, expressed in fractional seconds."""

    def now(self) -> float:
        """Return the current monotonic time in seconds."""
        ...


@runtime_checkable
class MetricsSink(Protocol):
    """Receives neutral runtime metrics for a run."""

    def record_model_call(self, event: ModelCallEvent) -> None:
        """Record that a model invocation is about to occur."""
        ...

    def record_tool_event(self, event: ToolEvent) -> None:
        """Record the outcome of a completed tool call."""
        ...


@runtime_checkable
class MemoryEventSink(Protocol):
    """Persists neutral tool-call events to a run's working memory."""

    def record_tool_event(self, event: ToolEvent) -> None:
        """Persist the outcome of a completed tool call."""
        ...


class MonotonicClock:
    """A :class:`Clock` backed by :func:`time.monotonic`."""

    def now(self) -> float:
        """Return the process monotonic clock reading in seconds."""
        return time.monotonic()


class NullMetricsSink:
    """A :class:`MetricsSink` that discards every event."""

    def record_model_call(self, event: ModelCallEvent) -> None:
        """Discard a model-call event."""

    def record_tool_event(self, event: ToolEvent) -> None:
        """Discard a tool event."""


class NullMemoryEventSink:
    """A :class:`MemoryEventSink` that discards every event.

    Wiring this no-op sink keeps the callback chain shape identical whether or
    not persistent memory is enabled, so a disabled store never changes the
    ordering the runtime validates.
    """

    def record_tool_event(self, event: ToolEvent) -> None:
        """Discard a tool event."""


@dataclass(frozen=True, slots=True)
class RuntimeServices:
    """The injectable collaborators every runtime callback depends on."""

    clock: Clock
    metrics: MetricsSink
    memory_sink: MemoryEventSink
    sandbox: SandboxExecutor | None = None

    @classmethod
    def default(cls) -> RuntimeServices:
        """Return services backed by a real clock and no-op sinks."""
        return cls(
            clock=MonotonicClock(),
            metrics=NullMetricsSink(),
            memory_sink=NullMemoryEventSink(),
        )


@runtime_checkable
class MemoryCheckpointSink(Protocol):
    """Persists a bounded progress checkpoint for a run's working memory.

    Satisfied structurally by the memory service, so the runtime never imports
    the concrete service type. The checkpoint payload is a neutral memory model,
    which belongs to the lower layer and is safe for this layer to reference.
    """

    def append_checkpoint(
        self,
        scope_id: str,
        checkpoint: CheckpointRecord,
        *,
        source: str,
    ) -> MemoryEnvelope:
        """Persist ``checkpoint`` under ``scope_id`` and return its envelope."""
        ...


def _state_value(state: object, key: str) -> object | None:
    """Read ``key`` from an ADK ``State`` proxy or a plain mapping, or ``None``.

    ADK's ``State`` is not a ``dict`` (and not even a ``Mapping``), so this
    duck-types on ``get`` rather than an ``isinstance`` guard.
    """
    getter = getattr(state, "get", None)
    return getter(key) if callable(getter) else None


def _checkpoint_from_state(raw: object) -> CheckpointRecord | None:
    """Build a bounded :class:`CheckpointRecord` from a state checkpoint value.

    The state value is expected to be a mapping carrying an optional ``label``,
    ``sequence``, and ``state``; anything else yields ``None`` (nothing to
    persist). Only the declared bounded state is copied -- never surrounding
    conversation data.
    """
    if not isinstance(raw, Mapping):
        return None
    label = raw.get("label")
    label_text = label if isinstance(label, str) else "context"
    sequence = raw.get("sequence")
    # ``bool`` is an ``int`` subclass; a stray flag must not become a sequence.
    sequence_value = sequence if isinstance(sequence, int) and not isinstance(sequence, bool) else 0
    state_value = raw.get("state")
    if isinstance(state_value, Mapping):
        bounded: dict[str, JsonValue] = {str(key): value for key, value in state_value.items()}
    else:
        reserved = {"label", "sequence", "state"}
        bounded = {str(key): value for key, value in raw.items() if key not in reserved}
    return CheckpointRecord(label=label_text, sequence=max(0, sequence_value), state=bounded)


def make_checkpoint_recorder(sink: MemoryCheckpointSink) -> Callable[[CallbackContext], None]:
    """Build an after-agent recorder that persists a bounded context checkpoint.

    When the run's state carries a memory scope and a
    :attr:`SessionKeys.CONTEXT_CHECKPOINT` value, the recorder writes a
    :class:`CheckpointRecord` before the scope closes. It is fail-open: any
    failure is logged without sensitive detail and swallowed so an after-agent
    hook never aborts a run.
    """

    def record_context_checkpoint(callback_context: CallbackContext) -> None:
        try:
            state = getattr(callback_context, "state", None)
            if state is None:
                return
            scope_id = _state_value(state, SessionKeys.MEMORY_SCOPE_ID)
            raw = _state_value(state, SessionKeys.CONTEXT_CHECKPOINT)
            if not isinstance(scope_id, str) or raw is None:
                return
            checkpoint = _checkpoint_from_state(raw)
            if checkpoint is None:
                return
            sink.append_checkpoint(scope_id, checkpoint, source=_CHECKPOINT_SOURCE)
        except Exception:
            logger.warning("record_context_checkpoint failed - continuing", exc_info=True)

    return record_context_checkpoint


def build_memory_backed_services(
    memory: MemoryService,
    *,
    clock: Clock | None = None,
    metrics: MetricsSink | None = None,
    sandbox: SandboxExecutor | None = None,
) -> RuntimeServices:
    """Wire a memory service as the runtime's :class:`MemoryEventSink`.

    The run scope is created by the runner, not here; this only bundles the
    service (as the tool-event sink) with a clock and metrics sink for the
    callback chain. The parameter type also gives a compile-time guarantee that
    a :class:`MemoryService` satisfies :class:`MemoryEventSink`.
    """
    return RuntimeServices(
        clock=clock if clock is not None else MonotonicClock(),
        metrics=metrics if metrics is not None else NullMetricsSink(),
        memory_sink=memory,
        sandbox=sandbox,
    )
