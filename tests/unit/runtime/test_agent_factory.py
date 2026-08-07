"""Unit tests for the composite-agent factories (Sequential/Parallel/Loop).

The three factories wrap ADK shell agents around already-built sub-agents. They
ignore the model/instruction/tools an LlmAgent would need and consume only the
descriptor's name/description, the resolved sub-agents, and the optional
pipeline-end after_agent callbacks. Only build_sequential_agent is wired to an
agent this slice; build_parallel_agent / build_loop_agent ship as the ready
foundation.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from google.adk.agents import BaseAgent, LlmAgent, LoopAgent, ParallelAgent, SequentialAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.sessions import InMemorySessionService

from arema.registry.descriptors import AgentDescriptor, AgentKind, RuntimeProfile
from arema.registry.errors import InvalidCapabilityDescriptorError
from arema.runtime.agent_factory import (
    AgentBuildContext,
    EscalationDecision,
    build_escalation_gate,
    build_loop_agent,
    build_parallel_agent,
    build_sequential_agent,
)
from arema.runtime.callbacks.chain import CallbackChain

if TYPE_CHECKING:
    from collections.abc import Mapping


def _child(name: str) -> BaseAgent:
    """A minimal sub-agent (never run in these tests, only wrapped)."""
    return BaseAgent(name=name)


def _ctx(
    *,
    name: str = "shell",
    factory=build_sequential_agent,
    sub_agents: tuple[BaseAgent, ...] = (),
    metadata: dict[str, object] | None = None,
) -> AgentBuildContext:
    return AgentBuildContext(
        descriptor=AgentDescriptor(
            id=name,
            name=name,
            description=f"{name} shell",
            prompt_id=None,
            factory=factory,  # type: ignore[arg-type]
            sub_agent_ids=tuple(a.name for a in sub_agents),
            metadata=metadata or {},
        ),
        profile=RuntimeProfile.safe_default(),
        model=None,
        instruction="",
        tools=(),
        sub_agents=sub_agents,
        chain=CallbackChain.empty(),
    )


def test_build_sequential_agent_wraps_sub_agents_in_order() -> None:
    children = (_child("a"), _child("b"), _child("c"))

    agent = build_sequential_agent(_ctx(name="seq", sub_agents=children))

    assert isinstance(agent, SequentialAgent)
    assert agent.name == "seq"
    assert [sub.name for sub in agent.sub_agents] == ["a", "b", "c"]


def test_build_parallel_agent_is_a_parallel_shell() -> None:
    children = (_child("r2"), _child("ghidra"))

    agent = build_parallel_agent(
        _ctx(name="par", factory=build_parallel_agent, sub_agents=children)
    )

    assert isinstance(agent, ParallelAgent)
    assert agent.name == "par"
    assert {sub.name for sub in agent.sub_agents} == {"r2", "ghidra"}


def test_build_loop_agent_reads_max_iterations_from_metadata() -> None:
    agent = build_loop_agent(
        _ctx(
            name="loop",
            factory=build_loop_agent,
            sub_agents=(_child("recover"), _child("recheck")),
            metadata={"max_iterations": 3},
        )
    )

    assert isinstance(agent, LoopAgent)
    assert agent.max_iterations == 3


@pytest.mark.parametrize(
    "metadata",
    [None, {}, {"max_iterations": None}, {"max_iterations": 0}, {"max_iterations": -1}],
)
def test_build_loop_agent_requires_positive_int_max_iterations(metadata: object) -> None:
    with pytest.raises(InvalidCapabilityDescriptorError, match="max_iterations"):
        build_loop_agent(
            _ctx(
                name="loop",
                factory=build_loop_agent,
                sub_agents=(_child("recover"),),
                metadata=metadata if isinstance(metadata, dict) else None,  # type: ignore[arg-type]
            )
        )


def test_build_loop_agent_rejects_bool_max_iterations() -> None:
    """A bool is an int subclass but must not pass as an iteration count."""
    with pytest.raises(InvalidCapabilityDescriptorError, match="max_iterations"):
        build_loop_agent(
            _ctx(
                name="loop",
                factory=build_loop_agent,
                sub_agents=(_child("recover"),),
                metadata={"max_iterations": True},
            )
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("escalate", [True, False])
async def test_build_escalation_gate_emits_evaluator_decision(escalate: bool) -> None:
    seen: list[Mapping[str, object]] = []

    def evaluator(state: Mapping[str, object]) -> EscalationDecision:
        seen.append(state)
        return EscalationDecision(escalate=escalate, state_delta={"seen": True})

    agent = build_escalation_gate(_ctx(name="gate"), evaluator=evaluator)
    context = SimpleNamespace(
        session=SimpleNamespace(state={"ready": True}),
        invocation_id="inv-1",
        branch="case-1",
    )

    events = [event async for event in agent._run_async_impl(context)]

    assert seen == [{"ready": True}]
    assert len(events) == 1
    assert events[0].author == "gate"
    assert events[0].invocation_id == "inv-1"
    assert events[0].branch == "case-1"
    assert events[0].actions.escalate is escalate
    assert events[0].actions.state_delta == {"seen": True}


@pytest.mark.asyncio
async def test_build_escalation_gate_copies_state_delta_and_callbacks() -> None:
    state_delta = {"seen": True}

    def after_agent(_context: object) -> None:
        pass

    def evaluator(_state: Mapping[str, object]) -> EscalationDecision:
        return EscalationDecision(escalate=True, state_delta=state_delta)

    context = _ctx(name="gate")
    context = AgentBuildContext(
        descriptor=context.descriptor,
        profile=context.profile,
        model=context.model,
        instruction=context.instruction,
        tools=context.tools,
        sub_agents=context.sub_agents,
        chain=context.chain,
        after_agent=(after_agent,),
    )
    agent = build_escalation_gate(context, evaluator=evaluator)
    events = [
        event
        async for event in agent._run_async_impl(
            SimpleNamespace(
                session=SimpleNamespace(state={"ready": True}),
                invocation_id="inv-1",
                branch=None,
            )
        )
    ]

    assert agent.after_agent_callback == [after_agent]
    assert events[0].actions.state_delta == {"seen": True}
    assert events[0].actions.state_delta is not state_delta


@pytest.mark.asyncio
async def test_build_escalation_gate_propagates_evaluator_programming_errors() -> None:
    def evaluator(_state: Mapping[str, object]) -> EscalationDecision:
        raise RuntimeError("programming error")

    agent = build_escalation_gate(_ctx(name="gate"), evaluator=evaluator)
    context = SimpleNamespace(
        session=SimpleNamespace(state={"ready": True}), invocation_id="inv-1", branch=None
    )

    with pytest.raises(RuntimeError, match="programming error"):
        _ = [event async for event in agent._run_async_impl(context)]


@pytest.mark.asyncio
async def test_build_escalation_gate_propagates_invalid_state_delta_errors() -> None:
    def evaluator(_state: Mapping[str, object]) -> EscalationDecision:
        return EscalationDecision(escalate=True, state_delta=object())  # type: ignore[arg-type]

    agent = build_escalation_gate(_ctx(name="gate"), evaluator=evaluator)
    context = SimpleNamespace(
        session=SimpleNamespace(state={"ready": True}), invocation_id="inv-1", branch=None
    )

    with pytest.raises(TypeError):
        _ = [event async for event in agent._run_async_impl(context)]


@pytest.mark.asyncio
async def test_build_escalation_gate_runs_through_public_adk_path_and_callbacks() -> None:
    callbacks: list[str] = []

    def after_agent(callback_context: object) -> None:
        assert callback_context is not None
        callbacks.append("called")

    def evaluator(_state: Mapping[str, object]) -> EscalationDecision:
        return EscalationDecision(escalate=True, state_delta={"seen": True})

    context = _ctx(name="gate")
    agent = build_escalation_gate(
        AgentBuildContext(
            descriptor=context.descriptor,
            profile=context.profile,
            model=context.model,
            instruction=context.instruction,
            tools=context.tools,
            sub_agents=context.sub_agents,
            chain=context.chain,
            after_agent=(after_agent,),
        ),
        evaluator=evaluator,
    )
    session_service = InMemorySessionService()
    session = await session_service.create_session(
        app_name="test-app", user_id="test-user", state={"ready": True}
    )
    parent_context = InvocationContext(
        session_service=session_service,
        invocation_id="inv-public",
        branch="case-public",
        agent=agent,
        session=session,
    )

    events = [event async for event in agent.run_async(parent_context)]

    assert callbacks == ["called"]
    assert len(events) == 1
    assert events[0].branch == "case-public"
    assert events[0].actions.state_delta == {"seen": True}


def test_compose_agents_builds_a_sequential_root_over_llm_children() -> None:
    """compose_agents routes a prompt_id=None root through the composite branch.

    The root becomes a SequentialAgent whose children are the two LlmAgents built
    first (post-order). The shell has no model/instruction; children keep theirs.
    """
    from arema.core.config import Settings
    from arema.registry.catalog import CatalogBuilder
    from arema.runtime.agent_factory import build_llm_agent, compose_agents
    from arema.runtime.services import RuntimeServices

    class _FakeCheckpointSink:
        def append_checkpoint(self, *_args: object, **_kwargs: object) -> None:
            pass

    def _loader(prompt_id: str) -> str:
        return f"INSTRUCTION-FOR-{prompt_id}"

    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(
        AgentDescriptor(
            id="seq_root",
            name="seq_root",
            description="sequential root",
            prompt_id=None,
            factory=build_sequential_agent,
            sub_agent_ids=("first", "second"),
        )
    )
    builder.add_agent(
        AgentDescriptor(
            id="first",
            name="first",
            description="first child",
            prompt_id="first",
            factory=build_llm_agent,
            prompt_loader=_loader,
        )
    )
    builder.add_agent(
        AgentDescriptor(
            id="second",
            name="second",
            description="second child",
            prompt_id="second",
            factory=build_llm_agent,
            prompt_loader=_loader,
        )
    )
    catalog = builder.freeze("seq_root")

    built = compose_agents(
        catalog,
        settings=Settings(_env_file=None, llm_provider="ollama"),
        services=RuntimeServices.default(),
        checkpoint_sink=_FakeCheckpointSink(),  # type: ignore[arg-type]
    )

    root = built["seq_root"]
    assert isinstance(root, SequentialAgent)
    assert not isinstance(root, LlmAgent)
    assert [sub.name for sub in root.sub_agents] == ["first", "second"]
    # safe_default has record_memory=True → the shell records one pipeline-end checkpoint.
    assert root.after_agent_callback
    assert built["first"].instruction == "INSTRUCTION-FOR-first"
    assert built["second"].instruction == "INSTRUCTION-FOR-second"


def test_build_llm_agent_plumbs_output_schema_to_the_llm_agent() -> None:
    """A descriptor's output_schema reaches the built LlmAgent so ADK coerces it."""
    from pydantic import BaseModel

    from arema.core.config import Settings
    from arema.registry.catalog import CatalogBuilder
    from arema.runtime.agent_factory import build_llm_agent, compose_agents
    from arema.runtime.services import RuntimeServices

    class _Out(BaseModel):
        value: str

    class _FakeCheckpointSink:
        def append_checkpoint(self, *_args: object, **_kwargs: object) -> None:
            pass

    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(
        AgentDescriptor(
            id="coerced",
            name="coerced",
            description="structured output agent",
            prompt_id="coerced",
            factory=build_llm_agent,
            prompt_loader=lambda _pid: "INSTRUCTION",
            output_key="coerced_out",
            output_schema=_Out,
        )
    )
    built = compose_agents(
        builder.freeze("coerced"),
        settings=Settings(_env_file=None, llm_provider="ollama"),
        services=RuntimeServices.default(),
        checkpoint_sink=_FakeCheckpointSink(),  # type: ignore[arg-type]
    )
    assert built["coerced"].output_schema is _Out


def test_coerced_agent_fails_open_when_output_schema_validation_raises() -> None:
    """A non-conforming final turn degrades its own stage instead of aborting.

    ADK re-raises the pydantic ``ValidationError`` from ``output_schema`` when the
    model emits a non-JSON payload (e.g. prose on a redundant loop pass). The
    ``_CoercedLlmAgent`` override must swallow it and leave ``output_key`` unset so
    the enclosing SequentialAgent pipeline keeps running.
    """
    from google.adk.events import Event
    from google.genai import types
    from pydantic import BaseModel

    from arema.runtime.agent_factory import _CoercedLlmAgent

    class _Out(BaseModel):
        value: str

    agent = _CoercedLlmAgent(name="stage", model="mock", output_key="stage_out", output_schema=_Out)
    event = Event(author="stage", content=types.Content(parts=[types.Part(text="not json")]))

    # Must not raise despite the invalid payload.
    agent._LlmAgent__maybe_save_output_to_state(event)  # type: ignore[attr-defined]

    assert "stage_out" not in event.actions.state_delta


def test_output_schema_drops_fenced_json_but_no_schema_keeps_it() -> None:
    """Why no evidence stage declares ``output_schema``.

    The configured provider fences its JSON even when ADK sets
    ``response_mime_type`` to ``application/json`` and passes a
    ``response_schema``. ADK coerces with ``model_validate_json``, which cannot see
    through a fence: the stage output is dropped and its evidence is lost. Without
    ``output_schema`` the same text is stored verbatim, and the stage's after-agent
    normalizer parses it through the fence-tolerant ``loads_model_json`` boundary.
    """
    from google.adk.events import Event
    from google.genai import types
    from pydantic import BaseModel

    from arema.runtime.agent_factory import _CoercedLlmAgent

    class _Out(BaseModel):
        value: str

    fenced = '```json\n{"value": "ok"}\n```'

    with_schema = _CoercedLlmAgent(
        name="stage", model="mock", output_key="stage_out", output_schema=_Out
    )
    event = Event(author="stage", content=types.Content(parts=[types.Part(text=fenced)]))
    with_schema._LlmAgent__maybe_save_output_to_state(event)  # type: ignore[attr-defined]
    assert "stage_out" not in event.actions.state_delta

    without_schema = _CoercedLlmAgent(name="stage", model="mock", output_key="stage_out")
    event = Event(author="stage", content=types.Content(parts=[types.Part(text=fenced)]))
    without_schema._LlmAgent__maybe_save_output_to_state(event)  # type: ignore[attr-defined]
    assert event.actions.state_delta["stage_out"] == fenced


def test_empty_final_chunk_does_not_overwrite_a_stored_stage_output() -> None:
    """A streamed turn's empty tail event must not erase the real answer.

    ADK assigns the joined non-thought text unconditionally, guarding the empty
    case only on the ``output_schema`` path. Since no evidence stage declares a
    schema (LESSONS_LEARNED #16), an empty final chunk used to replace a good
    envelope with ``""``, and the stage reported ``evidence_envelope_invalid``.
    """
    from google.adk.events import Event
    from google.genai import types

    from arema.runtime.agent_factory import _CoercedLlmAgent

    agent = _CoercedLlmAgent(name="stage", model="mock", output_key="stage_out")

    real = Event(author="stage", content=types.Content(parts=[types.Part(text='{"a": 1}')]))
    agent._LlmAgent__maybe_save_output_to_state(real)  # type: ignore[attr-defined]
    assert real.actions.state_delta["stage_out"] == '{"a": 1}'

    for blank in ("", "   \n"):
        empty = Event(author="stage", content=types.Content(parts=[types.Part(text=blank)]))
        agent._LlmAgent__maybe_save_output_to_state(empty)  # type: ignore[attr-defined]
        assert "stage_out" not in empty.actions.state_delta, blank


def test_narrative_reasoning_never_becomes_the_stage_output() -> None:
    """Reasoning is not an answer: prose in the thought channel must not be stored,
    or a trailing reasoning-only event would overwrite what an earlier one saved."""
    from google.adk.events import Event
    from google.genai import types

    from arema.runtime.agent_factory import _CoercedLlmAgent

    agent = _CoercedLlmAgent(name="stage", model="mock", output_key="stage_out")
    event = Event(
        author="stage",
        content=types.Content(parts=[types.Part(text="Let me think about this", thought=True)]),
    )

    agent._LlmAgent__maybe_save_output_to_state(event)  # type: ignore[attr-defined]

    assert "stage_out" not in event.actions.state_delta


def test_an_answer_misrouted_into_the_reasoning_channel_is_salvaged() -> None:
    """A provider can put the WHOLE answer in the reasoning channel. ADK stores
    only non-thought text, so the stage produced nothing and its evidence was lost
    -- observed live with a complete envelope in the transcript and
    payload_type=NoneType in the log. Losing it is worse than storing it."""
    from google.adk.events import Event
    from google.genai import types

    from arema.runtime.agent_factory import _CoercedLlmAgent

    agent = _CoercedLlmAgent(name="stage", model="mock", output_key="stage_out")
    payload = 'Reasoning about it... {"artifact_id": "abc", "findings": []}'
    event = Event(
        author="stage",
        content=types.Content(parts=[types.Part(text=payload, thought=True)]),
    )

    agent._LlmAgent__maybe_save_output_to_state(event)  # type: ignore[attr-defined]

    assert event.actions.state_delta["stage_out"] == payload


def test_a_real_answer_still_wins_over_reasoning() -> None:
    """When both channels carry text, only the answer is stored."""
    from google.adk.events import Event
    from google.genai import types

    from arema.runtime.agent_factory import _CoercedLlmAgent

    agent = _CoercedLlmAgent(name="stage", model="mock", output_key="stage_out")
    event = Event(
        author="stage",
        content=types.Content(
            parts=[
                types.Part(text='{"thought": "draft"}', thought=True),
                types.Part(text='{"answer": "final"}'),
            ]
        ),
    )

    agent._LlmAgent__maybe_save_output_to_state(event)  # type: ignore[attr-defined]

    assert event.actions.state_delta["stage_out"] == '{"answer": "final"}'


def test_coerced_agent_still_saves_valid_structured_output() -> None:
    """Fail-open must not regress the happy path: valid JSON is coerced + stored."""
    from google.adk.events import Event
    from google.genai import types
    from pydantic import BaseModel

    from arema.runtime.agent_factory import _CoercedLlmAgent

    class _Out(BaseModel):
        value: str

    agent = _CoercedLlmAgent(name="stage", model="mock", output_key="stage_out", output_schema=_Out)
    event = Event(
        author="stage",
        content=types.Content(parts=[types.Part(text='{"value": "ok"}')]),
    )

    agent._LlmAgent__maybe_save_output_to_state(event)  # type: ignore[attr-defined]

    assert event.actions.state_delta["stage_out"] == {"value": "ok"}


def test_build_llm_agent_returns_a_fail_open_coerced_agent() -> None:
    """The factory wires every LlmAgent through the fail-open coercion subclass."""
    from arema.core.config import Settings
    from arema.registry.catalog import CatalogBuilder
    from arema.runtime.agent_factory import _CoercedLlmAgent, build_llm_agent, compose_agents
    from arema.runtime.services import RuntimeServices

    class _FakeCheckpointSink:
        def append_checkpoint(self, *_args: object, **_kwargs: object) -> None:
            pass

    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(
        AgentDescriptor(
            id="plain",
            name="plain",
            description="a neutral agent",
            prompt_id="plain",
            factory=build_llm_agent,
            prompt_loader=lambda _pid: "INSTRUCTION",
        )
    )
    built = compose_agents(
        builder.freeze("plain"),
        settings=Settings(_env_file=None, llm_provider="ollama"),
        services=RuntimeServices.default(),
        checkpoint_sink=_FakeCheckpointSink(),  # type: ignore[arg-type]
    )
    assert isinstance(built["plain"], _CoercedLlmAgent)


def test_output_schema_requires_output_key() -> None:
    from pydantic import BaseModel

    from arema.registry.errors import InvalidCapabilityDescriptorError
    from arema.runtime.agent_factory import build_llm_agent

    class _Out(BaseModel):
        value: str

    with pytest.raises(InvalidCapabilityDescriptorError):
        AgentDescriptor(
            id="bad",
            name="bad",
            description="schema without output_key",
            prompt_id="bad",
            factory=build_llm_agent,
            output_schema=_Out,
        )


def test_output_schema_with_tool_ids_is_rejected() -> None:
    from pydantic import BaseModel

    from arema.registry.errors import InvalidCapabilityDescriptorError
    from arema.runtime.agent_factory import build_llm_agent

    class _Out(BaseModel):
        value: str

    with pytest.raises(InvalidCapabilityDescriptorError, match="output_schema"):
        AgentDescriptor(
            id="bad",
            name="bad",
            description="schema with tools",
            prompt_id="bad",
            factory=build_llm_agent,
            output_key="bad_out",
            output_schema=_Out,
            tool_ids=("some_tool",),
        )


def test_output_schema_with_mcp_server_ids_is_rejected() -> None:
    from pydantic import BaseModel

    from arema.registry.errors import InvalidCapabilityDescriptorError
    from arema.runtime.agent_factory import build_llm_agent

    class _Out(BaseModel):
        value: str

    with pytest.raises(InvalidCapabilityDescriptorError, match="output_schema"):
        AgentDescriptor(
            id="bad",
            name="bad",
            description="schema with mcp servers",
            prompt_id="bad",
            factory=build_llm_agent,
            output_key="bad_out",
            output_schema=_Out,
            mcp_server_ids=("some_mcp",),
        )


def test_compose_agents_orders_custom_callbacks_before_checkpoints() -> None:
    from arema.core.config import Settings
    from arema.registry.catalog import CatalogBuilder
    from arema.runtime.agent_factory import build_llm_agent, compose_agents
    from arema.runtime.services import RuntimeServices

    class _FakeCheckpointSink:
        def append_checkpoint(self, *_args: object, **_kwargs: object) -> None:
            pass

    captured: dict[str, tuple[object, ...]] = {}

    def normalize(_context: object) -> None:
        pass

    def deterministic_factory(context: AgentBuildContext) -> BaseAgent:
        captured[context.descriptor.id] = context.after_agent
        return BaseAgent(name=context.descriptor.name)

    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(
        AgentDescriptor(
            id="root",
            name="root",
            description="root shell",
            prompt_id=None,
            factory=build_sequential_agent,
            sub_agent_ids=("llm", "gate"),
            after_agent_callbacks=(normalize,),  # type: ignore[arg-type]
        )
    )
    builder.add_agent(
        AgentDescriptor(
            id="llm",
            name="llm",
            description="llm child",
            prompt_id="llm",
            factory=build_llm_agent,
            prompt_loader=lambda _prompt_id: "instruction",
            after_agent_callbacks=(normalize,),  # type: ignore[arg-type]
        )
    )
    builder.add_agent(
        AgentDescriptor(
            id="gate",
            name="gate",
            description="deterministic child",
            prompt_id=None,
            factory=deterministic_factory,
            kind=AgentKind.DETERMINISTIC,
            after_agent_callbacks=(normalize,),  # type: ignore[arg-type]
        )
    )

    built = compose_agents(
        builder.freeze("root"),
        settings=Settings(_env_file=None, llm_provider="ollama"),
        services=RuntimeServices.default(),
        checkpoint_sink=_FakeCheckpointSink(),  # type: ignore[arg-type]
    )

    assert built["root"].after_agent_callback[0] is normalize
    assert built["llm"].after_agent_callback[0] is normalize
    assert captured["gate"][0] is normalize
    assert len(built["root"].after_agent_callback) == 2
    assert len(built["llm"].after_agent_callback) == 2
    assert len(captured["gate"]) == 2


@pytest.mark.asyncio
async def test_public_lifecycle_normalizes_state_before_checkpoint_recording() -> None:
    from arema.core.config import Settings
    from arema.registry.catalog import CatalogBuilder
    from arema.runtime.agent_factory import compose_agents
    from arema.runtime.services import RuntimeServices
    from arema.runtime.sessions import SessionKeys
    from reverse_engineering.agents.evidence_output import normalize_evidence_output
    from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY

    artifact_id = "a" * 64
    output_key = "analysis:evidence"

    class _RecordingCheckpointSink:
        def __init__(self) -> None:
            self.records: list[object] = []

        def append_checkpoint(
            self,
            _scope_id: str,
            checkpoint: object,
            *,
            source: str,
        ) -> None:
            assert source
            self.records.append(checkpoint)

    def normalize(callback_context: object) -> None:
        normalize_evidence_output(  # type: ignore[arg-type]
            callback_context,
            output_key=output_key,
            stage="triage",
        )
        state = callback_context.state  # type: ignore[attr-defined]
        normalized = state[output_key]
        state[SessionKeys.CONTEXT_CHECKPOINT] = {
            "label": "normalized",
            "state": {"coverage_status": normalized["coverage"]["status"]},
        }

    def deterministic_factory(context: AgentBuildContext) -> BaseAgent:
        return build_escalation_gate(
            context,
            evaluator=lambda _state: EscalationDecision(escalate=False),
        )

    sink = _RecordingCheckpointSink()
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(
        AgentDescriptor(
            id="gate",
            name="gate",
            description="deterministic normalization gate",
            prompt_id=None,
            factory=deterministic_factory,
            kind=AgentKind.DETERMINISTIC,
            after_agent_callbacks=(normalize,),  # type: ignore[arg-type]
        )
    )
    agent = compose_agents(
        builder.freeze("gate"),
        settings=Settings(_env_file=None, llm_provider="ollama"),
        services=RuntimeServices.default(),
        checkpoint_sink=sink,  # type: ignore[arg-type]
    )["gate"]
    session_service = InMemorySessionService()
    session = await session_service.create_session(
        app_name="test-app",
        user_id="test-user",
        state={
            CURRENT_ARTIFACT_KEY: artifact_id,
            output_key: {
                "artifact_id": artifact_id,
                "coverage": {
                    "status": "complete",
                    "surfaces": ["imports"],
                    "limitations": [],
                },
                "findings": [],
            },
            SessionKeys.MEMORY_SCOPE_ID: "scope-1",
        },
    )
    invocation = InvocationContext(
        session_service=session_service,
        invocation_id="inv-normalize",
        agent=agent,
        session=session,
    )

    _ = [event async for event in agent.run_async(invocation)]

    assert len(sink.records) == 1
    assert sink.records[0].state == {"coverage_status": "complete"}  # type: ignore[attr-defined]


def test_compose_agents_uses_only_descriptor_callbacks_without_memory_recording() -> None:
    from arema.core.config import Settings
    from arema.registry.catalog import CatalogBuilder
    from arema.runtime.agent_factory import build_llm_agent, compose_agents
    from arema.runtime.services import RuntimeServices

    class _FakeCheckpointSink:
        def append_checkpoint(self, *_args: object, **_kwargs: object) -> None:
            pass

    def normalize(_context: object) -> None:
        pass

    profile = RuntimeProfile(id="no_memory", record_memory=False)
    builder = CatalogBuilder()
    builder.add_runtime_profile(profile)
    builder.add_agent(
        AgentDescriptor(
            id="llm",
            name="llm",
            description="llm agent",
            prompt_id="llm",
            factory=build_llm_agent,
            runtime_profile_id=profile.id,
            prompt_loader=lambda _prompt_id: "instruction",
            after_agent_callbacks=(normalize,),  # type: ignore[arg-type]
        )
    )

    built = compose_agents(
        builder.freeze("llm"),
        settings=Settings(_env_file=None, llm_provider="ollama"),
        services=RuntimeServices.default(),
        checkpoint_sink=_FakeCheckpointSink(),  # type: ignore[arg-type]
    )

    assert built["llm"].after_agent_callback == [normalize]
