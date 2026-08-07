"""Generic construction of ADK agents from validated capability descriptors.

This module is the seam between the immutable capability catalog and concrete
ADK agents. It defines the two build contexts descriptors reference under
``TYPE_CHECKING`` (:class:`ToolBuildContext`, :class:`AgentBuildContext`),
turns one resolved :class:`AgentBuildContext` into an ADK ``LlmAgent`` via
:func:`build_llm_agent`, and walks a catalog in dependency order via
:func:`compose_agents` -- resolving each agent's model, instruction, tools,
sub-agents, and validated callback chain before delegating construction to the
descriptor's factory.

Nothing here mutates the catalog: every collection resolved for an agent is a
fresh tuple, and the callback chain is built anew per agent from its profile.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator, Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, cast

from google.adk.agents import BaseAgent, LlmAgent, LoopAgent, ParallelAgent, SequentialAgent
from google.adk.events import Event, EventActions
from google.genai.types import Content, Part
from pydantic import ValidationError

from arema.core.config import get_settings
from arema.core.logging import get_logger
from arema.core.model_factory import get_agent_model
from arema.prompts.loader import load_prompt
from arema.registry.descriptors import AfterAgentCallback as DescriptorAfterAgentCallback
from arema.registry.descriptors import ContextMode
from arema.registry.errors import InvalidCapabilityDescriptorError
from arema.registry.mcp import build_mcp_toolset
from arema.runtime.callbacks.chain import CallbackChain, build_callback_chain, compose_after_tool
from arema.runtime.services import make_checkpoint_recorder
from arema.runtime.sessions import SessionKeys
from arema.runtime.token_pricing import PriceTable
from arema.runtime.token_usage import build_usage_record, render_usage_markdown

if TYPE_CHECKING:
    from google.adk.agents.base_agent import AfterAgentCallback
    from google.adk.agents.invocation_context import InvocationContext
    from google.adk.agents.llm_agent import (
        AfterModelCallback as AdkAfterModelCallback,
    )
    from google.adk.agents.llm_agent import (
        AfterToolCallback as AdkAfterToolCallback,
    )
    from google.adk.agents.llm_agent import (
        BeforeModelCallback as AdkBeforeModelCallback,
    )
    from google.adk.agents.llm_agent import (
        BeforeToolCallback as AdkBeforeToolCallback,
    )
    from google.adk.agents.llm_agent import (
        OnModelErrorCallback as AdkOnModelErrorCallback,
    )
    from google.adk.agents.llm_agent import (
        OnToolErrorCallback as AdkOnToolErrorCallback,
    )
    from google.adk.models.lite_llm import LiteLlm

    from arema.core.config import Settings
    from arema.registry.catalog import CapabilityCatalog
    from arema.registry.descriptors import (
        AgentDescriptor,
        RuntimeProfile,
        ToolDescriptor,
        ToolLike,
    )
    from arema.runtime.services import MemoryCheckpointSink, RuntimeServices

logger = get_logger(__name__)

__all__ = [
    "AgentBuildContext",
    "EscalationDecision",
    "ToolBuildContext",
    "build_escalation_gate",
    "build_llm_agent",
    "build_loop_agent",
    "build_parallel_agent",
    "build_sequential_agent",
    "build_token_usage_reporter",
    "compose_agents",
]


@dataclass(frozen=True, slots=True)
class ToolBuildContext:
    """Inputs a deferred tool factory needs to build one concrete tool.

    Supplied only when a :class:`~arema.registry.descriptors.ToolDescriptor`
    selects a ``factory`` instead of a concrete ``tool``; the frozen catalog is
    provided read-only so a factory can inspect sibling capabilities without
    ever mutating them.
    """

    settings: Settings
    services: RuntimeServices
    catalog: CapabilityCatalog


@dataclass(frozen=True, slots=True)
class AgentBuildContext:
    """Everything resolved for one agent, ready for an :class:`AgentFactory`."""

    descriptor: AgentDescriptor
    profile: RuntimeProfile
    model: str | LiteLlm | None
    instruction: str
    tools: tuple[ToolLike, ...]
    sub_agents: tuple[BaseAgent, ...]
    chain: CallbackChain
    output_key: str | None = None
    after_agent: tuple[DescriptorAfterAgentCallback, ...] = ()


@dataclass(frozen=True, slots=True)
class EscalationDecision:
    """A deterministic gate's escalation outcome and session-state update."""

    escalate: bool
    state_delta: Mapping[str, object] = field(default_factory=dict)


EscalationEvaluator = Callable[[Mapping[str, object]], EscalationDecision]


class _EscalationGate(BaseAgent):
    """Minimal ADK agent that turns one deterministic decision into one event."""

    evaluator: EscalationEvaluator

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        decision = self.evaluator(ctx.session.state)
        yield Event(
            author=self.name,
            invocation_id=ctx.invocation_id,
            branch=ctx.branch,
            actions=EventActions(
                escalate=decision.escalate,
                state_delta=dict(decision.state_delta),
            ),
        )


def build_escalation_gate(
    context: AgentBuildContext, *, evaluator: EscalationEvaluator
) -> BaseAgent:
    """Construct a deterministic single-event escalation gate."""
    return _EscalationGate(
        name=context.descriptor.name,
        description=context.descriptor.description,
        evaluator=evaluator,
        after_agent_callback=list(context.after_agent),
    )


class _TokenUsageReporter(BaseAgent):
    """Deterministic final stage: render per-model token usage as one message."""

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        state = ctx.session.state
        getter = getattr(state, "get", None)
        acc = getter(SessionKeys.MODEL_USAGE, None) if callable(getter) else None
        by_model = acc.get("by_model", {}) if isinstance(acc, dict) else {}
        run_id = acc.get("run_id") if isinstance(acc, dict) else None
        prices = PriceTable.from_settings(get_settings())
        markdown = render_usage_markdown(by_model, prices)
        record = build_usage_record(by_model, prices, run_id)
        yield Event(
            author=self.name,
            invocation_id=ctx.invocation_id,
            branch=ctx.branch,
            content=Content(role="model", parts=[Part(text=markdown)]),
            actions=EventActions(state_delta={SessionKeys.TOKEN_USAGE_RECORD: record}),
        )


def build_token_usage_reporter(context: AgentBuildContext) -> BaseAgent:
    """Construct the deterministic per-model token-usage reporter."""
    return _TokenUsageReporter(
        name=context.descriptor.name,
        description=context.descriptor.description,
        after_agent_callback=list(context.after_agent),
    )


# ADK's LlmAgent validates the final model response against ``output_schema`` in
# its private ``__maybe_save_output_to_state`` hook (name-mangled to
# ``_LlmAgent__maybe_save_output_to_state``) and re-raises the pydantic
# ``ValidationError`` if the model emitted a non-conforming payload -- e.g. prose
# instead of the structured tool call on a redundant loop pass. Left unhandled,
# that single bad turn aborts the entire SequentialAgent pipeline. This guard
# fails loud at import time if a future ADK release renames that hook, so the
# subclass below can never silently stop intercepting it.
_ADK_OUTPUT_SAVE_HOOK = "_LlmAgent__maybe_save_output_to_state"
if not hasattr(LlmAgent, _ADK_OUTPUT_SAVE_HOOK):  # pragma: no cover - defensive
    raise RuntimeError(
        "ADK LlmAgent no longer exposes "
        f"{_ADK_OUTPUT_SAVE_HOOK!r}; _CoercedLlmAgent's fail-open output_schema "
        "override must be updated for this ADK version."
    )


def _reasoning_only_text(event: Event) -> str:
    """Text a provider put in the reasoning channel when it answered nowhere else.

    ADK stores only non-``thought`` parts, which is correct: reasoning is not an
    answer. But a provider can misroute the WHOLE answer into that channel, and
    then the stage stores nothing and its evidence is lost -- observed live with a
    complete, well-formed envelope visible in the transcript and
    ``payload_type=NoneType`` in the log. Returning it is strictly better than
    losing the stage: it is the only answer the turn produced, and every consumer
    validates it against the strict schema anyway.

    Narrative reasoning is NOT an answer, so only reasoning that actually carries a
    structured payload qualifies. Without that constraint a trailing
    reasoning-only event could overwrite an answer an earlier event already stored
    -- the exact clobber this class exists to prevent.
    """
    if not event.content or not event.content.parts:
        return ""
    text = "".join(part.text for part in event.content.parts if part.text and part.thought).strip()
    return text if "{" in text and "}" in text else ""


def _event_text_is_blank(event: Event) -> bool:
    """Whether the event carries no non-thought text for ADK to store.

    Mirrors ADK's own join in ``__maybe_save_output_to_state``: reasoning parts
    (``thought``) are excluded, so a turn that is pure reasoning counts as blank.
    A non-final event is never a save candidate and is reported blank so the
    caller returns before ADK's own ``is_final_response`` check.
    """
    if not event.is_final_response() or not event.content or not event.content.parts:
        return True
    return not "".join(
        part.text for part in event.content.parts if part.text and not part.thought
    ).strip()


class _CoercedLlmAgent(LlmAgent):
    """``LlmAgent`` whose output save fails open instead of aborting or clobbering.

    Two narrow corrections to ADK's save hook, both keeping one stage's bad turn
    from costing the run its evidence:

    **A non-conforming payload must not abort the pipeline.** With an
    ``output_schema``, ADK raises the pydantic ``ValidationError``, which
    propagates out of the enclosing ``SequentialAgent`` and kills every downstream
    stage. It is swallowed here so the stage's ``output_key`` is simply left unset,
    the after-agent normalizer records a coverage limitation for that stage, and
    the pipeline continues to a degradation-aware report.

    **An empty final chunk must not overwrite a real answer.** ADK joins the
    final event's non-thought text and assigns it unconditionally; a streamed turn
    whose last event carries no text therefore replaces a good payload with ``""``.
    ADK guards this only on the ``output_schema`` path (see its own "empty final
    chunk of a stream" comment), so agents without a schema -- which is every
    evidence stage, per LESSONS_LEARNED #16 -- were exposed: an empty tail chunk
    silently erased the stage's findings and the run reported
    ``<stage>:evidence_envelope_invalid``. The guard is applied to both paths.
    """

    def _LlmAgent__maybe_save_output_to_state(self, event: Event) -> None:
        if self.output_key and _event_text_is_blank(event):
            # Only the final event is a save candidate; anything else is not this
            # hook's business and must fall through untouched.
            if not event.is_final_response():
                return
            salvaged = _reasoning_only_text(event) if self.output_schema is None else ""
            if salvaged:
                logger.warning(
                    "the model answered only in its reasoning channel; storing that "
                    "rather than losing the stage output",
                    agent_name=self.name,
                    output_key=self.output_key,
                    chars=len(salvaged),
                )
                event.actions.state_delta[self.output_key] = salvaged
                return
            logger.debug(
                "skipping empty final chunk so it cannot overwrite the stage output",
                agent_name=self.name,
                output_key=self.output_key,
                had_reasoning_text=bool(_reasoning_only_text(event)),
            )
            return
        try:
            super()._LlmAgent__maybe_save_output_to_state(event)  # type: ignore[misc]
        except ValidationError as exc:
            logger.warning(
                "output_schema coercion failed; leaving stage output unset so the "
                "pipeline fails open instead of aborting downstream stages",
                agent_name=self.name,
                output_key=self.output_key,
                error_type=type(exc).__name__,
            )


def build_llm_agent(context: AgentBuildContext) -> LlmAgent:
    """Construct an ADK ``LlmAgent`` from a fully resolved build context.

    Maps the profile's context mode onto ADK's ``include_contents`` (history →
    ``"default"``, isolated → ``"none"``) and wires every callback list from the
    validated chain, including both the tool-error and model-error handlers.
    """
    assert context.model is not None, (
        "build_llm_agent requires a resolved model; composite descriptors "
        "(prompt_id=None) are routed to build_sequential_agent / "
        "build_parallel_agent / build_loop_agent, not here."
    )
    include_contents: Literal["default", "none"] = (
        "none" if context.profile.context_mode is ContextMode.ISOLATED else "default"
    )
    chain = context.chain
    # Hand ADK a single composed after-tool callback, not the raw list: ADK stops
    # walking its after-tool list at the first truthy return, which would skip
    # every step after the SanitizationMembrane (including compaction). The
    # composite runs the whole validated chain in order. The list stays intact on
    # the CallbackChain, so the ordering invariants are still validated on it.
    composed_after_tool = compose_after_tool(chain.after_tool)
    return _CoercedLlmAgent(
        name=context.descriptor.name,
        model=context.model,
        description=context.descriptor.description,
        instruction=context.instruction,
        include_contents=include_contents,
        tools=list(context.tools),
        sub_agents=list(context.sub_agents),
        before_model_callback=cast("AdkBeforeModelCallback", list(chain.before_model)),
        after_model_callback=cast("AdkAfterModelCallback", list(chain.after_model)),
        before_tool_callback=cast("AdkBeforeToolCallback", list(chain.before_tool)),
        after_tool_callback=cast("AdkAfterToolCallback", composed_after_tool),
        on_tool_error_callback=cast("AdkOnToolErrorCallback", list(chain.on_tool_error)),
        on_model_error_callback=cast("AdkOnModelErrorCallback", list(chain.on_model_error)),
        after_agent_callback=cast("AfterAgentCallback", list(context.after_agent)),
        output_key=context.output_key,
        output_schema=context.descriptor.output_schema,
    )


def build_sequential_agent(context: AgentBuildContext) -> SequentialAgent:
    """Construct an ADK ``SequentialAgent`` shell from a resolved build context.

    The shell runs its sub-agents in fixed order, each to completion, sharing one
    session — framework-enforced orchestration that replaces prompt-directed
    ``transfer_to_agent`` chains (which loop on complex tasks). The shell carries
    no model, instruction, or tools; only its name, description, ordered
    sub-agents, and the optional pipeline-end ``after_agent`` callbacks matter.
    """
    return SequentialAgent(
        name=context.descriptor.name,
        description=context.descriptor.description,
        sub_agents=list(context.sub_agents),
        after_agent_callback=list(context.after_agent),
    )


def build_parallel_agent(context: AgentBuildContext) -> ParallelAgent:
    """Construct an ADK ``ParallelAgent`` shell from a resolved build context.

    Sub-agents run concurrently in isolated branches and join when all finish
    (NORTH_STAR Axis-2 consensus shape). Shares the SequentialAgent constructor
    surface; ignores model/instruction/tools. Foundation for a later slice.
    """
    return ParallelAgent(
        name=context.descriptor.name,
        description=context.descriptor.description,
        sub_agents=list(context.sub_agents),
        after_agent_callback=list(context.after_agent),
    )


def build_loop_agent(context: AgentBuildContext) -> LoopAgent:
    """Construct an ADK ``LoopAgent`` shell from a resolved build context.

    Loops its sub-agents until one escalates or ``max_iterations`` is reached.
    NORTH_STAR mandates loops be capped (deobfuscation loop, max 3), so
    ``metadata['max_iterations']`` MUST be a positive integer; the factory raises
    at build time otherwise. Foundation for a later slice.
    """
    raw = context.descriptor.metadata.get("max_iterations")
    if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
        raise InvalidCapabilityDescriptorError(
            f"LoopAgent '{context.descriptor.id}' requires "
            "metadata['max_iterations'] to be a positive integer "
            "(NORTH_STAR: loops must be capped)."
        )
    return LoopAgent(
        name=context.descriptor.name,
        description=context.descriptor.description,
        sub_agents=list(context.sub_agents),
        max_iterations=raw,
        after_agent_callback=list(context.after_agent),
    )


def _resolve_tool(descriptor: ToolDescriptor, tool_context: ToolBuildContext) -> ToolLike:
    """Return a concrete tool for one descriptor, building it lazily if deferred."""
    if descriptor.tool is not None:
        return descriptor.tool
    if descriptor.factory is not None:
        return descriptor.factory(tool_context)
    # Catalog validation guarantees exactly one of tool/factory; defensive only.
    raise ValueError(f"tool '{descriptor.id}' has neither a concrete tool nor a factory")


def _build_agent(
    descriptor: AgentDescriptor,
    *,
    catalog: CapabilityCatalog,
    settings: Settings,
    services: RuntimeServices,
    checkpoint_sink: MemoryCheckpointSink,
    built: dict[str, BaseAgent],
) -> BaseAgent:
    """Resolve one agent's dependencies and delegate to its factory.

    A prompt-less descriptor (a composite shell or deterministic leaf) has no
    model, instruction, tools, or tool callbacks, so only its sub-agents and the
    optional pipeline-end ``after_agent`` callbacks are resolved before delegating
    to its factory.
    """
    profile = catalog.runtime_profiles[descriptor.runtime_profile_id]
    sub_agents = tuple(built[sub_agent_id] for sub_agent_id in descriptor.sub_agent_ids)
    checkpoint_callbacks = cast(
        "tuple[DescriptorAfterAgentCallback, ...]",
        (make_checkpoint_recorder(checkpoint_sink),) if profile.record_memory else (),
    )
    after_agent = descriptor.after_agent_callbacks + checkpoint_callbacks

    if descriptor.prompt_id is None:
        build_context = AgentBuildContext(
            descriptor=descriptor,
            profile=profile,
            model=None,
            instruction="",
            tools=(),
            sub_agents=sub_agents,
            chain=CallbackChain.empty(),
            after_agent=after_agent,
        )
        return descriptor.factory(build_context)

    tool_context = ToolBuildContext(settings=settings, services=services, catalog=catalog)
    tool_descriptors = {tool_id: catalog.tools[tool_id] for tool_id in descriptor.tool_ids}
    tools = tuple(
        _resolve_tool(tool_descriptors[tool_id], tool_context) for tool_id in descriptor.tool_ids
    ) + tuple(
        build_mcp_toolset(catalog.mcp_servers[mcp_id], environment=dict(os.environ))
        for mcp_id in descriptor.mcp_server_ids
    )
    chain = build_callback_chain(profile, services=services, tools=tool_descriptors)
    # An LlmAgent requires an instruction; the composite branch above
    # short-circuited prompt-less agents, so prompt_id is non-None here.
    assert descriptor.prompt_id is not None
    if descriptor.prompt_loader is not None:
        instruction = descriptor.prompt_loader(descriptor.prompt_id)
    else:
        instruction = load_prompt(descriptor.prompt_id)
    model = get_agent_model(descriptor.id, settings=settings, use_retries=profile.retry_model)

    build_context = AgentBuildContext(
        descriptor=descriptor,
        profile=profile,
        model=model,
        instruction=instruction,
        tools=tools,
        sub_agents=sub_agents,
        chain=chain,
        output_key=descriptor.output_key,
        after_agent=after_agent,
    )
    return descriptor.factory(build_context)


def compose_agents(
    catalog: CapabilityCatalog,
    *,
    settings: Settings,
    services: RuntimeServices,
    checkpoint_sink: MemoryCheckpointSink,
) -> dict[str, BaseAgent]:
    """Build every catalog agent in dependency order, sub-agents first.

    Returns a mapping from agent id to its built ADK agent. The catalog is
    already validated as acyclic and fully reachable from the root, so a
    post-order walk from the root produces a safe construction order where each
    agent's sub-agents are built before the agent itself.
    """
    built: dict[str, BaseAgent] = {}
    order: list[str] = []
    seen: set[str] = set()

    def visit(agent_id: str) -> None:
        if agent_id in seen:
            return
        seen.add(agent_id)
        for sub_agent_id in catalog.agents[agent_id].sub_agent_ids:
            visit(sub_agent_id)
        order.append(agent_id)

    visit(catalog.root_agent_id)

    for agent_id in order:
        built[agent_id] = _build_agent(
            catalog.agents[agent_id],
            catalog=catalog,
            settings=settings,
            services=services,
            checkpoint_sink=checkpoint_sink,
            built=built,
        )
    return built
