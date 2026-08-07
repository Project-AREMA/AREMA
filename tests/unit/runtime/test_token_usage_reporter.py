from __future__ import annotations

import asyncio
from types import SimpleNamespace

from arema.registry.descriptors import AgentDescriptor, RuntimeProfile
from arema.runtime.agent_factory import AgentBuildContext, build_token_usage_reporter
from arema.runtime.callbacks.chain import CallbackChain
from arema.runtime.sessions import SessionKeys


def _reporter():
    descriptor = AgentDescriptor(
        id="token_usage_reporter",
        name="token_usage_reporter",
        description="Renders per-model token usage.",
        prompt_id=None,
        factory=build_token_usage_reporter,
        runtime_profile_id="p",
    )
    ctx = AgentBuildContext(
        descriptor=descriptor,
        profile=RuntimeProfile(id="p"),
        model=None,
        instruction="",
        tools=(),
        sub_agents=(),
        chain=CallbackChain.empty(),
    )
    return build_token_usage_reporter(ctx)


def _run(agent, state):
    ctx = SimpleNamespace(session=SimpleNamespace(state=state), invocation_id="i", branch=None)

    async def collect():
        return [ev async for ev in agent._run_async_impl(ctx)]

    return asyncio.run(collect())


def test_reporter_emits_table_and_record() -> None:
    state = {
        SessionKeys.MODEL_USAGE: {
            "run_id": "r1",
            "by_model": {
                "claude-opus-4-8": {
                    "input": 171894,
                    "cached": 640110,
                    "output": 41220,
                    "thinking": 12880,
                }
            },
        }
    }
    events = _run(_reporter(), state)
    assert len(events) == 1
    text = events[0].content.parts[0].text
    assert "## Token Usage & Cost" in text and "claude-opus-4-8" in text
    delta = events[0].actions.state_delta
    assert SessionKeys.TOKEN_USAGE_RECORD in delta
    assert delta[SessionKeys.TOKEN_USAGE_RECORD]["grand_total"]["total"] == 866104


def test_reporter_empty_accumulator_neutral_line() -> None:
    events = _run(_reporter(), {})
    assert len(events) == 1
    assert "No model usage was recorded" in events[0].content.parts[0].text
