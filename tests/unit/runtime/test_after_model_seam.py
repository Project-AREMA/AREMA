from __future__ import annotations

import asyncio
from types import SimpleNamespace

from arema.runtime.callbacks.chain import CallbackChain, build_callback_chain
from arema.runtime.callbacks.metrics import make_model_usage_token_recorder
from arema.runtime.services import RuntimeServices
from arema.runtime.sessions import SessionKeys
from arema.runtime.token_usage import UsageSample  # noqa: F401


def test_empty_chain_has_after_model() -> None:
    chain = CallbackChain.empty()
    assert chain.after_model == ()


def test_build_chain_after_model_is_tuple() -> None:
    # A profile with metrics off still yields a valid (empty) after_model tuple.
    from arema.registry.descriptors import RuntimeProfile

    profile = RuntimeProfile(id="p", record_metrics=False)
    chain = build_callback_chain(profile, services=RuntimeServices.default(), tools={})
    assert isinstance(chain.after_model, tuple)


def test_llm_agent_wires_after_model_callback() -> None:
    from arema.registry.descriptors import RuntimeProfile
    from arema.runtime.agent_factory import AgentBuildContext, build_llm_agent

    profile = RuntimeProfile(id="p")
    chain = build_callback_chain(profile, services=RuntimeServices.default(), tools={})
    # Minimal build context with a string model (no provider call at construction).
    from arema.registry.descriptors import AgentDescriptor

    descriptor = AgentDescriptor(
        id="a",
        name="a",
        description="d",
        prompt_id="a",
        factory=build_llm_agent,
        runtime_profile_id="p",
    )
    ctx = AgentBuildContext(
        descriptor=descriptor,
        profile=profile,
        model="gemini-2.0-flash",
        instruction="hi",
        tools=(),
        sub_agents=(),
        chain=chain,
    )
    agent = build_llm_agent(ctx)
    # ADK stores the list under after_model_callback.
    assert list(agent.after_model_callback or []) == list(chain.after_model)


class _RecState:
    def __init__(self, initial=None):
        self._d = dict(initial or {})

    def get(self, key, default=None):
        return self._d.get(key, default)

    def __setitem__(self, key, value):
        self._d[key] = value


def _ctx(state, agent_name="a", invocation_id="inv-1"):
    return SimpleNamespace(state=state, agent_name=agent_name, invocation_id=invocation_id)


def _model_key(agent_name="a"):
    # Mirror metrics._current_model_key: the handoff slot is per-agent.
    return f"{SessionKeys.CURRENT_MODEL}:{agent_name}"


def test_after_model_recorder_accumulates() -> None:
    state = _RecState({_model_key(): "opus", SessionKeys.RUN_ID: "r1"})
    recorder = make_model_usage_token_recorder(RuntimeServices.default())
    resp = SimpleNamespace(
        usage_metadata=SimpleNamespace(
            prompt_token_count=100,
            cached_content_token_count=40,
            candidates_token_count=10,
            thoughts_token_count=0,
            total_token_count=110,
        )
    )
    asyncio.run(recorder(callback_context=_ctx(state), llm_response=resp))
    acc = state.get(SessionKeys.MODEL_USAGE)
    assert acc["by_model"]["opus"] == {"input": 60, "cached": 40, "output": 10, "thinking": 0}


def test_after_model_recorder_fail_open_no_usage() -> None:
    state = _RecState({_model_key(): "opus"})
    recorder = make_model_usage_token_recorder(RuntimeServices.default())
    resp = SimpleNamespace(usage_metadata=None)
    asyncio.run(recorder(callback_context=_ctx(state), llm_response=resp))  # no raise
    assert state.get(SessionKeys.MODEL_USAGE) is None


def test_after_model_recorder_fail_open_no_model() -> None:
    state = _RecState({SessionKeys.RUN_ID: "r1"})  # no CURRENT_MODEL
    recorder = make_model_usage_token_recorder(RuntimeServices.default())
    resp = SimpleNamespace(
        usage_metadata=SimpleNamespace(
            prompt_token_count=1, candidates_token_count=1, total_token_count=2
        )
    )
    asyncio.run(recorder(callback_context=_ctx(state), llm_response=resp))
    assert state.get(SessionKeys.MODEL_USAGE) is None


def test_before_model_recorder_stashes_per_agent_model() -> None:
    from arema.runtime.callbacks.metrics import make_model_usage_recorder

    state = _RecState()
    before = make_model_usage_recorder(RuntimeServices.default())
    req = SimpleNamespace(model="anthropic/claude-opus-4-8")
    asyncio.run(before(callback_context=_ctx(state, "recon"), llm_request=req))
    assert state.get(_model_key("recon")) == "anthropic/claude-opus-4-8"


def test_before_then_after_model_handoff_populates_accumulator() -> None:
    # Wire the real before-model stash to the real after-model recorder against
    # one shared state (no manual model seeding) to prove the seam end to end.
    from arema.runtime.callbacks.metrics import make_model_usage_recorder

    state = _RecState({SessionKeys.RUN_ID: "r1"})
    before = make_model_usage_recorder(RuntimeServices.default())
    after = make_model_usage_token_recorder(RuntimeServices.default())
    ctx = _ctx(state, "host_indicators")
    asyncio.run(before(callback_context=ctx, llm_request=SimpleNamespace(model="opus")))
    resp = SimpleNamespace(
        usage_metadata=SimpleNamespace(
            prompt_token_count=100,
            cached_content_token_count=40,
            candidates_token_count=10,
            thoughts_token_count=0,
            total_token_count=110,
        )
    )
    asyncio.run(after(callback_context=ctx, llm_response=resp))
    acc = state.get(SessionKeys.MODEL_USAGE)
    assert acc["by_model"]["opus"] == {"input": 60, "cached": 40, "output": 10, "thinking": 0}


def _resp(prompt: int, candidates: int) -> object:
    return SimpleNamespace(
        usage_metadata=SimpleNamespace(
            prompt_token_count=prompt,
            cached_content_token_count=0,
            candidates_token_count=candidates,
            thoughts_token_count=0,
            total_token_count=prompt + candidates,
        )
    )


def test_parallel_branches_do_not_clobber_model_attribution() -> None:
    # Simulate ioc_extraction's ParallelAgent: two branches on different models
    # share one session.state, both before-model fire while the model calls are
    # still awaiting, then both after-model resolve. A single shared slot would
    # attribute host's tokens to net-model; the per-agent slot keeps them split.
    from arema.runtime.callbacks.metrics import make_model_usage_recorder

    state = _RecState({SessionKeys.RUN_ID: "r1"})
    before = make_model_usage_recorder(RuntimeServices.default())
    after = make_model_usage_token_recorder(RuntimeServices.default())
    host = _ctx(state, "host_indicators")
    net = _ctx(state, "network_indicators")

    asyncio.run(before(callback_context=host, llm_request=SimpleNamespace(model="host-model")))
    asyncio.run(before(callback_context=net, llm_request=SimpleNamespace(model="net-model")))
    asyncio.run(after(callback_context=host, llm_response=_resp(100, 100)))
    asyncio.run(after(callback_context=net, llm_response=_resp(200, 200)))

    acc = state.get(SessionKeys.MODEL_USAGE)
    assert set(acc["by_model"]) == {"host-model", "net-model"}
    assert acc["by_model"]["host-model"]["input"] == 100
    assert acc["by_model"]["net-model"]["input"] == 200


def test_adk_invocation_scope_resets_between_invocations() -> None:
    # The adk run / adk web path never seeds RUN_ID, so the recorder scopes on
    # ADK's invocation_id. A second analysis in the SAME reused session runs
    # under a new invocation_id, which must reset the accumulator rather than
    # fold onto the first analysis.
    state = _RecState()  # no RUN_ID
    after = make_model_usage_token_recorder(RuntimeServices.default())

    state[_model_key()] = "opus"
    asyncio.run(
        after(callback_context=_ctx(state, invocation_id="inv-A"), llm_response=_resp(100, 0))
    )
    state[_model_key()] = "opus"
    asyncio.run(
        after(callback_context=_ctx(state, invocation_id="inv-B"), llm_response=_resp(80, 0))
    )

    acc = state.get(SessionKeys.MODEL_USAGE)
    assert acc["run_id"] == "inv-B"
    # 80 (this invocation only), never 180 (cumulative — the bug the reset prevents)
    assert acc["by_model"]["opus"]["input"] == 80


def test_chain_includes_token_recorder_when_metrics_on() -> None:
    from arema.registry.descriptors import RuntimeProfile
    from arema.runtime.callbacks.roles import ROLE_RECORD_MODEL_TOKENS, callback_role

    profile = RuntimeProfile(id="p", record_metrics=True)
    chain = build_callback_chain(profile, services=RuntimeServices.default(), tools={})
    roles = [callback_role(cb) for cb in chain.after_model]
    assert ROLE_RECORD_MODEL_TOKENS in roles


def test_chain_excludes_token_recorder_when_metrics_off() -> None:
    from arema.registry.descriptors import RuntimeProfile

    profile = RuntimeProfile(id="p", record_metrics=False)
    chain = build_callback_chain(profile, services=RuntimeServices.default(), tools={})
    assert chain.after_model == ()
