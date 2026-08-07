# SequentialAgent Orchestration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace prompt-directed agent transfers with framework-enforced `SequentialAgent` orchestration so the RE pipeline cannot loop on complex binaries, and land the composite-agent factory foundation (`build_sequential_agent` + `build_parallel_agent` + `build_loop_agent`) in the neutral core.

**Architecture:** `reverse_engineer` becomes an ADK `SequentialAgent` shell whose five children (`sample_intake` → `triage_recon` → `deep_decompile` → `evidence_critic` → `report_generator`) run in fixed order sharing one session. The neutral-core factory gains three composite factories (only `build_sequential_agent` is wired to an agent this slice; `build_parallel_agent` / `build_loop_agent` ship as the ready foundation for NORTH_STAR Axis-2 consensus and the deobfuscation loop). An agent descriptor with `prompt_id=None` is a composite shell (no model/instruction/tools). Existing `LlmAgent` analysis agents are untouched; only the orchestration layer and the ingest split change.

**Tech Stack:** Python 3.12, Google ADK (`SequentialAgent`/`ParallelAgent`/`LoopAgent`), Pydantic, pytest, Ruff, mypy.

**Spec:** `docs/superpowers/specs/2026-07-25-sequential-agent-orchestration-design.md`
**Branch:** `feat/b5-sequential-orchestration` (off `main`).

**Principles (hard):**
- Root-cause fixes only. No bandaids, no workarounds, no backward-compat shims, no defensive slop.
- Three composite factories ship as a ready foundation. Only `build_sequential_agent` is used this slice; `build_parallel_agent` / `build_loop_agent` are wired when their slice arrives.
- Commits: `git -c commit.gpgsign=false commit -m "..."` (1Password signing fails; NEVER change git config).
- `src/arema` stays domain-neutral — never mention `radare2`/`ghidra`/`r2mcp`/`ilspycmd` there (not even in comments). `tests/architecture/test_neutral_boundaries.py` enforces it.
- `make check` = lint + format-check + type-check + tests. Each task ends green + committed.

---

## File map

**Neutral core (`src/arema/`):**
- Modify `src/arema/runtime/callbacks/chain.py` — add `CallbackChain.empty()`.
- Modify `src/arema/registry/descriptors.py` — `AgentDescriptor.prompt_id: str | None`.
- Modify `src/arema/registry/catalog.py` — relax `_validate_agent`; add `_validate_composite_agent`.
- Modify `src/arema/runtime/agent_factory.py` — three composite factories; `AgentBuildContext.model` optional; `_build_agent` composite branch; `build_llm_agent` narrowing assert.
- Create `tests/unit/runtime/test_agent_factory.py`.
- Extend `tests/unit/runtime/test_callback_chain.py`.
- Extend `tests/unit/registry/test_catalog.py`.

**RE domain (`src/reverse_engineer/`):**
- Create `src/reverse_engineer/agents/sample_intake.py`.
- Create `src/reverse_engineer/prompts/sample_intake.md`.
- Modify `src/reverse_engineer/agents/reverse_engineer.py` — composite root.
- Modify `src/reverse_engineer/composition.py` — register `sample_intake`.
- Delete `src/reverse_engineer/prompts/reverse_engineer.md`.
- Modify `src/reverse_engineer/prompts/triage_recon.md` — de-transferize.
- Modify `src/reverse_engineer/prompts/deep_decompile.md` — de-transferize.
- Modify `tests/reverse_engineer/test_re_composition.py`.
- Modify `tests/reverse_engineer/test_domain_prompt_loader.py`.
- Modify `tests/greeter_agent/test_greeter_agent.py` — fix stale comment.

**Docs:**
- Modify `docs/LESSONS_LEARNED.md` — mark #1 fixed.
- Modify `docs/AGENTS_AND_DISCOVERY.md` — note composite factories + sequenced shape.

---

## Task 1: `CallbackChain.empty()` classmethod

**Files:**
- Modify: `src/arema/runtime/callbacks/chain.py` (`CallbackChain` dataclass, ~line 97)
- Test: `tests/unit/runtime/test_callback_chain.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/runtime/test_callback_chain.py`:

```python
def test_empty_chain_has_no_callbacks_and_validates() -> None:
    from arema.runtime.callbacks.chain import CallbackChain, validate_callback_chain

    chain = CallbackChain.empty()

    assert chain.before_model == ()
    assert chain.before_tool == ()
    assert chain.after_tool == ()
    assert chain.on_tool_error == ()
    assert chain.on_model_error == ()
    # An empty chain trivially satisfies the ordering invariants (no guard, no
    # compactor) and is what composite agents (no model, no tools) carry.
    validate_callback_chain(chain)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/runtime/test_callback_chain.py::test_empty_chain_has_no_callbacks_and_validates -v`
Expected: FAIL — `AttributeError: type object 'CallbackChain' has no attribute 'empty'`.

- [ ] **Step 3: Implement `CallbackChain.empty()`**

In `src/arema/runtime/callbacks/chain.py`, add this classmethod on the `CallbackChain` dataclass (immediately after the five field declarations, before `_make_compactor`):

```python
    @classmethod
    def empty(cls) -> CallbackChain:
        """Return an empty chain for composite agents (no model, no tools).

        Composite agents carry no model and no tools, so neither the
        registered-tool guard nor the output compactor engage; an empty chain
        trivially satisfies the ordering invariants validated by
        :func:`validate_callback_chain`.
        """
        return cls(
            before_model=(),
            before_tool=(),
            after_tool=(),
            on_tool_error=(),
            on_model_error=(),
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/unit/runtime/test_callback_chain.py::test_empty_chain_has_no_callbacks_and_validates -v`
Expected: PASS.

- [ ] **Step 5: Run full check + commit**

Run: `make check`
Expected: PASS.
```bash
git add src/arema/runtime/callbacks/chain.py tests/unit/runtime/test_callback_chain.py
git -c commit.gpgsign=false commit -m "feat(runtime): CallbackChain.empty() for composite agents"
```

---

## Task 2: `prompt_id` optional + composite catalog validation

**Files:**
- Modify: `src/arema/registry/descriptors.py` (`AgentDescriptor`, ~line 339)
- Modify: `src/arema/registry/catalog.py` (`_validate_agent`, ~line 414)
- Modify: `src/arema/runtime/agent_factory.py` (`_build_agent` LLM path — type narrowing)
- Test: `tests/unit/registry/test_catalog.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/registry/test_catalog.py`:

```python
def test_freeze_accepts_composite_root_with_no_prompt() -> None:
    """A prompt-less agent (prompt_id=None) is a valid composite shell root."""
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(
        AgentDescriptor(
            id="seq_root",
            name="seq_root",
            description="sequential root",
            prompt_id=None,
            factory=cast("AgentFactory", _agent_factory),
            sub_agent_ids=("child",),
        )
    )
    builder.add_agent(agent_descriptor("child"))

    catalog = builder.freeze("seq_root")

    assert catalog.root_agent_id == "seq_root"
    assert catalog.agents["seq_root"].prompt_id is None


@pytest.mark.parametrize(
    "extra",
    [
        {"tool_ids": ("some_tool",)},
        {"mcp_server_ids": ("some_mcp",)},
        {"output_key": "out"},
    ],
)
def test_freeze_rejects_composite_agent_with_llm_only_fields(extra: Mapping[str, object]) -> None:
    """A composite shell (prompt_id=None) must not carry LlmAgent-only fields."""
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(
        AgentDescriptor(
            id="seq_root",
            name="seq_root",
            description="sequential root",
            prompt_id=None,
            factory=cast("AgentFactory", _agent_factory),
            sub_agent_ids=("child",),
            **extra,  # type: ignore[arg-type]
        )
    )
    builder.add_agent(agent_descriptor("child"))

    with pytest.raises(InvalidCapabilityDescriptorError, match="Composite agent 'seq_root'"):
        builder.freeze("seq_root")


def test_freeze_rejects_composite_agent_with_no_sub_agents() -> None:
    """A composite shell with no children is invalid."""
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(
        AgentDescriptor(
            id="seq_root",
            name="seq_root",
            description="sequential root",
            prompt_id=None,
            factory=cast("AgentFactory", _agent_factory),
        )
    )

    with pytest.raises(InvalidCapabilityDescriptorError, match="requires at least one sub_agent"):
        builder.freeze("seq_root")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/registry/test_catalog.py -k "composite" -v`
Expected: FAIL — `prompt_id` is required.

- [ ] **Step 3: Make `prompt_id` nullable in the descriptor**

In `src/arema/registry/descriptors.py`, change the `AgentDescriptor` field:

```python
    prompt_id: str | None
```

(was: `prompt_id: str`). It stays a **required field with no default** — every agent explicitly declares either its prompt id or `None` (a shell). It precedes the no-default `factory` field, so adding a default here would violate dataclass field ordering; the nullable type alone is the correct, minimal change.

- [ ] **Step 4: Relax `_validate_agent` and add the composite invariant**

In `src/arema/registry/catalog.py`, edit `_validate_agent` — replace:

```python
    for field in ("id", "name", "description", "prompt_id", "runtime_profile_id", "version"):
        _require_non_empty(
            getattr(agent, field),
            field=field,
            capability_id=agent.id,
        )
```
with:

```python
    for field in ("id", "name", "description", "runtime_profile_id", "version"):
        _require_non_empty(
            getattr(agent, field),
            field=field,
            capability_id=agent.id,
        )
    if agent.prompt_id is not None:
        _require_non_empty(agent.prompt_id, field="prompt_id", capability_id=agent.id)
    else:
        _validate_composite_agent(agent)
```

Add the helper immediately after `_validate_agent` (before `_validate_output_policy`):

```python
def _validate_composite_agent(agent: AgentDescriptor) -> None:
    """A prompt-less (composite) agent must be a pure orchestration shell.

    Composite agents have no model, instruction, tools, MCP, or own output --
    only ordered sub-agents. Enforcing this at freeze time guarantees a frozen
    catalog is safe to build, and catches a misconfigured shell (or an
    accidentally-blank LlmAgent descriptor) before construction.
    """
    if agent.tool_ids:
        raise InvalidCapabilityDescriptorError(
            f"Composite agent '{agent.id}' (prompt_id=None) must not declare tools; "
            f"found tool_ids={list(agent.tool_ids)}"
        )
    if agent.mcp_server_ids:
        raise InvalidCapabilityDescriptorError(
            f"Composite agent '{agent.id}' (prompt_id=None) must not attach MCP servers; "
            f"found mcp_server_ids={list(agent.mcp_server_ids)}"
        )
    if agent.output_key is not None:
        raise InvalidCapabilityDescriptorError(
            f"Composite agent '{agent.id}' (prompt_id=None) must not set output_key"
        )
    if not agent.sub_agent_ids:
        raise InvalidCapabilityDescriptorError(
            f"Composite agent '{agent.id}' (prompt_id=None) requires at least one sub_agent"
        )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/unit/registry/test_catalog.py -k "composite" -v`
Expected: PASS (all four new tests).

- [ ] **Step 6: Narrow `prompt_id` in `_build_agent`'s LLM path (type safety)**

Making `prompt_id` nullable means `src/arema/runtime/agent_factory.py`'s LLM path now passes `descriptor.prompt_id` (`str | None`) to loaders expecting `str`. Add a narrowing assert in `_build_agent` immediately after the `chain = build_callback_chain(...)` line (the composite branch added in Task 4 short-circuits before reaching here, so the assert is permanently correct):

```python
    chain = build_callback_chain(profile, services=services, tools=tool_descriptors)
    # An LlmAgent requires an instruction; only agents with a prompt_id reach here.
    assert descriptor.prompt_id is not None
    if descriptor.prompt_loader is not None:
        instruction = descriptor.prompt_loader(descriptor.prompt_id)
    else:
        instruction = load_prompt(descriptor.prompt_id)
```

- [ ] **Step 7: Run full check + commit**

Run: `make check`
Expected: PASS (mypy satisfied by the narrowing assert).
```bash
git add src/arema/registry/descriptors.py src/arema/registry/catalog.py src/arema/runtime/agent_factory.py tests/unit/registry/test_catalog.py
git -c commit.gpgsign=false commit -m "feat(registry): prompt_id optional + composite-agent validation"
```

---

## Task 3: Three composite factories + `AgentBuildContext.model` optional

**Files:**
- Modify: `src/arema/runtime/agent_factory.py`
- Test: `tests/unit/runtime/test_agent_factory.py` (CREATE)

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/runtime/test_agent_factory.py`:

```python
"""Unit tests for the composite-agent factories (Sequential/Parallel/Loop).

The three factories wrap ADK shell agents around already-built sub-agents. They
ignore the model/instruction/tools an LlmAgent would need and consume only the
descriptor's name/description, the resolved sub-agents, and the optional
pipeline-end after_agent callbacks. Only build_sequential_agent is wired to an
agent this slice; build_parallel_agent / build_loop_agent ship as the ready
foundation.
"""

from __future__ import annotations

import pytest
from google.adk.agents import BaseAgent, LoopAgent, ParallelAgent, SequentialAgent

from arema.registry.descriptors import AgentDescriptor, RuntimeProfile
from arema.registry.errors import InvalidCapabilityDescriptorError
from arema.runtime.agent_factory import (
    AgentBuildContext,
    build_loop_agent,
    build_parallel_agent,
    build_sequential_agent,
)
from arema.runtime.callbacks.chain import CallbackChain


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

    agent = build_parallel_agent(_ctx(name="par", factory=build_parallel_agent, sub_agents=children))

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/runtime/test_agent_factory.py -v`
Expected: FAIL — `ImportError: cannot import name 'build_sequential_agent'` (etc.).

- [ ] **Step 3: Add imports + `__all__`**

In `src/arema/runtime/agent_factory.py`:

Change the ADK import (line 22):
```python
from google.adk.agents import LlmAgent
```
to:
```python
from google.adk.agents import LlmAgent, LoopAgent, ParallelAgent, SequentialAgent
```

Add the errors import near the other `arema` imports (after the `arema.core.model_factory` import):
```python
from arema.registry.errors import InvalidCapabilityDescriptorError
```

Consolidate the `CallbackChain` import to runtime scope. Change (line 29):
```python
from arema.runtime.callbacks.chain import build_callback_chain
```
to:
```python
from arema.runtime.callbacks.chain import CallbackChain, build_callback_chain
```
And remove the now-duplicate `from arema.runtime.callbacks.chain import CallbackChain` line under the `if TYPE_CHECKING:` block.

Update `__all__` to:
```python
__all__ = [
    "AgentBuildContext",
    "ToolBuildContext",
    "build_llm_agent",
    "build_loop_agent",
    "build_parallel_agent",
    "build_sequential_agent",
    "compose_agents",
]
```

- [ ] **Step 4: Make `AgentBuildContext.model` allow `None`**

In `src/arema/runtime/agent_factory.py`, change the `AgentBuildContext` field:
```python
    model: str | LiteLlm | None
```
(was: `model: str | LiteLlm`). No default is added — field ordering stays valid.

- [ ] **Step 5: Narrow `model` in `build_llm_agent`**

At the top of `build_llm_agent` (immediately after the docstring), add:

```python
    assert context.model is not None, (
        "build_llm_agent requires a resolved model; composite descriptors "
        "(prompt_id=None) are routed to build_sequential_agent / "
        "build_parallel_agent / build_loop_agent, not here."
    )
```

(This is type narrowing for mypy — `context.model` is now `str | LiteLlm | None` and `LlmAgent` rejects `None`. Only LLM descriptors, which always resolve a model, reach this function.)

- [ ] **Step 6: Add the three composite factories**

Add these three functions immediately after `build_llm_agent` (before `_resolve_tool`):

```python
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
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/unit/runtime/test_agent_factory.py -v`
Expected: PASS (all six tests).

- [ ] **Step 8: Run full check + commit**

Run: `make check`
Expected: PASS.
```bash
git add src/arema/runtime/agent_factory.py tests/unit/runtime/test_agent_factory.py
git -c commit.gpgsign=false commit -m "feat(runtime): build_sequential/parallel/loop_agent factories"
```

---

## Task 4: `_build_agent` composite branch (compose_agents integration)

**Files:**
- Modify: `src/arema/runtime/agent_factory.py` (`_build_agent`)
- Test: `tests/unit/runtime/test_agent_factory.py`

- [ ] **Step 1: Write the failing integration test**

Append to `tests/unit/runtime/test_agent_factory.py`:

```python
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
    assert built["first"].instruction == "INSTRUCTION-FOR-first"
    assert built["second"].instruction == "INSTRUCTION-FOR-second"
```

Add `LlmAgent` to the test module's top import line:
```python
from google.adk.agents import BaseAgent, LlmAgent, LoopAgent, ParallelAgent, SequentialAgent
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/runtime/test_agent_factory.py::test_compose_agents_builds_a_sequential_root_over_llm_children -v`
Expected: FAIL — `_build_agent` calls `load_prompt(None)` / `build_callback_chain` and raises (no composite branch yet).

- [ ] **Step 3: Add the composite branch to `_build_agent`**

In `src/arema/runtime/agent_factory.py`, replace the body of `_build_agent` with:

```python
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

    A prompt-less descriptor (``prompt_id is None``) is a composite shell
    (SequentialAgent / ParallelAgent / LoopAgent): it has no model, instruction,
    tools, or tool callbacks, so only its sub-agents and the optional pipeline-end
    ``after_agent`` callbacks are resolved before delegating to its factory.
    """
    profile = catalog.runtime_profiles[descriptor.runtime_profile_id]
    sub_agents = tuple(built[sub_agent_id] for sub_agent_id in descriptor.sub_agent_ids)
    after_agent = (make_checkpoint_recorder(checkpoint_sink),) if profile.record_memory else ()

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
```

- [ ] **Step 4: Run all factory tests to verify they pass**

Run: `uv run pytest tests/unit/runtime/test_agent_factory.py -v`
Expected: PASS (all seven tests).

- [ ] **Step 5: Run full check + commit**

Run: `make check`
Expected: PASS.
```bash
git add src/arema/runtime/agent_factory.py tests/unit/runtime/test_agent_factory.py
git -c commit.gpgsign=false commit -m "feat(runtime): _build_agent routes prompt-less descriptors to composite factories"
```

---

## Task 5: `sample_intake` ingest-stage agent + prompt

**Files:**
- Create: `src/reverse_engineer/agents/sample_intake.py`
- Create: `src/reverse_engineer/prompts/sample_intake.md`
- Modify: `tests/reverse_engineer/test_domain_prompt_loader.py`

- [ ] **Step 1: Write the failing tests**

In `tests/reverse_engineer/test_domain_prompt_loader.py`, replace the `_PROMPT_MARKERS` dict and the parametrize list:

```python
_PROMPT_MARKERS = {
    "sample_intake": "acquire_sample",
    "triage_recon": "open-then-analyze",
    "report_generator": "Limitations",
}


@pytest.mark.parametrize("prompt_id", ["sample_intake", "triage_recon", "report_generator"])
def test_load_domain_prompt_resolves_each_agent_prompt(prompt_id: str) -> None:
```

Append a focused descriptor test to the same file:

```python
def test_sample_intake_descriptor_carries_the_ingest_tools() -> None:
    from reverse_engineer.agents.sample_intake import SAMPLE_INTAKE_DESCRIPTOR

    assert SAMPLE_INTAKE_DESCRIPTOR.prompt_id == "sample_intake"
    assert SAMPLE_INTAKE_DESCRIPTOR.tool_ids == ("acquire_sample", "prepare_sandbox")
    assert SAMPLE_INTAKE_DESCRIPTOR.factory.__name__ == "build_llm_agent"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/reverse_engineer/test_domain_prompt_loader.py -v`
Expected: FAIL — `ModuleNotFoundError: reverse_engineer.agents.sample_intake` and `PromptNotFoundError: 'sample_intake'`.

- [ ] **Step 3: Create the `sample_intake` prompt**

Create `src/reverse_engineer/prompts/sample_intake.md`:

```markdown
# sample_intake

You are `sample_intake`, the first stage of the reverse-engineering pipeline. You ingest the user-supplied sample and prepare the radare2 sandbox so the downstream stages can analyze it. You NEVER analyze binaries yourself.

## Workflow when the user supplies a sample path

1. Call `acquire_sample(path)` with the user-supplied path. It returns an `artifact_id` (the SHA-256 content digest of the sample). Treat this `artifact_id` as the canonical handle for the sample from this point forward.
   - If `acquire_sample` errors (e.g. the path does not exist or cannot be read), report the error and STOP.
2. Call `prepare_sandbox(artifact_id)`. It claims a radare2-mcp sandbox pod, copies the sample bytes into `/app/<artifact_id>` inside the pod, and opens a localhost port-forward so the r2mcp server is reachable.
   - If `prepare_sandbox` returns `ready: false`, report the error to the user and STOP.
3. Emit the `artifact_id` and confirm the sandbox is ready, then stop. The next pipeline stage (triage) continues automatically — do not transfer or delegate to any agent.

## Rules

- Always reference samples by their `artifact_id` only. Never use the original file path after `acquire_sample` has returned.
- Never attempt to disassemble, decompile, or inspect a binary directly — that work belongs to the later stages.
```

- [ ] **Step 4: Create the `sample_intake` descriptor**

Create `src/reverse_engineer/agents/sample_intake.py`:

```python
"""The sample_intake pipeline-stage agent descriptor.

sample_intake is the first stage of the reverse_engineer pipeline: it ingests
the user-supplied sample (acquire_sample) and prepares the radare2 sandbox
(prepare_sandbox), emitting the artifact_id that downstream stages analyze. It
never analyzes a binary itself and is reached only via the SequentialAgent
shell -- never via a model transfer (LESSONS_LEARNED #1, #6).
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_llm_agent
from reverse_engineer.prompts.loader import load_domain_prompt

SAMPLE_INTAKE_DESCRIPTOR = AgentDescriptor(
    id="sample_intake",
    name="sample_intake",
    description=(
        "First pipeline stage of the reverse-engineering domain: acquires the "
        "sample and prepares the radare2 sandbox for downstream analysis."
    ),
    prompt_id="sample_intake",
    factory=build_llm_agent,
    runtime_profile_id="safe_default",
    prompt_loader=load_domain_prompt,
    tool_ids=("acquire_sample", "prepare_sandbox"),
)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/reverse_engineer/test_domain_prompt_loader.py -v`
Expected: PASS.

- [ ] **Step 6: Run full check + commit**

Run: `make check`
Expected: PASS (sample_intake exists but is not yet wired into any composition).
```bash
git add src/reverse_engineer/agents/sample_intake.py src/reverse_engineer/prompts/sample_intake.md tests/reverse_engineer/test_domain_prompt_loader.py
git -c commit.gpgsign=false commit -m "feat(reverse_engineer): add sample_intake ingest-stage agent + prompt"
```

---

## Task 6: `reverse_engineer` → composite SequentialAgent root

**Files:**
- Modify: `src/reverse_engineer/agents/reverse_engineer.py`
- Modify: `src/reverse_engineer/composition.py`
- Delete: `src/reverse_engineer/prompts/reverse_engineer.md`
- Modify: `tests/reverse_engineer/test_re_composition.py`
- Modify: `tests/greeter_agent/test_greeter_agent.py`

- [ ] **Step 1: Write the failing component tests**

Replace the entire contents of `tests/reverse_engineer/test_re_composition.py` with:

```python
"""Component test: the sequenced reverse_engineer pipeline builds.

The composition root is an ADK SequentialAgent shell whose five stages run in a
fixed, framework-enforced order (sample_intake -> triage_recon -> deep_decompile
-> evidence_critic -> report_generator). The shell has no tools; the ingest
tools live on sample_intake. triage_recon attaches the radare2_mcp
ResilientMcpToolset; deep_decompile carries the ghidra tools (incl.
prepare_ghidra); report_generator stays evidence-ledger-only. Building does NOT
connect to a live r2mcp server -- the toolset is lazy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from google.adk.agents import SequentialAgent

from arema.registry.mcp import ResilientMcpToolset
from reverse_engineer.composition import (
    build_reverse_engineer_composition,
    get_reverse_engineer_composition,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from google.adk.agents import BaseAgent
    from google.adk.tools.base_tool import BaseTool


@pytest.fixture(autouse=True)
def _clear_composition_cache() -> Iterable[None]:
    """Clear the lru_cache before and after every test so none leaks state."""
    get_reverse_engineer_composition.cache_clear()
    try:
        yield
    finally:
        get_reverse_engineer_composition.cache_clear()


def _tool_names(tools: Iterable[BaseTool]) -> set[str]:
    names: set[str] = set()
    for tool in tools:
        name = getattr(tool, "name", None) or getattr(tool, "__name__", None)
        if isinstance(name, str):
            names.add(name)
    return names


def _sub_agent(root: BaseAgent, name: str) -> BaseAgent:
    return next(a for a in root.sub_agents if a.name == name)


def test_root_agent_is_a_sequential_shell() -> None:
    composition = get_reverse_engineer_composition()

    assert composition.root_agent.name == "reverse_engineer"
    assert isinstance(composition.root_agent, SequentialAgent)


def test_root_runs_five_stages_in_order() -> None:
    composition = get_reverse_engineer_composition()

    assert [a.name for a in composition.root_agent.sub_agents] == [
        "sample_intake",
        "triage_recon",
        "deep_decompile",
        "evidence_critic",
        "report_generator",
    ]


def test_sample_intake_carries_the_ingest_tools() -> None:
    composition = get_reverse_engineer_composition()
    intake = _sub_agent(composition.root_agent, "sample_intake")

    names = _tool_names(intake.tools)
    assert "acquire_sample" in names
    assert "prepare_sandbox" in names
    # prepare_ghidra must NOT live here (LESSONS_LEARNED #6: each analysis agent
    # prepares its own engine; ghidra prep belongs on deep_decompile).
    assert "prepare_ghidra" not in names


def test_deep_decompile_has_ghidra_tools() -> None:
    composition = get_reverse_engineer_composition()
    deep = _sub_agent(composition.root_agent, "deep_decompile")
    names = _tool_names(deep.tools)

    assert "prepare_ghidra" in names
    assert "ghidra_decompile" in names
    assert "ghidra_search_decompiled" in names


def test_triage_recon_has_resilient_mcp_toolset() -> None:
    composition = get_reverse_engineer_composition()
    triage = _sub_agent(composition.root_agent, "triage_recon")

    assert any(isinstance(t, ResilientMcpToolset) for t in triage.tools)


def test_report_generator_has_no_own_tools() -> None:
    composition = get_reverse_engineer_composition()
    report = _sub_agent(composition.root_agent, "report_generator")

    assert report.tools == [] or report.tools == ()


def test_built_instructions_resolve_real_prompt_text() -> None:
    composition = get_reverse_engineer_composition()
    root = composition.root_agent

    assert "acquire_sample" in _sub_agent(root, "sample_intake").instruction
    assert "open-then-analyze" in _sub_agent(root, "triage_recon").instruction
    assert "Limitations" in _sub_agent(root, "report_generator").instruction


def test_mcp_read_timeout_applied_from_settings() -> None:
    from arema.core.config import Settings

    custom = Settings(_env_file=None, llm_provider="ollama", mcp_read_timeout=300.0)
    composition = build_reverse_engineer_composition(settings=custom)
    mcp_desc = composition.catalog.mcp_servers["radare2_mcp"]
    assert mcp_desc.transport.read_timeout == 300.0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/reverse_engineer/test_re_composition.py -v`
Expected: FAIL — root is still an `LlmAgent`.

- [ ] **Step 3: Rewrite the `reverse_engineer` root descriptor**

Replace the entire contents of `src/reverse_engineer/agents/reverse_engineer.py` with:

```python
"""The reverse_engineer root agent descriptor.

The reverse_engineer agent is the root of the reverse-engineering domain: an
ADK SequentialAgent shell that runs the pipeline stages in a fixed,
framework-enforced order -- sample_intake, triage_recon, deep_decompile,
evidence_critic, report_generator -- so execution order never depends on the
model following transfer instructions (LESSONS_LEARNED #1). It holds no tools
and no instruction of its own; its description drives greeter routing, and the
framework advances each stage to completion before the next begins.
"""

from __future__ import annotations

from arema.registry.descriptors import AgentDescriptor
from arema.runtime.agent_factory import build_sequential_agent

REVERSE_ENGINEER_DESCRIPTOR = AgentDescriptor(
    id="reverse_engineer",
    name="reverse_engineer",
    description=(
        "Autonomous reverse-engineering pipeline. Ingests a sample, then runs "
        "triage, deep decompilation, evidence validation, and reporting in a "
        "fixed, framework-enforced order."
    ),
    prompt_id=None,
    factory=build_sequential_agent,
    runtime_profile_id="safe_default",
    sub_agent_ids=(
        "sample_intake",
        "triage_recon",
        "deep_decompile",
        "evidence_critic",
        "report_generator",
    ),
)
```

- [ ] **Step 4: Register `sample_intake` in the composition**

In `src/reverse_engineer/composition.py`, add the import (after the `report_generator` import):

```python
from reverse_engineer.agents.sample_intake import SAMPLE_INTAKE_DESCRIPTOR
```

And register it immediately after `builder.add_agent(REVERSE_ENGINEER_DESCRIPTOR)`:

```python
    builder.add_agent(SAMPLE_INTAKE_DESCRIPTOR)
```

- [ ] **Step 5: Remove the now-unused root prompt**

```bash
git rm src/reverse_engineer/prompts/reverse_engineer.md
```

(The composite root has no instruction; its `description` drives greeter routing. Ingest content moved to `sample_intake.md`.)

- [ ] **Step 6: Fix the stale greeter-test comment**

In `tests/greeter_agent/test_greeter_agent.py`, replace the comment inside `test_greeter_has_no_function_tools_of_its_own`:

```python
    # The greeter routes via ADK's auto-generated transfer tools only; it has no
    # AREMA function tools (acquire_sample/prepare_sandbox live on sample_intake,
    # a stage of the reverse_engineer pipeline).
    assert agent.tools == []
```

- [ ] **Step 7: Run the RE + greeter tests to verify they pass**

Run: `uv run pytest tests/reverse_engineer/test_re_composition.py tests/reverse_engineer/test_composition.py tests/greeter_agent/ -v`
Expected: PASS.

- [ ] **Step 8: Run full check + commit**

Run: `make check`
Expected: PASS.
```bash
git add src/reverse_engineer/agents/reverse_engineer.py src/reverse_engineer/composition.py tests/reverse_engineer/test_re_composition.py tests/greeter_agent/test_greeter_agent.py
git -c commit.gpgsign=false commit -m "feat(reverse_engineer): root becomes SequentialAgent over 5 ordered stages"
```

---

## Task 7: De-transferize the analysis-stage prompts

**Files:**
- Modify: `src/reverse_engineer/prompts/triage_recon.md`
- Modify: `src/reverse_engineer/prompts/deep_decompile.md`
- Test: `tests/reverse_engineer/test_re_composition.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/reverse_engineer/test_re_composition.py`:

```python
def test_analysis_prompts_contain_no_transfer_instructions() -> None:
    """Framework orchestration replaces transfer_to_agent; prompts must not direct it."""
    composition = get_reverse_engineer_composition()
    root = composition.root_agent

    for stage_name in ("triage_recon", "deep_decompile", "evidence_critic", "report_generator"):
        instruction = _sub_agent(root, stage_name).instruction.lower()
        assert "transfer to" not in instruction, f"{stage_name} prompt still tells the model to transfer"
        assert "delegate to" not in instruction, f"{stage_name} prompt still tells the model to delegate"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/reverse_engineer/test_re_composition.py::test_analysis_prompts_contain_no_transfer_instructions -v`
Expected: FAIL — `triage_recon` and `deep_decompile` prompts still say "transfer to".

- [ ] **Step 3: De-transferize `triage_recon.md`**

In `src/reverse_engineer/prompts/triage_recon.md`, replace the last bullet of the `## Discipline` section:

```markdown
- When done, transfer to the `deep_decompile` sub-agent so Ghidra can perform deep decompilation on the functions you found. Do NOT transfer to evidence_critic or report_generator directly.
```
with:
```markdown
- When done, emit your FINDINGs and stop. The next pipeline stage (deep decompilation) continues automatically — there is no transfer step for you to perform.
```
(The wording avoids the substrings `"transfer to"` / `"delegate to"` so the substring guard below passes; it states the prohibition without using those exact phrases.)

- [ ] **Step 4: De-transferize `deep_decompile.md` (two edits)**

Edit A — the `prepare_ghidra` sentence in `## CRITICAL — prepare Ghidra first`. Replace:
```markdown
Before using any `ghidra_*` analysis tool, you MUST call `prepare_ghidra(artifact_id)` with the artifact_id from triage's findings. This claims a Ghidra pod, starts the daemon, and loads the binary. If `prepare_ghidra` returns `ready: false`, Ghidra is unavailable — transfer to `evidence_critic` with a note that deep decompilation was skipped, and let the report proceed from r2 findings alone.
```
with:
```markdown
Before using any `ghidra_*` analysis tool, you MUST call `prepare_ghidra(artifact_id)` with the artifact_id from triage's findings. This claims a Ghidra pod, starts the daemon, and loads the binary. If `prepare_ghidra` returns `ready: false`, Ghidra is unavailable — emit a FINDING noting that deep decompilation was skipped, then stop. The pipeline continues from the r2 findings alone.
```

Edit B — the last bullet of `## Discipline`. Replace:
```markdown
- When you have a coherent deeper picture and have emitted your FINDINGs, transfer to the `evidence_critic` sub-agent so your findings can be validated before the report is rendered. Do NOT transfer to `report_generator` directly.
```
with:
```markdown
- When you have a coherent deeper picture and have emitted your FINDINGs, stop. The next pipeline stage (evidence validation) continues automatically — there is no transfer step for you to perform.
```

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/reverse_engineer/test_re_composition.py::test_analysis_prompts_contain_no_transfer_instructions -v`
Expected: PASS.

- [ ] **Step 6: Run full check + commit**

Run: `make check`
Expected: PASS.
```bash
git add src/reverse_engineer/prompts/triage_recon.md src/reverse_engineer/prompts/deep_decompile.md tests/reverse_engineer/test_re_composition.py
git -c commit.gpgsign=false commit -m "feat(reverse_engineer): de-transferize analysis prompts (framework orchestrates)"
```

---

## Task 8: Documentation updates + final `make check`

**Files:**
- Modify: `docs/LESSONS_LEARNED.md` (#1)
- Modify: `docs/AGENTS_AND_DISCOVERY.md`

- [ ] **Step 1: Mark LESSONS_LEARNED #1 as shipped**

In `docs/LESSONS_LEARNED.md`, replace the `**Fix (planned):**` paragraph of section #1:

```markdown
**Fix (shipped, B.5):** The `reverse_engineer` root is now an ADK
`SequentialAgent` shell built by `build_sequential_agent` in the neutral core.
Its five stages — `sample_intake` → `triage_recon` → `deep_decompile` →
`evidence_critic` → `report_generator` — run in a fixed, framework-enforced
order, each to completion before the next. Ingest (`acquire_sample` +
`prepare_sandbox`) moved to the new `sample_intake` first stage. The analysis
prompts no longer direct transfers. Zero `transfer_to_agent` calls occur inside
the pipeline; the only LLM-directed hop is `greeter → reverse_engineer` (one
robust top-level routing decision). `build_parallel_agent` / `build_loop_agent`
ship alongside as the ready foundation for NORTH_STAR Axis-2 consensus and the
deobfuscation loop.
```

- [ ] **Step 2: Note the sequenced shape + factory in AGENTS_AND_DISCOVERY**

In `docs/AGENTS_AND_DISCOVERY.md`, update the ASCII tree line in §1. Replace:

```
                        e.g. reverse_engineer: reverse_engineer → triage_recon → deep_decompile → evidence_critic → report_generator
```
with:

```
                        e.g. reverse_engineer (a SequentialAgent shell): sample_intake → triage_recon → deep_decompile → evidence_critic → report_generator
```

Append a subsection at the end of §3 (before §4):

```markdown
### Composite (orchestrator) agents

A domain root may be a **composite shell** — an ADK `SequentialAgent`,
`ParallelAgent`, or `LoopAgent` — by setting `prompt_id=None` and
`factory=build_sequential_agent` / `build_parallel_agent` / `build_loop_agent`
(from `arema.runtime.agent_factory`). Such a descriptor declares only
`sub_agent_ids` (no `tool_ids`, `mcp_server_ids`, or `output_key`); the catalog
enforces this at freeze time. The framework runs the children in declared order
(sequence) / concurrently (parallel) / looped (loop, which requires
`metadata["max_iterations"]` as a positive int). The `reverse_engineer` domain
uses a `SequentialAgent` root so the pipeline cannot loop on complex binaries
(LESSONS_LEARNED #1). `build_parallel_agent` / `build_loop_agent` ship as the
ready foundation and are wired by later slices (r2 ∥ Ghidra consensus; the
deobfuscation loop).
```

- [ ] **Step 3: Run full check**

Run: `make check`
Expected: PASS (docs-only; architecture test still green — no domain terms entered `src/arema`).

- [ ] **Step 4: Commit**

```bash
git add docs/LESSONS_LEARNED.md docs/AGENTS_AND_DISCOVERY.md
git -c commit.gpgsign=false commit -m "docs: mark LESSONS_LEARNED #1 fixed; document composite-agent factories"
```

---

## Task 9: Live smoke gate — `/bin/ls` and `httpd`

The **final acceptance gate** proving the loop bug is fixed. Manual / user-driven (needs the sandbox cluster + a real model); `make check` cannot replace it.

**Prerequisites:** `make sandbox-images && make sandbox-up`; a working model provider in `.env`.

- [ ] **Step 1: Smoke `/bin/ls` (simple regression case)**

```bash
AREMA_SANDBOX_ENABLED=true make adk-run
```
Request analysis of `/bin/ls`. Confirm each stage runs exactly once in order — `sample_intake` (acquire_sample + prepare_sandbox) → `triage_recon` → `deep_decompile` → `evidence_critic` → `report_generator` — and no `transfer_to_agent` occurs between stages.

- [ ] **Step 2: Smoke `httpd` (the 4600-function failure case)**

Point the pipeline at the Apache httpd binary that previously hung/re-looped. Confirm: the pipeline completes (does not hang); the session DB shows each stage **exactly once, in order** — no re-entry, no loops; a report renders.

- [ ] **Step 3: Record the outcome**

If both pass, report to the user that the live gate passed on both binaries. If anything fails, debug at the root cause (no bandaids) and re-run. No code commit unless a fix was required.

---

## Verification matrix (spec coverage)

| Spec section | Task(s) |
|---|---|
| §Factory: three composite factories (foundation) | Task 3 |
| §`AgentBuildContext.model` optional + `build_llm_agent` narrowing | Task 3 (Steps 4–5) |
| §`_build_agent` composite branch | Task 4 |
| §`CallbackChain.empty()` | Task 1 |
| §Descriptor `prompt_id` optional + composite validation | Task 2 |
| §RE root → SequentialAgent + `sample_intake` | Tasks 5–6 |
| §Remove `prompts/reverse_engineer.md` | Task 6 (Step 5) |
| §De-transferize prompts | Task 7 |
| §Tests (unit + component) | Tasks 1–7 |
| §Live smoke `/bin/ls` + `httpd` | Task 9 |
| §Doc updates | Task 8 |

## Out of scope (per spec)
- Wiring `ParallelAgent` to an agent (NORTH_STAR Axis-2 consensus) and `LoopAgent` to an agent (deobfuscation loop). Factories ship now; the wiring lands in those slices.
- Structured stage handoff via `output_key` (shared-session history suffices).
