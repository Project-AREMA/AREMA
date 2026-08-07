# AREMA SequentialAgent Orchestration — Design (Spec B, Slice 4 / B.5)

**Status:** Approved (brainstormed 2026-07-25)
**Spec ID:** B.5 (factory support for composite agents + the RE pipeline loop fix)
**Depends on:** Spec B Slices 1–3 (B.2 r2 loop, B.3 Trust & Quality Layer, B.4 Ghidra
2nd engine) — all merged into `main` (~690 tests passing). The five-agent
`reverse_engineer` → `triage_recon` → `deep_decompile` → `evidence_critic` →
`report_generator` graph built from `LlmAgent`s wired via `sub_agent_ids`.
**North star:** `docs/NORTH_STAR.md` §6 (agent roster uses `SequentialAgent` /
`ParallelAgent` / `LoopAgent`) and §3 (deterministic orchestration, probabilistic
interpretation).
**Architecture constraints:** `docs/AGENTS_AND_DISCOVERY.md`,
`docs/ARCHITECTURE.md`, `docs/EXTENDING_AREMA.md`, `docs/CONTEXT_AND_RESILIENCE.md`,
`docs/LESSONS_LEARNED.md` (#1 prompt-directed transfers are fragile; #6 each
analysis agent prepares its own engine).

## Goal

Replace **prompt-directed agent transfers** with **framework-enforced
orchestration**. Today the `reverse_engineer` root is an `LlmAgent` whose
sub-agents are reached via model-driven `transfer_to_agent` calls guided by
prompts. On complex binaries (httpd, 4600 functions) the model loses track of
pipeline state, re-enters agents, and creates transfer loops; the
`evidence_critic` is eventually invoked with chaotic, incomplete context and the
run hangs (LESSONS_LEARNED #1).

Concretely:

1. **Composite-agent factory support** in the neutral core — the factory today
   builds only `LlmAgent`. Add `build_sequential_agent` (and ship
   `build_parallel_agent` + `build_loop_agent` for the composite types NORTH_STAR
   §6 calls for, even though only Sequential is *used* by the RE pipeline here).
2. **Rewrite the RE pipeline** so `reverse_engineer` becomes a `SequentialAgent`
   shell: ingest → triage → deep_decompile → evidence_critic → report_generator,
   each stage running to completion before the next begins. No transfers, no
   loops. Ingest (`acquire_sample` + `prepare_sandbox`) moves into a new first
   stage, `sample_intake`.
3. **De-transferize the prompts** — remove every "transfer to / delegate to"
   instruction from the analysis agents; the framework advances, not the model.

The change is **transparent to the existing analysis agents**: they remain
`LlmAgent`s with the same tools, profiles, and callbacks. Only the orchestration
layer and the ingest split change.

## Decisions (locked during brainstorm)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Orchestration shape | **A — `SequentialAgent` root + dedicated ingest stage.** `reverse_engineer` becomes a `SequentialAgent`; a new `sample_intake` `LlmAgent` is stage 0 carrying `acquire_sample` + `prepare_sandbox`; then triage → deep → critic → report. Zero LLM-directed ordering inside the pipeline. AREMA's greeter is already the human interface, so a vestigial interface `LlmAgent` (Option D) would add a layer for nothing. |
| 2 | Factory scope | **Ship all three composite factories now** (`build_sequential_agent`, `build_parallel_agent`, `build_loop_agent`). Only Sequential is *used* by the RE pipeline; Parallel/Loop are shipped so a later slice (Axis-2 r2∥Ghidra consensus; deobfuscation loop) skips the neutral-core factory step. |
| 3 | Composite detection | **Branch on `descriptor.prompt_id is None`** (instruction-less ⇒ composite), not a new `AgentKind` enum. Lighter YAGNI; the factory field already selects construction strategy; `prompt_id=None` is a natural "no instruction" signal. |
| 4 | `LoopAgent.max_iterations` | Read from `descriptor.metadata["max_iterations"]`; **enforced at build time** in `build_loop_agent` (raises if absent/not a positive int). Freeze-time validation of Loop-specific rules is deferred until a domain actually adopts Loop. |
| 5 | Context handoff | **Shared session via `include_contents="default"`** — `artifact_id` flows through history exactly as today. No `output_key` / structured-handoff plumbing this slice (optional future). |
| 6 | Memory at pipeline end | The `SequentialAgent` root (`safe_default`, `record_memory=True`) keeps `after_agent` = checkpoint recorder → one lifecycle checkpoint when the whole pipeline finishes. Per-tool memory on triage/deep (`re_guarded`) is unchanged. |
| 7 | `prompts/reverse_engineer.md` | **Removed.** A composite root has no instruction; its `description` drives greeter routing. The ingest half of the old prompt moves to the new `sample_intake` prompt. |
| 8 | Neutrality | Three composite factories live in `src/arema/runtime/agent_factory.py` (ADK primitives, domain-neutral). The RE pipeline rewrite lives in `src/reverse_engineer/`. `src/arema` + `composition.py` stay domain-neutral; the architecture test scans for domain *terms* (`radare2`/`ghidra`/…), not for ADK agent types. |

### Why Option A (and not C or D)

Three shapes were considered:

- **A — `SequentialAgent` root + ingest stage** *(chosen).* Tree depth under the
  greeter stays at one level. `reverse_engineer` is a pure shell; `sample_intake`
  is stage 0. The only LLM-directed hop is `greeter → reverse_engineer` (robust,
  top-level domain routing — one hop, no loop possible). Fully eliminates the
  loop class.
- **C — `LlmAgent` root keeps ingest + `SequentialAgent` pipeline child.**
  Smallest descriptor diff, but leaves one residual LLM-directed hop (ingest →
  transfer into the pipeline) and adds a second tree level. The residual hop is
  not itself a loop risk, but it is precisely the kind of "model decides
  ordering" decision this slice exists to remove.
- **D — `LlmAgent` interface root + `SequentialAgent` pipeline child (ingest as
  stage 0).** Most faithful to NORTH_STAR §6 (`AnalystConsole` = `LlmAgent`
  root), but adds a near-vestigial interface agent that does nothing but
  transfer, plus a second transfer. In AREMA the greeter already plays the
  `AnalystConsole` role, so the extra layer buys nothing.

A is the leanest shape that removes *all* LLM-directed ordering from the
pipeline while keeping the existing analysis agents untouched.

## Architecture: the sequenced agent graph

```
greeter_agent   (LlmAgent)                      ← unchanged: the human interface / router
  └─ reverse_engineer   (SequentialAgent)       ← was LlmAgent; now a composite shell
       ├─ sample_intake     (LlmAgent)          ← NEW stage 0: acquire_sample + prepare_sandbox
       ├─ triage_recon      (LlmAgent)          ← unchanged builder; prompt de-transferized
       ├─ deep_decompile    (LlmAgent)          ← unchanged builder; prompt de-transferized
       ├─ evidence_critic   (LlmAgent)          ← unchanged builder; prompt de-transferized
       └─ report_generator  (LlmAgent)          ← unchanged builder; prompt de-transferized
```

### Execution semantics (ADK `SequentialAgent`)

`SequentialAgent._run_async_impl` iterates `sub_agents` in order, running each
`run_async` to completion before starting the next, sharing one
`InvocationContext` (one session). With `include_contents="default"` (the
`HISTORY` context mode of `safe_default`), each stage sees the full prior
conversation — so `artifact_id`, findings, and the critic's verdict flow forward
through history exactly as they do under the transfer model today. The
framework, not the model, advances the pipeline. There is no `transfer_to_agent`
involved inside the pipeline; the only transfer is `greeter → reverse_engineer`
(a single, robust, top-level routing decision).

ADK accepts any `BaseAgent` as a root (`agent.py:root_agent`) and as a sub_agent,
so a `SequentialAgent` root is valid for `adk run`/`adk web` discovery and as a
greeter sub-agent. `reverse_engineer` keeps `name="reverse_engineer"` so the
greeter's auto-generated `transfer_to_agent("reverse_engineer")` is unchanged.

## Neutral-core factory changes

### `src/arema/runtime/agent_factory.py`

Three new public factories, siblings to `build_llm_agent`:

```python
def build_sequential_agent(context: AgentBuildContext) -> SequentialAgent:
    return SequentialAgent(
        name=context.descriptor.name,
        description=context.descriptor.description,
        sub_agents=list(context.sub_agents),
        after_agent_callback=list(context.after_agent),
    )

def build_parallel_agent(context: AgentBuildContext) -> ParallelAgent:
    # Identical constructor surface to SequentialAgent.
    return ParallelAgent(
        name=context.descriptor.name,
        description=context.descriptor.description,
        sub_agents=list(context.sub_agents),
        after_agent_callback=list(context.after_agent),
    )

def build_loop_agent(context: AgentBuildContext) -> LoopAgent:
    max_iter = context.descriptor.metadata.get("max_iterations")
    if not isinstance(max_iter, int) or isinstance(max_iter, bool) or max_iter <= 0:
        raise InvalidCapabilityDescriptorError(
            f"LoopAgent '{context.descriptor.id}' requires metadata['max_iterations'] "
            "to be a positive integer (NORTH_STAR: loops must be capped)."
        )
    return LoopAgent(
        name=context.descriptor.name,
        description=context.descriptor.description,
        sub_agents=list(context.sub_agents),
        max_iterations=max_iter,
        after_agent_callback=list(context.after_agent),
    )
```

`__all__` gains all three. Imports: `ParallelAgent`, `LoopAgent`, `SequentialAgent`
from `google.adk.agents`.

### `AgentBuildContext` (allow a composite to omit the model)

Only the `model` *type annotation* changes (to permit `None`); **no new defaults
are added**, so dataclass field ordering (non-default before default) is
preserved. The composite branch passes `model=None`, `instruction=""`, `tools=()`
explicitly.

```python
@dataclass(frozen=True, slots=True)
class AgentBuildContext:
    descriptor: AgentDescriptor
    profile: RuntimeProfile
    model: str | LiteLlm | None              # was: str | LiteLlm  (still required — no default)
    instruction: str                          # composite branch passes ""
    tools: tuple[ToolLike, ...]               # composite branch passes ()
    sub_agents: tuple[BaseAgent, ...]
    chain: CallbackChain
    output_key: str | None = None
    after_agent: tuple[Callable[[CallbackContext], None], ...] = ()
```

`build_llm_agent` gains a defensive assertion that `context.model is not None`
(only LLM descriptors — which always resolve a model — reach it). This keeps the
uniform `(AgentBuildContext) -> BaseAgent` factory contract while letting
composites pass `None` for the model/instruction they would never use.

### `_build_agent` — branch on composite

```python
if descriptor.prompt_id is None:
    # Composite shell: no instruction, no model, no tools, no tool callbacks.
    instruction = ""
    model = None
    tools: tuple[ToolLike, ...] = ()
    chain = CallbackChain.empty()
else:
    # Existing LlmAgent resolution: prompt, model, tools, full callback chain.
    ...
after_agent = (make_checkpoint_recorder(checkpoint_sink),) if profile.record_memory else ()
```

`after_agent` is resolved for both branches (profile-driven, independent of
kind), so a composite root with `record_memory=True` still records one pipeline-
end checkpoint. The composite factory then ignores `model`/`instruction`/`tools`/
`chain` and consumes only `descriptor`, `sub_agents`, `after_agent`.

### `CallbackChain.empty()` (`src/arema/runtime/callbacks/chain.py`)

Tiny classmethod so the composite path reads cleanly:

```python
@classmethod
def empty(cls) -> CallbackChain:
    return cls(before_model=(), before_tool=(), after_tool=(),
               on_tool_error=(), on_model_error=())
```

Composites have no model and no tools, so the registered-tool-guard and
output-compactor ordering invariants do not engage; `validate_callback_chain`
on an empty chain passes trivially. No new role markers are needed.

## Descriptor + catalog validation changes

### `src/arema/registry/descriptors.py`

- `AgentDescriptor.prompt_id: str | None` (was required `str`). A required
  field whose value may be `None`: every agent explicitly declares either its
  prompt id or `None` (a composite shell). No default is added (it precedes the
  no-default `factory` field, so a default here would violate dataclass
  field ordering).

### `src/arema/registry/catalog.py::_validate_agent`

- Remove `"prompt_id"` from the required-non-empty field list.
- Add **composite invariants** (kind-agnostic — uniform across
  sequential/parallel/loop): if `agent.prompt_id is None`, then
  - `sub_agent_ids` must be non-empty (a shell with no children is invalid),
  - `tool_ids` must be empty (a shell has no tools),
  - `mcp_server_ids` must be empty (a shell attaches no MCP),
  - `output_key` must be `None` (a shell has no own structured output).

Existing whole-graph validation (`_validate_references`, `_validate_acyclic_agents`,
`_validate_reachable_agents`) already walks `sub_agent_ids` and is unchanged — a
composite composes naturally into the post-order build.

### Deferred (honest YAGNI)

Freeze-time validation of `LoopAgent.max_iterations` is **not** added in this
slice: no domain uses Loop here, so the build-time guard in `build_loop_agent`
is sufficient. When a domain adopts Loop (deobf phase), add kind-aware
validation then.

## RE domain rewrite (`src/reverse_engineer/`)

- **`agents/reverse_engineer.py`** — becomes a composite descriptor:

  ```python
  REVERSE_ENGINEER_DESCRIPTOR = AgentDescriptor(
      id="reverse_engineer",
      name="reverse_engineer",
      description=(
          "Autonomous reverse-engineering pipeline. Ingests a sample, then runs "
          "triage, deep decompilation, evidence validation, and reporting in a "
          "fixed, framework-enforced order."
      ),
      prompt_id=None,                       # composite shell — no instruction
      factory=build_sequential_agent,
      runtime_profile_id="safe_default",    # record_memory → pipeline-end checkpoint
      sub_agent_ids=(
          "sample_intake", "triage_recon", "deep_decompile",
          "evidence_critic", "report_generator",
      ),
  )
  ```

- **`agents/sample_intake.py`** (NEW) — the ingest stage:

  ```python
  SAMPLE_INTAKE_DESCRIPTOR = AgentDescriptor(
      id="sample_intake",
      name="sample_intake",
      description="First pipeline stage: acquire the sample and prepare the radare2 sandbox.",
      prompt_id="sample_intake",
      factory=build_llm_agent,
      runtime_profile_id="safe_default",
      prompt_loader=load_domain_prompt,
      tool_ids=("acquire_sample", "prepare_sandbox"),
  )
  ```

- **`prompts/sample_intake.md`** (NEW) — the ingest half of the old root prompt:
  call `acquire_sample(path)` → `prepare_sandbox(artifact_id)` → emit the
  `artifact_id` and sandbox readiness; stop and report on error. No transfer
  language.
- **`prompts/reverse_engineer.md`** — **removed** (composite root has no
  instruction).
- **Prompt trims** across `triage_recon.md`, `deep_decompile.md`,
  `evidence_critic.md`, `report_generator.md`: delete every "transfer to /
  delegate to / hand off to" line. Each agent now does its work and finishes;
  replace with a one-liner such as *"Emit your findings; the next pipeline stage
  continues automatically — do not transfer or delegate."*
- **`composition.py`** — register `SAMPLE_INTAKE_DESCRIPTOR` (one `add_agent`
  line). The four analysis descriptors, the tool/MCP registrations, and the
  codec wiring are unchanged.

### Lesson #6 preserved

`prepare_ghidra` stays on `deep_decompile` (each analysis agent prepares its own
engine). Only `acquire_sample` + `prepare_sandbox` move — from the old root to
`sample_intake`, which is itself an analysis-stage agent that runs first.

## Context, memory, and callback behavior

- **Context flow:** one shared session; `artifact_id`, findings, and the critic's
  verdict flow forward through history (`include_contents="default"`). No
  `state` plumbing and no `output_key` plumbing this slice.
- **Memory:** the `SequentialAgent` root records **one** lifecycle checkpoint on
  pipeline completion (`after_agent` from `record_memory`). `triage_recon` and
  `deep_decompile` keep their `re_guarded` per-tool memory callbacks (SanitizationMembrane,
  codec-backed memory, compactor) — unchanged.
- **Callback invariants:** composites carry no model and no tools, so the
  registered-tool-guard (must be first in `before_tool`) and output compactor
  (must be last in `after_tool`) invariants do not engage. No new role markers;
  `validate_callback_chain` on an empty chain is trivially valid.

## Testing

- **Unit / neutral core:**
  - `tests/unit/runtime/test_agent_factory.py` (NEW): each composite factory
    builds the correct ADK type; ignores `model`/`instruction`; wires
    `sub_agents` + `after_agent`; `build_loop_agent` reads `max_iterations` from
    `metadata` and raises when absent / non-int / non-positive / bool.
  - `tests/unit/runtime/test_callback_chain.py` (extend): `CallbackChain.empty()`
    is all-empty and passes `validate_callback_chain`.
  - `tests/unit/registry/test_catalog.py` (extend): `prompt_id=None` validates;
    a composite with non-empty `tool_ids` / `mcp_server_ids` / `output_key`, or
    empty `sub_agent_ids`, is rejected.
- **Component (`tests/reverse_engineer/`):** update `test_re_composition.py` and
  `test_composition.py` assertions — the root is a `SequentialAgent`
  (`isinstance(root, SequentialAgent)`); being a `BaseAgent`, it has **no
  `.tools` field**; `root.sub_agents` names == the 5 stages in order;
  `acquire_sample`/`prepare_sandbox` now live on `sample_intake`; the four LlmAgent
  stages still resolve real prompt text (distinctive-word assertions updated);
  `prepare_ghidra` remains on `deep_decompile`.
- **Live smoke (final gate):** `AREMA_SANDBOX_ENABLED=true make adk-run` —
  `/bin/ls` completes end-to-end through the report; **`httpd` (the 4600-function
  failure case) completes without re-entry loops**. Session DB shows each stage
  exactly once, in order. This is the real proof LESSONS_LEARNED #1 is resolved.

## Scope

**In scope:**

1. Three composite factories (`build_sequential_agent`, `build_parallel_agent`,
   `build_loop_agent`) + `__all__`/imports in `src/arema/runtime/agent_factory.py`.
2. `AgentBuildContext` relaxation (`model` optional) + defensive assert in
   `build_llm_agent`.
3. `_build_agent` composite branch + `CallbackChain.empty()`.
4. `AgentDescriptor.prompt_id` optional + composite invariants in
   `_validate_agent`.
5. RE pipeline rewrite: `reverse_engineer` → composite root; new `sample_intake`
   agent + prompt; remove `prompts/reverse_engineer.md`; de-transferize the four
   analysis prompts; register `sample_intake` in `composition.py`.
6. Tests (unit + component) + live smoke on `/bin/ls` and `httpd`.
7. Doc updates: `LESSONS_LEARNED.md` #1 (mark fix shipped), `AGENTS_AND_DISCOVERY.md`
   (note composite factories + the sequenced RE shape).

**Out of scope (deferred):**

- Actual *use* of `ParallelAgent` (NORTH_STAR Axis-2, r2 ∥ Ghidra consensus) and
  `LoopAgent` (Phase-2 deobfuscation loop) — factories shipped, unused.
- Freeze-time validation of `LoopAgent.max_iterations` (build-time guard suffices
  until a domain adopts Loop).
- Structured stage handoff via `output_key` (shared-session history is sufficient
  for this slice).
- `LoopAgent`/`ParallelAgent` live-mode support (ADK itself raises
  `NotImplementedError` for live mode on these types).

## Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Greeter's `transfer_to_agent` to a non-LLM `SequentialAgent` misbehaves. | ADK generates transfer tools per registered sub-agent by name regardless of target type; `BaseAgent.run_async` dispatches polymorphically. Verified against ADK `sequential_agent.py` + `base_agent.py`. Covered by the live smoke gate. |
| A composite root with `record_memory=True` double-records or mis-records. | `after_agent` fires once on pipeline completion (ADK `BaseAgent._handle_after_agent_callback`); the checkpoint recorder is idempotent per invocation. Covered by component test. |
| `prompt_id=None` silently makes an LLM descriptor instruction-less. | Composite invariants enforce that an instruction-less agent also has no tools/mcp/output_key and ≥1 sub-agent — so an accidentally-blank LLM descriptor is caught at freeze. |
| `SequentialAgent` carries ADK's `@experimental` marker on its state class. | The `SequentialAgent` class itself is stable and widely used; only its resume-state model is experimental. AREMA does not rely on resumable/paused invocations, so the experimental surface is untouched. |
| Stage sees stale/missing `artifact_id` without explicit handoff. | History-based flow is unchanged from the working transfer model today; the live smoke on `/bin/ls` + `httpd` verifies end-to-end. Structured `output_key` handoff remains an optional future hardening. |

## Open questions (none blocking)

- Whether a future slice should add explicit `output_key` per stage for
  structured handoff (decidable when a stage needs a machine-parseable
  predecessor output rather than free-text findings).
- Whether `ParallelAgent` consensus (Axis-2) wants a dedicated
  `consensus_agent` stage or a `ParallelAgent` with a follow-up `LlmAgent`
  reconciler — decided in that slice, not this one.
