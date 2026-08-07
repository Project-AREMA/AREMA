# AREMA Deobfuscation LoopAgent — Design

**Status:** Spec (revised 2026-07-26; design locked below; this is the execution contract)
**Branch:** `feat/deobfuscation-loop` (off `main` = `461cd3f`)
**Depends on:** Slice 2 (merged to `main`): the `malware_analyst` 8-stage spine
(`sample_intake → triage_recon → ioc_extraction → deep_decompile → behavior_characterization
→ attack_mapper → evidence_critic → malware_report_generator`); `build_loop_agent`
(`metadata['max_iterations']`, build-time enforced); the content-addressed `ArtifactStore`
(`acquire`/`path_for`); `recover_tool_exception` (tool errors degrade, never crash); the
`re_guarded` profile + SanitizationMembrane.
**North star:** `docs/NORTH_STAR.md` Phase 2 (deobfuscation loop, `LoopAgent` max 3,
classify → recover → re-triage, evidence-gated, capped) and §6 (Deobfuscation agent,
mindset = both).
**Architecture constraints:** `docs/AGENTS_AND_DISCOVERY.md`, `docs/ARCHITECTURE.md`,
`docs/LESSONS_LEARNED.md`.

## Decisions (locked during revision)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Tool implementations | Use the real upstream tools: Mandiant `flare-floss` and `upx/upx`, pinned to verified releases. No reimplementation or lookalike command. |
| 2 | Execution boundary | Kubernetes sandbox is mandatory. UPX/FLOSS never execute on the AREMA host or through `LocalSandboxExecutor`; unavailable/non-k8s execution degrades cleanly. |
| 3 | Image/pool shape | One extensible `deobfuscation-tools` image + warm pool for stateless, one-shot, file-in/result-out tools. Do not couple them to the r2 or Ghidra images. |
| 4 | AREMA surface | Two deferred-factory function tools, `upx_unpack` and `floss_decode`, sharing a reusable deobfuscation sandbox runtime. No MCP server and no `prepare_*` lifecycle agent. |
| 5 | FLOSS contract | Run FLOSS in JSON mode for PE decoded/stack/tight strings and preserve type/address provenance. Unsupported formats are non-applicable, not tool failures. |
| 6 | Extensibility | Installing a future executable in the image does not expose it to the model. Every tool requires an explicit wrapper, `ToolDescriptor`, `OutputPolicy`, sanitizer/evidence registration, and tests. |

## Goal

Give the pipeline a **deobfuscation stage** so packed/obfuscated samples can be analyzed
instead of stalling at opaque bytes. The stage is an ADK `LoopAgent` (max 3) that runs
*after triage, before deep decompilation* (NORTH_STAR `P1 → {packed?} → P2 → P3`). Each
iteration: **classify** the obfuscation, **recover** what is achievable at the binary
level (UPX unpack + FLOSS string decode), **re-triage** the (possibly unpacked) artifact,
and **gate** — escalate out of the loop when no further improvement is possible or when a
p-code-requiring obfuscation class is detected.

This turns the pipeline from "opaque on packed input" into "unpacks + decodes + hands
cleaner bytes to the downstream stages." It is the first deobfuscation slice; generic/
custom packer unpacking (dynamic memory-carve) stays post-MVP.

## Design research (why this shape)

The placement of p-code recovery was resolved by a research pass over the agentic-RE
literature and the ADK docs rather than by guess:

- **Agent4Decompile / "Constraint-Guided Multi-Agent Decompilation" (arXiv:2604.23940)**
  explicitly frames deobfuscation as *"specialized deobfuscation as preprocessing"* upstream
  of the decompile/refine loop. → **deobf stage belongs early, before deep decompile.**
- **"Deconstructing Obfuscation" (arXiv:2505.19887)** shows LLM agents *provably fail* on
  CFF / VM / opaque-predicate / combined obfuscation. → p-code recovery **must be
  engine-assisted** and therefore lives with whoever holds the Ghidra session.
- **LLM4Decompile (EMNLP 2024, arXiv:2403.05286)** establishes the **engine-owner
  (Ghidra) vs LLM-refiner** split. → the agent that owns the engine session is not the
  LLM that polishes output.
- **ADK `LoopAgent`** canonical exit idiom: a non-LLM checker reads state and sets
  `actions.escalate = True`. → the evidence-gate is a deterministic checker, not an LLM
  call. AREMA expresses this as the `deobf_gate` non-LLM `BaseAgent` (4th loop sub-agent).

**Synthesis:** split "deobfuscation" into two concerns by where their tooling lives —
binary-level recovery (unpack + decode) belongs in the early loop; p-code-level recovery
(CFF/VM devirtualization) belongs in `deep_decompile`, flag-driven. **No Ghidra enters the
loop**, so there is no duplicate engine setup and no session-sharing problem this slice.

### Why stateless function tools, not the radare2 MCP pattern

The radare2 MCP integration is justified by retained interactive engine state: r2mcp must
`open_file` and `analyze`, then serves a broad typed exploration surface (functions,
decompilation, xrefs, strings, sections, address navigation) across many model-directed
calls against the same `RCore`. MCP provides real value there: upstream schemas, discovery,
transport, and a persistent analysis session.

UPX and FLOSS have the opposite shape. Each performs one deterministic operation over one
artifact and returns either a recovered file or a complete result document. They have no
useful interactive session, loaded analysis database, or broad model-selected command
surface. An MCP server would add a daemon, port, attachment, session recovery, and a larger
attack surface without improving artifact custody or result validation.

The resulting boundary is explicit:

- The shared `deobfuscation-tools` image accepts **stateless, one-shot,
  file-in/result-out** unpackers, decoders, extractors, and normalizers.
- A future stateful debugger, emulator, devirtualizer, or analysis database gets its own
  engine image/pool and the integration surface its lifecycle warrants (MCP or stateful
  function tools); it is not forced into this shared runner.

## Target pipeline (end state)

```
malware_analyst (SequentialAgent)                              ← spine
  ├─ sample_intake            (LlmAgent)                       ← capability (unchanged)
  ├─ triage_recon             (LlmAgent, r2)                   ← capability (unchanged)
  ├─ deobfuscation            (LoopAgent, max 3)               ← NEW (this slice)
  │     ├─ deobf_classify     (LlmAgent, tool-less)
  │     ├─ recover            (SequentialAgent)
  │     │     ├─ upx_unpack   (LlmAgent, tool: upx_unpack)
  │     │     └─ floss_decode (LlmAgent, tool: floss_decode)
  │     ├─ retriage           (LlmAgent, r2)
  │     └─ deobf_gate         (non-LLM BaseAgent; reads state, escalates)
  ├─ ioc_extraction           (ParallelAgent)                  ← unchanged
  ├─ deep_decompile           (LlmAgent, Ghidra; honors pcode_preferred)  ← prompt clause
  ├─ behavior_characterization (LlmAgent)                      ← unchanged
  ├─ attack_mapper            (LlmAgent)                       ← unchanged
  ├─ evidence_critic          (LlmAgent)                       ← known-tool list extended
  └─ malware_report_generator (LlmAgent)                       ← unchanged
```

The spine grows from 8 to 9 stages. All new loop/recovery agents + tools live in the
`reverse_engineering` capability **library** (mindset = "both"; reusable by a future
`vuln_research`). `malware_analyst` only wires `deobfuscation` into its spine and adds the
`deep_decompile` prompt clause. The one neutral-core addition is `build_escalation_gate`
(see `deobf_gate` below) — a small domain-neutral factory. `src/arema` otherwise stays
domain-neutral.

## The loop (detailed)

`deobfuscation` is an `AgentDescriptor` shell: `prompt_id=None`,
`factory=build_loop_agent`, `metadata={"max_iterations": 3}`, `sub_agent_ids=("deobf_classify",
"recover", "retriage", "deobf_gate")`. `build_loop_agent` (neutral core) already enforces the
positive-int cap and wires the `after_agent` slot. The four sub-agents run in fixed order each
iteration; ADK resets **sub-agent-local** state each iteration, so all per-iteration handoff
goes through **shared session state**. A successful new `acquire_sample` explicitly resets
the deobfuscation aliases, caches, sentinels, snapshots, and gate facts, then sets the
canonical current artifact to the newly acquired id; this prevents one analysis from gaining
authority over the next. LLM stages persist their
JSON-only final response through `AgentDescriptor.output_key`; function tools write typed
per-iteration recovery facts through `ToolContext.state`.

### `deobf_classify` (tool-less LlmAgent)
Reads `triage_recon`'s findings (sections, entropy, entrypoint stub, imports) and classifies
the obfuscation family, then returns one strict JSON document persisted through
`output_key="deobf:classification"` (ADK resets sub-agent-local state each loop iteration,
so all handoff is via shared state):
- `deobf_plan = {upx: bool, floss: bool}` — whether each binary-level recovery applies.
  `floss=true` only for a detected PE input (raw shellcode support is deferred until AREMA
  has an explicit shellcode format/architecture contract).
- `pcode_preferred: bool` + `obf_class: str` — set true when CFF / VM / bogus-control-flow /
  opaque predicates are detected (the classes LLM-only recovery cannot solve).
- `artifact_id` — the current artifact under analysis. It must equal the injected canonical
  current id when present, using triage's id only on the first iteration.
- `pre_snapshot` — exact size/function/import/string/section counts used as the first gate
  baseline.

Initial triage obtains the four inventory totals with `count=true`, gets size from
`show_info`, and emits a structured `DEOBF_PRE_SNAPSHOT`. The classifier uses that exact
snapshot rather than inferring totals from paginated inventories or conversational estimates.
After recovery, the IOC lenses prefer latest retriage and FLOSS findings whose
artifact id equals the injected canonical current artifact. They ignore stale
findings for other artifacts; initial triage remains the fallback on the
non-recovery path. Upstream r2/Ghidra/FLOSS citations and internally generated
UPX recovery provenance are preserved.

### `recover` (SequentialAgent of `upx_unpack` → `floss_decode`)
Fixed order. Each child always calls its single function tool once; the wrapper reads
`deobf:classification`, resets its per-iteration state, and **no-ops** (returns one
`applicable=false` result for a skipped FINDING) when its flag is false. Always calling the
wrapper prevents stale recovery state from a prior iteration. UPX runs first because it
transforms the substrate that FLOSS then operates on.

### `upx_unpack` (LlmAgent, tool `upx_unpack`)
Calls the `upx_unpack` deferred-factory tool, which stages the current artifact in the
case-scoped `deobfuscation-tools` Kubernetes sandbox and runs the pinned upstream UPX
binary against a copy. It never mutates the stored source. On recovery, AREMA checks the
output size before transfer, reads the recovered bytes back through the sandbox filesystem,
and admits them to `ArtifactStore`. The store is content-addressed by SHA-256, so the
recovered binary gets a **new `artifact_id`** (idempotent on identical bytes). The agent
writes that id to shared state under `deobf:current_artifact_id` and advances the strict
classification document to the same id, so every later stage
(FLOSS, retriage, ioc_extraction, deep_decompile, …) operates on the unpacked sample.
It also writes a bounded, internally generated identifier-safe provenance alias containing
the UPX tool name and source/destination SHA-256 ids. Later no-op iterations preserve this
alias only while its destination still equals the canonical artifact; new-sample intake
clears it.

"Not packed by UPX" is an expected `applicable=false` result, not degradation. A missing
Kubernetes backend, timeout, corrupt packed input, oversized recovery, or sandbox failure is
`success=false, degraded=true` and the agent skips (fail-open).

### `floss_decode` (LlmAgent, tool `floss_decode`)
Calls the `floss_decode` deferred-factory tool, which stages the current artifact in the
same case-scoped sandbox and runs pinned Mandiant FLOSS with structured output:
`floss --json --only decoded stack tight -- <artifact>`. The wrapper parses FLOSS's native
result document and returns bounded records preserving the string type, text, encoding,
function/decoding-routine address, and call/program-counter address where available, plus
total counts, a per-iteration `new_count`, and a truncation marker. The wrapper fingerprints
the exact normalized public record fields and retains a bounded, validated set in trusted
session state. `new_count` and the gate's FLOSS progress fact count only fingerprints not
seen in prior loop iterations; malformed or overflowing fingerprint state degrades
fail-closed. New-sample intake resets the set. The agent selects at most 20 meaningful
records and emits evidence-backed FINDINGs tied to the canonical source artifact
(finding-enrich; no new artifact).

FLOSS v3.1.1 decoded/stack/tight recovery applies to Windows PE and explicitly selected
x86/x64 shellcode, not general ELF or Mach-O inputs. Unsupported formats return
`success=true, applicable=false`; they are not reported as broken tooling. FLOSS's default
16 MiB input safety guard remains enabled (no automatic `--large-file`). The tool no-ops
when `deobf_plan.floss` is false.

### `retriage` (LlmAgent, r2 tools)
Uses the identifier-safe injected current-artifact alias and calls `prepare_sandbox` first so
a newly recovered artifact is copied into the already-claimed radare2 pod, then runs r2mcp
`open_file` → `analyze` and re-runs
the r2 surface (`show_info`, `list_imports`, `list_strings`, `list_sections`, …) on the
**current** `artifact_id`. It writes the post-recovery finding snapshot to shared state
through `output_key="deobf:retriage_snapshot"`. Exact totals come from
`list_functions/list_imports/list_strings/list_sections(count=true)` and size comes from
`show_info`. Evidence is separately bounded: functions use
`list_functions(count=false,start=0,max_length=25)`; imports, strings, and sections use
`count=false,page_size=25`, omit `cursor` on the first page, and never pass `page`. The
snapshot contains artifact id plus exact size/function/import/string/section counts and a
bounded `findings` array using the normal evidence schema so the recovered artifact's r2
observations remain available to `evidence_critic`.

### `deobf_gate` (non-LLM `BaseAgent`) — the evidence-gate
The ADK-canonical escalate checker (the docs' `CheckStatusAndEscalate` idiom): a deterministic
`BaseAgent` built by a new neutral-core factory `build_escalation_gate`. The generic factory
accepts a domain evaluator via `functools.partial`; AREMA core knows no deobfuscation keys.
The evaluator reads the classification/retriage JSON plus typed tool state and yields an
event with `actions.escalate = True` to exit the loop when **any** of:
1. **No obfuscation was detected** (`deobf_plan` all false) — clean binary, exit on iteration 1.
2. **No improvement this iteration** — recover produced no new artifact and no new decoded
   strings, and retriage's finding snapshot did not grow vs. the previous baseline (the
   classifier's `pre_snapshot` on iteration 1, then the prior retriage snapshot).
3. **`pcode_preferred` is set** — hand off to `deep_decompile`, which owns the Ghidra session
   and can actually run p-code emulation on CFF/VM.
4. **Recovery tools all degraded/unavailable** — nothing more the loop can do.

Otherwise the loop iterates again (re-classify on the recovered artifact), capped at
`max_iterations = 3`.

Before retriage metrics can affect this decision, the gate requires the current snapshot's
`artifact_id` to be a lowercase SHA-256 exactly equal to the strict canonical-bound
classification artifact id. Missing, malformed, or stale snapshot identity is
`invalid_state`; the previous metric-only baseline does not need an artifact id.

> **Why a `BaseAgent` and not `retriage`'s `after_agent_callback`:** AREMA's `after_agent`
> slot is currently populated only at the **pipeline end** from the profile's `record_memory`
> flag (`agent_factory.py`); there is no per-descriptor `after_agent` field, so attaching a
> callback to one specific agent would require a new descriptor field + builder wiring. A
> dedicated non-LLM gate `BaseAgent` needs only a small domain-neutral factory
> (`build_escalation_gate`), matches the ADK-canonical idiom the research surfaced, and keeps
> the gate's four escalation rules in one testable unit. Same `actions.escalate` semantics.

## p-code recovery → `deep_decompile` (flag-driven)

p-code recovery stays with the Ghidra-session owner. The deterministic gate first validates
classification shape and equality with canonical current-artifact state as one trust
boundary. Invalid/missing classification or canonical mismatch fails closed and clears the
identifier-safe `deobf_pcode_preferred` alias. After that boundary succeeds, the gate
normalizes the alias to `"true"`/`"false"` and preserves it even on
`recovery_not_called` or malformed later recovery/snapshot facts.
`deep_decompile` leads with `ghidra_pcode` (high-SSA) only when that alias is exactly
`true`, rather than reinterpreting conversational classification JSON. `prepare_ghidra`
independently enforces artifact custody: canonical current-artifact state overrides the
model argument, malformed ids fail before sandbox claim/copy, and the authoritative id is
returned for every prepared finding. No new engine session or loop-side Ghidra is added. (A future
`GhidraSessionManager` service that shares one prepared project across consumers is the
generalized solution, but it is **not needed this slice** because only `deep_decompile` uses
Ghidra.)

## Recovery tool platform

### Image and Kubernetes pool

This slice adds one general-purpose, extensible sandbox image:

```
images/deobfuscation-tools/
  Dockerfile
  .dockerignore
  healthcheck.sh
```

The image contains the real upstream tools, pinned for reproducibility:

- Mandiant [`flare-floss`](https://github.com/mandiant/flare-floss) **3.1.1**, installed as
  `flare-floss==3.1.1` (the upstream-recommended automated-analysis integration and
  architecture-portable on AREMA's amd64/arm64 builds).
- [`upx/upx`](https://github.com/upx/upx) **5.2.0**, downloading the release asset matching
  the Docker target architecture and verifying its SHA-256:
  - `upx-5.2.0-amd64_linux.tar.xz`:
    `3db5d3294707439db97866feab8d75d800f028f48481a40547411824da4288a1`
  - `upx-5.2.0-arm64_linux.tar.xz`:
    `55d48a61e8ffd17152db871c855376cba7f08e830b37799d0947a16dff8ec36c`

The build runs both version checks. Runtime uses fixed UID/GID 1000, a writable `/work`
only, and `sleep infinity`; no port is exposed. `healthcheck.sh` verifies every installed
production tool and is the pod's exec readiness probe. Future tools extend this same
healthcheck.

`deploy/sandbox/10-deobfuscation-tools-template.yaml` and
`20-deobfuscation-tools-pool.yaml` mirror the existing engine hardening: no service-account
token, non-root, no privilege escalation, all capabilities dropped, requests of 500m CPU /
1 GiB memory, and limits of 2 CPU / 4 GiB memory (FLOSS is the resource driver). The dev
warm pool has one replica. The logical pool key is `deobfuscation-tools`.

### Shared stateless runtime

The Python surface is deliberately split between reusable Kubernetes mechanics and
tool-specific semantics:

```
src/reverse_engineering/tools/deobfuscation/
  __init__.py
  runtime.py
  toolset.py
  upx.py
  floss.py
```

`runtime.py` owns:

1. Enforcing `sandbox_backend="k8s"` (never silently falling back to local execution).
2. Resolving `case_id` and idempotently claiming `(case_id, "deobfuscation-tools")`.
3. Validating SHA-256 artifact ids and staging immutable bytes at fixed, non-agent-controlled
   sandbox paths. Every caller supplies a fixed input limit; staging reads at most
   `limit + 1` bytes and rejects oversized input before pod claim/write.
4. Running developer-defined commands with the configured sandbox timeout.
5. Inspecting/reading bounded result files and normalizing operational failures. Binary
   recovery files are capped at **512 MiB**; structured result files are capped at
   **32 MiB** before `read_file`.

It does **not** interpret UPX errors, FLOSS JSON, applicability, or future tool output.
Those semantics stay in `upx.py` and `floss.py`. `toolset.py` exposes the explicitly curated
descriptor tuple registered by composition. No `prepare_deobfuscation` tool, daemon,
port-forward, MCP descriptor, or module-level case-state registry is needed; the
`SandboxExecutor` already makes claim reuse idempotent and session cleanup releases every
case-scoped handle.

### Function-tool contracts

- `upx_unpack() -> {success, applicable, source_artifact_id,
  recovered_artifact_id?, source_size?, recovered_size?, tool_version, reason?, degraded?}`
  — derives the source only from strict canonical state and runs `upx -d` against a copy.
  It enforces a documented **512 MiB input cap** before claim/write and the same 512 MiB
  recovered-output cap before host transfer. Recovered bytes are admitted through
  `ArtifactStore.acquire_bytes(data)` and keyed by SHA-256; the source remains immutable.
- `floss_decode() -> {success, applicable, source_artifact_id, source_size?, format,
  records, counts, new_count, tool_version, truncated, reason?, degraded?}` — derives the
  source only from strict canonical state and runs FLOSS JSON mode for PE
  decoded/stack/tight strings, parses the native schema, enforces the 32 MiB result-file
  limit, and returns at most **200 records** before the `OutputPolicy` context cap.

Both are deferred-factory `ToolDescriptor`s because they require live settings, sandbox
services, and artifact custody. Both respect `recover_tool_exception` (tool errors degrade,
never crash the run) and the `re_guarded` SanitizationMembrane (returned strings and errors
are binary-origin text). `upx_unpack` uses
`OutputPolicy(max_chars=4_000, max_list_items=20)`; `floss_decode` uses
`OutputPolicy(max_chars=50_000, max_list_items=200)`.

Within one iteration, a valid first wrapper result is cached so an accidental duplicate
model call cannot execute the sandbox twice. The deterministic gate's normal iteration
boundary clears both wrapper result caches and every per-iteration changed/count/degraded
fact while preserving only the bounded FLOSS seen-fingerprint set. A fresh wrapper call
invalidates any old cache before marking itself called; a missing or malformed cache behind
a true called marker is atomically replaced by the locked degraded response with zero
progress. This prevents cancellation between loop children from exposing prior-iteration
results. Cache reuse accepts only the exact documented success, non-applicable-reason, or
degraded response variant, including cross-field count/truncation and artifact-identity
invariants; it rejects missing, extra, or contradictory fields. A valid duplicate cache
rehydrates its changed/count/degraded gate facts from the cached response before returning,
so missing or stale state cannot alter the deterministic gate decision.

### Extension contract

Adding a future custom stateless deobfuscator requires:

1. Install and pin it in `images/deobfuscation-tools/`; extend `healthcheck.sh`.
2. Add one semantic wrapper module using the shared runtime.
3. Add its `ToolDescriptor` to the curated `toolset.py` collection.
4. Add its name to sanitization and evidence-provenance policy.
5. Add wrapper, image, manifest, applicability, and failure-contract tests.

Installing an executable alone never exposes it to the model. This pattern and its
eligibility boundary are added to `docs/CREATING_TOOLS.md` as the stateless sandbox-CLI
variant of a deferred-factory tool.

## evidence_critic + provenance

`evidence_critic`'s known-tool list is **extended** to include `upx_unpack` and
`floss_decode` (p-code is already listed). Recovery FINDINGs cite those tools. Findings
about the *unpacked* sample are doubly cited: the r2/ghidra tool that analyzed the recovered
bytes carries the claim, and `upx_unpack` is recorded as the recovery provenance (in the
finding `detail`) from the internally generated prompt-safe alias, so the evidence ledger
stays complete without accepting model-supplied provenance. This is a tool-list *extension*,
not the "relax `evidence_critic` for lens syntheses" change Slice 2 explicitly deferred.

## Error handling & boundaries

- Sandbox disabled, backend `local`, or `auto` falling back to local → tool returns a
  Kubernetes-required degraded result and **does not execute a host command**.
- UPX reports not-packed → `applicable=false`; FLOSS receives unsupported ELF/Mach-O →
  `applicable=false`. Expected non-applicability is distinct from degradation.
- UPX / FLOSS operational failure, timeout, malformed output, or sandbox error → tool
  returns `degraded`, agent skips, loop continues (fail-open; AREMA idiom).
- UPX output exceeding the fixed recovery cap is rejected before `read_file`; FLOSS output
  is written to a result file, schema-validated, and record-capped before entering model
  context.
- Gate never escalates → `max_iterations = 3` hard cap (NORTH_STAR "never-ending automation"
  guard; enforced at build time by `build_loop_agent`).
- Clean binary → `deobf_classify` sets all flags false → gate escalates on iteration 1 → the
  loop is a fast pass-through (one classify turn + one retriage turn + escalate).
- Non-UPX packer (Themida/VMProtect/custom) → `upx_unpack` degrades; if `classify` recognizes
  the family it may still set `pcode_preferred` / emit a "packed with X, static unpack
  unavailable" FINDING; dynamic memory-carve stays post-MVP.

## Files (this slice)

**Create (`src/reverse_engineering/`):**
- `tools/deobfuscation/runtime.py`, `toolset.py`, `upx.py`, `floss.py`, `__init__.py` —
  reusable stateless Kubernetes runtime, curated descriptor set, and the two semantic
  function-tool wrappers.
- `agents/deobfuscation.py` — `DEOBFUSCATION_DESCRIPTOR` (LoopAgent shell, `prompt_id=None`,
  `factory=build_loop_agent`, `metadata={"max_iterations": 3}`, sub_agents
  `deobf_classify`, `recover`, `retriage`, `deobf_gate`).
- `agents/recover.py` — `RECOVER_DESCRIPTOR` (SequentialAgent shell, `prompt_id=None`,
  sub_agents `upx_unpack`, `floss_decode`).
- `agents/deobf_classify.py`, `agents/upx_unpack.py`, `agents/floss_decode.py`,
  `agents/retriage.py`, `agents/deobf_gate.py` — the four LlmAgent descriptors + the gate
  descriptor (`prompt_id=None`, `factory=build_escalation_gate`).
- `prompts/deobf_classify.md`, `prompts/upx_unpack.md`, `prompts/floss_decode.md`,
  `prompts/retriage.md` (the gate has no prompt — it is a non-LLM `BaseAgent`).

**Create (image/deployment):**
- `images/deobfuscation-tools/Dockerfile`, `.dockerignore`, `healthcheck.sh` — pinned
  upstream UPX + Mandiant FLOSS, multi-architecture, non-root.
- `deploy/sandbox/10-deobfuscation-tools-template.yaml` +
  `20-deobfuscation-tools-pool.yaml` — hardened template and one-replica dev warm pool.

**Neutral core (`src/arema/runtime/agent_factory.py`):**
- `build_escalation_gate(context) -> BaseAgent` — a small domain-neutral factory that returns
  a non-LLM `BaseAgent` whose `_run_async_impl` reads shared state and yields
  `Event(actions=EventActions(escalate=True))` per the four rules. The rules themselves are
  expressed via a small predicate the `deobf_gate` descriptor supplies (e.g. via `metadata`),
  so the factory stays generic/reusable and `src/arema` stays domain-neutral. Exported in
  `__all__`. (No change to the `before_tool`/`after_tool` callback-chain invariants — the
  gate is a leaf agent, not part of the tool callback chain.)

**Modify:**
- `src/reverse_engineering/artifacts/store.py` — add
  `ArtifactStore.acquire_bytes(data: bytes) -> str`, the byte-return counterpart to
  `acquire(path)`, preserving content-addressed idempotence for sandbox-recovered outputs.
- `src/reverse_engineering/composition.py::register_re_infrastructure` — register the
  deobfuscation tools + `DEOBFUSCATION_DESCRIPTOR` / `RECOVER_DESCRIPTOR` and re-export them.
- `src/reverse_engineering/prompts/deep_decompile.md` — add the `pcode_preferred` clause.
- `src/reverse_engineering/prompts/evidence_critic.md` — add `upx_unpack`, `floss_decode`
  to the known-tool list.
- `src/reverse_engineering/profiles.py` — add both tools to the binary-origin sanitizer set.
- `src/malware_analyst/agents/malware_analyst.py` — root `sub_agent_ids` 8 → 9 stages
  (insert `deobfuscation` after `triage_recon`).
- `src/malware_analyst/composition.py` — register `DEOBFUSCATION_DESCRIPTOR` +
  `RECOVER_DESCRIPTOR` + the four loop LlmAgents + `deobf_gate`.
- `Makefile` — add `sandbox-deobfuscation-image/up/down` and include them in the aggregate
  sandbox targets.
- `.env.example` — document the `deobfuscation-tools` pool-map entry and Kubernetes backend
  requirement.
- `docs/CREATING_TOOLS.md` — document the stateless sandbox-CLI function-tool pattern and
  its boundary versus stateful Ghidra/radare2 integrations.

**Tests:**
- `tests/reverse_engineering/` — shared runtime + tool wrappers (fake sandbox executor and
  realistic FLOSS JSON), `build_escalation_gate`'s four escalation rules,
  `deobf_classify` plan shape, the loop builds as a `LoopAgent` with
  `max_iterations=3`, `recover` is a `SequentialAgent` of `upx_unpack → floss_decode`, and
  `deobf_gate` is a `BaseAgent` (not `LlmAgent`).
- `tests/unit/test_deobfuscation_tools_manifest.py` — image/template/pool structure,
  readiness, non-root hardening, and expected image identity.
- `tests/malware_analyst/test_malware_analyst_composition.py` — extend to the 9-stage spine;
  `deobfuscation` is a `LoopAgent` nested in the `SequentialAgent`.
- `tests/architecture/test_neutral_boundaries.py` — stays green (`src/arema` additions are
  the domain-neutral `build_escalation_gate` only).

## Scope

**In scope:**
- The `deobfuscation` LoopAgent + `recover` SequentialAgent + 4 LlmAgent children + prompts.
- The pinned upstream UPX + Mandiant FLOSS `deobfuscation-tools` image, Kubernetes
  template/warm pool, reusable stateless runtime, and two curated function tools.
- The evidence-gate `deobf_gate` `BaseAgent` (4 deterministic escalation rules).
- The 9-stage spine wiring + the `deep_decompile` `pcode_preferred` clause + the
  `evidence_critic` known-tool extension.
- Sanitizer/evidence registration, Make/config documentation, and the
  `docs/CREATING_TOOLS.md` extension contract.
- Tests (unit + component + architecture + manifest) + image/version smoke + live UPX and
  FLOSS fixtures.

**Out of scope (deferred):**
- Generic / custom packer unpacking (Themida/VMProtect/memory-carve) — dynamic analysis,
  post-MVP (NORTH_STAR `DynamicAnalysis`).
- Implementing additional custom deobfuscators (this slice establishes their extension seam
  but ships only UPX and FLOSS).
- A `GhidraSessionManager` shared-session service (only needed if a future loop step touches
  Ghidra; this slice keeps Ghidra solely in `deep_decompile`).
- Full Phase-2 recovery breadth (capa, YARA, Detect-It-Easy, Ghidra p-code *emulation*
  scripts beyond the existing `ghidra_pcode` view).
- ADK 2.0 graph-workflow migration (the installed ADK runs the template workflows; flagged
  as a future watch).

## Testing

- **Unit — shared runtime:** fake executor proves Kubernetes-backend enforcement, case-id
  resolution, idempotent claim reuse, SHA-256 validation, fixed non-agent-controlled paths,
  artifact staging, configured timeout use, bounded file reads, and normalized failures.
  A dedicated test proves `LocalSandboxExecutor` is never invoked.
- **Unit — UPX:** recovered/not-packed/corrupt/timeout/unavailable-sandbox/oversized-output
  outcomes. Verify the source artifact is immutable, the recovered output is admitted under
  its content hash through `acquire_bytes`, identical recovered bytes are idempotent, and
  output size is checked before transfer.
- **Unit — FLOSS:** realistic v3.1.1 result documents for decoded/stack/tight strings;
  preserve type/address/encoding provenance; PE applicability; ELF/Mach-O non-applicability;
  default input-size guard; malformed JSON; record truncation; timeout and sandbox failure.
- **Unit — orchestration:** `deobf_gate`'s four escalation rules (clean binary / no
  improvement / `pcode_preferred` / all-degraded). `deobf_classify` plan shape (writes
  `deobf_plan`, `pcode_preferred`, `artifact_id`).
- **Component:** the 9-stage spine builds; `deobfuscation` is a `LoopAgent` nested in the
  `SequentialAgent`; `max_iterations == 3`; `recover` is a `SequentialAgent` of
  `upx_unpack → floss_decode`; the loop's sub-agents resolve real prompts; no lens/loop
  prompt contains "transfer to" / "delegate to".
- **Image/manifest:** pinned version arguments + checksums are present; amd64 and arm64 UPX
  selection is covered structurally; image runs `upx --version` and `floss --version`;
  readiness uses `healthcheck.sh`; pod is non-root with no token, no privilege escalation,
  dropped capabilities, bounded resources, no exposed port; warm pool references the
  template.
- **Architecture:** `src/arema` still domain-neutral; loop + tools live in
  `reverse_engineering`; the shared runtime contains no UPX/FLOSS semantic parsing; the
  curated toolset exposes only explicitly registered tools.
- **Live smoke (final gate):**
  1. Build/load the image and verify both real upstream version commands in the pod.
  2. A UPX-packed `/bin/ls` (packed with the same pinned UPX) round-trips through
     `deobfuscation` (unpack → re-triage), and the report contains recovered
     strings/imports. Regression: unpacked `/bin/ls` returns `applicable=false` and
     completes without recovery.
  3. A controlled PE fixture with known decoded/stack strings produces typed FLOSS records
     and evidence-backed FINDINGs. Do not use ELF `/bin/ls` as the FLOSS happy-path fixture.

## Risks & mitigations

| Risk | Mitigation |
|------|------------|
| Artifact identity drift: downstream stages read the wrong (pre-unpack) `artifact_id`. | Canonical current state is seeded by intake and cannot be derived from model output. Recovery and gate consumers require strict classification equality. Successful UPX admission advances canonical and classification ids together; retriage and later stages use prompt-safe canonical state. |
| Recovered artifact exists in `ArtifactStore` but not in the radare2 pod. | `retriage` owns `prepare_sandbox` and calls it with the current id before r2mcp `open_file`; the idempotent case-scoped claim reuses the pod while copying the new bytes. |
| ADK resets sub-agent-local state each loop iteration → per-iteration handoff lost. | LLM JSON uses descriptor `output_key` entries and function tools use typed `ToolContext.state` entries in shared session state, which is **not** reset. The recovery wrappers reset iteration-scoped facts before every run, and `deobf_gate` reads only these explicit keys. |
| Gate never escalates → infinite loop. | `max_iterations = 3` hard cap, enforced at build time by `build_loop_agent` (raises if absent/not a positive int). NORTH_STAR mandate. |
| Malicious parser input reaches UPX/FLOSS. | Kubernetes-only execution in a hardened non-root sandbox; no host/local fallback. UPX upstream explicitly requires execution-equivalent precautions for handled files. |
| Image silently contains the wrong/missing tool or architecture. | Pin upstream releases, verify UPX asset checksums, select amd64/arm64 asset explicitly, run version checks at build and readiness, and exercise both commands in the image smoke. |
| UPX expands a crafted sample into an enormous artifact. | Inspect output size inside the pod and enforce a fixed maximum before `read_file` or `ArtifactStore` admission. |
| FLOSS produces huge or malformed output. | Write JSON to a sandbox result file, validate the native result schema, retain the upstream 16 MiB input guard, apply a fixed record cap, then apply `OutputPolicy`. |
| FLOSS is treated as a universal ELF/Mach-O decoder. | Classifier and wrapper gate decoded/stack/tight recovery to PE (plus explicitly selected shellcode in future); unsupported formats are explicit non-applicability. Separate PE live fixture. |
| Future image additions become accidental model capabilities. | Tool installation and model exposure are separate. Explicit descriptor/toolset registration, sanitizer/evidence policy, and contract tests are mandatory for every addition. |
| A future stateful engine is forced into the stateless shared runtime. | Eligibility boundary is documented: stateful/exploratory tools receive their own engine image/pool and MCP or lifecycle integration. |
| `upx_unpack` finding citation: the unpacked sample's findings cite r2/ghidra tools, but the unpack itself is the provenance. | Doubly cited: r2/ghidra tool carries the claim; `upx_unpack` recorded in `detail`. `evidence_critic` known-tool list extended so it does not reject recovery provenance. |
| Deobf agents invent findings not backed by a tool. | Same invariant as Slice 2: every recovery FINDING cites a known tool (`upx_unpack` / `floss_decode` / r2 / ghidra). `evidence_critic` enforces it unchanged in spirit. |
| p-code path in `deep_decompile` never triggers (flag never set). | `deobf_classify` sets `pcode_preferred` on recognized CFF/VM; component test asserts the flag round-trips into state when classify detects the class. |
