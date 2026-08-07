# AREMA Scripted Unpacking Agent — Design

**Status:** Spec (2026-07-28; design approved — Q1/Q2/Q3 resolved with the user).
**Branch:** `feat/scripted-unpacking` (off `main` = `e72f729`).
**Post-MVP follow-on to:** `2026-07-25-deobfuscation-loop-design.md`, which scoped
*"generic/custom packer unpacking (dynamic memory-carve) stays post-MVP"* — this
is that work.
**Depends on (merged):** the deobfuscation LoopAgent (`deobf_classify` →
`obf_class == packed-other`; the `recover` → `CURRENT_ARTIFACT_KEY` → retriage →
provenance flow); the `deobfuscation-tools` sandbox runtime
(`stage_artifact`/`run_argv`/`read_bounded_file`); the content-addressed
`ArtifactStore`; the k8s agent-sandbox (WarmPool/SandboxClaim + the
`prepare_ilspy` port-forward pattern); `format_router` (conditional-wrapper
precedent); `context/budget.py` pressure tiers; the `OutputPolicy` compactor.
**North star:** `docs/NORTH_STAR.md` (packed-sample recovery / deobfuscation
lineage).
**Architecture constraints:** `docs/AGENTS_AND_DISCOVERY.md`,
`docs/ARCHITECTURE.md`, `docs/LESSONS_LEARNED.md`; neutrality
(`tests/architecture/test_neutral_boundaries.py`).

## Decisions (locked with the user)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Unpack strategy | **Static reimplementation only** for the first build; architecture prepared so a CPU emulator (ESIL → Unicorn/Qiling) drops in later with no rewrite. |
| 2 | radare2 exposure | **Full r2pipe inside the sandbox**; the read-only `radare2_mcp` stays as the cheap triage front-end (it structurally cannot do write/patch/emulate). |
| 3 | Execution backend | **Stateless exec + persistent filesystem workspace** now; swap to a persistent kernel (port-forward pattern) when emulation needs in-memory VM continuity — same `run_python` contract. |
| 4 | Isolation | **gVisor** + deny-all egress + read-only rootfs + non-root + dropped caps + cgroup memory cap now; **Kata/microVM** for the emulation phase. |
| 5 | .NET managed layer | **de4dot/dnlib companion path** (Phase 2), not radare2 — this is what serves the motivating `1595d92f…` .NET sample. |
| 6 | Placement | **A conditionally-gated `scripted_recover` stage *inside* the deobfuscation `LoopAgent`** (between `recover` and `retriage`), reusing `CURRENT_ARTIFACT_KEY` + `retriage` + `deobf_gate` + multi-stage recursion. A single gated `LlmAgent` (its tool loop is the iteration), with a global `run_python` budget — not a separate post-loop stage, not a nested `LoopAgent`. (Revised from the first draft after reading the code — see §3.) |

> The detailed, bite-sized implementation plan is a **separate** document per the
> Superpowers standard: `docs/superpowers/plans/YYYY-MM-DD-scripted-unpacking-*.md`,
> produced by the `writing-plans` skill after this spec is approved. §7 below is
> the high-level roadmap only.

## 1. Motivation

Our current deobfuscation stage recovers only the cases its two fixed CLI tools
know: `upx_unpack` (UPX) and `floss_decode` (obfuscated-string decoding). A real
sample — e.g. the packed .NET assembly in
`samples/dotnet/1595d92f…exe` (entropy 7.96, SmartAssembly/Dotfuscator markers) —
defeats both: it is not UPX, and its strings are decrypted at runtime, so FLOSS
finds nothing. `deobf_classify` already has a name for exactly this: **`obf_class
== packed-other`** (packed, but not by a tool we support).

When an expert reverse engineer hits this, they reach for **Python + radare2**:
detect the packer, read the unpacking stub, work out the decrypt/decompress
algorithm and its key material, and **reimplement it in Python** to recover the
cleartext payload — then continue analysis on the recovered code. This is a
capability, not a fixed tool: it needs the freedom to write and re-run many small
scripts, bounded by a resource budget so a hard sample cannot burn the host.

This document specifies an agent that performs that process and a phased plan to
build it as a clean extension of the existing architecture.

### 1.1 Honest scope boundary (important)

Industry practice is unambiguous on one point that affects the motivating sample:
**Python + radare2 is the right toolchain for _native_ packers, not for _.NET
managed-metadata_ protection.** radare2 sees a .NET PE's wrapper but not its CIL
method bodies / metadata tables in a useful way, and protectors like ConfuserEx /
.NET Reactor / SmartAssembly attack exactly that metadata. The standard tooling
for the managed layer is **de4dot / dnlib / dnSpyEx** (plus dynamic memory
dumping for `Assembly.Load`-style packers).

Consequences for this design:

- The scripted (Python + radare2) unpacker delivers real value on **native
  custom/unknown packers and the native _outer_ layer** of a sample.
- The **.NET managed layer is a sibling recovery path** (de4dot/dnlib), selected
  by format routing — not something radare2 solves. We treat it as a companion
  capability (Phase 2), so the motivating .NET sample is actually served.

Setting this expectation up front avoids building a radare2 tool and being
surprised it can't decrypt ConfuserEx metadata.

## 2. Design principles (grounded in industry practice)

1. **Emulate, never detonate — and in Phase 1, don't even emulate.** The whole
   generic-unpacking literature (PolyUnpack/Renovo/OmniUnpack; Qiling/Speakeasy)
   exists to recover unpacked bytes _without_ running the sample on a real host.
   Phase 1 goes further: pure static reading + Python reimplementation, no
   execution and no emulation of the stub at all.
2. **Broad agent freedom inside a deterministic outer bound.** Give the agent an
   open Python + full-radare2 workbench; wrap it in a resource governor
   (per-exec timeout, memory cgroup, output caps, max-executions, wall-clock and
   token budgets) that _guarantees termination_ and degrades gracefully.
3. **Bound radare2 at the sandbox boundary, not at the command set.** Unpacking
   needs write/patch (`io.cache`), segment dumps (`wtf`), and (later) ESIL
   emulation — operations a fixed read-only tool surface structurally cannot
   express. Give the agent the **full r2pipe API inside the sandbox**; safety
   comes from the isolated, disposable per-case pod. (radare2's own MCP ships a
   raw-command passthrough for the same reason.)
4. **The read-only radare2 MCP stays as the cheap _triage_ front-end.** It is not
   the unpacking engine. Progressive disclosure: cheap guided triage via the MCP;
   heavy unpacking via `run_python` + r2pipe.
5. **Results stay in the sandbox; only summaries reach the model.** Never push
   raw bytes into context — return hexdump slices, offsets, sizes, entropy, and
   hashes; spill full payloads/dumps to the SHA-256 artifact store and hand the
   model the hash + metadata. This dovetails with our existing `OutputPolicy`
   compactor and `context/budget.py` pressure tiers.
6. **Reuse existing rails.** Recovery already has a shape in this codebase
   (stage artifact → produce a new artifact → set `CURRENT_ARTIFACT_KEY` →
   retriage → carry provenance). The new capability rides those rails.

## 3. Where it fits in the pipeline — *inside* the deobfuscation loop

Current malware spine and the deobfuscation loop body:

```
sample_intake → triage_recon → deobfuscation(LoopAgent) → deep_engine_router → …

deobfuscation (LoopAgent, max_iterations):
    deobf_classify → recover(SequentialAgent: upx_unpack → floss_decode)
                   → retriage → deobf_gate
```

The scripted unpacker is a **new conditionally-gated `scripted_recover` stage
inside the deobfuscation loop, between `recover` and `retriage`** — *not* a
separate stage after the loop:

```
deobfuscation (LoopAgent, max_iterations raised for multi-stage):
    deobf_classify
      → recover            (cheap deterministic tools: UPX, FLOSS — unchanged)
      → scripted_recover   [gated: runs only when obf_class == packed-other,
                            nothing recovered yet this round, and the global
                            run_python budget remains]
      → retriage           (re-measures the recovered artifact — already
                            CURRENT_ARTIFACT_KEY-aware)
      → deobf_gate         (loops for the next packed layer, or exits on
                            no-improvement / budget)
```

**Why in the loop, not a separate post-loop stage** (this reverses an earlier
draft; the code settled it):

- The loop *owns* the recovery machinery a post-loop stage would have to
  reinvent: `CURRENT_ARTIFACT_KEY` (the artifact hand-off, §4.3), `retriage`,
  `deobf_gate`, provenance, and `recovery_evidence_json`.
- **Multi-stage recursion is free.** Real packers nest (packer → loader → core).
  The loop already does `classify → recover → retriage → gate → repeat`, so each
  iteration re-classifies the *recovered* artifact and cracks the next layer. A
  separate stage would rebuild this and would leave inconsistent evidence (triage
  of the packed original vs deep analysis of the recovered payload, with nothing
  re-measuring between).
- `max_iterations = 3` was a red herring — it's a tunable (raise it for the
  `packed-other` path), not an architectural reason to separate.

**Why a distinct stage and not a third sub-agent inside `recover`:** keep
`recover` homogeneous (instant, deterministic CLI tools). `scripted_recover` is
the natural home for a **format-router of *advanced* recovery strategies**,
mirroring `deep_engine_router`:

| Sample format | Advanced recovery path |
|---|---|
| native PE / ELF / Mach-O, `packed-other` | scripted static-reimplementation agent (this spec) |
| .NET / CLR, protected | `.NET recovery` companion (de4dot / dnlib) — Phase 2 |
| (future) any, static-resistant | emulation (ESIL → Unicorn/Qiling) — Phase 3 |

**The agent, not a nested loop.** `scripted_recover` gates a single **`LlmAgent`**
(`packer_analyst`) whose *own tool-calling loop* is the write→run→refine
iteration — it calls `run_python` many times in one invocation. No inner
`LoopAgent` is needed. Two iteration scales, cleanly separated: the **outer
deobfuscation loop** handles multi-stage recursion; the **agent's tool loop**
cracks one stage. The budget is a **global** `run_python` execution counter in
session state (spans loop iterations, does not reset per round), enforced by a
`before_tool` guard (§4.5).

## 4. Architecture

### 4.1 The workbench sandbox pool

A new pool `analysis-workbench` modeled on the existing `deobfuscation-tools`
template (exec-driven, non-root, dropped caps), with a richer image and stronger
isolation.

**Image `arema-analysis-workbench` — Phase 1 inventory:**

- `python3` + `radare2` + **`r2pipe`** (full scripting: read/patch/dump; ESIL is
  present but reserved for the emulation phase)
- Static PE/format tooling: **`pefile`**, **`LIEF`**, **`die-python`** (Elastic's
  Detect-It-Easy bindings, JSON packer/protector ID), **`yara-python`**
- Transform reimplementation: **`pycryptodome`** (AES/DES), **`arc4`** (RC4),
  **`aplib`** / `pylzma` / `zlib` (LZ family), crypto-constant scanning (`capa`)
- Dump repair (for recovered native payloads): **`libpeconv`/`pe_unmapper`**
  bindings or scripted `pefile`/`LIEF` for virtual→raw unmapping + header fix

**Emulation-phase additions (not built now):** `unicorn`, `capstone`,
`keystone`, `qiling`, `speakeasy-emulator`, `unipacker`. **.NET-companion
additions (Phase 2):** `de4dot` / `dnlib` (via the .NET runtime), and optionally a
dynamic-dump helper.

**Pod hardening** (all mandatory, independent of runtime):

- **Runtime isolation (gvisor/kata) is a documented production prereq, not a
  hard-set base-template field** — matching the existing fleet convention (every
  engine template *comments* the requirement rather than setting an unprovisioned
  `runtimeClassName`). The reference Kind cluster runs the whole fleet under the
  default runtime; provisioning gvisor/kata (RuntimeClass + runsc on the nodes)
  is a fleet-wide production-deployment concern applied via a deploy-time overlay,
  not per-pod YAML. Static-only Phase 0 needs no runtime isolation to *run*;
  Phase 1's static reading of hostile bytes (native-parser RCE risk) and the
  emulation phase (Phase 3) are what make provisioning it in production
  mandatory. Do **not** hard-set `runtimeClassName: gvisor` in the base template
  — it would make the workbench pod unschedulable on any cluster without the
  RuntimeClass (the fleet's readiness waits would then time out).
- **Deny-all egress `NetworkPolicy`** (including DNS) — no C2/exfil path. This is
  hard-set and **actually enforced**: install a policy-enforcing CNI (Calico) so
  the policy is not a silent no-op (Kind's default kindnet ignores NetworkPolicy).
- `readOnlyRootFilesystem: true`, no host mounts, ephemeral scratch under the
  case work dir only.
- `runAsNonRoot`, drop `ALL` caps, `allowPrivilegeEscalation: false`,
  `seccompProfile: RuntimeDefault`.
- `resources.limits`: CPU capped; **memory _limited_** (e.g. 4Gi) — unlike Ghidra
  (which we deliberately left uncapped), analysis code the agent writes can loop
  or allocate unboundedly, so a hard OOM-kill ceiling is a required backstop.

This is the same "before hostile code, set `runtimeClassName` to gvisor/kata"
note the existing templates already carry — made concrete and mandatory here.

### 4.2 Execution model & the `run_python` tool contract

The agent sees one stable tool:

```python
run_python(code: str, timeout_s: int = 60) -> ExecutionResult
```

`ExecutionResult` is modeled on E2B's execution object (the de-facto standard):

```
ExecutionResult:
  stdout: list[str]
  stderr: list[str]
  results: list[Result]          # rich results (text, json, png hexdump, …)
  error:   ExecutionError | None # name, value, traceback  ← agent debugs from this
  execution_count: int
  artifacts: list[str]           # SHA-256s of anything spilled to the store
```

**Phase 1 backend — stateless exec over a _persistent workspace_.** The Python
process is fresh each call, but the per-case workspace `/work/<case>` **persists
across calls**: dumps, intermediate files, helper modules the agent writes, and
the r2 project all survive. For static reimplementation this is sufficient and
much simpler than a live kernel — re-opening r2 per script is cheap, and the
agent accumulates state on the _filesystem_ (write a `helpers.py`, a
`stage1.bin`, notes) rather than in memory.

This reuses `tools/deobfuscation/runtime.py` almost verbatim
(`stage_artifact` → `run_argv` with the TERM/KILL `timeout` wrapper + bounded
output → `read_bounded_file`), with **one addition: a persistent-workspace
variant** of `stage_artifact` that prepares `/work/<case>` **once** (today
`stage_artifact` `rm -rf`s the work dir on every call) and lets subsequent
`run_python` calls reuse it.

**"Preparing the ground" for emulation — the contract is backend-agnostic.** When
the emulation phase needs in-memory VM continuity (keep an ESIL/Unicorn VM alive
across steps), the backend swaps from stateless-exec to a **persistent kernel**
(a minimal exec service, or Jupyter Kernel Gateway) running in the pod and reached
via `kubectl port-forward` — _exactly the pattern `radare2-mcp` and `ilspy-mcp`
already use_ (persistent service in a pod, port-forward, `prepare_*` claims +
tunnels). **No change to the agent or the `run_python` contract** — only the
tool's implementation and the pod image change. The industry consensus (E2B,
OpenAI, open-interpreter, AutoGen) is a persistent kernel for iterative code; we
adopt it _when emulation makes it necessary_, not before.

**radare2 access.** Inside `run_python`, scripts get the **full r2pipe API**
(`r2 = r2pipe.open(sample, flags=["-w"])`, `e io.cache=true`, read/patch/dump).
The existing read-only `radare2_mcp` remains available to the worker for cheap
guided triage. Two surfaces, two jobs: MCP = safe triage; r2pipe = unpacking.

### 4.3 Result handling & the artifact hand-off

- Truncate inline output (bytes + lines) via the existing `OutputPolicy`
  compactor; when it overflows, **spill the full output to the artifact store**
  and return head+tail + a `artifact://<sha>` pointer.
- A finalization tool registers the recovered payload:

  ```python
  register_unpacked_artifact(workspace_path: str, method: str) -> dict
  #   validates: file exists, size sane, entropy DROPPED vs. the packed input,
  #              parses as a plausible PE/ELF/Mach-O; rejects "still-packed" dumps
  #   → ArtifactStore.acquire(...) → new SHA-256
  #   → sets CURRENT_ARTIFACT_KEY + recovery provenance (unpacked ← original, method)
  #   → returns {artifact_id, size, entropy_before, entropy_after, format}
  ```

**How the recovered plaintext reaches the rest of the pipeline (no new
mechanism).** There is already a canonical "current artifact" in session state,
`CURRENT_ARTIFACT_KEY = "deobf:current_artifact_id"`, and **every downstream
consumer reads it, not the original**:

| Consumer | Reads `CURRENT_ARTIFACT_KEY` at |
|---|---|
| `prepare_ghidra.py:157` | the artifact Ghidra stages/decompiles |
| `prepare_sandbox.py:100` | the artifact the radare2 sandbox loads |
| `deep_analysis_gate.py:47` | the deep-analysis coverage anchor |
| `evidence_output.py:74,140` | the artifact every evidence envelope is bound to |
| `ghidra/coverage.py` | the deep-analysis coverage key |

`reset_deobfuscation_state` sets it to the original at intake; **`upx.py:250`
does `state[CURRENT_ARTIFACT_KEY] = recovered_artifact_id`** the instant UPX
unpacks. `register_unpacked_artifact` does *exactly the same* — so Ghidra and all
downstream stages transparently analyze the recovered payload, with zero
downstream changes. Because the stage lives *inside* the loop, `retriage` then
re-measures the recovered artifact and the gate decides whether to recurse, so
the evidence stays consistent (this is what a post-loop stage could not do).

### 4.4 The agent (a single gated `LlmAgent`)

```
scripted_recover   (conditional wrapper — runs only for native `packed-other`,
                    nothing recovered yet this round, global budget remaining)
  └─ packer_analyst   (LlmAgent, re_guarded profile)
        tools: run_python, register_unpacked_artifact, radare2_mcp (read-only triage)
        # the model's own tool-calling loop is the write→run→refine iteration;
        # a before_tool guard caps total run_python executions (global counter).
```

No inner `LoopAgent`: the `LlmAgent` naturally calls `run_python` repeatedly
within one invocation. Success/give-up is decided by the existing **`deobf_gate`**
(which already reads `CURRENT_ARTIFACT_KEY`, the retriage delta, and the iteration
count) plus the `before_tool` execution guard — no new gate agent. The gate's
existing "no-improvement → exit" logic already gives the honest give-up: if
`packer_analyst` recovered nothing, `CURRENT_ARTIFACT_KEY` is unchanged, retriage
shows no delta, and the loop exits (the pipeline continues on the packed sample,
with the "packed/protected" finding triage / `dotnet_decompile` already emitted).
On a static-resistant sample the worker emits a `recovery:scripted_unavailable`
limitation — the natural hook where a future **emulation escalation** (Phase 3)
plugs in.

**`packer_analyst` prompt** encodes the static-reimplementation workflow:

1. **Detect / confirm packing** — `pefile`/`die-python`: EP-section entropy
   (>7.0, tune), W^X sections, `SizeOfRawData==0`, EP outside `.text`, tiny import
   table (`LoadLibrary`/`GetProcAddress`/`VirtualAlloc` pattern), DIE/YARA hit.
2. **Locate the unpacking stub** via r2pipe (entry point, first-executed code,
   xrefs to the packed section).
3. **Fingerprint the transform** — recognize XOR/rolling-XOR (tight
   `xor`+`rol/ror` loop), RC4 (twin 0..255 KSA loops + swaps, PRGA XOR), AES
   (Rijndael S-box constant / key schedule), LZ (aPLib/LZMA/zlib magic or
   decompress-API call). Crypto-constant scan.
4. **Recover key material statically** — read embedded constants, trace data-flow
   from the decrypt loop back to its key source (resource/overlay/constant).
5. **Reimplement in Python** — `arc4`/`pycryptodome`/`aplib` reproduce the
   cleartext deterministically; write it to the workspace.
6. **Validate & fix up** — entropy dropped? parses as PE/ELF? For a native dump,
   unmap virtual→raw + rebuild header/IAT (`pe_unmapper`/`LIEF`/`pefile`).
7. **Register** the recovered artifact and emit the packer-mechanism finding.
   Recurse-awareness: note if the payload is itself packed (bounded by the gate).

**Control flow is the existing `deobf_gate`, not a new gate** (deterministic — the
exit authority for the whole loop):

- **Success:** `register_unpacked_artifact` set `CURRENT_ARTIFACT_KEY` to a valid
  artifact (entropy dropped, format sane) + emitted `recovery` evidence + the
  mechanism finding → `retriage` shows a delta → `deobf_gate` loops to crack the
  next layer (or exits if the payload is now clean).
- **Continue:** budget remains and the sample is still packed → the loop's next
  round re-runs `deobf_classify` → `scripted_recover`.
- **Give up (bounded):** the global `run_python` counter, `max_iterations`,
  wall-clock, or token budget is hit, or `retriage` shows no improvement → the
  existing `deobf_gate` "no-improvement / iteration-cap → exit" path fires. The
  worker emits a `recovery:scripted_unavailable` limitation (honest, not
  fabricated). The pipeline continues on the packed sample — the natural hook for
  a future **emulation escalation** (Phase 3).

Only deterministic `BaseAgent` gates decide control flow (consistent with
`deobf_gate`, `deep_analysis_gate`, `format_router`); the LLM only decides
_within_ a step.

### 4.5 Resource governor — the "threshold to prevent resource exhaustion"

Two nested layers, matching the industry pattern (freedom inside a deterministic
bound):

**Per-execution (hard, enforced by the sandbox):**

| Bound | Starting value | Enforced by |
|---|---|---|
| wall/CPU timeout per `run_python` | 60 s (300 s "long" flag) | `run_argv` TERM/KILL `timeout` wrapper |
| memory | 4 GiB hard | pod cgroup → OOM-kill |
| output per exec | 32 KiB / 2000 lines | `OutputPolicy` + spill-to-store |

**Loop-level (agent budget, surfaced gracefully):**

| Bound | Starting value | Enforced by |
|---|---|---|
| max `run_python` executions / case (**global**, spans loop rounds) | 40 | `before_tool` guard on a state counter |
| deobfuscation loop rounds (≈ packer stages) | `max_iterations` (raise from 3 for `packed-other`) | the deobfuscation `LoopAgent` + `deobf_gate` |
| total wall-clock / case | 30–60 min | outer watchdog |
| token budget / case | existing tiers | `context/budget.py` (NORMAL/WARNING/HARD/CRITICAL) |

**Graceful wrap-up:** at ~80 % of any budget, inject a "you have N executions / T
seconds left — finalize the best artifact you have and report" advisory (reuse the
WARNING/HARD tier + checkpoint-on-CRITICAL machinery already in the shell) so the
agent dumps what it has before the hard bound fires. Never a silent hard kill
mid-experiment.

### 4.6 Evidence, provenance & the report

- **Recovery evidence finding** — the reverse-engineered packer mechanism
  (algorithm, key source, payload location, OEP, IAT status). This is
  first-class threat intel, not a byproduct: "custom RC4, key = little-endian PE
  timestamp, payload in `.rsrc/CFG`, decrypted in place then jumped at OEP
  0x…". It flows into the evidence bus (a new `recovery`-family key or the
  existing `recovery_evidence_json`) and the report.
- **Provenance** links `unpacked ← original` + method, like `upx_provenance`, so
  the `evidence_critic` attributes findings on the recovered artifact correctly
  and the report can say "analysis performed on the unpacked payload".

## 5. Safety model (summary)

- **Phase 1 is static-only:** no sample execution, no emulation. Residual risk is
  a parser/library RCE from hostile input → contained by gVisor + deny-all
  egress + read-only rootfs + non-root + dropped caps + cgroup limits + the
  disposable per-case pod.
- **Never native execution** of the sample, in any phase.
- **Full r2pipe power ⇒ the sandbox boundary is load-bearing.** That is the point
  of the isolation above; the blast radius is one disposable pod with no network.
- **Emulation phase raises the bar:** ESIL first (r2-native _interpretation_,
  minimal added surface), then Unicorn/Qiling; escalate the runtime to
  Kata/microVM and keep the deny-all egress + instruction-count caps.

### 5.1 Prompt-injection surface & the SanitizationMembrane

`run_python` is the **single most potent prompt-injection surface in the whole
pipeline**, and the design must treat it that way. The `re_guarded` profile
already installs an `after_tool` **SanitizationMembrane**
(`make_sanitizing_after_tool(StructuralSanitizer(), _BINARY_ORIGIN_TOOLS)`) that
wraps a tool's output in `=== BEGIN/END UNTRUSTED TOOL-DERIVED DATA ===` framing
so the model treats malware-derived text as **data, not instructions**. It is
**opt-in by tool name**: `_BINARY_ORIGIN_TOOLS = radare2 ∪ ghidra ∪
deobfuscation-tools`.

Integration rules (both things — script output *and* recovered plaintext):

1. **Add `run_python` (and any triage MCP the workbench uses) to
   `_BINARY_ORIGIN_TOOLS`.** Its stdout/stderr is where **freshly-decrypted
   malware strings first appear in cleartext** — before the unpacker runs, an
   embedded injection payload is encrypted and inert; the instant the agent
   decrypts it, it is live. Membrane framing here matters more than anywhere
   else. The agent cannot bypass it: the callback wraps the tool's return value,
   not the script's internal behavior.
2. **The recovered plaintext never enters context as raw bytes.** It is spilled to
   the `ArtifactStore`; the model sees a hash + bounded metadata (size,
   entropy-before/after, format). When *downstream* stages analyze the recovered
   artifact, their tools (radare2/ghidra — already in the set) sanitize the
   derived output. So the plaintext is membrane-wrapped at every point it is ever
   surfaced to a model.
3. **`register_unpacked_artifact` returns only structured, non-content metadata**
   (hash/size/entropy/format) — never raw decrypted strings — so it is inherently
   non-hostile. Add it to `_BINARY_ORIGIN_TOOLS` defensively anyway.
4. **Bounded output is co-equal with framing.** A hard `OutputPolicy` byte/line
   cap on `run_python` (with spill-to-store) prevents a large decoded blob from
   flooding context and is the second half of the defense.

**Honest residual risk:** the membrane is *structural framing*, not content
filtering — it relies on the model honoring the untrusted markers, the same trust
model as the rest of the pipeline. Given `run_python` decrypts live malware, this
is stated as a known residual risk, mitigated by (a) framing, (b) bounded output,
and (c) the sandbox's **deny-all egress** — so even a successful injection has no
exfil path and no ability to act outside the disposable pod.

## 6. Neutrality guardrails

The neutral core (`src/arema`) must stay domain-agnostic — `test_neutral_boundaries`
forbids naming `radare2`/`ghidra`/etc. there. So:

- The **generic** primitive — "run agent-authored code in a persistent sandbox
  workspace with a resource governor" — _may_ live in the neutral runtime if we
  want to reuse it, phrased generically (a "code execution capability"), like
  `_SerializedTool` was kept domain-neutral.
- The **domain specifics** — r2pipe, packer workflow, `packer_analyst` prompt,
  the workbench image, format routing — live in `src/reverse_engineering`.

## 7. Phased plan

Each phase ends with `make check` green + a live `adk run` validation + docs.

### Phase 0 — Workbench foundation (no agent yet)
- Build `arema-analysis-workbench` image (Phase 1 inventory) + `SandboxTemplate` +
  `WarmPool` + hardening (gVisor, deny-all egress, RO rootfs, cgroup limits).
- Add the **persistent-workspace** staging variant to `deobfuscation/runtime.py`.
- Implement `run_python` (stateless-exec backend, E2B-shaped `ExecutionResult`,
  output spill-to-store) + `register_unpacked_artifact` + the resource governor
  (`before_tool` execution counter + guard).
- Wire the Makefile sandbox targets + `.env` pool map (`analysis-workbench`).
- **Prove it:** a fixed script (not an agent) runs in the pod against a sample,
  writes a dump, registers an artifact, and is correctly bounded by the timeout /
  memory / output / execution caps. Unit + component tests.

### Phase 1 — The static-reimplementation agent (inside the deobfuscation loop)
- `packer_analyst` `LlmAgent` + prompt (the §4.4 workflow) behind a
  **`scripted_recover` conditional stage inserted into the deobfuscation
  `LoopAgent` body between `recover` and `retriage`**, gated on
  `obf_class == packed-other` + nothing-recovered-this-round + global budget.
- `register_unpacked_artifact` sets `CURRENT_ARTIFACT_KEY` (§4.3) + provenance;
  `run_python` added to `_BINARY_ORIGIN_TOOLS` (§5.1); raise `max_iterations`.
- Reuse `deobf_gate` (no new gate). Recovery evidence + provenance.
- Tests (gating, artifact hand-off via `CURRENT_ARTIFACT_KEY`, global-budget
  enforcement, membrane framing of `run_python`, provenance, `deobf_gate` exit) +
  **live validation on a native custom-packed sample** (e.g. a simple XOR/RC4
  stub) showing the unpacked artifact flow into deep analysis.

### Phase 2 — .NET companion (serves the motivating sample)
- The correct toolchain for ConfuserEx/SmartAssembly/.NET-Reactor metadata
  protection that radare2 can't touch. **Refined to an implementation-ready design
  in §12:** deterministic **de4dot** added as a self-gating tool *inside the
  existing `deobfuscation-tools` sandbox and `recover` stage* — no new
  pod/pool/stage/path. `dnlib`/agentic .NET and dynamic in-memory dumping are
  deferred (§12.7), added only if de4dot proves insufficient.
- This is where the original `1595d92f…` .NET sample becomes recoverable.

### Phase 3 — CPU-emulator extension
- Swap the `run_python` backend to a **persistent kernel** (port-forward pattern,
  reuse `PortForwardRegistry`); add emulation libs to the image; escalate the
  runtime to **Kata**.
- Add an emulation branch to the worker: **ESIL first** (shellcode/decoder stubs,
  `aei`/`aeim`/`aeip` → step until invalid-op / loop-end / instruction-cap →
  `wtf` dump), then **Qiling/Speakeasy** for full-PE self-unpackers (hook
  `VirtualAlloc`/`VirtualProtect`/`VirtualFree`, dump on section-hop / tail-jump /
  W→X). Add W→X + anti-emulation handling and dump-repair (Scylla/pe-sieve).

## 8. Key decisions (recommendations + the fork you already resolved)

| Decision | Recommendation |
|---|---|
| Unpack strategy (now) | **Static reimplementation only** (your call); ground prepared for emulation (Phase 3). |
| Execution backend (now) | **Stateless exec + persistent filesystem workspace** — simplest, reuses `runtime.py`; sufficient for static reimpl. Persistent kernel arrives with emulation (Phase 3), same tool contract. |
| radare2 exposure | **Full r2pipe inside the sandbox**; keep the read-only `radare2_mcp` as the triage front-end. |
| Isolation floor | **gVisor** now; **Kata/microVM** for the emulation phase. |
| .NET managed layer | **de4dot/dnlib companion path** (Phase 2) — not radare2. |
| Placement | **Gated `scripted_recover` stage inside the deobfuscation loop** (between `recover` and `retriage`), reusing `CURRENT_ARTIFACT_KEY`/`retriage`/`deobf_gate`/multi-stage recursion — a single gated `LlmAgent` with a global budget. Revised from the first draft. |
| Artifact hand-off | **Reuse `CURRENT_ARTIFACT_KEY`** — `register_unpacked_artifact` sets it exactly like `upx.py:250`; every downstream stage already reads it (§4.3). No new mechanism. |
| Injection defense | **Add `run_python` to the `SanitizationMembrane`'s `_BINARY_ORIGIN_TOOLS`** + bounded output + spill plaintext to the store (§5.1). `run_python` is the highest-risk injection surface. |

## 9. Risks & how the design handles them

- **The motivating .NET sample isn't solved by Phase 1.** Its managed metadata
  needs de4dot/dnlib (Phase 2). Phase 1 delivers native-packer coverage; be
  explicit about that with stakeholders.
- **Static reimplementation has a ceiling** — runtime-derived keys, anti-analysis,
  virtualized stubs resist it. The loop's `deobf_gate` (no-improvement → exit)
  gives up honestly (`recovery:scripted_unavailable`) rather than fabricating, and
  Phase 3 emulation is the designed escalation.
- **Prompt injection from freshly-decrypted malware.** `run_python` is the
  highest-risk surface; mitigated by the SanitizationMembrane framing, bounded
  output, and deny-all egress (§5.1) — stated as a known residual risk.
- **Full r2pipe = larger blast radius.** Mitigated entirely at the sandbox
  boundary (isolated, disposable, no network). This is the deliberate trade the
  research endorses.
- **Persistent kernel adds attack surface** (Phase 3). Prefer a minimal custom
  exec service over full Jupyter; keep it behind the same pod isolation.
- **Runaway analysis code.** The two-layer governor (per-exec cgroup/timeout +
  loop-level execution/wall/token budgets with graceful wrap-up) guarantees
  termination.

## 10. References (selected)

Automated unpacking & emulation: Qiling unpacking tutorial and TA505 write-up;
Mandiant Speakeasy programmatic unpacking; unipacker (section-hopping); radare2
ESIL unpacking (shikata-ga-nai; XPN Metasploit-encoder); OmniUnpack / PolyUnpack /
Renovo and the 2023 "Towards Generic Malware Unpacking" survey.
Detection: NDSS'21 low-entropy packing study; `pefile`; Detect-It-Easy /
`die-python`; PEiD→YARA (Didier Stevens).
Static reimplementation: OALabs self-injection unpacking; RC4/XOR/AES recognition
(Talos, Intezer, Zero2Automated).
Dump repair: Scylla; hasherezade `pe-sieve` / `libpeconv` / `mal_unpack`.
.NET: `cyber.wtf` .NET deobfuscation; de4dot / de4dotEx / dnlib / dnSpyEx;
DotDumper / MegaDumper.
Agentic code execution & isolation: E2B (persistent Firecracker + Jupyter);
OpenAI Code Interpreter; open-interpreter; AutoGen Jupyter executor; Anthropic
"code execution with MCP"; Northflank Kata/Firecracker/gVisor comparisons; gVisor;
nsjail; LiteLLM iteration budgets.

## 11. Phase 1 implementation-ready design (approved 2026-07-28)

Phase 0 (the workbench foundation) is merged-ready on `feat/scripted-unpacking`.
This section pins the concrete Phase 1 design, grounded in the current code, so the
`writing-plans` step is unambiguous. It refines — does not contradict — §3–§5.

### 11.1 Two code-level findings that shaped the design

1. **The gate independently hard-codes the iteration cap.** `deobf_gate.py`
   exits on `iteration >= 3` regardless of the `LoopAgent`'s `max_iterations`
   metadata (also `3`). Raising one alone changes nothing — both must move from a
   **single source of truth**.
2. **Evidence is bound to the current artifact, strictly.** `parse_evidence_envelope`
   *rejects* an envelope whose `artifact_id` ≠ the current `plan.artifact_id`, and
   every finding must match its envelope. So the recovery finding must be built
   **bound to the recovered artifact id** — which the gate already does for every
   finding it emits. Therefore the gate, not the tool or the LLM, builds it.

### 11.2 Components

New (all under `src/reverse_engineering/`):
- `agents/scripted_recover.py` — `_ScriptedRecoverGate(BaseAgent)` +
  `SCRIPTED_RECOVER_DESCRIPTOR`, modeled on `agents/format_router.py`.
- `agents/packer_analyst.py` — the `packer_analyst` `LlmAgent` descriptor,
  mirroring `agents/upx_unpack.py`.
- `prompts/packer_analyst.md` — the §4.4 workflow, defensively framed.

Modified:
- `agents/deobfuscation.py` — `sub_agent_ids` gains `scripted_recover` between
  `recover` and `retriage`; `max_iterations` sourced from the shared constant.
- `agents/deobf_gate.py` — cap from the shared constant; `_scripted_outcome` folds
  a recovery finding + `recovery:scripted_unavailable` limitation into the evidence.
- `tools/workbench/register.py` — additionally writes `SCRIPTED_RESULT_KEY`.
- `tools/deobfuscation/state.py` — new keys `SCRIPTED_RESULT_KEY`,
  `SCRIPTED_ATTEMPTED_KEY`, and the shared `DEOBF_MAX_ITERATIONS` constant.
- `composition.py` — register the two new agents.

### 11.3 The `scripted_recover` conditional gate

A deterministic `BaseAgent` wrapper (LLM never decides control flow) runs
`packer_analyst` **iff all hold**, else yields nothing:

- `parse_current_classification(state).obf_class == "packed-other"`,
- native format — `SAMPLE_FORMAT_KEY ∉ {"dotnet"}` (reuses `format_router`'s
  managed set; .NET is Phase 2),
- **nothing recovered this round** — `UPX_CHANGED_KEY` false **and**
  `FLOSS_COUNT_KEY == 0` (if a cheap tool unpacked, let the loop recurse first),
- **budget remains** — `WORKBENCH_EXEC_COUNT_KEY < WORKBENCH_MAX_EXECUTIONS` (40).

On running the agent it sets `SCRIPTED_ATTEMPTED_KEY = True` (the gate's honest
give-up signal).

### 11.4 The `packer_analyst` agent

Mirrors `upx_unpack`'s descriptor: `build_llm_agent`, `runtime_profile_id="re_guarded"`
(the membrane already frames `run_python` — Phase 0), `prompt_id="packer_analyst"`.

- **tools:** `run_python`, `register_unpacked_artifact`.
- **mcp_server_ids:** `radare2_mcp` (cheap read-only triage — preserves the
  `run_python` budget; the proven `retriage`/`triage_recon` pattern).
- **model:** inherits the domain default (Sonnet 4) — **no override** (decision
  below). Its own tool-calling loop is the write→run→refine iteration; no inner
  `LoopAgent`.

### 11.5 Evidence, provenance, control flow

`register_unpacked_artifact` already sets `CURRENT_ARTIFACT_KEY`, advances the
classification, and writes `upx`-style provenance (Phase 0). Phase 1 adds a
deterministic **`SCRIPTED_RESULT_KEY`** = `{source_artifact_id, artifact_id,
method, entropy_before, entropy_after, format, size}` (`method` is the analyst's
already-bounded ≤200-char mechanism label).

The gate gains `_scripted_outcome`, exactly like `_upx_outcome`/`_floss_outcome`:
- **success** (`SCRIPTED_RESULT_KEY` present) → a `tool="scripted_recover"` finding
  **bound to `plan.artifact_id`** (the recovered id), folded into
  `RECOVERY_EVIDENCE_KEY`.
- **attempted, nothing recovered** (`SCRIPTED_ATTEMPTED_KEY` true, no result,
  `no_progress`) → gate adds `recovery:scripted_unavailable` and exits its existing
  `no_progress` path.

Both `SCRIPTED_RESULT_KEY` and `SCRIPTED_ATTEMPTED_KEY` reset each round in the
gate's `_iteration_delta` (exactly as `UPX_RESULT_KEY` does), so a prior round's
result can never re-emit a stale finding.

**Control flow needs no gate change**: success grows the retriage snapshot
(`grew=True` → loop recurses to the next layer); failure leaves
`CURRENT_ARTIFACT_KEY` unchanged (`no_progress` → clean exit). This is why the
stage lives *inside* the loop.

**Multi-layer evidence re-anchoring (implemented).** For a *second* recovering
round, `RECOVERY_EVIDENCE_KEY` (the loop's own cumulative, gate-authored evidence)
is still bound to the *pre-advance* artifact id while `plan.artifact_id` has moved
to the newly recovered id — and the strict `parse_evidence_envelope` (§11.1
finding 2) would reject that mismatch and fail the loop closed. The gate therefore
re-anchors its own prior evidence to the current artifact via
`rebind_evidence_envelope` (in `evidence_envelope.py`) instead of rejecting it:
only the anchor id changes, every finding's claim/detail is preserved, and
model-authored state (the retriage snapshot) stays strict. This is what actually
makes the §11.6 cap-of-6 nested-layer recursion accumulate evidence rather than
fail closed — a pre-existing loop-invariant bug (double-UPX exhibited it too),
found by the whole-branch review and fixed at the root.

### 11.6 Iteration cap

A single shared constant **`DEOBF_MAX_ITERATIONS = 6`** (in
`tools/deobfuscation/state.py`), imported by both `deobfuscation.py`
(`metadata["max_iterations"]`) and `deobf_gate.py` (replacing the literal `3`).
Six gives headroom for nested packer→loader→core layers; it is a tunable. The
global 40-exec `run_python` budget still spans all rounds, so more rounds grant
deeper nesting, not more executions.

### 11.7 Phase 1 decisions locked with the user (2026-07-28)

| Decision | Choice |
|---|---|
| `packer_analyst` model & safety | **Defensively-framed prompt; inherit the domain default model (Sonnet 4), no per-agent override.** |
| Resource-governor scope | **Defer** the §4.5 "80%-budget finalize" advisory and the per-case wall-clock watchdog. Phase 0's hard 40-exec cap + per-exec timeout/memory/output already guarantee termination; add graceful wrap-up later only if runs show abrupt cutoffs. |
| Validation | **Unit + component tests only** (gating matrix, artifact hand-off, gate-built evidence, iteration cap, membrane, provenance, catalog freeze). Defer live-cluster end-to-end and any native-packed fixture until a real native packed sample is on hand. |
| Iteration cap | **Raise to 6** via the shared constant (§11.6). |
| Recovery evidence | **Built by the gate** from `SCRIPTED_RESULT_KEY` (deterministic), not authored by the LLM (§11.5). |

### 11.8 Explicitly out of Phase 1 scope

Graceful-governor niceties (above); live validation + native fixture; the .NET
companion (Phase 2); emulation escalation (Phase 3).
radare2 exposure: r2pipe; radare2 scripting book; `radare2-mcp` (raw passthrough +
`readonly`/`sandbox` toggles); Reversecore_MCP (read-only curated surface).

_(Full URLs are in the research notes captured for this design; add inline links
when this graduates from proposal to committed doc.)_

## 12. Phase 2 implementation-ready design — the .NET companion (approved 2026-07-29)

Phases 0+1 are complete on `feat/scripted-unpacking`. Phase 2 makes a **protected
.NET/CLR sample** (the motivating `1595d92f…`, SmartAssembly/Dotfuscator) actually
recoverable, so the recovery→retriage→deep-analysis machinery can be exercised
end-to-end on a real sample. The chosen shape (locked with the user) is
**deterministic de4dot, added with the least possible surface — no new sandbox,
no new stage, no new path.**

### 12.1 Scope boundary (why this is NOT `packer_analyst`)

`packer_analyst` (Phase 1) recovers **native** custom packers (PE/ELF/Mach-O) via
Python + radare2; it is format-gated *out* of `.NET` samples and structurally
cannot crack CLR managed-metadata protection (§1.1). The .NET managed layer is a
**sibling deterministic tool**, not an agentic Python capability. The two meet only
on a .NET assembly wrapped in a *native* packer: `packer_analyst` peels the native
outer layer, then de4dot handles the managed inner layer — the loop's existing
cross-format layering.

### 12.2 The decision: de4dot is one more tool in the EXISTING recovery seam

de4dot is a deterministic recovery tool exactly like UPX and FLOSS, so it lives in
the **existing `deobfuscation-tools` sandbox and the existing `recover` stage** —
not a new pod/pool/template and not a new loop stage. This keeps the deobfuscation
loop a single unified path and makes "add another .NET tool later" the simplest
possible extension.

- **Image (`images/deobfuscation-tools`):** add a **mono runtime + de4dot** to the
  existing exec-driven cheap-tools image (already ships `upx` + a Python venv for
  `floss`). Pin a specific de4dot build; prove it in the healthcheck. *(The one
  real research/feasibility item: de4dot runs on Linux under mono; confirm the
  build + mono base and a `mono de4dot.exe <in> -o <out>` invocation.)*
- **Stage (`recover`):** becomes `upx_unpack → floss_decode → de4dot_deobfuscate`.
  Each tool **self-gates by applicability** — de4dot returns `applicable: False`
  for a non-`dotnet` sample or when it detects no obfuscator; upx/floss already
  no-op for non-PE. No format gate wraps the stage.

### 12.3 The de4dot tool + agent (mirror `upx.py` / `upx_unpack`)

- **`de4dot` tool** (`tools/deobfuscation/dotnet.py`, deferred-factory, patterned on
  `upx.py`): stage the current artifact into the `deobfuscation-tools` pool, run
  de4dot, and on success `acquire_bytes` → set `CURRENT_ARTIFACT_KEY` +
  `advance_classification_artifact` + provenance (`deobfuscated ← original`) +
  write `DE4DOT_RESULT_KEY` (mirrors `UPX_RESULT_KEY`).
- **Validation is de4dot-success-based, NOT the native entropy-drop gate.** A
  metadata-deobfuscated assembly need not drop whole-file entropy. Admit the output
  only when: de4dot **detected and cleaned a known obfuscator** (not a passthrough
  no-op), the output **parses as a valid CLR assembly** (COM descriptor present),
  and the size is sane. Otherwise `applicable: False` / rejected — never fabricate a
  recovery.
- **`de4dot_deobfuscate` LlmAgent** (mirrors `upx_unpack`): calls the tool exactly
  once and returns the structured result faithfully; `re_guarded` profile.

### 12.4 Hand-off, evidence, and the deep engine (no downstream change)

- The recovered assembly is still `.NET`, and `SAMPLE_FORMAT_KEY` is set **once at
  intake**, so it stays `"dotnet"`. `deep_engine_router` therefore routes the
  *recovered, clean* assembly to **ILSpy** automatically — ILSpy now decompiles
  deobfuscated C# instead of protected code. Zero change to routing or downstream.
- **Evidence:** the gate gains a `_de4dot_outcome` folded into
  `RECOVERY_EVIDENCE_KEY` exactly like `_upx_outcome`/`_floss_outcome` (the finding:
  which obfuscator de4dot identified + what it removed — real threat intel).
  Progress is detected by the existing `grew` retriage signal (a deobfuscated
  assembly exposes decrypted strings / real names → retriage grows). de4dot's
  result/called keys reset per round in `_iteration_delta` like `UPX_RESULT_KEY`.
- **Classifier:** no `deobf_classify` change — de4dot self-gates on its own
  obfuscator detection, independent of `obf_class`.

### 12.5 The extensibility recipe (the user's constraint)

Adding any future deterministic recovery tool (native or managed) is one repeatable,
localized recipe — never a pipeline rethink: (1) install it in the single
`deobfuscation-tools` image; (2) write a tool on the `upx.py` template
(stage → run → validate → advance + `<TOOL>_RESULT_KEY`); (3) append its
`*_deobfuscate` agent to `recover`'s `sub_agent_ids`; (4) add a `_<tool>_outcome`
evidence fold in the gate. One sandbox, one stage, one loop.

### 12.6 Decisions locked with the user (2026-07-29)

| Decision | Choice |
|---|---|
| .NET recovery shape | **Deterministic de4dot** (not an agentic .NET workbench). |
| Placement | **Inside `deobfuscation-tools` + `recover`** — NO new pod/pool/template/stage/path. de4dot self-gates like upx/floss. |
| Validation | **de4dot-success + valid-CLR-assembly**, not the native entropy-drop gate. |
| Acceptance | **Live end-to-end on the real `1595d92f…` sample** (de4dot → ILSpy → report reflects deobfuscated code), plus unit/component coverage (self-gating, hand-off, evidence, cross-format layering). |

### 12.7 Explicitly out of Phase 2 scope

An **agentic .NET path** (a `run_dotnet`/dnlib workbench + a `dotnet_analyst`
agent behind a `scripted_recover`-sibling gate) — added *only if* de4dot proves
insufficient for a real custom-protected sample, and still inside the same loop.
Dynamic in-memory .NET dumping (`Assembly.Load` packers). Emulation (Phase 3).

## 13. Phase 2b implementation-ready design — managed agentic recovery (approved 2026-07-29)

**Trigger (the §12.7 condition, now met).** Live-testing Phase 2 on the real
`1595d92f…` sample proved de4dot insufficient: the sample is **ConfuserEx** (not
SmartAssembly — the `Dotfuscator`/`SmartAssembly` attribute strings are *decoy*
misdirection), and **de4dot-cex 4.0.0 crashes** on it
(`System.InvalidCastException` in `ConfuserEx.ProxyCallFixer.EmulateManagedMethod`
*during obfuscator detection*, exit 1, no output). ILSpy also can't load it
(`Illegal tables in compressed metadata stream`) — deliberately malformed
metadata. So `de4dot:de4dot_failed` is the deterministic tool correctly reporting
its own crash; the `(agentic recovery, managed)` cell of `docs/TOOLS_USAGE.md` is
empty. Phase 2b fills it.

**Guiding principle (locked with the user).** No hardcoded flag-chains in a tool —
an **agent reasons** about the failure and uses tools freely, exactly as
`packer_analyst` does for native packers. The .NET recovery is the *managed sibling*
of the native scripted path, on a **shared** workbench engine.

### 13.1 `analysis-workbench` → the shared RE code-execution engine

The workbench stops being native-only and becomes **the one agentic-recovery
engine for every technology**: a pre-populated, free-code-execution sandbox.
Refines the TOOLS_USAGE matrix — the `agentic recovery` row is a **single shared
engine with per-technology *agents*** (native → `packer_analyst`, managed →
`dotnet_analyst`), not one pool per technology. Adding a technology later = add an
analyst agent + pre-bake its tools; **no new pool**.

- **Security posture (locked): deny-all egress stays.** This is the load-bearing
  control (the sandbox decrypts live malware + runs agent code on hostile input).
  The agent is free to run any command and build its own programs, but is **bounded
  by the pre-installed toolset and blocked egress** — **no runtime network
  install** (`pip`/`apt`/`uv` from the internet). When a tool is missing, it is
  **added to the image and rebuilt** (`make sandbox-build-images`), not installed at
  runtime. Read-only rootfs / non-root / dropped caps / memory cap / exec budget all
  stay.

### 13.2 Agent freedom — `run_python` stays the entry point

`run_python` already runs agent-authored Python in the persistent `/work`, and
Python can `subprocess.run(...)` **any installed CLI** (`de4dot`, `dotnet script`,
`mono`, `ilspycmd`) or write and run its own programs (a `.csx`, a helper module) —
that *is* "run any command / build your own programs", so **no new tool is added**
and all existing governors (exec budget, per-call timeout, output caps,
SanitizationMembrane framing) carry over unchanged. A barer `run_shell` is a trivial
future add if wanted; `run_python` covers it today.

### 13.3 The image — rich toolkit + "quick-add and rebuild" structure

Extend the workbench image with a **.NET SDK + dnlib + de4dot + `dotnet-script` /
`ilspycmd`** alongside the existing native set, plus the popular binary-analysis
Python libraries (capstone, pyelftools, macholib, cryptography, …). The Dockerfile
is organized so each tool family is **one obvious, pinned block** (a `pip` layer, an
`apt` layer, a `.NET-tools` layer); adding a tool = edit one block + rebuild. (The
image grows notably with a .NET SDK — acceptable for the RE workbench.)

### 13.4 `dotnet_analyst` — the managed sibling of `packer_analyst`

A new `LlmAgent` (same `re_guarded` profile; tools `run_python` +
`register_*`, and **no triage MCP** — the workbench already carries radare2 and
`ilspycmd` in-process, and `ilspy_mcp` cannot load a still-protected assembly, so
an external triage MCP would add nothing the agent can't reach via `run_python`),
with a **.NET-deobfuscation prompt**: fingerprint the
protector; run de4dot and *read its crash/output*; when de4dot is insufficient, use
**dnlib (via C#/`dotnet-script`)** to do targeted work — repair the malformed
metadata so ILSpy can load it, decrypt strings, strip the proxy-call / anti-tamper
layer — and produce a deobfuscated, loadable assembly. It **reasons**; it is not a
hardcoded flag-chain.

### 13.5 Placement — `dotnet_scripted_recover` gate in the loop

A managed sibling of `scripted_recover`, inside the deobfuscation `LoopAgent`,
running **iff** `SAMPLE_FORMAT_KEY == "dotnet"` **and** the sample is still protected
(deterministic de4dot did not already recover it this round) **and** the global
`run_python` budget remains. `scripted_recover` (native) and
`dotnet_scripted_recover` (managed) are **format-exclusive siblings** — the same
BaseAgent-gate pattern, mirror-imaged. Loop body:
`deobf_classify → recover → scripted_recover → dotnet_scripted_recover → retriage → deobf_gate`.

### 13.6 Registration + evidence

The recovered artifact is a valid CLR assembly (dnlib re-serialized), so admission
is on **"parses as a valid .NET assembly (`detect_format_bytes == "dotnet"`) and is
changed/loadable"** — *not* the native entropy-drop gate (a `dotnet` mode on
`register_unpacked_artifact` or a sibling `register_dotnet_artifact`). Recovery
advances `CURRENT_ARTIFACT_KEY` (stays `dotnet` → `deep_engine_router` → ILSpy,
unchanged). The gate folds a `dotnet_recover` evidence finding, mirroring
de4dot/scripted, and emits an honest `recovery:dotnet_scripted_unavailable`
limitation on give-up.

### 13.7 Decisions locked with the user (2026-07-29)

| Decision | Choice |
|---|---|
| Engine | **Extend `analysis-workbench` into the shared RE code-exec engine** (one engine, per-technology agents), not a new pool. |
| Security posture | **Deny-all egress kept; no runtime network install.** Rich pre-populated image + free code execution *within* the toolset; add tools by rebuilding the image. |
| Code-exec tool | **Reuse `run_python`** (Python may subprocess any installed CLI / write C# for `dotnet-script`); governors unchanged. |
| Agent | **New `dotnet_analyst`** (managed sibling of `packer_analyst`), reasoning-driven — no hardcoded flag-chains. |
| Placement | **`dotnet_scripted_recover` gate** in the loop, format-exclusive sibling of `scripted_recover`. |
| Registration | **valid-CLR + changed/loadable** validation (reuse `detect_format_bytes`), not entropy-drop. |
| Acceptance | **Loadable is the bar**: success = ILSpy can now load + decompile the recovered assembly (metadata repaired), even if not fully deobfuscated; fuller ConfuserEx removal (strings/names) is iterative improvement. Honest limitation on failure — never a fabricated recovery. |

### 13.8 Explicitly out of Phase 2b scope

Dynamic in-memory dumping (executing the managed sample — crosses "never execute the
sample"; a future *vertical* with its own safety model). Cross-technology layering
(format re-detection per round) and container fan-out (APK/IPA) — future *horizontal*
work (`docs/TOOLS_USAGE.md` §7). Emulation (Phase 3).
