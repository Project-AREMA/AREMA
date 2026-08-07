# AREMA Ghidra 2nd Engine — Design (Spec B, Slice 3 / B.4)

**Status:** Approved (brainstormed 2026-07-24)
**Spec ID:** B.4 (Slice 3 of the RE/Malware MVP)
**Depends on:** Spec B Slices 1–2 (B.2 the RE loop + B.3 the trust layer), both merged to `main`. Reuses the `K8sSandboxExecutor`, the `ArtifactStore`, the SanitizationMembrane (neutral core), the `re_guarded` profile, and the `evidence/finding` codec.
**North star:** `docs/NORTH_STAR.md` (§3 Axis 2 — r2 ∥ Ghidra consensus; §6 StaticDecomple; §7 Ghidra tooling). This slice ships the **sequential** deep-decompile path; the parallel/consensus fan-out (Axis 2) is a later slice that needs `ParallelAgent` factory support.

## Goal

Add Ghidra as the **second analysis engine**: a `deep_decompile` agent that takes
the artifact + triage's findings and drives Ghidra (via `ghidra-rpc`) for deep
pseudo-C decompilation, type recovery, and call-graph tracing — emitting deeper
evidence-backed FINDINGs that flow through the existing `evidence_critic`.

This slice also establishes the **repeatable function-tool pattern** for
CLI-driven sandbox engines (the function-tool analog of the MCP
`McpServerDescriptor` seam), so future engines (capa, objdump, YARA) integrate
the same way.

## Decisions (locked during brainstorm)

| # | Decision | Choice |
|---|----------|--------|
| 1 | Ghidra tool | **`ghidra-rpc`** (cellebrite-labs) — purpose-built headless CLI daemon (PyGhidra, load-once-stay-warm, structured JSON). NOT `ghidra-mcp` (GUI-plugin architecture; its headless mode is a bolt-on). |
| 2 | Integration surface | **AREMA function tools** wrapping the ghidra-rpc CLI (not MCP). The agent calls typed tools that shell out via `K8sSandboxExecutor.run`. |
| 3 | Agent | A new **`deep_decompile`** `LlmAgent`, sequential after `triage_recon`: `reverse_engineer → triage_recon → deep_decompile → evidence_critic → report_generator`. No `ParallelAgent` (deferred). |
| 4 | Sandbox | **Separate `ghidra-rpc` pool** (own SandboxTemplate + WarmPool). Resource isolation — Ghidra's JVM doesn't compete with r2; you only pay when deep analysis runs. |
| 5 | Pod shape | **Single container** `FROM` the python-runtime-sandbox image (has `/execute` on :8888) + JDK + Ghidra + ghidra-rpc. The executor's existing `/execute` path drives ghidra-rpc commands directly — **no MCP, no port-forward, no StreamableHTTP** (simpler than r2mcp). |
| 6 | Repeatable pattern | A **spec-driven builder** (`build_ghidra_toolset`): each tool is one `CliCommandSpec`; the builder turns specs into typed callables. Adding a tool = one spec line. Promote `SandboxCliToolset` to the neutral core when a 2nd CLI engine appears (rule of three — same lesson as the B.3 sanitization promotion). |
| 7 | Sanitization | `deep_decompile` uses `re_guarded`; the profile's `binary_origin_tools` grows to include the ghidra tool names (union with r2mcp — harmless, sanitizer only acts on called tools). |
| 8 | Neutrality | ghidra-rpc specifics (commands, daemon lifecycle) are domain code in `src/reverse_engineer/tools/ghidra/`. `src/arema` untouched. |

### Why ghidra-rpc (not ghidra-mcp)

- `ghidra-rpc` is **purpose-built for headless CLI-driven agentic use**: PyGhidra
  daemon, binary loaded once and stays warm, structured JSON output, designed for
  AI assistants that run shell commands. Its `SKILL.md` + CLI surface is exactly
  the "engine the agent drives via commands" model.
- `ghidra-mcp` (bethington) is a **GUI-plugin architecture** (installs into
  Ghidra's CodeBrowser, enabled via the plugin menu). It does ship a headless
  Docker mode (`GhidraMCPHeadless.jar`), but that mode is a bolt-on to a
  GUI-centric codebase, exposes a raw REST API (not MCP in headless), and its
  271-tool surface is overwhelming for a curated agent toolset.
- For the sandbox, ghidra-rpc's daemon model is cleaner and lighter.

### The transport insight (why this is LESS plumbing than r2mcp)

r2mcp is an MCP server — AREMA reaches it via `StreamableHTTP` over a
`kubectl port-forward` (the sandbox-router can't carry MCP). ghidra-rpc is a
**CLI daemon reached via shell execution**. AREMA's `K8sSandboxExecutor` claims pods (returns the pod name), and B.2's
`prepare_sandbox` already drives them via **raw kubectl** (`kubectl cp`,
`kubectl port-forward`) — bypassing the executor's `/execute` path. **The ghidra
tools reuse this proven kubectl pattern**: a `kubectl_exec(namespace, pod, command)`
helper runs `ghidra-rpc <command>` in the pod. No new transport, no port-forward
(ghidra-rpc is CLI-driven, not HTTP), no MCP machinery.

## Architecture: the 5-agent chain

```
reverse_engineer (root)
  │  tools: acquire_sample, prepare_sandbox, prepare_ghidra
  ├─ triage_recon     (r2mcp MCP; re_guarded)  → fast recon FINDINGs
  ├─ deep_decompile   (ghidra-rpc function tools; re_guarded)  → deep FINDINGs  [NEW]
  ├─ evidence_critic  (validates ALL findings — r2 + ghidra)
  └─ report_generator
```

`deep_decompile` receives triage's findings as text (which functions/areas are
interesting), drives Ghidra for deep decompilation of those functions, and emits
FINDINGs in the same format. The `evidence_critic` validates both r2 and ghidra
findings identically (it already checks "cites a real tool" — ghidra tool names
join the known-toolset list in the critic's prompt).

## The function-tool pattern (spec-driven builder)

### Location

```
src/reverse_engineer/tools/ghidra/
  __init__.py
  commands.py        CliCommandSpec dataclass + GHIDRA_COMMANDS (the curated spec table)
  toolset.py         build_ghidra_toolset(context) -> tuple[ToolDescriptor, ...]
  prepare_ghidra.py  build_prepare_ghidra(context) -> the prepare_ghidra factory tool
```

### CliCommandSpec

```python
@dataclass(frozen=True, slots=True)
class CliCommandSpec:
    name: str                  # the tool's __name__ (must match descriptor id for OutputPolicy)
    description: str
    subcommand: str            # the ghidra-rpc subcommand (e.g. "decompile")
    output_policy: OutputPolicy
    # How the tool's Python args map to the ghidra-rpc positional args (after <binary>):
    arg_template: str = ""     # e.g. "{function}", "{query}", "{regex}", or "" (no extra args)
    extra_flags: str = ""      # static flags appended to every call (e.g. "--high" for pcode)
```

The builder turns each spec into a typed callable whose signature is derived from
`arg_template` (e.g. `arg_template="{function}"` → `def tool(function: str, ...)`).
The binary name is injected from the case state (not a tool argument) — the agent
never passes it.

### The curated read-only tool surface (initial)

Corrected against the actual `ghidra-rpc` SKILL.md command reference. The set is
curated for the deep-decompile use case and emphasizes what makes Ghidra
**genuinely complementary** to r2 (not a redundant second opinion):

| Tool | ghidra-rpc subcommand | Args | Purpose |
|------|----------------------|------|---------|
| `ghidra_metadata` | `metadata` | binary | binary metadata (arch, bits, format) — cross-check with r2 `show_info` |
| `ghidra_list_functions` | `functions` | binary, `[--limit]` | paginated function inventory |
| `ghidra_decompile` | `decompile` | binary, function | pseudo-C decompilation (Ghidra's decompiler often differs from r2's — agreement = high confidence) |
| `ghidra_search_decompiled` | `search-decompiled` | binary, regex | **the power tool**: regex-search decompiled C across ALL functions in one call — find crypto constants, API-call patterns, vulnerability sinks. r2 cannot do this. |
| `ghidra_basic_blocks` | `basic-blocks` | binary, function | CFG / basic-block structure (control-flow analysis) |
| `ghidra_xrefs_to` | `xrefs-to` | binary, target | who references this symbol/address |
| `ghidra_imports` | `imports` | binary | imported symbols |
| `ghidra_strings` | `strings` | binary, query | string search (substring) |
| `ghidra_pcode` | `pcode` | binary, function, `[--high]` | Ghidra IR (P-code) — **fallback** when `decompile` produces bad output (common on ARM Thumb); high-SSA form reveals data flow |

**Why this set:** `search-decompiled`, `basic-blocks`, and `pcode` are the tools
that make Ghidra add genuine analytical depth beyond r2 recon, not just a second
decompiler opinion. The consensus value (NORTH_STAR Axis 2): where r2 and Ghidra
*agree* → high confidence; where they *differ* → signal for closer analysis.

(Read-only; rename/retype/patch/diff/struct-creation deferred — they need write
access and the evidence-critic contract is read-only analysis. The full
SKILL.md surface — 50+ commands including modifications, bookmarks, tags,
data-type authoring, version-tracking — is available for future slices.)

### Feeding the agent the ghidra-rpc knowledge (SKILL.md)

The `deep_decompile` prompt **distills the workflow guidance from the
ghidra-rpc SKILL.md** so the agent drives Ghidra effectively. The SKILL.md is
the tool's instruction manual; its key operational guidance is baked into the
prompt rather than left for the model to discover:

1. **The typical workflow**: `metadata` → `functions` → `imports`/`exports` →
   `decompile` interesting functions → `xrefs-to` trace callers →
   `search-decompiled` find patterns.
2. **`search-decompiled` is the power tool** — use it instead of
   decompile-every-function-and-grep. Find crypto constants, unsafe API calls,
   or any regex pattern across the whole binary in one call.
3. **`pcode --high` is the fallback** when `decompile` returns bad-instruction
   warnings (common on ARM Thumb / obfuscated code) — it re-decodes from the
   function object's context and reveals data flow.
4. **`<func>` accepts a name OR hex address** (e.g. `main` or `0x401000`); if a
   name is ambiguous the error lists matches — use the address.
5. **Binary-name handling**: `load` returns a `short_name` (e.g. `ls`); use it
   in all subsequent commands (commands match by substring). The
   `prepare_ghidra` step captures + stashes this name.
6. **All output is JSON** (including errors: `{"ok": false, "error": "...",
   "message": "..."}`). A nonzero exit = error.

The full SKILL.md is packaged as a domain prompt resource
(`src/reverse_engineer/prompts/ghidra_rpc_reference.md`) that the prompt
summarizes; the agent does not need to read it at runtime (the distilled
guidance is inline), but it's available for reference.

### build_ghidra_toolset

The builder closes over `context.services.sandbox` and the case context, and for
each `CliCommandSpec` produces:
- A typed **callable** (named to match the spec) that:
  1. Resolves the pod handle + binary name from the case state (stashed by
     `prepare_ghidra`).
  2. Builds the shell command: `ghidra-rpc <subcommand> <binary> <args>`.
  3. Calls `executor.run(handle, command, timeout=...)`.
  4. Parses the JSON result, returns a dict (`{success, output, ...}`).
  5. Fail-open on errors (return `{success: false, error: ...}`).
- A matching **`ToolDescriptor`** (id = the spec name, factory closes over the
  builder context, output_policy from the spec).

### prepare_ghidra(artifact_id)

A deferred-factory tool (same pattern as `prepare_sandbox`):
1. `executor.claim(case_id, "ghidra-rpc")` → pod name.
2. `kubectl cp` the artifact to `/app/<sha256>`.
3. `executor.run(handle, "ghidra-rpc start --project /tmp/work.gpr --headless --detach")`.
4. `executor.run(handle, "ghidra-rpc load /app/<sha256> --project /tmp/work.gpr")` →
   parse JSON, capture the **`short_name`** (e.g. `ls`) from the response — all
   subsequent ghidra tools use this name (commands match by substring).
5. Stash `{pod, binary_name (short_name), executor}` in the case registry
   (module-level, keyed by case_id — mirrors `prepare_sandbox`'s
   `_CASE_EXECUTORS`).
6. Return `{pod, binary, ready}`.

Cleanup: `release_ghidra_case(case_id)` stops the daemon + releases the executor
(fail-open, same pattern as `release_case`).

## Image + sandbox

### images/ghidra-rpc/Dockerfile

```
FROM debian:bookworm-slim                 # same base as the r2mcp image
RUN apt-get install -y openjdk-17-jdk ...  # JDK for Ghidra
# download + extract Ghidra 11.x to /opt/ghidra
# pip/uv install ghidra-rpc
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
USER 1000
# CMD: sleep infinity (the pod stays warm; ghidra-rpc daemon started on-demand by prepare_ghidra)
```

(Single container with Ghidra + ghidra-rpc. No python-runtime playground — the
pod is driven via raw `kubectl exec`, mirroring B.2's `kubectl cp` pattern.)

### deploy/sandbox manifests

- `10-ghidra-rpc-template.yaml` — `SandboxTemplate`, one container
  (`arema-ghidra-rpc:0.1.0`), `containerPort 8888`, httpGet readiness on `:8888`,
  shared `emptyDir` at `/app`, non-root UID 1000, dropped caps,
  `automountServiceAccountToken: false`. (Mirror the r2mcp template's hardening.)
- `20-ghidra-rpc-pool.yaml` — `SandboxWarmPool` referencing the template
  (`replicas: 1` for dev; Ghidra is memory-heavy).

### Make targets

`sandbox-ghidra-image`, `sandbox-ghidra-up`, `sandbox-ghidra-down` — mirroring
the `sandbox-mcp-*` targets.

### Settings

`AREMA_SANDBOX_POOL_MAP` gains `{"ghidra-rpc": "ghidra-rpc-pool"}` (env-driven,
same as the r2mcp pool map).

## Sanitization (reuses B.3)

`deep_decompile` uses `runtime_profile_id="re_guarded"`. The profile's
`binary_origin_tools` grows from the r2mcp-only set to the **union** of r2mcp +
ghidra tool names:

```python
_BINARY_ORIGIN_TOOLS = frozenset(RADARE2_MCP.tool_allowlist) | _GHIDRA_TOOL_NAMES
```

The sanitizer (now in the neutral core) frames + redacts output from both engines
identically. Harmless for an agent that only calls r2 tools (the ghidra names are
never matched).

## Resilience, neutrality, testing

- **Resilience:** ghidra tools are fail-open (return an error dict; the run
  continues). `prepare_ghidra` errors return `{ready: false}`. Daemon start/load
  failures surface clearly. The existing context-budget + compaction layers bound
  ghidra's JSON output via each tool's `OutputPolicy`.
- **Neutrality:** all ghidra code in `src/reverse_engineer/`. `src/arema`
  untouched. The spec-driven builder pattern is documented for future promotion
  (rule of three).
- **Testing:**
  - Unit: `CliCommandSpec` table is well-formed; `build_ghidra_toolset` produces
    the right tool names + OutputPolicies; each tool's callable shells out
    correctly against a **fake executor** (returns canned JSON); fail-open on
    executor error; `prepare_ghidra` claims + starts + loads (monkeypatched
    executor + subprocess).
  - Component: the 5-agent graph builds; `deep_decompile` has the ghidra tools;
    `re_guarded` covers both engines' tool names.
  - Manifest unit tests (mirror `test_radare2_mcp_manifest.py`).
  - **Live smoke test** (final gate): `/bin/ls` → triage (r2) → deep_decompile
    (Ghidra decompiles `main`) → critic validates ghidra findings → report cites
    both engines.

## Deliverables

- [ ] `images/ghidra-rpc/Dockerfile` (python-runtime + JDK + Ghidra + ghidra-rpc).
- [ ] `deploy/sandbox/10-ghidra-rpc-template.yaml` + `20-ghidra-rpc-pool.yaml`.
- [ ] Make targets (`sandbox-ghidra-image/up/down`).
- [ ] `CliCommandSpec` + the curated command table + `build_ghidra_toolset`.
- [ ] `prepare_ghidra` + `release_ghidra_case`.
- [ ] `deep_decompile` agent + prompt (distilling SKILL.md workflow guidance) +
      `ghidra_rpc_reference.md` resource + composition wiring.
- [ ] `re_guarded` binary_origin_tools union (r2 + ghidra).
- [ ] `evidence_critic` prompt updated (ghidra tool names join the known-toolset list).
- [ ] `make check` green; live smoke test PASS.

## Out of scope (later slices)

- **Parallel r2 ∥ Ghidra + consensus** (NORTH_STAR Axis 2) — needs `ParallelAgent`
  factory support + a reconciliation/diff step.
- **`ParallelAgent`/`LoopAgent` factory support** — deferred.
- **capa/YARA/Detect-It-Easy/FLOSS triage** — a separate triage-enrichment slice
  (would use the same spec-driven builder pattern).
- **Ghidra write operations** (rename, retype, patch, struct creation) — the
  evidence-critic contract is read-only; write/annotation is a later
  collaboration slice.
- **Binary diffing** (BSim) — cross-version, much later.
- **Promoting `SandboxCliToolset` to the neutral core** — when a 2nd CLI engine
  appears.

## Open questions (resolve in their task, not now)

- ghidra-rpc's exact PyPI package name / install path in the Dockerfile (confirm
  `pip install ghidra-rpc` vs `uv tool install` at build time). The SKILL.md says
  commands run as `uv run ghidra-rpc <command>` from the skill directory — confirm
  whether the image needs the skill dir on PATH, or whether `ghidra-rpc` is
  directly executable after install.
- **Pod-interaction mechanism (RESOLVED):** raw `kubectl exec` — consistent with
  B.2's proven pattern (`prepare_sandbox` claims via the executor but drives the
  pod via raw `kubectl cp` / `kubectl port-forward`, bypassing the executor's
  `/execute` path which needs a python-runtime container). The ghidra image is a
  single container with Ghidra + ghidra-rpc (no python-runtime needed), mirroring
  the r2mcp image structure. A `kubectl_exec(namespace, pod, command)` helper
  (sibling to the existing `kubectl_cp` in `runtime/portforward.py`) runs the
  ghidra-rpc CLI. The executor is used only for `claim` (pod name) +
  `release_session` (cleanup).
- ghidra-rpc's binary-name handling: the `load` command takes a path; the
  query commands take a binary *name* (e.g. `ls`). Need to map the sha256 path
  to the name ghidra-rpc assigns (likely the basename without extension).
- Ghidra memory: the JVM heap default may need tuning (`-Xmx`) for the pod's
  resource limits — confirm at live-test time.
