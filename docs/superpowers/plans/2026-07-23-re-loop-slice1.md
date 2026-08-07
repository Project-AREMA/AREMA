# RE Loop — Slice 1 (Spec B, B.2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** A working radare2 RE agent — ingest a sample → drive radare2 via the `radare2-mcp` server in the sandbox → render an evidence-backed report — in a new domain package that keeps `src/arema` neutral.

**Architecture:** A peer domain package `src/reverse_engineer/` (outside the neutrality perimeter) with its own `build_reverse_engineer_composition()` mirroring the core's, plus an ADK-discoverable `agents/reverse_engineer/agent.py`. r2 is driven by the `radare2-mcp` MCP server reached over a **direct pod port-forward** (`localhost:8765/mcp`); the artifact is placed in the pod via `kubectl cp`. Three `LlmAgent`s: AnalystConsole (root, has `acquire_sample`+`prepare_sandbox`) → TriageRecon (r2mcp MCP) → ReportGenerator (evidence-ledger-only).

**Tech Stack:** Python 3.11+, Google ADK 1.25.1, the B.0 MCP-attachment seam, the B.1 `arema-radare2-mcp:0.1.0` pod, kubectl, pytest. Refs: spec `docs/superpowers/specs/2026-07-23-re-malware-mvp-design.md`, B.1 findings in memory obs #109.

> **Commit signing:** use `git -c commit.gpgsign=false commit -m "..."` for every commit.

---

## Resolved design decisions (do not re-litigate)

1. **Domain package:** `src/reverse_engineer/` peer package + `agents/reverse_engineer/` ADK entry. `src/arema` untouched (neutral). Relax one arch-test (Task 1).
2. **MCP URL = fixed `http://127.0.0.1:8765/mcp`.** `prepare_sandbox` opens `kubectl port-forward pod/<name> 8765:8765` before TriageRecon runs. Single-case-at-a-time (MVP).
3. **Artifact into the pod = `kubectl cp`** to `/app/<sha256>` (r2mcp has no upload tool). Add `tar` to the r2mcp image (Task 2).
4. **`prepare_sandbox(artifact_id)`** = `K8sSandboxExecutor.claim(case_id, "radare2-mcp")` + `kubectl cp` the artifact + open the port-forward; stash pod name in state for cleanup.
5. **No `header_provider` / no router** for r2mcp (B.1 pivot). r2mcp runs without `-A`.
6. **Direction:** `reverse_engineer` imports `arema`; never the reverse.

## File structure

```
src/reverse_engineer/
  __init__.py
  composition.py            build_reverse_engineer_composition() + get_reverse_engineer_composition() (@lru_cache)
  artifacts/store.py        ArtifactStore (content-addressed ~/.arema/artifacts or .arema/artifacts)
  tools/
    acquire_sample.py       acquire_sample(path) -> {artifact_id, sha256, size}  + ToolDescriptor
    prepare_sandbox.py      prepare_sandbox(artifact_id) -> {pod, ready}         + ToolDescriptor
  mcp/radare2.py            RADARE2_MCP McpServerDescriptor (StreamableHttp url http://127.0.0.1:8765/mcp, tool_allowlist read-only)
  agents/
    analyst_console.py      ANALYST_CONSOLE_DESCRIPTOR (root; tool_ids=acquire/prepare; sub_agent_ids=triage,report)
    triage_recon.py         TRIAGE_RECON_DESCRIPTOR (mcp_server_ids=radare2_mcp)
    report_generator.py     REPORT_GENERATOR_DESCRIPTOR
  prompts/                  analyst_console.md, triage_recon.md, report_generator.md
agents/reverse_engineer/
  __init__.py
  agent.py                  root_agent = get_reverse_engineer_composition().root_agent
images/radare2-mcp/Dockerfile   (Task 2: add tar)
pyproject.toml             (add src/reverse_engineer to wheel packages)
tests/architecture/test_neutral_boundaries.py  (Task 1: relax packages assertion)
tests/reverse_engineer/    (unit + component tests)
```

---

## Task 1: Scaffold the domain package + ADK entry + relax arch-test

**Files:** Create `src/reverse_engineer/__init__.py`, `composition.py` (minimal `build_reverse_engineer_composition` that builds a 1-agent placeholder root reusing the neutral core's `build_llm_agent` + `safe_default` profile, so the package imports + ADK entry resolves); `agents/reverse_engineer/__init__.py` + `agent.py` (`root_agent = get_reverse_engineer_composition().root_agent`). Modify `pyproject.toml` (add `"src/reverse_engineer"` to `[tool.hatch.build.targets.wheel].packages`) and `tests/architecture/test_neutral_boundaries.py` (relax `test_project_metadata_is_arema` to assert `"src/arema" in packages` and `packages[0] == "src/arema"`, with name+script unchanged).

- [ ] Create the package + entry; `build_reverse_engineer_composition` returns an `ApplicationComposition`-shaped object (reuse `arema.composition.ApplicationComposition` or a thin dataclass with `.root_agent`). Keep it importable with NO provider creds (use `Settings(_env_file=None, llm_provider="ollama")`).
- [ ] `pip install -e .` (or `uv sync`) so `reverse_engineer` imports.
- [ ] Verify `adk` discovery: `uv run python -c "from reverse_engineer.composition import get_reverse_engineer_composition; print(get_reverse_engineer_composition().root_agent.name)"` resolves.
- [ ] Arch tests green: `uv run --extra dev pytest tests/architecture -q`.
- [ ] Commit: `feat: scaffold src/reverse_engineer domain package + ADK entry`.

## Task 2: Add `tar` to the r2mcp image (for kubectl cp)

**Files:** `images/radare2-mcp/Dockerfile` (add `tar` to the apt install line).
- [ ] Add `tar` to the `apt-get install` list; rebuild `arema-radare2-mcp:0.1.0`; `kind load`.
- [ ] Verify `kubectl cp` works into a pod: `kubectl cp /etc/hostname <ns>/<pod>:/app/probe.txt` then `kubectl exec ... -- ls /app/probe.txt`.
- [ ] Commit: `feat: add tar to radare2-mcp image for kubectl cp artifact transfer`.

## Task 3: ArtifactStore + acquire_sample

**Files:** `src/reverse_engineer/artifacts/store.py`, `src/reverse_engineer/tools/acquire_sample.py`, `tests/reverse_engineer/test_artifact_store.py`.
- [ ] `ArtifactStore(root: Path)`: `acquire(src_path) -> str` (SHA256 the bytes, write `<root>/<sha256>`, return sha256; idempotent). Pure stdlib (`hashlib`, `shutil`).
- [ ] `acquire_sample(path: str) -> dict` tool: resolve path, `ArtifactStore(...).acquire`, return `{artifact_id, sha256, size}`. Register as a `ToolDescriptor` with an `OutputPolicy`.
- [ ] Unit tests: content-addressing (same bytes → same id), dedup (no rewrite), missing file raises.
- [ ] Commit: `feat: ArtifactStore + acquire_sample tool`.

## Task 4: radare2_mcp McpServerDescriptor

**Files:** `src/reverse_engineer/mcp/radare2.py`.
- [ ] `RADARE2_MCP = McpServerDescriptor(id="radare2_mcp", transport=StreamableHttpTransport(url="http://127.0.0.1:8765/mcp", read_timeout=600.0), required=False, tool_allowlist=(... read-only subset: open_file, analyze, list_functions, decompile_function, list_strings, list_imports, list_exports, xrefs_to, show_info ...))`. Drop `run_command`/`run_javascript` from the allowlist.
- [ ] Unit test: the descriptor is well-formed + the allowlist excludes the EXEC tools.
- [ ] Commit: `feat: radare2_mcp McpServerDescriptor (StreamableHttp, read-only allowlist)`.

## Task 5: prepare_sandbox (claim + kubectl cp + port-forward)

**Files:** `src/reverse_engineer/tools/prepare_sandbox.py` (+ a small `src/reverse_engineer/runtime/portforward.py` helper).
- [ ] `prepare_sandbox(artifact_id) -> dict`: resolve artifact bytes from the store; `K8sSandboxExecutor` (from `RuntimeServices.sandbox`) `.claim(case_id, "radare2-mcp")` → pod name; `kubectl cp <artifact> <ns>/<pod>:/app/<sha256>`; open `kubectl port-forward pod/<pod> 8765:8765` (background, track the Popen); stash pod+portforward handle in a module-level registry keyed by case_id (for cleanup). Return `{pod, ready}`. Fail-open errors with a clear message.
- [ ] The case_id: read from `tool_context.state.get(SessionKeys.SANDBOX_CASE_ID)` (duck-typed `.get`), fallback to a fixed key for single-case MVP.
- [ ] Cleanup: a `release_case(case_id)` that terminates the port-forward + `executor.release_session` — wired to the CLI `/reset`/exit path (the domain registers an atexit/cleanup hook, OR reuses the core's sandbox release).
- [ ] Unit test with a fake executor (claim returns a pod name) + monkeypatched kubectl (subprocess): assert cp + port-forward invoked, handle registered.
- [ ] Commit: `feat: prepare_sandbox tool (claim + kubectl cp + port-forward)`.

## Task 6: evidence/finding codec

**Files:** `src/reverse_engineer/evidence.py` (or under artifacts/) — a `FindingRecord` pydantic model + `RecordCodec(namespace="evidence", kind="finding", schema_version=1)` registered on the composition's codec registry.
- [ ] `FindingRecord`: `artifact_id, claim, tool (citation), confidence (0..1), detail`.
- [ ] Unit test: encode/decode round-trip via the codec registry.
- [ ] Commit: `feat: evidence/finding memory codec`.

## Task 7: Agents + prompts + composition

**Files:** `src/reverse_engineer/agents/*.py`, `prompts/*.md`, `composition.py` (fill in).
- [ ] Prompts: `analyst_console.md` (human interface, reference artifacts by id only, delegate), `triage_recon.md` (drive r2mcp: open_file /app/<id>, analyze, gather functions/strings/imports, emit findings), `report_generator.md` (render from evidence, never invent).
- [ ] `TRIAGE_RECON_DESCRIPTOR`: `AgentDescriptor(..., prompt_id="triage_recon", factory=build_llm_agent, mcp_server_ids=("radare2_mcp",))`.
- [ ] `ANALYST_CONSOLE_DESCRIPTOR` (root): `tool_ids=("acquire_sample","prepare_sandbox")`, `sub_agent_ids=("triage_recon","report_generator")`.
- [ ] `build_reverse_engineer_composition`: register profile + agents + tools + MCP + codec; `builder.freeze("analyst_console")`; build memory service; `compose_agents`; return composition. Load prompts via the core's `load_prompt` (the prompts live under `src/reverse_engineer/prompts/` — confirm `load_prompt` resolves package-relative, or add a domain prompt loader).
- [ ] Component test: `get_reverse_engineer_composition()` builds; root has the 2 tools + 2 sub-agents; TriageRecon has the r2mcp toolset in its tools (B.0 wiring).
- [ ] Commit: `feat: AnalystConsole/TriageRecon/ReportGenerator agents + RE composition`.

## Task 8: Live end-to-end + make check

- [ ] `make sandbox-mcp-image && make sandbox-mcp-up` (pods Ready).
- [ ] `uv run arema` (or `adk run agents/reverse_engineer`) with `AREMA_SANDBOX_ENABLED=true`, `AREMA_SANDBOX_BACKEND=k8s`, a real sample; ask it to analyze; confirm it acquires → prepares → drives r2mcp (functions/strings) → reports. (This is the smoke test of the whole loop.)
- [ ] `make check` green (all unit/component/architecture).
- [ ] Commit any fixes; final `make check`.

---

## Self-review (plan author)

- **Spec coverage (B.2 / Slice 1):** ArtifactStore+acquire (T3), prepare_sandbox (T5), r2mcp descriptor (T4), 3 agents (T7), evidence codec (T6), domain package structure (T1), live loop (T8). ✓
- **Neutrality held:** all domain code in `src/reverse_engineer/`; `src/arema` untouched except the one arch-test relaxation (T1). ✓
- **Open implementation details** (resolve in-task, not blockers): exactly how `load_prompt` resolves domain prompts under `src/reverse_engineer/prompts/` (may need a domain prompt loader or packaging via importlib.resources); how the port-forward Popen is cleaned up on session end (registry + atexit). Both are local to their tasks.
- **Scope:** Slice 1 only (r2 path). Ghidra, SanitizationMembrane, EvidenceCritic, parallelism are B.3+.
