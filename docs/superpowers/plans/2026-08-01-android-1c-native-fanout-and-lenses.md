# Android Slice 1c — Native `.so` Fan-Out + Android Lenses (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the Android column. (1) An APK's bundled native libraries are analyzed by **Ghidra** — one ABI, bounded — alongside the jadx DEX decompilation, both flowing into the report; and (2) the downstream lenses become Android-aware: host/network IOCs from Android evidence, and MITRE **ATT&CK Mobile** mapping.

**Architecture:** Native analysis is a **new evidence stage** (`native_evidence_json`), not a second writer to `deep_evidence_json` — because the evidence normalizer *replaces* its slot while the critic *unions every stage*. A composite `java_deep_analysis` SequentialAgent runs `java_decompile` (jadx, DEX) then `android_native_analysis` (Ghidra over one ABI's `.so`); the deep-engine router routes `apk/dex/jar` to it. `android_native_analysis` reuses `prepare_ghidra` + the ghidra toolset over `.so` artifacts extracted from the APK and registered via `ArtifactStore` (no `CURRENT_ARTIFACT_KEY` repoint). Builds on Slice 1a (jadx route, format router) + Slice 1b (androguard triage).

**Spec:** `docs/superpowers/specs/2026-07-31-android-dex-apk-analysis-design.md` (§C fan-out + §E lenses). This is the final Android slice.

## Global Constraints (exact values — bind every task)

- **New evidence stage:** `NATIVE_EVIDENCE_KEY = "native_evidence_json"`, stage name `"native"`. Add `("native", "native_evidence_json")` to `CRITIC_STAGE_KEYS` in `evidence_output.py` (so `normalize_critic_output` unions it and `UPSTREAM_EVIDENCE_KEYS` derives it). Order it **after** `("deep", ...)`.
- **`.so` fan-out ABI:** exactly one — prefer `arm64-v8a`, else `armeabi-v7a`, else the first present ABI; never analyze the same lib across ABIs. Bound the count (`≤ MAX_NATIVE_LIBS = 8`) and each lib's size (skip a `.so` over a cap, recording it as a limitation).
- **`extract_android_native_libs(artifact_id)` tool:** runs in the **deobfuscation-tools pod** (stage the APK → extract the chosen ABI's `lib/<abi>/*.so` → read each back bounded → register each via `ArtifactStore` as a new sha256 artifact). It **must NOT repoint `CURRENT_ARTIFACT_KEY`** (unlike `register_unpacked_artifact`). Returns `{"success", "abi", "libs": [{"name","artifact_id"}], "skipped": [...]}`. Self-gates on `SAMPLE_FORMAT_KEY == "apk"` (a bare `dex`/`jar` carries no libs). Fail-open.
- **`android_native_analysis` agent:** `build_llm_agent`, `runtime_profile_id="re_guarded"`, `tool_ids=("extract_android_native_libs", "prepare_ghidra", <the 9 ghidra tool ids>)`, `output_key=NATIVE_EVIDENCE_KEY`, `evidence_output_callback(stage="native")`, **no `output_schema`**. Prompt: gate (skip with one cited FINDING if not `apk` or no libs), extract, `prepare_ghidra` on the primary/loader `.so`, decompile `JNI_OnLoad` + exports (bounded ≤3 libs, ≤10 FINDINGs). Reuses `prepare_ghidra` + the ghidra tools verbatim.
- **Composite route:** `JAVA_DEEP_ANALYSIS_DESCRIPTOR` — `build_sequential_agent`, `prompt_id=None`, `sub_agent_ids=("java_decompile","android_native_analysis")`. `deep_engine_router.format_engines` now maps `apk|dex|jar → java_deep_analysis` (was `java_decompile`); `sub_agent_ids` swaps `java_decompile` → `java_deep_analysis`. `java_decompile` becomes a sub-agent of `java_deep_analysis` (no longer directly under the router). Update the Slice-1a router test accordingly.
- **Ghidra reuse:** `android_native_analysis` shares the `ghidra-rpc` pool + `prepare_ghidra` + `GHIDRA_COMMANDS` with `deep_decompile_worker`; the ghidra tools are already in `_BINARY_ORIGIN_TOOLS`, so `.so` decompiled output is already sanitized. The **only** new tool is `extract_android_native_libs` — add it to `_BINARY_ORIGIN_TOOLS` (it echoes attacker-controlled lib names).
- **Lenses (§E):** update the prompts (evidence-driven agents; prompt-only) — `host_indicators.md`/`network_indicators.md` (Android host IOCs: package, signing-cert sha256, dangerous permissions, exported components; network IOCs: URLs/domains from resources + decompiled strings), `behavior_characterization.md` (Android capabilities: SMS interception, accessibility abuse, screen overlay, device-admin, dynamic code loading), `attack_mapper.md` (map Android evidence to the **ATT&CK Mobile** matrix, native/.NET stay on Enterprise).
- **Isolation:** the APK/`.so` are handled only in sandbox pods (deobf for extraction, ghidra for analysis); nothing parses them in the AREMA process.
- **ADK rules:** no bare `typing.Any` param annotations; no `isinstance(state, dict)` on ADK `State`; `src/arema` neutral; fail-open; `id` == runtime name; `build_format_router`/`build_sequential_agent` reused (no new orchestration code).
- **Commits:** plain `git commit` (signing off). `rtk` prefix; `uv run pytest`. `make check` green each task.

---

## File Structure

**Create:**
- `src/reverse_engineering/tools/android/native_libs.py` (`extract_android_native_libs` + `EXTRACT_ANDROID_NATIVE_LIBS_TOOL`)
- `src/reverse_engineering/agents/android_native_analysis.py` (`ANDROID_NATIVE_ANALYSIS_DESCRIPTOR`)
- `src/reverse_engineering/agents/java_deep_analysis.py` (`JAVA_DEEP_ANALYSIS_DESCRIPTOR`)
- `src/reverse_engineering/prompts/android_native_analysis.md`
- `tests/reverse_engineering/test_extract_native_libs.py`, `test_android_native_analysis.py`, `test_java_deep_analysis.py`

**Modify:**
- `src/reverse_engineering/agents/evidence_output.py` — add the `native` stage (+ its key constant, likely in `tools/ghidra/coverage.py` or a new one)
- `src/reverse_engineering/agents/format_router.py` — route `apk/dex/jar → java_deep_analysis`
- `src/reverse_engineering/composition.py` — register the extract tool
- `src/reverse_engineering/__init__.py` — export the new descriptors
- `src/reverse_engineering/profiles.py` — add `extract_android_native_libs` to `_BINARY_ORIGIN_TOOLS`
- `src/malware_analyst/composition.py` — register the two new agents
- `src/reverse_engineering/prompts/{host_indicators,network_indicators,behavior_characterization,attack_mapper}.md` — Android awareness
- `tests/reverse_engineering/test_format_router.py` (or the 1a router test), `tests/malware_analyst/test_malware_analyst_composition.py`

Execution order T1→T6.

---

### Task 1: The `native_evidence_json` stage

**Files:** Modify `src/reverse_engineering/agents/evidence_output.py` (`CRITIC_STAGE_KEYS`); add `NATIVE_EVIDENCE_KEY` (define in `tools/ghidra/coverage.py` next to `DEEP_EVIDENCE_KEY`, or a new `android/coverage.py`). Test: `tests/reverse_engineering/test_evidence_output.py` (extend) or a focused test.

**Interfaces — Produces:** `NATIVE_EVIDENCE_KEY = "native_evidence_json"`; the critic unions the `"native"` stage.

- [ ] **Step 1: Write the failing test** — assert the critic includes native findings:
```python
def test_critic_unions_native_evidence_stage():
    from reverse_engineering.agents.evidence_output import CRITIC_STAGE_KEYS, UPSTREAM_EVIDENCE_KEYS
    assert ("native", "native_evidence_json") in CRITIC_STAGE_KEYS
    assert "native_evidence_json" in UPSTREAM_EVIDENCE_KEYS
```
(Plus, if there is an existing `normalize_critic_output` integration test seeding stage envelopes, add a `native_evidence_json` envelope and assert its finding lands in `validated_evidence_json.accepted`.)
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** — add `NATIVE_EVIDENCE_KEY = "native_evidence_json"` and insert `("native", NATIVE_EVIDENCE_KEY)` into `CRITIC_STAGE_KEYS` after the `("deep", ...)` entry. `UPSTREAM_EVIDENCE_KEYS` derives automatically.
- [ ] **Step 4: Run tests** → PASS; `rtk make check` (the critic + report already iterate `CRITIC_STAGE_KEYS`, so this is centrally handled).
- [ ] **Step 5: Commit** — `git commit -am "feat(re): add native_evidence_json critic stage for android .so analysis"`

---

### Task 2: `extract_android_native_libs` tool

**Files:** Create `src/reverse_engineering/tools/android/native_libs.py`. Test: `tests/reverse_engineering/test_extract_native_libs.py`.

**Interfaces — Consumes:** `stage_artifact`/`run_argv`/`read_bounded_file` (deobf runtime), `ArtifactStore`/`default_artifacts_root`, `SAMPLE_FORMAT_KEY`. **Produces:** `EXTRACT_ANDROID_NATIVE_LIBS_TOOL` (id `extract_android_native_libs`, deferred factory).

- [ ] **Step 1: Write the failing tests** (monkeypatch `run_argv` to return a listing/bytes; a fake `ArtifactStore.add`):
```python
def test_picks_arm64_then_armeabi(...): ...   # both ABIs present -> abi == "arm64-v8a"
def test_registers_each_so_without_repointing_current_artifact(...): ...
    # CURRENT_ARTIFACT_KEY unchanged; libs[] carry the registered artifact_ids
def test_skips_non_apk(...): ...              # format="dex" -> {"success":False,"skipped":True}, no exec
def test_bounds_lib_count_and_size(...): ...  # >MAX or oversized -> recorded in skipped[]
def test_fails_open(...): ...                 # run_argv raises -> {"success":False,"error":...}
```
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** — `build_extract_android_native_libs(context)`; inner `extract_android_native_libs(artifact_id, tool_context)`: gate on `SAMPLE_FORMAT_KEY == "apk"`; `staged = stage_artifact(...)`; list `lib/*` entries (`run_argv(["unzip","-Z1", staged.input_path, "lib/*"])` or a python one-liner); pick the ABI (arm64-v8a > armeabi-v7a > first); for each `.so` (≤ `MAX_NATIVE_LIBS`, under the size cap) extract + `read_bounded_file` its bytes and `ArtifactStore(default_artifacts_root()).add(bytes)` → sha256 id (mirror `register_unpacked_artifact`'s store use but **do not** write `CURRENT_ARTIFACT_KEY`); return `{"success":True,"abi":abi,"libs":[{"name","artifact_id"}],"skipped":[...]}`. Wrap in `try/except` → fail-open dict. `EXTRACT_ANDROID_NATIVE_LIBS_TOOL = ToolDescriptor(id="extract_android_native_libs", ..., factory=build_extract_android_native_libs, output_policy=OutputPolicy(max_chars=4_000, max_list_items=20))`.
- [ ] **Step 4: Run tests** → PASS; `rtk make type-check`.
- [ ] **Step 5: Commit** — `git commit -am "feat(re): extract_android_native_libs (one-ABI .so -> registered artifacts)"`

---

### Task 3: `android_native_analysis` agent + prompt

**Files:** Create `src/reverse_engineering/agents/android_native_analysis.py`, `src/reverse_engineering/prompts/android_native_analysis.md`. Test: `tests/reverse_engineering/test_android_native_analysis.py`.

**Interfaces — Consumes:** `EXTRACT_ANDROID_NATIVE_LIBS_TOOL`, `prepare_ghidra` + `GHIDRA_COMMANDS` ids, `NATIVE_EVIDENCE_KEY`, `evidence_output_callback`. **Produces:** `ANDROID_NATIVE_ANALYSIS_DESCRIPTOR`.

- [ ] **Step 1: Write the failing tests** (mirror `deep_decompile` / `java_decompile` descriptor tests):
```python
def test_descriptor_well_formed():
    d = ANDROID_NATIVE_ANALYSIS_DESCRIPTOR
    assert d.id == d.name == "android_native_analysis"
    assert d.runtime_profile_id == "re_guarded"
    assert d.output_key == "native_evidence_json"
    assert d.tool_ids[0] == "extract_android_native_libs"
    assert "prepare_ghidra" in d.tool_ids and "ghidra_decompile" in d.tool_ids
    assert d.output_schema is None

def test_prompt_gates_and_bounds():
    t = load_domain_prompt("android_native_analysis").lower()
    assert "extract_android_native_libs" in load_domain_prompt("android_native_analysis")
    assert "jni_onload" in t and "apk" in t and "skip" in t
    assert "transfer to" not in t
```
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** — the descriptor mirrors `deep_decompile.py` (swap `output_key`/stage to native; prepend `extract_android_native_libs` to `tool_ids`, then `prepare_ghidra` + the ghidra tools). Write `android_native_analysis.md`: gate (if format≠apk or `extract` returns no libs → one cited skip FINDING, stop); else `extract_android_native_libs`, then for the primary/loader `.so` (largest, or a `lib*jiagu/secexe/...`-style loader name) `prepare_ghidra(artifact_id)` and decompile `JNI_OnLoad` + notable exports (`ghidra_imports`/`ghidra_list_functions`/`ghidra_decompile`); bounds ≤3 libs, ≤10 FINDINGs; FINDING schema; no transfer language.
- [ ] **Step 4: Run tests** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(re): android_native_analysis agent (Ghidra over APK .so)"`

---

### Task 4: Composite `java_deep_analysis` route

**Files:** Create `src/reverse_engineering/agents/java_deep_analysis.py`. Modify `src/reverse_engineering/agents/format_router.py`. Test: `tests/reverse_engineering/test_java_deep_analysis.py` + update the Slice-1a router test.

**Interfaces — Consumes:** `JAVA_DECOMPILE_DESCRIPTOR`, `ANDROID_NATIVE_ANALYSIS_DESCRIPTOR`, `build_sequential_agent`. **Produces:** `JAVA_DEEP_ANALYSIS_DESCRIPTOR`; the router routes JVM formats to it.

- [ ] **Step 1: Write the failing tests:**
```python
def test_java_deep_analysis_is_sequential_jadx_then_native():
    d = JAVA_DEEP_ANALYSIS_DESCRIPTOR
    assert d.factory.__name__ == "build_sequential_agent"
    assert d.sub_agent_ids == ("java_decompile", "android_native_analysis")

def test_router_routes_jvm_to_java_deep_analysis():
    d = DEEP_ENGINE_ROUTER_DESCRIPTOR
    assert d.metadata["format_engines"]["apk"] == "java_deep_analysis"
    assert "java_deep_analysis" in d.sub_agent_ids
    assert "java_decompile" not in d.sub_agent_ids   # now under java_deep_analysis
```
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** — `JAVA_DEEP_ANALYSIS_DESCRIPTOR = AgentDescriptor(id="java_deep_analysis", name="java_deep_analysis", description="Composite JVM/Android deep analysis: jadx (DEX) then Ghidra over native .so.", prompt_id=None, factory=build_sequential_agent, runtime_profile_id="safe_default", sub_agent_ids=("java_decompile","android_native_analysis"))`. In `format_router.py` `DEEP_ENGINE_ROUTER_DESCRIPTOR`: `sub_agent_ids` replace `"java_decompile"` → `"java_deep_analysis"`; `format_engines` map `apk/dex/jar → "java_deep_analysis"`. Update the Slice-1a router test (`java_decompile` is no longer a direct router sub-agent; `java_deep_analysis` is, and contains `java_decompile`).
- [ ] **Step 4: Run tests** → `uv run pytest tests/reverse_engineering/test_java_deep_analysis.py tests/reverse_engineering/test_format_router.py -v` → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(re): composite java_deep_analysis route (jadx + native .so)"`

---

### Task 5: Register + sanitizer + end-to-end wiring

**Files:** Modify `src/reverse_engineering/composition.py` (register the extract tool), `src/reverse_engineering/__init__.py` (exports), `src/reverse_engineering/profiles.py` (`_BINARY_ORIGIN_TOOLS`), `src/malware_analyst/composition.py` (register both agents). Tests: extend `test_re_guarded_profile.py`, `test_malware_analyst_composition.py`.

- [ ] **Step 1: Write the failing tests:**
```python
def test_extract_tool_is_sanitized_binary_origin():
    from reverse_engineering.profiles import _BINARY_ORIGIN_TOOLS
    assert "extract_android_native_libs" in _BINARY_ORIGIN_TOOLS

def test_composition_freezes_with_native_route_reachable():
    from malware_analyst.composition import get_malware_analyst_composition
    root = get_malware_analyst_composition().root_agent
    router = next(a for a in root.sub_agents if a.name == "deep_engine_router")
    jda = next(a for a in router.sub_agents if a.name == "java_deep_analysis")
    assert {a.name for a in jda.sub_agents} == {"java_decompile", "android_native_analysis"}
    assert "extract_android_native_libs" in get_malware_analyst_composition().catalog.tools
```
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** — `composition.py` `register_re_infrastructure`: `builder.add_tool(EXTRACT_ANDROID_NATIVE_LIBS_TOOL)`. `__init__.py`: export `ANDROID_NATIVE_ANALYSIS_DESCRIPTOR`, `JAVA_DEEP_ANALYSIS_DESCRIPTOR`. `profiles.py`: add `extract_android_native_libs` to `_BINARY_ORIGIN_TOOLS`. `malware_analyst/composition.py`: `add_agent(ANDROID_NATIVE_ANALYSIS_DESCRIPTOR)` + `add_agent(JAVA_DEEP_ANALYSIS_DESCRIPTOR)`.
- [ ] **Step 4: Full gate** — `rtk make check` → exit 0 (freeze validates `java_deep_analysis` → `{java_decompile, android_native_analysis}` reachable; the extract tool registered + sanitized; whole suite green).
- [ ] **Step 5: Commit** — `git commit -am "feat(re): register + wire the android native-lib fan-out end-to-end"`

---

### Task 6: Android-aware downstream lenses (§E)

**Files:** Modify `src/reverse_engineering/prompts/host_indicators.md`, `network_indicators.md`, `src/malware_analyst/prompts/behavior_characterization.md`, `attack_mapper.md` (confirm exact paths — IOC/host/network prompts may live under `reverse_engineering` or `malware_analyst`). Tests: `tests/.../test_ioc_lenses.py`, `test_behavior_lenses.py` (extend to assert Android tokens).

**Interfaces — Produces:** Android-aware lens prompts. Prompt-only; the evidence-driven agents are unchanged.

- [ ] **Step 1: Write the failing tests** — assert each prompt names its Android guidance:
```python
def test_host_ioc_prompt_covers_android():
    t = load_prompt("host_indicators").lower()
    for k in ("package", "certificate", "permission", "exported component"):
        assert k in t

def test_network_ioc_prompt_covers_android_urls():
    assert "resources" in load_prompt("network_indicators").lower()

def test_attack_mapper_uses_mobile_matrix_for_android():
    assert "att&ck mobile" in load_prompt("attack_mapper").lower() or "mobile matrix" in load_prompt("attack_mapper").lower()

def test_behavior_prompt_covers_android_capabilities():
    t = load_prompt("behavior_characterization").lower()
    for k in ("accessibility", "sms", "overlay", "device-admin"):
        assert k in t
```
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** — read each prompt and add an Android section (leave native/.NET guidance intact): host IOCs (package name, signing-cert sha256, dangerous permissions, exported components); network IOCs (URLs/domains from `strings.xml`/resources + decompiled Java + native strings); behavior (SMS interception, accessibility abuse, screen overlay, device-admin/lock, dynamic code loading / `DexClassLoader`); attack_mapper (for Android evidence, map to the **ATT&CK Mobile** matrix — its T-IDs — while native/.NET evidence stays on Enterprise). Keep each prompt evidence-cited and bounded.
- [ ] **Step 4: Run tests + full gate** — `uv run pytest tests/reverse_engineering/test_ioc_lenses.py tests/malware_analyst/test_behavior_lenses.py -v && rtk make check` → green.
- [ ] **Step 5: Commit** — `git commit -am "feat(malware): Android-aware IOC/behavior/ATT&CK-Mobile lenses"`

---

## Self-Review Notes

- **Spec coverage:** §C `.so` fan-out (one ABI, bounded Ghidra) via a new `native` evidence stage (T1), the extract tool (T2), the native agent reusing Ghidra (T3), the composite route (T4), wiring (T5); §E Android lenses (T6).
- **Root-cause / pattern fidelity:** the new stage rides the *existing* critic-union mechanism (no evidence-merge code); `android_native_analysis` reuses `prepare_ghidra` + `GHIDRA_COMMANDS`; `java_deep_analysis` reuses `build_sequential_agent`; the router reuses `build_format_router` (only its map changes); the extract tool mirrors `register_unpacked_artifact`'s `ArtifactStore` use but deliberately does **not** repoint `CURRENT_ARTIFACT_KEY`.
- **Type/interface consistency:** `NATIVE_EVIDENCE_KEY` (T1) is the `output_key` of `android_native_analysis` (T3) and a `CRITIC_STAGE_KEYS` entry (T1); the extract tool's `libs[].artifact_id` (T2) are sha256 ids `prepare_ghidra` accepts (T3); `java_deep_analysis.sub_agent_ids` (T4) reference agents from T3 + Slice 1a.
- **Confirm-during-impl (not placeholders):** the exact `ArtifactStore` "store bytes → sha256 id" method name (T2) — read `register_unpacked_artifact`'s use; the exact prompt-file locations for the four lenses (T6) — `grep` for their `prompt_id`s; whether a bare `dex`/`jar` route through `java_deep_analysis` correctly no-ops `android_native_analysis` (it self-gates on `apk`, T3). Ghidra's real decompilation of a `.so` is exercised only in-cluster; the extract tool + gating + wiring are unit-tested.
