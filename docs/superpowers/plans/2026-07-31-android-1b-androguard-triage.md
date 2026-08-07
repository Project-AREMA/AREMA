# Android Slice 1b — androguard Triage (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An `apk` / `dex` / `jar` sample is triaged by **androguard** — manifest, permissions, exported components, receivers, `debuggable`/cleartext, multidex inventory, native-lib enumeration, resource URLs, and **packer detection** — producing evidence-backed findings in the shared `triage_evidence_json` slot, selected by a **triage router** exactly like the native/.NET path uses `triage_recon`.

**Architecture:** androguard runs **inside the deobfuscation-tools sandbox pod** (never in the AREMA process — a hostile APK must be parsed in isolation) via the existing `stage_artifact → run_argv → read_bounded_file` one-shot pattern. A `triage_router` reuses Slice 1a's generalized `build_format_router` (a format→engine map) to route `apk|dex|jar → android_triage`, everything else → `triage_recon` (radare2). Builds on Slice 1a (which added `JVM_FORMATS`, the format router, and the jadx route).

**Spec:** `docs/superpowers/specs/2026-07-31-android-dex-apk-analysis-design.md` (§D). This is Slice 1b (triage) only; Slice 1c (`.so`→Ghidra fan-out + Android-aware IOC/behavior/ATT&CK-Mobile lenses) is a separate plan.

## Global Constraints (exact values — bind every task)

- **Triage engine:** androguard, added to the **existing `deobfuscation-tools` image/pool** — **no new pool**. It runs in the pod via `run_argv`; it is NEVER imported/executed in the AREMA process.
- **Tool:** `android_triage_scan(artifact_id: str)` — one androguard pass → a bounded structured dict. Self-gates on `SAMPLE_FORMAT_KEY` ∈ {`apk`,`dex`,`jar`}; a non-JVM sample returns a skip result. Fail-open (never raises into the run). `id == "android_triage_scan"` (so its `OutputPolicy` binds).
- **Scan output contract (keys):** `success`, `package`, `permissions{requested,dangerous}`, `components{activities,services,receivers,providers,exported}`, `flags{debuggable,uses_cleartext_traffic}`, `sdk{min,target}`, `certificate{sha256,subject}`, `dex{count,classes,methods}`, `native_libs[]` (`lib/<abi>/*.so`), `url_candidates[]`, `packer{detected,name,signals[]}`. APK gets the full set; a bare `dex` fills `dex`/`url_candidates` and leaves manifest-derived keys empty; a `jar` degrades to `dex`/class-level only.
- **Packer detection** is a **pure module** `packer_signatures.py` (loader `.so` name / assets / stub-class signatures → packer name) so it is unit-testable without androguard or a cluster. Starter table (extend as needed):
  - `libjiagu*.so` → `jiagu` (360)
  - `libsecexe.so`/`libsecmain.so`/`libSecShell.so`/`libDexHelper.so` → `bangcle`
  - `libtup.so`/`libshella*.so`/`libmobisec.so` → `legu` (Tencent)
  - `libdexprotector*.so` → `dexprotector`
  - `libAPKProtect.so` → `apkprotect`
- **Router:** a new `triage_router` reuses `build_format_router` (Slice 1a) — `metadata={"format_engines":{"apk":"android_triage","dex":"android_triage","jar":"android_triage"},"default_engine":"triage_recon"}`, `sub_agent_ids=("triage_recon","android_triage")`. It replaces `"triage_recon"` at **index 1** of `MALWARE_ANALYST_DESCRIPTOR.sub_agent_ids`. Both engines write `output_key=TRIAGE_EVIDENCE_KEY` (`"triage_evidence_json"`) via `evidence_output_callback(stage="triage")`.
- **Agent:** `android_triage` — `build_llm_agent`, `runtime_profile_id="re_guarded"`, `tool_ids=("android_triage_scan",)`, `output_key=TRIAGE_EVIDENCE_KEY`, `evidence_output_callback(stage="triage")`, **no `output_schema`** (schema+tools is the unreliable ADK combo — see `triage_recon.py`). Its own prompt.
- **Sanitizer:** `android_triage_scan` output is attacker-derived → add it to `_BINARY_ORIGIN_TOOLS` (`profiles.py`) so `re_guarded` frames it as untrusted.
- **Isolation & fail-open:** the tool stages the artifact into the deobf pod and reads bounded output; any pod/parse failure → `{"success": False, "error": ...}`, never a raise.
- **ADK rules:** no bare `typing.Any` param annotations; no `isinstance(state, dict)` on ADK `State`; `src/arema` stays domain-neutral; `id`s equal runtime names.
- **Commits:** plain `git commit` (`commit.gpgsign=false`). `rtk` prefix on git/make; `uv run pytest` for tests. `make check` green at every task. For image tasks: do NOT `docker build` (no docker/cluster here) — unit-test the pure logic + the tool via mocked `run_argv`.

---

## File Structure

**Create:**
- `src/reverse_engineering/tools/android/__init__.py`, `packer_signatures.py`, `triage_scan.py` (the `android_triage_scan` tool)
- `images/deobfuscation-tools/androguard_triage.py` (the in-pod androguard script → JSON, imports the packer signatures)
- `src/reverse_engineering/agents/android_triage.py`, `src/reverse_engineering/agents/triage_router.py`
- `src/reverse_engineering/prompts/android_triage.md`
- `tests/reverse_engineering/test_packer_signatures.py`, `test_android_triage_scan.py`, `test_android_triage.py`, `test_triage_router.py`

**Modify:**
- `images/deobfuscation-tools/requirements.in` (+ regenerated `requirements.lock`), `Dockerfile` (COPY the script), `healthcheck` (androguard version)
- `src/reverse_engineering/composition.py` — register `ANDROID_TRIAGE_SCAN_TOOL`
- `src/reverse_engineering/__init__.py` — export `ANDROID_TRIAGE_DESCRIPTOR`, `TRIAGE_ROUTER_DESCRIPTOR`
- `src/reverse_engineering/profiles.py` — add `android_triage_scan` to `_BINARY_ORIGIN_TOOLS`
- `src/malware_analyst/composition.py` — `add_agent(ANDROID_TRIAGE_DESCRIPTOR)` + `add_agent(TRIAGE_ROUTER_DESCRIPTOR)`
- `src/malware_analyst/agents/malware_analyst.py` — `sub_agent_ids[1]` `triage_recon` → `triage_router`
- `tests/malware_analyst/test_malware_analyst_composition.py` — update the pipeline-order test

Execution order T1→T6.

---

### Task 1: `packer_signatures.py` — pure packer detection

**Files:** Create `src/reverse_engineering/tools/android/__init__.py` (empty), `packer_signatures.py`. Test: `tests/reverse_engineering/test_packer_signatures.py`.

**Interfaces — Produces:** `detect_packer(native_libs: list[str], asset_names: list[str], app_class: str | None) -> dict` returning `{"detected": bool, "name": str | None, "signals": list[str]}`.

- [ ] **Step 1: Write the failing test**
```python
from reverse_engineering.tools.android.packer_signatures import detect_packer

def test_detects_jiagu_by_loader_so():
    r = detect_packer(["lib/arm64-v8a/libjiagu.so", "lib/arm64-v8a/libapp.so"], [], None)
    assert r["detected"] is True and r["name"] == "jiagu" and "libjiagu.so" in " ".join(r["signals"])

def test_detects_legu_variant():
    assert detect_packer(["lib/armeabi-v7a/libshellx-super.2019.so"], [], None)["name"] == "legu"

def test_clean_app_is_not_flagged():
    r = detect_packer(["lib/arm64-v8a/libnative-lib.so"], ["assets/config.json"], "com.example.App")
    assert r["detected"] is False and r["name"] is None and r["signals"] == []
```
- [ ] **Step 2: Run to verify fail** — `uv run pytest tests/reverse_engineering/test_packer_signatures.py -v` → FAIL (module absent).
- [ ] **Step 3: Implement** — a signature table (basename globs → packer name) matched against `native_libs` basenames (plus asset/app-class rules); return the first match with its signal(s), else not-detected. Use the Global-Constraints starter table; match on the `.so` **basename** (case-insensitive) with `fnmatch` so `libjiagu_art.so` matches `libjiagu*.so`.
- [ ] **Step 4: Run tests** → PASS.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(re): android packer-signature detection (pure)"`

---

### Task 2: androguard in the deobf image + the in-pod triage script

**Files:** Modify `images/deobfuscation-tools/requirements.in` (+ regenerate `requirements.lock`), `Dockerfile`, healthcheck. Create `images/deobfuscation-tools/androguard_triage.py`. Test: a script-contract test (no androguard/cluster needed) `tests/reverse_engineering/test_androguard_triage_script.py`.

**Interfaces — Produces:** `/opt/androguard_triage.py <apk_path>` printing the §Global-Constraints JSON to stdout; the deobf image carrying androguard.

- [ ] **Step 1: Write the failing test** — import the script's pure helpers (parse-independent) and assert the JSON contract shape + that it delegates packer detection to `packer_signatures.detect_packer`. Structure the script so androguard I/O is one function (`_load_apk(path)`) and the JSON assembly (`build_report(apk_view)`) is pure over a small duck-typed view, so `build_report` is unit-testable with a fake view:
```python
def test_build_report_shape_and_packer_delegation():
    from images_deobf.androguard_triage import build_report  # via a tests path shim, or copy the pure fn
    fake = _FakeApkView(package="com.x", perms=["android.permission.SEND_SMS"],
                        receivers=[("com.x.Boot", True)], native=["lib/arm64-v8a/libjiagu.so"])
    rep = build_report(fake)
    assert rep["package"] == "com.x"
    assert "android.permission.SEND_SMS" in rep["permissions"]["dangerous"]
    assert rep["packer"]["name"] == "jiagu"
```
(If importing the image script is awkward, place the pure `build_report` + the DANGEROUS-permission set in `src/reverse_engineering/tools/android/report.py`, import it from both the image script and the test — cleaner and keeps the pure logic in the tested tree. Prefer this.)
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** — put the pure report builder in `src/reverse_engineering/tools/android/report.py` (`build_report(view) -> dict`, `DANGEROUS_PERMISSIONS: frozenset`, delegates to `detect_packer`). `images/deobfuscation-tools/androguard_triage.py` imports it, does `_load_apk(sys.argv[1])` via `androguard.core.apk.APK` (or `androguard.misc.AnalyzeAPK`), adapts to the view, prints `json.dumps(build_report(view))`. Add `androguard==<pin a current 4.x>` to `requirements.in`; regenerate `requirements.lock` with `--require-hashes` (mirror the existing lock flow); `COPY androguard_triage.py /opt/androguard_triage.py` in the Dockerfile; add `androguard --version` (or `python -c "import androguard"`) to the healthcheck.
- [ ] **Step 4: Run tests** → `uv run pytest tests/reverse_engineering/test_androguard_triage_script.py -v` → PASS. (The androguard parse itself is exercised only in-cluster; note this.)
- [ ] **Step 5: Commit** — `git commit -am "feat(sandbox): androguard triage script + image dependency"`

---

### Task 3: `android_triage_scan` tool (staged, in-pod, fail-open)

**Files:** Create `src/reverse_engineering/tools/android/triage_scan.py`. Test: `tests/reverse_engineering/test_android_triage_scan.py`.

**Interfaces — Consumes:** `stage_artifact`/`run_argv`/`read_bounded_file` (`tools.deobfuscation.runtime`), `SAMPLE_FORMAT_KEY`, `JVM_FORMATS`. **Produces:** `ANDROID_TRIAGE_SCAN_TOOL: ToolDescriptor` (id `android_triage_scan`, deferred factory `build_android_triage_scan`).

- [ ] **Step 1: Write the failing tests** (monkeypatch `run_argv` to return an `ExecutionResult` with the script's JSON on stdout; a fake tool_context whose state carries `SAMPLE_FORMAT_KEY`):
```python
def test_scan_returns_structured_report_for_apk(monkeypatch, ...):
    # state format=apk; run_argv -> stdout = json of a report -> tool returns {"success":True, "report":{...}}
def test_scan_skips_a_native_sample(...):
    # state format="pe" -> {"success":False, "skipped":True, ...}, run_argv NOT called
def test_scan_fails_open_on_pod_error(monkeypatch, ...):
    # run_argv raises -> {"success":False,"error":...}, no raise
```
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** — mirror `build_de4dot_deobfuscate` (`tools/deobfuscation/dotnet.py`): `build_android_triage_scan(context: ToolBuildContext) -> ToolLike`; inner `android_triage_scan(artifact_id, tool_context)`: read `SAMPLE_FORMAT_KEY`; if not in `JVM_FORMATS` → `{"success":False,"skipped":True,"error":"android_triage_scan handles apk/dex/jar; got <format>"}` (no exec); else `staged = stage_artifact(context, artifact_id, tool_context, tool_name="android_triage_scan", max_input_bytes=...)`; `result = run_argv(staged, ["python", "/opt/androguard_triage.py", staged.input_path])`; parse `result.stdout` JSON → `{"success":True,"report":<parsed>}`; wrap in `try/except Exception` → `{"success":False,"error":str(exc)}`. `ANDROID_TRIAGE_SCAN_TOOL = ToolDescriptor(id="android_triage_scan", description=..., factory=build_android_triage_scan, output_policy=OutputPolicy(max_chars=8_000, max_list_items=40))`.
- [ ] **Step 4: Run tests** → PASS; `rtk make type-check`.
- [ ] **Step 5: Commit** — `git commit -am "feat(re): android_triage_scan tool (androguard in the deobf pod)"`

---

### Task 4: `android_triage` agent + prompt

**Files:** Create `src/reverse_engineering/agents/android_triage.py`, `src/reverse_engineering/prompts/android_triage.md`. Test: `tests/reverse_engineering/test_android_triage.py`.

**Interfaces — Consumes:** `ANDROID_TRIAGE_SCAN_TOOL`, `TRIAGE_EVIDENCE_KEY`, `evidence_output_callback`. **Produces:** `ANDROID_TRIAGE_DESCRIPTOR`.

- [ ] **Step 1: Write the failing tests** (mirror `triage_recon`'s contract):
```python
def test_descriptor_well_formed():
    d = ANDROID_TRIAGE_DESCRIPTOR
    assert d.id == d.name == "android_triage"
    assert d.runtime_profile_id == "re_guarded"
    assert d.tool_ids == ("android_triage_scan",)
    assert d.mcp_server_ids == () and d.output_key == "triage_evidence_json"
    assert d.output_schema is None

def test_prompt_covers_android_triage_signals():
    text = load_domain_prompt("android_triage").lower()
    for token in ("permission", "exported", "receiver", "packer", "native", "manifest"):
        assert token in text
    assert "android_triage_scan" in load_domain_prompt("android_triage")
    assert "transfer to" not in text
```
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** — the descriptor mirrors `triage_recon.py` (swap `mcp_server_ids=("radare2_mcp",)` for `tool_ids=("android_triage_scan",)`, same `output_key`/callback/profile). Write `android_triage.md`: call `android_triage_scan(artifact_id)` once, then emit evidence-backed FINDINGs for — dangerous permissions, exported components (attack surface), receivers indicating persistence (e.g. `BOOT_COMPLETED`), `debuggable`/cleartext, native libs, URL candidates, and a **packer** finding when `packer.detected` (name it; note the real DEX may need agentic recovery — Slice 2). Bounds (≤15 FINDINGs); FINDING schema (`artifact_id`,`claim`,`tool`,`confidence`,`detail`); no transfer language.
- [ ] **Step 4: Run tests** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(re): android_triage agent + prompt (androguard)"`

---

### Task 5: `triage_router` + wire into the pipeline

**Files:** Create `src/reverse_engineering/agents/triage_router.py`. Modify `src/malware_analyst/agents/malware_analyst.py` (`sub_agent_ids[1]`), `src/malware_analyst/composition.py` (register both agents), `tests/malware_analyst/test_malware_analyst_composition.py` (order test). Test: `tests/reverse_engineering/test_triage_router.py`.

**Interfaces — Consumes:** `build_format_router` (Slice 1a), `TRIAGE_RECON_DESCRIPTOR`, `ANDROID_TRIAGE_DESCRIPTOR`. **Produces:** `TRIAGE_ROUTER_DESCRIPTOR`.

- [ ] **Step 1: Write the failing tests:**
```python
def test_triage_router_routes_by_format():
    d = TRIAGE_ROUTER_DESCRIPTOR
    assert d.factory.__name__ == "build_format_router"
    assert set(d.sub_agent_ids) == {"triage_recon", "android_triage"}
    assert d.metadata["format_engines"]["apk"] == "android_triage"
    assert d.metadata["default_engine"] == "triage_recon"

def test_pipeline_uses_triage_router_at_position_two():
    from malware_analyst.agents.malware_analyst import MALWARE_ANALYST_DESCRIPTOR
    assert MALWARE_ANALYST_DESCRIPTOR.sub_agent_ids[1] == "triage_router"
    assert "triage_recon" not in MALWARE_ANALYST_DESCRIPTOR.sub_agent_ids  # now under the router
```
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** — `TRIAGE_ROUTER_DESCRIPTOR = AgentDescriptor(id="triage_router", name="triage_router", description="Route triage to radare2 (native/.NET) or androguard (Android/JVM) by container format.", prompt_id=None, factory=build_format_router, runtime_profile_id="safe_default", sub_agent_ids=("triage_recon","android_triage"), metadata={"format_engines":{"apk":"android_triage","dex":"android_triage","jar":"android_triage"},"default_engine":"triage_recon"})`. In `malware_analyst.py` replace `"triage_recon"` at index 1 with `"triage_router"`. In `malware_analyst/composition.py` add `builder.add_agent(ANDROID_TRIAGE_DESCRIPTOR)` and `builder.add_agent(TRIAGE_ROUTER_DESCRIPTOR)` (triage_recon stays registered — it's now the router's sub-agent). Update the order test's expected list (index 1 → `"triage_router"`).
- [ ] **Step 4: Run tests** → `uv run pytest tests/reverse_engineering/test_triage_router.py tests/malware_analyst/test_malware_analyst_composition.py -v` → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(re): triage_router routes triage by container format"`

---

### Task 6: Register tool + sanitizer + exports + end-to-end wiring

**Files:** Modify `src/reverse_engineering/composition.py` (register `ANDROID_TRIAGE_SCAN_TOOL`), `src/reverse_engineering/__init__.py` (exports), `src/reverse_engineering/profiles.py` (`_BINARY_ORIGIN_TOOLS`). Tests: extend `tests/.../test_re_guarded_profile.py`, `tests/malware_analyst/test_malware_analyst_composition.py`.

**Interfaces — Produces:** a frozen malware catalog where an `apk`/`dex`/`jar` sample routes to `android_triage`, whose scan output is sanitized.

- [ ] **Step 1: Write the failing tests:**
```python
def test_android_scan_is_sanitized_binary_origin():
    from reverse_engineering.profiles import _BINARY_ORIGIN_TOOLS
    assert "android_triage_scan" in _BINARY_ORIGIN_TOOLS

def test_composition_freezes_with_android_triage_reachable():
    from malware_analyst.composition import get_malware_analyst_composition
    root = get_malware_analyst_composition().root_agent
    router = next(a for a in root.sub_agents if a.name == "triage_router")
    assert {a.name for a in router.sub_agents} == {"triage_recon", "android_triage"}
    assert "android_triage_scan" in get_malware_analyst_composition().catalog.tools
```
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** — `composition.py` `register_re_infrastructure`: `builder.add_tool(ANDROID_TRIAGE_SCAN_TOOL)`. `__init__.py`: import + `__all__` add `ANDROID_TRIAGE_DESCRIPTOR`, `TRIAGE_ROUTER_DESCRIPTOR`. `profiles.py`: add `frozenset({ANDROID_TRIAGE_SCAN_TOOL.id})` (or the literal) into `_BINARY_ORIGIN_TOOLS`.
- [ ] **Step 4: Full gate** — `rtk make check` → exit 0 (freeze validates `triage_router` + `android_triage` reachable; sanitizer covers the scan; the updated order test + whole suite green).
- [ ] **Step 5: Commit** — `git commit -am "feat(re): register + wire androguard android_triage end-to-end"`

---

## Self-Review Notes

- **Spec coverage (§D):** androguard in the deobf pool (T2), the scan tool with the full triage-signal contract + packer detection (T1–T3), the `android_triage` agent (T4), the format-routed triage via `triage_router` reusing Slice 1a's `build_format_router` (T5), and sanitizer + end-to-end wiring (T6). Downstream Android-aware IOC/behavior/ATT&CK-Mobile prompts are Slice 1c.
- **Pattern fidelity:** the scan tool mirrors `de4dot` (`stage_artifact`/`run_argv`/`read_bounded_file`, self-gating, fail-open); `android_triage` mirrors `triage_recon` (no `output_schema`, `evidence_output_callback` stage="triage"); the `triage_router` reuses `build_format_router` verbatim — no new router code.
- **Isolation:** androguard parses the hostile APK **only in the sandbox pod** (T3 runs it via `run_argv`); the pure `packer_signatures`/`report` logic (T1–T2) carries no parsing and is fully unit-tested.
- **Type consistency:** `TRIAGE_EVIDENCE_KEY`/stage `"triage"` shared by `triage_recon` + `android_triage`; the scan output contract (T2 `build_report`) is what T3's tool returns and T4's agent consumes; `JVM_FORMATS` (Slice 1a) gates the scan and the router.
- **Confirm-during-impl (not placeholders):** the exact androguard version + regenerated hash-locked `requirements.lock` (T2); the androguard API surface for the `view` adapter (`APK.get_permissions/get_receivers/get_declared_permissions/...`) pinned against the pinned version; the deobf image is not built by `make check`, so T2's cluster-side parse is validated in-cluster, its pure logic by unit tests.
