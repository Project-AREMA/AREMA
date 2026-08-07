# Android Slice 1a — jadx Deep-Decompile Route (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An unpacked `apk` / `dex` / `jar` sample decompiles end-to-end through **jadx** — detected at intake, routed by a generalized `deep_engine_router`, decompiled in a sandboxed jadx pod, and written to the shared `deep_evidence_json` slot exactly like the native (Ghidra) and .NET (ILSpy) engines.

**Architecture:** jadx runs as a CLI over `kubectl exec` in its own WarmPool (mirroring `ghidra-rpc`, since both jadx MCP servers were rejected — GUI-bound / stdio-only). Re-implemented fresh against current main using GitHub PR #2 as the reference design (PR #2's base diverged too far to cherry-pick).

**Spec:** `docs/superpowers/specs/2026-07-31-android-dex-apk-analysis-design.md` (§B, §C, §G). Slice 1a is the deep-decompile route only; Slice 1b (androguard triage) and Slice 1c (`.so`→Ghidra fan-out + Android lenses) follow.

**Reference:** PR #2 (`gh pr diff 2 -- <file>`) is the port source. **Do not `git cherry-pick`** — port the code fresh, applying the adaptations below.

## Global Constraints (exact values — bind every task)

- **Formats:** `acquire_sample` returns `dex`, `apk`, `jar` (plus existing `dotnet`/`pe`/`elf`/`macho`/`unknown`). `SAMPLE_FORMAT_KEY = "sample:format"` (existing). DEX magic `b"dex\n"`; ZIP magic `b"PK\x03\x04"` → second-level sniff: an entry `AndroidManifest.xml` **or** `classes.dex` → `apk`; else `META-INF/MANIFEST.MF` or any `*.class` → `jar`; else `unknown`. **APK is tested before JAR** (APKs also carry `META-INF/MANIFEST.MF`).
- **jadx tool ids (exact):** `prepare_jadx`, `jadx_manifest`, `jadx_list_classes`, `jadx_class_source`, `jadx_search_sources`, `jadx_strings`, `jadx_list_resources`.
- **jadx decompile argv (exact):** `["jadx", "--no-imports", "-d", output_dir, sample_path]`, accepted exit codes `(0, 1)` (jadx exits 1 on partial decompile — still usable).
- **Class-name validation regex (verbatim):** `re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*\Z")`. A rejected name raises **before any argv is built** — no command runs.
- **Case-id resolution:** use main's `resolve_sandbox_case_id(tool_context)` from `arema.runtime.sessions` (raises `SandboxIdentityError`; derives `inv-<sha256[:32]>`). **Do NOT** port PR #2's `sandbox_cli.resolve_case_id`/`DEFAULT_CASE_KEY="re-mvp"` — it does not exist on main.
- **Router:** `deep_engine_router` generalizes from `{managed, native}` to a `format_engines: dict[str,str]` map + `default_engine`. `JVM_FORMATS = frozenset({"apk","dex","jar"})`. `MANAGED_FORMATS = frozenset({"dotnet"})` **stays exported** (2 external consumers: `scripted_recover.py`, `dotnet_scripted_recover.py`). Route: `{dotnet→dotnet_decompile, apk|dex|jar→java_decompile}`, default `deep_analysis`.
- **Shared output slot:** `java_decompile` writes `output_key=DEEP_EVIDENCE_KEY` (`"deep_evidence_json"`, from `tools.ghidra.coverage`) via `evidence_output_callback(output_key=DEEP_EVIDENCE_KEY, stage="deep")` — engine-agnostic downstream.
- **Profile:** `java_decompile` uses `runtime_profile_id="re_guarded"`; its tool outputs join `_BINARY_ORIGIN_TOOLS` (attacker-authored text).
- **Sandbox:** new pool `jadx` → `jadx-pool`; image `arema-jadx:0.1.0` (base `eclipse-temurin:21-jre`, jadx `1.5.1`); template mirrors the **deobfuscation-tools** template (exec readiness probe, deny-all egress, nonroot uid 1000, **no port**), with JVM-sized memory (limit `4Gi`, exceeds `-Xmx3g`). **Do not** apply PR #2's `.env.example` wholesale — add only `"jadx":"jadx-pool"` to the existing pool map.
- **ADK rules:** no bare `typing.Any` param annotations; no `isinstance(state, dict)` on ADK `State`; `src/arema` stays domain-neutral; fail-open tools.
- **Commits:** plain `git commit` (local `commit.gpgsign=false`). Use the `rtk` prefix on git/make. `uv run pytest` for tests (`rtk pytest` resolves to a system Python without the venv). `make check` green at every task.

---

## File Structure

**Create:**
- `src/reverse_engineering/tools/jadx/__init__.py`, `commands.py`, `toolset.py`, `prepare_jadx.py`
- `src/reverse_engineering/agents/java_decompile.py`
- `src/reverse_engineering/prompts/java_decompile.md`
- `images/jadx/Dockerfile`
- `deploy/sandbox/10-jadx-template.yaml`, `deploy/sandbox/20-jadx-pool.yaml`
- `tests/reverse_engineering/test_jadx_toolset.py`, `test_java_decompile.py`, `tests/unit/test_jadx_manifest.py`

**Modify:**
- `src/reverse_engineering/runtime/portforward.py` — add `ok_exit_codes` to `kubectl_exec`
- `src/reverse_engineering/tools/acquire_sample.py` — dex/apk/jar detection
- `src/reverse_engineering/agents/format_router.py` — generalize the router
- `src/reverse_engineering/composition.py` — register jadx tools in `register_re_infrastructure`
- `src/reverse_engineering/__init__.py` — export `JAVA_DECOMPILE_DESCRIPTOR`
- `src/reverse_engineering/profiles.py` — add jadx tools to `_BINARY_ORIGIN_TOOLS`
- `src/malware_analyst/composition.py` — `builder.add_agent(JAVA_DECOMPILE_DESCRIPTOR)`
- `Makefile`, `.env.example` — jadx pool
- `tests/reverse_engineering/test_acquire_sample.py`, `tests/.../test_re_guarded_profile.py`, `tests/malware_analyst/test_malware_analyst_composition.py` — extend

Execution order T1→T9.

---

### Task 1: `kubectl_exec` gains `ok_exit_codes`

The enabling change: jadx exits `1` on partial decompile and `grep` exits `1` on no-match; main's `kubectl_exec` raises on any nonzero.

**Files:** Modify `src/reverse_engineering/runtime/portforward.py` (`kubectl_exec`, ~line 180). Test: `tests/reverse_engineering/test_portforward.py` (extend or create).

**Interfaces — Produces:** `kubectl_exec(args, namespace, pod, *, timeout=300, ok_exit_codes=(0,))` — nonzero exits NOT in `ok_exit_codes` still raise `RuntimeError`.

- [ ] **Step 1: Write the failing test**
```python
def test_kubectl_exec_accepts_declared_nonzero_exit(monkeypatch):
    import subprocess
    from reverse_engineering.runtime import portforward
    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, returncode=1, stdout=b"partial", stderr=b"")
    monkeypatch.setattr(portforward.subprocess, "run", fake_run)
    # exit 1 tolerated when declared:
    assert portforward.kubectl_exec(["jadx"], "ns", "pod", ok_exit_codes=(0, 1)) == "partial"

def test_kubectl_exec_still_raises_on_undeclared_nonzero(monkeypatch):
    import subprocess
    from reverse_engineering.runtime import portforward
    monkeypatch.setattr(portforward.subprocess, "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 2, b"", b"boom"))
    with pytest.raises(RuntimeError):
        portforward.kubectl_exec(["x"], "ns", "pod")  # default ok_exit_codes=(0,)
```
- [ ] **Step 2: Run to verify it fails** — `uv run pytest tests/reverse_engineering/test_portforward.py -v` → FAIL (unexpected `ok_exit_codes` kwarg).
- [ ] **Step 3: Implement** — add the parameter and change the guard:
```python
def kubectl_exec(args, namespace, pod, *, timeout=300, ok_exit_codes=(0,)):
    # ... build ["kubectl","exec",f"pod/{pod}","-n",namespace,"--",*args], run check=False ...
    if result.returncode not in ok_exit_codes:
        raise RuntimeError(f"kubectl exec failed ({result.returncode}): {result.stderr.decode(errors='replace')}")
    return result.stdout.decode(errors="replace")
```
Keep the existing `TimeoutExpired` handling. Confirm no existing caller breaks (default `(0,)` preserves behavior).
- [ ] **Step 4: Run tests** — `uv run pytest tests/reverse_engineering/test_portforward.py -v` → PASS.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(re): kubectl_exec accepts declared non-zero exit codes"`

---

### Task 2: `acquire_sample` detects `dex` / `apk` / `jar`

**Files:** Modify `src/reverse_engineering/tools/acquire_sample.py` (`detect_format_bytes` ~49-93; `_detect_format` except tuple ~105; `ACQUIRE_SAMPLE_TOOL` description ~142). Test: `tests/reverse_engineering/test_acquire_sample.py`.

**Interfaces — Produces:** `detect_format_bytes` additionally returns `"dex"`, `"apk"`, `"jar"`; a `_sniff_zip(data: bytes) -> str` helper.

- [ ] **Step 1: Write the failing tests** (port PR #2's exact assertions):
```python
def test_detect_format_reads_a_dex_by_magic():
    assert detect_format_bytes(b"dex\n035\x00" + bytes(64)) == "dex"

def test_apk_wins_over_jar_despite_carrying_a_java_manifest():
    data = _zip_bytes([("AndroidManifest.xml", b"x"), ("classes.dex", b"y"),
                       ("META-INF/MANIFEST.MF", b"z")])
    assert detect_format_bytes(data) == "apk"

def test_detect_format_reads_an_ordinary_java_archive_as_jar():
    data = _zip_bytes([("META-INF/MANIFEST.MF", b"m"), ("org/x/Thing.class", b"c")])
    assert detect_format_bytes(data) == "jar"

def test_a_zip_without_java_or_android_markers_stays_unknown():
    data = _zip_bytes([("lib/net6.0/Thing.dll", b"d"), ("[Content_Types].xml", b"x")])
    assert detect_format_bytes(data) == "unknown"   # a .nupkg must not go to jadx

def test_detect_format_survives_a_corrupt_zip():
    assert detect_format_bytes(b"PK\x03\x04" + bytes(32)) == "unknown"   # no raise
```
Add a `_zip_bytes(entries)` helper (`io.BytesIO` + `zipfile.ZipFile(..., "w")`).
- [ ] **Step 2: Run to verify they fail** — `uv run pytest tests/reverse_engineering/test_acquire_sample.py -k "dex or apk or jar or corrupt_zip or nupkg" -v` → FAIL.
- [ ] **Step 3: Implement** — in `detect_format_bytes`, **after the Mach-O check, before the `if magic[:2] != b"MZ"` gate**, add:
```python
if magic[:4] == b"dex\n":
    return "dex"
if magic[:4] == b"PK\x03\x04":
    return _sniff_zip(data)
```
Add the helper (note the marker order — Android first):
```python
_ANDROID_ZIP_MARKERS = ("AndroidManifest.xml", "classes.dex")

def _sniff_zip(data: bytes) -> str:
    """Classify a ZIP container as ``apk`` (Android markers), ``jar`` (JVM
    markers), or ``unknown``. Never raises: a bad archive is ``unknown``."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
    except (OSError, zipfile.BadZipFile):
        return "unknown"
    entries = set(names)
    if any(marker in entries for marker in _ANDROID_ZIP_MARKERS):
        return "apk"
    if "META-INF/MANIFEST.MF" in entries or any(n.endswith(".class") for n in names):
        return "jar"
    return "unknown"
```
Add `import io`, `import zipfile`. Ensure `_detect_format`'s except tuple tolerates `zipfile.BadZipFile` (it is an `OSError` subclass, so the existing `(OSError, struct.error)` already covers it — verify). Update the `ACQUIRE_SAMPLE_TOOL` description string to list the new formats.
- [ ] **Step 4: Run tests** — `uv run pytest tests/reverse_engineering/test_acquire_sample.py -v` → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(re): acquire_sample detects dex/apk/jar (apk before jar)"`

---

### Task 3: jadx CLI command table + class-name security validation

**Files:** Create `src/reverse_engineering/tools/jadx/__init__.py` (empty), `commands.py`. Test: `tests/reverse_engineering/test_jadx_toolset.py` (the argv + security tests; the toolset wrapper lands in T4).

**Interfaces — Produces:** `JADX_COMMANDS: tuple[JadxCommandSpec, ...]` (the 6 read commands); `_CLASS_NAME_RE`, `InvalidClassNameError`, `_source_path_for(case_state, class_name)`. (Placed in `commands.py` or a small `security.py`; T4 imports them into the toolset.)

- [ ] **Step 1: Write the failing security + argv tests** — port PR #2's exact cases:
```python
_HOSTILE = ["../../../../etc/passwd", "com.example/../../../etc/shadow", "/etc/passwd",
            "com.example.App; cat /etc/passwd", "com.example.App\n/etc/passwd", "", "   "]

@pytest.mark.parametrize("bad", _HOSTILE)
def test_class_name_rejected_before_any_command(bad):
    from reverse_engineering.tools.jadx.commands import _source_path_for, InvalidClassNameError
    with pytest.raises(InvalidClassNameError):
        _source_path_for({"out": "/tmp/jadx_x"}, bad)

def test_class_name_maps_to_source_path():
    from reverse_engineering.tools.jadx.commands import _source_path_for
    assert _source_path_for({"out": "/tmp/jadx_x"}, "com.example.app.Main") == \
        "/tmp/jadx_x/sources/com/example/app/Main.java"

def test_nested_class_resolves_to_outer_file():
    from reverse_engineering.tools.jadx.commands import _source_path_for
    assert _source_path_for({"out": "/tmp/jadx_x"}, "com.x.Outer$Inner") == \
        "/tmp/jadx_x/sources/com/x/Outer.java"

def test_search_pattern_is_a_single_argv_token():
    spec = {s.name: s for s in JADX_COMMANDS}["jadx_search_sources"]
    argv = list(spec.build_argv({"out": "/tmp/jadx_x"}, {"pattern": "foo; rm -rf /"}))
    assert "foo; rm -rf /" in argv and argv[0] == "grep"

def test_only_manifest_and_strings_are_android_only():
    assert {s.name for s in JADX_COMMANDS if s.android_only} == {"jadx_manifest", "jadx_strings"}
```
- [ ] **Step 2: Run to verify fail** — module doesn't exist yet → FAIL.
- [ ] **Step 3: Implement** `commands.py` — the spec dataclass, the validation, and the 6 commands (argv from the reference, verbatim):
```python
_CLASS_NAME_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*\Z")
_GREP_OK = (0, 1)

class InvalidClassNameError(ValueError): ...

def _source_path_for(case_state, class_name):
    candidate = class_name.strip()
    if not _CLASS_NAME_RE.match(candidate):
        raise InvalidClassNameError(
            f"'{class_name}' is not a fully-qualified Java class name "
            "(expected e.g. com.example.app.MainActivity)")
    relative = candidate.replace(".", "/").split("$", 1)[0]
    return f"{case_state['out']}/sources/{relative}.java"

def _sources(cs): return f"{cs['out']}/sources"
def _resources(cs): return f"{cs['out']}/resources"
```
`JadxCommandSpec` (`frozen=True, slots=True`): `name, description, params: tuple[str,...], build_argv, output_policy, ok_exit_codes=(0,), android_only=False`. Build the 6 specs with the exact argv from the Global Constraints table (`jadx_manifest` → `["cat", f"{out}/resources/AndroidManifest.xml"]` android_only; `jadx_list_classes` → `find` + optional `-path *pkg*`; `jadx_class_source` → `["cat", kw["_source_path"]]`; `jadx_search_sources` → `["grep","-rnE","--include=*.java","-m","5","--", kw["pattern"], _sources(cs)]` ok `(0,1)`; `jadx_strings` → `cat .../res/values/strings.xml` android_only; `jadx_list_resources` → `find _resources`).
- [ ] **Step 4: Run tests** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(re): jadx command table + class-name security validation"`

---

### Task 4: jadx toolset (kubectl-exec, mirroring ghidra)

**Files:** Create `src/reverse_engineering/tools/jadx/toolset.py`. Test: extend `tests/reverse_engineering/test_jadx_toolset.py`.

**Interfaces — Consumes:** `JADX_COMMANDS`, `_source_path_for` (T3); `kubectl_exec` (T1); `resolve_sandbox_case_id` (main). **Produces:** `_JADX_CASE_STATE: dict[str, dict[str, str]]`; `build_jadx_toolset() -> tuple[ToolDescriptor, ...]`; `build_jadx_tool(context, spec)`.

- [ ] **Step 1: Write the failing tests** (seed `_JADX_CASE_STATE`, monkeypatch `kubectl_exec` to capture argv):
```python
@pytest.fixture
def seeded(monkeypatch):
    from reverse_engineering.tools.jadx import toolset
    toolset._JADX_CASE_STATE["c"] = {"pod":"jadx-1","out":"/tmp/jadx_x","namespace":"ns","format":"apk"}
    calls = {}
    monkeypatch.setattr(toolset, "kubectl_exec",
        lambda argv, ns, pod, **kw: calls.setdefault("argv", argv) or "out")
    yield toolset, calls
    toolset._JADX_CASE_STATE.clear()

def test_manifest_reads_decoded_manifest(seeded): ...     # argv == ["cat", "/tmp/jadx_x/resources/AndroidManifest.xml"]
def test_hostile_class_name_runs_no_command(seeded): ...   # success False, "fully-qualified" in error, kubectl_exec NOT called
def test_android_only_explains_itself_on_a_jar(seeded): ...# format "jar" + kubectl_exec raises -> error mentions "jar" + "Android resources"
def test_not_prepared_reports_cleanly(): ...               # empty case state -> success False, "not prepared"
def test_empty_output_is_degraded(seeded): ...             # stdout "  \n" -> success False, degraded True
def test_descriptor_ids_match_command_names(): ...         # {d.id for d in build_jadx_toolset()} == {s.name for s in JADX_COMMANDS}
```
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** `toolset.py` — copy the ghidra `build_ghidra_tool` shape (`src/reverse_engineering/tools/ghidra/toolset.py`), substituting: case state `_JADX_CASE_STATE`; case id via `resolve_sandbox_case_id(tool_context)` wrapped in try/except `SandboxIdentityError` → degraded dict; for a spec with `class_name` in params, call `_source_path_for` first and on `InvalidClassNameError` return `{"success":False,"error":str(exc),"tool":spec.name}` **without building argv or calling exec**; build argv via `spec.build_argv`; `kubectl_exec(argv, namespace, case_state["pod"], ok_exit_codes=spec.ok_exit_codes)`; on exception, if `spec.android_only and case_state.get("format") != "apk"` return the "reads Android resources, which a {format} sample does not carry" message; empty stdout → `{"success":False,"degraded":True,...}`. Reuse ghidra's `inspect.Signature` synthesis so ADK sees `tool_context` + one `str` param per `spec.params` (or extract that helper — your call; keep behavior identical). `build_jadx_toolset()` returns one deferred-factory `ToolDescriptor(id=spec.name, factory=lambda ctx, s=spec: build_jadx_tool(ctx, s), output_policy=spec.output_policy)` per spec.
- [ ] **Step 4: Run tests** → PASS; `rtk make type-check`.
- [ ] **Step 5: Commit** — `git commit -am "feat(re): jadx CLI toolset over kubectl exec"`

---

### Task 5: `prepare_jadx` — claim pod, copy sample, decompile once

**Files:** Create `src/reverse_engineering/tools/jadx/prepare_jadx.py`. Test: extend `tests/reverse_engineering/test_jadx_toolset.py` (or a `test_prepare_jadx.py`).

**Interfaces — Consumes:** the sandbox executor (`context.services.sandbox`), `kubectl_cp`, `_JADX_CASE_STATE`, `ArtifactStore`/`default_artifacts_root`, `resolve_sandbox_case_id`. **Produces:** `PREPARE_JADX_TOOL: ToolDescriptor` (id `prepare_jadx`, deferred factory); `release_jadx_case`.

- [ ] **Step 1: Write the failing test** — a fake executor whose `claim` returns a handle with `backend_id="jadx-1"`; monkeypatch `kubectl_cp` and `kubectl_exec` (the `find` class count returns 3 lines); assert the returned dict is `{"pod":"jadx-1","output_dir":"/tmp/jadx_<id>","classes":3,"ready":True}` and that `_JADX_CASE_STATE[case]` was seeded with `pod`/`out`/`namespace`/`format`. Add a fail-open test: executor `None` → `{"ready":False,"error":...}`; and jadx producing 0 classes → `{"ready":False,"error":"jadx produced no decompiled sources"}`.
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** — mirror `prepare_ghidra.py` (claim `pool="jadx"`) but with jadx's one-shot decompile (no daemon):
```python
def prepare_jadx(artifact_id: str, sample_format: str, tool_context: ToolContext) -> dict[str, object]:
    try:
        case_id = resolve_sandbox_case_id(tool_context)
        executor = _executor  # closed over from build_prepare_jadx(context.services.sandbox)
        if executor is None:
            return {"pod":"","output_dir":"","ready":False,"error":"sandbox executor is not configured"}
        handle = executor.claim(key=case_id, pool="jadx"); pod = handle.backend_id
        output_dir = f"/tmp/jadx_{artifact_id}"
        local = ArtifactStore(default_artifacts_root()).path_for(artifact_id)
        sample_path = f"/app/{artifact_id}"
        kubectl_cp(str(local), namespace, pod, sample_path)
        kubectl_exec(["jadx","--no-imports","-d",output_dir,sample_path], namespace, pod,
                     timeout=900, ok_exit_codes=(0,1))
        listing = kubectl_exec(["find",f"{output_dir}/sources","-type","f","-name","*.java"], namespace, pod)
        classes = len([ln for ln in listing.splitlines() if ln.strip()])
        if classes == 0:
            return {"pod":pod,"output_dir":output_dir,"ready":False,"error":"jadx produced no decompiled sources"}
        _JADX_CASE_STATE[case_id] = {"pod":pod,"out":output_dir,"namespace":namespace,"format":sample_format}
        return {"pod":pod,"output_dir":output_dir,"classes":classes,"ready":True}
    except Exception as exc:
        logger.warning("prepare_jadx failed", error_type=type(exc).__name__)
        return {"pod":locals().get("pod",""),"output_dir":"","ready":False,"error":str(exc)}
```
Wire `release_jadx_case(case_id)` (retry `executor.release_session` 3× on `OSError`, fall back to `_kubectl_delete_claims`) + `atexit.register`. `PREPARE_JADX_TOOL = ToolDescriptor(id="prepare_jadx", factory=build_prepare_jadx, output_policy=OutputPolicy(max_chars=2_000, max_list_items=10))`.
- [ ] **Step 4: Run tests** → PASS; `rtk make type-check`.
- [ ] **Step 5: Commit** — `git commit -am "feat(re): prepare_jadx one-shot decompile in a sandboxed pod"`

---

### Task 6: jadx sandbox image + template + pool + Makefile/env

**Files:** Create `images/jadx/Dockerfile`, `deploy/sandbox/10-jadx-template.yaml`, `deploy/sandbox/20-jadx-pool.yaml`; modify `Makefile`, `.env.example`. Test: create `tests/unit/test_jadx_manifest.py`.

**Interfaces — Produces:** the `jadx` pool wired into the pool map and Makefile.

- [ ] **Step 1: Write the failing structural test** (YAML-parse the manifests; no cluster) — port PR #2's `test_jadx_manifest.py` assertions:
```python
EXPECTED_IMAGE = "arema-jadx:0.1.0"
def test_pool_label(): ...          # template podTemplate labels["arema.dev/pool"] == "jadx"
def test_image_and_no_ports(): ...  # container image == EXPECTED_IMAGE; "ports" not in container
def test_exec_readiness_probe(): ...# readinessProbe.exec.command[0] == "jadx"; no httpGet/tcpSocket
def test_memory_limit_clears_heap(): ... # limits["memory"] == "4Gi"
def test_nonroot(): ...             # runAsNonRoot True, runAsUser 1000, caps drop ALL, automount False
def test_pool_ref_matches_template(): ... # 20-jadx-pool sandboxTemplateRef.name == template metadata.name
def test_pool_label_matches_makefile_wait_selector(): ... # Makefile `kubectl wait ... -l arema.dev/pool=jadx`
```
- [ ] **Step 2: Run to verify fail** → FAIL (files absent).
- [ ] **Step 3: Implement** — `images/jadx/Dockerfile` (`FROM eclipse-temurin:21-jre`; `ARG JADX_VERSION=1.5.1`; checksum-pinned download of `jadx-1.5.1.zip`, unzip to `/opt/jadx`, symlink `/usr/local/bin/jadx`; `ENV JAVA_OPTS="-Xmx3g"`; apt `ca-certificates wget unzip tar findutils grep`; nonroot uid/gid 1000; `WORKDIR /app`; `CMD ["sleep","infinity"]`). Copy `deploy/sandbox/10-deobfuscation-tools-template.yaml` → `10-jadx-template.yaml` (deny-all egress, exec readiness probe `["jadx","--version"]`, nonroot uid 1000) with `metadata.name: jadx-runtime-template`, pool label `jadx`, image `arema-jadx:0.1.0`, memory `requests 1Gi / limits 4Gi`, **no ports**. `20-jadx-pool.yaml` mirrors `20-deobfuscation-tools-pool.yaml` (`metadata.name: jadx-pool`, `replicas: 1`, `sandboxTemplateRef.name: jadx-runtime-template`). Makefile: add the `docker build`/`kind load` lines to `sandbox-build-images`, the two `kubectl apply` + a `kubectl wait -l arema.dev/pool=jadx` to `sandbox-up`, the two `kubectl delete` to `sandbox-down`, and bump the "five pools" comment to six. `.env.example`: append `,"jadx":"jadx-pool"` to the existing `AREMA_SANDBOX_POOL_MAP` (do **not** replace the map).
- [ ] **Step 4: Run tests** → `uv run pytest tests/unit/test_jadx_manifest.py -v` → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(sandbox): jadx engine image, template, WarmPool, wiring"`

---

### Task 7: `java_decompile` agent + prompt

**Files:** Create `src/reverse_engineering/agents/java_decompile.py`, `src/reverse_engineering/prompts/java_decompile.md`. Test: create `tests/reverse_engineering/test_java_decompile.py`.

**Interfaces — Consumes:** the jadx tools (T3-T5), `DEEP_EVIDENCE_KEY`, `evidence_output_callback`, `build_llm_agent`, `load_domain_prompt`. **Produces:** `JAVA_DECOMPILE_DESCRIPTOR`.

- [ ] **Step 1: Write the failing tests** (port PR #2's `test_java_decompile.py`):
```python
def test_descriptor_well_formed():
    d = JAVA_DECOMPILE_DESCRIPTOR
    assert d.id == d.name == "java_decompile"
    assert d.runtime_profile_id == "re_guarded"
    assert d.sub_agent_ids == () and d.mcp_server_ids == ()
    assert d.output_key == "deep_evidence_json"

def test_agent_holds_prepare_jadx_first_then_every_jadx_tool():
    ids = JAVA_DECOMPILE_DESCRIPTOR.tool_ids
    assert ids[0] == "prepare_jadx"
    assert set(ids) == {"prepare_jadx","jadx_manifest","jadx_list_classes",
        "jadx_class_source","jadx_search_sources","jadx_strings","jadx_list_resources"}

def test_prompt_gates_on_format_and_prepares_first():
    text = load_domain_prompt("java_decompile").lower()
    assert "format gate" in text and all(f in text for f in ("apk","dex","jar"))
    assert "prepare_jadx(artifact_id, sample_format)" in load_domain_prompt("java_decompile")
    assert "no unpacking step" in text and "directly" in text
    assert "transfer to" not in text
```
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** — the descriptor (mirror `dotnet_decompile.py`, swapping the MCP server for the jadx `tool_ids`, `prepare_jadx` at index 0):
```python
JAVA_DECOMPILE_DESCRIPTOR = AgentDescriptor(
    id="java_decompile", name="java_decompile",
    description="Java/Android decompilation engine driving jadx over the sandbox CLI.",
    prompt_id="java_decompile", factory=build_llm_agent, runtime_profile_id="re_guarded",
    prompt_loader=load_domain_prompt,
    tool_ids=("prepare_jadx","jadx_manifest","jadx_list_classes","jadx_class_source",
              "jadx_search_sources","jadx_strings","jadx_list_resources"),
    output_key=DEEP_EVIDENCE_KEY,
    after_agent_callbacks=(evidence_output_callback(output_key=DEEP_EVIDENCE_KEY, stage="deep"),),
)
```
Write `java_decompile.md` per PR #2 §7: format gate first (skip with one cited FINDING if format ∉ {apk,dex,jar}); `prepare_jadx(artifact_id, sample_format)` before any other tool; "jadx opens .apk/.dex/.jar directly; there is no unpacking step"; tool guidance (manifest first on APK; `jadx_search_sources` is the power tool for URLs / `Runtime.exec` / reflection / `DexClassLoader` / crypto / SMS / accessibility); bounds ≤5 classes read, ≤15 FINDINGs; FINDING schema (`artifact_id`, `claim`, `tool`, `confidence`, `detail`); no transfer language.
- [ ] **Step 4: Run tests** → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(re): java_decompile agent + prompt (jadx engine)"`

---

### Task 8: Generalize `deep_engine_router` to a format→engine map

**Files:** Modify `src/reverse_engineering/agents/format_router.py`. Test: extend `tests/reverse_engineering/` router tests (or create `test_format_router.py`).

**Interfaces — Consumes:** `java_decompile`. **Produces:** `_FormatRouter` keyed on `format_engines: dict[str,str]` + `default_engine`; `JVM_FORMATS`; `MANAGED_FORMATS` (unchanged, still exported).

- [ ] **Step 1: Write the failing tests** — build the router with three stub sub-agents and assert routing:
```python
def test_router_sends_dotnet_to_ilspy_jvm_to_jadx_native_to_ghidra():
    # seed state SAMPLE_FORMAT_KEY and assert which sub-agent runs, for
    # "dotnet"->dotnet_decompile, "apk"/"dex"/"jar"->java_decompile,
    # "pe"/"elf"/"unknown"->deep_analysis (default)

def test_descriptor_routes_all_three_engines():
    d = DEEP_ENGINE_ROUTER_DESCRIPTOR
    assert set(d.sub_agent_ids) == {"deep_analysis","dotnet_decompile","java_decompile"}
    assert d.metadata["format_engines"]["apk"] == "java_decompile"
    assert d.metadata["default_engine"] == "deep_analysis"

def test_managed_formats_still_exported():
    from reverse_engineering.agents.format_router import MANAGED_FORMATS
    assert MANAGED_FORMATS == frozenset({"dotnet"})
```
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** — replace the two-field `_FormatRouter` with a mapping form (keep `aclosing`); read `metadata["format_engines"]`/`metadata["default_engine"]` in `build_format_router`, validate every engine name resolves in `context.sub_agents`; update the descriptor to `sub_agent_ids=("deep_analysis","dotnet_decompile","java_decompile")` and `metadata={"format_engines":{"dotnet":"dotnet_decompile","apk":"java_decompile","dex":"java_decompile","jar":"java_decompile"},"default_engine":"deep_analysis"}`. Keep `JVM_FORMATS`/`MANAGED_FORMATS` module-level (the latter still imported by `scripted_recover`/`dotnet_scripted_recover`).
- [ ] **Step 4: Run tests** — router tests + `uv run pytest tests/reverse_engineering/ -k "scripted_recover"` (confirm `MANAGED_FORMATS` consumers unbroken) → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(re): generalize deep_engine_router to a format->engine map + jadx route"`

---

### Task 9: Register + wire the jadx engine end-to-end

**Files:** Modify `src/reverse_engineering/composition.py` (register tools in `register_re_infrastructure`), `src/reverse_engineering/__init__.py` (export `JAVA_DECOMPILE_DESCRIPTOR`), `src/reverse_engineering/profiles.py` (`_BINARY_ORIGIN_TOOLS`), `src/malware_analyst/composition.py` (`add_agent`). Tests: extend `tests/.../test_re_guarded_profile.py`, `tests/malware_analyst/test_malware_analyst_composition.py`.

**Interfaces — Consumes:** all prior tasks. **Produces:** a frozen malware catalog where an `apk`/`dex`/`jar` sample routes to `java_decompile`.

- [ ] **Step 1: Write the failing wiring tests:**
```python
def test_jadx_tools_are_sanitized_binary_origin():
    from reverse_engineering.profiles import _BINARY_ORIGIN_TOOLS
    for name in ("jadx_manifest","jadx_class_source","jadx_search_sources"):
        assert name in _BINARY_ORIGIN_TOOLS

def test_composition_freezes_with_java_decompile_reachable():
    from malware_analyst.composition import get_malware_analyst_composition
    catalog = get_malware_analyst_composition().catalog
    assert "java_decompile" in catalog.agents
    router = next(a for a in get_malware_analyst_composition().root_agent.sub_agents
                  if a.name == "deep_engine_router")
    assert "java_decompile" in {a.name for a in router.sub_agents}
```
- [ ] **Step 2: Run to verify fail** → FAIL.
- [ ] **Step 3: Implement** the wiring:
  - `composition.py` `register_re_infrastructure`: `builder.add_tool(PREPARE_JADX_TOOL)` and `for d in build_jadx_toolset(): builder.add_tool(d)` (near the ghidra toolset loop).
  - `__init__.py`: import + `__all__` add `JAVA_DECOMPILE_DESCRIPTOR`.
  - `profiles.py`: `_JADX_BINARY_TOOLS = frozenset(spec.name for spec in JADX_COMMANDS)` and OR it into `_BINARY_ORIGIN_TOOLS` (line ~36).
  - `malware_analyst/composition.py`: import `JAVA_DECOMPILE_DESCRIPTOR`; `builder.add_agent(JAVA_DECOMPILE_DESCRIPTOR)` next to `DOTNET_DECOMPILE_DESCRIPTOR`.
- [ ] **Step 4: Full gate** — `rtk make check` → exit 0 (freeze validates `java_decompile` reachable via `deep_engine_router`; sanitizer covers jadx; whole suite incl. the composition-order test green).
- [ ] **Step 5: Commit** — `git commit -am "feat(re): register + wire the jadx java_decompile engine end-to-end"`

---

## Self-Review Notes

- **Spec coverage (Slice 1a):** intake formats (T2), jadx engine (T3–T5), sandbox pool (T6), engine agent (T7), generalized router (T8), wiring + neutrality + sanitizer (T9), with the enabling `ok_exit_codes` (T1). Slice 1b (androguard triage) and 1c (`.so`→Ghidra + Android lenses) are separate plans.
- **Port fidelity:** every ported artifact (formats, class-name regex, argv, hostile inputs, manifest structure) uses PR #2's exact values; the four documented adaptations (main's `kubectl_exec ok_exit_codes`, `resolve_sandbox_case_id` not `re-mvp`, the code-router not self-gating, additive `.env.example`) are applied in T1/T4/T5/T8/T6.
- **Type consistency:** `_JADX_CASE_STATE` shape `{pod,out,namespace,format}` is written by `prepare_jadx` (T5) and read by the toolset (T4); `format_engines` map (T8) references `java_decompile` (T7); `DEEP_EVIDENCE_KEY`/`stage="deep"` keeps the engine-agnostic slot.
- **Confirm-during-impl:** the exact jadx `1.5.1` release URL + sha256 (T6 Dockerfile); whether ghidra's signature-synthesis helper is extracted or duplicated (T4) — either is acceptable if behavior matches.
