# Tool & engine usage: when and where

This document is the single reference for which analysis engine AREMA uses,
for what, and when. It exists to make the architecture *repeatable and
extensible*: adding a new sample technology (or a new tool) becomes "fill a cell
in the matrix", not "invent a new path".

> Status: living reference (first drafted 2026-07-29 while adding the .NET
> companion). Update it whenever an engine, stage, or technology is added.

## 1. The six engines at a glance

| Engine (pool) | Execution model | Reached via | What it is |
|---|---|---|---|
| **radare2-mcp** | Long-running MCP service, read-only, kubectl port-forward | `mcp_server_ids=("radare2_mcp",)` | Fast **triage/recon** of a native PE/ELF/Mach-O: entry point, sections, imports, strings, function list. Structurally cannot patch/emulate (read-only). |
| **ghidra-rpc** | Heavy RPC engine (own deadline) | `prepare_ghidra` + the ghidra toolset | **Native deep decompilation**: machine code → pseudo-C. |
| **ilspy-mcp** | MCP service (ICSharpCode.Decompiler), port-forward | `prepare_ilspy` + `mcp_server_ids=("ilspy_mcp",)` | **Managed deep decompilation**: .NET/CIL metadata → C#. |
| **jadx** | Exec-driven sandbox CLI toolset (`kubectl exec`), like ghidra; **no network service** | `prepare_jadx` + the jadx toolset | **Android/JVM deep decompilation**: DEX/APK bytecode → Java. |
| **deobfuscation-tools** | Exec-driven sandbox (`kubectl exec`, `stage_artifact`/`run_argv`); **no network service** | the deterministic recovery tools (`upx_unpack`, `floss_decode`, `de4dot_deobfuscate`) + `android_triage_scan` (androguard) | **Deterministic recovery**: fixed CLI tools that undo a *known* packing/obfuscation in one shot (UPX, FLOSS, de4dot). Cheap, no reasoning. Also hosts **androguard** (`/opt/androguard_triage.py`) for **Android triage**. |
| **analysis-workbench** | Exec-driven Python-scripting sandbox (`run_python`), persistent per-case workspace | the `packer_analyst` / `dotnet_analyst` agents (`run_python` + `register_unpacked_artifact`; `packer_analyst` also attaches `radare2_mcp` for triage), plus the deterministic `dnlib_roundtrip` tool | **Agentic recovery** (and one deterministic .NET step): an open Python + radare2/r2pipe + dnlib + crypto/parse-lib workbench where an LLM *reasons* about an *unknown/custom* packer and reimplements the unpacking. Also hosts the no-model `dnlib_roundtrip` metadata repair for .NET. Expensive, bounded by a budget. |

These six engines serve three functional roles, and each role is realized
once per sample technology.

| Role | What it answers | Native engine | Managed (.NET) engine | Android (DEX/APK) engine |
|---|---|---|---|---|
| **Triage** | "What is this and how is it protected?" | radare2-mcp | radare2-mcp (PE wrapper only; CIL is skipped) | **android_triage**: androguard in the deobfuscation-tools pod (radare2 sees only the ZIP shell; Dalvik is skipped) |
| **Recovery: deterministic** | "Undo a *known* protection in one shot" | deobfuscation-tools: `upx`, `floss` | deobfuscation-tools: `de4dot`; analysis-workbench: `dnlib_roundtrip` (metadata repair when de4dot fails/crashes) | **(none; jadx opens APK/DEX/JAR directly. A DEX packer is *detected* at triage, not stripped)** |
| **Recovery: agentic** | "Reason about an *unknown/custom* protection and script the unpack" | analysis-workbench: `packer_analyst` | analysis-workbench: `dotnet_analyst` (dnlib/.NET) | **(gap)** |
| **Deep decompile** | "Reconstruct source-level code for analysis" | ghidra-rpc | ilspy-mcp | **jadx** (DEX/APK → Java) + **android_native_analysis** (Ghidra over the bundled `.so`) |

## 2. The pipeline, stage by stage

```
sample_intake → triage_router → deobfuscation(loop) → deep_engine_router → ioc → behavior → attack → critic → report
```

| Stage | Engine used | Role |
|---|---|---|
| `sample_intake` | none (acquire_sample hashes+stores, **detects the container format** → `SAMPLE_FORMAT_KEY` and **names the packer/protector** from its watermark → `SAMPLE_PACKER_KEY`; `prepare_sandbox`/`prepare_ilspy` warm the pods, and prepare_sandbox also runs the **Detect It Easy pre-validator** on the staged bytes → `SAMPLE_DIE_KEY`); `acquire_sample` also performs **hash-reputation** lookup (CIRCL hashlookup keyless, MalwareBazaar, VirusTotal — only the SHA-256 ever leaves the host; no source uploads, and no credential means no request) when a credential is configured | classify technology |
| `triage_router` (format router) | routes by `SAMPLE_FORMAT_KEY` | n/a |
| ↳ `apk`/`dex`/`jar` → `android_triage` | **deobfuscation-tools** (androguard) | triage |
| ↳ default → `triage_recon` | **radare2-mcp** | triage (native/.NET) |
| `deobfuscation` (LoopAgent): `deobf_classify → recover → scripted_recover → dotnet_scripted_recover → retriage → deobf_gate` | see below | recovery |
| ↳ `recover` (Sequential): `upx_unpack → floss_decode → dotnet_recover` (a **managed-only format gate** over `de4dot_deobfuscate → dnlib_roundtrip`) | **deobfuscation-tools** (upx, floss, de4dot); **analysis-workbench** (`dnlib_roundtrip`, which needs the workbench pod's dnlib + dotnet-script) | deterministic recovery; upx/floss are PE-universal, the .NET tools run only for a `dotnet` assembly (a native sample skips them with no model turn) |
| ↳ `scripted_recover` (gate) → `packer_analyst` | **analysis-workbench** (+ radare2-mcp triage) | agentic recovery (native `packed-other` only) |
| ↳ `dotnet_scripted_recover` (gate) → `dotnet_analyst` | **analysis-workbench** (dnlib/.NET) | agentic recovery (managed `.NET`, e.g. de4dot-crashing ConfuserEx) |
| ↳ `retriage` | **radare2-mcp** | re-triage the recovered artifact |
| `deep_engine_router` (format router) | routes by `SAMPLE_FORMAT_KEY` | n/a |
| ↳ native → `deep_analysis` (Ghidra loop) | **ghidra-rpc** | deep decompile |
| ↳ dotnet → `dotnet_deep_analysis` (`dotnet_decompile`/ILSpy, then `dotnet_native_pivot` → `dotnet_native_analysis`/Ghidra when the managed leg produced no findings) | **ilspy-mcp** + **ghidra-rpc** (conditional native fallback) | deep decompile |
| ↳ `apk`/`dex`/`jar` → `java_deep_analysis` | **jadx** + **ghidra-rpc** (over the extracted native `.so`) | deep decompile |
| `ioc` / `behavior` / `attack_mapper` / `evidence_critic` / `report` | none (evidence consumers; read session state only) | synthesis |

Recovery hands off via one shared rail: any recovery tool that succeeds sets
`CURRENT_ARTIFACT_KEY` to the recovered artifact. Every downstream stage
(retriage, the deep engines, evidence) reads *that* key, so they transparently
analyze the recovered payload. The container format is decided once at intake
and is not re-detected, so a recovered .NET assembly still routes to ILSpy.

## 3. The classification model (answers: "classify by technology?")

Yes, classify on two axes, then read the tool off the matrix. The system
already carries the first axis (`SAMPLE_FORMAT_KEY`); this makes the model
explicit so it extends cleanly.

- **Axis 1: Technology / container** (*what the code is*). Decides the **triage**
  and **deep** engine and which **recovery** tools even apply.
  - `native`: PE / ELF / Mach-O machine code
  - `dotnet`: managed .NET / CIL
  - `apk` / `dex` / `jar`: Android/JVM Dalvik or Java bytecode (bundled native
    `.so` libraries route to the native column)
  - *(future: `python`/script, `wasm`, …)*
- **Axis 2: Protection** (*how it's hidden*). Decides the **recovery** approach
  *within* a technology.
  - **none** → skip recovery, go straight to deep decompile
  - **known / deterministic** (UPX; runtime-encoded strings; a de4dot-supported
    obfuscator) → a deterministic **deobfuscation-tools** CLI
  - **custom / unknown** (a bespoke packer; a de4dot-*crashing* ConfuserEx variant)
    → **agentic** recovery: an LLM reasons + scripts with the workbench tools

The recovery stage is deliberately **two-tier** (cheap deterministic first, then
agentic for what's left) on *both* technology columns, mirroring how the native
side already works (`recover` then `scripted_recover`).

## 4. "Regular" (native) samples: the baseline

A **native binary** (PE/ELF/Mach-O). Flow:

1. `sample_intake` → format `native`.
2. `triage_recon` → **radare2-mcp** (sections, imports, strings, entropy → is it packed? how?).
3. `deobfuscation`:
   - `recover` → **deobfuscation-tools**: `upx_unpack` (UPX), `floss_decode` (encoded strings). Each no-ops if not applicable.
   - if `obf_class == packed-other` (custom packer UPX/FLOSS can't touch) → `scripted_recover` → `packer_analyst` uses **analysis-workbench** (`run_python` + radare2/r2pipe + pefile/LIEF/pycryptodome) to reverse the stub and reimplement the unpack.
4. `deep_engine_router` → native → `deep_analysis` → **ghidra-rpc** decompiles to pseudo-C.
5. Evidence stages synthesize IOCs/behavior/ATT&CK → report.

## 5. `.NET` (managed) samples: the newer column

A **.NET/CIL assembly** (`dotnet`). Flow:

1. `sample_intake` → format `dotnet` (CLI header / COM-descriptor present).
2. `triage_recon` → **radare2-mcp**, but CIL analysis is skipped by protocol
   (radare2 reads the PE wrapper, meaning sections and the CLI header, but not the
   managed metadata/method bodies usefully; see `prompts/triage_recon.md`).
3. `deobfuscation`:
   - `recover` → `dotnet_recover` (managed-only gate): `de4dot_deobfuscate`
     (**deobfuscation-tools**) self-gates on `SAMPLE_FORMAT_KEY == "dotnet"` and
     deobfuscates a *de4dot-supported* obfuscator (SmartAssembly, older ConfuserEx, …),
     then `dnlib_roundtrip` (**analysis-workbench**) repairs the metadata when de4dot
     fails or crashes so the assembly loads again.
   - `dotnet_scripted_recover` → `dotnet_analyst` (**analysis-workbench**, dnlib/.NET)
     is the managed twin of `packer_analyst`: it runs when de4dot did *not* fully
     recover, to reverse the protector and extract config (see §6).
4. `deep_engine_router` → dotnet → `dotnet_deep_analysis`: `dotnet_decompile` drives
   **ilspy-mcp** (CIL → C#), then `dotnet_native_pivot` runs `dotnet_native_analysis`
   (**ghidra-rpc**) over the PE only if the managed leg produced no findings.
5. Evidence stages → report.

## 5b. `Android` (APK/DEX/JAR) samples: the newest column

An **Android / JVM-bytecode** sample (`apk`, `dex`, or `jar`). Flow:

1. `sample_intake` → format `apk` / `dex` / `jar` (ZIP with `AndroidManifest.xml` +
   `classes*.dex`; a bare `.dex` by magic; a `.jar`).
2. `triage_router` → **`android_triage`** (androguard in the **deobfuscation-tools**
   pod): package identity, permissions, exported components, signing cert, DEX
   metadata, and a commercial-packer name match. radare2 is skipped: it would see
   only the ZIP shell, just as CIL is skipped for `.NET`.
3. `deobfuscation`: the format router sends JVM formats to `recovery_skip` — the
   native/.NET `deobfuscation_loop` is bypassed entirely (jadx opens the container
   directly, so there is no unpack step). A detected DEX packer is reported as a
   limitation/host-IOC, not stripped. (Both recovery cells are empty.)
4. `deep_engine_router` → `apk`/`dex`/`jar` → **`java_deep_analysis`**: `java_decompile`
   drives **jadx** (DEX/APK → Java, the deep-evidence slot), then `android_native_analysis`
   extracts one ABI's native `.so` and runs **ghidra-rpc** over it (the native-evidence
   slot). Bundled native code thus falls back to the native column's deep engine.
5. Evidence stages synthesize IOCs / behavior / **ATT&CK Mobile** → report.

## 6. Known gaps (from the ConfuserEx `1595d92f…` sample)

The matrix in §1 had two weak/empty cells for managed code, both exposed by a
real ConfuserEx sample. The **agentic** one is now **filled**; managed triage
remains weak:

- Managed triage is weak: radare2 only sees the PE shell; there is no
  CIL-aware triage engine, so "what protector, how bad" is under-informed for
  `.NET` before recovery.
- Managed *agentic* recovery is now filled. When de4dot is *insufficient*, for
  example when it crashes (`InvalidCastException` in its ConfuserEx `ProxyCallFixer`)
  on a ConfuserEx variant, the deobfuscation loop now falls through to
  `dotnet_scripted_recover` → `dotnet_analyst`, the managed twin of
  `packer_analyst`: a `dotnet_analyst` agent over a .NET/dnlib scripting
  workbench (`analysis-workbench`). This closes the `(agentic recovery, managed)`
  cell that a de4dot-crashing sample used to leave empty.

Optionally extending this with dynamic in-memory dumping crosses the "never
execute the sample" line and needs an explicit safety decision; tracked as the
design's §12.7 follow-on.

## 7. Extensibility: two directions

The matrix extends along two independent directions. Both reuse the same
rails (`SAMPLE_FORMAT_KEY` for technology, `obf_class` for protection,
`CURRENT_ARTIFACT_KEY` for the recovery hand-off, and the `EvidenceEnvelope` bus
for every stage's output).

### Horizontal: new technology families (a new *column*)

e.g. iOS, WASM, `python`/script. Fill the column by supplying, in order of need:
1. a **format detector** in `acquire_sample` (a new `SAMPLE_FORMAT_KEY` value),
2. a **deep engine** routed by `deep_engine_router` (Ghidra/ILSpy analog: jadx
   for DEX, etc.),
3. **deterministic recovery** tool(s) in `deobfuscation-tools` (self-gating by
   format, like `de4dot`),
4. **agentic recovery** (a `<tech>_analyst` agent + a scripting workbench) for the
   custom/unknown cases,
5. **triage** coverage (reuse radare2 where the container is a native shell, or
   add a technology-aware triage step).

The Android (`apk`/`dex`/`jar`) column is the shipped reference implementation
of this recipe: (1) `acquire_sample` detects `apk`/`dex`/`jar`; (2) `java_deep_analysis`
routes on `deep_engine_router` (jadx for DEX/APK, plus Ghidra over the extracted
native `.so`); (3 and 4) Android needs *no* recovery engine, since jadx opens the
container directly, so both recovery cells are deliberately empty (a DEX packer is
detected at triage, not stripped); (5) triage is a technology-aware step:
`triage_router` sends `apk`/`dex`/`jar` to `android_triage` (androguard) instead of
radare2, since radare2 would see only the ZIP shell.

### Vertical: new analysis steps (a new *row in the spine*)

e.g. a YARA/signature stage, config extraction, capability tagging, binary diff.
Each new step is an agent that reads `CURRENT_ARTIFACT_KEY` and writes an
`EvidenceEnvelope` to its `output_key`; the deterministic-gate + evidence-critic
machinery already normalizes, deduplicates, and reports it. Inserting the agent
into the `malware_analyst` spine (or a sub-loop) is the whole change.

### Honest caveats (where the single-sample model needs an explicit extension)

- Composite / container formats (APK, IPA, JAR, self-extracting installers)
  hold *multiple* sub-artifacts of possibly *different* technologies. The current
  model assumes one sample → one technology. One case is now modeled:
  `extract_android_native_libs` fans an APK out to its native `.so`
  sub-artifacts, each routed through the native (Ghidra) deep engine via
  `android_native_analysis`. But the general N-arbitrary-sub-artifact fan-out
  (arbitrary containers holding multiple, differently-classified technologies)
  still needs an extraction role that classifies and routes each sub-artifact
  through the matrix independently. The recovery loop's recursion +
  `CURRENT_ARTIFACT_KEY` hand-off is the foundation, but that general *fan-out* is
  not yet modeled.
- Cross-technology layering: `SAMPLE_FORMAT_KEY` is decided once at intake.
  A native packer wrapping a .NET payload (or vice-versa) would keep the *outer*
  format after recovery and mis-route the deep engine. Same-technology recovery
  (the common case, incl. the .NET scenario) is unaffected; cross-technology
  layering needs format re-detection after each recovery round.
- Dynamic analysis is a deliberately absent axis: every engine here is
  static (the safety stance is "never execute the sample"). Industry pipelines
  usually pair static analysis with a *dynamic/sandbox* tier for behavior/IOCs;
  adding it is a future direction that also changes the safety model.

To add a new tool to an existing cell (e.g. another deterministic .NET
deobfuscator): install it in the relevant image, write the tool on the `upx.py`
template (self-gate → run → validate → advance `CURRENT_ARTIFACT_KEY` +
`<TOOL>_RESULT_KEY`), append its agent to the stage's roster, and fold its
evidence in the gate. One sandbox, one stage, no new path.
