# Android / JVM Analysis Column — Design

**Date:** 2026-07-31
**Status:** Approved for planning (Slice 1)
**Author:** brainstorming session (Opus 4.8)
**Reference:** GitHub PR #2 (AsherDLL, "Add the Java/Android decompilation route
via jadx") — the authoritative design for the jadx layer, re-implemented fresh
against current `main` (its base diverged too far to cherry-pick; see §9).

## Goal

Add an **Android / JVM analysis column** to AREMA's format-routed pipeline, so an
`apk` / `dex` / `jar` sample is triaged, decompiled, and reported with the same
evidence discipline as the completed native and .NET columns. The column is
mapped across all four pipeline dimensions (triage, deterministic recovery,
agentic recovery, deep decompile); **Slice 1 builds the analysis path for
unpacked samples** (the common case) and **detects — but does not yet statically
unpack — packed samples**. Recovery is fully mapped here and built in Slice 2.

## The column, against the .NET template

The .NET column is the closest analog (managed bytecode; near-source decompile;
deterministic + agentic recovery) and is the template.

| Dimension | Native ✅ | .NET ✅ (template) | **Android/JVM** |
|---|---|---|---|
| Intake / format | PE/ELF/Mach-O magic | `dotnet` (CLR header) | `dex` magic; `apk`/`jar` ZIP-inspect |
| Triage | radare2 | radare2 + obf-classify | **androguard**: manifest, permissions, components, DEX inventory, native-lib enum, packer detection |
| Recovery — deterministic | UPX | de4dot, dnlib | apktool decode, DEX string-deobf **(Slice 2)** |
| Recovery — agentic | packer_analyst | dotnet_analyst | `android_analyst` (reverse loader, dump DEX) **(Slice 2)** |
| Deep decompile | Ghidra | ILSpy (MCP) | **jadx** (CLI over kubectl exec) |
| Cross-column | — | — | native `.so` → **Ghidra** (one ABI, bounded) |

## Non-negotiable principles

1. **Static analysis only.** The sample is never executed. Android packers that
   decrypt the real DEX at runtime are handled by *static* agentic recovery
   (Slice 2, reverse the loader) — never by running the app. When static
   recovery cannot reach the real DEX, the report states the packer and the
   limitation; it never invents recovered content.
2. **Format routes before engines.** Exactly like native/.NET: the container
   format decided at ingest selects the triage and deep-decompile engines. No
   model call is spent standing an engine down.
3. **Re-implement, don't cherry-pick.** PR #2 is the reference design; the code
   is written fresh against current `main` so it integrates with the
   `deep_engine_router`, the deobfuscation loop, and the agentic-recovery gates
   that did not exist at PR #2's base (§9).
4. **Attacker-authored output is sanitized.** Decompiled Java (jadx) and parsed
   Android metadata (androguard) are attacker-controlled text; both join the
   `re_guarded` sanitizer's binary-origin set, exactly like disassembly.
5. **Evidence discipline unchanged.** Every finding cites its producing tool +
   artifact id; the `evidence_critic` gate rejects unsupported claims; coverage
   limitations flow into the report.

## Scope

### Slice 1 — build now (this spec's implementation target)

- **Intake:** `acquire_sample` learns `dex`, `apk`, `jar`; family
  `JVM_FORMATS = {"apk", "dex", "jar"}` (extensible to `aar`/`aab`).
- **Deep decompile:** generalize `deep_engine_router`; add the composite
  `java_deep_analysis` engine = **jadx** (DEX) **+ a bounded Ghidra sub-pass over
  one ABI's native `.so`**.
- **Triage:** **androguard** (in the existing `deobfuscation-tools` pool), routed
  by format; produces the Android triage evidence incl. **packer detection**.
- **Downstream lenses:** Android-aware prompt updates (IOC, behavior, ATT&CK
  Mobile); the critic + report handle the packer-detected limitation.
- **Sandbox:** one new `jadx` pool; androguard folded into `deobfuscation-tools`.

### Slice 2 — mapped here, built next

- Deterministic recovery: `apktool` decode into the workbench; DEX string-deobf.
- Agentic `android_analyst`: reverse the packer's DEX loader (native `.so` via
  Ghidra + Java stub via jadx), reimplement the decryption in the workbench,
  dump the real DEX, `register_unpacked_artifact` → retriage — slotting into the
  existing deobfuscation loop + agentic-recovery gate.

## Components (Slice 1)

### B. Intake — `acquire_sample`

`detect_format_bytes` gains: `dex` (magic `dex\n0..\0`); `apk` (ZIP whose entries
include `AndroidManifest.xml` **and** a `classes*.dex`); `jar` (ZIP with `.class`
entries / `META-INF`, no `AndroidManifest.xml`). Ambiguity resolves
manifest-first (an `apk` is a `jar` with a manifest). Hostile inputs (zip bombs,
missing entries, truncated magic) fail closed to `unknown`. Ported from PR #2's
verified detection + tests.

### C. Deep decompile — generalized router + composite java engine

- **`deep_engine_router`** changes from a 2-way managed/native switch to a
  format-family→engine map. `MANAGED_FORMATS = {"dotnet"}` becomes a mapping
  `{dotnet → dotnet_decompile, apk|dex|jar → java_deep_analysis}` with the native
  Ghidra loop as the default. All engines write the shared `deep_evidence_json`.
- **`java_deep_analysis`** (composite): `prepare_jadx` does one whole-sample
  decompile pass; jadx read-tools produce the DEX decompile evidence; **then**,
  if the sample bundles native libraries, a bounded Ghidra sub-pass runs over
  **one ABI** (`arm64-v8a`, else `armeabi-v7a`) — since the same lib content
  repeats across ABIs — decompiling `JNI_OnLoad` / exports. Both write
  `deep_evidence_json`.
- **jadx toolset** (re-implemented from PR #2), CLI over `kubectl exec` like
  `ghidra-rpc` (both jadx MCP servers rejected — GUI-bound / stdio-only, neither
  works in a pod):
  - `prepare_jadx` — the one expensive step; decompiles the whole sample.
  - `jadx_manifest` — decoded `AndroidManifest.xml` (permissions, exported
    components, `debuggable`, `usesCleartextTraffic`).
  - `jadx_list_classes` — class inventory, narrowable by package.
  - `jadx_class_source` — reconstructed Java for one class (by FQN).
  - `jadx_search_sources` — regex across every decompiled class in one call.
  - `jadx_strings` — `res/values/strings.xml` (endpoints often live here).
  - `jadx_list_resources` — bundled files (embedded payloads, native `.so`).
- **Security:** the class name is the only model-supplied value that becomes a
  filesystem path — validated against a Java binary-name pattern (not sanitized);
  nothing runs on failure. Regex / package filters reach `grep`/`find` as single
  argv entries; no `sh -c` anywhere. jadx output joins `re_guarded`.

### D. Triage — androguard, format-routed

- **androguard** added to the existing `deobfuscation-tools` pool (no new pool) —
  a Python library/CLI with a rich APK/DEX/manifest/permissions API.
- A **triage router** (mirrors `deep_engine_router`): `native`/`dotnet` →
  `triage_recon` (radare2); `apk`/`dex`/`jar` (the JVM family) → `android_triage`
  (androguard). Both write `triage_evidence_json`. `android_triage` adapts by
  sub-format: full manifest triage for an `apk`, class/string-level for a bare
  `dex`, and minimal for a pure-Java `jar` (no manifest/Dalvik — defer to the
  jadx decompile).
- **`android_triage`** surfaces, from the APK/DEX (no execution): package name;
  requested + dangerous permissions; exported components (activities / services /
  receivers / providers) as attack surface; receivers indicating persistence
  (e.g. `BOOT_COMPLETED`); `debuggable` / `usesCleartextTraffic`; min/target SDK;
  signing certificate identity/hash; multidex inventory (class/method counts);
  native-library enumeration (`lib/<abi>/*.so`); URLs/endpoints in resources; and
  **packer detection** — signatures over known loader `.so` names (`libjiagu`,
  `libsecexe`, `libDexHelper`, `libtup`/Legu, `libdexprotector`, …), assets
  patterns, stub `application` class names, and loader package structure. APK
  gets full manifest triage; bare `dex` degrades to class/string-level.

### E. Downstream lenses — Android awareness

The evidence-driven lenses generalize, but their prompts are updated (PR #2
updated the same files):

- **IOC extraction** (host/network): Android host IOCs — package, signing cert,
  requested permissions, exported components; network IOCs — URLs/domains from
  resources and decompiled strings.
- **behavior_characterization** + **attack_mapper**: map Android capabilities and
  **MITRE ATT&CK Mobile** TTPs (accessibility abuse, screen overlay, SMS
  interception, device-admin/lock, dynamic code loading).
- **evidence_critic** + **malware_report_generator**: format-agnostic; the report
  names the detected packer and, for a packed sample, records the limitation
  "packed by \<packer\>; real DEX not statically recovered (agentic recovery is a
  later capability)."

### F. Packer handling (Slice 1)

Triage **detects** the packer (§D signatures). Deep analysis decompiles the stub
DEX (jadx) and analyzes the loader `.so` (Ghidra). No DEX unpacking is attempted;
the report states the packer + the coverage limitation. This mirrors the .NET
lesson (de4dot could not unpack ConfuserEx-Compressor, so `dotnet_analyst` had to
exist) — Android's real recovery is agentic and lands in Slice 2.

### G. Sandbox / infra

- **New `jadx` pool** — `images/jadx` Dockerfile, a `SandboxTemplate` + `WarmPool`
  under `deploy/sandbox/`, driven by the **jadx CLI over `kubectl exec`** (no
  listener; `prepare_jadx` lives on `java_deep_analysis`, next to its tools, like
  `prepare_ghidra`). Deny-all egress like the other static engines.
- **androguard** added to the `deobfuscation-tools` image (no new pool).
- `make sandbox-build-images` → 6 images; `.env.example` `AREMA_SANDBOX_POOL_MAP`
  += the jadx pool.

## Global Constraints (exact values — bind every task)

- **Formats:** values `apk`, `dex`, `jar`; `JVM_FORMATS = {"apk", "dex", "jar"}`;
  `SAMPLE_FORMAT_KEY = "sample:format"` (existing). APK detection is
  manifest-first (an apk is a jar + `AndroidManifest.xml`).
- **jadx tools (exact ids):** `prepare_jadx`, `jadx_manifest`, `jadx_list_classes`,
  `jadx_class_source`, `jadx_search_sources`, `jadx_strings`, `jadx_list_resources`.
- **jadx transport:** CLI over `kubectl exec` (a `sandbox_cli` toolset, like
  `ghidra-rpc`); NOT an ADK MCP server.
- **Router:** `deep_engine_router` routes `apk|dex|jar → java_deep_analysis`,
  `dotnet → dotnet_decompile`, else the native Ghidra loop; the triage router
  routes `apk|dex|jar → android_triage`, else `triage_recon`. Both keep the
  shared output slots (`deep_evidence_json`, `triage_evidence_json`).
- **`.so` fan-out:** one ABI only — prefer `arm64-v8a`, fallback `armeabi-v7a`;
  bounded Ghidra loop (`JNI_OnLoad` + exports).
- **Security:** class name validated against a Java binary-name pattern; no
  `sh -c`; jadx + androguard output added to the `re_guarded` binary-origin set.
- **Static-only:** Slice 1 never unpacks a DEX; a detected packer is reported with
  the limitation wording above.
- **Neutrality:** all Android engines/agents live under `src/reverse_engineering`
  + `src/malware_analyst`; `src/arema` stays domain-neutral (no `jadx`/`apk`/
  `androguard` names leak into the core — the neutrality guard test still passes).

## Testing

- **Intake:** `dex`/`apk`/`jar` detection incl. ZIP inspection + hostile inputs
  (missing entries, zip bombs, truncated magic → `unknown`).
- **jadx toolset:** class-name validation against path traversal / absolute path /
  embedded `;` and newline (asserts *no command executed*); resource tools degrade
  cleanly on a bare `dex`/`jar`.
- **android_triage:** manifest parse (permissions, exported components,
  `debuggable`/cleartext), native-lib enumeration, and **packer detection**
  signatures over a fixture set.
- **Routers:** generalized `deep_engine_router` (`jvm→jadx`, `dotnet→ILSpy`,
  `native→Ghidra`) + the `.so` fan-out (one ABI); triage router
  (`apk/dex/jar→android_triage`, else `triage_recon`).
- **Downstream:** the Android-lens prompt updates carry the new evidence
  (permissions/components → IOCs, ATT&CK Mobile TTPs).
- **End-to-end:** a real (small, benign) APK fixture → jadx decompile + androguard
  manifest triage + one-ABI `.so` Ghidra pass → report. (PR #2 verified jadx on a
  real APK in ~2s / 191 classes; reuse that shape.)
- Whole suite green (`make check`) at every milestone.

## Confirmed decisions

- Foundation first: Slice 1 = intake + jadx deep + androguard triage + one-ABI
  `.so`→Ghidra; recovery (deterministic + agentic) mapped, built in Slice 2. ✅
- Triage engine: **androguard** in the existing `deobfuscation-tools` pool. ✅
- PR #2 port: **re-implement fresh** against current `main` (reference design). ✅
- Native `.so`: **fan out to Ghidra now**, one ABI, bounded. ✅

## §9 — Why re-implement, not cherry-pick

PR #2 is stacked on an old `main` (before the deobfuscation loop,
`deep_engine_router`, retriage, and agentic recovery landed). Its route diagram
("add a third parallel decompile engine") does not match today's architecture,
and a literal cherry-pick would conflict across nearly every changed file. We
therefore take PR #2 as the authoritative *design* — its rejected-MCP analysis,
the `kubectl exec` CLI approach, the exact jadx tool surface, the class-name
security model, the "jadx opens apk/dex/jar directly, no unpack needed" finding,
and its test shapes — and re-implement against current `main`, integrating with
the generalized router, the format-routed triage, and (Slice 2) the existing
recovery loop.

## Open items (resolved in the plan, not blocking)

- **androguard packaging** in the `deobfuscation-tools` image (CLI vs a thin
  Python wrapper invoked over `kubectl exec`) — pinned during implementation.
- **jadx version** and the exact CLI flags for headless whole-sample decompile —
  pinned in the `images/jadx` Dockerfile, verified against a real APK.
- **ATT&CK Mobile vs Enterprise** in `attack_mapper` — confirm the prompt maps to
  the Mobile matrix for Android evidence while leaving native/.NET on Enterprise.
