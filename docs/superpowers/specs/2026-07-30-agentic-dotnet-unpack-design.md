# Agentic .NET Unpack — Controlled In-Sandbox Execution (Design)

**Status:** Implemented (2026-07-30/31; branch `feat/scripted-unpacking`).
**Follow-on to:** `2026-07-29-scripted-unpacking-phase2b-dotnet-agentic.md` (the
managed `dotnet_analyst` agent) and the deterministic
`dnlib_roundtrip` first-pass.
**Motivating sample:** `1595d92f…` (`server1.exe`, SkiDzEX = a ConfuserEx fork).

## 1. Problem

The managed deep-recovery agent (`dotnet_analyst`, analysis-workbench pool)
could *diagnose* the protector but never *recovered* the payload — every run of the
.NET sample produced an empty/low-value report. The design question was whether to
add a deterministic string-decryptor tool, and where it fits the vertical/horizontal
matrix (`docs/TOOLS_USAGE.md`).

## 2. Decisive investigation (live, in-pod)

Root-cause RE of the sample inside the workbench pod (recorded in memory
`dotnet-sample-is-confuserex-compressor`) overturned the premise:

1. **It is ConfuserEx *Compressor* packing, not string encryption.** `#US` heap is
   emptied (32 bytes); `ldstr` reads `""`; **zero** string-decrypter calls. The real
   malware is a **second assembly**, LZMA-compressed (~3.24 MB) in RVA field
   `_649DF7D38BBA4B94_`, decompressed + `Assembly.Load`ed at runtime by the
   `<Module>::.cctor` chain. `rt.dll` is only the unpacker **stub** — no IOCs can
   come from decompiling it.
2. **de4dot-cex is out.** It crashes identically (`InvalidCastException` in
   `ConfuserEx.ProxyCallFixer.EmulateManagedMethod`, during *detection*) on **both**
   the original and the dnlib-round-tripped file. The round-trip only makes the stub
   loadable; it does not rescue de4dot. So "de4dot second pass" is refuted.
3. **Pure static recovery is not reliable.** Reimplementing the LZMA fails (the props
   byte is invalid → a per-build deriver/framing). Invoking the decompressor directly
   on the raw field overflows (the loader preprocesses first). Reversing the per-build
   key by hand would be a brittle, sample-specific "hardcoded solution" — the very
   thing the engineering standard forbids.
4. **What works (proven):** run the sample's OWN unpack routine while skipping its
   self-defense — with dnlib: neuter `<Module>::.cctor` to `ret`; patch the loader's
   `Assembly.Load(byte[])` call to `File.WriteAllBytes(dump)` returning null; add a
   `Main` that calls the loader in try/catch; **run it under `mono`** (the .NET Core
   host behind `dotnet-script` cannot even load the .NET Framework assembly). This
   extracted the 4.35 MB inner assembly. **The sample is multi-layer** — that inner
   assembly is itself ConfuserEx-protected, so recovery must iterate.

## 3. Decision

- **Placement is unchanged and correct:** this is the **Agentic recovery × managed
  (.NET)** matrix cell = `dotnet_analyst` on the analysis-workbench pool. No new
  cell, pool, sandbox, or tool is required — `run_python` (which can
  `subprocess.run` mono/dotnet-script/dnlib) + `register_unpacked_artifact` already
  express the whole technique.
- **The real blockers were capability, guidance, time, and policy — not tooling:**
  1. **Model.** The deep agents ran on grok-4 (global provider `xai`), which made
     zero `run_python` calls and fabricated. Pin `dotnet_analyst` + `packer_analyst`
     to **`zai/glm-5.2`** via `agent_model_overrides` (per-agent, provider resolved
     independently of the global provider). Config only.
  2. **Prompt.** Rewrite `dotnet_analyst.md` from "reverse the string decryptor" to a
     general **fingerprint → technique-menu** framework (compressor-pack /
     string-enc / CFG-flatten / anti-tamper), teaching the controlled-unpack recipe
     and **multi-layer iteration** — as techniques to reason over, referenced by what
     recon *observed*, never by hardcoded sample names.
  3. **Time.** Raise `AREMA_SANDBOX_RUN_TIMEOUT` to 300 (a dnlib rewrite of a
     multi-MB assembly + a mono run do not fit in 120 s).
  4. **Policy (user-approved):** relax the strict static-only rule. **All execution
     is permitted inside the controlled, disposable, egress-denied sandbox** — the
     sandbox isolation is the safety boundary. `packer_analyst.md` relaxed the same
     way for consistency.

## 4. Changes

- `src/reverse_engineering/agents/dotnet_scripted_recover.py` — deep agent runs
  AFTER a successful dnlib round-trip; one deep pass (persistent marker).
- `src/reverse_engineering/prompts/dotnet_analyst.md` — full rewrite (§3.2).
- `src/reverse_engineering/prompts/packer_analyst.md` — execution rule relaxed.
- `src/reverse_engineering/tools/workbench/register.py` — expand `$WORKDIR/`,
  accept absolute workspace paths.
- `.env.example` — document per-agent overrides for the deep agents + the raised
  sandbox timeout. Operator `.env` sets `zai/glm-5.2` + `AREMA_SANDBOX_RUN_TIMEOUT=300`.
- Tests updated; `make check` green (1385 passed, 1 skipped). Commit `1301596`.

## 5. Validation

- Technique proven manually in-pod (inner assembly extracted, 4.35 MB, valid MZ).
- `dotnet_analyst` confirmed built on `openai/glm-5.2` with its two tools.
- Live end-to-end autonomous run (glm-5.2 driving the recon + unpack) — see the
  session summary for the observed result.

## 6. Follow-ups (optional)

- If model-driven reliability proves inconsistent, add a deterministic
  "isolated-decode" primitive (extract-methods-to-clean-module-and-run) as a
  force-multiplier — the technique is already scriptable in `run_python`, so this is
  reliability, not capability.
- The inner assembly is protected again; confirm the deobfuscation LoopAgent's
  multi-layer recursion (or the agent's in-session iteration) reaches cleartext IOCs.
