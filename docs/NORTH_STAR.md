# AREMA — Design Document v2.1

### Autonomous Reverse Engineering & Malware Analysis: a headless, defended, multi-engine agentic pipeline on Google ADK

---

# 0\. Scope & assumptions (read this first)

This revision realigns the design to the current project decisions. Where a decision was underspecified, the assumption made is stated here so it can be vetoed:

- **RE-general core, malware-analysis first.** The system is a *general* reverse-engineering pipeline; the first *mindset* (and the MVP) is malware analysis. Vulnerability research is the second mindset sharing the same core (see §6). This matches the north-star split: same substrate, different lens.  
- **Static-first.** Static analysis is the backbone. Dynamic analysis (sandbox detonation) is a *parallel track* added after the static MVP, not part of it.  
- **radare2 is the recon tool.** r2 does fast first-pass reconnaissance; Ghidra (ghidralib/PyGhidra, default, free) and IDA (idalib or RPC, optional, licensed) do the deep decompilation of *native* binaries, and are run **in parallel for consensus** (see §3, §7).  
- **Format-aware routing.** Triage picks the decompiler family by file type: **native** (PE/ELF/Mach-O) → radare2 \+ Ghidra/IDA; **.NET/CIL** → ILSpy (`ilspycmd` / ILSpy MCP); **Java/Android** (JAR/DEX/APK) → `jadx` CLI. Managed bytecode (.NET, Java) decompiles near-source, so its path is lighter than the native consensus path (§4, §7).  
- **Bulk / comparative analysis is first-class.** Because every case emits a *uniform* evidence record, the corpus is comparable: is a new sample a **variant** of known malware, a **new campaign**, or **unrelated**? This cross-sample correlation is a major advantage over single-binary tools (§3, §4 Phase 7).  

---

## 3\. The four axes of parallelism

Parallelism is a first-class design concern, not an optimization afterthought. Reverse engineering has **four independent axes** along which work fans out; the recon stage exists partly to *discover the parallel structure* so the orchestrator can schedule it.

**Axis 1 — Across samples (horizontal scale-out).** The whole pipeline is per-sample and stateless across samples. N samples run on N workers. This is the docker-compose scaling story: add workers, not code. → ADK: one `Session` per case, a worker pool consumes a queue.

**Axis 2 — Across engines (consensus).** r2, and Ghidra, analyze the *same* sample independently and their outputs are **reconciled**. r2 gives fast recon; Ghidra give deep decompilation whose disagreements are themselves signal (a function both engines decompile identically is high-confidence; divergence flags obfuscation or a decompiler bug). → ADK: `ParallelAgent(sub_agents=[ghidra_agent])` → consensus/diff step.

**Axis 3 — Across call-graph subtrees (function-level).** functions are analyzed **bottom-up** (leaves first) so callers inherit resolved callee context. This is *sequential within a dependency chain* but **parallel across independent branches and strongly-connected components**. A 400-function binary is not 400 sequential LLM calls — it is a topological wavefront where each "layer" of independent functions runs concurrently. → ADK: schedule each independent SCC/branch as a parallel unit; barrier between topological layers.

**Axis 4 — Across analysis lenses & the static/dynamic split.** Given a decompiled function set, multiple *lenses* are mutually independent: function-semantics (naming/typing), behavior characterization, crypto-constant detection, anti-analysis detection, and — for the vuln mindset — vulnerability-pattern scanning. These fan out. Separately, the **dynamic track** (sandbox detonation, post-MVP) depends only on the raw sample, not on decompilation, so it runs **concurrently with the entire static track** and joins at synthesis. → ADK: `ParallelAgent` over lenses; static and dynamic as two parallel branches that a synthesis barrier joins.

| Axis | Unit of parallelism | Dependency / barrier | ADK primitive |
| :---- | :---- | :---- | :---- |
| 1 Samples | one case each | none (embarrassingly parallel) | worker pool / Session-per-case |
| 2 Engines | r2 ∥ Ghidra | ILSPY (mcp) | join at consensus | `ParallelAgent` |
| 3 Call-graph | independent SCCs/branches | callee-before-caller within a chain | wavefront of `ParallelAgent` per topo-layer |
| 4 Lenses \+ static/dynamic | each lens; static ∥ dynamic | join at synthesis | `ParallelAgent` |

**The recon-first rule:** radare2 runs first precisely because its cheap output — file profile, call graph, function inventory, string/import tables, packing signal — is the **schedule** for Axes 2–4. You cannot fan out intelligently until recon has drawn the map.

**Fan-out has a fan-in twin — corpus correlation.** The same per-sample independence that makes Axis 1 scale also yields a *uniform* evidence record per case, which makes samples **comparable**. After individual analyses complete, a corpus barrier compares them — fuzzy hashes (ssdeep/TLSH), import hashes (imphash/telfhash), capability- and string-set overlap, and function-level structural diffs (BinDiff/Diaphora) — to decide whether a new sample is a variant, a new campaign, or unrelated (§4, Phase 7). Bulk analysis is not a separate system; it is the fan-in that closes Axis 1\.

---

## 4\. Pipeline (workflow first, then agents)

Described as a plain workflow (per the project's "workflow → agentic task" philosophy), then mapped to agents in §6.

**Phase 0 — Acquisition & safety** *(sequential, always first).* Hash (MD5/SHA256/ssdeep/TLSH/imphash), store as an immutable artifact with a chain-of-custody record, set the case's risk flags. No analysis yet. *(Methodology: PMA Ch. 1.)*

**Phase 1 — Recon / triage (radare2-first, parallel fan-out).** On the raw bytes, concurrently: file/format/arch identification, entropy \+ packer detection (Detect-It-Easy), string extraction (raw \+ FLOSS), capa capabilities, YARA *scan* against existing rulesets, and **radare2 `aaa`** to produce the function inventory \+ call graph \+ imports/exports. Triage also **routes by format** (native → r2 \+ Ghidra; .NET → ILSpy) and runs a cheap **corpus lookup** (fuzzy/import hashes vs. prior cases) to answer "have we seen this — or something like it?" before any deep work. Output: a **triage bundle** (a durable artifact, Cerberus-style) that schedules everything downstream. *(PMA Ch. 1–3.)*

**Phase 2 — Deobfuscation loop** *(conditional; `LoopAgent`, max 3 iterations).* If triage flags packing/obfuscation: classify (CFF, bogus control flow, string encryption, API hashing, VM), apply the matching recovery (FLOSS, unpacking profile, p-code emulation, memory carve), re-triage, and **require evidence that quality improved** or exit to manual. Capped to prevent the "never-ending automation" failure mode from the challenges paper. *(PRE Ch. 5; PMA Ch. 15–18.)*

**Phase 3 — Deep decompilation (format-routed).** *Native* (PE/ELF/Mach-O): import into Ghidra (ghidralib/PyGhidra), produce per-function decompilation from each, and **reconcile** — agree → high confidence; disagree → flag for closer analysis. *Managed code* skips the native consensus: **.NET/CIL → ILSpy** (`ilspycmd`/MCP), both of which decompile near-source, so a single authoritative decompiler suffices (an optional second — e.g. dnSpyEx or CFR — can still cross-check).

**Phase 4 — Analysis lenses (parallel) \+ dynamic track (parallel, post-MVP).** Fan out the lenses over the (consensus) decompilation — function-semantics (call-graph-ordered, Axis 3), behavior characterization, crypto/anti-analysis detection, and (vuln mindset) vulnerability-pattern lens. Concurrently, if enabled and human-approved, the **dynamic track** detonates the sample and collects traces. *(PMA Ch. 6–7, 11; PBA Ch. 12–13 for the vuln/symbolic path.)*

**Phase 5 — Synthesis & cross-verification** *(barrier).* Join all parallel outputs. Unify naming/structs, reconcile and run the **evidence critic**: every claim must cite a tool artifact or it is rejected.

**Phase 6 — Reporting** *(evidence-ledger-only).* Render the analyst report **from the evidence ledger, never from agent memory** — the model cannot invent a claim that has no artifact behind it. Executive summary, technical walk-through, behavior/ATT\&CK mapping (as *analysis*, not detection rules), confidence, and explicit caveats.

**Phase 7 — Corpus correlation (cross-sample; optional per run).** Operates over the evidence store *across cases*, not within one. Cheap similarity primitives (ssdeep/TLSH, imphash/telfhash, capability- and string-set overlap) build a similarity graph; structural diffing (BinDiff/Diaphora, or function-embedding similarity) resolves *what changed* between near-neighbours. The LLM then produces an **evidence-backed relational judgment** — e.g. "variant of family X (same C2 routine `fn_0x401a00`, added anti-debug), likely same actor, new campaign" — with the diff artifacts as provenance. This is the bulk-analysis capability and the fan-in complement to Axis 1\.

flowchart TD

    A\[Analyst Console\] \--\> P0\[Phase 0: Acquire \+ hash \+ custody\]

    P0 \--\> FW\[Sanitization membrane\]

    FW \--\> P1\[Phase 1: radare2 recon \+ triage fan-out\]

    P1 \--\> R{packed / obfuscated?}

    R \--\>|yes| P2\[Phase 2: Deobfuscation loop max 3\]

    P2 \--\> P1

    R \--\>|no| P3\[Phase 3: Ghidra  deep decompile → consensus\]

    P3 \--\> P4\[Phase 4: lenses ∥ \+ dynamic track ∥\]

    P4 \--\> P5\[Phase 5: synthesis \+ evidence critic barrier\]

    P5 \--\> P6\[Phase 6: evidence-only report\]

    P6 \-.optional.-\> P7\[Phase 7: corpus correlation across cases\]

---

## 5\. Three-plane architecture

Kept from v1 (it is the design's best idea), minus the v1 fourth "automation" plane.

- **Control plane (ADK).** Owns routing, retries, loops, human gates, and session state. Deterministic. Holds only IDs and risk flags — never raw binary data.  
- **Analysis plane (agents).** Narrow LLM specialists that consume *typed, sanitized evidence* and emit *typed judgments*. Probabilistic, but sandboxed and least-privileged.  
- **Evidence plane (immutable store).** Artifacts (samples, decompilation, traces), the evidence ledger (claim → citations → confidence), and the provenance graph (tool → claim → report). It is also the substrate for **cross-case corpus correlation** (Phase 7): because records are uniform, samples across cases are directly comparable.

The invariant: **deterministic orchestration, probabilistic interpretation.** The graph is trustworthy; the LLM is treated as a capable but fallible — and attackable — worker.

---

## 6\. Agent roster (v2)

MVP agents in **bold**; the rest are the RE-general core filled in over the roadmap. Detection/IOC/rule-generation agents from v1 are **removed** from MVP.

| Agent | ADK type | Mindset | Role |
| :---- | :---- | :---- | :---- |
| **AnalystConsole** | `LlmAgent` (root) | both | Human interface; references samples by artifact ID only |
| **SanitizationMembrane** | `LlmAgent` \+ `before_tool_callback` | both | Structural defense on all binary-origin text (§10) |
| **TriageRecon** | `LlmAgent` over r2 tools | radare2-first recon → triage bundle; **format routing** \+ corpus lookup |
| Deobfuscation | `LoopAgent` (max 3\) | both | Classify \+ recover obfuscation; evidence-gated |
| **StaticDecompile** | `ParallelAgent`\[ghidra\] · ILSpy · | both | **Format-routed** deep decompile; consensus for native |
| **FunctionSemantics** | `LlmAgent`, call-graph-ordered | both | Names/types/purpose bottom-up (Axis 3\) |
| BehaviorCharacterization | `LlmAgent` | malware | Capabilities \+ ATT\&CK *as analysis* |
| VulnLens | `LlmAgent` (+ angr/symbex tools) | vuln | Attack-surface \+ memory-safety patterns |
| DynamicAnalysis | `LlmAgent` (long-running tools) | both | Sandbox detonation (post-MVP, HITL-gated) |
| **EvidenceCritic** | `LlmAgent` | both | Rejects unsupported claims; consistency gate |
| CorpusCorrelation | `LlmAgent` (+ ssdeep/TLSH/BinDiff tools) | both | Cross-sample: variant / campaign / unrelated (Phase 7\) |
| **ReportGenerator** | `LlmAgent` | both | Evidence-ledger-only reporting |

The **mindset** column is how one core serves two goals: the malware and vuln mindsets are the *same pipeline* with different lens agents (Behavior vs VulnLens) and different report templates — not two codebases.

---

## 7\. Tooling & engines

| Layer | Engine | Role | License | MVP |
| :---- | :---- | :---- | :---- | :---- |
| Recon | **radare2** \+ r2pipe | fast first pass: functions, callgraph, imports, strings | LGPL | ✅ |
| Triage | capa, FLOSS, Detect-It-Easy, YARA (scan) | capabilities, string decode, packer id | Apache/BSD | ✅ |
| Deep (default) | **Ghidra** \+ ghidralib \+ PyGhidra | headless decompilation, program DB writeback | Apache-2.0 | ✅ |
| Deep (.NET) | **ILSpy** `ilspycmd` / ILSpy MCP | near-source C\#/CIL decompilation | MIT | ✅ if .NET |
| Deobf | FLOSS, Ghidra p-code emu, z3 | recover strings/CFG | mixed | phase 3 |

**Engine ordering (as specified):** r2 recon **first** (cheap, schedules the rest) → Ghidra \+ IDA **deep in parallel** → reconcile. IDA is optional because idalib needs an OEM license for server/multi-user use; the free default path (Ghidra) is fully functional, and IDA joins the consensus when a license is present. **Format routes before engines:** triage first decides native vs. managed; native follows r2 → Ghidra ∥ IDA, while .NET goes to ILSpy and Java/Android to jadx — managed bytecode decompiles near-source, so the heavy consensus step is native-only.

---

Very important, for the radare2 tool we have a previous attempt, use /Users/alevsk/Development/security-agent-adk/mcp-servers/r2-mcp for inspiration and evaluate if this is the right way to have the r2 tool for usage to the agent
