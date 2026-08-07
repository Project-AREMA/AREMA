# AREMA — Slide Deck: Content + Image Prompts

> **What this file is.** A presenter-ready outline for a talk on **AREMA** — the
> agentic reverse-engineering & malware-analysis *framework* built on Google ADK.
> This is the second deck in a series: the first talk argued *that* AI can assist
> malware analysis and RE; **this** deck shows the framework that operationalizes
> it, and how anyone can extend it.
>
> **How to use it.** Each slide has three parts: **① On-slide** (the minimal text
> that goes on the slide), **② Talk track** (speaker notes / narration), and
> **③ Image prompt** (paste into Claude design / an image model). Feed the whole
> file to a design agent; the *Global visual direction* block below keeps every
> generated asset in one visual language.
>
> **Audience/format assumption:** a 25–35 min technical talk for security + AI
> engineers (conference / meetup). ~26 slides across 6 sections. Trim the
> Lessons and Roadmap sections first if you need it shorter.

---

## Global visual direction (paste into your design agent ONCE)

```
BRAND / MOOD
AREMA = "Autonomous Reverse Engineering & Malware Analysis." A defended,
multi-engine, agentic pipeline. Tone: precise, technical, calm-under-threat —
a bomb-disposal lab, not a hacker-in-a-hoodie cliché. Think "instrumented
containment," not "chaos."

PALETTE (dark-first)
- Background:  #0B0E14  (near-black navy) with a faint engineering grid
- Surface:     #141922  (raised panels/cards)
- Primary accent (analysis / signal):  #22D3EE  (electric cyan)
- Secondary accent (caution / recovery): #F59E0B (amber)
- Danger (the sample / untrusted, used SPARINGLY): #EF4444 (red)
- Structure / lines: #334155 → #64748B (slate)
- Text: #E2E8F0 primary, #94A3B8 secondary

TYPE
- Headings: geometric sans (Inter / Söhne / Neue Haas). Tight, confident.
- Data / code / labels: monospace (JetBrains Mono / IBM Plex Mono).

STYLE
- Thin-line isometric or top-down schematic diagrams; subtle glows on active
  nodes; generous negative space. Nodes = rounded rects; flows = 1–2px lines
  with small arrowheads. Avoid stock-photo people and literal "matrix rain."
- The untrusted sample is always a red-tinted, quarantined object; analysis
  engines are cyan; recovery/deobfuscation is amber.
- IMPORTANT: image models render text poorly. For any diagram with real labels,
  build it natively in the slide tool (tables/shapes) and use AI images only for
  hero backgrounds / section dividers / conceptual metaphors. Where a prompt is
  for a labeled diagram, keep on-image text to 0–3 short words.

ASPECT: 16:9. Leave a clear title-safe zone (top-left or centered).
```

---

## Deck map

| # | Section | Slides |
|---|---|---|
| 0 | Open | 1–3 |
| 1 | Architecture | 4–10 |
| 2 | The Matrix (horizontal × vertical) | 11–14 |
| 3 | Sandboxing strategy | 15–18 |
| 4 | Lessons learned | 19–23 |
| 5 | Future roadmap | 24–25 |
| 6 | Close | 26 |

---

# SECTION 0 — OPEN

## Slide 1 — Title

**① On-slide**
- **AREMA**
- Autonomous Reverse Engineering & Malware Analysis
- *A defended, multi-engine agentic pipeline on Google ADK*
- [Your name • event • date] · *open-source framework (coming soon)*

**② Talk track**
> Last time I made the case that LLM agents can genuinely help with malware
> analysis and reverse engineering. The obvious next question was: *okay — what
> does the machine that does it actually look like?* This talk is that machine.
> It's a framework, it's static-first, it never runs the sample, and I'm
> releasing it.

**③ Image prompt**
```
A dark, cinematic hero image, 16:9. A single glowing quarantined binary
artifact (a faceted red-tinted crystal/cube) suspended at center inside a
translucent containment chamber, studied by thin cyan scanning beams from
multiple surrounding lens-like engines arranged in a ring. Near-black navy
background (#0B0E14) with a faint engineering grid, volumetric haze, subtle
amber rim-light. Precise, clinical, "bomb-disposal lab" mood. No text, no
people. Thin-line isometric-schematic aesthetic mixed with soft realism.
```

---

## Slide 2 — Bridge from the last talk

**① On-slide**
- Talk 1: *"AI can help reverse-engineer malware."* → **belief**
- Talk 2: *"Here's the framework that makes it repeatable, safe, and extensible."* → **engineering**
- The hard part was never the model. It was everything *around* the model.

**② Talk track**
> A demo where a chatbot decompiles one binary is easy. A *system* you can point
> at an unknown sample, that won't loop forever, won't get prompt-injected by the
> malware's own strings, won't execute the payload, and that a stranger can
> extend without touching the core — that's the work. The model is a capable,
> fallible, *attackable* worker. The framework is the adult in the room.

**③ Image prompt**
```
Split-composition 16:9. Left third: a loose, sketchy, glowing single-node
"demo" — one lightbulb idea, warm and fuzzy. Right two-thirds: the same idea
crystallized into a rigorous engineered lattice of interconnected cyan nodes on
a grid, structured and load-bearing. Dark navy background, cyan primary, amber
accents. Conveys "belief → engineering." No text, no people, schematic style.
```

---

## Slide 3 — Thesis: the one idea to remember

**① On-slide**
- **Deterministic orchestration. Probabilistic interpretation.**
- The graph is trustworthy. The LLM is a capable, fallible, *attackable* worker.
- Everything else in this talk is a consequence of that sentence.

**② Talk track**
> If you take one thing away: separate the parts you can *prove* from the parts
> you can only *trust*. Routing, ordering, retries, gates, sandbox boundaries —
> deterministic, testable, framework-enforced. Reading decompiled code and
> forming judgments — that's the LLM, and we wrap it in evidence rules so it
> can't invent a claim. Determinism on the outside, probability on the inside.

**③ Image prompt**
```
16:9 conceptual diagram. A clockwork-precise outer ring (crisp geometric gears
/ rails in slate + cyan, sharp and exact) enclosing a softer, luminous,
slightly turbulent cyan-amber core (organic, cloud-like, uncertain). Outer =
deterministic control; inner = probabilistic reasoning. Dark navy background.
Minimal, elegant, high-contrast. No text.
```

---

# SECTION 1 — ARCHITECTURE

## Slide 4 — What AREMA is (and isn't)

**① On-slide**
- A **domain-neutral agent shell** on Google **ADK** + pluggable **domain packages**
- **Static-first.** Never executes the sample. Analysis, not detonation.
- **Declaration ≠ Construction:** immutable capability descriptors vs. the ADK agents built from them
- Ships today: a full **reverse-engineering + malware-analysis** pipeline

**② Talk track**
> The core (`src/arema`) knows nothing about malware — no tool names, no domains.
> It's a shell for *building* defended agent pipelines. Capabilities live in
> domain packages that plug in. The reverse-engineering domain is the first real
> tenant. The neutral core is enforced by tests: a *comment* mentioning "ghidra"
> in the core fails the build.

**③ Image prompt**
```
16:9. A clean isometric "motherboard + modules" metaphor: a neutral slate
baseboard (the core) with standardized glowing cyan sockets, and several
distinct domain cards plugging in (one lit up = the RE/malware domain in amber).
Emphasize the standardized socket/seam. Dark navy background, thin-line
schematic. 0–2 words max. Precise engineering aesthetic.
```

---

## Slide 5 — The layering (dependencies point strictly downward)

**① On-slide** *(build this as a native stacked diagram)*
```
cli.py / agent.py     entry points (interactive · --query · --web · ADK root_agent)
      │
runner.py             one turn, one memory scope (always closed)
      │
composition.py        build_default_composition → frozen ApplicationComposition
      │
registry/             CatalogBuilder → validated, immutable CapabilityCatalog
      │
runtime/              agent_factory · callback chain · context budget · services
      │
memory/               MemoryService over a MemoryStore port (InMemory | SQLite)
      │
core/                 config · logging · model_factory (LiteLLM)
```
- Higher imports lower. The reverse **never** happens — enforced by `Protocol` seams, not convention.

**② Talk track**
> Strict downward layering. `memory/` never imports `runtime/`; they meet through
> `runtime_checkable` protocols so neither owns the other's concrete type. This
> is what lets you swap the SQLite store for in-memory in a test without the
> runtime noticing. Boring, on purpose. Boring is what survives.

**③ Image prompt**
```
16:9. A crisp vertical stack of 7 rounded horizontal slabs (layers), each
connected only to the one directly below by a single downward arrow, glowing
cyan. Top slabs lighter, bottom slabs are the darker "foundation." Slate
structure, cyan flow lines, dark navy background. Convey "strictly downward, one
direction." Minimal labels (0–1 words). Elegant technical schematic.
```

---

## Slide 6 — The three-plane architecture

**① On-slide**
- **Control plane (ADK):** routing, retries, loops, human gates, session state. Holds only IDs + risk flags — *never raw binary*.
- **Analysis plane (agents):** narrow LLM specialists; consume *typed, sanitized evidence*, emit *typed judgments*. Sandboxed, least-privileged.
- **Evidence plane (immutable store):** artifacts, the evidence ledger (claim → citations → confidence), provenance graph.

**② Talk track**
> Three planes, three trust levels. The control plane is deterministic and never
> touches raw malware bytes — it moves *references*. The analysis plane is where
> the model lives; it only ever sees sanitized, typed evidence. The evidence
> plane is the ground truth: every claim points back to a tool artifact. The
> report is rendered from *that*, not from the model's memory — so the model
> literally cannot narrate a finding that no tool produced.

**③ Image prompt**
```
16:9. Three stacked translucent horizontal planes floating in dark space,
slightly separated, each a different accent: top plane slate/white
(deterministic control), middle plane cyan (probabilistic analysis agents),
bottom plane amber (immutable evidence store). Thin light-threads connect them
vertically. A small red quarantined artifact sits ONLY in the bottom plane,
never touching the top. Dark navy background, volumetric, clean. No text.
```

---

## Slide 7 — The pipeline spine (framework-enforced order)

**① On-slide** *(native flow diagram)*
```
sample_intake → triage_recon → deobfuscation(loop) → deep_engine_router
    → ioc → behavior → attack_mapper → evidence_critic → report
```
- One ADK **`SequentialAgent`** — fixed order, each stage runs to completion before the next.
- **Zero** LLM-directed `transfer_to_agent` calls inside the pipeline (the only model-directed hop is *greeter → domain*).

**② Talk track**
> This started life as five agents that transferred to each other by *prompt* —
> "when you're done, hand off to the next one." On a 4,600-function binary it
> deadlocked: agents re-entered each other in loops and the run hung forever.
> The fix was to stop asking the model to drive control flow. The order is now a
> `SequentialAgent` — the framework enforces it. Lesson #1, and the whole
> architecture bends around it: **determinism owns the order.**

**③ Image prompt**
```
16:9. A horizontal "spine" of 8–9 rounded nodes connected left-to-right by a
single confident cyan rail with forward arrowheads, one node styled as a small
looping sub-cycle (the deobfuscation loop) with a circular arrow. Clean, linear,
inevitable — like an assembly line. Dark navy background, slate nodes, cyan
flow, one amber node (recovery). Minimal labels (short or none). Schematic.
```

---

## Slide 8 — Recovery is a two-tier loop

**① On-slide**
- **`deobfuscation` LoopAgent:** `classify → recover → scripted_recover → retriage → gate`
- **Tier 1 — deterministic (cheap, no reasoning):** `upx_unpack`, `floss_decode`, `de4dot` — undo a *known* protection in one shot. Each **self-gates** by applicability.
- **Tier 2 — agentic (expensive, budgeted):** an LLM *reasons* about an *unknown/custom* packer and **scripts** the unpack.
- Evidence-gated + capped iterations → no "never-ending automation."

**② Talk track**
> Deobfuscation is where naive agents burn tokens forever. Two tiers. First we
> try the cheap deterministic tools — if it's UPX, `upx -d` is a millisecond, no
> LLM needed. Only when the known tools *can't* touch it do we escalate to the
> agentic tier: give the model a Python workbench and let it reverse the stub and
> reimplement the unpack. And the whole loop is *gated* — it must show the
> quality actually improved, or it exits. Capped iterations. That gate is the
> difference between a tool and a runaway.

**③ Image prompt**
```
16:9. A two-lane funnel metaphor. A red quarantined "packed" artifact enters at
left. Lane 1 (top, fast): three quick stamped deterministic tools flip it open
instantly (amber, crisp, mechanical). If still sealed, it drops to Lane 2
(bottom, slower): a glowing workbench where cyan reasoning-threads carefully
pick the lock. A circular "loop + gate" checkpoint at the exit. Dark navy, amber
+ cyan. Minimal/no text. Schematic-clean.
```

---

## Slide 9 — The evidence bus: how stages hand off

**① On-slide**
- Inter-stage truth travels through **named session-state keys**, not conversation history.
- Every producer writes a bounded **`EvidenceEnvelope`** (artifact-bound JSON) to its `output_key`.
- **One shared rail:** any recovery that succeeds advances `CURRENT_ARTIFACT_KEY` → every downstream stage transparently analyzes the *recovered* payload.
- Container format decided **once** at intake (`SAMPLE_FORMAT_KEY`) → a recovered .NET assembly still routes to ILSpy.

**② Talk track**
> Agents love to "remember" things from the chat. That's a bug waiting to happen —
> conversation history is not evidence. So we made state the bus: each stage
> writes a typed, bounded envelope to a named key, and downstream stages read
> *that*. The elegant part is the hand-off rail: unpack something, and you just
> point `CURRENT_ARTIFACT_KEY` at the recovered file. Every later stage —
> re-triage, decompile, IOCs — follows the pointer automatically. No stage knows
> or cares whether it's looking at the original or a peeled payload.

**③ Image prompt**
```
16:9. A horizontal "data bus" bar (like a circuit backplane) glowing cyan, with
several agent modules docked onto it from above, each dropping a small labeled
"envelope" token onto the bus. One bright pointer/marker slides along the bus
(the CURRENT_ARTIFACT pointer) advancing from an old artifact to a freshly
recovered one. Dark navy, slate modules, cyan bus, amber pointer. No prose text.
```

---

## Slide 10 — Adding a capability = registering a descriptor

**① On-slide**
- Extending the shell is **declarative**: register an immutable descriptor, then `freeze()`.
- `freeze(root)` validates the *whole graph*: missing refs, unreachable agents, cycles, unsafe transports, duplicate ids → a frozen catalog is **guaranteed safe to build**.

```python
builder.add_agent(AgentDescriptor(id="worker_agent", ...))
builder.add_tool(ToolDescriptor(id="clock_now", tool=clock_now,
                                output_policy=OutputPolicy(max_chars=2_000)))
builder.add_mcp_server(McpServerDescriptor(id="example_mcp", transport=...))
```

**② Talk track**
> You don't write wiring code to add a capability — you *declare* it, and a
> validator either accepts the whole graph or rejects it with a specific reason.
> Cyclic sub-agents, an agent nobody can reach from the root, a tool that
> references a codec that doesn't exist, an MCP transport with an embedded
> credential — all caught at freeze time, before a single model call. "It
> compiled" actually means "it's structurally safe."

**③ Image prompt**
```
16:9. A "validation gate" metaphor: loose descriptor cards (agent, tool, MCP)
feed into a crisp inspection gate that stamps them and freezes them into a
solid, glowing, immutable crystalline graph on the far side. A couple of
malformed cards bounce off the gate (rejected). Slate + cyan, dark navy
background. Conveys "validated → frozen → safe." No text, schematic.
```

---

# SECTION 2 — THE MATRIX (the core idea)

## Slide 11 — The insight: fill a cell, don't invent a path

**① On-slide**
- Adding support for a new sample technology should be **"fill a cell in a matrix,"** not "invent a new pipeline."
- Two axes:
  - **Horizontal — Technology / container** (*what the code is*): native · .NET · (future: JVM · script · WASM)
  - **Vertical — Functional role** (*what the step does*): Triage · Recovery · Deep decompile

**② Talk track**
> This is the conceptual heart of the framework. Most RE tooling grows as a pile
> of special cases. We forced it into a grid. One axis is the *technology* — is
> this a native PE, a .NET assembly, tomorrow a JVM class? The other axis is the
> *role* — am I triaging, recovering, or deep-decompiling? Every real tool is
> just a cell: "the deep-decompile role, for the .NET column, is ILSpy." Once you
> see the grid, extension stops being creative and becomes *mechanical*. That's
> the goal — make the frontier boring.

**③ Image prompt**
```
16:9. A clean glowing grid/matrix floating in dark space, columns and rows
implied by luminous slate gridlines, a few cells filled with softly glowing
cyan tiles and one empty dark cell highlighted (the gap). Isometric slight tilt.
The metaphor: a periodic-table-like grid of capabilities. Dark navy background,
cyan fill, amber highlight on one cell. Keep any text to 0. Elegant, minimal.
```

---

## Slide 12 — The matrix, filled (roles × technology)

**① On-slide** *(build as a native table — this is the money slide)*

| Role ↓ / Tech → | **Native** (PE/ELF/Mach-O) | **.NET / CIL** | **Android / JVM** (apk/dex/jar) |
|---|---|---|---|
| **Triage** — "what is it & how protected?" | radare2-mcp | radare2-mcp (PE wrapper only) | `android_triage` — androguard in the deobfuscation-tools pod (radare2 sees only the ZIP shell; Dalvik is skipped) |
| **Recovery — deterministic** — "undo a *known* protection" | `upx`, `floss` | `de4dot` | — (jadx opens apk/dex/jar directly; a DEX packer is *detected* at triage, not stripped) |
| **Recovery — agentic** — "reason about an *unknown* protection" | `packer_analyst` (Python + r2pipe) | `dotnet_analyst` (dnlib workbench) *← the gap we just filled* | — |
| **Deep decompile** — "reconstruct source-level code" | ghidra-rpc → pseudo-C | ilspy-mcp → C# | jadx (DEX→Java) + `android_native_analysis` (Ghidra over the bundled `.so`) |

- **Six engines, three roles, realized once per technology column.**

**② Talk track**
> Here's the grid with real names. Read a column top-to-bottom and you get the
> full playbook for that technology. Read a row across and you see the *same role*
> implemented per technology. And notice how the matrix earns its keep: it made a
> gap *visible*. When de4dot **crashed** on a ConfuserEx variant, the
> managed-agentic cell was empty — there was no .NET equivalent of our native
> `packer_analyst`. The grid told us exactly what to build: a `dotnet_analyst`
> with a dnlib scripting workbench. We filled the cell. No new pipeline — one
> new cell.

**③ Image prompt**
```
16:9. A polished 4x2 capability matrix rendered as glowing tiles on dark navy,
rows = roles, columns = technologies. Most tiles glow steady cyan; the two
"agentic recovery" tiles glow amber; one tile shows a "just healed" pulse (was
empty, now filled) with a subtle amber-to-cyan transition ring. Isometric, clean
gridlines, soft glows. Because this needs real labels, keep the AI image as a
BACKGROUND texture only and overlay the real table in the slide tool.
```

---

## Slide 13 — Extending horizontally: a new technology column

**① On-slide**
- Add a **column** (next up: iOS · WASM · scripting) by filling cells in order of need:
  1. a **format detector** in `acquire_sample` (new `SAMPLE_FORMAT_KEY`)
  2. a **deep engine** routed by `deep_engine_router` (jadx for DEX, …)
  3. **deterministic recovery** tool(s) (self-gating by format)
  4. **agentic recovery** (`<tech>_analyst` + a scripting workbench)
  5. **triage** coverage (reuse radare2 where the shell is native, else add one)
- **Android is the reference build:** `apk`/`dex`/`jar` detected at intake → `android_triage`
  (androguard) at triage → `java_deep_analysis` (jadx DEX→Java + Ghidra over the bundled `.so`)
  at deep decompile. (Both recovery cells stay empty — jadx opens the container directly.)
- Same rails: `SAMPLE_FORMAT_KEY`, `obf_class`, `CURRENT_ARTIFACT_KEY`, `EvidenceEnvelope`.

**② Talk track**
> Horizontal growth is adding a whole new technology — and we've already done it
> with Android. We didn't touch the core. We filled cells in priority order:
> detect `apk`/`dex`/`jar` at intake, route triage to androguard, route the deep
> engine to jadx (with Ghidra picking up the bundled native `.so`). Android needed
> no deobfuscation cells — jadx opens the container directly. Every one of those
> hooks onto rails that already existed. The next column — iOS, WASM — fills in the
> same way. The pipeline shape doesn't change — the column just fills in.

**③ Image prompt**
```
16:9. The capability matrix from before, but with a NEW empty column sliding in
from the right edge, its cells lighting up one-by-one top-to-bottom in sequence
(1→5), cyan fill cascading down. Motion/direction implied by trailing light.
Dark navy, slate grid, cyan cascade. Convey "add a column, fill downward." Text:
0–1 words. Isometric schematic.
```

---

## Slide 14 — Extending vertically: a new analysis step

**① On-slide**
- Add a **row to the spine** (YARA/signature · config extraction · capability tagging · binary diff).
- Each new step is *one agent* that **reads `CURRENT_ARTIFACT_KEY`** and **writes an `EvidenceEnvelope`** to its `output_key`.
- The gate + evidence-critic machinery normalizes, dedupes, and reports it automatically. Inserting it into the spine is the whole change.

**② Talk track**
> Vertical growth is adding a new *kind of analysis* — a YARA stage, config
> extraction, capability tagging, a binary-diff step. It's even cheaper than a
> column: a new step is a single agent that reads the current artifact and writes
> a typed evidence envelope. The critic and reporting machinery already know how
> to consume any envelope, so the new step "just appears" in the report. Add one
> agent to the sequence — done.

**③ Image prompt**
```
16:9. The horizontal pipeline spine from Slide 7, but with a new node dropping
DOWN into an open slot in the rail, clicking into place, and immediately its
output-envelope token appears on the evidence bus below. Convey "insert one node
→ it participates automatically." Dark navy, cyan rail, one new amber node
snapping in. Minimal/no text. Schematic.
```

---

# SECTION 3 — SANDBOXING STRATEGY

## Slide 15 — The prime directive: never execute the sample

**① On-slide**
- **Every engine here is static.** Safety stance: *never run the malware.*
- Binary execution boundary is **Kubernetes-only** and is an architectural invariant (not a prompt).
- The *tools* run in the sandbox; the **sample is data**, decompiled and read — not detonated.
- Dynamic detonation is a **deliberately-absent axis** (a future track with its own safety model).

**② Talk track**
> Foundational rule: we do not run the sample. Ghidra, radare2, ILSpy, the
> unpackers — they *operate on* the bytes; they never *execute* them. And even
> the tools don't run on my laptop — anything that touches a sample runs inside a
> Kubernetes sandbox. That boundary is enforced in code and locked by regression
> tests, not left to a polite instruction in a prompt. Dynamic analysis —
> actually detonating samples — is a whole separate track with a whole separate
> safety conversation. It's intentionally *not* in the static core.

**③ Image prompt**
```
16:9. A red quarantined binary artifact sealed inside a thick transparent
containment vessel; robotic cyan instrument-arms reach IN to scan/read it but
the artifact never leaves and is never "powered on" (no spark, no execution
glow). A bold containment membrane separates it from a clean outer lab. Dark
navy, red sample, cyan instruments, slate glass. Clinical, safe. No text.
```

---

## Slide 16 — The runtime topology (host reasons, pods execute)

**① On-slide** *(native flow diagram)*
```
ADK reasoning loop (on host)
   → agent calls an execution tool
      → k8s-agent-sandbox client
         → kubectl port-forward → sandbox-router
            → SandboxClaim adopts a pre-warmed pod
               → tool runs in the pod → result returns
```
- **Warm pools** keep pods pre-booted; a **claim** adopts one on demand; the pool self-replenishes.
- **Local-tunnel mode** (Kind/Minikube/CI): host Python → `kubectl port-forward` → router → pod.
- Engines reached as **MCP services** (port-forward) or **exec-driven** (`kubectl exec`).

**② Talk track**
> Important mental model: the *thinking* happens on the host — the ADK loop keeps
> running under `adk web`. The pods don't run the agent; they run the *tools*.
> When an agent needs to execute something, the sandbox client claims a
> pre-warmed pod through a router over a port-forward, runs the tool there, and
> streams the result back. Warm pools mean we're not cold-booting a container per
> call. Some engines are long-running MCP services we port-forward to; others we
> just `kubectl exec` into. One sandbox identity per case, shared across every
> engine in that run.

**③ Image prompt**
```
16:9. Left: a "host" workstation node glowing cyan (the reasoning brain). A
single tunnel/conduit crosses a boundary to the right: a Kubernetes cluster
region containing a "router" hub and a row of pre-warmed pod containers (warm
pool), one highlighted as "claimed." Data flows host→tunnel→router→pod and back.
Dark navy, cyan host, slate cluster, one amber claimed pod. Thin-line isometric.
Minimal labels (host / cluster only, or none).
```

---

## Slide 17 — Defense in depth: the pod is a cage

**① On-slide**
- `securityContext`: `runAsNonRoot`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem`, **drop ALL capabilities**
- **deny-all egress** NetworkPolicy · no service-account token · no host paths · no privileged containers
- CPU/memory + process limits · execution timeouts · dedicated sandbox namespace · **gVisor / Kata** runtime for real isolation
- Plain `kind create cluster` is **not** hardened — these controls are the difference.

**② Talk track**
> The pod is treated as hostile-code containment. Non-root, no new privileges,
> read-only root FS, every Linux capability dropped, no egress, no mounted
> service-account token, no host mounts, hard CPU/mem/pid limits, timeouts, its
> own namespace, and gVisor or Kata for kernel-level isolation. The default Kind
> cluster gives you *none* of that — it's fine for learning the CRDs and claims,
> but it is explicitly not a place to run hostile code. The hardening list is the
> product.

**③ Image prompt**
```
16:9. A single pod rendered as a layered containment cell: concentric protective
shells around a small red artifact — each shell labeled by an ICON only (a
dropped-capabilities shield, a severed network cable for no-egress, a lock for
read-only FS, a no-root crown-with-slash, a gVisor/Kata inner wall). Cyan shells
on dark navy, red core. Convey "many independent layers." Icons not words.
```

---

## Slide 18 — Egress: the security control that lied

**① On-slide**
- We shipped a **deny-all egress** policy. The verifier said **PASS**. The pod could still reach `1.1.1.1:443`.
- Three compounding traps:
  1. The sandbox framework's **managed** policy *allows* internet by default; K8s policies are **additive (OR)** → our deny was negated.
  2. The verifier probed the **wrong pod** (a labelled stand-in, not the real warm-pool pod) → false assurance.
  3. A NetworkPolicy **drops** (not rejects) → "offline" tools *hang* on full timeouts instead of failing fast.
- Fix: express the deny **through** the framework's own managed policy; verify **inside a live warm-pool pod**; make tools truly offline (pinned package cache, fast-fail DNS).

**② Talk track**
> This one's my favorite because it's so humbling. We had a deny-all egress
> policy. Our verification script passed. And the real pod could still open a TCP
> connection to the public internet. Three bugs stacked: the sandbox framework
> *itself* injects an allow-internet policy, and Kubernetes NetworkPolicies only
> ever *add* permits — so ours was OR'd away. Our verifier tested a decoy pod that
> wasn't even subject to the framework's policy. And once we *did* enforce the
> deny, tools started *hanging* for minutes — because a NetworkPolicy silently
> drops packets, so an "offline" tool waits out the entire TCP and DNS timeout
> chain. "The policy object exists" is not "traffic is blocked." Verify on the
> real workload, and make your tools never reach for the network in the first
> place.

**③ Image prompt**
```
16:9. A dramatic "security theater vs reality" split. Left: a confident green
"PASS" checkmark over a padlocked network gate (the illusion). Right: the same
gate with a hidden side-door wide open, a data packet slipping through to a
glowing internet cloud. Between them, a subtle "OR" logic-gate symbol hinting
the policies combined permissively. Dark navy, deceptive green→alarming amber.
Minimal text (only "PASS" allowed). Conceptual, cinematic.
```

---

# SECTION 4 — LESSONS LEARNED

## Slide 19 — Section intro: what only shows up in production

**① On-slide**
- 15 hard-won bugs. Each: a symptom, a root cause, a fix.
- The pattern behind all of them: **the model was never the hard part.**
- Orchestration · async · memory · isolation · silent-success — the *systems* problems.

**② Talk track**
> None of these bugs are about the LLM being dumb. They're about async
> cancellation semantics, cgroup memory accounting, Kubernetes policy composition,
> and tools that return success while producing nothing. This is what "agentic"
> actually costs. I'll show five.

**③ Image prompt**
```
16:9 section-divider. A dark "lab wall" pinned with a constellation of small
glowing incident cards connected by thin investigation threads (red string on a
detective board, but clean and cyan-tinted, not messy). A sense of "war stories
mapped." Dark navy, cyan threads, a few amber and red pins. No legible text —
cards are abstract glyphs.
```

---

## Slide 20 — Lesson: don't let the model drive control flow

**① On-slide**
- **Symptom:** 5-agent pipeline on a 4,600-function binary deadlocks — agents re-enter each other, run hangs forever.
- **Root cause:** control flow was **prompt-directed** (`transfer_to_agent`). ADK lets *any* sub-agent transfer to *any* sibling; on long runs the model loses the thread and re-delegates.
- **Fix:** a framework-enforced **`SequentialAgent`**. Fixed order. **Zero** in-pipeline transfers.
- **Rule:** never rely on the LLM to sequence a pipeline of >2–3 agents.

**② Talk track**
> This is the origin story of the whole "deterministic orchestration" thesis. We
> asked the model to run the pipeline by transferring between agents. It worked in
> demos and deadlocked in production. The model isn't a scheduler. Give ordering
> to the framework and give judgment to the model.

**③ Image prompt**
```
16:9. Left: a tangle of agents transferring to each other chaotically — arrows
looping back on themselves into a knot (red, disordered). Right: the same agents
snapped into a clean single-file conveyor (cyan, ordered). Transformation from
chaos-graph to a straight line. Dark navy, red→cyan. No text. Schematic.
```

---

## Slide 21 — Lesson: `asyncio.wait_for` poisons the exception chain

**① On-slide**
- **Symptom:** a transient MCP timeout crashes the *entire* run — the "resilient" toolset re-raises instead of degrading.
- **Root cause:** `wait_for` cancels via `CancelledError`, which lingers in `__context__`. Code walking the chain saw it and treated a **timeout** as a **real cancellation**.
- **Fix:** check for `TimeoutError` *first* — if present, the `CancelledError` below is `wait_for`'s, not a genuine cancel → degrade gracefully.

```
ConnectionError → __cause__: TimeoutError → __context__: CancelledError (from wait_for)
```

**② Talk track**
> Subtle async trap. We had logic that re-raises genuine cancellations (so
> shutdown works) but catches everything else. Trouble is, `asyncio.wait_for`
> *implements* its timeout by cancelling the inner task — so a `CancelledError`
> gets stapled into the exception chain of a plain timeout. Our "is this a real
> cancel?" check walked the chain, found it, and killed the run. The tell is a
> `TimeoutError` sitting above it. Check for that first. One `if`, but you only
> find it by reading the traceback three frames deep.

**③ Image prompt**
```
16:9. A close-up of an "exception chain" as a vertical chain of glowing links,
each link labeled by an icon. Near the bottom, a CancelledError link is
disguised/masked (a wolf-in-sheep's-clothing motif) while a TimeoutError link
above it is the real signal, spotlighted in cyan. Convey "look one link higher."
Dark navy, cyan highlight, amber warning glow. Minimal text.
```

---

## Slide 22 — Lesson: exit 137 is the kernel, not your heap

**① On-slide**
- **Symptom:** Ghidra decompile-search dies with exit **137**; coverage comes back partial; downstream IOC/behavior lenses starve → "not determined" report.
- **Root cause:** pod had `limits.memory: 4Gi` and **no `-Xmx`**. JDK 21 derives heap from the cgroup (**~1Gi** at 25%). Ghidra's decompiler is a **native subprocess per function** whose memory is *off-heap* → total RSS blows past 4Gi → **cgroup OOM-killer** (137 = 128 + SIGKILL).
- **Fix:** remove the fixed `limits.memory` (let it burst against the node), set an explicit `-Xmx12g`, and **retry the load** — the node is *shared* with other JVM workloads, so kills can come from *external* pressure the scheduler can't see.

**② Talk track**
> "It's a 4-gig pod, why is it OOMing?" Because a JVM with a memory *limit* but no
> explicit heap silently runs on ~25% of that limit — a 1-gig heap in a 4-gig pod.
> And Ghidra's decompiler isn't Java; it's a native C++ process spawned per
> function, eating the *other* three gigs off-heap. So you simultaneously have too
> small a heap and too small a cap. Exit 137 is always the kernel's OOM-killer,
> never a Java `OutOfMemoryError` — that distinction tells you it's an
> availability problem. We unboxed the limit, set the heap explicitly, and added a
> retry because the node is shared with other heavy JVMs and the kill can come
> from *outside* the cluster entirely.

**③ Image prompt**
```
16:9. A container box labeled "4Gi" but inside, a tiny Java heap balloon (1Gi)
crammed next to a much larger native process blob spilling OUT past the box
walls; a kernel "SIGKILL" guillotine descends from above stamped "137". Convey
"the limit didn't mean what you thought; the native side burst the box." Dark
navy, amber container, red overflow, one number "137" allowed as text.
```

---

## Slide 23 — Lesson: beware silent success

**① On-slide**
- Two failures that returned **`success: true`** while producing **nothing**:
  - **Ghidra decompiler native missing on arm64.** Every *other* Ghidra feature worked; decompile returned empty `c_code`; the wrapper reported success → "Decompilation Unavailable" in the report, cause invisible.
  - **`output_schema` aborted the whole pipeline.** A redundant loop pass emitted *prose* instead of the tool call; ADK re-raised a `ValidationError` that killed **every** downstream stage.
- **Fixes:** make empty output a **loud** `degraded` result; **fail open to the stage**, never to the whole run (a private-hook override + an import-time guard so the coupling can't rot silently).
- **Rule:** verify the *decompiler produced output*, not just that *the engine ran*.

**② Talk track**
> The most dangerous failure is the one that looks like success. Ghidra ran fine —
> metadata, listings, xrefs all worked — but the *decompiler* is a separate native
> binary that the official release doesn't ship for arm64. It returned empty, our
> wrapper called that success, and the report just said "unavailable" with no
> reason. Second one: we adopted structured output, and on a redundant loop pass
> the model narrated "coverage complete" as prose — ADK validated that against the
> schema, threw, and the exception took out every remaining stage. The meta-lesson:
> a per-stage failure must fail open *to that stage*, and "the tool returned"
> must never be confused with "the tool did its job." Make empty output scream.

**③ Image prompt**
```
16:9. A vending-machine metaphor: a green "SUCCESS" light glows while the
delivery tray below is completely empty. A magnifying glass reveals the void.
Beside it, a small domino chain where one prose-shaped tile topples an entire
row (one stage failure cascading to all). Dark navy, deceptive green, empty
tray, cyan magnifier. Only "SUCCESS" as text. Conceptual, slightly unsettling.
```

---

# SECTION 5 — FUTURE ROADMAP

## Slide 24 — More building blocks (grow the matrix)

**① On-slide**
- **New columns (horizontal):** Android (apk/dex/jar → jadx) **✅ shipped** · iOS · WASM · scripting
- **New rows (vertical):** YARA/signature stage · config extraction · capability tagging · binary diff
- **New engines / consensus:** Ghidra ∥ IDA for native (agreement = confidence, divergence = signal)
- **The framework was designed so these are additive** — new cells and rows, not new pipelines.

**② Talk track**
> The roadmap is literally "fill more of the grid." Android already shipped as a
> column; next up: iOS, WASM. More rows: a YARA stage, config extraction, capability tagging, binary
> diff. More engines per cell: run Ghidra and IDA in parallel and treat their
> agreement as a confidence signal and their disagreement as a flag. None of this
> is a rewrite. The entire architecture exists so that growth is *addition*. The
> best measure of the design is that the roadmap is boring.

**③ Image prompt**
```
16:9. The capability matrix again, now expanding on BOTH axes: several new
columns fading in on the right and several new rows fading in at the bottom,
cells lighting up cyan as they populate — a grid growing outward from a solid
lit core. Convey "same structure, more coverage." Dark navy, cyan growth, amber
frontier cells. Isometric. Text: 0.
```

---

## Slide 25 — Bigger frontiers (and honest limits)

**① On-slide**
- **Agentic recovery everywhere** — a `<tech>_analyst` + scripting workbench per column (native ✅, .NET ✅ just landed).
- **Dynamic analysis track** — detonation for behavior/IOCs; **changes the safety model** (HITL-gated).
- **Corpus correlation (fan-in)** — uniform evidence records → variant / new campaign / unrelated across cases.
- **Honest gaps:** composite containers (APK/JAR/installers) need a **fan-out** role; cross-technology layering needs **format re-detection after each recovery round**.

**② Talk track**
> Beyond filling cells, three bigger bets. One: an agentic analyst for every
> technology, not just native and .NET. Two: a dynamic track — actually detonating
> samples for behavior — which is powerful but rewrites the safety model, so it's
> human-gated and separate. Three: corpus correlation — because every case emits
> the *same* evidence shape, we can ask across cases "is this a variant, a new
> campaign, or unrelated?" And I want to be honest about the edges: today it's one
> sample, one technology. Containers that hold many sub-artifacts need a fan-out
> role we haven't modeled, and a native packer wrapping a .NET payload needs us to
> re-detect the format after each unpack. Known, named, on the list.

**③ Image prompt**
```
16:9. A horizon/expedition metaphor: a solid lit "base camp" (the current
framework) with three glowing paths extending toward distant peaks labeled by
ICONS only — a detonation/spark peak (dynamic), a constellation-of-samples peak
(corpus correlation), a nested-boxes peak (containers). One path is dotted
(honest gap). Dark navy, cyan paths, amber horizon glow. Aspirational but
grounded. No words.
```

---

# SECTION 6 — CLOSE

## Slide 26 — Close & call to action

**① On-slide**
- **Deterministic orchestration. Probabilistic interpretation.**
- A **static-first**, **never-execute**, **matrix-extensible** RE/malware framework on ADK.
- Extend it by **filling a cell**, not inventing a path.
- **Open-sourcing soon** — [repo / handle / QR]. Come add a column.

**② Talk track**
> To close where we started: the model was the easy part. The framework — the
> determinism, the sandbox, the evidence bus, the matrix — is what makes agentic
> reverse engineering something you can trust, extend, and hand to someone else.
> I'm releasing it. If you want a new technology or a new analysis lens, the grid
> is waiting for you to fill a cell. Thank you.

**③ Image prompt**
```
16:9 closing hero. Pull back to reveal the full AREMA system as one elegant
luminous machine: the containment chamber (center), the ring of analysis engines
(cyan), the capability matrix glowing as a wall behind it, and the pipeline spine
as a rail through the foreground — all unified, calm, powerful. A single open
"socket" invites a new module (the audience's contribution). Dark navy, cyan +
amber, cinematic depth. Optional 1-word wordmark "AREMA" bottom-left. Leave
title-safe space for a QR code bottom-right.
```

---

## Appendix A — Optional deep-dive slides (swap in for a longer/technical audience)

- **Context & resilience** (from `docs/CONTEXT_AND_RESILIENCE.md`): 3-layer defense — per-tool output compaction (always the last after-tool step) → context-budget tiers (NORMAL/WARNING/HARD/CRITICAL) that compact older tool results then older model text → clean checkpointed stop at unrecoverable CRITICAL. *Image: a pressure gauge with graded tiers, calmly bleeding off load.*
- **Resilient MCP**: optional servers degrade to `[]` tools; required servers re-raise; cancellation is never an availability signal. *Image: a service that gracefully "shrinks" instead of crashing.*
- **Fail-open memory**: lifecycle writes catch store errors, log the error *type* only, mark degraded, continue — and only ever persist neutral metadata (never prompts, args, model text, or output). *Image: a ledger that keeps writing through a paper jam.*
- **The neutrality perimeter**: architecture tests scan `src/arema` at the *source-text* level — a comment saying "ghidra" fails the build. *Image: a customs border that inspects even the labels.*
- **Four axes of parallelism** (from `NORTH_STAR.md`): across samples · across engines (consensus) · across call-graph subtrees (topological wavefront) · across analysis lenses + static/dynamic. *Image: one input fanning into four orthogonal parallel planes.*

## Appendix B — Source docs (for fact-checking each slide)

| Slide topic | Source |
|---|---|
| Layering, composition, pipeline invariants | `docs/ARCHITECTURE.md` |
| The engine/role matrix, extensibility axes | `docs/TOOLS_USAGE.md` |
| Three planes, four axes, agent roster, vision | `docs/NORTH_STAR.md` |
| Kubernetes sandbox, warm pools, hardening | `docs/SANDBOXING.md` |
| Every "lessons learned" slide | `docs/LESSONS_LEARNED.md` |
| Multi-agent layout, ADK discovery, add-a-domain | `docs/AGENTS_AND_DISCOVERY.md` |
| Context budget, compaction, resilience | `docs/CONTEXT_AND_RESILIENCE.md` |

## Appendix C — Speaker cheat-sheet (numbers worth memorizing)

- **9-stage** sequential spine; **0** LLM-directed transfers inside the pipeline.
- **6 engines**, **3 roles**, **3 technology columns** shipping today (native, .NET, Android/JVM).
- Recovery is **2-tier**: deterministic first (ms), agentic second (budgeted).
- Exit **137** = cgroup OOM-killer (128 + SIGKILL 9), *never* a Java heap error.
- Deobfuscation loop is **evidence-gated + iteration-capped** — no runaway automation.
- Sample is **never executed**; execution boundary is **Kubernetes-only**, test-locked.
```
