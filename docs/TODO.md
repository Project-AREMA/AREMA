# AREMA — Future Work

Known-wanted work that is not built, with enough detail to pick up cold. This is
deliberately separate from [`ARCHITECTURAL_ISSUES.md`](./ARCHITECTURAL_ISSUES.md),
which records defects found in shipped behaviour; everything here is capability
that was never claimed to exist.

An entry earns its place by naming what actually blocks it. "Would be nice" is
not an entry.

---

## TODO-001 — Multi-artifact pipeline (comparing two samples in one run)

**Status:** blocked on architecture. Not started.

A user can already ask for a local file *or* a hash, and each resolves by its own
rule (`acquire_sample` for a path, `acquire_sample_by_hash` for a digest). What
does not work is the natural next request:

> compare the malware in `/path/to/file` to the malware `<sha256>`

The resolution half works. The comparison half does not, and the pipeline is
structurally single-artifact rather than incidentally so:

- **over twenty call sites across ~20 modules** hang off one
  `CURRENT_ARTIFACT_KEY`
  (`src/reverse_engineering/tools/deobfuscation/state.py:17`).
- `reset_deobfuscation_state` states the rule outright: *"The new canonical
  artifact id is the only authority retained."* A second ingest deliberately
  clears the first sample's aliases, caches, snapshots and gate facts.
- `EvidenceEnvelope` binds every finding to one `artifact_id`, and
  `_findings_match_envelope_artifact` rejects an envelope whose findings name
  another. That is a correctness guarantee worth keeping, not an obstacle to
  route around.

So a second ingest today would silently replace the first, and the report would
describe a sample the user never asked about. Rather than do that quietly,
`sample_intake.md` now ingests the first sample named, says only one runs per
pass, and suggests running the second separately.

**What it would take**

The interesting question is not "how do we hold two artifact ids" but "what is
the unit of analysis". Two plausible shapes, and they are not equivalent:

1. **Run the existing pipeline twice, then diff the two `CriticEnvelope`s.** The
   pipeline stays single-artifact and a comparison stage reads two completed
   evidence sets. Cheapest, and it composes with TODO-002.
2. **Make the artifact a scoped dimension of state**, so stages operate over a
   set. Much larger: every state key, the gate logic, sandbox identity, and the
   evidence anchor all become per-artifact.

Shape 1 is almost certainly right first. It also raises questions worth settling
before code: what a comparison actually reports (shared imports? matching
functions? overlapping IOCs? fuzzy-hash distance?), and whether comparison is a
new domain rather than a stage in this one.

**Touches:** `deobfuscation/state.py`, `sample_intake`, the critic, the report
lens, and whatever holds the second envelope.

---

## TODO-002 — Bulk analysis

**Status:** not started. Shares TODO-001's foundations.

Analyze many samples in one invocation: a directory, a hash list, a feed export.
Today one run means one sample, start to finish.

**What it would take**

- **Per-sample isolation.** Same root problem as TODO-001: session state is
  scoped to one sample. Sequential runs with a clean state reset between them is
  the cheap version and probably the right first one.
- **Concurrency is the real cost.** Running samples in parallel means concurrent
  sandbox claims, and the local port-forward allocation is a known collision risk
  when two cases run at once. That needs solving before parallel bulk, not after.
- **Token budget.** A single UPX-packed `ls` cost 698k to 1.04M tokens depending
  on the model. Bulk work needs a per-sample ceiling and a cheap-triage-first
  path, or the first directory anyone points at it will be expensive.
  Hash-reputation enrichment already helps here: a digest catalogued in NSRL can
  be dispositioned in milliseconds instead of a full deep pass, though **not** by
  skipping analysis outright (a known-good hash is a signal, never a
  short-circuit — see `intel/` and the verdict rules).
- **Aggregate reporting.** N reports, or one report over N samples, is a product
  question and not an obvious default.

---

## TODO-003 — Drag-and-drop sample intake

**Status:** not started. Smallest of the three, and independent of TODO-001/002.

Today a sample arrives as a path typed at `adk run`, or as a hash. Dropping a
file onto the web UI (`make adk-web`) is the obvious ergonomic gap.

**What it would take**

- **Establish what ADK's dev UI already offers.** It is a Google-maintained
  surface and this has not been checked; if it supports file attachment, the work
  may be mostly plumbing an uploaded file to a host path `acquire_sample` can
  read. Check before designing anything.
- **The dropped file must land on the host filesystem.** `acquire_sample` reads a
  local path and hashes it in place. A browser upload has to be written somewhere
  the agent process can reach, with the same size bounds the fetch path already
  applies.
- **The upload prohibition still holds, and is easy to violate here by accident.**
  A drop is a file arriving *into* the system. Nothing about that changes the
  rule that a sample never leaves it. `tests/architecture/test_no_sample_upload.py`
  guards `src/reverse_engineering/intel/`; if a drop path introduces a new module
  that both reads files and makes requests, that guard does not cover it and
  needs extending.
- **Consider whether the dev UI is the right home at all.** `adk web` is a
  development surface. If drag-and-drop is meant for analysts rather than
  developers, that is a product decision about having a real front end, and worth
  making explicitly rather than by drifting into it.

---

## TODO-004 — CILFI, and CIL pattern matching in general

**Status:** researched, not started. Deliberately deferred.

[CILFI](https://github.com/Washi1337/cilfi) is a **pattern-matching engine for
CIL**, not a decompiler. You write `.cilfi` signature files describing the shape
of a method's IL — with wildcards for unknown operands, alternatives, and regex
over string operands — and it reports every method that matches. Its
demonstration identifies all 83 KoiVM opcode handlers in a virtualized assembly.

It was requested as an answer to a run where "ILSpy could not decompile". It
would not have helped: that run never reached the .NET stage at all (see
LESSONS_LEARNED #20), and even had it reached it, CILFI does not decompile
anything.

**Where it would genuinely help**

Finding a specific function in a protected assembly when you already know the
shape of the code you are looking for: a string decryptor, a VM dispatch loop, a
config blob initializer, an anti-debug check. That is a real and recurring
problem, and pattern matching is the right tool for it.

**What it would take**

- **A build step.** It is distributed as source; producing the NativeAOT binary
  means adding a .NET SDK build stage to the deobfuscation sandbox image. That is
  a larger change to the image than any tool currently in it.
- **A signature library, which is the actual work.** CILFI with no `.cilfi` files
  finds nothing. Useful signatures have to be authored per obfuscator family
  (SmartAssembly, ConfuserEx, .NET Reactor, KoiVM), each requiring someone to
  reverse that family first and encode what they learned. That is research, not
  integration, and it does not become a pipeline stage until the library exists.
- **A decision about who writes signatures.** A model authoring `.cilfi` files at
  runtime is a different and much more speculative feature than shipping a
  curated set.

**Cheaper thing to consider first**

The `dotnet_analyst` stage already runs arbitrary Python in the workbench with
dnlib available, and used it to locate a SmartAssembly string decryptor by hand
in a live run. A small library of reusable IL-matching helpers there would
capture much of the same value with no new image, no new binary, and no new
language — and would show whether the signature-authoring problem is tractable
before committing to a tool built around it.

---

## TODO-005 — Shodan enrichment of network endpoints

**Status:** researched, not started.

Enrich the endpoints an analysis surfaces — domains, IPs, IP+port pairs — with
what Shodan already knows about them: open services, banners, ASN, hosting
country, certificate details. Today an endpoint reaches the report as a bare
string with no indication of whether it is a bulletproof host, a compromised
WordPress box, or Cloudflare.

**The credit model decides the design**

| endpoint | returns | query credits |
|---|---|---|
| `/shodan/host/{ip}` | every service seen on that IP | **none** |
| `/dns/resolve` | hostnames → IPs | **none** |
| `/dns/reverse` | IPs → hostnames | **none** |
| `/dns/domain/{domain}` | subdomains and DNS records | **1 per lookup** |
| `/shodan/host/search` | search results | 1 per filtered query |

A free Developer account gets an API key and **zero query credits**, so anything
credit-consuming fails outright. The zero-credit path is therefore
**domain → `/dns/resolve` → `/shodan/host/{ip}`**, which answers the question
that actually matters ("what is running there") without ever touching
`/dns/domain/`. Build that path; treat the credit-consuming endpoints as a
separate, later decision.

**The real blocker: there is nothing structured to feed it**

Network IOCs are `EvidenceFinding`s with `kind=network_ioc` whose value lives in
free-text `claim`/`detail`. There is no structured endpoint field anywhere, and
`enforce_network_coverage` only *counts* such findings — it never parses one. The
single piece of structured extraction in the tree is `_URL_RE` in
`images/deobfuscation-tools/androguard_triage.py`, which is APK-only, URL-only,
and never leaves that tool's JSON.

Three ways out, cheapest first:

1. **Regex over `detail`** in a post-`network_indicators` callback. The prompt
   already instructs the model to put the bare value there, and this is the same
   rung the androguard script already sits on.
2. **Enrich only the VirusTotal relations**, which are *already* structured
   (`IntelRelation.value`) and already fetched at intake. Zero extraction work.
   Narrower coverage: it sees what VT associates, not what the analysis found.
3. **Widen the evidence schema** with a structured endpoint field. Most correct,
   most expensive: `EvidenceFinding` is frozen and `extra="forbid"`, with a whole
   salvage path that exists because models already fumble the current shape.

**What it would take**

`src/reverse_engineering/intel/` is the template — same credential gate, same
`sanitize_summary` on the way back, same host-side-only rule (sandbox pods have
`networkPolicy.egress: []`). One caveat: Shodan does **not** belong in
`IntelSettings.active_sources`, which gates on a *file digest*; it answers about
endpoints and needs its own switch, or `_lookup_one` will hand it a SHA-256 it
cannot use.

**Sanitization is mandatory, not optional.** Shodan banners are raw service
output from hosts an attacker may control, and they land in an ADK instruction
template where `{}` is a placeholder.

---

## TODO-006 — capa, and a sample knowledge base

**Status:** researched, not started. Two separable pieces; capa can ship alone.

### capa

[capa](https://github.com/mandiant/capa) v9.4.0 identifies capabilities in a
binary and maps them to **MITRE ATT&CK and MBC**, deterministically, with
`tactic`/`technique`/`subtechnique`/`id` as structured fields. Today every ATT&CK
row in a report comes from a model reasoning over prose findings.

- `pip install flare-capa`, Python ≥3.10, ~56 dependencies, no network needed —
  it fits the egress-denied deobfuscation pod. Standalone binaries also exist.
- Supports PE, ELF, **.NET**, shellcode, and CAPE/DRAKVUF/VMRay sandbox reports.
- **Honest limitation:** its .NET extractor is built on `dnfile`/`dncil`, the
  libraries that struggle on maliciously-crafted assemblies. capa is strongest on
  native PE/ELF and weakest on exactly the protected .NET samples that are
  hardest here. Expect little from it on a SmartAssembly-packed sample.

Adding a CLI tool to the deobfuscation image touches six places, all enforced:
`requirements.in` (+ regenerate the hash-pinned lock), a `Dockerfile` smoke
assertion, `healthcheck.sh` (it is the pod readiness probe, so a version mismatch
keeps the pod unready), a wrapper module, `DEOBFUSCATION_TOOLSET` (which also
puts it inside the sanitization membrane), and the **evidence-critic tool
allowlist** — a finding citing `capa` is rejected as "cites no known tool" until
that last one is done.

capa's mappings should enter as `kind="attack"` findings citing `capa`, not
replace `attack_mapper`. They are different evidence — capabilities from bytes
versus characterized behaviour — and replacing the mapper would empty the ATT&CK
section on every Android sample, which capa does not cover at all.

### The knowledge base

The intent is *correlation, not skipping*: right after acquisition, check whether
this digest has been analyzed before and surface the prior report; use capa
capability sets as a cross-sample similarity key. **Similar capabilities are a
lead to follow, never a reason to skip analysis.**

**Blocker, and it is the same one for both pieces: the memory subsystem has
never persisted a single record.** The live database holds one scope and zero
rows. `record_tool_event` drops any event without a scope id, and that id is only
ever seeded by `run_single_query` — which the ADK entry points (`adk run`,
`adk web`) never call. Fix that one gap and `record_tool_event` and the
checkpoint recorder start working too.

Once persistence works, the rest is unusually cheap:

- **`MemoryQuery.source` is the digest key.** Indexed, exact-match, queryable
  across scopes with `scope_id=None`. No schema change, no second migration.
- **Scopes are durable** — `close_scope` only stamps `closed_at`, and no read
  path filters on it. A well-known cache scope created idempotently keeps rows
  reachable after a run scope closes.
- **Annotations already have a model.** `NoteRecord(text, author)` is registered
  as the core `arema.core/note` codec and, like everything else here, has never
  been written.
- `FINDING_CODEC` is a complete, tested, registered, **entirely unused**
  template — follow it exactly and you inherit a proven pattern, as its first
  writer.

Recommended split of annotations: a machine summary written every run (capa
capabilities, verdict, third-party family names) is what makes correlation work
at all, and analyst notes added deliberately are knowledge the pipeline cannot
produce. Keep them in separate report sections for the same reason first-party
evidence and third-party intel are already kept apart — so "the model thought
this" never acquires the authority of "the analyst confirmed this".
