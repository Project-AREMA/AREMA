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

- **43 call sites** hang off one `CURRENT_ARTIFACT_KEY`
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
