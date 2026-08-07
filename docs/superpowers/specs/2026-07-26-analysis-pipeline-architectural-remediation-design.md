# Analysis Pipeline Architectural Remediation — Design

**Status:** Approved design

**Date:** 2026-07-26

**Incident:** ADK Dev UI session
`9f3a73cf-38a5-43f9-b2af-ee8430cdca7d`

**Issue register:** `docs/ARCHITECTURAL_ISSUES.md`

## Goal

Make AREMA's self-contained malware-analysis pipeline produce complete,
traceable, sandbox-derived evidence regardless of whether it is invoked through
the CLI, ADK Dev UI, or another ADK runner.

The remediation must address causes, not symptoms:

- one sandbox identity contract for all tools and entry points;
- durable recovery outcomes;
- framework-enforced deep-analysis completion;
- evidence producers ordered before their consumers;
- explicit state-backed evidence handoff;
- a critic whose scope matches the pipeline; and
- negative conclusions gated by recorded coverage.

Threat-intelligence enrichment is the next step and remains out of scope.

## Non-goals

- No external hash lookup, reputation, family attribution, or third-party IOC
  feed.
- No dynamic detonation.
- No host execution of malware or deobfuscation tools.
- No weakening of artifact identity, provenance, sanitization, output bounds,
  or Kubernetes-only execution.
- No uncapped retry or analysis loop.
- No replacement of Ghidra, Radare2, UPX, or Mandiant FLOSS.

## Design principles

1. **One authority per concern.** Sandbox identity, canonical artifact identity,
   recovery outcome, evidence handoff, and completion state each have one
   resolver or schema.
2. **State is the handoff plane.** Conversation history is context, not an API.
3. **Completion is deterministic.** Models choose investigative targets;
   deterministic gates decide whether required work occurred.
4. **Failures are evidence.** A bounded failure or coverage gap survives until
   reporting.
5. **Absence requires coverage.** “None found” is valid only after the required
   analysis completed.
6. **All binary operations stay in Kubernetes.**

## Architecture

### 1. Invocation-scoped sandbox identity

Add a neutral resolver in `arema.runtime.sessions`:

```python
def resolve_sandbox_case_id(context: object) -> str:
    ...
```

Resolution order:

1. Read `SessionKeys.SANDBOX_CASE_ID` by duck-typing `context.state.get`.
2. If it is a non-empty string, preserve it exactly.
3. Otherwise read the non-empty ADK `context.invocation_id`, derive a stable
   case key, write it back to `context.state`, and return it.
4. If neither value exists, raise a neutral `SandboxIdentityError`.

The derived key must be deterministic within one invocation, distinct across
invocations, and safe for the sandbox adapter. The Kubernetes adapter already
maps caller keys to claim names; the resolver does not manufacture Kubernetes
resource names.

`prepare_sandbox`, `prepare_ghidra`, and the deobfuscation staging runtime use
this resolver. Their private `re-mvp` defaults are deleted. Tests cover explicit
state, Dev UI-shaped invocation state, malformed state, missing identity, and
cross-tool equality.

This resolves the lifecycle inconsistency without coupling AREMA to the Dev UI
or adding entry-point-specific initialization.

### 2. Durable recovery summary

Split deobfuscation state into:

- **iteration state:** call markers, caches, progress counts, and current
  snapshots; and
- **terminal state:** immutable outcome records and limitations.

The terminal JSON envelope is stored under an identifier-safe prompt alias and
an internal state key. It contains:

```json
{
  "artifact_id": "<canonical sha256>",
  "exit_reason": "complete|no_progress|degraded|pcode_handoff|iteration_cap",
  "upx": {
    "status": "success|non_applicable|degraded",
    "changed": false,
    "error_code": ""
  },
  "floss": {
    "status": "success|non_applicable|degraded",
    "new_count": 0,
    "error_code": ""
  },
  "limitations": []
}
```

The gate writes this envelope before resetting iteration-local values.
Subsequent iterations merge limitations by stable identity and never erase a
material failure. A new `acquire_sample` resets both iteration and terminal
state because it starts a new authority domain.

### 3. Explicit evidence envelopes

Every evidence-producing LLM agent receives an `output_key` and returns one
bounded JSON envelope:

```json
{
  "artifact_id": "<canonical sha256>",
  "coverage": {
    "status": "complete|partial|failed",
    "surfaces": [],
    "limitations": []
  },
  "findings": [
    {
      "artifact_id": "<canonical sha256>",
      "claim": "...",
      "tool": "...",
      "confidence": 0.0,
      "detail": "...",
      "kind": "metadata|host_ioc|network_ioc|behavior|attack|limitation"
    }
  ]
}
```

The envelope is intentionally small. It is not a general event store and does
not duplicate raw tool output.

A shared parser validates:

- exact top-level shape;
- canonical lowercase SHA-256 identity;
- bounded strings and finding count;
- confidence range;
- allowed coverage states and finding kinds; and
- limitation shape.

Consumers use identifier-safe injected aliases for these outputs. Invalid or
missing envelopes produce a failed-coverage limitation. They never cause a
consumer to reconstruct authority from arbitrary conversation text.

The existing content-addressed memory and finding codec remain unchanged;
session state is the within-run handoff plane.

### 4. Pipeline order

The malware pipeline becomes:

```text
sample_intake
→ triage_recon
→ deobfuscation
→ deep_analysis
    ├─ deep_decompile_worker
    └─ deep_analysis_gate
→ ioc_extraction
    ├─ host_indicators
    └─ network_indicators
→ behavior_characterization
→ attack_mapper
→ evidence_critic
→ malware_report_generator
```

Deep analysis precedes IOC extraction so host/network lenses can consume all
local static evidence: triage, recovery/FLOSS, and Ghidra.

The generic reverse-engineering package owns the deep-analysis loop. The
malware domain owns ordering and malware-specific synthesis.

### 5. Enforced deep-analysis completion

Rename the existing LLM leaf to `deep_decompile_worker` and place it in a capped
`deep_analysis` LoopAgent with a deterministic `deep_analysis_gate`.

Ghidra tool callbacks maintain artifact-bound facts:

```json
{
  "artifact_id": "<canonical sha256>",
  "prepared": true,
  "semantic_search_succeeded": true,
  "target_analysis_succeeded": true,
  "surfaces": ["ghidra_search_decompiled", "ghidra_decompile"]
}
```

Rules:

- `prepare_ghidra.ready=true` for the canonical artifact sets `prepared`.
- A successful, non-empty `ghidra_search_decompiled` result sets semantic
  search coverage.
- A successful, non-empty `ghidra_decompile` or high p-code result sets target
  analysis coverage.
- Metadata, imports, strings, or a function inventory cannot set either deep
  coverage flag.
- Facts with a different artifact ID are ignored.
- Degraded or empty results never count as coverage.

The gate exits only when all three predicates are true. Otherwise the next
bounded worker iteration receives an exact prompt-safe statement of the missing
surface. The maximum remains finite. Exhaustion or an unavailable Ghidra
sandbox produces a partial/failed deep evidence envelope and an explicit
limitation; it cannot produce “no semantic patterns.”

Ghidra preparation is idempotent for a claimed case/artifact, so later worker
iterations reuse the prepared project instead of reimporting the binary.

### 6. IOC and behavior synthesis

Host and network IOC agents consume:

- triage envelope;
- recovery summary and FLOSS findings; and
- deep-analysis envelope.

Selection remains artifact-bound. Each synthesized finding preserves the
original analysis tool citation. A lens may qualify what an import or decoded
string suggests, but cannot convert a capability primitive into observed
behavior.

Network negative conclusions require at least one completed network-relevant
surface:

- successful applicable FLOSS coverage;
- Ghidra strings coverage; or
- Ghidra semantic-search/decompile coverage aimed at network APIs, endpoints,
  or protocols.

Without that coverage, the network envelope reports `partial` or `failed` and
states “not determined.”

Behavior characterization consumes IOC and deep envelopes and requires an
explicit source-to-sink path for an observed behavior. Import-only evidence may
be emitted as a lower-confidence capability primitive, not a data-flow claim.

ATT&CK mapping consumes only behavior findings. A primitive without observed
behavior may be mapped only when the technique itself is discovery of that
primitive and the detail supports it; otherwise it is skipped or qualified.

### 7. Critic and report contracts

The critic consumes named envelopes from:

- triage;
- recovery;
- deep analysis;
- host IOC;
- network IOC;
- behavior; and
- ATT&CK.

It returns a validated envelope with:

- accepted findings;
- qualified findings;
- rejected finding IDs with bounded reasons;
- merged coverage; and
- preserved limitations.

The critic never needs to infer which conversational messages are evidence.
The report generator consumes only this validated envelope.

Report language follows coverage:

- `complete` with no matches: “No indicators were found by the completed
  static-analysis surfaces.”
- `partial` or `failed`: “Indicators were not determined because …”
- a present IOC: render the exact value and original tool citation.

### 8. Failure handling and observability

Public tool responses remain sanitized and bounded. Internally, logs record the
failure class and lifecycle boundary without malware-derived content.

Stable failure distinctions include:

- sandbox identity unavailable;
- sandbox claim unavailable;
- staging failed;
- tool execution failed;
- result invalid;
- analysis incomplete; and
- evidence envelope invalid.

The model receives safe public error codes. The report receives only validated
limitations. Backend diagnostics never enter model context.

## Testing strategy

### Neutral runtime

- sandbox resolver unit tests;
- explicit case preservation;
- invocation-derived identity persistence;
- missing identity rejection;
- cross-invocation isolation.

### Reverse-engineering components

- all sandbox tools use the shared resolver;
- deobfuscation failure survives gate exit;
- deep gate rejects metadata-only completion;
- deep gate accepts semantic search plus decompile/p-code;
- stale-artifact coverage is rejected;
- cap exhaustion emits a limitation.

### Malware composition and prompts

- pipeline order is locked;
- each evidence producer has its output key;
- every consumer prompt names its required aliases;
- critic scope includes every producer;
- report differentiates “none found” from “not determined.”

### End-to-end regression

A hermetic ADK session shaped like Dev UI—no pre-seeded sandbox case, but with
an invocation ID—must:

1. resolve one shared sandbox case;
2. run applicable FLOSS instead of returning `sandbox_unavailable`;
3. prevent metadata-only deep completion;
4. pass a FLOSS- or Ghidra-derived URL through network extraction and critic;
5. retain recovery/deep limitations; and
6. render the correct coverage language.

The live Kubernetes smoke test remains the final validation. Malware bytes and
all analysis commands remain inside claimed pods.

## Migration and compatibility

- Existing callers that pass a case ID keep the same identity.
- Dev UI and direct ADK runners gain invocation-scoped identity automatically.
- No session state is migrated across stored sessions; new invocations populate
  the new keys.
- Existing textual history remains visible to models as non-authoritative
  context during the transition, but prompts prohibit using it as evidence.
- The Ghidra 600/660-second timeout contract remains unchanged.

## Documentation updates

- `docs/ARCHITECTURAL_ISSUES.md` records the incident and invariants.
- `docs/ARCHITECTURE.md` documents invocation-scoped sandbox identity,
  state-backed evidence flow, and the deep-analysis gate.
- `docs/AGENTS_AND_DISCOVERY.md` documents the revised malware pipeline.
- `docs/CREATING_TOOLS.md` requires the shared sandbox identity resolver for
  every sandbox-backed tool.
- The implementation plan records exact TDD steps and verification commands.

## Out-of-scope next step

Threat-intelligence enrichment is the next independent architectural slice.
It may add hash reputation, family attribution, historical network IOCs, and
external sandbox relationships only after its credential, privacy, egress,
provenance, cache, and rate-limit contracts are designed and approved.
