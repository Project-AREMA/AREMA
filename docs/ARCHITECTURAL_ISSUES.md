# Architectural Issues

> Defects found in shipped behaviour. Capability that was never built lives in
> [`TODO.md`](./TODO.md).

This register records cross-component failures that cannot be corrected safely
inside one prompt, agent, or tool wrapper. Each issue includes the violated
invariant, observed impact, and root remediation. It is not a backlog of small
defects; entries belong here when multiple valid components compose into an
invalid system behavior.

AI-001 through AI-007 are implemented (see each status for the implementing
commits) and locked end to end by the hermetic Dev UI-shaped regression in
`tests/malware_analyst/test_analysis_pipeline_regression.py`, which drives the
identity resolver, recovery gate, deep-analysis gate, and network-coverage
enforcement against the known incident evidence with no Kubernetes and no model.

## AI-001 — Sandbox identity depends on the entry point

**Status:** Implemented (56553e8, 0007309, 69fbf77)

**Observed in:** ADK Dev UI session
`9f3a73cf-38a5-43f9-b2af-ee8430cdca7d`

### Failure

The Dev UI created a valid ADK session without
`SessionKeys.SANDBOX_CASE_ID`. Radare2 and Ghidra silently substituted the
process-wide `re-mvp` key, while the stateless deobfuscation runtime rejected
the missing key. FLOSS returned `sandbox_unavailable` before it attempted a
Kubernetes claim, even though the pool pod and FLOSS binary were healthy.

The missing identity also makes unrelated Dev UI invocations compete for the
same Radare2/Ghidra case and leaves their cleanup ownership ambiguous.

### Violated invariant

Every sandbox operation in one ADK invocation must resolve the same non-empty
case identity. Different entry points may supply that identity differently, but
tools must not invent private defaults.

### Root remediation

Introduce one domain-neutral sandbox-case resolver:

1. Preserve an explicit, non-empty `SessionKeys.SANDBOX_CASE_ID`.
2. Otherwise derive the identity from ADK's invocation ID and persist it into
   session state.
3. Reject the operation when neither source is available.

Radare2, Ghidra, UPX, FLOSS, and future sandbox tools must use this resolver.
Remove the `re-mvp` fallback from production tool paths.

### Verification

- Dev UI-shaped tool contexts with only an invocation ID resolve one stable
  case across Radare2, Ghidra, and deobfuscation.
- Explicit CLI case IDs remain authoritative.
- Missing state and missing invocation identity fail before a claim.
- Concurrent invocations resolve different cases.

## AI-002 — Recovery failures disappear at the loop boundary

**Status:** Implemented (238b194)

### Failure

The deobfuscation gate reads `UPX_DEGRADED_KEY`,
`FLOSS_DEGRADED_KEY`, and the current result to decide whether to exit, then
clears those same values in its state delta. Downstream stages cannot reliably
distinguish:

- recovery was unnecessary;
- recovery ran and found nothing;
- recovery was attempted but infrastructure failed; or
- recovery produced usable evidence.

The final report consequently omitted the FLOSS sandbox failure from its
limitations.

### Violated invariant

Iteration-local control markers may be reset, but terminal analysis outcomes
and limitations are immutable evidence for the remainder of the run.

### Root remediation

Separate mutable iteration state from durable outcome state. The gate resets
only call markers and progress counters. It writes a terminal recovery summary
containing the canonical artifact ID, UPX outcome, FLOSS outcome, error codes,
counts, and whether the loop exited because of completion, no progress,
degradation, p-code handoff, or the iteration cap.

Downstream prompts consume that summary explicitly. The evidence critic retains
supported failure/limitation records, and the report renders them.

### Verification

- A degraded FLOSS result survives loop exit unchanged.
- A later iteration cannot overwrite an earlier material limitation without
  retaining its history.
- Non-applicable recovery is not reported as failure.
- The report differentiates unsupported format, no recovered strings, and
  sandbox failure.

## AI-003 — Deep analysis completion is model-discretionary

**Status:** Implemented (1c88786, 696213c)

### Failure

In the observed session, Ghidra preparation completed successfully after
approximately 281 seconds. The deep-decompile agent then called only:

- `ghidra_metadata`;
- `ghidra_list_functions`; and
- `ghidra_imports`.

It never called decompilation, semantic search, strings, cross-references,
control-flow analysis, or p-code. It nevertheless declared that no deeper
patterns were visible. The prompt describes a deeper workflow, but the runtime
does not enforce completion.

### Violated invariant

A stage named deep analysis must not complete successfully with metadata-only
evidence.

### Root remediation

Make deep analysis a bounded worker-and-gate loop:

1. The worker prepares Ghidra and performs model-directed analysis.
2. Ghidra tool callbacks record successful semantic-search and
   decompile/p-code facts for the authoritative artifact.
3. A deterministic gate exits only after successful preparation, at least one
   cross-function semantic search, and at least one targeted decompile or
   p-code result.
4. The loop remains capped. If the cap is reached, durable state records an
   incomplete-analysis limitation rather than claiming semantic absence.

Metadata, imports, or a function-name page cannot satisfy the gate.

### Verification

- Metadata-only worker output causes another bounded iteration.
- Search plus targeted decompile/p-code satisfies the gate.
- Empty/degraded tool results do not satisfy it.
- Exhaustion produces an explicit incomplete limitation.
- Ghidra preparation remains once per artifact and reuses its claimed state.

## AI-004 — IOC extraction runs before the strongest evidence exists

**Status:** Implemented (51a4e85)

### Failure

The pipeline runs IOC extraction before deep decompilation. The network lens can
consume initial triage, retriage, and FLOSS findings, but it cannot consume
Ghidra strings or decompiled data produced later.

When FLOSS failed and Radare2 triage emitted no string findings, the network
lens had no canonical evidence and returned no indicators.

### Violated invariant

An evidence-synthesis stage must run after every evidence-producing stage whose
output it is required to consider.

### Root remediation

Reorder the spine to:

```text
sample_intake
→ triage_recon
→ deobfuscation
→ deep_analysis
→ ioc_extraction
→ behavior_characterization
→ attack_mapper
→ evidence_critic
→ malware_report_generator
```

IOC lenses receive explicit triage, recovery/FLOSS, and deep-analysis outputs.
They continue to preserve the original tool citation and canonical artifact
identity.

### Verification

- Composition tests lock the new order.
- Network IOC extraction receives deep-analysis state.
- A Ghidra-derived URL can reach the critic and report without FLOSS.
- A FLOSS-derived URL can reach the critic and report without Ghidra.

## AI-005 — Evidence handoff relies on ambient conversation history

**Status:** Implemented (ec18958)

### Failure

Most agents emit free-form `FINDING` blocks into shared conversational history.
Downstream agents infer which prior messages belong to which stage. In the
observed session, the evidence critic's own reasoning said its input appeared
cut off. This transport has no explicit completeness boundary and is sensitive
to context compaction, parallel-branch joining, unrelated model prose, and
stage ordering.

### Violated invariant

Authoritative inter-stage evidence must travel through named, bounded state
contracts. Conversation history may provide context, but it is not the evidence
bus.

### Root remediation

Assign explicit output keys to every evidence-producing stage:

- triage;
- recovery summary and FLOSS findings;
- deep analysis;
- host IOCs;
- network IOCs;
- behavior;
- ATT&CK mappings; and
- validated findings.

Prompts reference only these injected aliases for authoritative handoff. Each
stage emits a bounded JSON evidence envelope with canonical artifact identity,
findings, and limitations. A shared parser validates envelope shape before a
consumer trusts it. Invalid envelopes become explicit limitations rather than
silently disappearing.

### Verification

- Downstream prompts name every required state alias.
- Tests prove unrelated conversation text cannot become evidence.
- Parallel IOC outputs remain independently addressable after the join.
- Context compaction cannot remove state-backed findings.

## AI-006 — Evidence critic scope does not match the pipeline

**Status:** Implemented (5c0b616)

### Failure

The evidence critic runs after IOC extraction, behavior characterization, and
ATT&CK mapping, but its prompt says it receives only triage, retriage, and
deep-decompile findings. In the observed session it removed every host,
behavior, and ATT&CK finding while retaining metadata and imports.

It also failed to follow its overstatement rule: findings that should have been
retained at lower confidence were silently omitted.

### Violated invariant

The consistency gate must enumerate and validate every authoritative producer
that precedes it. Rejection must be attributable, and limitations must survive.

### Root remediation

The critic consumes the explicit evidence envelopes from all upstream stages.
Its contract:

- validates tool citation, artifact identity, detail support, recovery
  provenance, and finding type;
- preserves supported findings;
- lowers confidence and records a qualification when evidence supports only a
  capability primitive rather than observed behavior;
- rejects unsupported findings with a bounded rejection reason; and
- carries upstream limitations into the validated envelope.

The report generator consumes only this validated envelope.

### Verification

- Host, network, behavior, and ATT&CK findings are represented in critic tests.
- Import-only capability claims are qualified rather than promoted to observed
  data flow.
- Unsupported ATT&CK mappings are rejected with a reason.
- Recovery and deep-analysis limitations appear in the final report.

## AI-007 — Agent contracts permit false negative conclusions

**Status:** Implemented (51a4e85, 5c0b616, 696213c)

### Failure

Several agents reported absence rather than absence of evidence:

- deep decompile inferred no patterns without examining code;
- behavior characterization emitted capability claims without required data
  flow; and
- the final report rendered “no network IOCs” when the relevant decoder had
  failed.

### Violated invariant

Failure to observe is not evidence of absence unless the required analysis
surface completed successfully and its coverage is recorded.

### Root remediation

Evidence envelopes carry coverage and limitation fields. Negative conclusions
are allowed only when the corresponding coverage predicate is satisfied:

- network absence requires completed string/semantic coverage;
- behavioral absence requires completed deep-analysis coverage; and
- deobfuscation absence requires successful applicable recovery.

Otherwise stages emit “not determined” with the blocking limitation.

### Verification

- Failed FLOSS plus incomplete Ghidra yields “network indicators not
  determined,” never “none.”
- Complete searches with zero matches may yield a bounded negative finding.
- The report distinguishes observed absence from incomplete coverage.

## Threat-intelligence enrichment — shipped, and the invariant it amends

This was deferred out of the remediation above pending separate decisions for
provider credentials, sample/hash privacy, network egress, provenance, caching,
rate limits, and the distinction between locally observed evidence and
third-party intelligence. Those are now settled and hash-reputation enrichment
is implemented in `src/reverse_engineering/intel/`.

It amends one invariant this document previously stated without qualification,
that *all findings must derive from tools operating on the supplied artifact
inside AREMA's Kubernetes sandboxes*. That remains true of every finding except
one kind. The amended rule:

> Every finding whose `kind` is not `intel` derives from a tool operating on the
> supplied artifact inside AREMA's Kubernetes sandboxes. A finding whose `kind`
> **is** `intel` derives from a third-party service that was asked about the
> artifact's SHA-256, never about its contents, and is required to be labelled
> as such everywhere it appears.

The exception is deliberately narrow and structurally enforced rather than left
to prose. `FindingKind.INTEL` exists so the boundary is a field a consumer can
branch on: the critic does not demand a source-to-sink path from an intel
finding, the report renders them in their own section under an explicit "not
derived from this analysis" line, and the stage that decides the verdict may
weigh them while being forbidden to restate them as claims about the code.

How the seven contracts resolved:

- **Credentials** — a domain-local `IntelSettings`, never a field on the neutral
  core's `Settings`, which `tests/unit/core/test_config.py` asserts by name must
  not carry a vendor key.
- **Sample/hash privacy** — the 64-character digest is the only thing that
  leaves the host. No filename, no path, no bytes. Nothing uploads a sample, and
  no upload path exists to be enabled: a lookup asks whether a fingerprint has
  been seen, while an upload publishes the file permanently to the receiving
  service's partners and cannot be undone.
- **Network egress** — host process only. Every sandbox pool declares
  `networkPolicy.egress: []`, and per lesson #15 a dropped packet in there
  becomes a multi-minute hang rather than a fast failure, so a pod could not do
  this even if the policy allowed it.
- **Provenance** — the new kind, plus a fixed tool name per source that must
  also appear on the critic's allowlist.
- **Caching** — none. One acquire per run means one sweep per run, well inside
  every quota. The ceiling is a repeated acquire costing one extra request per
  source; the upgrade path is a memory-store codec keyed by digest.
- **Rate limits** — no limiter. VirusTotal's free tier allows 4 requests per
  minute and 500 per day against at most one request per run. The
  `ToolLifecycleCallbacks(before=...)` seam is where one goes if that changes.
- **Observed vs third-party** — the amended invariant above.

Two properties keep it inert until asked for. `IntelSettings.active_sources`
returns nothing when no credential is configured, so an unconfigured checkout
makes no outbound request at all, including to the keyless source. And every
source fails open independently, so a dead endpoint costs its own timeout and
never the acquisition it rides on.

