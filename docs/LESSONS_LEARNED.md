# AREMA — Lessons Learned

Hard-won insights from building an autonomous reverse-engineering agent pipeline
on Google ADK. Each entry is a real bug, its root cause, and the fix — the kind
of knowledge that only surfaces when you run agents against live binaries in a
real Kubernetes sandbox.

---

## 1. Prompt-directed agent transfers are fragile — use framework orchestration

**Symptom:** On complex binaries (4600 functions), the 5-agent pipeline (triage →
deep_decompile → evidence_critic → report) gets stuck. Agents re-enter each other
in loops. The evidence_critic is invoked with incomplete, chaotic context and
can't complete. The session hangs indefinitely.

**Root cause:** The pipeline relied on `transfer_to_agent` calls directed by
prompts ("when done, transfer to the next agent"). ADK's transfer model lets any
sub-agent transfer to any sibling — the model doesn't always follow the intended
linear sequence. On long, complex analyses the model loses track of pipeline
state and re-delegates to agents that already ran, creating loops.

**Fix (shipped, B.5):** The `reverse_engineer` root is now an ADK
`SequentialAgent` shell built by `build_sequential_agent` in the neutral core.
Its five stages — `sample_intake` → `triage_recon` → `deep_decompile` →
`evidence_critic` → `report_generator` — run in a fixed, framework-enforced
order, each to completion before the next. Ingest (`acquire_sample` +
`prepare_sandbox`) moved to the new `sample_intake` first stage. The analysis
prompts no longer direct transfers. Zero `transfer_to_agent` calls occur inside
the pipeline; the only LLM-directed hop is `greeter → reverse_engineer` (one
robust top-level routing decision). `build_parallel_agent` / `build_loop_agent`
ship alongside as the ready foundation for NORTH_STAR Axis-2 consensus and the
deobfuscation loop.

**Lesson:** Never rely on the LLM to direct agent execution order on complex tasks.
Use framework-enforced orchestration (SequentialAgent, ParallelAgent) for any
pipeline with more than 2-3 agents.

---

## 2. `asyncio.wait_for` poisons the exception chain with `CancelledError`

**Symptom:** A transient MCP timeout (the server was briefly unavailable) crashed
the entire ADK event generator instead of degrading gracefully. The
`ResilientMcpToolset` — designed to catch errors for optional servers and return
no-tools — re-raised the error instead of catching it.

**Root cause:** `asyncio.wait_for` cancels its inner task on timeout by sending a
`CancelledError`. This `CancelledError` remains in the exception's `__context__`
chain. The `_is_cancellation` function walked the chain, found the
`CancelledError`, and returned `True` — treating a timeout as a genuine
cancellation. The code then re-raised (to propagate real cancellations during
shutdown), crashing the run.

```
ConnectionError → __cause__: TimeoutError → __context__: CancelledError (from wait_for)
```

**Fix:** Check for `TimeoutError` first in the chain. If present, the
`CancelledError` below it is from `wait_for`'s timeout mechanism, not a genuine
cancellation — return `False` so the optional server degrades gracefully.

**Lesson:** `asyncio.wait_for` uses `CancelledError` internally. Any code that
walks exception chains looking for `CancelledError` must distinguish
`wait_for`'s internal cancellation from a genuine task cancellation. A
`TimeoutError` in the chain is the distinguishing signal.

---

## 3. Port-forward readiness is application-layer, not transport-layer

**Symptom:** The MCP client crashed immediately after the port-forward opened.
The TCP port was open (the r2mcp HTTP server was listening), but the MCP
StreamableHTTP handler wasn't ready for the `initialize` handshake.

**Root cause:** `PortForwardRegistry.open()` spawned `kubectl port-forward` via
`subprocess.Popen` and returned immediately — before the tunnel was forwarding.
Even after adding a TCP-connect readiness check, the MCP session still failed
because TCP connectivity only proves the port is open, not that the MCP
application layer is handling requests.

**Fix:** The readiness check sends an HTTP GET to the MCP endpoint
(`http://127.0.0.1:8765/mcp`). Any HTTP response (including 400/405 error codes)
proves the application layer is up. The check blocks `open()` until the endpoint
responds, guaranteeing the MCP client connects to a ready server.

**Lesson:** Transport-layer readiness (TCP connect) is necessary but not
sufficient for application-layer protocols. Always validate at the layer the
client actually uses — HTTP for MCP StreamableHTTP, not just TCP.

---

## 4. MCP `read_timeout` must accommodate the longest tool call

**Symptom:** The r2 `analyze` command (auto-analysis `aaa`) on a 1.7 MB binary
(Apache httpd) took 2-4 minutes. The MCP `read_timeout` was set to 120s. The
timeout fired mid-analysis, the MCP connection dropped, ADK reconnected with a
new session, and r2mcp lost its per-session `open_file` state. Every subsequent
call failed with "Use the open_file method before calling any other method."

**Root cause:** The `read_timeout` was lowered from 600s to 120s as a fix for a
previous hang. But that hang's root cause was a DIFFERENT bug (the
`strict_tool_calls` feature forced optional numeric parameters to be required,
the model filled them with empty strings, and r2mcp rejected them). That bug was
fixed independently by `json_repair` (which replaced `strict_tool_calls`). The
120s timeout was an overcorrection for a problem that no longer existed.

**Fix:** Made `read_timeout` configurable via `AREMA_MCP_READ_TIMEOUT` (default
600s). Applied to all MCP server descriptors at composition time. The 600s value
accommodates `analyze` on binaries up to ~10 MB.

**Lesson:** When a timeout fix addresses a symptom of a different root cause,
revert the timeout after the root cause is fixed. A timeout that's too short for
legitimate operations is worse than one that's too long for failures. Make
timeouts configurable so operators can tune per-environment.

---

## 5. LLM-generated tool-call JSON vs. CLI tool output JSON

**Symptom:** The `ghidra-rpc load` command outputs multi-line pretty-printed JSON.
The code parsed only the last line (`splitlines()[-1]`), which was `}` — not
valid JSON. The `short_name` extraction failed silently, and all subsequent
ghidra tool calls used the SHA-256 hash as the binary name (which ghidra-rpc
couldn't find).

**Root cause:** Two bugs in one line:
1. `splitlines()[-1]` on pretty-printed JSON takes only the closing brace.
2. `short_name` is nested under `result.short_name`, not at the top level.

**Why json_repair didn't help:** `json_repair` fixes malformed JSON in
**LLM tool-call arguments** (the `function.arguments` field the model generates).
It does NOT repair JSON in tool **outputs** (CLI stdout, MCP responses). These
are different failure modes at different layers of the stack.

**Fix:** Parse the entire stdout as JSON. Extract `short_name` from the nested
`result` field.

**Lesson:** `json_repair` is scoped to LLM-generated JSON only. Tool output JSON
parsing must be correct independently. When wrapping a CLI tool, test against
real output — the format (pretty-printed vs compact, nesting structure) often
differs from the documentation.

---

## 6. Each analysis agent must prepare its own engine

**Symptom:** `prepare_ghidra` was registered on the root agent
(`reverse_engineer`). The root's workflow said "call prepare_ghidra between
triage and deep_decompile." But `prepare_ghidra` was never called — the Ghidra
tools reported "not prepared for this case."

**Root cause:** In ADK's transfer model, once the root delegates to a sub-agent
(`transfer_to_agent("triage_recon")`), the sub-agent runs autonomously and
transfers to the next agent. The root **never regains control** between
sub-agent delegations. A tool on the root's `tool_ids` that should be called
between two sub-agent delegations is unreachable.

**Fix:** Move `prepare_ghidra` to `deep_decompile`'s own `tool_ids`. Each
analysis agent prepares its own engine before using it — `deep_decompile` calls
`prepare_ghidra(artifact_id)` as its first action.

**Lesson:** In ADK's LlmAgent transfer model, the root agent cannot call tools
between sub-agent delegations. Tools that an agent needs must be on THAT agent's
`tool_ids`, not the root's. This is analogous to the transfer-target lesson:
each agent's prompt must specify the correct next transfer target, not a
hypothetical "return to root for the next step."

---

## 7. Ghidra 11.4.x requires JDK 21, not JDK 17

**Symptom:** The Ghidra daemon failed to start inside the sandbox pod:
`LaunchSupport.jar -jdk_home` returned exit 1 with "unsupported java version."

**Root cause:** Ghidra 11.0-11.3 require JDK 17. Ghidra 11.4+ requires JDK 21.
The Dockerfile installed `openjdk-17-jdk-headless` (Debian Bookworm's default).
Debian Bookworm doesn't ship JDK 21 at all — only Debian Trixie (13) does.

**Fix:** Switched the base image from `debian:bookworm-slim` to
`eclipse-temurin:21-jdk` (provides JDK 21 + correct `JAVA_HOME`). The
`ghidra-rpc` README says "Java 17+" but that's the minimum for the Python
wrapper; the actual Ghidra version dictates the JDK requirement.

**Lesson:** Always verify the JDK requirement for the specific Ghidra version,
not the wrapper tool's stated minimum. Use `eclipse-temurin` as the base for
Ghidra containers — it's arch-portable (`JAVA_HOME` is correct on both amd64
and arm64) and ships the right JDK.

---

## 8. The agent over-analyzes large binaries — bound the triage

**Symptom:** On a 1.7 MB binary (httpd) with 4600 functions, the triage agent
decompiled many functions, gathered extensive strings, and ran for 15+ minutes
without completing. The prompt said "be selective" but the model didn't comply.

**Root cause:** The triage prompt says "do not exhaustively decompile every
function" and "be selective," but these are soft guidelines. On an interesting
binary with many named functions (TP-Link router firmware with function names
like `httpPwdDecode`, `webServerInit`), the model explores aggressively. With no
hard bound (max function count, max tool calls, max time), the triage runs
unbounded.

**Fix (planned):** Add hard bounds to the triage prompt — "decompile at most 3-5
functions," "emit at most 15 findings," "stop after gathering the essential
triage picture." Consider a turn limit or tool-call budget specific to triage.
The NORTH_STAR Phase 1 envisions a "triage bundle" — a structured, bounded
output artifact — rather than open-ended exploration.

**Lesson:** LLM agents need hard bounds on exploration, not just soft guidance.
Without explicit limits, an agent with interesting tools on an interesting
binary will keep exploring indefinitely. Bound the output (max findings, max
decompilations) to keep the pipeline moving.

---

## 9. Sandbox claim cleanup races with the k8s client tunnel teardown

**Symptom:** At run end, `executor.release_session()` raises `SSLError`
(FileNotFoundError — the k8s API tunnel is already torn down). The error is
non-fatal but leaves orphaned `sandboxclaim` resources. The verbose urllib3
traceback floods the logs.

**Root cause:** The k8s-agent-sandbox client's local tunnel (kubectl port-forward
to the API server) is torn down before the `sandboxclaim` deletion request
completes. The deletion request fails because the tunnel is gone.

**Fix:** The `release_case` helper retries on `OSError` (which includes
`SSLError`) with a short backoff, then falls back to a direct
`kubectl delete sandboxclaim --all` command. Both paths are fail-open — the
analysis always completes before cleanup runs. Orphaned claims are pruned via
`make sandbox-prune`.

**Lesson:** In local-tunnel k8s setups, the API connection is ephemeral. Cleanup
operations that depend on the API must handle its disappearance gracefully.
Retries + a direct-kubectl fallback + a prune command form a defense-in-depth
cleanup strategy.

---

## 10. Domain-neutral code must not mention domain terms — enforced by tests

**Symptom:** Adding a comment about "r2mcp" in `src/arema/core/config.py` (the
neutral core) caused the architecture test to fail: "No src/arema module
hardcodes a concrete domain tool/pool name."

**Root cause:** The architecture test
(`tests/architecture/test_neutral_boundaries.py`) scans all of `src/arema` for
domain terms (`radare2`, `r2mcp`, `ghidra`, `ilspycmd`). Even a COMMENT
mentioning "r2mcp" in the neutral core triggers the failure.

**Fix:** Made the comment domain-neutral ("an analysis engine in a sandbox pod"
instead of "r2mcp in a sandbox pod").

**Lesson:** The neutrality perimeter is enforced at the source-text level, not
just the code level. Comments, docstrings, and variable names in `src/arema`
must not mention domain-specific tools. This is a feature, not a bug — it
prevents the neutral core from accidentally coupling to a specific domain.

---

## 11. The `make check` lint scope must cover all source packages

**Symptom:** Unused `# noqa` directives and formatting issues in
`src/reverse_engineer/` were never caught by `make check`. The Makefile's lint
target only covered `src/arema`.

**Root cause:** `SRC := src/arema` in the Makefile. As new domain packages were
added (`src/greeter_agent`, `src/reverse_engineer`), they weren't included in
the lint/typecheck scope. Issues slipped through silently.

**Fix:** Extended `SRC` to `src/arema src/greeter_agent src/reverse_engineer`.
Future domains are covered if they're added to the list (or if `SRC` is changed
to `src`).

**Lesson:** When the project structure grows (new packages, new domains), update
the quality-gate scope. A lint/typecheck target that doesn't cover all source
code provides false confidence. New packages should be added to the Makefile's
`SRC` list as part of the add-a-domain recipe.

---

## 12. Ghidra's decompiler is a native binary — the official release omits linux_arm_64

**Symptom:** On every binary (httpd *and* `/bin/ls`), `ghidra_decompile` and
`ghidra_pcode` returned empty output while `ghidra_metadata`/`list_functions`/
`imports`/`xrefs_to`/`strings`/`disassemble`/`basic-blocks` worked. The agent's
report said "Decompilation Unavailable" and "empty C code or errors." This was
latent from B.4 (the Ghidra 2nd-engine slice) — B.4's live-verification
produced findings via the non-decompiler tools, so the empty decompilation went
unnoticed.

**Root cause:** Ghidra's decompiler is a **native binary** (`os/<arch>/decompile`)
spawned as a subprocess; the rest of Ghidra (metadata, listing, xrefs) is pure
Java and needs no native. Ghidra 11.4.1's official release ships the decompiler
native for `linux_x86_64` / `mac_arm_64` / `mac_x86_64` / `win_x86_64` — **not
`linux_arm_64`**. The sandbox runs on arm64 nodes (Apple Silicon), so Ghidra's
`DecompileProcessFactory` logged `os/linux_arm_64/decompile does not exist ...
Could not find decompiler executable` and the decompiler never ran.
`ghidra-rpc` then returned `ok:true` with an empty `result.c_code` — and the
AREMA wrapper returned `success:True` on that empty output, silently hiding the
failure. (The httpd endianness discrepancy in the report was a red herring — the
language and disassembly were correct.)

**Fix (shipped):**
1. **Root cause — image** (`images/ghidra-rpc/Dockerfile`): on aarch64 build
   hosts, build the missing `linux_arm_64/decompile` native from Ghidra's bundled
   C++ source and purge the build toolchain afterward:
   `apt install g++ bison flex make binutils-dev` (`binutils-dev` for `bfd.h` —
   the non-obvious dep), then
   `make ghidra_opt ARCH=aarch64 OSDIR=linux_arm_64 ARCH_TYPE=` (empty
   `ARCH_TYPE=` — the Makefile's default `-m32` is invalid on arm64; its arch
   branch predates aarch64 and carries a `TODO`), install `ghidra_opt` as
   `os/linux_arm_64/decompile`. Build the `ghidra_opt` target (the Ghidra-integrated
   decompiler), not `decomp_opt` (standalone). Verified the binary still runs
   after purging the toolchain.
2. **Defense-in-depth — tool wrapper** (`tools/ghidra/toolset.py`): introspect
   the `ghidra-rpc` JSON and return a `degraded` result when `ok` is false or the
   result field (`c_code` for decompile, `ops` for pcode `--high`) is empty, so a
   future decompiler failure is visible instead of silent success.

**Lesson:** A tool whose decompiler is a native subprocess can fail silently on
a new architecture while every *other* feature works — verifying "the engine
runs" via metadata/listing is not enough; you must verify the *decompiler*
produces output. When a release omits a native for your arch, build it from the
bundled source (Ghidra ships the C++), mind the `-m32`/arch-branch gotcha, and
make empty decompiler output a loud failure, not a quiet one.

## 13. ADK `output_schema` aborts the whole pipeline when a model turn is non-conforming

**Symptom:** After switching the evidence stages from prose-parsing to ADK's
`output_schema` coercion (structured output), the malware-analysis pipeline
would produce a *truncated* report: `triage`/`recovery`/`deep` completed, but
`host_indicators`, `network_indicators`, `behavior_characterization`,
`attack_mapper`, and `evidence_critic` all produced **no output** and the run
exited non-zero. The deep evidence itself was valid — coercion was working — yet
everything downstream vanished.

**Root cause:** ADK's `LlmAgent` validates the final model response against
`output_schema` in a private hook (`__maybe_save_output_to_state`) and
**re-raises** the pydantic `ValidationError` when the payload does not conform.
On a *redundant* `deep_decompile` loop pass, the model — believing it was already
done — emitted prose ("**Coverage complete.** … proceeds to next stage.")
instead of calling the synthetic `set_model_response` tool. ADK ran
`output_schema.model_validate_json("**Coverage complete.** …")` →
`ValidationError: Invalid JSON` → the exception propagated out of the enclosing
`SequentialAgent` root and killed every remaining stage. `output_schema` turned
what used to be a *fail-open* degradation (a prose turn just yielded a low-value
envelope) into a *fatal* one.

**Fix (shipped):** `runtime/agent_factory.py` builds every `LlmAgent` as a thin
`_CoercedLlmAgent` subclass that overrides ADK's name-mangled save hook
(`_LlmAgent__maybe_save_output_to_state`) to catch `ValidationError`, log it, and
leave the stage's `output_key` **unset** (any prior loop-pass value is
preserved). The after-agent evidence normalizer then records a coverage
limitation for that one stage and the pipeline continues. `output_schema` remains
the primary coercion mechanism; only the crash-on-reject behavior changes. An
import-time guard asserts the hook name still exists so a future ADK release that
renames it fails loud instead of silently reintroducing the crash.

**Lesson:** Framework-level structured-output coercion is the right primary
mechanism (deterministic, no prose-scraping), but ADK's default is to *raise* on
a non-conforming turn — and inside a `SequentialAgent`/`LoopAgent` one raised
stage aborts the entire run. Any per-stage failure in a long pipeline must
**fail open to that stage**, never to the whole pipeline. When the framework
only exposes the seam as a private method, override it deliberately and guard the
private name so the coupling can't rot silently.

## 14. Ghidra OOM-kills (exit 137) at a memory *limit* because the JVM heap is cgroup-derived

**Symptom:** `ghidra_search_decompiled` failed with `RuntimeError` and the agent
noted "the search failed with an OOM/crash (exit 137)". Coverage came back
`partial` with `deep:ghidra_search_decompiled_failed` and
`target_analysis_succeeded: false` — no decompilation/semantic-search surface was
ever produced, which starved the downstream IOC/behavior/ATT&CK lenses (all
returned empty findings) and yielded a "Decompilation failed … network not
determined" report. Exit 137 = 128 + SIGKILL(9): the kernel **cgroup OOM-killer**,
not a Java `OutOfMemoryError`.

**Root cause:** The ghidra-rpc pod carried `limits.memory: 4Gi` and set **no**
`-Xmx`/Ghidra `MAXMEM`. JDK 21 is cgroup-aware, so with no explicit heap it
derives `MaxHeapSize` from `MaxRAMPercentage=25%` → **~1Gi** under a 4Gi cap.
Ghidra's decompiler is a **native C++ subprocess spawned per function** (see
lesson 12) whose memory is *off-heap*; decompiling a binary with hundreds of
functions drove total pod RSS (1Gi heap + native decompiler + metaspace +
mmap'd files) past the 4Gi cgroup limit and the OOM-killer terminated it. The
1Gi heap was itself far too small for the analysis, and the fixed limit left no
room for the native side to grow.

**Fix (shipped):** `deploy/sandbox/10-ghidra-rpc-template.yaml`:
1. **Remove `limits.memory`** so the container is bounded only by the (ample)
   node — the JVM heap *and* the off-heap native decompiler can grow as a large
   binary demands. `requests.memory: 4Gi` keeps the pod Burstable so the
   scheduler still reserves a floor. (CPU stays capped.)
2. **Set `_JAVA_OPTIONS: -Xmx12g`** so the heap gets an explicit, generous
   ceiling instead of the ~1Gi cgroup ergonomic. `_JAVA_OPTIONS` takes final
   precedence over anything pyghidra/Ghidra sets, and its "Picked up …" banner
   goes to **stderr**, which `kubectl_exec` discards (it parses stdout only), so
   it cannot corrupt tool JSON.
3. **Retry the load on transient kills** (`tools/ghidra/prepare_ghidra.py`): once
   the fixed cap was gone, a *second* failure mode surfaced — the sandbox node is
   a Docker VM **shared with other heavy JVM workloads** (a Trino cluster in our
   case), so free memory is variable and a contention spike can make the kernel
   SIGKILL the analysis (again exit 137) even with no cgroup limit. k8s
   `requests` cannot reserve against processes *outside* the cluster, so the only
   real defenses are a leaner footprint and resilience. `prepare_ghidra` now
   retries the whole start+load sequence (`_LOAD_ATTEMPTS`, backoff long enough
   for a spike to pass), restarting the daemon each attempt so a half-dead JVM
   can't poison the reload; if every attempt is killed it degrades the stage
   (the pipeline's fail-open carry-forward still produces a report from FLOSS +
   triage evidence).

**Lesson:** A JVM tool in a container with a memory *limit* but no explicit
`-Xmx` runs on a heap the JDK silently derives from that limit (25% by default) —
so a "4Gi pod" may run Ghidra on a 1Gi heap and still OOM-kill, because a native
subprocess consumes the *other* 3Gi off-heap. Set the heap explicitly (don't
trust the ergonomic), and for a workload with an unbounded native side, don't box
it under a fixed memory limit — size the request and let it burst against the
node. Exit 137 is always the cgroup/kernel killer, never a Java heap exception;
that distinction tells you it's a *memory-availability* problem, not an `-Xmx`
one — here it was both a too-small heap *and* a too-small cap. And once the cap
is gone, remember the node is shared: a kill can come from *external* memory
pressure the scheduler can't see, so the heavy, killable step needs a retry, not
just a bigger number.

## 15. A "deny-all egress" can be a silent no-op — the framework's default policy allows the internet, and a DROP makes offline tools *hang*

**Symptom:** The analysis-workbench pool carried `30-analysis-workbench-denyall-egress.yaml`
(podSelector `arema.dev/pool`, empty egress) and `make sandbox-verify-egress`
reported **PASS**, yet a live warm-pool pod could open TCP connections to the
public internet (`1.1.1.1:443`). The deny-all was dead weight. Then, once egress
was *actually* enforced, the .NET analysis **hung for minutes** (`dotnet-script`
restore, `ilspycmd` on a malformed assembly) instead of completing.

**Root cause — three compounding issues:**
1. **The framework's DEFAULT managed policy allows internet egress.** The
   agent-sandbox `SandboxTemplate` has `networkPolicyManagement: Managed`; when
   `spec.networkPolicy` is unset it GENERATES a NetworkPolicy that allows egress to
   `0.0.0.0/0` minus private ranges. K8s NetworkPolicies are **additive (OR)**, so
   that allow-internet policy negated our standalone deny-all. Our policy selected
   pods by `arema.dev/pool`; the framework's selected them by
   `agents.x-k8s.io/sandbox-template-ref-hash` — both matched the warm-pool pod,
   union = allow.
2. **`verify-egress-denied.sh` tested the wrong pod.** It probed a `kubectl run`
   pod carrying only the pool label — which is *not* subject to the framework's
   managed policy — so it validated the standalone deny-all in isolation and
   returned PASS while the real warm-pool pods (which also carry the template-hash
   label) leaked. **False assurance.**
3. **A NetworkPolicy denies by DROP, not REJECT.** Under `--network none` a
   tool's network call fails *instantly* (unreachable) and falls back to its
   offline path; under a Calico deny-all the SYN/DNS packet is silently **dropped**,
   so the call hangs on the full TCP/DNS timeout chain (amplified by `ndots:5`
   search-domain expansion) — minutes, not milliseconds.

**Fix (shipped):**
- **Declare the deny-all in the template, not beside it.** `10-analysis-workbench-template.yaml`
  now sets `spec.networkPolicy: {egress: [], ingress: []}` so the framework's
  *managed* policy (the one that reliably selects warm-pool pods) denies all
  traffic. `30-…denyall-egress.yaml` is kept only as a defense-in-depth second
  layer.
- **Verify the real pod.** `verify-egress-denied.sh` now `kubectl exec`s the probe
  inside a live warm-pool pod (subject to the managed policy), with a plain
  no-label baseline pod to prove node egress works.
- **Make the sandbox truly offline so nothing reaches for the network.**
  `dotnet-script` is wrapped to force `--sources /opt/nuget-offline` (restores
  from the prewarmed global cache, never nuget.org); DNS is pointed at a
  non-listening resolver with `timeout:1 attempts:1 ndots:1` so any hostname
  lookup fails in ~0s; a writable `/tmp` emptyDir is added (the .NET first-run
  configurer's `NuGet-Migrations` mutex needs it on the read-only rootfs). With
  all three, the ConfuserEx `.NET` analysis completes **in-pod under enforced
  deny-all egress in ~17s** (de4dot insufficient → dnlib metadata round-trip →
  ilspycmd loads ~21 MB of C#).

**Lesson:** "The NetworkPolicy object exists" and even "a labelled probe pod is
blocked" are both false assurance — a managed-sandbox framework may inject its own
allow-egress policy, and K8s policies only ever *add* permits, so you must verify
on the **actual** workload pod, and prefer expressing the deny *through* the
framework's own policy mechanism rather than racing it with a standalone object.
Separately, a deny-all egress changes tool failure from fast-fail to **hang**: an
"offline" sandbox is only offline if its tools never *attempt* the network
(pin package sources to a local cache, make DNS fail fast) — otherwise every
dropped packet becomes a multi-minute stall.

---

## 16. `output_schema` is not a substitute for the fence-tolerant JSON boundary

**Symptom:** A full live run on a .NET assembly completed all 16 stages with zero
tracebacks and produced a report containing **one** accepted claim. Seven of eight
stages reported `<stage>:evidence_envelope_invalid`. ILSpy had genuinely run —
`analyze_assembly` ×7, `search_members_by_name` ×6, `search_strings` ×3 — and
`triage_recon` had emitted a well-formed envelope carrying eight findings. All of
it was discarded between the model and the report. Nothing failed loudly: the
pipeline is designed to fail open, so a total evidence loss looked like a green run.

**Root cause:** Lesson #13 closed by keeping `output_schema` as "the primary
coercion mechanism", having found it unreliable only when combined with tool use
(fixed in `a8cb168` by dropping it from tool-using agents). That diagnosis was one
layer too shallow. The real variable is not tool use, it is **who parses the text**.

Measured directly against the configured provider with **no tools attached**, and
with ADK's own request shape — `response_mime_type: application/json` plus a
`response_schema` — the model still answered:

```
part[0] thought=True   1751 chars   <- reasoning, correctly excluded by ADK
part[1] thought=None    144 chars   <- '```json\n{ ... }'   <- fenced anyway
```

ADK stores the non-thought join and coerces it with
`output_schema.model_validate_json(...)`, a strict parser that cannot see through a
Markdown fence. So the schema'd stages failed 100% of the time, `_CoercedLlmAgent`
swallowed each `ValidationError` exactly as #13 designed, and each stage's output
was left unset. Meanwhile the *unschema'd* stages parsed the identical text
correctly, because their after-agent normalizer routes through `loads_model_json`:

```
loads_model_json(fenced)          -> OK      (fence stripped, json_repair fallback)
ADK model_validate_json(fenced)   -> ValidationError
```

`output_schema` was quietly the one path in the system that bypassed the "single
robust model->JSON boundary" every other parser is required by an architecture
test to use.

**Fix (shipped):** No stage declares `output_schema`. `triage_recon`,
`host_indicators`, `network_indicators`, `behavior_characterization`,
`attack_mapper` and `evidence_critic` all already had an after-agent normalizer;
those normalizers now own parsing, through the fence-tolerant boundary.
`_CoercedLlmAgent` stays as the fail-open guard for any future schema'd agent.
`tests/malware_analyst/test_evidence_handoff.py` previously asserted the opposite
invariant, with the comment "the model cannot emit fenced/prose text" — it now
asserts that no evidence producer declares `output_schema`, and
`test_agent_factory.py` pins the mechanism directly: the same fenced payload is
dropped with a schema and stored verbatim without one.

**The sequel, found while verifying the fix:** removing `output_schema` also
removes a guard that only existed on that branch. ADK assigns the joined
non-thought text to `output_key` *unconditionally*, and skips the assignment for
an empty result only inside `if self.output_schema:` (its own comment: "this is an
empty final chunk of a stream"). Without a schema, a streamed turn whose final
event carries no text therefore overwrites a perfectly good envelope with `""`.
The verification run showed exactly that: `triage` and `deep` had produced real
envelopes, and the dumped raw for both was `''`. `_CoercedLlmAgent` now applies the
empty guard on both paths, treating a reasoning-only turn as empty too, since ADK
excludes `thought` parts from the join. Measured across three identical live runs
on the same sample: **7 stages losing their evidence -> 3 -> 0**.

**Lesson:** A provider's structured-output mode is a *request*, not a guarantee —
`response_mime_type: application/json` did not stop this one fencing its answer.
So the tolerant parser must sit on **every** path that turns model text into
JSON, including the framework's own. The failure mode is what makes this
expensive: fail-open degradation plus per-stage isolation meant a run that lost
essentially all of its evidence still exited clean, with a plausible-looking
report. Fail-open needs a loud aggregate signal — when most stages of a run
report `evidence_envelope_invalid`, that is a broken pipeline, not a degraded one.

---

## 17. A stage can lose its evidence in three ways that all look identical

**Symptom:** After #16, live runs still lost whole stages. Six back-to-back runs
on the same two samples showed `triage`, `deep` and `native` reporting
`<stage>:evidence_envelope_invalid` in runs 1-4, while the transcript plainly
contained a complete, well-formed envelope with real findings. Every failure
logged the same thing — `error_type=ValidationError` — and nothing else.

**Root cause:** Three unrelated faults, indistinguishable from that one line.

1. **The turn carried more than one JSON value.** `json_repair` recovers every
   value it finds and returns a **list**; validating a list against an object
   model fails at the *root*, so the whole stage was discarded while a good
   envelope sat in element 0.
2. **The provider misrouted the answer into the reasoning channel.** ADK stores
   only non-`thought` parts, which is right — reasoning is not an answer — but
   when the *entire* answer lands there the stage stores nothing at all. This is
   what kept `dotnet_decompile` (the ILSpy deep stage) empty; the salvage now
   rescues 2.6-4.0 KB payloads for it on most runs.
3. **An empty final chunk overwrote a real answer** (#16's sequel).

**Fix (shipped):** Diagnostics first, because the fix could not be found without
them. The failure log gained two content-free fields: `rejected_fields`, taken
from pydantic's own `errors()` as `field.path:failure_kind`, and `payload_type`,
the type the text decoded to. The value stays out — it is model-controlled — but
the *location* and the *shape* are facts about our own schema. That turned an
opaque `ValidationError` into `payload_type=list rejected_fields=[':model_type']`,
which names cause 1 outright, and `payload_type=NoneType`, which names cause 2.

Then: `parse_evidence_envelope` / `parse_critic_judgment` select the single
object carrying the shape they require when decoding yields a list — by shape,
never content or position, and all-or-nothing, so two envelopes are refused
rather than guessed between. And `_CoercedLlmAgent` stores reasoning-channel text
when the answer channel is empty **and that text carries a structured payload**;
narrative reasoning is excluded, or a trailing reasoning-only event would
overwrite what an earlier one saved.

Measured across six runs on the same samples: stages losing evidence went
**2, 2, 2 → 1 → 0, 0** as each fix landed, and the final coverage limitations went
from `deep:evidence_envelope_invalid, deobfuscation:retriage_snapshot_invalid` to
`[]`. Zero tracebacks throughout — this never announced itself.

**Lesson:** When a failure is swallowed by design, the log *is* the product. Three
different faults presented as one indistinguishable line for weeks, and each
diagnosis cost a temporary patch-in-a-raw-dump cycle. A privacy rule of "log
nothing about the payload" is too blunt: type names and schema field paths carry
no model content and are exactly what makes the difference between "malformed"
and "never an object". Add them permanently, not as debugging scaffolding — and
be equally disciplined the other way, because a diagnostic that cries wolf (the
readiness probe's self-inflicted "connection reset by peer") buries the real
signal just as effectively as no diagnostic at all.

---

## 18. A working fallback hid a primary path that had never once succeeded

**Symptom:** Every run, every pool, without exception:

```
k8s sandbox client terminate failed; falling back to kubectl
    error_type=MaxRetryError pool=radare2-mcp
```

Three to five of these per run across six consecutive runs. Nothing leaked —
`kubectl delete sandboxclaim` always did the job — so it read as a benign
degradation note rather than a defect.

**Root cause:** `release_all_cases` was wired **only** to `atexit`. Nothing
released the run's claims when the pipeline finished, so the release always
happened during interpreter shutdown — and by then the kubernetes client had
already dropped its transport in its own `atexit` handler. The executor's own
`terminate()` could therefore never succeed. Not "rarely": *never*, because the
ordering is structural rather than racy.

The fallback was doing 100% of the work, which is exactly why nobody noticed. The
comment above it even described the cause correctly ("the kube client transport
can be dead at interpreter exit") and treated it as an edge case to tolerate,
rather than as a reason to stop releasing at exit.

**Fix (shipped):** `release_case_at_pipeline_end` hangs on the domain root's
`after_agent_callbacks`, so claims are released the moment the pipeline finishes,
while the process and its client are still healthy. The `atexit` sweep stays as
the backstop for a crashed or interrupted run, and finds nothing after a clean
one. A test pins the wiring, not just the callback: a root that loses it silently
regresses to the path where the primary release cannot work. Measured live:
fallback warnings per run went **3 → 0**, with no leaked claims.

**Lesson:** A fallback that always fires is not resilience, it is a broken primary
path with the alarm muted. Treat "the degraded path ran" as an error budget:
if it never returns to zero, the thing it was protecting is dead. This is the
same shape as #16 — fail-open machinery working perfectly while the capability it
protected produced nothing — and it is worth a periodic audit of every fallback,
retry, and `except: pass` that has quietly become the normal path.

---

## 19. A strict schema at a model boundary is all-or-nothing, so one bad field costs a whole stage

**Symptom:** After #16 and #17 had removed three separate causes of
`<stage>:evidence_envelope_invalid`, a live run on a UPX-packed ELF still lost the
whole deep stage. The report was honest about it — `deep:evidence_envelope_invalid`
in the limitations, and a behavior stage reporting "insufficient evidence ... due to
empty or invalid upstream findings" — but Ghidra had run, and its findings existed.

**Root cause:** `EvidenceEnvelope` is strict on purpose: `extra="forbid"`, a closed
`kind` enum, bounded strings, an exact artifact match. `normalize_evidence_output`
validated the entire payload in one call, so *any* rejection anywhere replaced
*everything* with a failed envelope. Measured against the model, each of these
discards a whole stage:

| emitted | rejection |
|---|---|
| `detail` omitted, or `"detail": null` | required field missing |
| `"confidence": "0.8"` | `StrictFloat` rejects `str` |
| an extra key on a finding, the envelope, or `coverage` | `extra="forbid"` |
| `"kind": "observation"` | not a `FindingKind` |
| an unknown `coverage.status` | not a `CoverageStatus` |

Note what is *not* on that list: `"confidence": 1`. Pydantic's strict mode accepts
an `int` for a `float`, and the guess that it did not cost an hour before the test
was written that checked. Measure the boundary; do not reason about it.

The design comment above the lenient wire models had said for months that the
strict model "is then reconstructed, **fail-open**, by the after-agent
normalizer". It was not. And the workaround had already leaked into a prompt —
`behavior_characterization.md` pleading that "any other value makes the whole
envelope invalid and the entire stage's findings are discarded". A prompt is not
a fix; it is a note that the fix is missing.

**Fix (shipped):** `salvage_evidence_envelope` runs only when the strict parse
rejects, and coerces each finding independently through the lenient `_FindingInput`
that already existed for `output_schema`. Every step is a subtraction or a
normalization — drop the finding that cannot be coerced, ignore an unknown key,
read a null `detail` as omitted, drop rather than relabel a finding naming another
artifact — and each survivor is re-validated strictly before it is stored. Nothing
unsalvageable changes behaviour: prose still fails the stage exactly as before.

Nothing is absorbed silently either: `<stage>:findings_dropped:<n>` and
`<stage>:evidence_rebound` reach the report's limitations, and a salvaged envelope
may never keep claiming `complete`.

**Lesson:** Strictness is right at the *storage* boundary and wrong at the *parsing*
boundary, and putting both in one `model_validate` call silently makes the strict
one govern the tolerant one. Where an all-or-nothing validation sits between an
unreliable producer and a consumer that needs partial results, the blast radius of
a single bad field is the entire batch — so validate per item and report the count
you dropped. The tell that this had been true for a long time was in the prompt:
when instructions start begging the model not to trip a validator, the validator
is the thing to fix.

---

## 20. A cap that counts executions does not bound context, and the stage that pays is the next one

**Symptom:** A live run on a SmartAssembly-packed .NET sample (QuasarRAT,
`1595d92f…`) produced a report saying the sample could not be decompiled and that
"all decompile/retriage/string surfaces failed". The obvious reading was that
ILSpy had been defeated by the protector, which for a packed .NET sample is
entirely plausible — and wrong.

**Root cause:** Reconstructed from the session DB, 288 events:

| agent | model calls | prompt tokens |
|---|---|---|
| **dotnet_analyst** | **101** | **9,231,921** |
| retriage | 7 | 700,202 |
| everything else | 38 | ~1.5M |
| **dotnet_decompile (ILSpy)** | **0** | **0** |

`dotnet_decompile`'s only output was:

```
[Run stopped: estimated context usage (238632 tokens) remains at or above the
critical threshold of the configured budget (200000 tokens) even after
compaction. A checkpoint was recorded before the limit was exceeded.]
```

**ILSpy never ran.** The stage was killed on arrival, before its first tool call,
because `dotnet_analyst` had already spent the run's context.

The governor that was supposed to prevent this worked exactly as designed.
`WORKBENCH_MAX_EXECUTIONS = 100` caps `run_python` executions per case, and the
run made **101 model calls against it** — it hit the cap precisely. But a cap on
*how many* scripts run says nothing about what they cost. Each execution appends
its script and its output to a conversation that every subsequent call re-sends,
so 100 permitted executions grew the context to 238k while a counter that only
knew about "100" reported everything was fine.

Three properties made it invisible:

1. **The budget is per-run but the cap is per-tool.** Nothing related the two, so
   no single component could observe that one stage was consuming the budget of
   the stages behind it.
2. **The victim reports the symptom.** The killed stage emitted a coverage
   failure, so the report attributed the outcome to ILSpy. The stage that caused
   it looked successful — it did a great deal of real work and hit no error.
3. **The .NET route had no fallback.** `deep_analysis` is a `LoopAgent` with a
   gate and `java_deep_analysis` is a `SequentialAgent` with a native second leg;
   `dotnet_decompile` was a bare `LlmAgent` with neither, so losing it lost the
   entire deep stage.

**Fix (shipped):** Context budget raised 200k → 400k, and — the part that
matters — the .NET route became a composite whose second leg runs Ghidra over the
PE when the managed leg produces nothing. The pivot fires on *evidence*, not on a
diagnosis, because "ILSpy was never attached", "ILSpy was defeated" and "ILSpy
was killed before it started" are indistinguishable downstream and all want the
same answer: read the bytes. It fails toward pivoting.

**Lesson:** A resource governor must bound the resource that is actually scarce.
Counting invocations is a proxy for cost, and a proxy that is wrong by two orders
of magnitude is not a bound at all — it is a number that makes everyone feel
governed. When a shared budget is consumed by one stage, the failure surfaces in
a *different* stage, so the error message names the victim and never the cause;
budget-exhaustion symptoms should be read as "who spent it", never "what broke".
And a pipeline branch with no fallback converts any single stage's failure into
the loss of everything downstream of it — which is why the sibling branches that
already had one never produced a symptom like this.
