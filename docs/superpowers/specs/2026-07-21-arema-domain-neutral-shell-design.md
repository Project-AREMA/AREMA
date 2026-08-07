# AREMA Domain-Neutral ADK Shell Design

**Date:** 2026-07-21  
**Status:** Approved for implementation planning  
**Project name:** AREMA — Autonomous Reverse Engineering & Malware Analysis

## 1. Purpose

Replace the inherited security-assessment application with a domain-neutral Google ADK shell. The new baseline will preserve the proven runtime infrastructure—model configuration, context management, memory, resilience, sessions, and MCP integration contracts—while physically removing all existing security agents, tools, MCP servers, prompts, schemas, reports, containers, and domain tests.

Milestone 1 ships exactly one minimal no-tools smoke agent. It does not ship reverse-engineering or malware-analysis behavior. Those capabilities, including any replacement for the current radare2 MCP server, will be designed and implemented separately on top of the clean extension interfaces defined here.

## 2. Mandate

The implementation must:

1. Rename the Python package, CLI, configuration identity, paths, and documentation from `security_agent` / `security-agent-adk` to `arema` / `arema`.
2. Preserve infrastructure behavior only when it is domain-neutral or can be made domain-neutral.
3. Remove legacy domain files from the active branch instead of moving them into a disabled `legacy/` directory.
4. Preserve recoverability through Git history and an annotated pre-cleanup tag.
5. Register exactly one no-tools smoke root agent.
6. Register no tools, sub-agents, or MCP servers.
7. Introduce typed, explicit registration for future agents, tools, MCP servers, memory codecs, and runtime policies.
8. Replace assessment-specific working memory with a generic, typed, extensible store.
9. Preserve context isolation, compaction, model resilience, callback ordering, throttling, turn limits, and session behavior through neutral policies and tests.
10. Leave no dead security-domain code, configuration, containers, generated artifacts, or misleading documentation in the active repository.

## 3. Current-State Findings

The inherited project is only partially pluggable.

- Agents are imported and registered manually in the root agent.
- Tools are imported manually and assigned in each agent constructor.
- Genuine MCP connections use a reusable registry and resilient ADK `McpToolset`, but each owning agent still references server names directly.
- The security tools under `mcp-servers/security-tools` are not used as MCP by the ADK agents; they are an editable in-process Python dependency with container wrappers.
- The agent factory encodes assessment categories such as scanning, authentication, analysis, and documentation.
- Context, policy, and working-memory callbacks reach into security-tool registries, scan names, endpoints, injection points, assessment phases, and findings.
- The current reverse-engineering agent uses a `STANDALONE` factory path that omits after-tool compaction, working-memory writes, checkpoints, and the standard model-error callback.
- The current radare2 container has useful isolation properties but uses an unpinned latest `r2mcp`, an SSE/Supergateway bridge, and wiring tests rather than live analysis integration tests.

These findings rule out a delete-only cleanup. The selected approach is a surgical extraction: reconstruct neutral boundaries in place, cover them with focused tests, and then delete the legacy domain implementation.

## 4. Goals and Non-Goals

### 4.1 Goals

- A small, understandable AREMA package with explicit ownership boundaries.
- One importable ADK `root_agent` with no tools or sub-agents.
- Model-provider portability and per-agent model overrides.
- Deterministic callback ordering and runtime-policy composition.
- Bounded context and configurable isolation modes.
- Typed capability catalogs with startup validation.
- Optional MCP graceful degradation without any registered servers in the default composition.
- A generic working-memory envelope, relations, record codecs, migrations, SQLite backend, and in-memory test backend.
- A neutral CLI, runner, documentation set, and development workflow.
- Strict linting, typing, unit, component, and architecture checks.

### 4.2 Non-Goals

- Reverse engineering, malware triage, static analysis, dynamic analysis, sandboxing, disassembly, debugging, or reporting workflows.
- A radare2 MCP server or any other MCP server implementation.
- A compatibility layer for old `security_agent` imports, workspace data, reports, or environment variables.
- Dynamic filesystem scanning, Python entry-point discovery, or a third-party plugin distribution system.
- A separate published `arema-runtime` package.
- A PostgreSQL backend. The existing nonfunctional stub is removed; the backend protocol remains extensible.
- Migration of old assessment records into the generic memory schema.

## 5. Target Package Architecture

```text
src/arema/
├── __init__.py
├── agent.py                 # ADK discovery; exports root_agent
├── composition.py           # Sole concrete assembly point
├── agents/
│   ├── __init__.py
│   └── smoke_agent.py       # Only registered agent
├── runtime/
│   ├── __init__.py
│   ├── agent_factory.py
│   ├── models.py
│   ├── sessions.py
│   ├── callbacks/
│   └── context/
├── registry/
│   ├── __init__.py
│   ├── descriptors.py
│   ├── agents.py
│   ├── tools.py
│   ├── mcp.py
│   └── errors.py
├── memory/
│   ├── __init__.py
│   ├── models.py
│   ├── codecs.py
│   ├── service.py
│   ├── store.py
│   ├── migrations.py
│   └── backends/
│       ├── memory.py
│       └── sqlite.py
├── core/
│   ├── __init__.py
│   ├── config.py
│   ├── logging.py
│   └── model_factory.py
├── prompts/
│   ├── loader.py
│   └── smoke_agent.md
├── runner.py
└── cli.py
```

The final layout may combine files that remain trivially small, but it must preserve these ownership boundaries.

### 5.1 Dependency Rules

- `core`, `registry`, and `memory` do not import concrete agents or capabilities.
- `memory` does not depend on ADK agent classes, tool implementations, or MCP transports.
- `runtime` may depend on `core`, `registry`, and `memory`, but contains no reverse-engineering, malware, pentest, scan, finding, endpoint, injection, authentication, or assessment concepts.
- Capability modules produce descriptors without mutating global registries during import.
- `composition.py` is the only module that assembles concrete descriptors and freezes the catalog.
- `agent.py` exports the single composed root agent for ADK discovery and contains no capability definitions.

## 6. Default Smoke Composition

The default catalog contains:

- One `AgentDescriptor` for `smoke_agent`.
- Zero `ToolDescriptor` entries.
- Zero `McpServerDescriptor` entries.
- Zero sub-agent references.

The smoke agent is the ADK `root_agent`. It identifies itself as the AREMA infrastructure shell, confirms runtime availability, and responds conversationally. It does not transfer, call tools, claim reverse-engineering capability, or simulate future functionality.

The smoke path must exercise model construction, provider configuration, session creation, request capture, callback ordering, context accounting, memory health reporting, CLI execution, and ADK discovery.

## 7. Typed Registration and Composition

The current domain-specific `AgentType` enum is removed. Neutral runtime behavior is selected with a `RuntimeProfile`.

### 7.1 Agent Descriptor

`AgentDescriptor` defines:

- Stable identifier, display name, and routing description.
- Agent factory and prompt identifier.
- Referenced tool, MCP-server, and sub-agent identifiers.
- Runtime profile.
- Optional output key.
- Version and general capability metadata.

### 7.2 Tool Descriptor

`ToolDescriptor` defines:

- Stable identifier, version, description, and callable or factory.
- Output-compaction policy.
- Optional memory codecs.
- Optional lifecycle callbacks and capability metadata.

It does not assume a scan phase, finding count, cookie parameter, endpoint, or security-tool registry.

### 7.3 MCP Server Descriptor

`McpServerDescriptor` defines:

- Stable identifier.
- Typed stdio, SSE, or streamable-HTTP transport configuration.
- Environment substitution, timeouts, headers, tool allowlists, and tool-name policy.
- Required or optional availability.

The default catalog has no MCP descriptors. Standard `.mcp.json` parsing may remain as an optional configuration adapter, but it is not the ownership or registration mechanism.

### 7.4 Runtime Profile

`RuntimeProfile` selects neutral policies for:

- Context budgeting and isolation.
- Model throttling and retry behavior.
- Turn limits.
- Tool guards and error recovery.
- Memory and lifecycle event recording.
- Capability-specific callback additions.

Every agent receives the safe default profile unless a descriptor explicitly opts out of a policy. There is no special standalone path that silently loses compaction, memory, or error handling.

### 7.5 Catalog Construction

1. Capability modules return descriptors without import-time registration side effects.
2. `composition.py` adds descriptors to a catalog builder.
3. The builder rejects duplicate identifiers, unresolved references, dependency cycles, multiple roots, and invalid transport configuration.
4. The builder freezes the descriptors into an immutable `CapabilityCatalog`.
5. The composer resolves local tools and MCP toolsets, constructs agents in dependency order, and exports one root agent.

Empty tool and MCP registries are valid. Invalid composition is a startup error.

## 8. Generic Working Memory

### 8.1 Relational Envelope

The store uses a stable relational envelope and typed JSON payloads. Domain extensions register payload codecs instead of adding domain tables.

```text
memory_scopes
  id, parent_id, scope_type, created_at, closed_at, metadata

memory_records
  id, scope_id, namespace, kind, schema_version, revision,
  source, payload, metadata, content_hash,
  created_at, updated_at, expires_at

memory_relations
  id, scope_id, source_record_id, target_record_id,
  relation_type, metadata, created_at

schema_migrations
  version, applied_at
```

Indexes support lookup by scope, namespace, kind, source, timestamps, and expiry. The SQLite implementation enables foreign keys and uses explicit transactions for multi-record writes.

### 8.2 First-Party Record Types

- `EventRecord`: lifecycle and runtime events.
- `ArtifactRecord`: references to files or external objects, including media type, size, and digest.
- `NoteRecord`: agent- or user-authored durable knowledge.
- `CheckpointRecord`: resumable state and compact summaries.

Binary artifacts are not stored inside SQLite. Artifact records reference controlled paths or object URIs and include integrity hashes.

### 8.3 Codec Registry

`RecordCodecRegistry` is keyed by `(namespace, kind, schema_version)`. A codec:

- Validates a typed Pydantic payload.
- Serializes and deserializes the payload.
- Optionally upgrades older payload versions.

Unknown record kinds remain readable as raw envelopes for forward compatibility. Core database migrations modify the envelope only; payload migrations belong to codecs.

### 8.4 Service API

The service supports:

- Creating and closing hierarchical scopes.
- Appending and retrieving typed records.
- Updating records with optimistic revision checks.
- Creating typed relations between records.
- Filtering by scope, namespace, kind, source, tags, and time.
- Cursor pagination and deterministic ordering.
- Explicit transactions for multi-record operations.
- Backend health and status reporting.

SQLite is the production default. The in-memory backend implements the same contract for tests. Automatic runtime writes fail open and surface degraded health. Explicit service calls return typed errors. Memory is never dumped into model context automatically; retrieval requires an explicit, bounded context policy.

## 9. Context Management

The shell preserves the existing layered principles without security-tool coupling.

- Root agents may use conversation history for interactive continuity.
- Specialist agents may choose isolated context with `include_contents="none"`.
- Cross-agent data flows through explicit state, bounded memory retrieval, or output keys.
- Context budgeting preserves warning, hard, and critical pressure tiers.
- Older tool results and model text are compacted progressively according to configuration.
- Tool output compaction is driven by `ToolDescriptor.output_policy`, not hardcoded tool-name sets.
- Memory retrieval has record-count and token limits.
- At the hard safety limit, the runtime stops cleanly and writes a resumable checkpoint instead of submitting an oversized model request.

Context-policy behavior is tested with synthetic descriptors and responses because the default smoke agent has no tools.

## 10. Callback Ordering and Runtime Flow

A normal request follows this path:

```text
CLI or ADK UI
  → session runner
  → request/run metadata capture
  → ordered before-model policies
  → smoke root agent
  → model response
  → lifecycle event write
  → caller
```

The runtime constructs and validates callback chains centrally.

```text
before model:
  capture request → throttle → turn limit → context budget → usage metrics

before tool:
  registered-tool guard → capability policies

after tool:
  outcome event → capability callbacks → memory codecs → output compaction

model/tool errors:
  typed recovery handlers and bounded retries
```

Output compaction must be last after tool execution. The tool guard must be first before tool execution. These are builder invariants rather than documentation-only rules.

## 11. Resilience and Error Policy

- Duplicate IDs, unresolved dependencies, cycles, multiple roots, invalid transport configuration, or missing required startup configuration fail fast with typed errors.
- Transient model/provider failures use bounded retries with exponential backoff.
- Optional unavailable MCP servers produce unavailable capability status without crashing composition or unrelated agents.
- Required unavailable MCP servers produce a clear startup or runtime error.
- Automatic memory and telemetry writes fail open, log sanitized diagnostics, and report degraded health.
- Explicit memory operations fail with typed errors so callers control recovery.
- Callback failures are isolated and recorded unless the callback enforces a declared safety boundary.
- Context pressure compacts progressively and terminates cleanly at the safety limit.
- Secrets, credentials, raw binary contents, and arbitrary artifact bodies do not enter standard logs or generic model context automatically.

## 12. Configuration and Public Identity

The package distribution, import namespace, command, session application name, paths, and documentation use AREMA naming.

- Package/import: `arema`
- CLI command: `arema`
- ADK export: `arema.agent:root_agent`
- Default persistent root: `~/.arema/`
- Working-memory default: `~/.arema/memory/`
- Application/session name: `arema`

Configuration retains model-provider selection, model overrides, retry limits, context budgets, throttling, turn limits, logging, and memory backend settings. Security API keys, report settings, scan gates, authentication, browser, security-tool, and old MCP gateway settings are removed.

No backward-compatible `SECURITY_AGENT_*` paths, commands, imports, or environment aliases are provided.

## 13. Deletion Boundary

Create an annotated pre-cleanup Git tag before implementation deletes legacy files. Then remove, rather than archive:

- The entire `src/security_agent/` package after neutral behavior is extracted.
- Assessment and discipline agents and prompts.
- The old `.adk/SOUL.md` and `.adk/CONSTITUTION.md`.
- The entire `mcp-servers/` directory and Docker Compose MCP/tool services.
- Security tools, wrappers, schemas, reports, workspace formats, and generated schemas.
- Pentest, browser, security-tool, report, and reverse-engineering tests.
- Security-specific examples, scripts, targets, documentation, historical plans, and generated runtime artifacts.
- Unused report, document-rendering, web-scanning, container-tool, and editable `security-tools` dependencies.
- Security-specific environment variables, Make targets, CI steps, CLI text, metadata, and configuration.

Local caches, coverage output, session databases, and generated files must remain ignored and absent from the committed tree.

## 14. Documentation Reset

The active documentation set covers only:

- AREMA identity and the milestone-1 scope.
- Installation and model-provider configuration.
- CLI and ADK launch instructions.
- Architecture and extension boundaries.
- Adding an agent, tool, MCP server, memory codec, and runtime policy.
- Context-management and resilience guarantees.

It must not imply that reverse engineering or malware analysis is implemented in milestone 1.

## 15. Verification Strategy

### 15.1 Registry Tests

- Valid smoke catalog with one root, zero tools, and zero MCP servers.
- Duplicate identifiers.
- Unresolved tool, MCP, and sub-agent references.
- Dependency cycles and multiple roots.
- Invalid transport configuration.
- Optional MCP degradation and required MCP failure.
- Frozen catalog immutability.

### 15.2 Memory Tests

- Identical store contract against SQLite and in-memory backends.
- Scope hierarchy and closure.
- Core record validation.
- Codec registration, version decoding, and payload upgrades.
- Unknown-record forward compatibility.
- Relations and referential integrity.
- Filtering, cursor pagination, and deterministic ordering.
- Optimistic revision conflicts.
- Schema migrations and repeatable initialization.
- Explicit transactions.
- Fail-open automatic writes and strict explicit calls.

### 15.3 Runtime Tests

- Callback ordering invariants.
- Original request capture.
- Model-provider construction and per-agent overrides.
- Retry/backoff and sanitized error behavior.
- Throttling and turn limits.
- Warning, hard, and critical context tiers.
- Root-history and isolated-context modes.
- Synthetic tool-output compaction from descriptor policy.
- Hard-limit checkpoint behavior.

### 15.4 Component and Architecture Tests

- `arema.agent:root_agent` imports successfully.
- The smoke agent has no tools, sub-agents, or transfers.
- CLI execution works with a fake model and session service.
- ADK discovery loads the root agent.
- Runtime health reports model, memory, and catalog status.
- Active code does not import `security_agent` or `security_tools`.
- Active code/config contains no old agent, pentest tool, Playwright, radare2, or MCP-server registrations.

### 15.5 Quality Gate

The milestone is complete only when:

- `ruff check` passes.
- `ruff format --check` passes.
- `mypy --strict` passes.
- The complete new test suite passes.
- `git status --short` shows no generated artifacts after verification.
- Repository searches confirm that removed domain registrations and imports are absent from active code and configuration.
- No disabled legacy implementation or obsolete container remains in the committed tree.

## 16. Implementation Sequencing Constraints

The implementation plan must preserve a working testable path throughout the migration:

1. Tag the pre-cleanup state.
2. Introduce neutral tests and foundational AREMA modules.
3. Port and neutralize model, logging, context, resilience, and session behavior.
4. Implement typed registries and the smoke composition.
5. Implement the generic memory envelope and backends.
6. Switch package, CLI, ADK discovery, configuration, and development commands to AREMA.
7. Remove legacy domain code, MCP servers, containers, tests, dependencies, and documentation.
8. Run architecture searches and the full quality gate.

No reverse-engineering capability is added during this sequence.

## 17. Completion Definition

Milestone 1 is complete when the repository is recognizably AREMA, imports and runs one domain-neutral smoke agent, retains the approved infrastructure guarantees behind typed extension interfaces, has a generic extensible memory service, contains no registered tools or MCP servers, and carries no inactive legacy security implementation in the active tree.
