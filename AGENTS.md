# AREMA

AREMA (Autonomous Reverse Engineering & Malware Analysis) is a multi-domain
agent platform built on Google ADK. Four packages live under `src/`:

- `arema/` — domain-neutral core (runtime, registry, memory, sandbox, callbacks). No `agent.py`.
- `greeter_agent/` — the welcome router; delegates to registered domains via ADK `transfer_to_subagent`.
- `reverse_engineering/` — RE **capability library** (no `agent.py`); exposes `register_re_infrastructure(builder, codecs, settings)`.
- `malware_analyst/` — the live ADK domain; a 10-stage `SequentialAgent` root.

The greeter routes **only** to `malware_analyst`. There is no `reverse_engineer/`
package — do not reintroduce that name. ADK discovers agents from `src/`
(`arema --web` sets `cwd=src/`); each package with an `agent.py` exposing
`root_agent` is one discoverable agent.

## Commands

```bash
make setup      # uv sync --extra dev --inexact
make check      # ruff + ruff format --check + mypy + pytest — run before committing
make test       # pytest tests
make test-unit  # tests/unit only
make adk-run    # adk run src/greeter_agent  (interactive router)
make adk-web    # uv run arema --web --port 8000
```

The sandbox is **off by default**; opt in with `AREMA_SANDBOX_ENABLED=true`.
Full cluster lifecycle: `make sandbox-cluster setup-sandbox sandbox-build-images sandbox-up`.
Config reference: `.env.example`.

## Critical rules (ADK-specific, non-obvious)

- **Never** annotate a tool parameter with bare `typing.Any`. Python 3.14 removed
  `isinstance(x, Any)` and ADK calls `isinstance(default, annotation)` at import.
  Use `object`; compound types like `dict[str, Any]` are fine.
- **Never** `isinstance(state, dict)` on ADK `CallbackContext.state` /
  `ToolContext.state` — it is a custom proxy, not a dict. Duck-type on `.get`
  (see `src/arema/runtime/services.py:_state_value`).
- A `ToolDescriptor.id` **must equal** the tool function's `__name__`, or its
  `OutputPolicy` will not bind at compose time.
- Tool callbacks needing `RuntimeServices`/sandbox use a
  `ToolDescriptor(factory=…)` that closes over `ToolBuildContext`; a tool taking
  `tool_context: ToolContext` must import `ToolContext` at runtime
  (`# noqa: TC002`) because ADK resolves annotations via `get_type_hints`.
- Callback ordering is enforced by **identity role markers**
  (`runtime/callbacks/roles.py`), never name comparisons: the registered-tool
  guard is **first** in `before_tool`; the output compactor is the **single last**
  step in `after_tool`. `compose_after_tool` folds the whole after-tool list into
  one callback because ADK short-circuits on the first truthy return — do not
  bypass it. Add a role marker when a new callback participates in ordering.
- MCP servers default to `required=False`: an unavailable optional server degrades
  to `[]` tools (never aborts the run); a `required=True` server re-raises; a
  cancellation is never treated as unavailability.

## Neutrality (enforced by `tests/architecture/test_neutral_boundaries.py`)

`src/arema/` stays domain-neutral. Do not import a domain package from the core,
and do not hardcode concrete tool/engine/pool names (`radare2`, `ghidra`, `ilspy`,
`jadx`, …) anywhere in `src/arema/`. Concrete capabilities live in
`src/reverse_engineering/` and `src/malware_analyst/`. The sandbox subsystem is
neutral-core, but engine/pool names enter only via `Settings.sandbox_pool_map`.
Sample bytes never leave the host — `tests/architecture/test_no_sample_upload.py`
AST-enforces this for the intel layer.

## Style

- Python ≥ 3.11. Ruff (`line-length=100`, `target-version=py311`), isort, mypy `strict=true`.
- Follow existing patterns; prefer editing over creating. No comments unless asked.
- Agent prompts are package-relative `.md` loaded by each package's own loader
  (`load_<domain>_prompt`); the core `load_prompt` only reads `arema.prompts`.
- Extending the shell = register immutable descriptors in a composition root
  before `builder.freeze(...)`. Full recipes/validation: `docs/EXTENDING_AREMA.md`.

## Tests

- Suite is pinned hermetic: conftests set `AREMA_LLM_PROVIDER=ollama`,
  `AREMA_SANDBOX_BACKEND=local`, blank the intel API keys, and redirect `HOME`
  so no provider key or cluster is required. Mirror the nearest `conftest.py`
  when adding tests.
- Before adding an agent/domain, read `docs/AGENTS_AND_DISCOVERY.md` (authoritative
  layout + add-a-domain recipe). Architecture/data-flow: `docs/ARCHITECTURE.md`.
  End-to-end setup: `docs/DEVELOPMENT.md`.

<!-- rtk-instructions v2 -->
# RTK (Rust Token Killer) - Token-Optimized Commands

## Golden Rule

**Always prefix commands with `rtk`**. If RTK has a dedicated filter, it uses it. If not, it passes through unchanged. This means RTK is always safe to use.

**Important**: Even in command chains with `&&`, use `rtk`:
```bash
# ❌ Wrong
git add . && git commit -m "msg" && git push

# ✅ Correct
rtk git add . && rtk git commit -m "msg" && rtk git push
```

## RTK Commands by Workflow

### Build & Compile (80-90% savings)
```bash
rtk cargo build         # Cargo build output
rtk cargo check         # Cargo check output
rtk cargo clippy        # Clippy warnings grouped by file (80%)
rtk tsc                 # TypeScript errors grouped by file/code (83%)
rtk lint                # ESLint/Biome violations grouped (84%)
rtk prettier --check    # Files needing format only (70%)
rtk next build          # Next.js build with route metrics (87%)
```

### Test (60-99% savings)
```bash
rtk cargo test          # Cargo test failures only (90%)
rtk go test             # Go test failures only (90%)
rtk jest                # Jest failures only (99.5%)
rtk vitest              # Vitest failures only (99.5%)
rtk playwright test     # Playwright failures only (94%)
rtk pytest              # Python test failures only (90%)
rtk rake test           # Ruby test failures only (90%)
rtk rspec               # RSpec test failures only (60%)
rtk test <cmd>          # Generic test wrapper - failures only
```

### Git (59-80% savings)
```bash
rtk git status          # Compact status
rtk git log             # Compact log (works with all git flags)
rtk git diff            # Compact diff (80%)
rtk git show            # Compact show (80%)
rtk git add             # Ultra-compact confirmations (59%)
rtk git commit          # Ultra-compact confirmations (59%)
rtk git push            # Ultra-compact confirmations
rtk git pull            # Ultra-compact confirmations
rtk git branch          # Compact branch list
rtk git fetch           # Compact fetch
rtk git stash           # Compact stash
rtk git worktree        # Compact worktree
```

Note: Git passthrough works for ALL subcommands, even those not explicitly listed.

### GitHub (26-87% savings)
```bash
rtk gh pr view <num>    # Compact PR view (87%)
rtk gh pr checks        # Compact PR checks (79%)
rtk gh run list         # Compact workflow runs (82%)
rtk gh issue list       # Compact issue list (80%)
rtk gh api              # Compact API responses (26%)
```

### JavaScript/TypeScript Tooling (70-90% savings)
```bash
rtk pnpm list           # Compact dependency tree (70%)
rtk pnpm outdated       # Compact outdated packages (80%)
rtk pnpm install        # Compact install output (90%)
rtk npm run <script>    # Compact npm script output
rtk npx <cmd>           # Compact npx command output
rtk prisma              # Prisma without ASCII art (88%)
rtk uv run <cmd>        # Compact uv project command output
```

### Files & Search (60-75% savings)
```bash
rtk ls <path>           # Tree format, compact (65%)
rtk read <file>         # Code reading with filtering (60%)
rtk grep <pattern>      # Search grouped by file (75%). Format flags (-c, -l, -L, -o, -Z) run raw.
rtk find <pattern>      # Find grouped by directory (70%)
```

### Analysis & Debug (70-90% savings)
```bash
rtk err <cmd>           # Filter errors only from any command
rtk log <file>          # Deduplicated logs with counts
rtk json <file>         # JSON structure without values
rtk deps                # Dependency overview
rtk env                 # Environment variables compact
rtk summary <cmd>       # Smart summary of command output
rtk diff                # Ultra-compact diffs
```

### Infrastructure (85% savings)
```bash
rtk docker ps           # Compact container list
rtk docker images       # Compact image list
rtk docker logs <c>     # Deduplicated logs
rtk kubectl get         # Compact resource list
rtk kubectl logs        # Deduplicated pod logs
```

### Network (65-70% savings)
```bash
rtk curl <url>          # Compact HTTP responses (70%)
rtk wget <url>          # Compact download output (65%)
```

### Meta Commands
```bash
rtk gain                # View token savings statistics
rtk gain --history      # View command history with savings
rtk discover            # Analyze Claude Code sessions for missed RTK usage
rtk proxy <cmd>         # Run command without filtering (for debugging)
rtk init                # Add RTK instructions to CLAUDE.md
rtk init --global       # Add RTK to ~/.claude/CLAUDE.md
```

## Token Savings Overview

| Category | Commands | Typical Savings |
|----------|----------|-----------------|
| Tests | vitest, playwright, cargo test | 90-99% |
| Build | next, tsc, lint, prettier | 70-87% |
| Git | status, log, diff, add, commit | 59-80% |
| GitHub | gh pr, gh run, gh issue | 26-87% |
| Package Managers | pnpm, npm, npx | 70-90% |
| Files | ls, read, grep, find | 60-75% |
| Infrastructure | docker, kubectl | 85% |
| Network | curl, wget | 65-70% |

Overall average: **60-90% token reduction** on common development operations.
<!-- /rtk-instructions -->