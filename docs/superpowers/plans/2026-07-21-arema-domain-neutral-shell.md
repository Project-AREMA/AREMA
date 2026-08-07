# AREMA Domain-Neutral ADK Shell Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the inherited security-assessment project with a domain-neutral AREMA ADK shell containing one no-tools smoke root agent, typed capability registration, generic structured memory, and the existing runtime hardening without any legacy domain code.

**Architecture:** Build `src/arema` alongside the legacy package, prove each neutral subsystem with an isolated `tests_arema` suite, switch all entry points to AREMA, and only then delete the legacy package and assets. A single explicit composition root freezes typed agent/tool/MCP descriptors; neutral runtime profiles supply ordered callbacks; structured memory uses a stable relational envelope plus versioned payload codecs.

**Tech Stack:** Python 3.11+, Google ADK 1.25.1, LiteLLM, Pydantic v2, pydantic-settings, SQLite, structlog, Rich, pytest, pytest-asyncio, Hypothesis, Ruff, mypy, uv, Hatchling.

---

## Scope and sequencing

This is one migration plan rather than separate subsystem plans because registry construction, runtime policies, memory integration, smoke composition, package identity, and legacy deletion form one atomic acceptance boundary. Each task below produces a testable commit. The new package and test suite coexist with the old package until Task 13, so removal never precedes replacement.

Execute this plan in a dedicated worktree. Do not add reverse-engineering logic, malware-analysis logic, tools, or active MCP server registrations.

## Final file map

### Runtime package

| Path | Responsibility |
|---|---|
| `src/arema/__init__.py` | Package metadata only |
| `src/arema/agent.py` | ADK discovery export |
| `src/arema/composition.py` | Sole concrete catalog assembly |
| `src/arema/agents/smoke_agent.py` | Smoke descriptor and agent factory |
| `src/arema/core/config.py` | Neutral Pydantic settings |
| `src/arema/core/logging.py` | Structured logging setup |
| `src/arema/core/model_factory.py` | Provider-neutral LiteLLM construction |
| `src/arema/prompts/loader.py` | Package-relative prompt loading |
| `src/arema/prompts/smoke_agent.md` | Only shipped prompt |
| `src/arema/registry/descriptors.py` | Frozen descriptor and transport types |
| `src/arema/registry/catalog.py` | Catalog builder, validation, immutable catalog |
| `src/arema/registry/mcp.py` | ADK MCP toolset construction and degradation |
| `src/arema/registry/errors.py` | Typed composition errors |
| `src/arema/runtime/callbacks/chain.py` | Ordered callback construction and validation |
| `src/arema/runtime/callbacks/*.py` | One neutral policy per callback |
| `src/arema/runtime/context/budget.py` | Context estimation and tiered compaction |
| `src/arema/runtime/context/compactor.py` | Descriptor-driven tool output compaction |
| `src/arema/runtime/agent_factory.py` | ADK agent construction from build context |
| `src/arema/runtime/sessions.py` | Session/run identifiers and state keys |
| `src/arema/runtime/services.py` | Clock, metrics, and memory event sink protocols |
| `src/arema/memory/models.py` | Scope, envelope, relation, payload, query models |
| `src/arema/memory/codecs.py` | Versioned payload codec registry |
| `src/arema/memory/errors.py` | Typed backend, codec, and integrity errors |
| `src/arema/memory/store.py` | Backend protocol and transaction contract |
| `src/arema/memory/backends/memory.py` | Deterministic in-memory backend |
| `src/arema/memory/backends/sqlite.py` | SQLite backend |
| `src/arema/memory/migrations.py` | Ordered SQLite envelope migrations |
| `src/arema/memory/service.py` | Typed service, decoding, strict/fail-open APIs |
| `src/arema/runner.py` | Programmatic and interactive ADK runner |
| `src/arema/cli.py` | `arema` command |
| `agents/arema/agent.py` | ADK CLI wrapper importing `arema.agent` |

### Final test tree

During Tasks 1–12 these files live under `tests_arema/`; Task 13 renames that directory to `tests/` after deleting the legacy suite.

| Path | Responsibility |
|---|---|
| `tests/unit/core/` | Settings, models, logging |
| `tests/unit/registry/` | Descriptor, catalog, MCP behavior |
| `tests/unit/runtime/` | Callback order, resilience, context policies |
| `tests/unit/memory/` | Models, codecs, shared store contract, service |
| `tests/component/test_smoke_composition.py` | One-agent/zero-capability composition |
| `tests/component/test_runner.py` | Runner with fake ADK boundary |
| `tests/architecture/test_neutral_boundaries.py` | Forbidden imports and stale registration checks |

## Task 1: Protect the legacy baseline and introduce the AREMA package seam

**Files:**
- Create: `src/arema/__init__.py`
- Create: `tests_arema/unit/test_package.py`
- Modify: `pyproject.toml`

- [ ] **Step 1: Verify the execution worktree and create the recovery tag**

Run:

```bash
git status --short
git log -1 --oneline
git tag --list pre-arema-domain-reset-2026-07-21
```

Expected: clean status, the design/plan commits at `HEAD`, and no existing tag with that name.

Run:

```bash
git tag -a pre-arema-domain-reset-2026-07-21 -m "Stable security-agent baseline before AREMA domain reset"
git show --no-patch --oneline pre-arema-domain-reset-2026-07-21
```

Expected: the annotated tag points to the pre-cleanup commit.

- [ ] **Step 2: Write the failing package identity test**

```python
"""Package identity tests for the AREMA migration seam."""

from arema import __version__


def test_package_exposes_arema_version() -> None:
    assert __version__ == "0.1.0"
```

- [ ] **Step 3: Run the test and verify the missing package failure**

Run: `uv run pytest tests_arema/unit/test_package.py -v`

Expected: collection fails with `ModuleNotFoundError: No module named 'arema'`.

- [ ] **Step 4: Add the transitional package and wheel configuration**

Create `src/arema/__init__.py`:

```python
"""AREMA — Autonomous Reverse Engineering & Malware Analysis."""

__version__ = "0.1.0"

__all__ = ["__version__"]
```

Temporarily change the Hatch package list so old and new packages can coexist:

```toml
[tool.hatch.build.targets.wheel]
packages = ["src/security_agent", "src/arema"]
```

- [ ] **Step 5: Reinstall and verify the seam**

Run:

```bash
uv sync --all-extras
uv run pytest tests_arema/unit/test_package.py -v
```

Expected: one passing test.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml src/arema/__init__.py tests_arema/unit/test_package.py uv.lock
git commit -m "chore: introduce AREMA package seam"
```

## Task 2: Port neutral configuration, logging, and model construction

**Files:**
- Create: `src/arema/core/__init__.py`
- Create: `src/arema/core/config.py`
- Create: `src/arema/core/logging.py`
- Create: `src/arema/core/model_factory.py`
- Create: `tests_arema/unit/core/test_config.py`
- Create: `tests_arema/unit/core/test_model_factory.py`

- [ ] **Step 1: Write failing settings tests**

Create tests that instantiate `Settings(_env_file=None)` with patched environments and assert:

```python
def test_neutral_defaults_use_arema_paths(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    settings = Settings(_env_file=None)
    assert settings.app_name == "arema"
    assert settings.memory_backend == "sqlite"
    assert settings.memory_path == Path.home() / ".arema" / "memory" / "arema.db"
    assert settings.context_budget_tokens == 80_000


def test_settings_have_no_security_domain_fields() -> None:
    fields = set(Settings.model_fields)
    assert not fields & {
        "virustotal_api_key",
        "shodan_api_key",
        "mcp_playwright_enabled",
        "report_output_dir",
        "scan_gate_enabled",
        "phase_turn_caps",
    }


def test_google_requires_api_key(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "google")
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with pytest.raises(ValueError, match="GOOGLE_API_KEY is required"):
        Settings(_env_file=None)
```

Create model tests for provider prefixes and per-agent overrides:

```python
def test_agent_override_can_select_another_provider(monkeypatch) -> None:
    settings = Settings(
        _env_file=None,
        llm_provider="ollama",
        agent_model_overrides={"smoke_agent": "anthropic/claude-sonnet-4-20250514"},
        anthropic_api_key="test-key",
    )
    model = get_agent_model("smoke_agent", settings=settings)
    assert isinstance(model, LiteLlm)
    assert model.model == "anthropic/claude-sonnet-4-20250514"
```

- [ ] **Step 2: Run the tests and verify missing-module failures**

Run: `uv run pytest tests_arema/unit/core -v`

Expected: collection fails because `arema.core` does not exist.

- [ ] **Step 3: Implement the neutral settings surface**

Create a single `Settings` model retaining only these field groups:

```python
class LLMProvider(StrEnum):
    GOOGLE = "google"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    LMSTUDIO = "lmstudio"
    OPENAI_COMPATIBLE = "openai_compatible"
    ZAI = "zai"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_find_env_file(),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    llm_provider: LLMProvider = LLMProvider.GOOGLE
    google_api_key: SecretStr | None = None
    google_model: str = "gemini-2.0-flash"
    openai_api_key: SecretStr | None = None
    openai_model: str = "gpt-4o"
    openai_api_base: str | None = None
    anthropic_api_key: SecretStr | None = None
    anthropic_model: str = "claude-sonnet-4-20250514"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    lmstudio_base_url: str = "http://localhost:1234/v1"
    lmstudio_model: str = "local-model"
    openai_compatible_api_key: SecretStr | None = None
    openai_compatible_base_url: str = "http://localhost:8000/v1"
    openai_compatible_model: str = "default"
    zai_api_key: SecretStr | None = None
    zai_model: str = "glm-4.5-flash"
    zai_api_base: str = "https://api.z.ai/api/paas/v4"

    app_name: str = "arema"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    agent_temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    agent_max_tokens: int | None = Field(default=None, ge=1)
    agent_model_overrides: dict[str, str] = Field(default_factory=dict)
    agent_model_max_tokens: dict[str, int] = Field(default_factory=dict)
    agent_model_temperature: dict[str, float] = Field(default_factory=dict)

    llm_num_retries: int = Field(default=3, ge=0, le=10)
    llm_retry_min_wait: float = Field(default=1.0, ge=0.1, le=30.0)
    llm_retry_max_wait: float = Field(default=60.0, ge=1.0, le=300.0)
    llm_min_call_interval: float = Field(default=0.0, ge=0.0, le=60.0)

    context_budget_tokens: int = Field(default=80_000, ge=10_000, le=500_000)
    context_warning_ratio: float = Field(default=0.60, gt=0.0, lt=1.0)
    context_hard_ratio: float = Field(default=0.75, gt=0.0, lt=1.0)
    context_critical_ratio: float = Field(default=0.85, gt=0.0, lt=1.0)
    context_max_list_items: int = Field(default=30, ge=5, le=200)
    context_preserve_recent_tools: int = Field(default=3, ge=1, le=10)
    context_preserve_recent_model_turns: int = Field(default=4, ge=1, le=20)
    default_turn_limit: int = Field(default=100, ge=1, le=1000)
    agent_turn_limits: dict[str, int] = Field(default_factory=dict)

    memory_enabled: bool = True
    memory_backend: Literal["sqlite", "memory"] = "sqlite"
    memory_path: Path = Field(
        default_factory=lambda: Path.home() / ".arema" / "memory" / "arema.db"
    )
    memory_retrieval_max_records: int = Field(default=20, ge=1, le=200)
    memory_retrieval_token_limit: int = Field(default=4_000, ge=100, le=50_000)
```

Add cross-field validators enforcing provider API keys, ordered context ratios, positive per-agent limits, and valid per-agent temperatures. Add cached `get_settings()` and `clear_settings_cache()` functions.

- [ ] **Step 4: Port logging and model construction with neutral imports**

Port the structured logger behavior from `src/security_agent/core/logging.py`, but do not configure logging at import time. Port provider setup, prefix resolution, retry configuration, and per-agent overrides from `model_factory.py`. Give `get_agent_model` this testable signature:

```python
def get_agent_model(
    agent_name: str | None = None,
    *,
    settings: Settings | None = None,
    use_retries: bool = True,
) -> str | LiteLlm:
    resolved = settings or get_settings()
    if agent_name is not None:
        override = resolved.agent_model_overrides.get(agent_name)
        if override is not None:
            return create_model(
                resolved,
                model_override=override,
                max_tokens=resolved.agent_model_max_tokens.get(agent_name),
                temperature=resolved.agent_model_temperature.get(agent_name),
                use_retries=use_retries,
            )
    return create_model(resolved, use_retries=use_retries)
```

When `use_retries` is true, use `resolved.llm_num_retries`, `resolved.llm_retry_min_wait`, and `resolved.llm_retry_max_wait` when creating `LiteLlm`; otherwise set the provider wrapper's retry count to zero. Never log secret values.

- [ ] **Step 5: Run focused and legacy regression tests**

Run:

```bash
uv run pytest tests_arema/unit/core -v
uv run pytest tests/unit/test_config.py tests/unit/test_model_factory.py tests/unit/test_llm_retry.py -q
```

Expected: all new and selected legacy tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/arema/core tests_arema/unit/core
git commit -m "feat: add neutral AREMA core runtime"
```

## Task 3: Define frozen capability descriptors and catalog validation

**Files:**
- Create: `src/arema/registry/__init__.py`
- Create: `src/arema/registry/descriptors.py`
- Create: `src/arema/registry/catalog.py`
- Create: `src/arema/registry/errors.py`
- Create: `tests_arema/unit/registry/test_catalog.py`

- [ ] **Step 1: Write failing catalog tests**

Cover a valid empty-capability root plus each invalid graph:

```python
def test_catalog_accepts_one_root_and_empty_capability_registries() -> None:
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(agent_descriptor("smoke"))
    catalog = builder.freeze(root_agent_id="smoke")
    assert catalog.root_agent_id == "smoke"
    assert tuple(catalog.agents) == ("smoke",)
    assert not catalog.tools
    assert not catalog.mcp_servers


def test_catalog_rejects_duplicate_ids() -> None:
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(agent_descriptor("smoke"))
    with pytest.raises(DuplicateCapabilityError, match="smoke"):
        builder.add_agent(agent_descriptor("smoke"))


def test_catalog_rejects_unresolved_tool_reference() -> None:
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(agent_descriptor("smoke", tool_ids=("missing",)))
    with pytest.raises(UnresolvedCapabilityError, match="missing"):
        builder.freeze(root_agent_id="smoke")


def test_catalog_rejects_agent_cycle() -> None:
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(agent_descriptor("a", sub_agent_ids=("b",)))
    builder.add_agent(agent_descriptor("b", sub_agent_ids=("a",)))
    with pytest.raises(CapabilityCycleError):
        builder.freeze(root_agent_id="a")
```

Also test an unknown runtime profile, a disconnected second root, invalid tool source selection, an unresolved MCP reference, duplicate MCP IDs, and invalid transport fields. Assert mapping mutation raises `TypeError` after `freeze()`.

- [ ] **Step 2: Run tests and verify missing registry failures**

Run: `uv run pytest tests_arema/unit/registry/test_catalog.py -v`

Expected: collection fails because `arema.registry` does not exist.

- [ ] **Step 3: Implement descriptor types**

Use frozen, slotted dataclasses and immutable tuples/mappings:

```python
class ContextMode(StrEnum):
    HISTORY = "history"
    ISOLATED = "isolated"


Callback: TypeAlias = Callable[..., object]


@dataclass(frozen=True, slots=True)
class RuntimeProfile:
    id: str
    context_mode: ContextMode = ContextMode.HISTORY
    capture_request: bool = True
    throttle_model: bool = True
    retry_model: bool = True
    enforce_turn_limit: bool = True
    enforce_context_budget: bool = True
    record_metrics: bool = True
    guard_tools: bool = True
    record_memory: bool = True
    compact_tool_output: bool = True
    extra_before_model: tuple[Callback, ...] = ()
    extra_before_tool: tuple[Callback, ...] = ()
    extra_after_tool: tuple[Callback, ...] = ()

    @classmethod
    def safe_default(cls) -> "RuntimeProfile":
        return cls(id="safe_default")


@dataclass(frozen=True, slots=True)
class OutputPolicy:
    max_chars: int = 15_000
    max_list_items: int = 30
    drop_fields: tuple[str, ...] = ()
    preserve_fields: tuple[str, ...] = ()


JsonScalar: TypeAlias = str | int | float | bool | None


@dataclass(frozen=True, slots=True)
class ToolLifecycleCallbacks:
    before: tuple[Callback, ...] = ()
    after: tuple[Callback, ...] = ()
    on_error: tuple[Callback, ...] = ()
    memory: tuple[Callback, ...] = ()


@dataclass(frozen=True, slots=True)
class AgentDescriptor:
    id: str
    name: str
    description: str
    prompt_id: str
    factory: AgentFactory
    runtime_profile_id: str = "safe_default"
    tool_ids: tuple[str, ...] = ()
    mcp_server_ids: tuple[str, ...] = ()
    sub_agent_ids: tuple[str, ...] = ()
    output_key: str | None = None
    metadata: Mapping[str, JsonScalar] = field(default_factory=dict)
    version: str = "1"


@dataclass(frozen=True, slots=True)
class ToolDescriptor:
    id: str
    description: str
    tool: ToolLike | None = None
    factory: ToolFactory | None = None
    output_policy: OutputPolicy = OutputPolicy()
    memory_codec_ids: tuple[str, ...] = ()
    callbacks: ToolLifecycleCallbacks = ToolLifecycleCallbacks()
    metadata: Mapping[str, JsonScalar] = field(default_factory=dict)
    version: str = "1"


@dataclass(frozen=True, slots=True)
class StdioTransport:
    command: str
    args: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    connect_timeout: float = 120.0


@dataclass(frozen=True, slots=True)
class SseTransport:
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    connect_timeout: float = 5.0
    read_timeout: float = 600.0


@dataclass(frozen=True, slots=True)
class StreamableHttpTransport:
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    connect_timeout: float = 5.0
    read_timeout: float = 600.0
    terminate_on_close: bool = True


@dataclass(frozen=True, slots=True)
class McpServerDescriptor:
    id: str
    transport: StdioTransport | SseTransport | StreamableHttpTransport
    required: bool = False
    tool_allowlist: tuple[str, ...] = ()
    tool_name_prefix: str | None = None
```

Define `AgentFactory` as a protocol accepting `AgentBuildContext` and returning ADK `BaseAgent`; use a postponed annotation plus a `TYPE_CHECKING` import so the descriptor layer does not create a runtime cycle. Define `ToolLike` as the same supported callable/base-tool/base-toolset union used by ADK, and `ToolFactory` as a protocol accepting `ToolBuildContext` and returning `ToolLike`. Validate that each tool supplies exactly one of `tool` or `factory`. In each descriptor's `__post_init__`, copy metadata, env, and header mappings into `MappingProxyType` so frozen descriptors retain no mutable mappings.

- [ ] **Step 4: Implement validated immutable catalog construction**

`CatalogBuilder.freeze(root_agent_id: str)` must:

1. Confirm the root exists.
2. Confirm every agent runtime-profile, tool, MCP, and sub-agent reference exists.
3. Detect cycles with a three-state depth-first traversal and reject agents unreachable from the declared root as extra roots.
4. Validate tool source exclusivity plus descriptor/transport invariants.
5. Return `CapabilityCatalog` with `MappingProxyType` copies for runtime profiles, agents, tools, and MCP servers.
6. Mark the builder frozen so later `add_*` calls raise `CatalogFrozenError`.

Expose typed errors: `DuplicateCapabilityError`, `UnresolvedCapabilityError`, `CapabilityCycleError`, `InvalidRootError`, `UnreachableAgentError`, `InvalidToolDescriptorError`, `InvalidTransportError`, `MissingEnvironmentValueError`, and `CatalogFrozenError`.

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests_arema/unit/registry/test_catalog.py -v`

Expected: all catalog tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/arema/registry tests_arema/unit/registry/test_catalog.py
git commit -m "feat: add typed capability catalog"
```

## Task 4: Connect typed MCP descriptors to resilient ADK toolsets

**Files:**
- Create: `src/arema/registry/mcp.py`
- Create: `tests_arema/unit/registry/test_mcp.py`

- [ ] **Step 1: Write failing transport and degradation tests**

```python
def test_streamable_http_descriptor_builds_adk_params() -> None:
    descriptor = McpServerDescriptor(
        id="sample",
        transport=StreamableHttpTransport(url="http://localhost:9000/mcp"),
    )
    toolset = build_mcp_toolset(descriptor)
    assert isinstance(toolset.connection_params, StreamableHTTPConnectionParams)
    assert toolset.tool_name_prefix is None


async def test_optional_server_degrades_to_empty_tools(monkeypatch) -> None:
    toolset = build_mcp_toolset(optional_sse_descriptor())

    async def fail(*args: object, **kwargs: object) -> list[BaseTool]:
        raise ConnectionError("offline")

    monkeypatch.setattr(McpToolset, "get_tools", fail)
    assert await toolset.get_tools() == []
    assert toolset.availability.status is McpStatus.UNAVAILABLE
    assert toolset.availability.error_type == "ConnectionError"


async def test_required_server_propagates_connection_failure(monkeypatch) -> None:
    toolset = build_mcp_toolset(required_sse_descriptor())
    monkeypatch.setattr(McpToolset, "get_tools", fail)
    with pytest.raises(ConnectionError, match="offline"):
        await toolset.get_tools()
```

Add tests for stdio, SSE, streamable HTTP, prefixing, tool allowlists, environment substitution, and invalid timeouts.

- [ ] **Step 2: Run tests and verify missing types**

Run: `uv run pytest tests_arema/unit/registry/test_mcp.py -v`

Expected: collection fails because `arema.registry.mcp` does not exist.

- [ ] **Step 3: Implement transport conversion and secret-safe substitution**

Use the validated transport descriptors created in Task 3. Add exhaustive `isinstance` conversion to the three ADK connection-parameter types. The catalog remains the ownership layer; this module only resolves environment placeholders and constructs runtime toolsets.

- [ ] **Step 4: Implement the resilient toolset**

Subclass `McpToolset` with a `required` flag and an immutable `McpAvailability` snapshot (`UNKNOWN`, `AVAILABLE`, or `UNAVAILABLE`, plus sanitized error type). `get_tools()` returns `[]`, updates availability, and logs a sanitized warning for optional failures; it re-raises for required failures. Resolve only explicit `${ENV_NAME}` placeholders in env/header values at construction time, fail with `MissingEnvironmentValueError` when absent, and never include the resolved value in logs or exceptions. Convert descriptor transports to `StdioConnectionParams`, `SseConnectionParams`, or `StreamableHTTPConnectionParams`. Apply `McpToolset`'s tool filter for the allowlist and never catch `asyncio.CancelledError`.

- [ ] **Step 5: Run tests**

Run:

```bash
uv run pytest tests_arema/unit/registry -v
uv run pytest tests/unit/test_mcp_toolsets.py -q
```

Expected: all new tests and the legacy resilience regression tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/arema/registry tests_arema/unit/registry/test_mcp.py
git commit -m "feat: add resilient typed MCP registration"
```

## Task 5: Port generic context budgeting and descriptor-driven output compaction

**Files:**
- Create: `src/arema/runtime/__init__.py`
- Create: `src/arema/runtime/context/__init__.py`
- Create: `src/arema/runtime/context/budget.py`
- Create: `src/arema/runtime/context/compactor.py`
- Create: `tests_arema/unit/runtime/test_context_budget.py`
- Create: `tests_arema/unit/runtime/test_output_compactor.py`

- [ ] **Step 1: Write failing context-policy tests**

Port the provider-neutral cases from the existing context tests and add descriptor-policy cases:

```python
def test_compactor_uses_policy_not_tool_name() -> None:
    response = {"raw": "x" * 100, "items": list(range(10)), "keep": "value"}
    policy = OutputPolicy(max_chars=200, max_list_items=3, drop_fields=("raw",))
    compacted = compact_response(response, policy)
    assert "raw" not in compacted
    assert compacted["items"] == [0, 1, 2]
    assert compacted["keep"] == "value"


@pytest.mark.parametrize(
    ("ratio", "pressure"),
    [(0.59, ContextPressure.NORMAL), (0.60, ContextPressure.WARNING),
     (0.75, ContextPressure.HARD), (0.85, ContextPressure.CRITICAL)],
)
def test_context_pressure_thresholds(ratio: float, pressure: ContextPressure) -> None:
    assert classify_pressure(ratio) is pressure
```

Add tests that critical pressure preserves one recent tool result and one recent model turn, repeated compaction is idempotent, and hard-limit exhaustion returns a checkpoint response.

- [ ] **Step 2: Run tests and verify missing runtime modules**

Run: `uv run pytest tests_arema/unit/runtime/test_context_budget.py tests_arema/unit/runtime/test_output_compactor.py -v`

Expected: collection failures for missing modules.

- [ ] **Step 3: Port and neutralize context budgeting**

Move the pure estimation, tool-result compaction, and model-text compaction behavior from `src/security_agent/callbacks/context_budget.py` into `arema.runtime.context.budget`. Read all thresholds and preservation counts from `Settings`; do not duplicate defaults as module constants. Replace assessment wording with run/session wording.

Expose these typed functions and implement their full bodies in this task:

```python
class ContextPressure(StrEnum):
    NORMAL = "normal"
    WARNING = "warning"
    HARD = "hard"
    CRITICAL = "critical"
```

- `estimate_tokens(contents: Sequence[Content]) -> int` estimates all text, function-call arguments, and function responses in the request.
- `classify_pressure(ratio: float, settings: Settings | None = None) -> ContextPressure` applies the configured warning, hard, and critical thresholds.
- `enforce_context_budget(callback_context: CallbackContext, llm_request: LlmRequest) -> LlmResponse | None` compacts at hard pressure and terminates safely at unrecoverable critical pressure.

At unrecoverable critical pressure, write checkpoint state and return an `LlmResponse` explaining that the run stopped before exceeding the configured context limit.

- [ ] **Step 4: Implement policy-driven compaction**

`compact_response(response, policy)` performs recursive field dropping, bounded list truncation, and largest-value deep truncation until `max_chars` is satisfied. `make_output_compactor(policy_by_tool_id)` returns an ADK after-tool callback and looks up the current tool ID in the immutable mapping. Unknown tools use the safe default policy.

- [ ] **Step 5: Run focused and legacy regression tests**

Run:

```bash
uv run pytest tests_arema/unit/runtime/test_context_budget.py tests_arema/unit/runtime/test_output_compactor.py -v
uv run pytest tests/unit/test_context_budget.py tests/unit/test_context_compactor.py -q
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/arema/runtime/context tests_arema/unit/runtime
git commit -m "feat: preserve neutral context management"
```

## Task 6: Build neutral runtime profiles and validated callback chains

**Files:**
- Modify: `src/arema/registry/descriptors.py`
- Modify: `src/arema/registry/catalog.py`
- Create: `src/arema/runtime/sessions.py`
- Create: `src/arema/runtime/services.py`
- Create: `src/arema/runtime/callbacks/__init__.py`
- Create: `src/arema/runtime/callbacks/capture_request.py`
- Create: `src/arema/runtime/callbacks/throttle.py`
- Create: `src/arema/runtime/callbacks/turn_limit.py`
- Create: `src/arema/runtime/callbacks/tool_guard.py`
- Create: `src/arema/runtime/callbacks/model_error.py`
- Create: `src/arema/runtime/callbacks/metrics.py`
- Create: `src/arema/runtime/callbacks/memory.py`
- Create: `src/arema/runtime/callbacks/chain.py`
- Create: `tests_arema/unit/runtime/test_callback_chain.py`
- Create: `tests_arema/unit/runtime/test_resilience.py`

- [ ] **Step 1: Write failing ordering and resilience tests**

```python
def test_safe_default_chain_has_stable_order() -> None:
    chain = build_callback_chain(
        RuntimeProfile.safe_default(),
        services=fake_services(),
        tools={},
    )
    assert callback_names(chain.before_model) == [
        "capture_request",
        "throttle_model_calls",
        "enforce_turn_limit",
        "enforce_context_budget",
        "record_model_usage",
    ]
    assert callback_names(chain.before_tool)[0] == "registered_tool_guard"
    assert callback_names(chain.after_tool) == [
        "record_tool_event",
        "compact_tool_output",
    ]


def test_chain_rejects_callback_after_compactor() -> None:
    with pytest.raises(CallbackOrderError, match="compactor must be last"):
        validate_callback_chain(invalid_chain())


async def test_capture_request_stores_latest_user_text() -> None:
    context, request = callback_fixture(user_text="hello AREMA")
    await capture_request(context, request)
    assert context.state[SessionKeys.USER_REQUEST] == "hello AREMA"
```

Add tests for throttle timing, per-agent turn limits, tool lookup recovery, model-error sanitization, metrics failures remaining fail-open, and memory-event sink failures remaining fail-open. Test fixtures provide a `RuntimeServices` value with a fake clock, metrics sink, and `MemoryEventSink`; no concrete store dependency is needed yet.

- [ ] **Step 2: Run tests and verify missing policy modules**

Run: `uv run pytest tests_arema/unit/runtime/test_callback_chain.py tests_arema/unit/runtime/test_resilience.py -v`

Expected: collection failures.

- [ ] **Step 3: Implement neutral state keys and finish runtime-profile validation**

```python
class SessionKeys(StrEnum):
    USER_REQUEST = "user_request"
    RUN_ID = "run_id"
    MEMORY_SCOPE_ID = "memory_scope_id"
    TURN_COUNT = "_runtime:turn_count"
    MODEL_CALLS = "_runtime:model_calls"
    TOOL_CALLS = "_runtime:tool_calls"
    CONTEXT_CHECKPOINT = "_runtime:context_checkpoint"
```

Keep `RuntimeProfile` in `arema.registry.descriptors`, where Task 3 establishes the registration contract. Extend the catalog tests to prove that an agent referencing an unknown profile fails with `UnresolvedCapabilityError`, that `safe_default` is available in the frozen profile mapping, and that the mapping is immutable.

- [ ] **Step 4: Port one-responsibility neutral callbacks**

Port the generic behavior from capture, throttle, turn-cap, tool-guard, model-error, and token/tool metrics callbacks. Define `RuntimeServices` and a small `MemoryEventSink` protocol so the callback layer depends on an interface, not SQLite or a concrete service. `record_tool_event` sends only tool ID, success/failure, elapsed time, run/scope IDs, and output size; it never sends arguments or raw output. Remove Playwright hints, assessment terms, phase counters, scan policy, JSON report assumptions, and raw security state keys. Use `CallbackContext.state` rather than `session.state` and structured sanitized logs.

- [ ] **Step 5: Implement chain construction and invariant validation**

`build_callback_chain(profile, services, tools)` creates immutable tuples in the approved order. For a tool call the after-tool order is outcome event, profile and `ToolDescriptor.callbacks.after` additions, codec-backed `ToolDescriptor.callbacks.memory` additions, then output compaction. A no-op memory sink preserves the default shape when persistent memory is disabled. `validate_callback_chain` asserts the registered-tool guard is first when enabled, memory/capability work precedes compaction, and compaction is last. Use identity-based role markers on callback wrappers rather than fragile function-name comparisons in production validation.

- [ ] **Step 6: Run tests**

Run:

```bash
uv run pytest tests_arema/unit/runtime -v
uv run pytest tests/unit/test_capture_user_request.py tests/unit/test_llm_throttle.py tests/unit/test_turn_cap.py tests/unit/test_unknown_tool_guard.py tests/unit/test_model_error_callback.py -q
```

Expected: all new tests and applicable legacy regressions pass.

- [ ] **Step 7: Commit**

```bash
git add src/arema/runtime tests_arema/unit/runtime
git commit -m "feat: add validated neutral runtime policies"
```

## Task 7: Define generic memory envelopes and versioned codecs

**Files:**
- Create: `src/arema/memory/__init__.py`
- Create: `src/arema/memory/models.py`
- Create: `src/arema/memory/codecs.py`
- Create: `src/arema/memory/errors.py`
- Create: `tests_arema/unit/memory/test_models.py`
- Create: `tests_arema/unit/memory/test_codecs.py`

- [ ] **Step 1: Write failing model and codec tests**

```python
def test_artifact_payload_requires_integrity_digest() -> None:
    with pytest.raises(ValidationError):
        ArtifactRecord(uri="file:///tmp/sample.bin", media_type="application/octet-stream")


def test_codec_upgrades_v1_payload_to_v2() -> None:
    registry = RecordCodecRegistry()
    registry.register(note_v1_codec())
    registry.register(note_v2_codec(upgrade_from_previous=upgrade_note_v1))
    decoded = registry.decode(envelope(kind="note", schema_version=1, payload={"text": "x"}))
    assert decoded == NoteRecord(text="x", author="unknown")


def test_unknown_record_remains_raw() -> None:
    envelope_value = envelope(namespace="extension", kind="unknown", payload={"x": 1})
    assert RecordCodecRegistry().decode(envelope_value) == envelope_value
```

- [ ] **Step 2: Run tests and verify missing memory modules**

Run: `uv run pytest tests_arema/unit/memory/test_models.py tests_arema/unit/memory/test_codecs.py -v`

Expected: collection failures.

- [ ] **Step 3: Implement envelope and payload models**

Use UTC-aware timestamps and strict Pydantic models:

```python
JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]


class MemoryScope(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: str = Field(default_factory=lambda: uuid4().hex)
    parent_id: str | None = None
    scope_type: str
    created_at: datetime = Field(default_factory=utc_now)
    closed_at: datetime | None = None
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


class MemoryEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: str = Field(default_factory=lambda: uuid4().hex)
    scope_id: str
    namespace: str
    kind: str
    schema_version: int = Field(ge=1)
    revision: int = Field(default=1, ge=1)
    source: str
    payload: dict[str, JsonValue]
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    content_hash: str
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None
```

Add `MemoryRelation`, `MemoryQuery`, `MemoryPage`, `EventRecord`, `ArtifactRecord`, `NoteRecord`, and `CheckpointRecord`. `ArtifactRecord` stores URI, media type, byte size, and SHA-256; it never stores artifact bytes.

Define a non-built-in error hierarchy in `memory/errors.py`: `MemoryStoreError` as the base plus `BackendInitError`, `BackendUnavailableError`, `RecordNotFoundError`, `RevisionConflictError`, `InvalidCursorError`, `CodecRegistrationError`, and `RelationIntegrityError`. Do not name a project exception `MemoryError`, because that is Python's built-in allocation failure.

- [ ] **Step 4: Implement codec registration and upgrade chains**

`RecordCodec[T]` contains namespace, kind, schema version, Pydantic payload type, and an optional upgrade function from the previous version. Registration rejects duplicate keys and broken version chains. Encoding computes a canonical SHA-256 over sorted JSON. Decoding applies each version upgrade in order and validates the current payload model.

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests_arema/unit/memory/test_models.py tests_arema/unit/memory/test_codecs.py -v`

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/arema/memory tests_arema/unit/memory
git commit -m "feat: add extensible memory record schema"
```

## Task 8: Implement the store protocol and in-memory backend

**Files:**
- Create: `src/arema/memory/store.py`
- Create: `src/arema/memory/backends/__init__.py`
- Create: `src/arema/memory/backends/memory.py`
- Create: `tests_arema/unit/memory/store_contract.py`
- Create: `tests_arema/unit/memory/test_memory_store.py`

- [ ] **Step 1: Write the reusable backend contract**

The contract test mixin must verify initialization, nested scopes, scope closure, insert/get, optimistic update, relation integrity, filters, tag filtering through `metadata["tags"]`, expiry exclusion, cursor pagination, deterministic `(created_at, id)` ordering, transactions, and health status. Instantiate it for `InMemoryStore` first.

Example conflict case:

```python
def test_update_rejects_stale_revision(store: MemoryStore) -> None:
    scope = store.create_scope(MemoryScope(scope_type="run"))
    record = store.insert_record(note_envelope(scope.id, "first"))
    store.update_record(record.model_copy(update={"payload": {"text": "second"}}), expected_revision=1)
    with pytest.raises(RevisionConflictError):
        store.update_record(record, expected_revision=1)
```

- [ ] **Step 2: Run the contract and verify missing store failure**

Run: `uv run pytest tests_arema/unit/memory/test_memory_store.py -v`

Expected: collection failure for missing backend.

- [ ] **Step 3: Define the backend protocol**

```python
@runtime_checkable
class MemoryStore(Protocol):
    def initialize(self) -> None:
        raise NotImplementedError

    def transaction(self) -> ContextManager[None]:
        raise NotImplementedError

    def create_scope(self, scope: MemoryScope) -> MemoryScope:
        raise NotImplementedError

    def get_scope(self, scope_id: str) -> MemoryScope | None:
        raise NotImplementedError

    def close_scope(self, scope_id: str, closed_at: datetime) -> MemoryScope:
        raise NotImplementedError

    def insert_record(self, record: MemoryEnvelope) -> MemoryEnvelope:
        raise NotImplementedError

    def get_record(self, record_id: str) -> MemoryEnvelope | None:
        raise NotImplementedError

    def update_record(
        self,
        record: MemoryEnvelope,
        expected_revision: int,
    ) -> MemoryEnvelope:
        raise NotImplementedError

    def query_records(self, query: MemoryQuery) -> MemoryPage:
        raise NotImplementedError

    def create_relation(self, relation: MemoryRelation) -> MemoryRelation:
        raise NotImplementedError

    def list_relations(self, record_id: str) -> tuple[MemoryRelation, ...]:
        raise NotImplementedError

    def health(self) -> StoreHealth:
        raise NotImplementedError
```

- [ ] **Step 4: Implement the in-memory backend**

Use dictionaries protected by `threading.RLock`. Transactions snapshot all dictionaries and restore them on exception. Cursor tokens are URL-safe base64 encodings of compact JSON containing the last `created_at` and `id`; malformed cursors raise `InvalidCursorError`. Return model copies so callers cannot mutate stored state.

- [ ] **Step 5: Run contract tests**

Run: `uv run pytest tests_arema/unit/memory/test_memory_store.py -v`

Expected: all in-memory contract cases pass.

- [ ] **Step 6: Commit**

```bash
git add src/arema/memory tests_arema/unit/memory
git commit -m "feat: add generic memory store contract"
```

## Task 9: Implement SQLite migrations, backend parity, and memory service

**Files:**
- Create: `src/arema/memory/migrations.py`
- Create: `src/arema/memory/backends/sqlite.py`
- Create: `src/arema/memory/service.py`
- Modify: `src/arema/runtime/services.py`
- Create: `tests_arema/unit/memory/test_sqlite_store.py`
- Create: `tests_arema/unit/memory/test_service.py`
- Modify: `tests_arema/unit/runtime/test_callback_chain.py`

- [ ] **Step 1: Parametrize the shared store contract for SQLite**

Use a temporary database fixture:

```python
@pytest.fixture
def store(tmp_path: Path) -> Iterator[SQLiteStore]:
    value = SQLiteStore(tmp_path / "arema.db")
    value.initialize()
    yield value
    value.close()
```

Run the entire contract from Task 8 against this fixture. Add tests that initialization is repeatable, migration rows apply once, foreign keys reject missing scopes/records, WAL mode is enabled, and concurrent optimistic updates produce one winner.

- [ ] **Step 2: Run SQLite tests and verify failures**

Run: `uv run pytest tests_arema/unit/memory/test_sqlite_store.py -v`

Expected: collection failure for missing `SQLiteStore`.

- [ ] **Step 3: Implement migration 1 exactly as the approved envelope**

Create tables `memory_scopes`, `memory_records`, `memory_relations`, and `schema_migrations`. Use text ISO-8601 UTC timestamps, JSON text payload/metadata, foreign keys, and indexes:

```sql
CREATE INDEX idx_memory_records_scope_kind
ON memory_records(scope_id, namespace, kind, created_at, id);

CREATE INDEX idx_memory_records_source
ON memory_records(source, created_at, id);

CREATE INDEX idx_memory_records_expiry
ON memory_records(expires_at);
```

Apply migrations inside `BEGIN IMMEDIATE`; insert the migration version only after its statements succeed.

- [ ] **Step 4: Implement SQLite backend parity**

Use parameterized SQL for values and fixed SQL identifiers only. Enable `PRAGMA journal_mode=WAL`, `PRAGMA foreign_keys=ON`, and a bounded busy timeout. Optimistic updates use `WHERE id = ? AND revision = ?`; zero affected rows distinguish missing records from revision conflicts. Relation inserts rely on foreign keys and translate integrity failures into typed memory errors.

- [ ] **Step 5: Write and implement service behavior and runtime integration**

Test and implement `MemoryService` methods that encode typed payloads, call the store, decode pages, and expose health. `retrieve_bounded(query, *, max_records, token_limit)` caps both record count and estimated serialized payload tokens before returning data for model context, with settings supplying conservative defaults. No query result enters an agent instruction automatically. Add `safe_append_event`: it catches `MemoryStoreError`, logs a sanitized warning, marks service health degraded, and returns `False`; `append_event` remains strict and raises.

```python
def safe_append_event(self, scope_id: str, event: EventRecord, *, source: str) -> bool:
    try:
        self.append(scope_id, event, namespace="arema.core", kind="event", source=source)
    except MemoryStoreError as exc:
        logger.warning("memory event write failed", error_type=type(exc).__name__)
        return False
    return True
```

Make `MemoryService` satisfy the `MemoryEventSink` protocol from Task 6. Resolve the scope from `SessionKeys.MEMORY_SCOPE_ID`; create the run scope in the runner, not inside individual callbacks. Extend callback-chain tests with the real service over `InMemoryStore` and assert that `record_tool_event` writes a sanitized `arema.core/event` envelope before capability callbacks and output compaction. If `SessionKeys.CONTEXT_CHECKPOINT` is present, the after-agent lifecycle recorder writes a `CheckpointRecord` before the scope closes. Store lifecycle metadata only—tool ID, status, elapsed time, counts, run/scope IDs, output size, and bounded checkpoint state—and never raw prompts, tool arguments, model text, or tool output.

- [ ] **Step 6: Run all memory tests**

Run: `uv run pytest tests_arema/unit/memory -v`

Expected: both backends pass the same contract and all service tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/arema/memory tests_arema/unit/memory
git commit -m "feat: add SQLite memory service"
```

## Task 10: Compose the smoke root agent with the safe runtime profile

**Files:**
- Create: `src/arema/prompts/__init__.py`
- Create: `src/arema/prompts/loader.py`
- Create: `src/arema/prompts/smoke_agent.md`
- Create: `src/arema/runtime/agent_factory.py`
- Create: `src/arema/agents/__init__.py`
- Create: `src/arema/agents/smoke_agent.py`
- Create: `src/arema/composition.py`
- Create: `src/arema/agent.py`
- Create: `agents/arema/__init__.py`
- Create: `agents/arema/agent.py`
- Create: `tests_arema/component/test_smoke_composition.py`

- [ ] **Step 1: Write failing smoke composition tests**

```python
def test_default_catalog_contains_only_smoke_agent() -> None:
    composition = build_default_composition(settings=ollama_settings())
    assert composition.catalog.root_agent_id == "smoke_agent"
    assert tuple(composition.catalog.agents) == ("smoke_agent",)
    assert not composition.catalog.tools
    assert not composition.catalog.mcp_servers


def test_root_agent_has_no_capabilities() -> None:
    from arema.agent import root_agent

    assert root_agent.name == "smoke_agent"
    assert root_agent.tools == []
    assert root_agent.sub_agents == []
    assert root_agent.on_tool_error_callback is not None
```

Also assert the before-model order, no transfer tool, history context mode, package-relative prompt loading, and ADK wrapper identity.

- [ ] **Step 2: Run tests and verify composition failure**

Run with a local no-key provider:

```bash
LLM_PROVIDER=ollama uv run pytest tests_arema/component/test_smoke_composition.py -v
```

Expected: missing composition/agent modules.

- [ ] **Step 3: Implement prompt loading and smoke prompt**

Use `importlib.resources.files("arema.prompts")` so installed wheels work outside the repository root. The prompt content is:

```markdown
# AREMA Infrastructure Smoke Agent

You are the domain-neutral smoke agent for AREMA (Autonomous Reverse Engineering & Malware Analysis).

Your purpose is to verify that the ADK runtime, model connection, sessions, context policies, resilience callbacks, and memory health are operational.

You have no tools, MCP servers, sub-agents, reverse-engineering capabilities, or malware-analysis capabilities. Never claim that those capabilities are available. Respond briefly and conversationally. When asked for unavailable analysis, explain that this milestone is an infrastructure shell.
```

- [ ] **Step 4: Implement generic agent building and composition**

`ToolBuildContext` includes settings, runtime services, and the frozen catalog; use it only when a descriptor selects `factory` instead of a concrete tool. `AgentBuildContext` includes the descriptor, resolved model, instruction, tools, sub-agents, callback chain, and optional output key. Resolve the model with `use_retries=profile.retry_model`. `build_llm_agent` maps context mode to ADK `include_contents` (`"default"` for history and `"none"` for isolation), passes both tool-error and model-error callbacks, and never mutates the catalog.

`build_default_composition(settings: Settings | None = None)`:

1. Registers `RuntimeProfile.safe_default()`.
2. Registers the smoke descriptor.
3. Freezes one root and empty tool/MCP registries.
4. Creates the configured memory service; the runner creates one scope per run and places its ID in session state.
5. Validates every registered tool's `memory_codec_ids` against the immutable `RecordCodecRegistry` before resolving capabilities.
6. Composes agents in dependency order and attaches a fail-open after-agent lifecycle recorder when the selected profile enables memory.
7. Returns frozen `ApplicationComposition(catalog, root_agent, memory_service)`.

`src/arema/agent.py` exports `root_agent = get_default_composition().root_agent`. The top-level `agents/arema/agent.py` only re-exports that value.

- [ ] **Step 5: Run smoke, registry, runtime, and memory tests**

Run:

```bash
LLM_PROVIDER=ollama uv run pytest tests_arema -v
LLM_PROVIDER=ollama uv run python -c "from arema.agent import root_agent; print(root_agent.name, len(root_agent.tools), len(root_agent.sub_agents))"
```

Expected: all tests pass and the command prints `smoke_agent 0 0`.

- [ ] **Step 6: Commit**

```bash
git add src/arema agents/arema tests_arema/component
git commit -m "feat: compose no-tools AREMA smoke agent"
```

## Task 11: Add the neutral runner and CLI

**Files:**
- Create: `src/arema/runner.py`
- Create: `src/arema/cli.py`
- Create: `tests_arema/component/test_runner.py`
- Create: `tests_arema/component/test_cli.py`

- [ ] **Step 1: Write failing runner and CLI tests**

Inject the runner boundary instead of calling a live provider:

```python
async def test_run_single_query_collects_text(fake_runner_factory) -> None:
    response = await run_single_query("hello", runner_factory=fake_runner_factory)
    assert response == "AREMA runtime operational"
    assert fake_runner_factory.closed


def test_cli_help_is_neutral() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "arema.cli", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Autonomous Reverse Engineering & Malware Analysis" in result.stdout
    assert "security agent" not in result.stdout.lower()
```

Add tests for `--version`, `--query`, `/help`, `/status`, `/exit`, runner cleanup after exceptions, and one distinct memory scope per run. `/status` reports one agent, zero tools, zero MCP servers, and memory health.

- [ ] **Step 2: Run tests and verify missing entry points**

Run: `uv run pytest tests_arema/component/test_runner.py tests_arema/component/test_cli.py -v`

Expected: collection failures.

- [ ] **Step 3: Implement runner without import-time side effects**

Port response-event collection from the existing runner. Do not call `configure_logging()` at module import. Accept an injectable `RunnerFactory` in `run_single_query`; the default creates `InMemoryRunner(agent=root_agent, app_name=settings.app_name)`. Before starting, create a `MemoryScope(scope_type="run")` and seed `SessionKeys.RUN_ID` plus `SessionKeys.MEMORY_SCOPE_ID` into the ADK session state. Close the memory scope and runner in `finally`, including provider-error paths. Log query length, not query contents.

- [ ] **Step 4: Implement neutral CLI commands**

Use `argparse` and Rich. The CLI exposes `--query`, `--web`, `--port`, `--verbose`, and `--version`. Interactive commands are `/help`, `/status`, `/clear`, and `/exit`; there are no `/tools` or `/agents` capability lists beyond the factual status summary. Call `configure_logging()` inside `main()`. Lazily import runner/composition code after argument parsing so `arema --help` and `arema --version` require neither provider credentials nor a writable memory path.

- [ ] **Step 5: Run component tests**

Run: `LLM_PROVIDER=ollama uv run pytest tests_arema/component -v`

Expected: all component tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/arema/runner.py src/arema/cli.py tests_arema/component
git commit -m "feat: add neutral AREMA runner and CLI"
```

## Task 12: Switch project metadata, development tooling, CI, and documentation

**Files:**
- Modify: `pyproject.toml`
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yml`
- Modify: `.env.example`
- Modify: `.gitignore`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Create: `docs/ARCHITECTURE.md`
- Create: `docs/EXTENDING_AREMA.md`
- Create: `docs/CONTEXT_AND_RESILIENCE.md`
- Create: `tests_arema/architecture/test_neutral_boundaries.py`
- Modify: `uv.lock`

- [ ] **Step 1: Write failing tooling and architecture tests**

```python
def test_project_metadata_is_arema() -> None:
    data = tomllib.loads(Path("pyproject.toml").read_text())
    assert data["project"]["name"] == "arema"
    assert data["project"]["scripts"] == {"arema": "arema.cli:main"}
    assert data["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["src/arema"]


def test_arema_source_has_no_legacy_imports() -> None:
    source = "\n".join(path.read_text() for path in Path("src/arema").rglob("*.py"))
    assert "security_agent" not in source
    assert "security_tools" not in source


def test_default_composition_has_no_domain_registration_terms() -> None:
    source = Path("src/arema/composition.py").read_text().lower()
    for term in ("playwright", "radare2", "r2mcp", "nmap", "sqlmap", "assessment"):
        assert term not in source
```

- [ ] **Step 2: Run tests and verify metadata failure**

Run: `uv run pytest tests_arema/architecture -v`

Expected: project metadata assertions fail while the transitional package configuration remains.

- [ ] **Step 3: Rewrite project metadata and dependencies**

Set:

```toml
[project]
name = "arema"
version = "0.1.0"
description = "Extensible Google ADK foundation for Autonomous Reverse Engineering & Malware Analysis"
requires-python = ">=3.11"
dependencies = [
    "google-adk==1.25.1",
    "litellm>=1.80.8,<2.0",
    "pydantic>=2.0,<3.0",
    "pydantic-settings>=2.0,<3.0",
    "python-dotenv>=1.0,<2.0",
    "structlog>=24.0,<26.0",
    "rich>=13.0,<15.0",
]

[project.scripts]
arema = "arema.cli:main"

[tool.hatch.build.targets.wheel]
packages = ["src/arema"]
```

Keep pytest, pytest-asyncio, pytest-cov, Hypothesis, Ruff, mypy, and pre-commit in development dependencies. Remove the `security-tools` optional dependency and uv source. Change coverage source and mypy/Make targets to `src/arema`.

- [ ] **Step 4: Rewrite environment, Make, and CI configuration**

`.env.example` retains provider, model override, retry, context, logging, turn-limit, and memory settings only. Use `MEMORY_PATH=~/.arema/memory/arema.db`. Remove every gateway, scanner, browser, report, and security API key setting.

Make targets are `setup`, `run`, `adk-run`, `adk-web`, `test`, `test-unit`, `test-component`, `lint`, `format-check`, `type-check`, `check`, and `clean`. CI removes `continue-on-error`, runs Ruff and mypy against `src/arema`, and runs `tests_arema` until Task 13 renames it.

- [ ] **Step 5: Reset active documentation**

Rewrite `README.md` and `CLAUDE.md` around the approved milestone. Create exact extension instructions showing one descriptor registration in `composition.py` for an agent, tool, MCP server, memory codec, and runtime profile. State prominently that reverse engineering and malware analysis are not implemented yet.

- [ ] **Step 6: Lock dependencies and run tooling tests**

Run:

```bash
uv lock
uv sync --extra dev
uv run pytest tests_arema/architecture -v
uv run ruff check src/arema tests_arema
uv run ruff format --check src/arema tests_arema
uv run mypy src/arema
```

Expected: all commands pass.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml uv.lock Makefile .github/workflows/ci.yml .env.example .gitignore README.md CLAUDE.md docs src/arema tests_arema
git commit -m "chore: switch project identity to AREMA"
```

## Task 13: Physically remove the legacy domain implementation

**Files:**
- Delete: `src/security_agent/`
- Delete: `agents/security_agent/`
- Delete: `.adk/prompts/`, `.adk/SOUL.md`, `.adk/CONSTITUTION.md`
- Delete: `mcp-servers/`
- Delete: `.mcp.json`
- Delete: root `docker-compose.yml`
- Delete: `targets/`, `templates/`, `schemas/`, `examples/`, security report scripts
- Delete: legacy `tests/`
- Rename: `tests_arema/` to `tests/`
- Delete: security-specific historical documentation and Claude agent/skill files
- Modify: `pyproject.toml`, `Makefile`, `.github/workflows/ci.yml`, `.gitignore`

- [ ] **Step 1: Verify the replacement suite passes before deletion**

Run:

```bash
LLM_PROVIDER=ollama uv run pytest tests_arema -q
uv run ruff check src/arema tests_arema
uv run mypy src/arema
git tag --list pre-arema-domain-reset-2026-07-21
```

Expected: all checks pass and the recovery tag exists.

- [ ] **Step 2: Enumerate deletion targets before removing them**

Run:

```bash
git ls-files src/security_agent agents/security_agent .adk mcp-servers targets templates schemas examples tests
git ls-files docs | rg '2026-04|docs/spec/done|docs/todo|Disrupting-the-first|ONBOARDING_NEW|TEST_ADK_PROMPTS'
```

Expected: output contains only the legacy files described by the approved design plus the old test suite. Confirm `docs/superpowers/specs/2026-07-21-arema-domain-neutral-shell-design.md` and this plan are not in the deletion list.

- [ ] **Step 3: Delete tracked legacy trees and assets**

Remove the enumerated legacy trees and root assets with these bounded paths:

```bash
git rm -r src/security_agent agents/security_agent .adk mcp-servers targets templates schemas examples scripts
git rm .mcp.json docker-compose.yml src/.adk/session.db
git rm .claude/agents/adk-python-engineer.md .claude/scheduled_tasks.lock
git rm -r .claude/skills/adk-agent-patterns
git rm -r docs/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign_convertedToImages docs/plans docs/spec docs/todo
git rm docs/ANTHROPIC.md docs/CONTAINER_TOOL_VALIDATION.md docs/CONTEXT_MANAGEMENT.md docs/GOOGLE_GEMINI.md docs/LMSTUDIO.md docs/OLLAMA.md docs/ONBOARDING_NEW_AGENT.md docs/ONBOARDING_NEW_AGENT_FAMILY.md docs/ONBOARDING_NEW_TOOL.md docs/OPENAI.md docs/OPENAI_COMPATIBLE.md docs/TEST_ADK_PROMPTS.md docs/ZAI.md
git rm docs/superpowers/plans/2026-04-*.md docs/superpowers/specs/2026-04-*.md
```

Retain `.claude/skills/python-engineering-patterns/` because it is generic. The new README and three neutral architecture/extension/runtime documents replace the deleted provider and context guides.

Do not delete the approved 2026-07-21 design or implementation plan.

- [ ] **Step 4: Replace the old test tree**

Run:

```bash
git rm -r tests
git mv tests_arema tests
```

Update `pyproject.toml`, Makefile, and CI from `tests_arema` to `tests`.

- [ ] **Step 5: Verify runtime databases are gone and tighten ignores**

The commands in Step 3 remove every tracked `.adk/session.db` under `src`, `agents`, and `scripts`. Verify with `git ls-files | rg 'session\.db$'` and expect no output. Keep generic ignores for `.adk/`, `*.db`, `*.db-wal`, and `*.db-shm`. Remove Playwright and reverse-engineering-specific ignore entries.

- [ ] **Step 6: Re-lock and verify imports after physical removal**

Run:

```bash
uv lock
uv sync --extra dev
LLM_PROVIDER=ollama uv run python -c "from arema.agent import root_agent; assert root_agent.name == 'smoke_agent'"
uv run pytest tests -q
```

Expected: AREMA imports and the complete replacement suite passes with no legacy package present.

- [ ] **Step 7: Commit the deletion**

```bash
git add -A
git commit -m "refactor: remove legacy security domain"
```

## Task 14: Run final architecture, quality, and cleanliness verification

**Files:**
- Modify only if verification exposes a defect: `src/arema/**`, `tests/**`, neutral docs/config

- [ ] **Step 1: Run the complete quality gate**

Run:

```bash
uv run ruff check src/arema tests
uv run ruff format --check src/arema tests
uv run mypy src/arema
LLM_PROVIDER=ollama uv run pytest tests -v --tb=short
```

Expected: every command exits zero.

- [ ] **Step 2: Verify composition and public entry points**

Run:

```bash
LLM_PROVIDER=ollama uv run python -c "from arema.agent import root_agent; print(root_agent.name, len(root_agent.tools), len(root_agent.sub_agents))"
uv run arema --help
uv run arema --version
```

Expected: `smoke_agent 0 0`, neutral AREMA help text, and `arema 0.1.0`.

- [ ] **Step 3: Search active code and configuration for stale coupling**

Run:

```bash
test ! -e src/security_agent
test ! -e mcp-servers
test ! -e docker-compose.yml
test ! -e .mcp.json
! rg -n "security_agent|security_tools|reverse_engineering_agent|security_assessment_agent|playwright|r2mcp|radare2|nmap|sqlmap" src/arema agents/arema pyproject.toml Makefile .env.example .github README.md CLAUDE.md docs/ARCHITECTURE.md docs/EXTENDING_AREMA.md docs/CONTEXT_AND_RESILIENCE.md
```

Expected: all assertions succeed and `rg` returns no matches. The acronym expansion in general project documentation is allowed; implemented-capability claims are not.

- [ ] **Step 4: Verify repository cleanliness**

Run:

```bash
git status --short
git ls-files | rg '(__pycache__|\.pyc$|session\.db$|\.pytest_cache|\.ruff_cache|\.mypy_cache|htmlcov|^\.coverage$)'
```

Expected: clean status and no tracked generated artifacts.

- [ ] **Step 5: Commit any verification-only corrections**

If Step 1–4 required changes, rerun all four steps and commit only the corrections:

```bash
git add -A
git commit -m "fix: satisfy AREMA shell quality gate"
```

If no files changed, do not create an empty commit.

## Handoff criteria

The implementation is ready for review when:

- The recovery tag exists.
- `src/arema` is the only application package.
- `arema.agent:root_agent` is the smoke agent with zero tools and zero sub-agents.
- The default catalog has zero MCP server descriptors.
- Both memory backends pass the same store contract.
- Context, callback-order, resilience, and architecture tests pass.
- Legacy code and generated artifacts are physically absent.
- The full quality gate and cleanliness checks pass.
