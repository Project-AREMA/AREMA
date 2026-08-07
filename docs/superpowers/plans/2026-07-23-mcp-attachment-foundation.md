# MCP-Attachment Foundation (Spec B, B.0) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lift the `mcp_server_ids` `NotImplementedError` in AREMA's agent factory so an ADK `LlmAgent` can attach MCP toolsets from the catalog — the domain-neutral prerequisite that makes the radare2-mcp integration (Spec B B.1/B.2) possible.

**Architecture:** Three small, backward-compatible additions: (1) `ResilientMcpToolset` forwards an optional `header_provider` to ADK's `McpToolset`; (2) `McpServerDescriptor` carries an optional `header_provider`; (3) `agent_factory._build_agent` resolves each `mcp_server_id` via the existing `build_mcp_toolset` and appends it to the agent's `tools`. No composite agents, no cluster, no domain code — pure plumbing, fully testable in `make check`.

**Tech Stack:** Python 3.11+, Google ADK 1.25.1 (`McpToolset.header_provider`), pydantic, pytest, ruff, mypy. Reference spec: `docs/superpowers/specs/2026-07-23-re-malware-mvp-design.md` (§ "The MCP-attachment seam (B.0)").

> **Commit signing:** this repo signs via 1Password, which is failing. For every commit step use EXACTLY `git -c commit.gpgsign=false commit -m "..."` (one-shot override; do NOT modify git config).

---

## File Structure

**Modify:**
- `src/arema/registry/mcp.py` — `ResilientMcpToolset.__init__` gains `header_provider`; `build_mcp_toolset` forwards `descriptor.header_provider`.
- `src/arema/registry/descriptors.py` — new `HeaderProvider` type alias; `McpServerDescriptor.header_provider` field.
- `src/arema/runtime/agent_factory.py` — replace the `mcp_server_ids` `NotImplementedError` with toolset resolution; add `import os` + `build_mcp_toolset` import.

**Create (tests):**
- `tests/unit/registry/test_mcp_header_provider.py` — `ResilientMcpToolset` + `McpServerDescriptor` + `build_mcp_toolset` header_provider plumbing.
- `tests/unit/runtime/test_mcp_attachment.py` — an agent with `mcp_server_ids` resolves MCP toolsets into its `tools` (wiring test with a stubbed `build_mcp_toolset`).

---

## Task 1: `ResilientMcpToolset` forwards `header_provider`

**Files:**
- Modify: `src/arema/registry/mcp.py` (`ResilientMcpToolset.__init__`, ~lines 91-107)
- Test: `tests/unit/registry/test_mcp_header_provider.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/registry/test_mcp_header_provider.py`:

```python
"""header_provider plumbing for the resilient MCP toolset + descriptor."""

from __future__ import annotations

from mcp import StdioServerParameters

from arema.registry.mcp import ResilientMcpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams


def _stdio_params() -> StdioConnectionParams:
    return StdioConnectionParams(
        server_params=StdioServerParameters(command="true", args=[]),
        timeout=5.0,
    )


def test_resilient_toolset_accepts_header_provider() -> None:
    def hp(_ctx: object) -> dict[str, str]:
        return {"X-Test": "v"}

    toolset = ResilientMcpToolset(
        descriptor_id="test",
        required=False,
        connection_params=_stdio_params(),
        header_provider=hp,
    )

    assert toolset.required is False
    # ADK's McpToolset stores the provider privately; reaching here proves the kwarg
    # was forwarded (super() would TypeError on an unexpected keyword otherwise).
    assert toolset._header_provider is hp


def test_resilient_toolset_header_provider_defaults_none() -> None:
    toolset = ResilientMcpToolset(
        descriptor_id="test",
        required=False,
        connection_params=_stdio_params(),
    )

    assert toolset._header_provider is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra dev pytest tests/unit/registry/test_mcp_header_provider.py -v`
Expected: FAIL — `TypeError: __init__() got an unexpected keyword argument 'header_provider'`.

- [ ] **Step 3: Forward `header_provider` to the ADK base class**

In `src/arema/registry/mcp.py`, edit `ResilientMcpToolset.__init__` to accept and forward `header_provider`. The full method becomes:

```python
    def __init__(
        self,
        *,
        descriptor_id: str,
        required: bool,
        connection_params: McpConnectionParams,
        tool_filter: list[str] | None = None,
        tool_name_prefix: str | None = None,
        header_provider: HeaderProvider | None = None,
    ) -> None:
        super().__init__(
            connection_params=connection_params,
            tool_filter=tool_filter,
            tool_name_prefix=tool_name_prefix,
            header_provider=header_provider,
        )
        self._descriptor_id = descriptor_id
        self.required = required
        self._availability = McpAvailability(status=McpStatus.UNKNOWN)
```

Then add the `HeaderProvider` import at the top of `mcp.py`. The existing `if TYPE_CHECKING:` block (around line 29-33) imports from ADK; add the alias import there is NOT suitable because `Callable` is needed at runtime for the default. Instead, import `HeaderProvider` from descriptors at module top (it is a runtime `Callable` alias defined in Task 2). Add to the runtime imports near the top:

```python
from arema.registry.descriptors import (
    HeaderProvider,
    McpServerDescriptor,
    SseTransport,
    StdioTransport,
    StreamableHttpTransport,
)
```

(i.e. add `HeaderProvider` to the existing `from arema.registry.descriptors import (...)` block — do not duplicate the import.)

> Note: Task 2 defines `HeaderProvider` in `descriptors.py`. If you run this task's test before Task 2 lands, the import will fail — that is expected; the test goes green once Task 2 is done. Alternatively, do Task 2 first. The plan orders Task 1 then Task 2, but they are tightly coupled; completing both makes the test pass.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --extra dev pytest tests/unit/registry/test_mcp_header_provider.py -v`
Expected: PASS (after Task 2 lands; `toolset.header_provider is hp` confirms ADK stored it).

- [ ] **Step 5: Commit**

```bash
git add src/arema/registry/mcp.py
git -c commit.gpgsign=false commit -m "feat: forward header_provider through ResilientMcpToolset"
```

---

## Task 2: `HeaderProvider` alias + `McpServerDescriptor.header_provider`

**Files:**
- Modify: `src/arema/registry/descriptors.py` (add alias ~top; add field to `McpServerDescriptor` ~lines 449-469)
- Test: `tests/unit/registry/test_mcp_header_provider.py` (append)

- [ ] **Step 1: Append the failing test**

Append to `tests/unit/registry/test_mcp_header_provider.py`:

```python
from arema.registry.descriptors import McpServerDescriptor, StdioTransport


def test_descriptor_carries_optional_header_provider() -> None:
    def hp(_ctx: object) -> dict[str, str]:
        return {"X-Sandbox-Port": "8765"}

    descriptor = McpServerDescriptor(
        id="radare2_mcp",
        transport=StdioTransport(command="true", args=()),
        header_provider=hp,
    )

    assert descriptor.header_provider is hp


def test_descriptor_header_provider_defaults_none() -> None:
    descriptor = McpServerDescriptor(
        id="radare2_mcp",
        transport=StdioTransport(command="true", args=()),
    )

    assert descriptor.header_provider is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra dev pytest tests/unit/registry/test_mcp_header_provider.py -k descriptor -v`
Expected: FAIL — `HeaderProvider` not defined / `header_provider` not a field.

- [ ] **Step 3: Add the alias + field**

In `src/arema/registry/descriptors.py`, add the `HeaderProvider` type alias near the other type aliases (after the `_Item = TypeVar(...)` line, ~line 36). `Callable` is already imported at the top (`from collections.abc import Callable, Iterable, Mapping`):

```python
# A callable that returns extra HTTP headers for a remote MCP server, invoked per
# request with the ADK readonly context. Used to inject per-run routing headers
# (e.g. X-Sandbox-ID / X-Sandbox-Port / Authorization) for a sandboxed MCP server.
# The context is typed as ``object`` here to avoid coupling the descriptor layer to
# ADK's ReadonlyContext; the value passed at runtime is the ADK ReadonlyContext.
HeaderProvider = Callable[[object], dict[str, str]]
```

Then add the field to `McpServerDescriptor` (after `tool_name_prefix`, before `__post_init__`):

```python
@dataclass(frozen=True, slots=True)
class McpServerDescriptor:
    """A named MCP server and its exposed-tool policy."""

    id: str
    transport: StdioTransport | SseTransport | StreamableHttpTransport
    required: bool = False
    tool_allowlist: tuple[str, ...] = ()
    tool_name_prefix: str | None = None
    header_provider: HeaderProvider | None = None
```

(The frozen dataclass accepts the new field with a default; `__post_init__` only immutizes `tool_allowlist`, which is unchanged.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run --extra dev pytest tests/unit/registry/test_mcp_header_provider.py -v`
Expected: PASS (all 4 tests — the Task 1 pair now resolve `HeaderProvider` too).

- [ ] **Step 5: Lint + types**

Run: `uv run --extra dev ruff check src/arema/registry/descriptors.py src/arema/registry/mcp.py tests/unit/registry/test_mcp_header_provider.py && uv run --extra dev mypy src/arema/registry/descriptors.py src/arema/registry/mcp.py`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/arema/registry/descriptors.py tests/unit/registry/test_mcp_header_provider.py
git -c commit.gpgsign=false commit -m "feat: add header_provider field to McpServerDescriptor"
```

---

## Task 3: `build_mcp_toolset` forwards `descriptor.header_provider`

**Files:**
- Modify: `src/arema/registry/mcp.py` (`build_mcp_toolset`, ~lines 263-288)
- Test: `tests/unit/registry/test_mcp_header_provider.py` (append)

- [ ] **Step 1: Append the failing test**

Append to `tests/unit/registry/test_mcp_header_provider.py`:

```python
from arema.registry.mcp import build_mcp_toolset


def test_build_mcp_toolset_forwards_header_provider() -> None:
    def hp(_ctx: object) -> dict[str, str]:
        return {"X-Sandbox-Port": "8765"}

    descriptor = McpServerDescriptor(
        id="radare2_mcp",
        transport=StdioTransport(command="true", args=()),
        header_provider=hp,
    )

    toolset = build_mcp_toolset(descriptor)

    assert isinstance(toolset, ResilientMcpToolset)
    assert toolset._header_provider is hp
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra dev pytest tests/unit/registry/test_mcp_header_provider.py::test_build_mcp_toolset_forwards_header_provider -v`
Expected: FAIL — `toolset.header_provider is None` (build_mcp_toolset does not pass it yet).

- [ ] **Step 3: Forward the provider in `build_mcp_toolset`**

In `src/arema/registry/mcp.py`, edit the `return ResilientMcpToolset(...)` at the end of `build_mcp_toolset` to pass the descriptor's provider:

```python
    return ResilientMcpToolset(
        descriptor_id=descriptor.id,
        required=descriptor.required,
        connection_params=connection_params,
        tool_filter=list(descriptor.tool_allowlist) or None,
        tool_name_prefix=descriptor.tool_name_prefix,
        header_provider=descriptor.header_provider,
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run --extra dev pytest tests/unit/registry/test_mcp_header_provider.py -v`
Expected: PASS (all 5).

- [ ] **Step 5: Commit**

```bash
git add src/arema/registry/mcp.py tests/unit/registry/test_mcp_header_provider.py
git -c commit.gpgsign=false commit -m "feat: forward descriptor header_provider in build_mcp_toolset"
```

---

## Task 4: Resolve `mcp_server_ids` into agent tools (lift the `NotImplementedError`)

This is the core wiring. An `AgentDescriptor` with `mcp_server_ids` must produce an `LlmAgent` whose `tools` include the resolved `ResilientMcpToolset`s.

**Files:**
- Modify: `src/arema/runtime/agent_factory.py` (imports + `_build_agent`, ~lines 155-166)
- Test: `tests/unit/runtime/test_mcp_attachment.py`

- [ ] **Step 1: Write the failing wiring test**

Create `tests/unit/runtime/test_mcp_attachment.py`:

```python
"""An agent with mcp_server_ids resolves MCP toolsets into its tools."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from arema.core.config import Settings
from arema.registry.catalog import CatalogBuilder
from arema.registry.descriptors import (
    AgentDescriptor,
    McpServerDescriptor,
    RuntimeProfile,
    StdioTransport,
)
from arema.runtime.agent_factory import build_llm_agent, compose_agents
from arema.runtime.services import RuntimeServices

if TYPE_CHECKING:
    from arema.runtime.sandbox.port import SandboxExecutor  # noqa: F401


class _FakeCheckpointSink:
    def append_checkpoint(self, *_args: object, **_kwargs: object) -> None:
        pass


def _settings() -> Settings:
    return Settings(_env_file=None, llm_provider="ollama")


def test_agent_with_mcp_server_ids_has_the_toolset_in_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A sentinel returned by a stubbed build_mcp_toolset so we can assert it lands in
    # the agent's tools WITHOUT needing a live MCP server.
    sentinel = object()

    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_mcp_server(
        McpServerDescriptor(
            id="stub_mcp",
            transport=StdioTransport(command="true", args=()),
        )
    )
    builder.add_agent(
        AgentDescriptor(
            id="mcp_agent",
            name="mcp_agent",
            description="An agent that delegates to an MCP server.",
            prompt_id="smoke_agent",
            factory=build_llm_agent,
            runtime_profile_id="safe_default",
            mcp_server_ids=("stub_mcp",),
        )
    )
    catalog = builder.freeze("mcp_agent")

    monkeypatch.setattr(
        "arema.runtime.agent_factory.build_mcp_toolset",
        lambda descriptor, **_kw: sentinel,
    )

    built = compose_agents(
        catalog,
        settings=_settings(),
        services=RuntimeServices.default(),
        checkpoint_sink=_FakeCheckpointSink(),  # type: ignore[arg-type]
    )
    agent = built["mcp_agent"]

    assert sentinel in agent.tools


def test_agent_without_mcp_server_ids_is_unaffected() -> None:
    """Backward compatibility: agents without mcp_server_ids build exactly as before."""
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(
        AgentDescriptor(
            id="plain_agent",
            name="plain_agent",
            description="A plain agent.",
            prompt_id="smoke_agent",
            factory=build_llm_agent,
            runtime_profile_id="safe_default",
        )
    )
    catalog = builder.freeze("plain_agent")

    built = compose_agents(
        catalog,
        settings=_settings(),
        services=RuntimeServices.default(),
        checkpoint_sink=_FakeCheckpointSink(),  # type: ignore[arg-type]
    )

    assert built["plain_agent"].tools == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --extra dev pytest tests/unit/runtime/test_mcp_attachment.py -v`
Expected: FAIL — `NotImplementedError: agent 'mcp_agent' references MCP servers ...`.

- [ ] **Step 3: Wire MCP toolsets into the agent**

In `src/arema/runtime/agent_factory.py`, add the two imports near the top (with the other runtime imports; `os` is not yet imported):

```python
import os
```

```python
from arema.registry.mcp import build_mcp_toolset
```

Then in `_build_agent`, **delete** the `NotImplementedError` block:

```python
    if descriptor.mcp_server_ids:
        # MCP toolset resolution is not part of the no-tools infrastructure shell.
        raise NotImplementedError(
            f"agent '{descriptor.id}' references MCP servers, which this composition "
            "does not yet resolve"
        )
```

And change the `tools = ...` line (a few lines below) to append the resolved MCP toolsets. The new block is:

```python
    tool_context = ToolBuildContext(settings=settings, services=services, catalog=catalog)
    tool_descriptors = {tool_id: catalog.tools[tool_id] for tool_id in descriptor.tool_ids}
    tools = tuple(
        _resolve_tool(tool_descriptors[tool_id], tool_context) for tool_id in descriptor.tool_ids
    ) + tuple(
        build_mcp_toolset(catalog.mcp_servers[mcp_id], environment=dict(os.environ))
        for mcp_id in descriptor.mcp_server_ids
    )
```

(Leaving everything else in `_build_agent` — sub-agent resolution, callback chain, instruction, model, build_context, `descriptor.factory(build_context)` — unchanged.)

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run --extra dev pytest tests/unit/runtime/test_mcp_attachment.py -v`
Expected: PASS (sentinel is in `agent.tools`; plain agent unaffected).

- [ ] **Step 5: Commit**

```bash
git add src/arema/runtime/agent_factory.py tests/unit/runtime/test_mcp_attachment.py
git -c commit.gpgsign=false commit -m "feat: resolve mcp_server_ids into agent tools"
```

---

## Task 5: Update docs + architecture guard, final `make check`

The architecture invariant to preserve: MCP wiring is domain-neutral. The existing `test_arema_source_names_no_concrete_domain_tool` (scans all of `src/arema` for `radare2`/`ghidra`/`r2mcp`/`ilspycmd`) already guards this; B.0 adds none of those. We extend the EXTENDING doc's MCP note (which currently says attachment is NYI) to reflect that it now works.

**Files:**
- Modify: `docs/EXTENDING_AREMA.md` (§3 "Register an MCP server" note), `docs/ARCHITECTURE.md` (`build_llm_agent` note about MCP raising)
- Verify: `tests/architecture/test_neutral_boundaries.py`

- [ ] **Step 1: Update the EXTENDING_AREMA MCP note**

In `docs/EXTENDING_AREMA.md`, §3 ends with a `> **Not yet attached to agents.** ...` blockquote saying the factory raises `NotImplementedError`. Replace that blockquote with:

```markdown
> **Attached.** `build_mcp_toolset` produces a `ResilientMcpToolset`, and the agent
> factory now resolves an agent's `mcp_server_ids` onto that agent — each referenced
> server's toolset is appended to the agent's `tools`. For per-run routing of a
> sandboxed MCP server, give the descriptor a `header_provider`
> (`Callable[[object], dict[str,str]]`) whose return value ADK injects into every
> request (e.g. `X-Sandbox-ID` / `X-Sandbox-Port` / `Authorization`).
```

- [ ] **Step 2: Update the ARCHITECTURE note**

In `docs/ARCHITECTURE.md`, the "Agent factory" section says referencing MCP servers raises `NotImplementedError`. Update that sentence to:

```markdown
`build_llm_agent` maps the profile's context mode onto ADK's `include_contents`
(`isolated → "none"`, `history → "default"`) and wires every callback list from
the validated chain. An agent's `mcp_server_ids` are resolved into `ResilientMcpToolset`s
(via `build_mcp_toolset`) and appended to the agent's `tools`, so MCP tools flow
through the same `tools` list as function tools (the registered-tool guard stays
first in `before_tool`, the output compactor last in `after_tool`).
```

- [ ] **Step 3: Run the architecture tests**

Run: `uv run --extra dev pytest tests/architecture -v`
Expected: PASS (5 tests) — confirms the MCP wiring added no domain term to `src/arema` and the sandbox module is still registry-free.

- [ ] **Step 4: Run the full gate**

Run: `make check`
Expected: PASS — lint, format-check, mypy, and the full suite green (the new MCP tests count; nothing regressed). Report the exact passed count.

- [ ] **Step 5: Commit**

```bash
git add docs/EXTENDING_AREMA.md docs/ARCHITECTURE.md
git -c commit.gpgsign=false commit -m "docs: MCP server attachment is wired; update extending/architecture notes"
```

---

## Self-Review (completed by plan author)

**Spec coverage (B.0 from the spec § "The MCP-attachment seam (B.0)"):**
- (1) lift `mcp_server_ids` NotImplementedError → Task 4 ✓
- (2) `ResilientMcpToolset` forwards `header_provider` → Task 1 ✓
- (3) `McpServerDescriptor` gains optional `header_provider` → Task 2 ✓ (+ `build_mcp_toolset` forwards it → Task 3 ✓)
- neutral smoke test proving an MCP toolset attaches → Task 4 (wiring test with stubbed `build_mcp_toolset`) ✓
- `make check` green + neutrality tests green → Task 5 ✓

**Placeholder scan:** none — every code step contains real code; doc edits contain real replacement text.

**Type consistency:** `HeaderProvider = Callable[[object], dict[str, str]]` is defined once (Task 2) and imported by `mcp.py` (Task 1) and used in `build_mcp_toolset` (Task 3). The `header_provider` kwarg name is identical across `McpServerDescriptor`, `ResilientMcpToolset.__init__`, `build_mcp_toolset`, and ADK's `McpToolset`. `_build_agent` uses `build_mcp_toolset(catalog.mcp_servers[mcp_id], environment=dict(os.environ))` — signature matches the existing `build_mcp_toolset(descriptor, *, environment=None)`.

**Scope:** This plan is B.0 only — the domain-neutral MCP-attachment foundation. B.1 (r2mcp image + two-container transport) and B.2 (ArtifactStore + acquire/prepare + the 3 RE agents) are deliberately separate plans, written after B.0 lands and the r2mcp transport's open details (HTTP endpoint path) are verified.
