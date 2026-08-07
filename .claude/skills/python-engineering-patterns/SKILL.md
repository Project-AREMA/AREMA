---
name: python-engineering-patterns
description: Use when writing, reviewing, or refactoring Python code in production projects — enforces strict typing, structured error handling, Pydantic configuration, structlog logging, pytest patterns, and dependency hygiene. Triggers on symptoms like bare Any annotations, except-pass blocks, f-string loggers, untyped dicts, hardcoded config, missing return types, or unpinned dependencies.
---

# Python Engineering Patterns

Production Python patterns. Opinionated. Non-negotiable where marked.

## Type Safety

### Rules (Non-Negotiable)

| Rule | Bad | Good |
|------|-----|------|
| All functions have return type annotations | `def foo(x):` | `def foo(x: str) -> int:` |
| No bare `Any` as parameter annotation | `executor: Any = None` | `executor: object = None` |
| Compound `Any` is OK | — | `dict[str, Any]`, `list[Any]` |
| No unparametrized generics | `items: list = []` | `items: list[str] = []` |
| `type: ignore` must have error code | `# type: ignore` | `# type: ignore[return-value]` |

### Typed Structures Over Dicts

When a dict shape is used in more than one function, define a type:

```python
# Bad — shape is implicit, no IDE help, easy to typo keys
def process(entry: dict[str, Any]) -> None: ...

# Good — for internal pipeline data (no validation needed)
class EndpointEntry(TypedDict):
    url: str
    method: str
    finding_count: int

# Good — for external/untrusted data (validation needed)
class ScanResult(BaseModel):
    target: str
    findings: list[Finding]
    model_config = ConfigDict(strict=True)
```

**Decision rule:** `TypedDict` for internal data passed between trusted functions. `BaseModel` for data crossing trust boundaries (user input, API responses, LLM-generated arguments).

### Constants Over Magic Strings

When string literals are shared across modules, centralize them:

```python
# Bad — duplicated across files, rename breaks silently
state["_coverage:tested"]  # in file A
_KEY = "_coverage:tested"  # in file B (independent copy)

# Good — single source of truth
class StateKeys(StrEnum):
    COVERAGE_TESTED = "_coverage:tested"
```

## Error Handling

### Rules (Non-Negotiable)

| Rule | Bad | Good |
|------|-----|------|
| Never bare `except: pass` | `except Exception: pass` | `except Exception: logger.debug("name failed", exc_info=True)` |
| Catch specific exceptions first | `except Exception` | `except (ConnectionError, TimeoutError)` then `except Exception` |
| Always log context | `logger.error("failed")` | `logger.error("scan failed", tool=name, target=url, error=str(e))` |
| Fail-open with visibility | Silently swallow | Log warning, return None/default, continue |

### Fail-Open Pattern (for non-critical middleware)

```python
def my_callback(...) -> None:
    try:
        # actual logic
    except Exception as exc:
        logger.warning("my_callback failed — continuing", error=str(exc), exc_info=True)
        return None  # passthrough
```

## Configuration

### Pydantic Settings Pattern

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="APP_")

    api_key: str = Field(description="Required API key")
    timeout: int = Field(default=60, ge=1, le=3600)
    debug: bool = False

    @model_validator(mode="after")
    def validate_cross_fields(self) -> Self:
        if self.provider == "anthropic" and self.temperature > 1.0:
            raise ValueError("Anthropic max temperature is 1.0")
        return self

@lru_cache
def get_settings() -> Settings:
    return Settings()
```

**Rules:**
- Single `Settings` class as source of truth — never duplicate defaults in module constants
- `get_settings()` with `@lru_cache` — call in functions, not at module level
- `@field_validator` for single-field rules, `@model_validator` for cross-field rules
- Never read `os.environ` directly — always go through Settings

### No Import-Time Side Effects

```python
# Bad — forces env lookup + structlog config on every import
configure_logging()  # at module level

# Good — explicit call in entry points only
if __name__ == "__main__":
    configure_logging()
    main()
```

## Logging (structlog)

### Rules (Non-Negotiable)

| Rule | Bad | Good |
|------|-----|------|
| No f-strings in logger calls | `logger.info(f"Found {n} items")` | `logger.info("items discovered", count=n)` |
| Use keyword args for structured fields | `logger.info(f"Error: {e}")` | `logger.error("operation failed", error=str(e), tool=name)` |
| Include context | `logger.warning("failed")` | `logger.warning("scan failed", target=url, phase="recon")` |

## Testing (pytest)

### Patterns

| Pattern | When | Example |
|---------|------|---------|
| `@pytest.mark.parametrize` | Same test logic, different inputs | Tool names, URL variations, error types |
| Fixtures with `autouse` | Setup/teardown for every test | Mock settings, clean state |
| `conftest.py` per directory | Shared fixtures scoped to test group | `tests/unit/conftest.py` |
| Property-based (Hypothesis) | Pure functions over string/URL input | URL normalization, path matching |
| Mock at boundary, not internals | Test behavior, not implementation | Mock HTTP calls, not internal helpers |

### Test Naming

```python
# Pattern: test_<unit>_<scenario>_<expected>
def test_compact_response_strips_raw_output(): ...
def test_budget_callback_compresses_at_threshold(): ...
def test_login_callback_skips_when_already_authenticated(): ...
```

## Dependency Management

| Rule | Rationale |
|------|-----------|
| Pin critical deps with upper bounds | `litellm>=1.80,<2.0` prevents breaking changes |
| Use `uv.lock` in CI | Reproducible builds |
| Optional deps for cross-package imports | `[project.optional-dependencies] mcp = ["security-tools"]` |
| `asyncio.iscoroutinefunction` is deprecated | Use `inspect.iscoroutinefunction()` (Python 3.14+) |
| Install and run dev tools (ruff, mypy) | Declared but not installed = inert |

## Project Structure

```
src/project_name/
    core/           # Config, shared types, logging setup
    agents/         # Domain-specific agent modules
    callbacks/      # Callback implementations + shared helpers
        session_keys.py     # StrEnum for all state keys
        _helpers.py         # Shared callback utilities
    tools/          # Tool implementations by category
    schemas/        # Pydantic models for data contracts
    __init__.py
tests/
    unit/           # Deterministic, fast, isolated
    component/      # Single-component with mocked dependencies
    integration/    # Full system with real dependencies
    conftest.py     # Global fixtures
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Deferred import of stdlib (`from pathlib import ...` inside function) | Move to top-level — deferred import is only for circular import avoidance |
| Duplicate `from typing import` statements | Merge into single import line; use ruff `I001` |
| `Console()` or logger at module level | Lazy instantiation or explicit init in entry points |
| `json.dumps(obj, default=str) // 4` for token estimation | Add calibration test; document margin of error |
| `list` without type parameter in module variables | Always parametrize: `list[str]`, `list[Callable[..., dict]]` |
