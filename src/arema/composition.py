"""Compose the default AREMA application from its capability catalog.

:func:`build_default_composition` registers the runtime profile and the single
root agent, freezes a validated catalog with empty tool and server registries,
creates the configured memory service, validates that every registered tool's
declared codecs exist, and builds the agent graph in dependency order. The
result is an immutable :class:`ApplicationComposition`; :func:`get_default_composition`
memoizes the process-wide default so the ADK entry point resolves one root.

The run-scoped memory lifetime is created by the runner, not here -- this
module only wires the service that a run will later scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING

from arema.agents.smoke_agent import SMOKE_AGENT_DESCRIPTOR
from arema.core.config import get_settings
from arema.core.logging import get_logger
from arema.memory.backends.memory import InMemoryStore
from arema.memory.backends.sqlite import SQLiteStore
from arema.memory.service import MemoryService, default_core_codec_registry
from arema.registry.catalog import CatalogBuilder
from arema.registry.descriptors import RuntimeProfile
from arema.runtime.agent_factory import compose_agents
from arema.runtime.sandbox.local import LocalSandboxExecutor
from arema.runtime.services import build_memory_backed_services

if TYPE_CHECKING:
    from google.adk.agents import BaseAgent

    from arema.core.config import Settings
    from arema.memory.codecs import RecordCodecRegistry
    from arema.memory.store import MemoryStore
    from arema.registry.catalog import CapabilityCatalog
    from arema.runtime.sandbox.port import SandboxExecutor

logger = get_logger(__name__)

_ROOT_AGENT_ID = SMOKE_AGENT_DESCRIPTOR.id


class CompositionError(RuntimeError):
    """Raised when an application cannot be composed from its catalog."""


@dataclass(frozen=True, slots=True)
class ApplicationComposition:
    """An immutable, fully wired application ready to run."""

    catalog: CapabilityCatalog
    root_agent: BaseAgent
    memory_service: MemoryService
    sandbox: SandboxExecutor | None = None


def build_memory_service(settings: Settings, codecs: RecordCodecRegistry) -> MemoryService:
    """Create the memory service backing the run, selecting the configured store."""
    backend = settings.memory_backend
    if backend == "memory":
        store: MemoryStore = InMemoryStore()
    elif backend == "sqlite":
        store = SQLiteStore(settings.memory_path)
    else:  # pragma: no cover - Settings constrains the backend to a Literal.
        raise CompositionError(f"unsupported memory backend '{backend}'")
    store.initialize()
    return MemoryService(store=store, codecs=codecs, settings=settings)


def build_sandbox_executor(settings: Settings) -> SandboxExecutor | None:
    """Build the configured sandbox executor, or ``None`` when disabled.

    Selection is domain-neutral: ``local`` always works; ``k8s``/``auto`` resolve
    to a k8s adapter when the optional client is importable. Neither branch names
    a concrete domain pool -- pool names come only from settings.
    """
    if not settings.sandbox_enabled:
        return None
    if settings.sandbox_backend == "local":
        return LocalSandboxExecutor(
            root=settings.memory_path.parent / "sandbox",
            default_pool=settings.sandbox_default_pool,
        )
    if settings.sandbox_backend in ("k8s", "auto"):
        # The k8s module imports k8s_agent_sandbox lazily inside __init__, so the
        # package absence surfaces when K8sSandboxExecutor is *constructed*, not
        # when the module is imported. Keep construction inside the guard so the
        # documented degradation contract holds: k8s -> clean CompositionError,
        # auto -> local fallback.
        try:
            from arema.runtime.sandbox.k8s import K8sSandboxExecutor

            return K8sSandboxExecutor(settings=settings)
        except ImportError:
            if settings.sandbox_backend == "k8s":
                raise CompositionError(
                    "sandbox_backend='k8s' requires the 'sandbox' extra (k8s-agent-sandbox)"
                ) from None
            return LocalSandboxExecutor(
                root=settings.memory_path.parent / "sandbox",
                default_pool=settings.sandbox_default_pool,
            )
    return None


def validate_tool_codecs(catalog: CapabilityCatalog, codecs: RecordCodecRegistry) -> None:
    """Reject any tool that declares a codec id the registry cannot resolve."""
    known = codecs.codec_ids()
    for tool in catalog.tools.values():
        for codec_id in tool.memory_codec_ids:
            if codec_id not in known:
                raise CompositionError(
                    f"tool '{tool.id}' declares unknown memory codec '{codec_id}'"
                )


def build_default_composition(settings: Settings | None = None) -> ApplicationComposition:
    """Build the default single-root application composition.

    Registers the guarded runtime profile and the root descriptor, freezes a
    catalog with empty tool and server registries, wires the configured memory
    service, validates tool codecs, and composes the agent graph. Every
    lifecycle callback that touches memory is fail-open, and the frozen catalog
    is never mutated.
    """
    resolved = settings if settings is not None else get_settings()
    codecs = default_core_codec_registry()

    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(SMOKE_AGENT_DESCRIPTOR)
    catalog = builder.freeze(_ROOT_AGENT_ID)

    memory_service = build_memory_service(resolved, codecs)
    validate_tool_codecs(catalog, codecs)

    sandbox = build_sandbox_executor(resolved)
    services = build_memory_backed_services(memory_service, sandbox=sandbox)
    built = compose_agents(
        catalog,
        settings=resolved,
        services=services,
        checkpoint_sink=memory_service,
    )
    root_agent = built[catalog.root_agent_id]

    logger.info(
        "composed default application",
        root_agent_id=catalog.root_agent_id,
        agent_count=len(catalog.agents),
        memory_backend=resolved.memory_backend,
    )
    return ApplicationComposition(
        catalog=catalog,
        root_agent=root_agent,
        memory_service=memory_service,
        sandbox=sandbox,
    )


@lru_cache
def get_default_composition() -> ApplicationComposition:
    """Return the process-wide default composition, building it once."""
    return build_default_composition()
