"""Unit tests for the deterministic deep-analysis format router.

The router runs exactly one engine per sample -- ILSpy for a managed .NET
assembly, the composite ``java_deep_analysis`` route for a JVM/Android container,
Ghidra for everything else -- chosen from the format decided at ingest, with no
model call spent standing the other engines down.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from google.adk.agents import BaseAgent

from arema.registry.errors import InvalidCapabilityDescriptorError
from reverse_engineering.agents.format_router import (
    DEEP_ENGINE_ROUTER_DESCRIPTOR,
    MANAGED_FORMATS,
    _FormatRouter,
    build_format_router,
)
from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY

_ran: list[str] = []

_FORMAT_ENGINES = {
    "dotnet": "dotnet_decompile",
    "apk": "java_deep_analysis",
    "dex": "java_deep_analysis",
    "jar": "java_deep_analysis",
}


class _FakeEngine(BaseAgent):
    """A stand-in engine that records that it ran and yields one marker event."""

    async def run_async(self, _parent_context: object):  # type: ignore[override]
        _ran.append(self.name)
        yield SimpleNamespace(author=self.name)


def _router() -> _FormatRouter:
    return _FormatRouter(
        name="deep_engine_router",
        sub_agents=[
            _FakeEngine(name="deep_analysis"),
            _FakeEngine(name="dotnet_decompile"),
            _FakeEngine(name="java_deep_analysis"),
        ],
        format_engines=dict(_FORMAT_ENGINES),
        default_engine="deep_analysis",
    )


def _run(fmt: str | None) -> list[object]:
    _ran.clear()
    state = {SAMPLE_FORMAT_KEY: fmt} if fmt is not None else {}
    ctx = SimpleNamespace(session=SimpleNamespace(state=state))

    async def collect() -> list[object]:
        return [event async for event in _router()._run_async_impl(ctx)]  # type: ignore[arg-type]

    return asyncio.run(collect())


@pytest.mark.parametrize(
    ("sample_format", "expected_engine"),
    [
        ("dotnet", "dotnet_decompile"),
        ("apk", "java_deep_analysis"),
        ("dex", "java_deep_analysis"),
        ("jar", "java_deep_analysis"),
        ("pe", "deep_analysis"),
        ("elf", "deep_analysis"),
        ("macho", "deep_analysis"),
        ("unknown", "deep_analysis"),
        (None, "deep_analysis"),  # missing format falls back to the default engine
    ],
)
def test_router_sends_dotnet_to_ilspy_jvm_to_jadx_native_to_ghidra(
    sample_format: str | None, expected_engine: str
) -> None:
    events = _run(sample_format)

    assert _ran == [expected_engine], "exactly one engine runs, and it is the right one"
    assert [getattr(event, "author", None) for event in events] == [expected_engine]


def test_descriptor_routes_all_three_engines() -> None:
    """Two of the three routes are composites: a managed or JVM decompiler paired
    with a native leg, because neither subsumes the other."""
    d = DEEP_ENGINE_ROUTER_DESCRIPTOR
    assert set(d.sub_agent_ids) == {
        "deep_analysis",
        "dotnet_deep_analysis",
        "java_deep_analysis",
    }
    assert d.metadata["format_engines"]["apk"] == "java_deep_analysis"
    assert d.metadata["format_engines"]["dotnet"] == "dotnet_deep_analysis"
    assert d.metadata["default_engine"] == "deep_analysis"


def test_managed_formats_still_exported() -> None:
    assert frozenset({"dotnet"}) == MANAGED_FORMATS


def test_build_format_router_rejects_an_engine_name_not_among_sub_agents() -> None:
    context = SimpleNamespace(
        descriptor=SimpleNamespace(
            name="deep_engine_router",
            description="router",
            metadata={
                "format_engines": {"dotnet": "does_not_exist"},
                "default_engine": "deep_analysis",
            },
        ),
        sub_agents=[
            _FakeEngine(name="deep_analysis"),
            _FakeEngine(name="dotnet_decompile"),
            _FakeEngine(name="java_decompile"),
        ],
        after_agent=(),
    )

    with pytest.raises(InvalidCapabilityDescriptorError, match="unknown sub-agents"):
        build_format_router(context)  # type: ignore[arg-type]
