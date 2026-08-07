"""The _FormatGate runs its children only for applicable formats (dotnet_recover)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from google.adk.agents import BaseAgent

from arema.registry.errors import InvalidCapabilityDescriptorError
from reverse_engineering.agents.format_gate import (
    DOTNET_RECOVER_DESCRIPTOR,
    _FormatGate,
    build_format_gate,
)
from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY

_ran: list[str] = []


class _FakeWorker(BaseAgent):
    async def run_async(self, _parent: object):  # type: ignore[override]
        _ran.append(self.name)
        yield SimpleNamespace(author=self.name)


def _gate() -> _FormatGate:
    return _FormatGate(
        name="dotnet_recover",
        sub_agents=[_FakeWorker(name="de4dot_deobfuscate"), _FakeWorker(name="dnlib_roundtrip")],
        applicable_formats=frozenset({"dotnet"}),
    )


def _run(sample_format: object) -> list[str]:
    _ran.clear()
    state: dict[str, object] = {} if sample_format is None else {SAMPLE_FORMAT_KEY: sample_format}
    ctx = SimpleNamespace(session=SimpleNamespace(state=state), invocation_id="inv-1", branch=None)

    async def collect() -> None:
        async for _ in _gate()._run_async_impl(ctx):  # type: ignore[arg-type]
            pass

    asyncio.run(collect())
    return list(_ran)


def test_runs_children_in_order_for_the_applicable_format() -> None:
    assert _run("dotnet") == ["de4dot_deobfuscate", "dnlib_roundtrip"]


@pytest.mark.parametrize("fmt", ["pe", "elf", "macho", "unknown", "apk", "dex", "jar"])
def test_skips_children_for_a_non_applicable_format(fmt: str) -> None:
    assert _run(fmt) == []


def test_skips_children_when_the_format_is_missing() -> None:
    assert _run(None) == []


def test_descriptor_is_a_managed_only_gate_over_the_dotnet_tools() -> None:
    d = DOTNET_RECOVER_DESCRIPTOR
    assert d.id == d.name == "dotnet_recover"
    assert d.factory is build_format_gate
    assert d.sub_agent_ids == ("de4dot_deobfuscate", "dnlib_roundtrip")
    assert d.metadata["applicable_formats"] == ["dotnet"]


def test_build_rejects_missing_applicable_formats() -> None:
    context = SimpleNamespace(
        descriptor=SimpleNamespace(name="g", description="", metadata={}),
        sub_agents=[],
        after_agent=[],
    )
    with pytest.raises(InvalidCapabilityDescriptorError):
        build_format_gate(context)  # type: ignore[arg-type]
