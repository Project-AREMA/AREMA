"""Component tests for the neutral AREMA command-line interface.

``--help``/``--version`` are exercised via subprocess (they must succeed
without provider credentials or a writable memory path). Everything else is
exercised in-process against fakes -- a hand-built, no-tools capability
catalog and a minimal memory-service double -- so these tests never build the
real SQLite-backed default composition or call a live provider.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
from rich.console import Console

import arema.cli as cli
from arema import __version__
from arema.agents.smoke_agent import SMOKE_AGENT_DESCRIPTOR
from arema.composition import ApplicationComposition
from arema.registry.catalog import CatalogBuilder
from arema.registry.descriptors import RuntimeProfile

if TYPE_CHECKING:
    from pathlib import Path

    from arema.registry.catalog import CapabilityCatalog


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _FakeHealth:
    healthy: bool
    detail: str | None = None


class _FakeMemoryService:
    """A minimal double for the parts of ``MemoryService`` ``/status`` reads."""

    def __init__(self, *, healthy: bool = True, detail: str | None = None) -> None:
        self._health = _FakeHealth(healthy=healthy, detail=detail)

    def health(self) -> _FakeHealth:
        return self._health


def _fake_catalog() -> CapabilityCatalog:
    """Build a real, validated, single-agent, no-tools capability catalog."""
    builder = CatalogBuilder()
    builder.add_runtime_profile(RuntimeProfile.safe_default())
    builder.add_agent(SMOKE_AGENT_DESCRIPTOR)
    return builder.freeze(SMOKE_AGENT_DESCRIPTOR.id)


def _fake_composition(*, healthy: bool = True, detail: str | None = None) -> ApplicationComposition:
    """Build a composition with a real catalog and a fake memory service.

    ``root_agent`` is never read by anything under test here, so a plain
    placeholder stands in for a built ADK agent.
    """
    return ApplicationComposition(
        catalog=_fake_catalog(),
        root_agent=object(),
        memory_service=_FakeMemoryService(healthy=healthy, detail=detail),
    )


def _composition_with_sandbox(stub: object) -> ApplicationComposition:
    """Build a composition whose ``sandbox`` is the given stub executor.

    ``ApplicationComposition`` is a frozen dataclass; the stub only needs to
    expose ``release_session`` (and optionally ``release_all``) to satisfy the
    interactive command dispatcher under test.
    """
    return ApplicationComposition(
        catalog=_fake_catalog(),
        root_agent=object(),
        memory_service=_FakeMemoryService(),
        sandbox=stub,  # type: ignore[arg-type]
    )


def _plain_console() -> Console:
    """Build a Rich console that renders to an in-memory buffer, no ANSI."""
    return Console(file=io.StringIO(), force_terminal=False, no_color=True, width=100)


def _console_text(console: Console) -> str:
    assert isinstance(console.file, io.StringIO)
    return console.file.getvalue()


# ---------------------------------------------------------------------------
# --help / --version (subprocess: must need no credentials, no writable path)
# ---------------------------------------------------------------------------


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


def test_cli_version_prints_arema_version() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "arema.cli", "--version"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == f"arema {__version__}"


def test_help_and_version_need_no_credentials_and_create_no_memory_database(
    tmp_path: Path,
) -> None:
    """``--help``/``--version`` must never import the runner/composition/agent.

    Points ``HOME`` at an empty directory and configures a provider that
    would fail credential validation if ``Settings()`` were ever constructed,
    so any accidental eager import would surface as a non-zero exit here.
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"HOME", "USERPROFILE", "AREMA_LLM_PROVIDER", "GOOGLE_API_KEY"}
    }
    env["HOME"] = str(tmp_path)
    env["USERPROFILE"] = str(tmp_path)
    env["AREMA_LLM_PROVIDER"] = "google"

    for flag in ("--help", "--version"):
        result = subprocess.run(
            [sys.executable, "-m", "arema.cli", flag],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0, result.stderr

    assert not (tmp_path / ".arema").exists()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def test_parser_defaults_to_interactive_mode() -> None:
    args = cli.build_arg_parser().parse_args([])

    assert args.query is None
    assert args.web is False
    assert args.port == 8000
    assert args.verbose is False


def test_parser_parses_query_and_verbose() -> None:
    args = cli.build_arg_parser().parse_args(["--query", "hi", "--verbose"])

    assert args.query == "hi"
    assert args.verbose is True


def test_parser_parses_web_and_port() -> None:
    args = cli.build_arg_parser().parse_args(["--web", "--port", "9001"])

    assert args.web is True
    assert args.port == 9001


# ---------------------------------------------------------------------------
# format_help / format_status
# ---------------------------------------------------------------------------


def test_format_help_lists_only_the_four_documented_commands() -> None:
    help_text = cli.format_help()

    for command in ("/help", "/status", "/clear", "/exit"):
        assert command in help_text
    assert "/tools" not in help_text
    assert "/agents" not in help_text


def test_format_status_reports_one_agent_zero_tools_zero_servers_and_health() -> None:
    status = cli.format_status(_fake_composition(healthy=True))

    assert "agents: 1" in status
    assert "tools: 0" in status
    assert "mcp servers: 0" in status
    assert "healthy" in status


def test_format_status_reports_degraded_memory_with_detail() -> None:
    status = cli.format_status(_fake_composition(healthy=False, detail="disk full"))

    assert "degraded (disk full)" in status


# ---------------------------------------------------------------------------
# Interactive command dispatch
# ---------------------------------------------------------------------------


def test_help_command_is_handled_and_returns_help_text() -> None:
    result = cli.handle_interactive_command("/help", composition=_fake_composition())

    assert result.handled
    assert result.message is not None
    assert "/status" in result.message
    assert not result.exit_requested
    assert not result.clear_requested


def test_status_command_is_handled_and_returns_status_text() -> None:
    result = cli.handle_interactive_command("/status", composition=_fake_composition())

    assert result.handled
    assert result.message is not None
    assert "agents: 1" in result.message


def test_clear_command_requests_a_clear() -> None:
    result = cli.handle_interactive_command("/clear", composition=_fake_composition())

    assert result.handled
    assert result.clear_requested
    assert result.message is None


def test_reset_command_releases_sandbox_session() -> None:
    released: list[str] = []

    class _StubSandbox:
        def release_session(self, key: str) -> None:
            released.append(key)

    composition = _composition_with_sandbox(_StubSandbox())

    result = cli.handle_interactive_command("/reset", composition=composition, case_id="case-1")

    assert result.handled
    assert result.message is not None
    assert released == ["case-1"]


@pytest.mark.parametrize("command", ["/exit", "/quit"])
def test_exit_command_releases_sandbox_session(command: str) -> None:
    released: list[str] = []

    class _StubSandbox:
        def release_session(self, key: str) -> None:
            released.append(key)

    composition = _composition_with_sandbox(_StubSandbox())

    result = cli.handle_interactive_command(command, composition=composition, case_id="case-1")

    assert result.handled
    assert result.exit_requested
    assert released == ["case-1"]


def test_reset_is_a_noop_when_sandbox_is_none() -> None:
    # /reset against a composition with no sandbox must not raise.
    result = cli.handle_interactive_command(
        "/reset", composition=_fake_composition(), case_id="case-1"
    )

    assert result.handled
    assert result.message is not None


def test_reset_is_a_noop_when_case_id_is_none() -> None:
    # No case_id (backward-compatible call) -> nothing to release, no raise.
    released: list[str] = []

    class _StubSandbox:
        def release_session(self, key: str) -> None:
            released.append(key)

    composition = _composition_with_sandbox(_StubSandbox())

    result = cli.handle_interactive_command("/reset", composition=composition)

    assert result.handled
    assert released == []


def test_reset_swallows_release_errors() -> None:
    # A failing release_session must never crash the CLI (fail-open).
    class _ExplodingSandbox:
        def release_session(self, _key: str) -> None:
            raise RuntimeError("sandbox blew up")

    composition = _composition_with_sandbox(_ExplodingSandbox())

    result = cli.handle_interactive_command("/reset", composition=composition, case_id="case-1")

    assert result.handled


@pytest.mark.parametrize("command", ["/exit", "/quit", "/EXIT", "  /exit  "])
def test_exit_commands_request_an_exit(command: str) -> None:
    result = cli.handle_interactive_command(command, composition=_fake_composition())

    assert result.handled
    assert result.exit_requested


@pytest.mark.parametrize(
    "text",
    ["/tools", "/agents", "what security tools do you have?", "help me with status"],
)
def test_unrecognized_input_is_left_unhandled_for_the_agent(text: str) -> None:
    result = cli.handle_interactive_command(text, composition=_fake_composition())

    assert not result.handled


# ---------------------------------------------------------------------------
# Interactive session loop (end to end, against fakes)
# ---------------------------------------------------------------------------


async def test_run_interactive_session_dispatches_commands_and_routes_queries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    composition = _fake_composition()
    console = _plain_console()
    turns = iter(["/help", "/status", "hello there", "/exit"])

    async def fake_run_single_query(query: str, **kwargs: object) -> str:
        del kwargs
        return f"echo: {query}"

    monkeypatch.setattr("arema.runner.run_single_query", fake_run_single_query)

    exit_code = await cli.run_interactive_session(
        composition,
        console,
        prompt_fn=lambda: next(turns),
    )

    output = _console_text(console)
    assert exit_code == 0
    assert "Available commands" in output
    assert "AREMA status" in output
    assert "echo: hello there" in output
    assert "Goodbye" in output


async def test_run_interactive_session_skips_blank_input() -> None:
    composition = _fake_composition()
    console = _plain_console()
    turns = iter(["   ", "/exit"])

    exit_code = await cli.run_interactive_session(
        composition,
        console,
        prompt_fn=lambda: next(turns),
    )

    assert exit_code == 0


async def test_run_interactive_session_exits_cleanly_on_eof() -> None:
    composition = _fake_composition()
    console = _plain_console()

    def _raise_eof() -> str:
        raise EOFError

    exit_code = await cli.run_interactive_session(
        composition,
        console,
        prompt_fn=_raise_eof,
    )

    assert exit_code == 0
    assert "Goodbye" in _console_text(console)


async def test_run_interactive_session_reports_provider_errors_and_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    composition = _fake_composition()
    console = _plain_console()
    turns = iter(["bad query", "/exit"])

    async def failing_run_single_query(query: str, **kwargs: object) -> str:
        del query, kwargs
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr("arema.runner.run_single_query", failing_run_single_query)

    exit_code = await cli.run_interactive_session(
        composition,
        console,
        prompt_fn=lambda: next(turns),
    )

    output = _console_text(console)
    assert exit_code == 0
    assert "Error" in output
    assert "provider unavailable" in output


# ---------------------------------------------------------------------------
# main() query mode (in-process, against a monkeypatched runner)
# ---------------------------------------------------------------------------


def test_main_query_mode_prints_the_response(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def fake_run_single_query(query: str, **kwargs: object) -> str:
        del kwargs
        return f"echo: {query}"

    monkeypatch.setattr("arema.runner.run_single_query", fake_run_single_query)

    exit_code = cli.main(["--query", "hello"])

    assert exit_code == 0
    assert "echo: hello" in capsys.readouterr().out


def test_main_query_mode_reports_provider_errors(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def failing_run_single_query(query: str, **kwargs: object) -> str:
        del query, kwargs
        raise RuntimeError("boom")

    monkeypatch.setattr("arema.runner.run_single_query", failing_run_single_query)

    exit_code = cli.main(["--query", "hello"])

    assert exit_code == 1
    assert "Error" in capsys.readouterr().out


def test_main_handles_keyboard_interrupt_gracefully(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise_keyboard_interrupt() -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("arema.composition.get_default_composition", _raise_keyboard_interrupt)

    exit_code = cli.main([])

    assert exit_code == 130
