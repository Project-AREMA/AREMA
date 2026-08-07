"""The neutral AREMA command-line interface.

Wraps :mod:`arema.runner` in an ``argparse`` front end with three modes: a
one-shot ``--query``, the ADK developer web UI (``--web``), and an
interactive Rich-driven session with five commands -- ``/help``, ``/status``,
``/clear``, ``/reset``, and ``/exit``. ``/reset`` and ``/exit`` (plus Ctrl+C
and process shutdown) release the bound sandbox session fail-open. There are no
``/tools`` or ``/agents`` capability listings; ``/status`` reports only the
factual counts already exposed by the capability catalog plus memory health.

Argument parsing itself (including ``--help`` and ``--version``) never
imports the runner, composition, or agent modules, and never calls
:func:`~arema.core.logging.configure_logging`. Those happen only inside
:func:`main`, after ``argparse`` has already parsed (and, for ``--help`` and
``--version``, already exited) -- so neither flag requires provider
credentials or a writable memory path.
"""

from __future__ import annotations

import argparse
import asyncio
import atexit
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import uuid4

from rich.prompt import Prompt

from arema import __version__
from arema.core.logging import configure_logging, get_console, get_logger

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from rich.console import Console

    from arema.composition import ApplicationComposition
    from arema.runner import RunnerFactory

logger = get_logger(__name__)

_BANNER = (
    "[bold cyan]AREMA[/bold cyan] [dim]v{version}[/dim]\n"
    "[dim italic]Autonomous Reverse Engineering & Malware Analysis[/dim italic]"
)

_HELP_TEXT = (
    "[bold]Available commands:[/bold]\n"
    "  [cyan]/help[/cyan]    Show this help message\n"
    "  [cyan]/status[/cyan]  Show the current agent, tool, and memory status\n"
    "  [cyan]/clear[/cyan]   Clear the screen\n"
    "  [cyan]/reset[/cyan]   Release the current sandbox session\n"
    "  [cyan]/exit[/cyan]    Exit AREMA\n"
    "\n"
    "Anything else is sent to AREMA as a query."
)

_EXIT_COMMANDS = frozenset({"/exit", "/quit"})
_RESET_COMMANDS = frozenset({"/reset"})


@dataclass(frozen=True, slots=True)
class InteractiveCommandResult:
    """The effect of dispatching one interactive slash command."""

    handled: bool
    exit_requested: bool = False
    clear_requested: bool = False
    message: str | None = None


def format_banner() -> str:
    """Return the Rich-markup banner shown at the start of a session."""
    return _BANNER.format(version=__version__)


def format_help() -> str:
    """Return the Rich-markup help text listing the interactive commands."""
    return _HELP_TEXT


def format_status(composition: ApplicationComposition) -> str:
    """Return a factual status summary: agent, tool, server, and memory counts.

    Reports exactly what the frozen capability catalog and the memory
    service's health check can prove -- no speculative capability listing.
    """
    health = composition.memory_service.health()
    health_text = "healthy" if health.healthy else "degraded"
    if health.detail:
        health_text = f"{health_text} ({health.detail})"
    return (
        "[bold]AREMA status[/bold]\n"
        f"  agents: {len(composition.catalog.agents)}\n"
        f"  tools: {len(composition.catalog.tools)}\n"
        f"  mcp servers: {len(composition.catalog.mcp_servers)}\n"
        f"  memory: {health_text}"
    )


def handle_interactive_command(
    command: str,
    *,
    composition: ApplicationComposition,
    case_id: str | None = None,
) -> InteractiveCommandResult:
    """Dispatch one interactive slash command.

    Anything that is not exactly one of ``/help``, ``/status``, ``/clear``,
    ``/reset``, ``/exit``, or ``/quit`` is left unhandled so the caller treats
    it as a query -- a user asking a question containing the word "status" is
    never swallowed by the command dispatcher.

    ``case_id`` binds the active sandbox session; when present, ``/reset`` and
    ``/exit`` release that session fail-open. It defaults to ``None`` so callers
    that don't participate in sandbox bookkeeping (existing tests, ad-hoc use)
    keep working unchanged.
    """
    normalized = command.strip().lower()
    if normalized == "/help":
        return InteractiveCommandResult(handled=True, message=format_help())
    if normalized == "/status":
        return InteractiveCommandResult(handled=True, message=format_status(composition))
    if normalized == "/clear":
        return InteractiveCommandResult(handled=True, clear_requested=True)
    if normalized in _RESET_COMMANDS:
        _release_sandbox(composition, case_id)
        return InteractiveCommandResult(handled=True, message="[dim]Sandbox session reset.[/dim]")
    if normalized in _EXIT_COMMANDS:
        _release_sandbox(composition, case_id)
        return InteractiveCommandResult(handled=True, exit_requested=True)
    return InteractiveCommandResult(handled=False)


def _release_sandbox(composition: ApplicationComposition, case_id: str | None) -> None:
    """Release the sandbox session bound to ``case_id``, fail-open.

    A release failure (or no sandbox / no case id) must never abort the CLI;
    the error is logged at WARNING and the interactive loop continues.
    """
    sandbox = composition.sandbox
    if sandbox is None or case_id is None:
        return
    try:
        sandbox.release_session(case_id)
    except Exception:
        logger.warning("sandbox release failed", exc_info=True)


def _safe_release_all(sandbox: object) -> None:
    """Release every outstanding sandbox handle at process shutdown, fail-open.

    The :class:`~arema.runtime.sandbox.port.SandboxExecutor` port only promises
    ``release_session``; ``release_all`` is an optional manager capability, so
    it is located via ``getattr`` and any failure is swallowed.
    """
    try:
        release_all = getattr(sandbox, "release_all", None)
        if callable(release_all):
            release_all()
    except Exception:
        logger.warning("sandbox shutdown release failed", exc_info=True)


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the ``arema`` argument parser.

    Constructing and parsing with this parser never imports the runner,
    composition, or agent modules -- ``--help`` and ``--version`` are
    satisfied entirely by ``argparse`` itself.
    """
    parser = argparse.ArgumentParser(
        prog="arema",
        description=(
            "AREMA -- Autonomous Reverse Engineering & Malware Analysis. "
            "A domain-neutral, ADK-based autonomous agent shell."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  arema                       Start an interactive session\n"
            '  arema --query "..."         Run a single query and exit\n'
            "  arema --web                 Start the ADK web interface (dev only)\n"
        ),
    )
    parser.add_argument(
        "-q",
        "--query",
        type=str,
        default=None,
        help="Run a single query and exit.",
    )
    parser.add_argument(
        "-w",
        "--web",
        action="store_true",
        help="Start the ADK web interface (development only).",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8000,
        help="Port for the web interface (default: 8000).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"arema {__version__}",
    )
    return parser


async def _run_query_mode(query: str, console: Console) -> int:
    """Run one query and print its response; return the process exit code."""
    from arema.runner import run_single_query

    try:
        response = await run_single_query(query)
    except Exception as exc:
        logger.exception("query failed", query_length=len(query))
        console.print(f"[red]Error:[/red] {exc}")
        return 1
    console.print(response)
    return 0


def _run_web_mode(port: int, console: Console) -> int:
    """Start the ADK developer web UI as a subprocess; return its exit code."""
    import subprocess
    from pathlib import Path

    import arema

    agents_dir = Path(arema.__file__).resolve().parent.parent
    console.print(f"[bold]Starting the AREMA web interface on port {port}...[/bold]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]")
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "google.adk.cli", "web", "--port", str(port)],
            cwd=agents_dir,
            check=False,
        )
    except FileNotFoundError:
        console.print("[red]Error:[/red] the ADK CLI is not installed.")
        return 1
    if completed.returncode != 0:
        console.print(
            f"[red]Error:[/red] the ADK web interface exited with status {completed.returncode}."
        )
    return completed.returncode


def _default_prompt() -> str:
    """Read one line of interactive input via Rich's prompt."""
    return Prompt.ask("[bold green]You[/bold green]")


async def run_interactive_session(
    composition: ApplicationComposition,
    console: Console,
    *,
    runner_factory: RunnerFactory | None = None,
    prompt_fn: Callable[[], str] = _default_prompt,
) -> int:
    """Drive one interactive AREMA session until the user exits.

    ``composition``, ``runner_factory``, and ``prompt_fn`` are injected so
    this loop is testable end to end against fakes -- no live provider, no
    terminal, and no SQLite-backed default composition required.
    """
    from arema.runner import run_single_query

    console.print(format_banner())
    console.print("[dim]Type /help for available commands.[/dim]\n")

    # One stable case id per interactive session: ADK creates a new session and
    # a new anonymous user per query, so any per-session handle (e.g. a sandbox
    # case) must bind to this value, not to the per-query session id.
    case_id = uuid4().hex

    while True:
        try:
            raw_input = prompt_fn()
        except (KeyboardInterrupt, EOFError):
            _release_sandbox(composition, case_id)
            console.print("\n[dim]Goodbye![/dim]")
            return 0

        stripped = raw_input.strip()
        if not stripped:
            continue

        command_result = handle_interactive_command(
            stripped, composition=composition, case_id=case_id
        )
        if command_result.handled:
            if command_result.message is not None:
                console.print(command_result.message)
            if command_result.clear_requested:
                console.clear()
            if command_result.exit_requested:
                console.print("[dim]Goodbye![/dim]")
                return 0
            continue

        console.print()
        try:
            response = await run_single_query(
                stripped, runner_factory=runner_factory, case_id=case_id
            )
        except Exception as exc:
            logger.exception("interactive query failed", query_length=len(stripped))
            console.print(f"[red]Error:[/red] {exc}")
            continue
        console.print(f"[bold cyan]AREMA:[/bold cyan] {response}\n")


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments and dispatch to query, web, or interactive mode."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    configure_logging()
    if args.verbose:
        import logging

        logging.getLogger().setLevel(logging.DEBUG)

    console = get_console()

    try:
        if args.query:
            return asyncio.run(_run_query_mode(args.query, console))
        if args.web:
            return _run_web_mode(args.port, console)

        from arema.composition import get_default_composition

        composition = get_default_composition()
        if composition.sandbox is not None:
            atexit.register(_safe_release_all, composition.sandbox)
        return asyncio.run(run_interactive_session(composition, console))
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted. Goodbye![/dim]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
