"""Structured logging configuration for AREMA."""

import logging
import sys
from typing import Any

import structlog
from rich.console import Console

from arema.core.config import get_settings


def configure_logging() -> None:
    """Configure standard logging and structlog from application settings."""
    settings = get_settings()
    level = getattr(logging, settings.log_level)
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.set_exc_info,
    ]
    if settings.log_level == "DEBUG":
        processors.append(
            structlog.dev.ConsoleRenderer(
                colors=True,
                exception_formatter=structlog.dev.plain_traceback,
            )
        )
    else:
        processors.append(structlog.processors.JSONRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a structlog logger optionally bound to a name."""
    return structlog.get_logger(name)  # type: ignore[no-any-return]


_console: Console | None = None


def get_console() -> Console:
    """Return the shared rich console, creating it on first use."""
    global _console
    if _console is None:
        _console = Console()
    return _console
