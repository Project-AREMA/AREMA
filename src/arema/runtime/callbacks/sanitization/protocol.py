"""The OutputSanitizer protocol: a pluggable untrusted-origin text defense.

The default backend is :class:`StructuralSanitizer` (framing + denylist, no
deps). A future ``GuardrailsSanitizer`` implements the same protocol so
Guardrails AI (or any backend) drops in without a rewrite.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from typing import Any


@runtime_checkable
class OutputSanitizer(Protocol):
    """Neutralize instruction-like text in an untrusted-origin tool response."""

    def sanitize(self, tool_name: str, response: dict[str, Any]) -> dict[str, Any]:
        """Return a sanitized copy of *response* (never mutate the original)."""
        ...


class PassthroughSanitizer:
    """A no-op sanitizer that returns the response unchanged.

    Useful for tests and as the "disabled" backend.
    """

    def sanitize(self, _tool_name: str, response: dict[str, Any]) -> dict[str, Any]:
        return response
