"""Shared helpers for mutating an ADK ``LlmRequest`` from a before-model callback."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from google.adk.models.llm_request import LlmRequest


def append_to_system_instruction(llm_request: LlmRequest, text: str) -> None:
    """Append *text* to the request's system instruction, handling both forms.

    No-ops silently when the request has no config. Handles a plain-string
    instruction and a ``Content``-style instruction with parts.
    """
    config = getattr(llm_request, "config", None)
    if config is None:
        return

    existing = getattr(config, "system_instruction", "") or ""
    if isinstance(existing, str):
        config.system_instruction = existing + text
        return

    parts = getattr(existing, "parts", None) or []
    if parts and hasattr(parts[0], "text"):
        parts[0].text = (parts[0].text or "") + text
