"""Tests for the json_repair safety net on LLM tool-call arguments.

AREMA repairs malformed tool-call JSON (single-quoted keys, trailing commas,
unquoted keys, Python literals) in every provider response via ``json_repair``,
so ADK never sees invalid JSON -- robust for all tools (including external MCP
tools) and all providers, without forcing strict schemas.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from arema.core.model_factory import _ConfiguredRetryLiteLLMClient, _repair_tool_call_arguments


def _response(args: str) -> Any:
    """Build a litellm-shaped ModelResponse with one tool call carrying ``args``."""
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    tool_calls=[SimpleNamespace(function=SimpleNamespace(name="t", arguments=args))]
                )
            )
        ]
    )


def test_repair_fixes_single_quotes_and_trailing_comma() -> None:
    fixed = _repair_tool_call_arguments(_response("{'path': '/bin/ls',}"))

    assert fixed.choices[0].message.tool_calls[0].function.arguments == '{"path": "/bin/ls"}'


def test_repair_fixes_unquoted_keys_and_python_literals() -> None:
    fixed = _repair_tool_call_arguments(_response("{path: '/bin/ls', ok: True}"))

    args = fixed.choices[0].message.tool_calls[0].function.arguments
    assert '"path": "/bin/ls"' in args


def test_repair_passes_valid_json_through_unchanged() -> None:
    fixed = _repair_tool_call_arguments(_response('{"path": "/bin/ls"}'))

    assert fixed.choices[0].message.tool_calls[0].function.arguments == '{"path": "/bin/ls"}'


def test_repair_handles_response_without_tool_calls() -> None:
    response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(tool_calls=None))])

    assert _repair_tool_call_arguments(response) is response


def test_repair_handles_empty_arguments() -> None:
    fixed = _repair_tool_call_arguments(_response(""))

    assert fixed.choices[0].message.tool_calls[0].function.arguments == ""


@pytest.mark.asyncio
async def test_client_repairs_args_before_returning(monkeypatch: pytest.MonkeyPatch) -> None:
    import arema.core.model_factory as factory

    async def fake_acompletion(_self: Any, **_kwargs: Any) -> Any:
        return _response("{'path': '/bin/ls',}")

    monkeypatch.setattr(factory.LiteLLMClient, "acompletion", fake_acompletion)

    client = _ConfiguredRetryLiteLLMClient()
    result = await client.acompletion(model="m", messages=[], tools=[], num_retries=0)

    assert result.choices[0].message.tool_calls[0].function.arguments == '{"path": "/bin/ls"}'
