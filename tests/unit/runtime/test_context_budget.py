"""Tests for provider-neutral context-budget compaction."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest import mock

import pytest
from google.adk.models.llm_response import LlmResponse
from google.genai.types import Content, FunctionCall, FunctionResponse, Part

from arema.core.config import Settings
from arema.runtime.context.budget import (
    CHECKPOINT_STATE_KEY,
    ContextPressure,
    _compact_old_model_text,
    _compact_old_tool_results,
    classify_pressure,
    enforce_context_budget,
    estimate_tokens,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_func_response_part(response: object, name: str = "search") -> Part:
    """Create a real Part carrying a FunctionResponse."""
    return Part(function_response=FunctionResponse(name=name, response=response))


def _make_func_call_part(name: str = "search") -> Part:
    """Create a real Part carrying a FunctionCall."""
    return Part(function_call=FunctionCall(name=name, args={}))


def _make_text_part(text: str) -> Part:
    """Create a real Part carrying plain text."""
    return Part(text=text)


def _make_content(parts: list[Part], role: str = "model") -> Content:
    """Create a real Content with the given parts and role."""
    return Content(parts=parts, role=role)


def _settings(**overrides: object) -> Settings:
    """Build a credential-free Settings instance for deterministic tests."""
    return Settings(_env_file=None, llm_provider="ollama", **overrides)  # type: ignore[arg-type]


_LONG_TEXT = "A" * 600


# ---------------------------------------------------------------------------
# estimate_tokens
# ---------------------------------------------------------------------------


class TestEstimateTokens:
    def test_basic_estimation(self) -> None:
        data = [{"text": "hello world" * 100}]
        tokens = estimate_tokens(data)
        assert tokens > 0
        assert tokens == len(json.dumps(data)) // 4

    def test_empty_sequence_returns_zero(self) -> None:
        assert estimate_tokens([]) == 0

    def test_estimate_equals_json_char_count_over_four(self) -> None:
        data = [{"key": "value " * 50}]
        expected = len(json.dumps(data, default=str)) // 4
        assert estimate_tokens(data) == expected

    def test_doubling_input_roughly_doubles_estimate(self) -> None:
        text = "The quick brown fox jumps over the lazy dog. " * 20
        single = estimate_tokens([{"text": text}])
        double = estimate_tokens([{"text": text}, {"text": text}])
        assert single > 0
        ratio = double / single
        assert 1.5 <= ratio <= 2.5

    def test_non_serialisable_returns_zero_without_raising(self) -> None:
        with mock.patch(
            "arema.runtime.context.budget.json.dumps",
            side_effect=RuntimeError("boom"),
        ):
            result = estimate_tokens([{"key": "value"}])
        assert result == 0

    def test_content_with_function_response_produces_positive_estimate(self) -> None:
        contents = [
            _make_content(
                [_make_func_response_part({"id": "run-1", "item_count": 3}, name="search")]
            )
        ]
        assert estimate_tokens(contents) > 0

    def test_content_with_function_call_produces_positive_estimate(self) -> None:
        contents = [_make_content([_make_func_call_part("search")])]
        assert estimate_tokens(contents) > 0


# ---------------------------------------------------------------------------
# classify_pressure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ratio", "pressure"),
    [
        (0.59, ContextPressure.NORMAL),
        (0.60, ContextPressure.WARNING),
        (0.75, ContextPressure.HARD),
        (0.85, ContextPressure.CRITICAL),
    ],
)
def test_context_pressure_thresholds(ratio: float, pressure: ContextPressure) -> None:
    assert classify_pressure(ratio) is pressure


def test_classify_pressure_honours_explicit_settings_override() -> None:
    settings = _settings(
        context_warning_ratio=0.3,
        context_hard_ratio=0.5,
        context_critical_ratio=0.7,
    )
    assert classify_pressure(0.2, settings) is ContextPressure.NORMAL
    assert classify_pressure(0.35, settings) is ContextPressure.WARNING
    assert classify_pressure(0.55, settings) is ContextPressure.HARD
    assert classify_pressure(0.9, settings) is ContextPressure.CRITICAL


# ---------------------------------------------------------------------------
# _compact_old_tool_results
# ---------------------------------------------------------------------------


class TestCompactOldToolResults:
    def test_compacts_old_preserves_recent(self) -> None:
        contents = [
            _make_content([_make_func_response_part({"id": i, "item_count": i}, name=f"tool_{i}")])
            for i in range(5)
        ]
        count = _compact_old_tool_results(contents, preserve_recent=2)
        assert count == 3

        for content in contents[:3]:
            response = content.parts[0].function_response.response
            assert isinstance(response, dict)
            assert response["result"].startswith("[Compacted]")

        for content in contents[3:]:
            response = content.parts[0].function_response.response
            assert "id" in response

    def test_nothing_to_compact_when_few_results(self) -> None:
        contents = [_make_content([_make_func_response_part({"id": "s1"})])]
        assert _compact_old_tool_results(contents, preserve_recent=3) == 0

    def test_skips_already_compacted(self) -> None:
        already = _make_func_response_part(
            {"result": "[Compacted] search completed. done."}, name="search"
        )
        contents = [
            _make_content([already]),
            _make_content([_make_func_response_part({"id": "s2"})]),
            _make_content([_make_func_response_part({"id": "s3"})]),
            _make_content([_make_func_response_part({"id": "s4"})]),
        ]
        assert _compact_old_tool_results(contents, preserve_recent=1) == 2

    def test_ignores_text_only_content(self) -> None:
        contents = [
            _make_content([_make_text_part("user message")]),
            _make_content([_make_func_response_part({"id": "s1"})]),
            _make_content([_make_func_response_part({"id": "s2"})]),
        ]
        assert _compact_old_tool_results(contents, preserve_recent=1) == 1

    def test_compact_message_uses_generic_count_fields_and_tool_name(self) -> None:
        part = _make_func_response_part({"item_count": 4, "record_count": 2}, name="search")
        contents = [
            _make_content([part]),
            _make_content([_make_func_response_part({"keep": True})]),
        ]
        _compact_old_tool_results(contents, preserve_recent=1)
        message = contents[0].parts[0].function_response.response["result"]
        assert "search" in message
        assert "4 item" in message
        assert "2 record" in message

    def test_summary_falls_back_to_completed_for_no_signal(self) -> None:
        part = _make_func_response_part({"status": "ok"}, name="search")
        contents = [
            _make_content([part]),
            _make_content([_make_func_response_part({"keep": True})]),
        ]
        _compact_old_tool_results(contents, preserve_recent=1)
        message = contents[0].parts[0].function_response.response["result"]
        assert "completed" in message


# ---------------------------------------------------------------------------
# _compact_old_model_text
# ---------------------------------------------------------------------------


class TestCompactOldModelText:
    def test_truncates_long_text_preserves_recent(self) -> None:
        contents = [_make_content([_make_text_part(_LONG_TEXT)]) for _ in range(5)]
        count = _compact_old_model_text(
            contents, preserve_recent_turns=2, min_length=500, prefix_chars=200
        )
        assert count == 3

        for content in contents[:3]:
            text = content.parts[0].text
            assert "[... truncated by context budget ...]" in text
            assert text.startswith("A" * 200)

        for content in contents[3:]:
            assert content.parts[0].text == _LONG_TEXT

    def test_preserves_short_text(self) -> None:
        short_text = "B" * 400
        contents = [_make_content([_make_text_part(short_text)]) for _ in range(4)]
        count = _compact_old_model_text(
            contents, preserve_recent_turns=0, min_length=500, prefix_chars=200
        )
        assert count == 0
        for content in contents:
            assert content.parts[0].text == short_text

    def test_ignores_function_response_parts(self) -> None:
        func_part = Part(function_response=FunctionResponse(name="tool", response={"key": "val"}))
        func_part.text = _LONG_TEXT
        contents = [_make_content([func_part]) for _ in range(4)]
        count = _compact_old_model_text(
            contents, preserve_recent_turns=0, min_length=500, prefix_chars=200
        )
        assert count == 0

    def test_function_call_parts_never_truncated(self) -> None:
        call_part = Part(function_call=FunctionCall(name="tool", args={"q": "x"}))
        call_part.text = _LONG_TEXT
        contents = [_make_content([call_part], role="model") for _ in range(4)]
        count = _compact_old_model_text(
            contents, preserve_recent_turns=0, min_length=500, prefix_chars=200
        )
        assert count == 0
        for content in contents:
            assert content.parts[0].text == _LONG_TEXT

    def test_user_role_content_never_truncated(self) -> None:
        contents = [_make_content([_make_text_part(_LONG_TEXT)], role="user") for _ in range(4)]
        count = _compact_old_model_text(
            contents, preserve_recent_turns=0, min_length=500, prefix_chars=200
        )
        assert count == 0
        for content in contents:
            assert content.parts[0].text == _LONG_TEXT

    def test_idempotent_on_already_truncated(self) -> None:
        contents = [_make_content([_make_text_part(_LONG_TEXT)]) for _ in range(4)]
        first_pass = _compact_old_model_text(
            contents, preserve_recent_turns=1, min_length=500, prefix_chars=200
        )
        assert first_pass == 3

        second_pass = _compact_old_model_text(
            contents, preserve_recent_turns=1, min_length=500, prefix_chars=200
        )
        assert second_pass == 0


# ---------------------------------------------------------------------------
# enforce_context_budget
# ---------------------------------------------------------------------------


class TestEnforceContextBudget:
    async def test_returns_none_for_empty_contents(self) -> None:
        llm_request = SimpleNamespace(contents=[])
        result = await enforce_context_budget(SimpleNamespace(state={}), llm_request)
        assert result is None

    async def test_returns_none_for_none_contents(self) -> None:
        llm_request = SimpleNamespace(contents=None)
        result = await enforce_context_budget(SimpleNamespace(state={}), llm_request)
        assert result is None

    async def test_no_action_below_warning_threshold(self) -> None:
        settings = _settings()
        llm_request = SimpleNamespace(contents=[_make_content([_make_text_part("short")])])
        with mock.patch("arema.runtime.context.budget.get_settings", return_value=settings):
            result = await enforce_context_budget(SimpleNamespace(state={}), llm_request)
        assert result is None

    async def test_compacts_at_warning_pressure(self) -> None:
        settings = _settings(context_budget_tokens=10_000, context_preserve_recent_tools=1)
        contents = [
            _make_content([_make_func_response_part({"data": "x" * 200, "id": i})])
            for i in range(5)
        ]
        llm_request = SimpleNamespace(contents=contents)

        with (
            mock.patch("arema.runtime.context.budget.get_settings", return_value=settings),
            mock.patch("arema.runtime.context.budget.estimate_tokens", return_value=6_500),
        ):
            result = await enforce_context_budget(SimpleNamespace(state={}), llm_request)

        assert result is None
        compacted = sum(
            1
            for content in contents
            if isinstance(content.parts[0].function_response.response, dict)
            and str(content.parts[0].function_response.response.get("result", "")).startswith(
                "[Compacted]"
            )
        )
        assert compacted == 4

    async def test_critical_pressure_preserves_one_tool_and_one_model_turn(self) -> None:
        """At CRITICAL pressure only the single most recent tool result and the
        single most recent model turn survive compaction -- when that is enough
        to recover, the run continues (returns None)."""
        settings = _settings(
            context_budget_tokens=10_000,
            context_preserve_recent_tools=3,
            context_preserve_recent_model_turns=4,
        )
        tool_contents = [
            _make_content([_make_func_response_part({"data": "x" * 200, "id": i})])
            for i in range(4)
        ]
        model_contents = [
            _make_content([_make_text_part(_LONG_TEXT)], role="model") for _ in range(5)
        ]
        llm_request = SimpleNamespace(contents=[*tool_contents, *model_contents])

        with (
            mock.patch("arema.runtime.context.budget.get_settings", return_value=settings),
            mock.patch(
                "arema.runtime.context.budget.estimate_tokens",
                side_effect=[9_000, 7_000, 2_000],
            ),
        ):
            result = await enforce_context_budget(SimpleNamespace(state={}), llm_request)

        assert result is None  # compaction recovered before the critical floor

        tool_compacted = sum(
            1
            for content in tool_contents
            if isinstance(content.parts[0].function_response.response, dict)
            and str(content.parts[0].function_response.response.get("result", "")).startswith(
                "[Compacted]"
            )
        )
        assert tool_compacted == 3  # 4 results - 1 preserved

        text_truncated = sum(
            1
            for content in model_contents
            if "[... truncated by context budget ...]" in content.parts[0].text
        )
        assert text_truncated == 4  # 5 turns - 1 preserved

    async def test_repeated_compaction_is_idempotent(self) -> None:
        settings = _settings(
            context_budget_tokens=10_000,
            context_preserve_recent_tools=2,
            context_preserve_recent_model_turns=2,
        )
        contents = [
            _make_content([_make_func_response_part({"data": "x" * 50, "id": i})]) for i in range(6)
        ]
        llm_request = SimpleNamespace(contents=contents)

        with (
            mock.patch("arema.runtime.context.budget.get_settings", return_value=settings),
            mock.patch("arema.runtime.context.budget.estimate_tokens", return_value=6_500),
        ):
            first_result = await enforce_context_budget(SimpleNamespace(state={}), llm_request)
            snapshot = [dict(content.parts[0].function_response.response) for content in contents]
            second_result = await enforce_context_budget(SimpleNamespace(state={}), llm_request)

        assert first_result is None
        assert second_result is None
        for content, before in zip(contents, snapshot, strict=True):
            assert content.parts[0].function_response.response == before

    async def test_hard_limit_exhaustion_returns_checkpoint_response(self) -> None:
        """When nothing further can be compacted and the estimate stays at or
        above the critical threshold, the run stops cleanly instead of
        submitting an oversized request."""
        settings = _settings(context_budget_tokens=10_000)
        already_compacted = _make_func_response_part(
            {"result": "[Compacted] search completed. done."}, name="search"
        )
        contents = [
            _make_content([already_compacted]),
            _make_content([_make_text_part("short")], role="model"),
        ]
        llm_request = SimpleNamespace(contents=contents)
        callback_context = SimpleNamespace(state={})

        with (
            mock.patch("arema.runtime.context.budget.get_settings", return_value=settings),
            mock.patch("arema.runtime.context.budget.estimate_tokens", return_value=9_500),
        ):
            result = await enforce_context_budget(callback_context, llm_request)

        assert isinstance(result, LlmResponse)
        assert result.content is not None
        response_text = result.content.parts[0].text
        assert "context" in response_text.lower()

        checkpoint = callback_context.state[CHECKPOINT_STATE_KEY]
        assert checkpoint["tokens"] == 9_500
        assert checkpoint["budget"] == 10_000

    async def test_checkpoint_still_terminates_when_state_write_is_unavailable(self) -> None:
        settings = _settings(context_budget_tokens=10_000)
        contents = [
            _make_content(
                [
                    _make_func_response_part(
                        {"result": "[Compacted] search completed. done."}, name="search"
                    )
                ]
            )
        ]
        llm_request = SimpleNamespace(contents=contents)
        callback_context = SimpleNamespace(state=None)

        with (
            mock.patch("arema.runtime.context.budget.get_settings", return_value=settings),
            mock.patch("arema.runtime.context.budget.estimate_tokens", return_value=9_500),
        ):
            result = await enforce_context_budget(callback_context, llm_request)

        assert isinstance(result, LlmResponse)
