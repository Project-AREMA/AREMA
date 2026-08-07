"""Tests for descriptor-driven, tool-agnostic output compaction."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest import mock

from hypothesis import HealthCheck, given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st

from arema.registry.descriptors import OutputPolicy
from arema.runtime.context.compactor import compact_response, make_output_compactor

# ---------------------------------------------------------------------------
# compact_response
# ---------------------------------------------------------------------------


def test_compactor_uses_policy_not_tool_name() -> None:
    response = {"raw": "x" * 100, "items": list(range(10)), "keep": "value"}
    policy = OutputPolicy(max_chars=200, max_list_items=3, drop_fields=("raw",))
    compacted = compact_response(response, policy)
    assert "raw" not in compacted
    assert compacted["items"] == [0, 1, 2]
    assert compacted["keep"] == "value"


def test_compact_response_does_not_mutate_input() -> None:
    response = {"raw": "secret", "items": [1, 2, 3, 4]}
    original = json.loads(json.dumps(response))
    policy = OutputPolicy(max_list_items=2, drop_fields=("raw",))

    compact_response(response, policy)

    assert response == original


def test_drop_fields_applies_recursively() -> None:
    response = {
        "keep": "value",
        "nested": {"raw": "secret", "safe": "ok"},
        "list_of_nested": [{"raw": "secret2", "safe": "ok2"}],
    }
    policy = OutputPolicy(drop_fields=("raw",))

    compacted = compact_response(response, policy)

    assert "raw" not in compacted["nested"]
    assert compacted["nested"]["safe"] == "ok"
    assert "raw" not in compacted["list_of_nested"][0]
    assert compacted["list_of_nested"][0]["safe"] == "ok2"


def test_bound_lists_recurse_into_nested_lists() -> None:
    response = {"outer": [{"inner": list(range(10))}]}
    policy = OutputPolicy(max_list_items=2)

    compacted = compact_response(response, policy)

    assert compacted["outer"][0]["inner"] == [0, 1]


def test_preserve_fields_exempt_from_dropping_and_bounding() -> None:
    response = {"raw": "secret", "credentials": list(range(50))}
    policy = OutputPolicy(
        max_list_items=3,
        drop_fields=("raw", "credentials"),
        preserve_fields=("credentials",),
    )

    compacted = compact_response(response, policy)

    assert "raw" not in compacted
    assert compacted["credentials"] == list(range(50))


def test_deep_truncate_shrinks_largest_value_until_within_budget() -> None:
    response = {"small": "ok", "huge": "z" * 5_000}
    policy = OutputPolicy(max_chars=200, max_list_items=100)

    compacted = compact_response(response, policy)

    assert len(json.dumps(compacted)) <= 200
    assert compacted["small"] == "ok"
    assert compacted["huge"] != "z" * 5_000


def test_deep_truncate_preserves_protected_fields_even_when_oversized() -> None:
    response = {"credentials": "z" * 5_000}
    policy = OutputPolicy(max_chars=50, preserve_fields=("credentials",))

    compacted = compact_response(response, policy)

    assert compacted["credentials"] == "z" * 5_000


def test_deep_truncate_converges_without_reaching_pass_cap() -> None:
    """A pathological single huge field must not loop indefinitely -- the
    algorithm must detect a stable fixed point and stop early."""
    response = {"huge": "z" * 50_000}
    policy = OutputPolicy(max_chars=5_000)

    compacted = compact_response(response, policy)

    assert len(json.dumps(compacted)) <= 5_000


def test_compact_response_applied_twice_is_idempotent() -> None:
    response = {"raw": "secret", "items": list(range(20)), "huge": "z" * 2_000}
    policy = OutputPolicy(max_chars=100, max_list_items=3, drop_fields=("raw",))

    once = compact_response(response, policy)
    twice = compact_response(once, policy)

    assert once == twice


# ---------------------------------------------------------------------------
# make_output_compactor
# ---------------------------------------------------------------------------


def test_make_output_compactor_uses_registered_policy() -> None:
    policy = OutputPolicy(max_chars=1_000, max_list_items=1, drop_fields=("noisy",))
    compactor = make_output_compactor({"probe": policy})
    tool = SimpleNamespace(name="probe")
    response: dict[str, Any] = {"noisy": "drop me", "items": [1, 2, 3]}

    result = compactor(tool=tool, args={}, tool_context=SimpleNamespace(), tool_response=response)

    assert result is not None
    assert "noisy" not in result
    assert result["items"] == [1]


def test_make_output_compactor_falls_back_to_safe_default_for_unknown_tool() -> None:
    compactor = make_output_compactor({"known": OutputPolicy(max_list_items=1)})
    tool = SimpleNamespace(name="unregistered")
    response: dict[str, Any] = {"items": list(range(50))}

    result = compactor(tool=tool, args={}, tool_context=SimpleNamespace(), tool_response=response)

    assert result is not None
    assert result["items"] == list(range(30))  # OutputPolicy() default max_list_items


def test_make_output_compactor_ignores_non_dict_responses() -> None:
    compactor = make_output_compactor({})
    tool = SimpleNamespace(name="probe")

    result = compactor(
        tool=tool, args={}, tool_context=SimpleNamespace(), tool_response="not-a-dict"
    )

    assert result is None


def test_make_output_compactor_fails_open_on_unexpected_error() -> None:
    compactor = make_output_compactor({"probe": OutputPolicy()})
    tool = SimpleNamespace(name="probe")

    with mock.patch(
        "arema.runtime.context.compactor.compact_response",
        side_effect=RuntimeError("boom"),
    ):
        result = compactor(
            tool=tool, args={}, tool_context=SimpleNamespace(), tool_response={"a": 1}
        )

    assert result is None


def test_make_output_compactor_mapping_is_copied_not_referenced() -> None:
    policies = {"probe": OutputPolicy(max_list_items=1)}
    compactor = make_output_compactor(policies)
    policies["probe"] = OutputPolicy(max_list_items=99)
    tool = SimpleNamespace(name="probe")

    result = compactor(
        tool=tool,
        args={},
        tool_context=SimpleNamespace(),
        tool_response={"items": list(range(10))},
    )

    assert result is not None
    assert result["items"] == [0]  # still uses the policy captured at construction time


def test_make_output_compactor_is_keyword_callable_like_adk_invokes_it() -> None:
    """ADK's flow invokes after_tool_callback entirely by keyword; the callable
    returned here must accept that exact calling convention."""
    compactor = make_output_compactor({})
    tool = SimpleNamespace(name="probe")

    result = compactor(
        tool=tool,
        args={"q": "value"},
        tool_context=SimpleNamespace(),
        tool_response={"ok": True},
    )

    assert result == {"ok": True}


# ---------------------------------------------------------------------------
# Property-based: compaction is safe, bounded, and idempotent for arbitrary
# JSON-shaped tool responses.
# ---------------------------------------------------------------------------

_json_scalars = st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=20))
_json_values = st.recursive(
    _json_scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.text(min_size=1, max_size=10), children, max_size=5),
    ),
    max_leaves=20,
)


@given(response=st.dictionaries(st.text(min_size=1, max_size=10), _json_values, max_size=5))
@hypothesis_settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_compact_response_is_bounded_and_idempotent_for_arbitrary_json(
    response: dict[str, Any],
) -> None:
    policy = OutputPolicy(max_chars=300, max_list_items=3)

    once = compact_response(response, policy)
    twice = compact_response(once, policy)

    assert once == twice
    for value in once.values():
        if isinstance(value, list):
            assert len(value) <= policy.max_list_items
