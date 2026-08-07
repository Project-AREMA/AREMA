"""Unit tests for the single robust model->JSON boundary."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from reverse_engineering.model_json import MAX_MODEL_JSON_CHARS, loads_model_json


def test_plain_json_object():
    assert loads_model_json('{"a": 1}') == {"a": 1}


def test_strips_json_code_fence():
    assert loads_model_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_strips_bare_code_fence():
    assert loads_model_json('```\n{"a": 1}\n```') == {"a": 1}


def test_strips_fence_with_trailing_prose_whitespace():
    assert loads_model_json('  ```json\n{"a": [1, 2]}\n```  ') == {"a": [1, 2]}


def test_passes_through_already_parsed_mapping():
    obj = {"a": 1}
    assert loads_model_json(obj) is obj


def test_rejects_nan_infinity_constants():
    with pytest.raises(ValueError):
        loads_model_json('{"a": NaN}')
    with pytest.raises(ValueError):
        loads_model_json('```json\n{"a": Infinity}\n```')


def test_repairs_trailing_comma_via_json_repair():
    assert loads_model_json('{"a": 1,}') == {"a": 1}


def test_repairs_fenced_trailing_comma():
    assert loads_model_json('```json\n{"a": 1, "b": 2,}\n```') == {"a": 1, "b": 2}


def test_unrecoverable_text_raises():
    with pytest.raises(ValueError):
        loads_model_json("this is not json at all ~~~")


def test_oversized_input_exceeds_default_cap_raises():
    with pytest.raises(ValueError):
        loads_model_json("x" * (MAX_MODEL_JSON_CHARS + 1))


def test_at_limit_input_still_parses():
    text = '{"a": 1}'
    assert loads_model_json(text, max_chars=len(text)) == {"a": 1}


def test_caller_supplied_smaller_max_chars_is_honored():
    text = '{"a": 1}'
    with pytest.raises(ValueError):
        loads_model_json(text, max_chars=len(text) - 1)


def test_fence_wrapped_in_leading_and_trailing_prose():
    # The anchored stripper does not match this (the fence does not span the
    # whole string), so this succeeds via the json_repair salvage fallback,
    # not via ``_strip_code_fence`` -- documents the real, end-to-end behavior.
    text = 'Here is the result:\n```json\n{"a": 1}\n```\nHope this helps'
    assert loads_model_json(text) == {"a": 1}


def test_fenced_payload_with_embedded_code_fence_in_string_value_round_trips():
    # Regression: an unanchored/non-greedy fence regex matches the FIRST ```
    # sequence, which is the embedded fence inside the string value here, not
    # the wrapper's closing fence -- silently truncating the decoded value.
    # The anchored + greedy regex must find the wrapper's real closing fence.
    text = '```json\n{"finding": "Sample uses ```powershell```"}\n```'
    assert loads_model_json(text) == {"finding": "Sample uses ```powershell```"}


def test_unfenced_json_with_embedded_code_fence_in_string_value_parses_as_is():
    # The anchored regex must NOT match unfenced text (it doesn't span the
    # whole string as a fence), so this decodes directly without stripping.
    text = '{"finding": "Sample uses ```powershell```"}'
    assert loads_model_json(text) == {"finding": "Sample uses ```powershell```"}


# Modules that legitimately parse MODEL-authored text into JSON. Each must go
# through loads_model_json, never a bare json.loads -- that is what let the
# ```json bug recur. Non-model json.loads (sqlite rows, tool stdout) is fine and
# lives in other modules, which this guard does not touch.
_MODEL_JSON_PARSERS = (
    "src/reverse_engineering/evidence_envelope.py",
    "src/reverse_engineering/agents/deobf_gate.py",
    "src/reverse_engineering/tools/deobfuscation/state.py",
    "src/reverse_engineering/agents/evidence_output.py",
    "src/malware_analyst/evidence.py",
)


def _collect_json_import_aliases(tree: ast.Module) -> tuple[set[str], set[str]]:
    """Return (json_module_names, direct_loads_names) bound by this module's imports.

    ``json_module_names`` holds local names bound to the ``json`` module itself
    (``import json`` -> "json"; ``import json as j`` -> "j"). ``direct_loads_names``
    holds local names bound directly to ``json.loads`` (``from json import loads``
    -> "loads"; ``from json import loads as jl`` -> "jl"). Both import styles let a
    caller invoke ``json.loads`` without the literal token sequence ``json.loads``
    appearing at the call site, so the call-site matcher below needs both sets.
    """
    json_module_names: set[str] = set()
    direct_loads_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "json":
                    json_module_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "json":
            for alias in node.names:
                if alias.name == "loads":
                    direct_loads_names.add(alias.asname or alias.name)
    return json_module_names, direct_loads_names


def test_model_output_parsers_do_not_call_bare_json_loads():
    offenders = []
    for rel in _MODEL_JSON_PARSERS:
        tree = ast.parse(Path(rel).read_text())
        json_module_names, direct_loads_names = _collect_json_import_aliases(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_module_attr_call = (
                isinstance(func, ast.Attribute)
                and func.attr == "loads"
                and isinstance(func.value, ast.Name)
                and func.value.id in json_module_names
            )
            is_direct_name_call = isinstance(func, ast.Name) and func.id in direct_loads_names
            if is_module_attr_call or is_direct_name_call:
                offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, (
        "bare json.loads on model output found (including aliased/from-imports); "
        "route through loads_model_json: " + ", ".join(offenders)
    )
