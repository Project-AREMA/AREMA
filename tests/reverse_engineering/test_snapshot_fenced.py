"""A fenced (```json) retriage snapshot must parse, not read as invalid."""

from __future__ import annotations

from reverse_engineering.agents.deobf_gate import _parse_snapshot


def test_fenced_snapshot_parses():
    raw = (
        "```json\n"
        '{"size": 1627136, "function_count": 0, "import_count": 1,'
        ' "string_count": 452, "section_count": 7}\n'
        "```"
    )
    snap = _parse_snapshot(raw)
    assert snap["size"] == 1627136
    assert snap["section_count"] == 7
