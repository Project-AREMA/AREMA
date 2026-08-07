"""The execution-flow diagram is drawn by code, never written by a model.

These tests pin the two properties the report depends on: a diagram can only
contain a shape the stage declared, and the rendered text is safe to paste into
both a mermaid renderer and an ADK instruction template.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from reverse_engineering.evidence_envelope import (
    CoverageStatus,
    parse_evidence_envelope,
    rebind_evidence_envelope,
    salvage_evidence_envelope,
)
from reverse_engineering.execution_flow import (
    MAX_EDGE_LABEL_CHARS,
    MAX_FLOW_EDGES,
    MAX_FLOW_LABEL_CHARS,
    MAX_FLOW_NODES,
    MAX_FLOW_TOOL_CHARS,
    ExecutionEdge,
    ExecutionFlow,
    ExecutionNode,
    filter_flow_by_cited_tools,
    render_mermaid,
    sanitize_execution_flow,
)


def _raw(nodes: list[dict[str, object]], edges: list[dict[str, object]] | None = None) -> dict:
    return {"nodes": nodes, "edges": edges if edges is not None else []}


def _node(node_id: str, label: str = "Step", tool: str = "ghidra_decompile") -> dict[str, object]:
    return {"id": node_id, "label": label, "tool": tool}


UPX_FLOW = _raw(
    [
        _node("entry", "Entry: UPX stub"),
        _node("unpack", "Decompress payload in memory"),
        _node("persist", "Append a line to $HOME/.profile", tool="ghidra_strings"),
    ],
    [
        {"src": "entry", "dst": "unpack"},
        {"src": "unpack", "dst": "persist", "label": "on success"},
    ],
)


# --- structural sanitation ----------------------------------------------------


def test_a_well_formed_flow_survives_intact() -> None:
    flow = sanitize_execution_flow(UPX_FLOW)

    assert flow is not None
    assert [node.id for node in flow.nodes] == ["entry", "unpack", "persist"]
    assert len(flow.edges) == 2


def test_an_edge_to_an_undeclared_node_is_dropped_and_its_nodes_survive() -> None:
    flow = sanitize_execution_flow(
        _raw([_node("a"), _node("b")], [{"src": "a", "dst": "ghost"}, {"src": "a", "dst": "b"}])
    )

    assert flow is not None
    assert len(flow.nodes) == 2
    assert [(edge.src, edge.dst) for edge in flow.edges] == [("a", "b")]


def test_a_duplicate_node_id_keeps_the_first_declaration() -> None:
    flow = sanitize_execution_flow(_raw([_node("a", "First"), _node("a", "Second")]))

    assert flow is not None
    assert [(node.id, node.label) for node in flow.nodes] == [("a", "First")]


def test_a_repeated_edge_is_collapsed() -> None:
    flow = sanitize_execution_flow(
        _raw([_node("a"), _node("b")], [{"src": "a", "dst": "b"}, {"src": "a", "dst": "b"}])
    )

    assert flow is not None
    assert len(flow.edges) == 1


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "flowchart TD; a --> b",
        [],
        {"nodes": "entry"},
        {"nodes": []},
        _raw([{"id": "has spaces", "label": "x", "tool": "t"}]),
        _raw([{"id": "a", "label": "", "tool": "t"}]),
        _raw([{"id": "a", "label": "x", "tool": ""}]),
        _raw([{"label": "x", "tool": "t"}]),
    ],
)
def test_unusable_input_yields_no_diagram_rather_than_an_error(raw: object) -> None:
    assert sanitize_execution_flow(raw) is None


def test_nodes_and_edges_beyond_the_caps_are_dropped() -> None:
    nodes = [_node(f"n{index}") for index in range(MAX_FLOW_NODES + 5)]
    edges = [{"src": "n0", "dst": f"n{index}"} for index in range(1, MAX_FLOW_EDGES + 5)]
    flow = sanitize_execution_flow(_raw(nodes, edges))

    assert flow is not None
    assert len(flow.nodes) == MAX_FLOW_NODES
    assert len(flow.edges) <= MAX_FLOW_EDGES


def test_a_flow_whose_only_node_is_malformed_yields_nothing() -> None:
    assert sanitize_execution_flow(_raw([{"id": "a!", "label": "x", "tool": "t"}])) is None


# --- label sanitation ---------------------------------------------------------


@pytest.mark.parametrize("char", ['"', "{", "}", "<", ">", "|", "\\", "`"])
def test_characters_that_could_escape_the_diagram_are_removed(char: str) -> None:
    """The rendered block legitimately contains quotes and backticks of its own,
    so the node line is pinned exactly rather than scanned for the character."""
    flow = sanitize_execution_flow(_raw([_node("a", f"before{char}after")]))

    assert flow is not None
    assert char not in flow.nodes[0].label
    node_line = next(
        line for line in render_mermaid(flow).splitlines() if line.startswith("    n0")
    )
    assert node_line == '    n0["before after (ghidra_decompile)"]'


def test_a_newline_cannot_split_a_label_across_mermaid_statements() -> None:
    flow = sanitize_execution_flow(_raw([_node("a", 'evil\n    b["injected"]')]))

    assert flow is not None
    assert "\n" not in flow.nodes[0].label
    # fence, header, exactly one node, fence -- the smuggled statement is inert
    # text inside the surviving node's quoted label.
    assert len(render_mermaid(flow).splitlines()) == 4


def test_control_and_non_ascii_characters_become_spaces() -> None:
    flow = sanitize_execution_flow(_raw([_node("a", "reads\x00\x07config 你好 file")]))

    assert flow is not None
    assert flow.nodes[0].label == "reads config file"


def test_labels_are_truncated_to_their_bounds() -> None:
    flow = sanitize_execution_flow(
        _raw(
            [_node("a", "x" * (MAX_FLOW_LABEL_CHARS + 50), tool="t" * (MAX_FLOW_TOOL_CHARS + 50))],
            [{"src": "a", "dst": "a", "label": "y" * (MAX_EDGE_LABEL_CHARS + 50)}],
        )
    )

    assert flow is not None
    assert len(flow.nodes[0].label) == MAX_FLOW_LABEL_CHARS
    assert len(flow.nodes[0].tool) == MAX_FLOW_TOOL_CHARS
    assert len(flow.edges[0].label) == MAX_EDGE_LABEL_CHARS


def test_a_label_that_sanitizes_to_nothing_drops_the_node_and_its_edges() -> None:
    flow = sanitize_execution_flow(
        _raw([_node("a"), _node("b", '"""')], [{"src": "a", "dst": "b"}])
    )

    assert flow is not None
    assert [node.id for node in flow.nodes] == ["a"]
    assert flow.edges == ()


def test_a_bracket_survives_because_the_label_is_quoted() -> None:
    """Stripping brackets would mangle real evidence such as ``argv[0]``."""
    flow = sanitize_execution_flow(_raw([_node("a", "reads argv[0]")]))

    assert flow is not None
    assert "argv[0]" in render_mermaid(flow)


# --- rendering ----------------------------------------------------------------


def test_render_produces_a_complete_fenced_diagram() -> None:
    rendered = render_mermaid(sanitize_execution_flow(UPX_FLOW))

    assert rendered.startswith("```mermaid\nflowchart TD\n")
    assert rendered.endswith("\n```")
    assert '    n0["Entry: UPX stub (ghidra_decompile)"]' in rendered
    assert "    n0 --> n1" in rendered
    assert '    n1 -->|"on success"| n2' in rendered


def test_every_node_carries_its_tool_citation_in_the_picture() -> None:
    """A reader must be able to check a step against the report's evidence
    without leaving the diagram."""
    rendered = render_mermaid(sanitize_execution_flow(UPX_FLOW))

    assert rendered.count("(ghidra_decompile)") == 2
    assert rendered.count("(ghidra_strings)") == 1


def test_model_chosen_ids_never_reach_the_output() -> None:
    flow = sanitize_execution_flow(
        _raw([_node("end", "First"), _node("graph", "Second")], [{"src": "end", "dst": "graph"}])
    )
    rendered = render_mermaid(flow)

    assert "end" not in rendered
    assert "graph" not in rendered
    assert "    n0 --> n1" in rendered


def test_nothing_to_draw_renders_the_empty_string() -> None:
    assert render_mermaid(None) == ""


def test_the_rendered_block_carries_no_instruction_template_placeholder() -> None:
    """The string is injected into an ADK instruction template, where a stray
    brace would be resolved as a state placeholder."""
    rendered = render_mermaid(sanitize_execution_flow(_raw([_node("a", "reads {secret_key?}")])))

    assert "{" not in rendered
    assert "}" not in rendered


# --- the strict model refuses what the sanitizer promises never to build ------


def test_a_dangling_edge_cannot_be_constructed_directly() -> None:
    with pytest.raises(ValidationError):
        ExecutionFlow(
            nodes=(ExecutionNode(id="a", label="A", tool="t"),),
            edges=(ExecutionEdge(src="a", dst="b"),),
        )


def test_duplicate_ids_cannot_be_constructed_directly() -> None:
    with pytest.raises(ValidationError):
        ExecutionFlow(
            nodes=(
                ExecutionNode(id="a", label="A", tool="t"),
                ExecutionNode(id="a", label="B", tool="t"),
            )
        )


def test_a_flow_needs_at_least_one_node() -> None:
    with pytest.raises(ValidationError):
        ExecutionFlow(nodes=())


# --- filtering by surviving evidence ------------------------------------------


def test_a_node_citing_a_tool_with_no_surviving_evidence_is_dropped() -> None:
    flow = filter_flow_by_cited_tools(sanitize_execution_flow(UPX_FLOW), {"ghidra_decompile"})

    assert flow is not None
    assert [node.id for node in flow.nodes] == ["entry", "unpack"]


def test_dropping_a_node_drops_every_edge_that_touched_it() -> None:
    flow = filter_flow_by_cited_tools(sanitize_execution_flow(UPX_FLOW), {"ghidra_decompile"})

    assert flow is not None
    assert [(edge.src, edge.dst) for edge in flow.edges] == [("entry", "unpack")]


def test_no_surviving_tool_leaves_no_diagram() -> None:
    assert filter_flow_by_cited_tools(sanitize_execution_flow(UPX_FLOW), {"list_imports"}) is None
    assert filter_flow_by_cited_tools(sanitize_execution_flow(UPX_FLOW), set()) is None


def test_filtering_nothing_is_a_noop() -> None:
    assert filter_flow_by_cited_tools(None, {"ghidra_decompile"}) is None


# --- carried on the envelope, unable to harm it -------------------------------

ARTIFACT_ID = "a" * 64


def _envelope(flow: object) -> dict[str, object]:
    return {
        "artifact_id": ARTIFACT_ID,
        "coverage": {"status": "complete", "surfaces": ["ghidra_decompile"], "limitations": []},
        "findings": [
            {
                "artifact_id": ARTIFACT_ID,
                "claim": "The sample appends to $HOME/.profile.",
                "tool": "ghidra_decompile",
                "confidence": 0.8,
                "detail": "fopen + fputs on the profile path",
                "kind": "behavior",
            }
        ],
        "flow": flow,
    }


def test_a_flow_rides_the_envelope_and_round_trips() -> None:
    envelope = parse_evidence_envelope(json.dumps(_envelope(UPX_FLOW)), artifact_id=ARTIFACT_ID)

    assert envelope.flow is not None
    assert [node.id for node in envelope.flow.nodes] == ["entry", "unpack", "persist"]

    reparsed = parse_evidence_envelope(envelope.model_dump(mode="json"), artifact_id=ARTIFACT_ID)
    assert reparsed.flow == envelope.flow


@pytest.mark.parametrize(
    "flow",
    [
        None,
        "flowchart TD; a --> b",
        {"nodes": [{"id": "bad id!", "label": "x", "tool": "t"}]},
        {"nodes": [{"id": "a", "label": "x", "tool": "t", "unexpected": True}]},
        {"nodes": [], "edges": [{"src": "a", "dst": "b"}]},
        {"nodes": UPX_FLOW["nodes"], "unexpected": True},
    ],
)
def test_a_malformed_flow_never_costs_the_stage_its_findings(flow: object) -> None:
    """The regression guard for the whole point of Part 1: the diagram is
    decoration, and decoration may not invalidate evidence."""
    envelope = parse_evidence_envelope(json.dumps(_envelope(flow)), artifact_id=ARTIFACT_ID)

    assert len(envelope.findings) == 1
    assert envelope.coverage.status is CoverageStatus.COMPLETE


def test_an_envelope_with_a_bad_flow_and_a_bad_finding_still_salvages_both_ways() -> None:
    payload = _envelope({"nodes": "not a list"})
    payload["findings"] = [*payload["findings"], {"claim": "broken"}]  # type: ignore[list-item]
    envelope, dropped, _ = salvage_evidence_envelope(json.dumps(payload), artifact_id=ARTIFACT_ID)

    assert dropped == 1
    assert len(envelope.findings) == 1
    assert envelope.flow is None


def test_a_salvaged_envelope_keeps_a_good_flow() -> None:
    payload = _envelope(UPX_FLOW)
    payload["summary"] = "an extra key that fails strict validation"
    envelope, _dropped, _rebound = salvage_evidence_envelope(
        json.dumps(payload), artifact_id=ARTIFACT_ID
    )

    assert envelope.flow is not None
    assert render_mermaid(envelope.flow).startswith("```mermaid")


def test_rebinding_carries_the_flow_across_the_new_anchor() -> None:
    envelope = parse_evidence_envelope(json.dumps(_envelope(UPX_FLOW)), artifact_id=ARTIFACT_ID)
    rebound = rebind_evidence_envelope(envelope, artifact_id="b" * 64)

    assert rebound.artifact_id == "b" * 64
    assert rebound.flow == envelope.flow
