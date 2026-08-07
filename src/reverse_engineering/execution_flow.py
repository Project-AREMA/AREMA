"""A cited execution flow, rendered deterministically as mermaid.

The report's execution diagram is never authored by a model. A free-hand mermaid
block is prose, and prose is where inventions live -- a model asked to "draw the
flow" will happily connect two functions it never saw called. A stage instead
emits structured nodes and edges, each node naming the tool its step rests on,
and this module renders them.

Two properties follow, and neither depends on the model behaving:

* the diagram can only contain a shape the stage declared, because the renderer
  has nothing else to draw from; and
* after :func:`filter_flow_by_cited_tools`, it can only name a tool whose
  evidence survived the critic, so a rejected finding takes its step with it.

Node ids are model-chosen and are remapped to ``n0..nN`` on render, so an id can
never reach the output. Labels are restricted to a conservative ASCII subset:
``"`` terminates a mermaid label, ``|`` delimits an edge label, and ``{``/``}``
would be read as a placeholder by the ADK instruction template the rendered
string is injected into.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StrictStr, model_validator

MAX_FLOW_NODES = 24
MAX_FLOW_EDGES = 40
MAX_FLOW_LABEL_CHARS = 80
MAX_EDGE_LABEL_CHARS = 40
MAX_FLOW_TOOL_CHARS = 40

_NODE_ID = Annotated[StrictStr, Field(pattern=r"^[A-Za-z0-9_]{1,32}$")]

# Every character that can end a mermaid label, start an edge label, open an
# HTML entity, or be read as an ADK instruction placeholder.
_UNSAFE_LABEL_CHARS = '"{}<>|\\`'
_LABEL_TRANSLATION = str.maketrans(dict.fromkeys(_UNSAFE_LABEL_CHARS, " "))
_WHITESPACE = re.compile(r"\s+")

__all__ = [
    "MAX_EDGE_LABEL_CHARS",
    "MAX_FLOW_EDGES",
    "MAX_FLOW_LABEL_CHARS",
    "MAX_FLOW_NODES",
    "MAX_FLOW_TOOL_CHARS",
    "ExecutionEdge",
    "ExecutionFlow",
    "ExecutionNode",
    "filter_flow_by_cited_tools",
    "render_mermaid",
    "sanitize_execution_flow",
]


class ExecutionNode(BaseModel):
    """One step of the sample's execution, and the tool that evidences it."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    id: _NODE_ID
    label: Annotated[StrictStr, Field(min_length=1, max_length=MAX_FLOW_LABEL_CHARS)]
    tool: Annotated[StrictStr, Field(min_length=1, max_length=MAX_FLOW_TOOL_CHARS)]


class ExecutionEdge(BaseModel):
    """A transition from one declared step to another."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    src: _NODE_ID
    dst: _NODE_ID
    label: Annotated[StrictStr, Field(default="", max_length=MAX_EDGE_LABEL_CHARS)]


class ExecutionFlow(BaseModel):
    """A bounded, internally consistent execution summary."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    nodes: tuple[ExecutionNode, ...] = Field(min_length=1, max_length=MAX_FLOW_NODES)
    edges: tuple[ExecutionEdge, ...] = Field(default=(), max_length=MAX_FLOW_EDGES)

    @model_validator(mode="after")
    def _edges_reference_declared_nodes(self) -> ExecutionFlow:
        """A dangling edge is a drawing of a transition nobody declared."""
        declared = {node.id for node in self.nodes}
        if len(declared) != len(self.nodes):
            raise ValueError("execution flow node ids must be unique")
        if any(edge.src not in declared or edge.dst not in declared for edge in self.edges):
            raise ValueError("execution flow edges must reference declared nodes")
        return self


def _clean(value: object, *, max_chars: int) -> str:
    """Reduce model text to a bounded, single-line, mermaid-safe ASCII label."""
    if not isinstance(value, str):
        return ""
    stripped = "".join(
        char if char.isascii() and char.isprintable() else " "
        for char in value.translate(_LABEL_TRANSLATION)
    )
    return _WHITESPACE.sub(" ", stripped).strip()[:max_chars].strip()


def _node(raw: object) -> ExecutionNode | None:
    if not isinstance(raw, Mapping):
        return None
    try:
        return ExecutionNode(
            id=raw.get("id"),  # type: ignore[arg-type]
            label=_clean(raw.get("label"), max_chars=MAX_FLOW_LABEL_CHARS),
            tool=_clean(raw.get("tool"), max_chars=MAX_FLOW_TOOL_CHARS),
        )
    except (TypeError, ValueError):
        return None


def _edge(raw: object, declared: set[str]) -> ExecutionEdge | None:
    if not isinstance(raw, Mapping):
        return None
    try:
        edge = ExecutionEdge(
            src=raw.get("src"),  # type: ignore[arg-type]
            dst=raw.get("dst"),  # type: ignore[arg-type]
            label=_clean(raw.get("label"), max_chars=MAX_EDGE_LABEL_CHARS),
        )
    except (TypeError, ValueError):
        return None
    return edge if edge.src in declared and edge.dst in declared else None


def sanitize_execution_flow(raw: object) -> ExecutionFlow | None:
    """Recover a usable flow from model output, or ``None``. Never raises.

    A diagram is decoration: it may never cost a stage its evidence. Every
    defect is therefore absorbed here -- a malformed node is dropped, a duplicate
    id ignored, an edge to an undeclared node discarded -- rather than raised at
    the envelope that carries it.
    """
    if not isinstance(raw, Mapping):
        return None
    raw_nodes = raw.get("nodes")
    raw_edges = raw.get("edges")

    nodes: list[ExecutionNode] = []
    declared: set[str] = set()
    for item in (raw_nodes if isinstance(raw_nodes, list) else [])[:MAX_FLOW_NODES]:
        node = _node(item)
        if node is None or node.id in declared:
            continue
        declared.add(node.id)
        nodes.append(node)
    if not nodes:
        return None

    edges: list[ExecutionEdge] = []
    for item in (raw_edges if isinstance(raw_edges, list) else [])[:MAX_FLOW_EDGES]:
        edge = _edge(item, declared)
        if edge is not None and edge not in edges:
            edges.append(edge)

    try:
        return ExecutionFlow(nodes=tuple(nodes), edges=tuple(edges))
    except ValueError:
        return None


def filter_flow_by_cited_tools(flow: ExecutionFlow | None, tools: set[str]) -> ExecutionFlow | None:
    """Keep only the steps whose tool still has surviving evidence behind it."""
    if flow is None:
        return None
    kept = tuple(node for node in flow.nodes if node.tool in tools)
    if not kept:
        return None
    declared = {node.id for node in kept}
    edges = tuple(edge for edge in flow.edges if edge.src in declared and edge.dst in declared)
    return ExecutionFlow(nodes=kept, edges=edges)


def render_mermaid(flow: ExecutionFlow | None) -> str:
    """Render a fenced mermaid block, or ``""`` when there is nothing to draw."""
    if flow is None:
        return ""
    ids = {node.id: f"n{index}" for index, node in enumerate(flow.nodes)}
    lines = ["```mermaid", "flowchart TD"]
    lines.extend(f'    {ids[node.id]}["{node.label} ({node.tool})"]' for node in flow.nodes)
    for edge in flow.edges:
        arrow = f'-->|"{edge.label}"|' if edge.label else "-->"
        lines.append(f"    {ids[edge.src]} {arrow} {ids[edge.dst]}")
    lines.append("```")
    return "\n".join(lines)
