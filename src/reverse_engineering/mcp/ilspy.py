"""The ilspy_mcp McpServerDescriptor: read-only ILSpy-MCP over streamable HTTP.

The transport targets a ``kubectl port-forward pod/<name> 3001:3001`` (opened by
``prepare_ilspy``) so ADK reaches the in-pod ILSpy-MCP server at
localhost:3001/mcp. ``required=False`` honours the resilience contract: a down or
unreachable server degrades to an empty toolset instead of aborting the run.

The ``tool_allowlist`` pins the read-only analysis surface. ILSpy-MCP exposes 27
tools; three are withheld:

- ``export_project`` writes a whole decompiled .csproj tree to disk inside the
  pod — a bulk write with no analysis value the per-type tools do not already
  give.
- ``load_assembly_directory`` and ``resolve_type`` operate on a *directory* of
  assemblies. A case holds exactly one artifact, so multi-assembly resolution has
  nothing to resolve against and would only widen the reachable filesystem.

Everything else is read-only introspection over the single loaded assembly.
"""

from __future__ import annotations

from arema.registry.descriptors import McpServerDescriptor, StreamableHttpTransport

ILSPY_MCP = McpServerDescriptor(
    id="ilspy_mcp",
    transport=StreamableHttpTransport(
        url="http://127.0.0.1:3001/mcp",
        # Matched to radare2_mcp's bound and overridden at composition time from
        # AREMA_MCP_READ_TIMEOUT. Decompilation is far quicker than r2's `analyze`
        # (ILSpy's own per-operation timeout defaults to 30s), but a large
        # assembly's type listing still benefits from the same generous ceiling.
        read_timeout=600.0,
    ),
    required=False,
    tool_allowlist=(
        # assembly overview + metadata
        "analyze_assembly",
        "get_assembly_metadata",
        "get_assembly_attributes",
        "list_embedded_resources",
        "extract_resource",
        # type discovery
        "list_assembly_types",
        "list_namespace_types",
        "get_type_members",
        "find_type_hierarchy",
        "find_implementors",
        "find_extension_methods",
        "find_compiler_generated_types",
        "search_members_by_name",
        # decompilation + IL
        "decompile_type",
        "decompile_method",
        "disassemble_type",
        "disassemble_method",
        # cross-references
        "find_usages",
        "find_dependencies",
        "find_instantiations",
        # attributes + literal search
        "get_type_attributes",
        "get_member_attributes",
        "search_strings",
        "search_constants",
    ),
)
