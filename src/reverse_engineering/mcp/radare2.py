"""The radare2_mcp McpServerDescriptor: read-only r2mcp over streamable HTTP.

The transport targets a ``kubectl port-forward pod/<name> 8765:8765`` (opened by
``prepare_sandbox`` in Task 5) so ADK reaches the in-pod r2mcp server at
localhost:8765/mcp. ``required=False`` honours the resilience contract: a down or
unreachable server degrades to an empty toolset instead of aborting the run.

The ``tool_allowlist`` pins the read-only analysis surface the agent may call.
r2mcp's default mode already omits the dangerous ``run_*`` tools, so this is
defense in depth: if a future image change exposes a mutating/exec tool it will
not reach the agent.
"""

from __future__ import annotations

from arema.registry.descriptors import McpServerDescriptor, StreamableHttpTransport

RADARE2_MCP = McpServerDescriptor(
    id="radare2_mcp",
    transport=StreamableHttpTransport(
        url="http://127.0.0.1:8765/mcp",
        # The read_timeout must accommodate the longest tool call: r2 `analyze`
        # (auto-analysis `aaa`) on a large binary (e.g. Apache httpd at 1.7 MB
        # takes ~2-4 min; a 10 MB binary can take 5-10 min). A timeout that is
        # too short fires mid-analysis, the MCP connection drops, ADK reconnects
        # with a new session, and r2mcp loses its per-session open_file state —
        # every subsequent call fails with "Use the open_file method." 600s
        # (10 min) is the bound that worked for B.2; the 120s reduction in B.3
        # was an overcorrection for a hang whose real root cause was the
        # strict_tool_calls bug (now fixed by json_repair).
        read_timeout=600.0,
    ),
    required=False,
    tool_allowlist=(
        # file/analysis lifecycle (required to open + analyze a binary)
        "open_file",
        "analyze",
        "close_file",
        # function/disasm/decompile surface
        "list_functions",
        "list_functions_tree",
        "decompile_function",
        "disassemble",
        "disassemble_function",
        "use_decompiler",
        "list_decompilers",
        "get_function_prototype",
        "show_function_details",
        "get_current_address",
        # symbols / imports / exports / refs
        "list_imports",
        "list_exports",
        "list_symbols",
        "list_libraries",
        "xrefs_to",
        "lookup_address",
        "lookup_export",
        "lookup_symbol",
        # binary metadata + strings + sections/entrypoints/classes
        "show_info",
        "list_strings",
        "list_all_strings",
        "list_sections",
        "list_entrypoints",
        "list_classes",
        "list_methods",
        # misc read-only helpers
        "list_files",
        "hexdump",
        "calculate",
    ),
)
