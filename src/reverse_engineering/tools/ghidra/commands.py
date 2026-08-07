"""The curated ghidra-rpc command table: a spec-driven function-tool surface.

Each :class:`CliCommandSpec` is one entry that :func:`build_ghidra_toolset`
turns into a typed AREMA function tool. Adding a tool is one spec line; the
shape generalizes to any future sandbox-CLI engine (promote to a neutral
``SandboxCliToolset`` when a second engine appears — rule of three).
"""

from __future__ import annotations

from dataclasses import dataclass

from arema.registry.descriptors import OutputPolicy


@dataclass(frozen=True, slots=True)
class CliCommandSpec:
    """One ghidra-rpc subcommand wrapped as a function tool.

    ``arg_template`` uses ``{placeholder}`` markers naming the tool's parameters
    (e.g. ``"{function}"``); the builder turns those markers into the tool's
    keyword parameters so the LLM sees a typed surface. The binary name is never
    a parameter — it is injected from the case state stashed by
    :func:`prepare_ghidra`.
    """

    name: str
    description: str
    subcommand: str
    output_policy: OutputPolicy
    arg_template: str = ""
    extra_flags: str = ""
    result_field: str | None = None
    # Client-side kubectl exec deadline for this command. Fast list/metadata
    # commands finish well within the default; whole-binary decompilation
    # (search-decompiled) needs a larger budget and pins its own server-side
    # ``--socket-timeout`` strictly below this so ghidra-rpc terminates the
    # sweep gracefully before the client would hard-kill it.
    timeout_seconds: int = 300


GHIDRA_COMMANDS: tuple[CliCommandSpec, ...] = (
    CliCommandSpec(
        name="ghidra_metadata",
        description="Get binary metadata (arch, bits, format) from Ghidra.",
        subcommand="metadata",
        output_policy=OutputPolicy(max_chars=4_000),
    ),
    CliCommandSpec(
        name="ghidra_list_functions",
        description="List functions in the binary (paginated to the first 100).",
        subcommand="functions",
        output_policy=OutputPolicy(max_chars=8_000, max_list_items=50),
        arg_template="--limit 100",
    ),
    CliCommandSpec(
        name="ghidra_decompile",
        description="Decompile a function to Ghidra pseudo-C. Pass a name or hex address.",
        subcommand="decompile",
        output_policy=OutputPolicy(max_chars=10_000),
        arg_template="{function}",
        # ghidra-rpc returns ok:true with c_code="" when the decompiler cannot
        # run (e.g. a missing native binary). Treat that as degraded, not success.
        result_field="c_code",
    ),
    CliCommandSpec(
        name="ghidra_search_decompiled",
        description=(
            "Regex-search decompiled C across ALL functions in one call. Use to find "
            "crypto constants, API-call patterns, or vulnerability sinks."
        ),
        subcommand="search-decompiled",
        output_policy=OutputPolicy(max_chars=10_000, max_list_items=30),
        arg_template="{pattern}",
        # Whole-binary decompilation sweep: give ghidra-rpc a bounded server-side
        # deadline (600s) that returns within the client kubectl budget (660s),
        # mirroring the prepare_ghidra 600/660 load contract. Without this the
        # server default (--socket-timeout 1800s) outlives the client, so kubectl
        # hard-kills a legitimately-running sweep at the 300s default.
        extra_flags="--socket-timeout 600",
        timeout_seconds=660,
    ),
    CliCommandSpec(
        name="ghidra_basic_blocks",
        description="Get the basic blocks (CFG) of a function for control-flow analysis.",
        subcommand="basic-blocks",
        output_policy=OutputPolicy(max_chars=8_000),
        arg_template="{function}",
    ),
    CliCommandSpec(
        name="ghidra_xrefs_to",
        description="Find cross-references TO a symbol or address (who calls this).",
        subcommand="xrefs-to",
        output_policy=OutputPolicy(max_chars=6_000, max_list_items=30),
        arg_template="{target}",
    ),
    CliCommandSpec(
        name="ghidra_imports",
        description="List imported symbols.",
        subcommand="imports",
        output_policy=OutputPolicy(max_chars=6_000, max_list_items=50),
    ),
    CliCommandSpec(
        name="ghidra_strings",
        description="Search defined strings (substring match).",
        subcommand="strings",
        output_policy=OutputPolicy(max_chars=6_000, max_list_items=30),
        arg_template="{query}",
    ),
    CliCommandSpec(
        name="ghidra_pcode",
        description=(
            "Get Ghidra P-code IR for a function (high-SSA form). Fallback when "
            "decompile produces bad output, common on ARM Thumb / obfuscated code."
        ),
        subcommand="pcode",
        output_policy=OutputPolicy(max_chars=10_000),
        arg_template="{function}",
        extra_flags="--high",
        # --high pcode comes from the decompiler; empty ops means it never ran.
        result_field="ops",
    ),
)
