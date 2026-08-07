# ghidra-rpc command reference (maintainer doc)

A condensed reference for the `ghidra-rpc` CLI surface wrapped as AREMA
function tools. The agent (`deep_decompile`) never invokes `ghidra-rpc`
directly — it calls the `ghidra_*` function tools below, which shell into the
sandbox pod via `kubectl_exec`. This doc is for maintainers, not agent
instructions.

## The 9 curated commands

Each row is one `CliCommandSpec` in `tools/ghidra/commands.py`. The tool name
is what the LLM sees; the `ghidra-rpc` subcommand is what is executed.

| Tool                  | subcommand          | params              | output                                  |
|-----------------------|---------------------|---------------------|-----------------------------------------|
| `ghidra_metadata`     | `metadata`          | (none)              | arch, bits, format                      |
| `ghidra_list_functions` | `functions`       | `--limit 100`       | paginated function inventory (first 100)|
| `ghidra_decompile`    | `decompile`         | `{function}`        | Ghidra pseudo-C for one function        |
| `ghidra_search_decompiled` | `search-decompiled` | `{pattern}`    | regex hits across ALL decompiled C      |
| `ghidra_basic_blocks` | `basic-blocks`      | `{function}`        | CFG basic blocks of one function        |
| `ghidra_xrefs_to`     | `xrefs-to`          | `{target}`          | cross-references TO a symbol/address    |
| `ghidra_imports`      | `imports`           | (none)              | imported symbols                        |
| `ghidra_strings`      | `strings`           | `{query}`           | defined strings (substring match)       |
| `ghidra_pcode`        | `pcode {function} --high` | `{function}`  | P-code IR (high-SSA form)               |

## Output shape (every tool, including errors)

All tools return a JSON dict, never raw text:

- success: `{"success": true, "output": "<ghidra-rpc stdout>"}`
- failure: `{"success": false, "error": "<message>", "tool": "<name>"}`

If ghidra was not prepared for the case, the tool short-circuits with
`{"success": false, "error": "ghidra not prepared for this case"}` — there is
no binary loaded yet.

## Key gotchas

- **Binary name is never a tool parameter.** `prepare_ghidra` runs
  `ghidra-rpc load` on the artifact path; that returns a `short_name`
  (e.g. `ls`), which is stashed in case state and injected into every command.
  The `{function}`/`{pattern}`/`{query}`/`{target}` params are the only
  agent-controlled inputs.
- **`ghidra_decompile` accepts a name OR a hex address.** A symbol name
  (`main`) and a hex address (`0x401200`) are both valid for `{function}`.
- **`{function}`/`{pattern}` values are never shell-interpreted.** They are
  inserted as single argv tokens (`_tokenize_arg_template`), so regex specials
  and spaces are safe. Only developer-controlled flags are whitespace-split.
- **`ghidra_pcode` always adds `--high`** to request the high-SSA form — this
  is the fallback when `ghidra_decompile` produces bad output (ARM Thumb,
  obfuscated code).
