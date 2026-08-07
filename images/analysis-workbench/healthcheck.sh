#!/bin/sh
set -e
radare2 -v >/dev/null
python3 -c "import r2pipe, pefile, lief, die, yara, Crypto, arc4, aplib"
python3 -c "import r2pipe, pefile, lief, capstone, macholib"
command -v de4dot >/dev/null
test -f /opt/dnlib/dnlib.dll
# Actually RUN the managed tools, not just `command -v` them: a target/runtime
# mismatch (e.g. a .NET 6-targeted tool on a .NET 8-only runtime) only surfaces on
# invocation, so exercising them here catches it at build time rather than mid-analysis.
mono --version >/dev/null
dotnet --version >/dev/null
dotnet-script --version >/dev/null
ilspycmd --version >/dev/null
