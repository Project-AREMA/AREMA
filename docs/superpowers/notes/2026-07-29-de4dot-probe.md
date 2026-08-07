# de4dot-cex probe (Task 1) — expected behavior, to confirm at live build (Task 7)

This environment has no Docker/Kubernetes, so de4dot could not be run under
`mono` here. What follows was established by downloading the pinned release
asset and inspecting it directly (checksum computed locally, CLI usage
cross-referenced against public de4dot documentation, and the console
message strings extracted from the shipped assemblies) — **not** by
executing the tool. Task 7's live build must confirm every "confirm live"
item below and adjust the Task 4/6 constants if reality differs.

## Release pin

- Repo: [`ViRb3/de4dot-cex`](https://github.com/ViRb3/de4dot-cex) (a de4dot
  fork with full vanilla ConfuserEx support — broadest obfuscator coverage).
  Archived/read-only since 2022-12-08; last and only tagged release is
  `v4.0.0` (published 2020-01-10), so there is nothing newer to pin.
- Release asset: `de4dot-cex.zip`, downloaded from
  `https://github.com/ViRb3/de4dot-cex/releases/download/v4.0.0/de4dot-cex.zip`
  (size 2,829,058 bytes).
- SHA-256 (computed locally with `shasum -a 256` against the downloaded
  asset, not taken from a search result):
  `c726cbd18b894ca63b7f6a565c6c86ef512b96e68119c6502cdf64a51f6a1c78`
- Zip layout (verified by extracting): **flat**, not nested in a
  subdirectory — `de4dot.exe`, `de4dot-x64.exe`, and a `bin/` directory with
  `de4dot.cui.dll`, `de4dot.code.dll`, `dnlib.dll`, etc. all sit directly
  under the extraction root. So `unzip -q de4dot-cex.zip -d /opt/de4dot`
  puts the entry point at `/opt/de4dot/de4dot.exe`, matching the wrapper:
  `exec mono /opt/de4dot/de4dot.exe "$@"`.

## (a) Invocation

`de4dot <input> -o <output>` is the documented single-file form (de4dot's
CLI is unchanged from upstream de4dot in this fork): `de4dot file.dll -o
output.dll`. No other flag is required for a basic run — de4dot
auto-detects the obfuscator and deobfuscates in one pass. (If `-o` is
omitted, de4dot defaults to writing `<input>-cleaned.<ext>` next to the
input instead, which is why the tool always passes `-o` explicitly.)
**Confirm live:** run `de4dot <input> -o <output>` against a plain (never
obfuscated) .NET assembly and against the `1595d92f…` sample to see the
real stdout/exit code.

## (b) Stdout line naming a detected obfuscator

Confirmed by extracting the UTF-16LE string table of the shipped
`bin/de4dot.cui.dll`: the format string is literally

```
Detected {0} ({1})
```

i.e. at runtime this renders as `Detected <Name> (<Version>)` — e.g.
`Detected SmartAssembly (...)` — matching the plan's `_DETECTED_PATTERN`
(`r"Detected\s+(?P<name>.+?)\s*(?:\(|v\d|$)"`). **Confirm live:** capture the
exact wording de4dot prints for the `1595d92f…` sample (SmartAssembly /
Dotfuscator per the plan) so Task 4's pattern is validated against a real
string, not just the format literal.

## (c) Output file when no obfuscator is detected

Confirmed by extracting the UTF-16LE string table of `bin/de4dot.code.dll`:
the literal message is

```
Could not detect obfuscator!
```

Public de4dot documentation (FAQ / usage guides) does not state whether an
output file is still written in this case. **Working assumption for Task
4/6** (per the plan): when there is no `Detected` line in stdout, treat the
sample as `no_obfuscator` and do **not** trust/admit any output file de4dot
may or may not have written — `applicable: False`, no artifact advance,
regardless of what's on disk. **Confirm live:** run de4dot against a sample
with no recognized obfuscator (e.g. a plain, never-obfuscated .NET DLL) and
check both stdout for the absence of `Detected` and whether `-o`'s target
path exists afterward, so the "writes nothing" assumption above is verified
rather than asserted.

## (d) `--version` / build string for the healthcheck

No `--version` (or similar) CLI flag was found in the decompiled string
tables, and the CLI usage docs found do not mention one. What IS confirmed
from the shipped assemblies' embedded version metadata:
`AssemblyVersion 3.1.41592.3405` (de4dot's own core-library version, as
built into this de4dot-cex v4.0.0 release — distinct from the GitHub
release tag `v4.0.0` itself). de4dot's classic startup banner (per public
screenshots/blog posts, e.g. "de4dot vX.Y.Z.W" followed by
`Copyright (C) 2011-2015 de4dot@gmail.com`, the latter literal string is
present in both `de4dot.exe` and `de4dot.cui.dll`) is presumed to print this
version on every invocation, including a bare `de4dot` with no arguments —
which is why `healthcheck.sh`'s check only asserts the banner contains the
substring `de4dot` (`de4dot 2>&1 | grep -c 'de4dot'`) rather than a specific
version number, unlike the exact-match `upx --version` / `floss --version`
checks. **Confirm live:** run bare `de4dot` (no args) and record the exact
banner text; if it reliably includes `3.1.41592.3405` (or another stable
build string), consider tightening the healthcheck to an exact match like
the upx/floss checks.

## Sources consulted

- https://github.com/ViRb3/de4dot-cex/releases/tag/v4.0.0 (release metadata
  via `gh api repos/ViRb3/de4dot-cex/releases/tags/v4.0.0`)
- https://github.com/de4dot/de4dot/wiki/FAQ
- https://deepwiki.com/de4dot/de4dot/1.1-installation-and-usage
- Local inspection: `shasum -a 256` on the downloaded asset; `unzip -l`
  the layout; UTF-16LE string extraction from `de4dot.exe`,
  `bin/de4dot.cui.dll`, `bin/de4dot.code.dll`.
