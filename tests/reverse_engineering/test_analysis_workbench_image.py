"""Structural unit tests for the analysis-workbench .NET RE toolchain addition.

Task 1 only wires the Dockerfile, wrapper, healthcheck, and dnlib smoke script;
there is no cluster to run against here (the live build + toolchain probe
happen on the user's cluster -- see spec Task 5). These tests assert on the
Dockerfile/wrapper/healthcheck text, mirroring the sibling de4dot addition to
the deobfuscation-tools image (tests/unit/test_deobfuscation_tools_manifest.py).
"""

from __future__ import annotations

from pathlib import Path

DOCKERFILE = Path("images/analysis-workbench/Dockerfile")
WRAPPER = Path("images/analysis-workbench/de4dot-wrapper")
SMOKE = Path("images/analysis-workbench/dnlib-smoke.csx")
HEALTHCHECK = Path("images/analysis-workbench/healthcheck.sh")


def test_dockerfile_installs_mono_runtime_and_a_dotnet_sdk() -> None:
    text = DOCKERFILE.read_text()
    assert "mono-runtime" in text
    assert "libmono-system-windows-forms4.0-cil" in text
    assert "dot.net/v1/dotnet-install.sh" in text
    assert "DOTNET_CHANNEL=8.0" in text


def test_dockerfile_uses_a_builder_stage_for_downloads() -> None:
    # Mirrors images/deobfuscation-tools/Dockerfile: downloader tooling
    # (curl/unzip) and the .NET SDK install/tool-restore machinery live only
    # in a discarded builder stage; the runtime stage copies the resulting
    # file trees over instead of re-downloading them.
    text = DOCKERFILE.read_text()
    assert text.count("FROM debian:12-slim") == 2
    assert "FROM debian:12-slim AS builder" in text


def test_runtime_image_excludes_build_downloader_tooling() -> None:
    text = DOCKERFILE.read_text()
    runtime_stage = text.rsplit("FROM debian:12-slim", maxsplit=1)[1]
    assert "COPY --from=builder /usr/share/dotnet /usr/share/dotnet" in runtime_stage
    assert "COPY --from=builder /opt/dotnet-tools /opt/dotnet-tools" in runtime_stage
    assert "COPY --from=builder /opt/dnlib /opt/dnlib" in runtime_stage
    assert "COPY --from=builder /opt/de4dot /opt/de4dot" in runtime_stage
    assert "curl" not in runtime_stage
    assert "unzip" not in runtime_stage
    # mono-runtime is an apt package, not a downloaded file tree, so it must
    # still be installed directly in the runtime stage (it cannot be carried
    # over from the builder stage with a single COPY).
    assert "mono-runtime" in runtime_stage


def test_dockerfile_pins_and_checksum_verifies_de4dot_cex() -> None:
    text = DOCKERFILE.read_text()
    assert "DE4DOT_VERSION=4.0.0" in text
    assert "c726cbd18b894ca63b7f6a565c6c86ef512b96e68119c6502cdf64a51f6a1c78" in text
    assert "ViRb3/de4dot-cex/releases/download" in text
    assert "sha256sum -c" in text.split("DE4DOT_SHA256", maxsplit=1)[1]


def test_dockerfile_copies_the_de4dot_wrapper() -> None:
    text = DOCKERFILE.read_text()
    assert "COPY --chmod=0755 de4dot-wrapper /usr/local/bin/de4dot" in text


def test_dockerfile_references_dnlib_as_an_offline_local_dll() -> None:
    text = DOCKERFILE.read_text()
    assert '#r "/opt/dnlib/dnlib.dll"' in text
    assert "DNLIB_VERSION=4.4.0" in text
    assert "nuget.org/api/v2/package/dnlib" in text


def test_wrapper_execs_de4dot_under_mono() -> None:
    text = WRAPPER.read_text()
    assert text.startswith("#!/bin/sh")
    assert 'exec mono /opt/de4dot/de4dot.exe "$@"' in text


def test_dnlib_smoke_script_loads_the_local_dll() -> None:
    text = SMOKE.read_text()
    assert text.startswith('#r "/opt/dnlib/dnlib.dll"')
    assert "ModuleDefMD" in text


def test_healthcheck_checks_the_dotnet_re_toolchain() -> None:
    text = HEALTHCHECK.read_text()
    # The managed .NET/mono tools must be actually INVOKED, not merely located
    # with `command -v`: a target/runtime mismatch (e.g. a .NET 6-targeted tool
    # on a .NET 8-only runtime) only surfaces on invocation. ilspycmd in
    # particular targets net6 and needs DOTNET_ROLL_FORWARD to run on net8, so
    # executing it here is what catches that regression at build time.
    assert "mono --version >/dev/null" in text
    assert "dotnet --version >/dev/null" in text
    assert "dotnet-script --version >/dev/null" in text
    assert "ilspycmd --version >/dev/null" in text
    # de4dot runs under mono (exercised above); presence is sufficient for it.
    assert "command -v de4dot >/dev/null" in text
    assert "test -f /opt/dnlib/dnlib.dll" in text
