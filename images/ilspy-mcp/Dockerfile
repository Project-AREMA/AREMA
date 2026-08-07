# ilspy-mcp sandbox image for AREMA (the .NET/CIL decompilation engine).
#
# This is the MANAGED-CODE ENGINE container, the counterpart to radare2-mcp
# (recon) and ghidra-rpc (native deep decompilation). It runs cervonwong/ILSpy-MCP
# in HTTP mode, exposing 27 MCP tools built on ICSharpCode.Decompiler (the engine
# behind ILSpy) that ADK drives via StreamableHTTP over a DIRECT POD PORT-FORWARD
# (kubectl port-forward pod/<name> 3001:3001 -> http://127.0.0.1:3001/mcp),
# exactly like the r2mcp image. The sandbox-router is NOT used for MCP.
#
# Key choices (verified empirically against the v1.2.0 release):
#  - The release ships SELF-CONTAINED binaries, so no .NET SDK/runtime is
#    installed here. `ldd` shows only libc/libstdc++/libm/libgcc -- but .NET
#    dlopen()s ICU at startup and refuses to run without it, and bookworm-slim
#    ships no ICU. Hence libicu72 (the alternative,
#    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1, would degrade string casing and
#    comparison across decompiled identifiers).
#  - The tarball extracts FLAT (./ILSpy.Mcp, ./appsettings.json, ...), not into a
#    directory of its own, so it is extracted with `tar -C /opt/ilspy-mcp`.
#  - HTTP MCP endpoint is /mcp; a bare GET returns 400, which is exactly what
#    AREMA's port-forward readiness probe treats as "application layer is up".
#  - `--transport http` is required; the binary defaults to stdio, which cannot
#    be reached inside a pod whose name is unknown until claim time.
#
# The agent's artifact is copied in by AREMA's prepare_ilspy as
# /app/<sha256>.dll. The .dll extension is MANDATORY, not cosmetic: verified that
# byte-identical assemblies fail with "An error occurred invoking
# 'analyze_assembly'" when the path has no recognised assembly extension.

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# tar is required by `kubectl cp`, which AREMA's prepare_ilspy uses to copy the
# artifact bytes into /app. libicu72 is required by the .NET runtime (see header).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates wget tar libicu72 \
    && rm -rf /var/lib/apt/lists/*

# Install the pinned ILSpy-MCP release, verifying the published checksum.
ARG ILSPY_MCP_VERSION=v1.2.0
ARG ILSPY_MCP_RELEASE=https://github.com/cervonwong/ILSpy-MCP/releases/download
RUN set -eux; \
    case "$(dpkg --print-architecture)" in \
        amd64) asset=ilspy-mcp-linux-x64 ;; \
        arm64) asset=ilspy-mcp-linux-arm64 ;; \
        *) echo "unsupported architecture: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac; \
    wget -q "${ILSPY_MCP_RELEASE}/${ILSPY_MCP_VERSION}/${asset}.tar.gz" -O /tmp/ilspy-mcp.tar.gz; \
    wget -q "${ILSPY_MCP_RELEASE}/${ILSPY_MCP_VERSION}/${asset}.sha256" -O /tmp/ilspy-mcp.sha256; \
    sed "s|${asset}.tar.gz|/tmp/ilspy-mcp.tar.gz|" /tmp/ilspy-mcp.sha256 | sha256sum -c -; \
    mkdir -p /opt/ilspy-mcp; \
    tar xzf /tmp/ilspy-mcp.tar.gz -C /opt/ilspy-mcp; \
    chmod +x /opt/ilspy-mcp/ILSpy.Mcp; \
    rm -f /tmp/ilspy-mcp.tar.gz /tmp/ilspy-mcp.sha256 /opt/ilspy-mcp/ILSpy.Mcp.pdb; \
    /opt/ilspy-mcp/ILSpy.Mcp --help > /dev/null

# Non-root runtime user at a FIXED numeric UID/GID (1000) so kubelet can verify
# runAsNonRoot when the manifest sets runAsUser: 1000 (a named user alone makes
# kubelet reject pod creation with CreateContainerConfigError). Matches the
# radare2-mcp and ghidra-rpc images.
RUN groupadd -r -g 1000 ilspyuser \
    && useradd -r -u 1000 -g 1000 -m -d /home/ilspyuser ilspyuser \
    && mkdir -p /app \
    && chown -R 1000:1000 /app /home/ilspyuser

USER 1000
ENV HOME=/home/ilspyuser
WORKDIR /app
EXPOSE 3001

CMD ["/opt/ilspy-mcp/ILSpy.Mcp", "--transport", "http", "--host", "0.0.0.0", "--port", "3001"]
