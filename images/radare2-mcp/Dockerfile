# radare2-mcp sandbox image for AREMA (Spec B, B.1/B.2).
#
# This is the TYPED RADARE2 MCP ENGINE container. It runs the official
# radare2-mcp server in HTTP mode, exposing the curated MCP tool surface
# (open_file, analyze, list_functions, decompile_function, ...) that ADK drives
# via StreamableHTTP over a DIRECT POD PORT-FORWARD (kubectl port-forward
# pod/<name> 8765:8765 -> http://127.0.0.1:8765/mcp). The sandbox-router is NOT
# used for MCP (verified: it consumes Authorization and mangles the body).
#
# Key choices (verified empirically):
#  - r2mcp is built FROM SOURCE via meson -> /usr/local/bin/r2mcp, NOT `r2pm -ci`.
#    `r2pm` installs into a user HOME dir that the non-root runtime UID cannot write
#    (it resolves to /.local/share -> Permission denied). meson install is system-wide.
#  - The HTTP MCP endpoint is /mcp (streamable-http; POST initialize returns the
#    JSON-RPC initialize result). ADK's StreamableHTTPConnectionParams.url must end
#    in /mcp.
#  - DEFAULT mode (no -R): the agent MUST call open_file("/app/<sha256>") then
#    analyze before any listing tool returns data. The `-R` flag strips exactly
#    open_file/analyze/close_file and must NOT be used. The `-r` flag (dangerous
#    run_* tools) is OFF by default; do NOT enable it.
#  - No -A: the port-forward / network is the auth boundary (the router cannot
#    forward Authorization to the pod, so r2mcp bearer auth is unusable through it).
#
# The agent's artifact is copied into /app/<sha256> by AREMA's prepare_sandbox
# (kubectl cp; r2mcp has no upload tool); r2mcp's open_file tool opens it.

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# `tar` is required by `kubectl cp`, which AREMA's prepare_sandbox uses to copy
# the artifact bytes into the shared /app volume (r2mcp has no upload tool).
# (debian:bookworm-slim ships tar as a required package; listing it explicitly
# documents the dependency and survives a base-image swap.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates git build-essential pkg-config meson ninja-build file tar \
    && rm -rf /var/lib/apt/lists/*

# Build radare2 (pinned) into /usr/local so r2mcp can link against the native r2 APIs.
ARG RADARE2_VERSION=6.1.8
RUN git clone --branch "${RADARE2_VERSION}" --depth 1 https://github.com/radareorg/radare2.git /tmp/radare2 \
    && meson setup --prefix=/usr/local --buildtype=release /tmp/radare2/build /tmp/radare2 \
    && meson compile -C /tmp/radare2/build \
    && meson install -C /tmp/radare2/build \
    && ldconfig \
    && r2 -v \
    && rm -rf /tmp/radare2

# Build the radare2-mcp server from source into /usr/local/bin/r2mcp.
RUN git clone --depth 1 https://github.com/radareorg/radare2-mcp.git /tmp/r2mcp \
    && meson setup --prefix=/usr/local /tmp/r2mcp/build /tmp/r2mcp \
    && meson compile -C /tmp/r2mcp/build \
    && meson install -C /tmp/r2mcp/build \
    && rm -rf /tmp/r2mcp \
    && r2mcp -v

# Detect It Easy, for AREMA's deterministic packer pre-validator. It runs here
# rather than in its own pod because prepare_sandbox already claims this pod at
# intake AND has already kubectl cp'd the sample to /app/<sha256>: the scan costs
# one `kubectl exec` with no extra claim and no second copy. Same pin as the
# analysis-workbench image so both carry one DIE version.
#
# --break-system-packages: bookworm marks its python3 as externally managed
# (PEP 668) and pip refuses a system install without it. This is a
# single-purpose container image, not a shared host, so there is no environment
# to protect from.
#
# NOTE: die-python's `database_path` points one level ABOVE the signature root.
# Every caller must pass database=str(die.database_path / "db"); an unqualified
# scan matches nothing and reports Unknown for every packer without erroring.
#
# libglib2.0-0 is the ONLY system library the extension needs (it also pulls
# libpcre2-8-0). Determined with ldd against the installed _die*.so: the wheel
# vendors Qt6 and ICU 73 into die/lib/ and everything else it wants is already
# in the base. Without glib the import fails with
# "libglib-2.0.so.0: cannot open shared object file".
#
# The build-time check scans a real binary rather than only importing, so a
# broken signature database or a non-loading engine fails the build here instead
# of degrading silently at analysis time.
ARG DIE_PYTHON_VERSION=0.4.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip libglib2.0-0 \
    && pip3 install --break-system-packages --no-cache-dir "die-python==${DIE_PYTHON_VERSION}" \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -c "\
import die, json; \
db = die.database_path / 'db'; \
assert db.is_dir(), db; \
out = die.scan_file('/usr/local/bin/r2mcp', die.ScanFlags.ALL_TYPES_SCAN | die.ScanFlags.RESULT_AS_JSON, database=str(db)); \
assert json.loads(out).get('detects'), out"

# Non-root runtime user at a FIXED numeric UID/GID (1000) so kubelet can verify
# runAsNonRoot when the manifest sets runAsUser: 1000 (a named user alone makes
# kubelet reject pod creation with CreateContainerConfigError). 1000 matches the
# python-runtime base image convention.
RUN groupadd -r -g 1000 r2user \
    && useradd -r -u 1000 -g 1000 -m -d /home/r2user r2user \
    && mkdir -p /app \
    && chown -R 1000:1000 /app /home/r2user

USER 1000
ENV HOME=/home/r2user
WORKDIR /app
EXPOSE 8765

# HTTP MCP server on :8765, in DEFAULT mode (no -R, no -r). Verified live that
# the `-R` (read-only) flag strips EXACTLY open_file/analyze/close_file (they
# lack the `R` mode marker), leaving the agent unable to open or analyze a
# binary (every tool returns "Use the open_file method before calling any other
# method"). The agent MUST call open_file("/app/<sha256>") then analyze before
# any listing tool returns data, so -R cannot be used. The safety boundary is
# the `-r` flag (which ENABLES the dangerous run_command/run_javascript/
# run_frida_script EXEC tools) -- it is OFF by default, so default mode exposes
# open_file/analyze + the read-only analysis tools and ZERO run_*/exec tools.
# No -A: the direct pod port-forward / network is the auth boundary for dev.
CMD ["r2mcp", "-H", "0.0.0.0:8765"]
