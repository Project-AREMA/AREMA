# Shared RE code-execution workbench: Python + radare2 + .NET RE toolchain.
# Exec-driven (no network service); deny-all egress at runtime -- every tool is
# pre-installed and used OFFLINE. Add a tool = extend the matching block + rebuild.
FROM debian:12-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    DOTNET_ROOT=/usr/share/dotnet NUGET_XMLDOC_MODE=skip

# --- build-only tooling: curl/unzip to fetch archives, plus libicu so the .NET
# SDK can actually run here (dotnet tool install aborts without ICU). This whole
# stage is discarded; the runtime stage installs its own libicu72 separately. ---
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip libicu72 \
    && rm -rf /var/lib/apt/lists/*

# --- .NET SDK (for dotnet-script + ilspycmd; agent writes C# offline) ---
# Pinned; confirm the channel/version + arch asset at live build (Task 5).
# Installed as a self-contained directory tree (not an apt package), so unlike
# mono-runtime below it can be carried into the runtime stage with a plain COPY.
ARG DOTNET_CHANNEL=8.0
# dotnet-install.sh requires bash (uses `set -o pipefail`); Debian's /bin/sh is
# dash, so invoke it explicitly with bash (present in the base image).
RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && bash /tmp/dotnet-install.sh --channel "${DOTNET_CHANNEL}" --install-dir /usr/share/dotnet \
    && ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet \
    && rm -f /tmp/dotnet-install.sh

# dotnet-script (C# scripting) + ilspycmd (managed decompile/verify), restored now
# so runtime is offline. Pin exact versions; confirm at live build.
RUN dotnet tool install --tool-path /opt/dotnet-tools dotnet-script --version 1.6.0 \
    && dotnet tool install --tool-path /opt/dotnet-tools ilspycmd --version 8.2.0.7535

# --- dnlib as an offline local DLL (referenced via #r "/opt/dnlib/dnlib.dll") ---
ARG DNLIB_VERSION=4.4.0
RUN curl -fsSL "https://www.nuget.org/api/v2/package/dnlib/${DNLIB_VERSION}" -o /tmp/dnlib.zip \
    && mkdir -p /opt/dnlib && unzip -q -j /tmp/dnlib.zip 'lib/net45/dnlib.dll' -d /opt/dnlib \
    && rm -f /tmp/dnlib.zip

# --- de4dot-cex (managed deobfuscator, runs under mono) ---
ARG DE4DOT_VERSION=4.0.0
ARG DE4DOT_SHA256=c726cbd18b894ca63b7f6a565c6c86ef512b96e68119c6502cdf64a51f6a1c78
RUN curl -fsSL "https://github.com/ViRb3/de4dot-cex/releases/download/v${DE4DOT_VERSION}/de4dot-cex.zip" -o /tmp/de4dot.zip \
    && echo "${DE4DOT_SHA256}  /tmp/de4dot.zip" | sha256sum -c - \
    && unzip -q /tmp/de4dot.zip -d /opt/de4dot && rm -f /tmp/de4dot.zip

# --- radare2 (native triage + scripting engine) ---
# radare2 was dropped from Debian bookworm's repos (no installation candidate),
# so pin the official upstream release .deb and verify it, rather than relying on
# it floating in apt. Arch-selected so the image builds on both amd64 and arm64;
# installed (with its deps) in the runtime stage below.
ARG RADARE2_VERSION=5.9.8
RUN arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) sha=6c6dec5f769d7b7ac35c9d5ebf850be66c4650874dfb4319d3ede26d20ae5c39 ;; \
      arm64) sha=f0bde63f54e88f8b3b15966db33611a0b6a5f7cc270887f2798d0142bc1385a5 ;; \
      *) echo "unsupported build arch for radare2: $arch" >&2; exit 1 ;; \
    esac; \
    mkdir -p /opt/radare2; \
    curl -fsSL "https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2_${RADARE2_VERSION}_${arch}.deb" \
      -o /opt/radare2/radare2.deb; \
    echo "${sha}  /opt/radare2/radare2.deb" | sha256sum -c -

# --- arc4: a C-extension RC4 library with no prebuilt arm64 wheel on PyPI.
# Compile it into a wheel here (the builder has a toolchain) so the lean runtime
# stage installs it from the wheel without carrying gcc/python3-dev itself. ---
ARG ARC4_VERSION=0.4.0
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc python3-dev python3-pip \
    && pip3 wheel --no-deps "arc4==${ARC4_VERSION}" -w /opt/wheels \
    && rm -rf /var/lib/apt/lists/*

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive PIP_NO_CACHE_DIR=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    DOTNET_ROOT=/usr/share/dotnet NUGET_XMLDOC_MODE=skip \
    DOTNET_ROLL_FORWARD=Major
# ^ ilspycmd 8.2 targets .NET 6 but this image ships only the .NET 8 runtime;
# Major roll-forward lets it (and any net6-targeted tool) run on net8. dotnet-script
# already targets net8, so this is a no-op for it.

# --- system packages (native RE + .NET runtime deps) ---
# Downloader tooling used only to fetch/extract archives stays behind in the
# discarded builder stage above and is deliberately absent from this list.
# radare2 comes from the pinned upstream .deb staged by the builder (it is no
# longer in Debian bookworm); installing it in this same RUN lets apt resolve
# its runtime dependencies from the still-present package index.
COPY --from=builder /opt/radare2/radare2.deb /tmp/radare2.deb
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv ca-certificates \
      mono-runtime libmono-system-windows-forms4.0-cil libicu72 \
      /tmp/radare2.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/radare2.deb

# .NET SDK, dotnet-script/ilspycmd, dnlib, and de4dot are all self-contained
# file trees produced by the builder stage above -- carried over with COPY
# --from=builder rather than re-downloaded. mono-runtime above is the one
# exception: it's an apt package and, unlike these, cannot be carried across
# stages with a single COPY, so it is installed directly in this stage.
COPY --from=builder /usr/share/dotnet /usr/share/dotnet
COPY --from=builder /opt/dotnet-tools /opt/dotnet-tools
COPY --from=builder /opt/dnlib /opt/dnlib
COPY --from=builder /opt/de4dot /opt/de4dot
RUN ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet \
    && ln -s /opt/dotnet-tools/dotnet-script /usr/local/bin/dotnet-script \
    && ln -s /opt/dotnet-tools/ilspycmd /usr/local/bin/ilspycmd \
    && mkdir -p /opt/nuget-offline \
    && mv /opt/dotnet-tools/dotnet-script /opt/dotnet-tools/dotnet-script.real
# Shadow dotnet-script with an offline wrapper (--sources /opt/nuget-offline) so
# every invocation -- via PATH (/opt/dotnet-tools) or the /usr/local/bin symlink
# above -- restores offline in the deny-all-egress sandbox. The prewarm below
# calls dotnet-script.real directly so build-time restore can still reach nuget.org.
COPY --chmod=0755 dotnet-script-wrapper /opt/dotnet-tools/dotnet-script
COPY --chmod=0755 de4dot-wrapper /usr/local/bin/de4dot
# Fixed, reviewed script for the DETERMINISTIC dnlib metadata round-trip (the
# first-pass .NET recovery, run by the dnlib_roundtrip tool via dotnet-script --
# no model in the loop).
COPY dnlib-roundtrip.csx /opt/dnlib-roundtrip.csx

# --- Python RE / binary-analysis libraries ---
# arc4 resolves from the locally-built wheel staged by the builder (no compiler
# in this stage); everything else pulls prebuilt wheels from PyPI at build time.
COPY --from=builder /opt/wheels /opt/wheels
RUN pip3 install --break-system-packages --find-links /opt/wheels \
      r2pipe==1.9.4 pefile==2024.8.26 lief==0.15.1 die-python==0.4.0 \
      yara-python==4.5.1 pycryptodome==3.21.0 arc4==0.4.0 aplib==0.6 \
      capstone==5.0.3 pyelftools==0.31 macholib==1.16.3 \
    && rm -rf /opt/wheels

COPY healthcheck.sh /usr/local/bin/analysis-workbench-healthcheck
RUN chmod +x /usr/local/bin/analysis-workbench-healthcheck

RUN useradd --uid 1000 --create-home workbench && mkdir -p /work && chown workbench /work
# Pre-warm the global NuGet cache as UID 1000 so first agent run needs no network.
# Use dotnet-script.real (not the offline wrapper) so this build-time restore can
# reach nuget.org and populate /home/workbench/.nuget/packages, which the runtime
# wrapper then restores from offline.
USER 1000
ENV HOME=/home/workbench PATH=/opt/dotnet-tools:${PATH}
COPY --chown=1000 dnlib-smoke.csx /home/workbench/dnlib-smoke.csx
RUN /opt/dotnet-tools/dotnet-script.real /home/workbench/dnlib-smoke.csx
# In the hardened sandbox the root filesystem is read-only with only /work
# writable, but dotnet-script must write a NuGet.Config + compile new scripts
# under $HOME. Redirect every writable .NET path to /work while still restoring
# from the prewarmed (read-only) package cache baked above -- this keeps the
# managed toolchain fully OFFLINE in the sandbox (compiles under /work, restores
# from the image cache, never reaches nuget.org). Set AFTER the prewarm so the
# build still populates the cache under /home/workbench.
ENV HOME=/work \
    NUGET_PACKAGES=/home/workbench/.nuget/packages \
    TMPDIR=/work
WORKDIR /work
ENTRYPOINT ["sleep", "infinity"]
