# ghidra-rpc sandbox image for AREMA (Spec B, B.4).
#
# Single container: Ghidra 11.4.x + JDK 21 + ghidra-rpc (cellebrite-labs). The pod
# stays warm (sleep infinity); AREMA's prepare_ghidra starts the headless
# ghidra-rpc daemon, copies the artifact in (kubectl cp), and loads the binary;
# the ghidra_* tools then drive the CLI via raw kubectl exec (mirrors B.2's
# kubectl-cp pattern). There is no python-runtime playground /execute endpoint.
#
# Base: eclipse-temurin:21-jdk — provides JDK 21 (Ghidra 11.4+ requirement) with
# JAVA_HOME already set (/opt/java/openjdk). Debian Bookworm only ships JDK 17;
# Ghidra 11.4 rejects JDK 17 at launch (LaunchSupport "unsupported java version").
#
# Version pairing (VERIFIED): ghidra-rpc declares pyghidra>=2.2.1 with NO upper
# bound, so pip would otherwise pull pyghidra 3.x which targets Ghidra 12 and
# refuses a Ghidra 11 install at startup. pyghidra 2.2.x is the Ghidra 11.4.x
# line, so we pin pyghidra==2.2.1 explicitly.
#
# ghidra-rpc is NOT published on PyPI; it is installed from its git source
# (hatchling build). The Ghidra release asset embeds a release DATE in its name
# (ghidra_<ver>_PUBLIC_<YYYYMMDD>.zip) that cannot be derived from the version,
# so the date is an explicit ARG.
#
# Native decompiler for linux_arm_64: Ghidra 11.4.1 ships the native decompiler
# binary only for linux_x86_64 / mac / win -- NOT linux_arm_64. The sandbox runs
# on arm64 nodes; without the native, Ghidra's Decompiler cannot instantiate and
# `decompile` silently returns empty C with ok:true (the decompiler never runs).
# On aarch64 build hosts the Dockerfile builds the missing native from Ghidra's
# bundled C++ source ("Building Native Components") and purges the build
# toolchain afterward (the standalone `decompile` binary was verified to run
# without g++/bison/flex/make/binutils-dev installed). On x86_64 hosts the step
# is a no-op (the shipped linux_x86_64 binary is used).

FROM eclipse-temurin:21-jdk

ENV DEBIAN_FRONTEND=noninteractive

# tar (kubectl cp) + wget/unzip (Ghidra download) + python3/pip (ghidra-rpc) + git.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates wget unzip tar python3 python3-pip git \
    && rm -rf /var/lib/apt/lists/*

# Download + extract Ghidra 11.4.1 to /opt/ghidra (symlink for a stable path).
ARG GHIDRA_VERSION=11.4.1
ARG GHIDRA_DATE=20250731
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && ln -s "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra \
    && rm /tmp/ghidra.zip

# Build the linux_arm_64 decompiler native when building on aarch64 (no-op on
# x86_64, which uses the binary shipped in the release). See header note.
RUN if [ "$(uname -m)" = "aarch64" ]; then \
        apt-get update \
        && apt-get install -y --no-install-recommends g++ bison flex make binutils-dev \
        && cd "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC/Ghidra/Features/Decompiler/src/decompile/cpp" \
        && make -j"$(nproc)" ghidra_opt ARCH=aarch64 OSDIR=linux_arm_64 ARCH_TYPE= \
        && mkdir -p "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC/Ghidra/Features/Decompiler/os/linux_arm_64" \
        && cp ghidra_opt "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC/Ghidra/Features/Decompiler/os/linux_arm_64/decompile" \
        && chmod +x "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC/Ghidra/Features/Decompiler/os/linux_arm_64/decompile" \
        && apt-get purge -y g++ bison flex make binutils-dev \
        && apt-get autoremove -y \
        && rm -rf /var/lib/apt/lists/* \
                  "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC/Ghidra/Features/Decompiler/src/decompile/cpp/ghi_opt" \
                  "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC/Ghidra/Features/Decompiler/src/decompile/cpp/com_opt" ; \
    fi

ENV GHIDRA_INSTALL_DIR=/opt/ghidra
# JAVA_HOME is already set by the eclipse-temurin base image (/opt/java/openjdk).

# Install ghidra-rpc (cellebrite-labs) from git source, PINNED to v0.2.0 for
# reproducibility. Pin pyghidra==2.2.1 FIRST so pip does not upgrade it to the
# Ghidra-12-only 3.x line.
ARG GHIDRA_RPC_REF=v0.2.0
RUN pip3 install --break-system-packages "pyghidra==2.2.1" \
    && git clone --depth 1 --branch "${GHIDRA_RPC_REF}" https://github.com/cellebrite-labs/ghidra-rpc.git /tmp/ghidra-rpc \
    && pip3 install --break-system-packages /tmp/ghidra-rpc \
    && rm -rf /tmp/ghidra-rpc \
    && ghidra-rpc --version

# Non-root runtime user at a FIXED numeric UID/GID (1000) so kubelet can verify
# runAsNonRoot when the manifest sets runAsUser: 1000. Idempotent: the
# eclipse-temurin base (Ubuntu) may already have a user at UID 1000.
RUN (groupadd -r -g 1000 guser || true) \
    && (useradd -r -u 1000 -g 1000 -m -d /home/guser guser || true) \
    && mkdir -p /app /home/guser \
    && chown -R 1000:1000 /app /home/guser

USER 1000
ENV HOME=/home/guser
WORKDIR /app

# The pod stays warm (sleep); the ghidra-rpc daemon is started on-demand by
# AREMA's prepare_ghidra tool (kubectl exec ... ghidra-rpc start --headless).
CMD ["sleep", "infinity"]
