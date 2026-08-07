# jadx sandbox image for AREMA (the Java/Android decompilation engine).
#
# This is the MANAGED-JVM ENGINE container, alongside radare2-mcp (recon),
# ghidra-rpc (native), deobfuscation-tools (UPX/FLOSS/de4dot) and ilspy-mcp
# (.NET). Unlike the MCP engines it exposes no port: AREMA's prepare_jadx drives
# the jadx CLI over `kubectl exec`, exactly as it drives ghidra-rpc. The pod
# stays warm with `sleep infinity`.
#
# Why the CLI rather than a jadx MCP server:
#  - zinja-coder/jadx-mcp-server is a bridge to a plugin running inside
#    jadx-GUI (it connects to the plugin on 127.0.0.1:8650) and its tool surface
#    is GUI-oriented (get_selected_text, fetch_current_class, rename_variable).
#    Running Swing under a virtual display in a pod to serve batch analysis is
#    the wrong shape.
#  - Qtty/jadx-mcp-server is genuinely headless but stdio-only, and a stdio
#    server cannot be reached inside a pod whose name is unknown until claim
#    time -- the same reason the stdio ILSpy server was rejected.
#  - The jadx CLI is what NORTH_STAR section 7 specifies for Java/Android, is
#    headless by construction, and needs no listener, so LESSONS_LEARNED #18's
#    MCP bootstrapping constraint does not apply.
#
# jadx reads .apk/.dex/.jar/.aar/.aab directly; no unzip or apktool step is
# needed. It decodes the binary AndroidManifest.xml back to readable XML and
# lays decompiled Java out by package under `sources/`.

FROM eclipse-temurin:21-jre

ENV DEBIAN_FRONTEND=noninteractive

# tar is required by `kubectl cp`, which prepare_jadx uses to copy the artifact
# in. unzip/wget fetch the jadx release. findutils/grep back the read-only tools.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates wget unzip tar findutils grep \
    && rm -rf /var/lib/apt/lists/*

# Install the pinned + checksum-verified jadx release. The archive is a plain
# bin/ + lib/ layout, so it only has to be unzipped and put on PATH. The
# checksum matches upstream release asset jadx-1.5.1.zip; bump both together on
# a version change (a jadx release is immutable, so a mismatch means a corrupt
# or substituted download and the build must fail loud).
ARG JADX_VERSION=1.5.1
ARG JADX_SHA256=12fd966431903b8e15c36e5007f19343475be7d8f2a55f082e7a929eeabc937e
RUN wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -O /tmp/jadx.zip \
    && echo "${JADX_SHA256}  /tmp/jadx.zip" | sha256sum -c - \
    && mkdir -p /opt/jadx \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && rm /tmp/jadx.zip \
    && chmod +x /opt/jadx/bin/jadx \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx

# jadx sizes its heap from the JVM default, which tracks the container memory
# limit; a large APK otherwise dies with OutOfMemoryError partway through.
ENV JAVA_OPTS="-Xmx3g"

# Non-root runtime user at a FIXED numeric UID/GID (1000) so kubelet can verify
# runAsNonRoot when the manifest sets runAsUser: 1000. Idempotent: the
# eclipse-temurin base (Ubuntu) may already have a user at UID 1000.
RUN (groupadd -r -g 1000 jadxuser || true) \
    && (useradd -r -u 1000 -g 1000 -m -d /home/jadxuser jadxuser || true) \
    && mkdir -p /app /home/jadxuser \
    && chown -R 1000:1000 /app /home/jadxuser

USER 1000
ENV HOME=/home/jadxuser
WORKDIR /app

# The pod stays warm; prepare_jadx runs the decompilation on demand via
# `kubectl exec ... jadx -d <out> /app/<sha256>`.
CMD ["sleep", "infinity"]
