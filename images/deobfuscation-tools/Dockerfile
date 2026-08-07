# Declared before the first FROM so both stages pin the same Debian snapshot
# from a single source of truth (each stage re-declares the bare ARG below to
# pull this value into its own scope, per Docker's per-stage ARG rules).
ARG DEBIAN_SNAPSHOT=20260726T023453Z

FROM python:3.11-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba AS builder

ENV DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
ARG UPX_VERSION=5.2.0
ARG UPX_AMD64_SHA256=3db5d3294707439db97866feab8d75d800f028f48481a40547411824da4288a1
ARG UPX_ARM64_SHA256=55d48a61e8ffd17152db871c855376cba7f08e830b37799d0947a16dff8ec36c
ARG DEBIAN_SNAPSHOT

RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf 'deb https://snapshot.debian.org/archive/debian/%s/ bookworm main\n' "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl g++ unzip xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
      amd64) upx_arch=amd64; upx_sha="${UPX_AMD64_SHA256}" ;; \
      arm64) upx_arch=arm64; upx_sha="${UPX_ARM64_SHA256}" ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && archive="upx-${UPX_VERSION}-${upx_arch}_linux.tar.xz" \
    && curl -fsSL "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/${archive}" -o "/tmp/${archive}" \
    && echo "${upx_sha}  /tmp/${archive}" | sha256sum -c - \
    && tar -xJf "/tmp/${archive}" -C /tmp \
    && install -m 0755 "/tmp/upx-${UPX_VERSION}-${upx_arch}_linux/upx" /usr/local/bin/upx \
    && rm -rf "/tmp/${archive}" "/tmp/upx-${UPX_VERSION}-${upx_arch}_linux"

# de4dot (managed-code deobfuscator) runs under mono. Pinned + checksum-verified,
# mirroring the UPX install above. The de4dot-cex fork is used for its broader
# obfuscator coverage (full vanilla ConfuserEx support). mono-runtime itself is
# installed in the runtime stage below (it must be present when the container
# runs, not just here, and is not something a single COPY can carry across
# stages the way the static upx binary is).
ARG DE4DOT_VERSION=4.0.0
ARG DE4DOT_SHA256=c726cbd18b894ca63b7f6a565c6c86ef512b96e68119c6502cdf64a51f6a1c78
RUN curl -fsSL "https://github.com/ViRb3/de4dot-cex/releases/download/v${DE4DOT_VERSION}/de4dot-cex.zip" -o /tmp/de4dot.zip \
    && echo "${DE4DOT_SHA256}  /tmp/de4dot.zip" | sha256sum -c - \
    && unzip -q /tmp/de4dot.zip -d /opt/de4dot \
    && rm -f /tmp/de4dot.zip

COPY build-requirements.lock requirements.lock /tmp/

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --require-hashes -r /tmp/build-requirements.lock --no-cache-dir \
    && /opt/venv/bin/pip install --require-hashes -r /tmp/requirements.lock --no-build-isolation --no-cache-dir \
    && /opt/venv/bin/pip uninstall -y pybind11 setuptools wheel \
    && upx --version \
    && /opt/venv/bin/floss --version \
    && /opt/venv/bin/python -c "import androguard"

FROM python:3.11-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba

ARG DEBIAN_SNAPSHOT

COPY --from=builder /usr/local/bin/upx /usr/local/bin/upx
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /tmp/requirements.lock /opt/runtime-requirements.lock
COPY --from=builder /opt/de4dot /opt/de4dot

# mono-runtime is de4dot's execution engine; it must live in the runtime image
# itself (unlike the static upx binary above, apt packages cannot be carried
# over from the builder stage with a single COPY). Re-apply the same snapshot
# pin used by the builder stage so this apt-get resolves against a frozen
# mirror instead of the live bookworm archive.
ENV DEBIAN_FRONTEND=noninteractive
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf 'deb https://snapshot.debian.org/archive/debian/%s/ bookworm main\n' "${DEBIAN_SNAPSHOT}" > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends mono-runtime libmono-system-windows-forms4.0-cil unzip \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 healthcheck.sh /usr/local/bin/deobfuscation-tools-healthcheck
COPY --chmod=0755 de4dot /usr/local/bin/de4dot

# The in-pod androguard triage entrypoint plus the pure report/packer package it
# imports. The pure package is the SAME source the AREMA unit tests exercise,
# supplied through the ``arema-pure`` named build-context
# (--build-context arema-pure=src/reverse_engineering/tools/android) so there is
# a single source of truth and no in-pod drift -- nothing is copied into this
# image's own build context. It is imported as ``androguard_pure`` off PYTHONPATH.
COPY --chmod=0755 androguard_triage.py /opt/androguard_triage.py
COPY --from=arema-pure . /opt/androguard_pure

RUN groupadd -r -g 1000 deobf \
    && useradd -r -u 1000 -g 1000 -m -d /home/deobf deobf \
    && mkdir -p /work \
    && chown -R 1000:1000 /work /home/deobf

USER 1000
ENV HOME=/home/deobf \
    PATH=/opt/venv/bin:${PATH} \
    PYTHONPATH=/opt
WORKDIR /work
CMD ["sleep", "infinity"]
