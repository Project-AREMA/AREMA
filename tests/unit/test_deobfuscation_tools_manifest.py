import json
import subprocess
from pathlib import Path

import yaml

DOCKERFILE = Path("images/deobfuscation-tools/Dockerfile")
TEMPLATE = Path("deploy/sandbox/10-deobfuscation-tools-template.yaml")
POOL = Path("deploy/sandbox/20-deobfuscation-tools-pool.yaml")
LOCK = Path("images/deobfuscation-tools/requirements.lock")
BUILD_LOCK = Path("images/deobfuscation-tools/build-requirements.lock")
HEALTHCHECK = Path("images/deobfuscation-tools/healthcheck.sh")
SMOKE = Path("images/deobfuscation-tools/smoke-test.sh")
DE4DOT_WRAPPER = Path("images/deobfuscation-tools/de4dot")
CI_WORKFLOW = Path(".github/workflows/deobfuscation-tools-smoke.yml")
MAKEFILE = Path("Makefile")
ENV_EXAMPLE = Path(".env.example")


def _docs() -> tuple[dict, dict]:
    return yaml.safe_load(TEMPLATE.read_text()), yaml.safe_load(POOL.read_text())


def test_image_pins_real_upstream_tools_and_both_architectures() -> None:
    text = DOCKERFILE.read_text()
    assert "flare-floss==3.1.1" in LOCK.read_text()
    assert "UPX_VERSION=5.2.0" in text
    assert "3db5d3294707439db97866feab8d75d800f028f48481a40547411824da4288a1" in text
    assert "55d48a61e8ffd17152db871c855376cba7f08e830b37799d0947a16dff8ec36c" in text
    assert "TARGETARCH" in text
    assert (
        text.count(
            "FROM python:3.11-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba"
        )
        == 2
    )
    assert "snapshot.debian.org/archive/debian/" in text
    assert "DEBIAN_SNAPSHOT=20260726T023453Z" in text


def test_runtime_image_excludes_build_compiler() -> None:
    text = DOCKERFILE.read_text()
    runtime_stage = text.rsplit("FROM python:3.11-slim-bookworm", maxsplit=1)[1]
    assert "COPY --from=builder" in runtime_stage
    assert "g++" not in runtime_stage


def test_dockerfile_pins_and_checksum_verifies_de4dot_cex() -> None:
    text = DOCKERFILE.read_text()
    assert "DE4DOT_VERSION=4.0.0" in text
    assert "c726cbd18b894ca63b7f6a565c6c86ef512b96e68119c6502cdf64a51f6a1c78" in text
    assert "ViRb3/de4dot-cex/releases/download" in text
    assert "sha256sum -c" in text.split("DE4DOT_SHA256", maxsplit=1)[1]


def test_dockerfile_installs_mono_runtime() -> None:
    text = DOCKERFILE.read_text()
    assert "mono-runtime" in text
    assert "libmono-system-windows-forms4.0-cil" in text


def test_dockerfile_copies_de4dot_wrapper_into_runtime_image() -> None:
    text = DOCKERFILE.read_text()
    runtime_stage = text.rsplit("FROM python:3.11-slim-bookworm", maxsplit=1)[1]
    assert "COPY --chmod=0755 de4dot /usr/local/bin/de4dot" in runtime_stage
    # mono-runtime must be installed where it will actually run: the final image,
    # not just the discarded builder stage.
    assert "mono-runtime" in runtime_stage


def test_runtime_image_ships_unzip_for_native_lib_extraction() -> None:
    # Regression (found by the in-cluster APK smoke test): extract_android_native_libs
    # shells `unzip -Z1`/`unzip -p` in this pod. unzip was only in the builder stage,
    # so the tool exited 127 (command not found) in the runtime image and the .so
    # fan-out could never extract native libraries.
    text = DOCKERFILE.read_text()
    runtime_stage = text.rsplit("FROM python:3.11-slim-bookworm", maxsplit=1)[1]
    assert "unzip" in runtime_stage


def test_runtime_stage_mono_install_is_snapshot_pinned() -> None:
    # The runtime-stage apt-get for mono-runtime must resolve against the same
    # frozen Debian snapshot as the builder stage, not the live bookworm
    # mirror, so a rebuild can't silently pull a different mono version.
    text = DOCKERFILE.read_text()
    runtime_stage = text.rsplit("FROM python:3.11-slim-bookworm", maxsplit=1)[1]
    mono_index = runtime_stage.index("apt-get install -y --no-install-recommends mono-runtime")
    preamble = runtime_stage[:mono_index]
    assert "ARG DEBIAN_SNAPSHOT" in preamble
    assert "snapshot.debian.org/archive/debian/" in preamble
    update_index = preamble.rindex("apt-get update")
    sources_index = preamble.rindex("sources.list")
    assert sources_index < update_index < mono_index


def test_de4dot_wrapper_execs_de4dot_under_mono() -> None:
    text = DE4DOT_WRAPPER.read_text()
    assert text.startswith("#!/bin/sh")
    assert 'exec mono /opt/de4dot/de4dot.exe "$@"' in text


def test_fully_hashed_floss_lock_is_consumed_by_builder() -> None:
    lock = LOCK.read_text()
    assert "flare-floss==3.1.1" in lock
    requirements = [
        line for line in lock.splitlines() if "==" in line and not line.startswith((" ", "#"))
    ]
    assert requirements
    for requirement in requirements:
        package_block = lock[lock.index(requirement) :]
        next_requirement = next(
            (
                line
                for line in package_block.splitlines()[1:]
                if "==" in line and not line.startswith((" ", "#"))
            ),
            None,
        )
        if next_requirement:
            package_block = package_block[: package_block.index(next_requirement)]
        assert "--hash=sha256:" in package_block, requirement

    dockerfile = DOCKERFILE.read_text()
    assert "requirements.lock /tmp/" in dockerfile
    assert "pip install --require-hashes -r /tmp/requirements.lock" in dockerfile


def test_fully_hashed_pep517_build_lock_closes_isolated_build_inputs() -> None:
    lock = BUILD_LOCK.read_text()
    for package in ("packaging", "setuptools", "pybind11", "wheel"):
        assert f"{package}==" in lock
    requirements = [
        line for line in lock.splitlines() if "==" in line and not line.startswith((" ", "#"))
    ]
    assert requirements
    for requirement in requirements:
        package_block = lock[lock.index(requirement) :]
        assert "--hash=sha256:" in package_block

    dockerfile = DOCKERFILE.read_text()
    assert "COPY build-requirements.lock" in dockerfile
    assert "pip install --require-hashes -r /tmp/build-requirements.lock" in dockerfile
    assert "--no-build-isolation" in dockerfile
    # The build-only isolated inputs are uninstalled so they never linger in the
    # runtime image. ``packaging`` is deliberately excluded from the uninstall:
    # it is ALSO a runtime dependency of androguard (via matplotlib) and is
    # pinned in requirements.lock, so removing it would break the runtime import.
    assert "pip uninstall -y pybind11 setuptools wheel" in dockerfile
    assert "packaging==" in LOCK.read_text()


def test_healthcheck_requires_exact_tool_versions() -> None:
    text = HEALTHCHECK.read_text()
    assert '"5.2.0"' in text
    assert '"3.1.1"' in text
    assert "upx --version" in text
    assert "floss --version" in text


def test_healthcheck_invokes_de4dot() -> None:
    text = HEALTHCHECK.read_text()
    assert "de4dot 2>&1 | grep -c 'de4dot'" in text
    assert 'test "${de4dot_ok}" -ge 1' in text


def test_deobfuscation_make_targets_fail_on_kind_or_readiness_errors() -> None:
    makefile = MAKEFILE.read_text()
    build_target = makefile.split("sandbox-build-images:", maxsplit=1)[1].split(
        "sandbox-up:", maxsplit=1
    )[0]
    up_target = makefile.split("sandbox-up:", maxsplit=1)[1].split("sandbox-down:", maxsplit=1)[0]
    # The image load and the readiness waits must fail loud, never `|| true`, so a
    # kind-load or readiness failure surfaces instead of being masked.
    assert "kind load docker-image arema-deobfuscation-tools:0.1.0" in build_target
    assert "|| true" not in build_target
    assert "arema.dev/pool=deobfuscation-tools" in up_target
    assert "kubectl wait --for=condition=Ready" in up_target
    assert "|| true" not in up_target


def test_smoke_script_and_native_ci_cover_runtime_contract() -> None:
    smoke = SMOKE.read_text()
    for expected in (
        "upx --version",
        "floss --version",
        "deobfuscation-tools-healthcheck",
        "id -u",
        "id -g",
        "binary2strings",
        "pip check",
        "command -v g++",
        "command -v cc",
        "command -v c++",
        "command -v make",
        "command -v cmake",
        "dpkg-query",
        "*-dev",
        r"\${Status}",
    ):
        assert expected in smoke

    workflow = CI_WORKFLOW.read_text()
    assert "ubuntu-24.04" in workflow
    assert "ubuntu-24.04-arm" in workflow
    assert "docker build -t arema-deobfuscation-tools:0.1.0 images/deobfuscation-tools" in workflow
    assert "images/deobfuscation-tools/smoke-test.sh" in workflow
    assert "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4" in workflow


def test_pool_map_and_make_dry_run_wire_deobfuscation_pool() -> None:
    settings = {
        line.split("=", maxsplit=1)[0]: line.split("=", maxsplit=1)[1]
        for line in ENV_EXAMPLE.read_text().splitlines()
        if line.startswith("AREMA_") and "=" in line
    }
    assert (
        json.loads(settings["AREMA_SANDBOX_POOL_MAP"])["deobfuscation-tools"]
        == "deobfuscation-tools-pool"
    )

    image = subprocess.run(
        ["make", "-n", "sandbox-build-images"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    up = subprocess.run(
        ["make", "-n", "sandbox-up"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "docker build -t arema-deobfuscation-tools:0.1.0" in image
    assert "kind load docker-image arema-deobfuscation-tools:0.1.0" in image
    assert "kubectl apply -f deploy/sandbox/10-deobfuscation-tools-template.yaml" in up
    assert "kubectl apply -f deploy/sandbox/20-deobfuscation-tools-pool.yaml" in up
    assert "kubectl wait --for=condition=Ready pod -l arema.dev/pool=deobfuscation-tools" in up
    assert "|| true" not in up


def test_template_is_hardened_exec_driven_and_bounded() -> None:
    template, pool = _docs()
    pod = template["spec"]["podTemplate"]["spec"]
    container = pod["containers"][0]
    assert container["image"] == "arema-deobfuscation-tools:0.1.0"
    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert container["securityContext"]["runAsUser"] == 1000
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert "exec" in container["readinessProbe"]
    assert "ports" not in container
    assert container["resources"]["requests"] == {"cpu": "500m", "memory": "1Gi"}
    assert container["resources"]["limits"] == {"cpu": "2", "memory": "4Gi"}
    assert pool["spec"]["replicas"] == 1
    assert pool["spec"]["sandboxTemplateRef"]["name"] == template["metadata"]["name"]


def test_deny_all_egress_and_fast_fail_dns() -> None:
    """Malware-analysis pool hardening: the agent-sandbox framework's DEFAULT
    managed policy ALLOWS internet egress, so declaring empty egress+ingress makes
    the managed policy deny both (the agent reaches the pod kubelet-mediated, so
    deny-all ingress is unaffected). DNS fails fast so a hostname lookup fails
    instantly instead of hanging on the deny-all egress DROP. See LESSONS_LEARNED
    #15 and the analysis-workbench template."""
    doc = yaml.safe_load(TEMPLATE.read_text())
    pol = doc["spec"]["networkPolicy"]
    assert pol["egress"] == [] and pol["ingress"] == []
    pod = doc["spec"]["podTemplate"]["spec"]
    assert pod["dnsPolicy"] == "None"
    opts = {o["name"]: o["value"] for o in pod["dnsConfig"]["options"]}
    assert opts["attempts"] == "1" and opts["timeout"] == "1"
