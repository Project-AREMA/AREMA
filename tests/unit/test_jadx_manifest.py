"""Structural unit tests for the jadx sandbox manifest.

Validates deploy/sandbox/10-jadx-template.yaml WITHOUT a cluster. jadx is
exec-backed like ghidra-rpc and deobfuscation-tools, so the pod exposes no port
and the readiness probe is an exec probe; mirrors
``test_deobfuscation_tools_manifest.py``.
"""

from __future__ import annotations

from pathlib import Path

import yaml

TEMPLATE_PATH = Path("deploy/sandbox/10-jadx-template.yaml")
POOL_PATH = Path("deploy/sandbox/20-jadx-pool.yaml")
MAKEFILE = Path("Makefile")
ENV_EXAMPLE = Path(".env.example")
EXPECTED_IMAGE = "arema-jadx:0.1.0"


def _template_spec() -> dict[str, object]:
    doc = yaml.safe_load(TEMPLATE_PATH.read_text())
    assert doc["kind"] == "SandboxTemplate"
    return doc["spec"]  # type: ignore[return-value]


def _container() -> dict[str, object]:
    pod_spec = _template_spec()["podTemplate"]["spec"]  # type: ignore[index]
    containers = pod_spec["containers"]  # type: ignore[index]
    assert len(containers) == 1
    return containers[0]  # type: ignore[return-value]


def test_template_uses_v1beta1_podtemplate() -> None:
    spec = _template_spec()
    assert "podTemplate" in spec
    assert "template" not in spec, "use spec.podTemplate.spec, not v1alpha1 spec.template"


def test_pool_ref_matches_template() -> None:
    template = yaml.safe_load(TEMPLATE_PATH.read_text())
    pool = yaml.safe_load(POOL_PATH.read_text())
    assert template["metadata"]["name"] == "jadx-runtime-template"
    assert pool["spec"]["sandboxTemplateRef"]["name"] == "jadx-runtime-template"
    assert pool["spec"]["replicas"] >= 1


def test_pool_label() -> None:
    labels = _template_spec()["podTemplate"]["metadata"]["labels"]  # type: ignore[index]
    assert labels["arema.dev/pool"] == "jadx"


def test_image_and_no_ports() -> None:
    """jadx is driven over kubectl exec, so the pod listens on nothing."""
    container = _container()
    assert container["image"] == EXPECTED_IMAGE
    assert "ports" not in container


def test_exec_readiness_probe() -> None:
    container = _container()
    probe = container["readinessProbe"]  # type: ignore[index]
    assert "exec" in probe, "no socket to probe; exec `jadx --version` instead"
    assert probe["exec"]["command"][0] == "jadx"
    assert "httpGet" not in probe
    assert "tcpSocket" not in probe


def test_memory_limit_clears_heap() -> None:
    """The image sets -Xmx3g; a limit at or below that gets the JVM OOM-killed."""
    limits = _container()["resources"]["limits"]  # type: ignore[index]
    assert limits["memory"] == "4Gi"


def test_deny_all_egress() -> None:
    """jadx analyses live malware offline; mirror the deobfuscation-tools deny-all."""
    network_policy = _template_spec()["networkPolicy"]  # type: ignore[index]
    assert network_policy["egress"] == []
    assert network_policy["ingress"] == []


def test_nonroot() -> None:
    container = _container()
    pod_spec = _template_spec()["podTemplate"]["spec"]  # type: ignore[index]
    assert pod_spec["securityContext"]["runAsNonRoot"] is True
    assert container["securityContext"]["runAsNonRoot"] is True
    assert container["securityContext"]["runAsUser"] == 1000
    assert "ALL" in container["securityContext"]["capabilities"]["drop"]
    assert pod_spec["automountServiceAccountToken"] is False


def test_pool_label_matches_makefile_wait_selector() -> None:
    """The Makefile's sandbox-up waits on the same pool label the template sets."""
    makefile = MAKEFILE.read_text()
    up_target = makefile.split("sandbox-up:", maxsplit=1)[1].split(
        "sandbox-verify-egress:", maxsplit=1
    )[0]
    assert "kubectl apply -f deploy/sandbox/10-jadx-template.yaml" in up_target
    assert "kubectl apply -f deploy/sandbox/20-jadx-pool.yaml" in up_target
    assert "kubectl wait --for=condition=Ready pod -l arema.dev/pool=jadx" in up_target

    build_target = makefile.split("sandbox-build-images:", maxsplit=1)[1].split(
        "sandbox-up:", maxsplit=1
    )[0]
    assert "docker build -t arema-jadx:0.1.0 images/jadx" in build_target
    assert "kind load docker-image arema-jadx:0.1.0" in build_target


def test_env_example_wires_jadx_pool() -> None:
    settings = {
        line.split("=", maxsplit=1)[0]: line.split("=", maxsplit=1)[1]
        for line in ENV_EXAMPLE.read_text().splitlines()
        if line.startswith("AREMA_") and "=" in line
    }
    import json

    pool_map = json.loads(settings["AREMA_SANDBOX_POOL_MAP"])
    assert pool_map["jadx"] == "jadx-pool"
    # The additive change must preserve the existing engine pools.
    assert pool_map["ghidra-rpc"] == "ghidra-rpc-pool"
    assert pool_map["deobfuscation-tools"] == "deobfuscation-tools-pool"
