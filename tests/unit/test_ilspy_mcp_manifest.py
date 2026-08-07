"""Structural unit tests for the ilspy-mcp sandbox manifest.

Validates deploy/sandbox/10-ilspy-mcp-template.yaml WITHOUT a cluster: the
SandboxTemplate must use the v1beta1 ``spec.podTemplate.spec`` shape, the
ilspy-mcp container must expose :3001 with tcpSocket probes (the server has no
health endpoint and answers a bare GET /mcp with 400), and run non-root as a
fixed numeric UID. Also checks the engine is wired into the consolidated
``sandbox-build-images`` / ``sandbox-up`` / ``sandbox-down`` make targets and the
``.env.example`` pool map. Mirrors ``test_ghidra_rpc_manifest.py``.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import yaml

TEMPLATE_PATH = Path("deploy/sandbox/10-ilspy-mcp-template.yaml")
POOL_PATH = Path("deploy/sandbox/20-ilspy-mcp-pool.yaml")
ENV_EXAMPLE = Path(".env.example")
EXPECTED_IMAGE = "arema-ilspy-mcp:0.1.0"
MCP_PORT = 3001


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


def test_template_name_matches_pool_ref() -> None:
    template = yaml.safe_load(TEMPLATE_PATH.read_text())
    pool = yaml.safe_load(POOL_PATH.read_text())
    assert template["metadata"]["name"] == "ilspy-mcp-runtime-template"
    assert pool["spec"]["sandboxTemplateRef"]["name"] == "ilspy-mcp-runtime-template"  # type: ignore[index]
    assert pool["spec"]["replicas"] >= 1  # type: ignore[index]


def test_pool_label_matches_makefile_wait_selector() -> None:
    """`make sandbox-up` waits on arema.dev/pool=ilspy-mcp."""
    labels = _template_spec()["podTemplate"]["metadata"]["labels"]  # type: ignore[index]
    assert labels["arema.dev/pool"] == "ilspy-mcp"


def test_container_image_and_port() -> None:
    container = _container()
    assert container["image"] == EXPECTED_IMAGE  # type: ignore[index]
    ports = container["ports"]  # type: ignore[index]
    assert any(p["containerPort"] == MCP_PORT for p in ports)


def test_probes_are_tcp_socket_not_http_get() -> None:
    container = _container()
    for probe_name in ("readinessProbe", "livenessProbe"):
        probe = container[probe_name]  # type: ignore[index]
        assert "tcpSocket" in probe, f"{probe_name} must be tcpSocket (GET /mcp answers 400)"
        assert probe["tcpSocket"]["port"] == MCP_PORT  # type: ignore[index]
        assert "httpGet" not in probe


def test_container_runs_nonroot_fixed_uid() -> None:
    container = _container()
    pod_spec = _template_spec()["podTemplate"]["spec"]  # type: ignore[index]
    assert pod_spec["securityContext"]["runAsNonRoot"] is True  # type: ignore[index]
    assert container["securityContext"]["runAsNonRoot"] is True  # type: ignore[index]
    assert container["securityContext"]["runAsUser"] == 1000  # type: ignore[index]
    assert "ALL" in container["securityContext"]["capabilities"]["drop"]  # type: ignore[index]
    assert pod_spec["automountServiceAccountToken"] is False  # type: ignore[index]


def test_pool_map_and_make_dry_run_wire_the_ilspy_pool() -> None:
    settings = {
        line.split("=", maxsplit=1)[0]: line.split("=", maxsplit=1)[1]
        for line in ENV_EXAMPLE.read_text().splitlines()
        if line.startswith("AREMA_") and "=" in line
    }
    assert json.loads(settings["AREMA_SANDBOX_POOL_MAP"])["ilspy-mcp"] == "ilspy-mcp-pool"

    build = subprocess.run(
        ["make", "-n", "sandbox-build-images"], check=True, capture_output=True, text=True
    ).stdout
    up = subprocess.run(
        ["make", "-n", "sandbox-up"], check=True, capture_output=True, text=True
    ).stdout
    down = subprocess.run(
        ["make", "-n", "sandbox-down"], check=True, capture_output=True, text=True
    ).stdout

    assert "docker build -t arema-ilspy-mcp:0.1.0 images/ilspy-mcp" in build
    assert "kind load docker-image arema-ilspy-mcp:0.1.0" in build
    assert "kubectl apply -f deploy/sandbox/10-ilspy-mcp-template.yaml" in up
    assert "kubectl apply -f deploy/sandbox/20-ilspy-mcp-pool.yaml" in up
    assert "kubectl wait --for=condition=Ready pod -l arema.dev/pool=ilspy-mcp" in up
    assert "|| true" not in up  # readiness waits fail loud, never masked
    assert "kubectl delete -f deploy/sandbox/20-ilspy-mcp-pool.yaml" in down
    assert "kubectl delete -f deploy/sandbox/10-ilspy-mcp-template.yaml" in down


def test_deny_all_egress_and_fast_fail_dns() -> None:
    """Malware-analysis pool hardening: the agent-sandbox framework's DEFAULT
    managed policy ALLOWS internet egress, so declaring empty egress+ingress makes
    the managed policy deny both (the agent reaches the pod kubelet-mediated, so
    deny-all ingress is unaffected). DNS fails fast so a hostname lookup fails
    instantly instead of hanging on the deny-all egress DROP. See LESSONS_LEARNED
    #15 and the analysis-workbench template."""
    doc = yaml.safe_load(TEMPLATE_PATH.read_text())
    pol = doc["spec"]["networkPolicy"]
    assert pol["egress"] == [] and pol["ingress"] == []
    pod = doc["spec"]["podTemplate"]["spec"]
    assert pod["dnsPolicy"] == "None"
    opts = {o["name"]: o["value"] for o in pod["dnsConfig"]["options"]}
    assert opts["attempts"] == "1" and opts["timeout"] == "1"
