"""Structural unit tests for the radare2-mcp sandbox manifest (Spec B, B.1).

Validates deploy/sandbox/10-radare2-mcp-template.yaml WITHOUT a cluster: the
SandboxTemplate must use the v1beta1 ``spec.podTemplate.spec`` shape, the r2mcp
container must expose :8765 with tcpSocket probes (httpGet would 401 under auth),
and run non-root as a fixed numeric UID. These fail fast in ``make check`` on a
regression of any of the bugs hit while building B.1.
"""

from __future__ import annotations

from pathlib import Path

import yaml

TEMPLATE_PATH = Path("deploy/sandbox/10-radare2-mcp-template.yaml")
POOL_PATH = Path("deploy/sandbox/20-radare2-mcp-pool.yaml")
EXPECTED_IMAGE = "arema-radare2-mcp:0.1.0"
MCP_PORT = 8765


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
    assert template["metadata"]["name"] == "radare2-mcp-runtime-template"
    assert pool["spec"]["sandboxTemplateRef"]["name"] == "radare2-mcp-runtime-template"  # type: ignore[index]
    assert pool["spec"]["replicas"] >= 1  # type: ignore[index]


def test_container_image_and_port() -> None:
    container = _container()
    assert container["image"] == EXPECTED_IMAGE  # type: ignore[index]
    ports = container["ports"]  # type: ignore[index]
    assert any(p["containerPort"] == MCP_PORT for p in ports)


def test_probes_are_tcp_socket_not_http_get() -> None:
    """httpGet would get 401 (r2mcp gates all requests under -A) and never go Ready;
    tcpSocket just checks :8765 is listening. Robust either way."""
    container = _container()
    for probe_name in ("readinessProbe", "livenessProbe"):
        probe = container[probe_name]  # type: ignore[index]
        assert "tcpSocket" in probe, f"{probe_name} must be tcpSocket (httpGet 401s under auth)"
        assert probe["tcpSocket"]["port"] == MCP_PORT  # type: ignore[index]
        assert "httpGet" not in probe


def test_container_runs_nonroot_fixed_uid() -> None:
    """A named user alone makes kubelet reject creation (CreateContainerConfigError)
    under runAsNonRoot; the UID must be a fixed numeric (1000)."""
    container = _container()
    pod_spec = _template_spec()["podTemplate"]["spec"]  # type: ignore[index]
    assert pod_spec["securityContext"]["runAsNonRoot"] is True  # type: ignore[index]
    assert container["securityContext"]["runAsNonRoot"] is True  # type: ignore[index]
    assert container["securityContext"]["runAsUser"] == 1000  # type: ignore[index]
    assert "ALL" in container["securityContext"]["capabilities"]["drop"]  # type: ignore[index]
    assert pod_spec["automountServiceAccountToken"] is False  # type: ignore[index]


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
