"""Structural unit tests for the ghidra-rpc sandbox manifest (Spec B, B.4)."""

from __future__ import annotations

from pathlib import Path

import yaml

TEMPLATE_PATH = Path("deploy/sandbox/10-ghidra-rpc-template.yaml")
POOL_PATH = Path("deploy/sandbox/20-ghidra-rpc-pool.yaml")
EXPECTED_IMAGE = "arema-ghidra-rpc:0.1.0"


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
    assert "template" not in spec


def test_template_name_matches_pool_ref() -> None:
    template = yaml.safe_load(TEMPLATE_PATH.read_text())
    pool = yaml.safe_load(POOL_PATH.read_text())
    assert template["metadata"]["name"] == "ghidra-rpc-runtime-template"
    assert pool["spec"]["sandboxTemplateRef"]["name"] == "ghidra-rpc-runtime-template"  # type: ignore[index]
    assert pool["spec"]["replicas"] >= 1  # type: ignore[index]


def test_container_image() -> None:
    container = _container()
    assert container["image"] == EXPECTED_IMAGE  # type: ignore[index]


def test_container_runs_nonroot_fixed_uid() -> None:
    container = _container()
    pod_spec = _template_spec()["podTemplate"]["spec"]  # type: ignore[index]
    assert pod_spec["securityContext"]["runAsNonRoot"] is True  # type: ignore[index]
    assert container["securityContext"]["runAsNonRoot"] is True  # type: ignore[index]
    assert container["securityContext"]["runAsUser"] == 1000  # type: ignore[index]
    assert "ALL" in container["securityContext"]["capabilities"]["drop"]  # type: ignore[index]
    assert pod_spec["automountServiceAccountToken"] is False  # type: ignore[index]


def test_readiness_probe_is_exec_no_port() -> None:
    """The ghidra pod is exec-driven (kubectl exec), not HTTP. The readiness
    probe must be an exec probe, and no container ports should be declared."""
    container = _container()
    probe = container["readinessProbe"]  # type: ignore[index]
    assert "exec" in probe, "readinessProbe must be exec (the pod is kubectl-exec-driven)"
    assert "tcpSocket" not in probe
    assert "httpGet" not in probe
    assert "ports" not in container, "an exec-driven pod should declare no container ports"


def test_no_memory_limit_so_the_decompiler_can_grow() -> None:
    """Ghidra's decompiler (JVM heap + a native subprocess spawned per function)
    OOM-kills (exit 137) under a fixed memory limit on large binaries. The
    container must carry no memory limit; a memory request keeps it schedulable."""
    container = _container()
    resources = container["resources"]  # type: ignore[index]
    assert "memory" not in resources.get("limits", {}), (
        "ghidra-rpc must NOT set a memory limit: a fixed cap OOM-kills the native "
        "decompiler on binaries with many functions (see LESSONS_LEARNED #14)"
    )
    assert "memory" in resources.get("requests", {}), (
        "keep a memory request so the pod stays Burstable and schedulable"
    )


def test_jvm_heap_is_set_explicitly_not_left_to_cgroup_ergonomic() -> None:
    """Without an explicit -Xmx, JDK 21 derives the heap from the cgroup limit
    (MaxRAMPercentage=25%), leaving Ghidra on a ~1Gi heap that starves the
    decompiler. Pin a generous heap via _JAVA_OPTIONS (final JVM precedence)."""
    container = _container()
    env = {e["name"]: e["value"] for e in container.get("env", [])}  # type: ignore[index]
    assert "_JAVA_OPTIONS" in env, "the JVM heap must be pinned, not cgroup-derived"
    assert "-Xmx" in env["_JAVA_OPTIONS"], "_JAVA_OPTIONS must set an explicit max heap"


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
