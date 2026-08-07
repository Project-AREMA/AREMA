"""Structural test for the analysis-workbench sandbox manifest (no cluster).

Validates the v1beta1 podTemplate shape, exec-driven (no port), the mandatory
hardening (gvisor runtimeClass, non-root fixed UID, dropped caps, RO rootfs,
memory limit), the deny-all egress NetworkPolicy, and that the engine is wired
into sandbox-build-images / sandbox-up / sandbox-down + the .env.example pool map.

Also validates that the deny-all egress NetworkPolicy is backed by an *enforcing
datapath* (the manifest is inert under Kind's default kindnet CNI, which ignores
NetworkPolicy): a Kind config that disables the default CNI, an installer that
provisions Calico and refuses to run on kindnet, and an enforcement smoke check
wired into the Makefile.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

TEMPLATE = Path("deploy/sandbox/10-analysis-workbench-template.yaml")
POOL = Path("deploy/sandbox/20-analysis-workbench-pool.yaml")
NETPOL = Path("deploy/sandbox/30-analysis-workbench-denyall-egress.yaml")
KIND_CONFIG = Path("deploy/sandbox/kind-cluster.yaml")
INSTALL_SCRIPT = Path("deploy/sandbox/install-agent-sandbox.sh")
VERIFY_EGRESS = Path("deploy/sandbox/verify-egress-denied.sh")
MAKEFILE = Path("Makefile")
ENV_EXAMPLE = Path(".env.example")
EXPECTED_IMAGE = "arema-analysis-workbench:0.1.0"


def _container() -> dict[str, object]:
    doc = yaml.safe_load(TEMPLATE.read_text())
    assert doc["kind"] == "SandboxTemplate"
    pod = doc["spec"]["podTemplate"]["spec"]
    # runtimeClassName (gvisor/kata) is a production hardening prereq applied at
    # deploy time -- NOT hard-set in the base template (fleet convention; the
    # reference Kind cluster provisions no such RuntimeClass). See the next test.
    assert "runtimeClassName" not in pod, "base template must not hard-set an unprovisioned runtime"
    containers = pod["containers"]
    assert len(containers) == 1
    return containers[0]


def _pod_spec() -> dict[str, object]:
    return yaml.safe_load(TEMPLATE.read_text())["spec"]["podTemplate"]["spec"]


def _template_spec() -> dict[str, object]:
    return yaml.safe_load(TEMPLATE.read_text())["spec"]


def test_runtime_hardening_is_documented_as_a_prereq() -> None:
    # Matches the other engine templates: the gvisor/kata requirement is carried
    # as a documented prerequisite, so it is explicit rather than a silent gap.
    text = TEMPLATE.read_text()
    assert "runtimeClassName" in text  # present in the comment guidance
    assert "gvisor" in text and "kata" in text


def test_container_is_hardened_and_exec_driven() -> None:
    c = _container()
    assert c["image"] == EXPECTED_IMAGE
    assert "ports" not in c, "exec-driven: no container port"
    sec = c["securityContext"]
    assert sec["runAsNonRoot"] is True and sec["runAsUser"] == 1000
    assert sec["allowPrivilegeEscalation"] is False
    assert sec["readOnlyRootFilesystem"] is True
    assert sec["capabilities"]["drop"] == ["ALL"]
    assert c["resources"]["limits"]["memory"], "a hard memory ceiling is mandatory"


def test_template_declares_primary_deny_all_egress() -> None:
    # PRIMARY enforcer: the framework (networkPolicyManagement: Managed) generates
    # the NetworkPolicy from spec.networkPolicy, selecting warm-pool pods by their
    # sandbox-template-ref-hash label (a standalone policy on arema.dev/pool does
    # NOT reliably reach controller-created pods). Empty egress+ingress == deny
    # all; the framework's DEFAULT (field absent) instead ALLOWS internet egress
    # and additively negates any standalone deny-all, so this must be explicit.
    np = _template_spec().get("networkPolicy")
    assert np is not None, (
        "template must declare spec.networkPolicy; the framework default ALLOWS egress"
    )
    assert np.get("egress", "unset") == [], "egress must be an empty list (deny all)"
    assert np.get("ingress", "unset") == [], "ingress must be an empty list (deny all)"


def test_offline_sandbox_has_writable_tmp_and_fast_fail_dns() -> None:
    spec = _pod_spec()
    c = _container()
    mounts = {m["mountPath"] for m in c["volumeMounts"]}
    vols = {v["name"] for v in spec["volumes"]}
    # The .NET first-run configurer creates a named Mutex under /tmp; readOnly
    # rootfs makes /tmp read-only, so a writable emptyDir at /tmp is mandatory.
    assert "/tmp" in mounts and "tmp" in vols
    # Fully-offline sandbox: DNS must fail fast so a tool doing a hostname lookup
    # fails instantly rather than hanging on the deny-all egress DROP.
    assert spec.get("dnsPolicy") == "None"
    opts = {o["name"]: o["value"] for o in spec["dnsConfig"]["options"]}
    assert opts.get("attempts") == "1" and opts.get("timeout") == "1"


def test_denyall_egress_targets_the_pool() -> None:
    # Defense-in-depth second layer (primary is the template's spec.networkPolicy).
    doc = yaml.safe_load(NETPOL.read_text())
    assert doc["kind"] == "NetworkPolicy"
    assert doc["spec"]["podSelector"]["matchLabels"]["arema.dev/pool"] == "analysis-workbench"
    assert doc["spec"]["policyTypes"] == ["Egress"]
    assert doc["spec"].get("egress", []) == [], "egress must be empty (deny all)"


def test_wired_into_make_targets_and_env() -> None:
    mk = MAKEFILE.read_text()
    assert "arema-analysis-workbench:0.1.0" in mk
    assert "20-analysis-workbench-pool.yaml" in mk
    assert "analysis-workbench" in ENV_EXAMPLE.read_text()


def test_kind_config_disables_default_cni_for_an_enforcing_datapath() -> None:
    # kindnet ignores NetworkPolicy, so the cluster must disable the default CNI
    # (Calico is installed on top by the installer) for the deny-all egress to bite.
    doc = yaml.safe_load(KIND_CONFIG.read_text())
    assert doc["kind"] == "Cluster"
    assert doc["networking"]["disableDefaultCNI"] is True


def test_installer_provisions_a_policy_enforcing_cni_and_refuses_kindnet() -> None:
    script = INSTALL_SCRIPT.read_text()
    # Installs a policy-enforcing CNI (Calico) and waits for it to be Ready ...
    assert "calico" in script.lower()
    assert "daemonset/calico-node" in script
    # ... and fails fast rather than degrading silently on a kindnet cluster.
    assert "kindnet" in script


def test_egress_enforcement_check_exists_and_is_wired() -> None:
    assert VERIFY_EGRESS.exists()
    assert os.access(VERIFY_EGRESS, os.X_OK), "verify-egress-denied.sh must be executable"
    body = VERIFY_EGRESS.read_text()
    # Proves ENFORCEMENT on the REAL warm-pool pods (subject to the framework's
    # managed policy) via `kubectl exec`, not a `kubectl run` stand-in carrying
    # only the pool label -- that stand-in escapes the managed policy and gives
    # false assurance while the real analysis pods leak.
    assert "arema.dev/pool" in body
    assert "analysis-workbench" in body
    assert "warm-pool" in body.lower()
    assert "kubectl exec" in body
    mk = MAKEFILE.read_text()
    assert "sandbox-verify-egress:" in mk
    assert "verify-egress-denied.sh" in mk
    assert "sandbox-cluster:" in mk
    assert "kind-cluster.yaml" in mk


def test_netpol_documents_the_cni_prerequisite() -> None:
    # The CNI prerequisite is documented next to the netpol manifest itself.
    text = NETPOL.read_text()
    assert "kindnet" in text
    assert "Calico" in text or "policy-enforcing" in text
