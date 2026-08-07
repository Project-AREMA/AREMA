#!/usr/bin/env bash
# Install Kubernetes Agent Sandbox (pinned) + the sandbox router into an existing
# Kind cluster. Implements SANDBOXING.md steps 1 and 5. Idempotent-ish: safe to
# re-run. Set AGENT_SANDBOX_VERSION to override the pin.
set -euo pipefail

AGENT_SANDBOX_VERSION="${AGENT_SANDBOX_VERSION:-v0.5.2}"
CALICO_VERSION="${CALICO_VERSION:-v3.28.2}"
SYSTEM_NS="agent-sandbox-system"
DEMO_NS="${AREMA_SANDBOX_NAMESPACE:-agent-sandbox-demo}"
ROUTER_IMAGE="sandbox-router:${AGENT_SANDBOX_VERSION}"

# The deny-all egress NetworkPolicy that isolates the analysis-workbench pool is
# only enforced by a policy-enforcing CNI. Kind's default CNI (kindnet) silently
# IGNORES NetworkPolicy, so on a stock cluster the deny-all egress is a no-op and
# a compromised run_python pod keeps a full exfil path. Guarantee an enforcing
# datapath (Calico) here, or fail fast -- never let the control degrade silently.
ensure_policy_enforcing_cni() {
  if kubectl -n kube-system get daemonset kindnet >/dev/null 2>&1; then
    cat >&2 <<'MSG'
!! kindnet (Kind's default CNI) is installed. kindnet does NOT enforce
   NetworkPolicy, so the deny-all egress that isolates the analysis-workbench
   pool would be SILENTLY IGNORED -- a compromised run_python pod would keep a
   full network exfil path. Refusing to proceed on a non-enforcing datapath.

   Recreate the cluster with the default CNI disabled, then re-run:
     kind delete cluster
     make sandbox-cluster     # kind create cluster --config deploy/sandbox/kind-cluster.yaml
     make setup-sandbox
MSG
    exit 1
  fi

  if kubectl -n kube-system get daemonset calico-node >/dev/null 2>&1; then
    echo ">> Policy-enforcing CNI (Calico) already installed."
  else
    echo ">> Installing Calico ${CALICO_VERSION} (policy-enforcing CNI) ..."
    kubectl apply -f \
      "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
  fi

  echo ">> Waiting for Calico + nodes to be Ready ..."
  kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s
  kubectl wait --for=condition=Ready node --all --timeout=300s
}

echo ">> Ensuring a NetworkPolicy-enforcing CNI ..."
ensure_policy_enforcing_cni

echo ">> Applying agent-sandbox ${AGENT_SANDBOX_VERSION} ..."
kubectl apply -f \
  "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AGENT_SANDBOX_VERSION}/sandbox-with-extensions.yaml"

echo ">> Waiting for controller ..."
kubectl wait --for=condition=Ready pod \
  -l app=agent-sandbox-controller -n "${SYSTEM_NS}" --timeout=180s

echo ">> CRDs present:"
kubectl get crds | grep agents.x-k8s.io

echo ">> Ensuring namespace ${DEMO_NS} ..."
kubectl get namespace "${DEMO_NS}" >/dev/null 2>&1 || kubectl create namespace "${DEMO_NS}"

# Build + deploy the sandbox router. REQUIRED for the host->Kind "LocalTunnel"
# path that SandboxClient uses when AREMA runs on your workstation (the only
# mode that works outside a pod). The router is cloned from the pinned
# agent-sandbox release, built, loaded into kind, and applied with the local
# image. v0.5.2's router refuses to start without ROUTER_AUTH_TOKEN; for local
# dev we set ALLOW_UNAUTHENTICATED_ROUTER=true (the router is only reachable via
# localhost port-forward, never exposed externally). Set ROUTER_AUTH_TOKEN
# instead for any non-local deployment.
echo ">> Building + deploying the sandbox router ..."
ASB_CHECKOUT="$(mktemp -d)"
git clone --branch "${AGENT_SANDBOX_VERSION}" --depth 1 \
  https://github.com/kubernetes-sigs/agent-sandbox.git "${ASB_CHECKOUT}/agent-sandbox"
ROUTER_SRC="${ASB_CHECKOUT}/agent-sandbox/clients/python/agentic-sandbox-client/sandbox-router"
docker build -t "${ROUTER_IMAGE}" "${ROUTER_SRC}"
kind load docker-image "${ROUTER_IMAGE}"
# Use the locally loaded image (Never pull) + the dev unauthenticated flag.
sed -e 's|image: .*|image: '"${ROUTER_IMAGE}"'|' \
    -e 's|# imagePullPolicy: Never|imagePullPolicy: Never|' \
    "${ROUTER_SRC}/sandbox_router.yaml" > /tmp/sandbox_router.arema.yaml
kubectl apply -n "${SYSTEM_NS}" -f /tmp/sandbox_router.arema.yaml
kubectl set env deployment/sandbox-router-deployment -n "${SYSTEM_NS}" \
  ALLOW_UNAUTHENTICATED_ROUTER=true
rm -rf "${ASB_CHECKOUT}"

echo ">> Waiting for sandbox router ..."
# Wait only on the current replicaset's pods (ignore terminating old ones).
kubectl rollout status deployment/sandbox-router-deployment -n "${SYSTEM_NS}" --timeout=180s

echo ">> Done. Next: make sandbox-build-images && make sandbox-up"
echo ">>       then: make sandbox-verify-egress   (prove deny-all egress is enforced)"
