#!/usr/bin/env bash
# Enforcement smoke check for the analysis-workbench deny-all egress.
#
# WHY THIS EXISTS. A deny-all egress can be applied yet do NOTHING: Kind's default
# kindnet CNI ignores NetworkPolicy, and -- the trap this script now guards against
# -- the agent-sandbox framework's DEFAULT managed NetworkPolicy for a
# SandboxTemplate ALLOWS egress to the whole internet, additively negating any
# standalone deny-all. Asserting the policy object exists is false assurance.
#
# CRITICAL: the pod under test must be an ACTUAL warm-pool pod. The framework's
# managed NetworkPolicy selects warm-pool pods by their agents.x-k8s.io/
# sandbox-template-ref-hash label; a `kubectl run` pod carrying only the pool
# label is NOT subject to it and would pass while the real analysis pods leak.
# So we probe a live warm-pool pod (subject to the managed policy), not a
# hand-rolled stand-in.
#
# Method (IP literal only -- deny-all blocks DNS too, so never use a hostname):
#   - baseline pod (no policy)      MUST connect  -> proves the node has egress
#   - live warm-pool pod (managed)  MUST be refused -> proves enforcement
#
# Exit codes:
#   0  enforced      (warm-pool egress refused, baseline reachable)
#   1  NOT enforced  (warm-pool pod reached the internet -- the deny-all is a no-op)
#   2  inconclusive  (no warm-pool pod up, no baseline connectivity, or setup failed)
set -euo pipefail

NS="${AREMA_SANDBOX_NAMESPACE:-agent-sandbox-demo}"
IMAGE="${WORKBENCH_IMAGE:-arema-analysis-workbench:0.1.0}"
TARGET_IP="${EGRESS_PROBE_IP:-1.1.1.1}"
TARGET_PORT="${EGRESS_PROBE_PORT:-53}"
POOL_SELECTOR="arema.dev/pool=analysis-workbench"
BASELINE_POD="egress-check-baseline-$$"

PROBE="import socket,sys
try:
    socket.create_connection(('${TARGET_IP}', ${TARGET_PORT}), timeout=5).close()
except OSError:
    sys.exit(1)
sys.exit(0)"

cleanup() {
  kubectl delete pod "${BASELINE_POD}" -n "${NS}" \
    --ignore-not-found --grace-period=0 --force >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo ">> Verifying deny-all egress enforcement in namespace ${NS} ..."

# The live warm-pool pod is what actually runs untrusted code; it is what must be
# isolated. Require one to be present (make sandbox-up), and pick a Running one.
GUARDED_POD="$(kubectl get pods -n "${NS}" \
  -l "${POOL_SELECTOR}" --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [ -z "${GUARDED_POD}" ]; then
  echo "!! No Running analysis-workbench warm-pool pod found; run 'make sandbox-up' first." >&2
  exit 2
fi

echo ">> Baseline pod (no policy) should reach ${TARGET_IP}:${TARGET_PORT} ..."
kubectl run "${BASELINE_POD}" -n "${NS}" \
  --image="${IMAGE}" --image-pull-policy=IfNotPresent --restart=Never \
  --command -- python3 -c "${PROBE}" >/dev/null
for _ in $(seq 1 60); do
  phase="$(kubectl get pod "${BASELINE_POD}" -n "${NS}" \
    -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  case "${phase}" in Succeeded | Failed) break ;; esac
  sleep 2
done
baseline_ec="$(kubectl get pod "${BASELINE_POD}" -n "${NS}" \
  -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null)"
if [ "${baseline_ec}" != "0" ]; then
  echo "!! Baseline pod could NOT reach ${TARGET_IP}:${TARGET_PORT} (exit '${baseline_ec}')." >&2
  echo "   Cannot distinguish policy enforcement from missing node egress; inconclusive." >&2
  exit 2
fi
echo ">> Baseline reachable."

echo ">> Live warm-pool pod ${GUARDED_POD} must be REFUSED ..."
if kubectl exec -n "${NS}" "${GUARDED_POD}" -- python3 -c "${PROBE}"; then
  echo "!! FAIL: warm-pool pod ${GUARDED_POD} reached ${TARGET_IP}:${TARGET_PORT} --" >&2
  echo "   the deny-all egress is NOT enforced on the real analysis pods. Check that" >&2
  echo "   the SandboxTemplate declares spec.networkPolicy (deny egress); the" >&2
  echo "   framework's DEFAULT managed policy ALLOWS internet egress." >&2
  exit 1
fi

echo ">> PASS: warm-pool egress refused; deny-all egress is enforced on the real pods."
exit 0
