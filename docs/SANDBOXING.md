The important distinction

Your ADK agent continues running on the host under adk web. Kubernetes pods do not automatically run the ADK reasoning loop.

Instead:

Browser
  ↓
ADK web process on your host
  ↓
ADK agent calls execute_python(...)
  ↓
k8s-agent-sandbox Python client
  ↓
kubectl port-forward → sandbox-router
  ↓
SandboxClaim
  ↓
pre-warmed sandbox pod
  ↓
python3 run.py

For a local Kind cluster, you generally should not use GkeCodeExecutor. That executor is tied to GKE-specific sandbox infrastructure. The open-source Kubernetes Agent Sandbox integration uses SandboxClient as an ordinary ADK tool. The official ADK example follows exactly this pattern.

1. Install Agent Sandbox into your existing Kind cluster

The current Agent Sandbox release is v0.5.2. Pinning the version is preferable to installing from main.

export AGENT_SANDBOX_VERSION=v0.5.2

kubectl apply -f \
  "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AGENT_SANDBOX_VERSION}/sandbox-with-extensions.yaml"

Wait for the controller:

kubectl wait \
  --for=condition=Ready \
  pod \
  -l app=agent-sandbox-controller \
  -n agent-sandbox-system \
  --timeout=180s

Verify the CRDs:

kubectl get crds | grep agents.x-k8s.io

You should see resources resembling:

sandboxes.agents.x-k8s.io
sandboxclaims.extensions.agents.x-k8s.io
sandboxtemplates.extensions.agents.x-k8s.io
sandboxwarmpools.extensions.agents.x-k8s.io

Agent Sandbox uses a Sandbox CRD for the underlying stateful singleton pod and extension CRDs for templates, claims, and warm pools.

2. Clone the repository

The repository contains the Python runtime template and router manifests.

git clone --branch v0.5.2 \
  https://github.com/kubernetes-sigs/agent-sandbox.git

cd agent-sandbox

Create a dedicated namespace:

kubectl create namespace agent-sandbox-demo
3. Create the Python sandbox template

The official quickstart supplies a ready-made Python runtime template.

export SANDBOX_NAMESPACE=agent-sandbox-demo
export SANDBOX_TEMPLATE_NAME=python-runtime-template

envsubst '${SANDBOX_NAMESPACE} ${SANDBOX_TEMPLATE_NAME}' \
  < clients/python/agentic-sandbox-client/python-sandbox-template.yaml \
  | kubectl apply -f -

Verify it:

kubectl get sandboxtemplate -n agent-sandbox-demo

Expected:

NAME                      AGE
python-runtime-template   ...
4. Create a warm pool

Create two Python sandbox pods that are already running and waiting to be claimed:

kubectl apply -f - <<'EOF'
apiVersion: extensions.agents.x-k8s.io/v1beta1
kind: SandboxWarmPool
metadata:
  name: python-sandbox-pool
  namespace: agent-sandbox-demo
spec:
  replicas: 2
  sandboxTemplateRef:
    name: python-runtime-template
EOF

Check it:

kubectl get sandboxwarmpool -n agent-sandbox-demo
kubectl get pods -n agent-sandbox-demo

The warm pool creates pods ahead of time. A SandboxClaim adopts one of them when your Python application asks for a sandbox, and the controller creates a replacement to keep the pool full.

Wait for the pool pods:

kubectl wait \
  --for=condition=Ready \
  pod \
  -l agents.x-k8s.io/pool \
  -n agent-sandbox-demo \
  --timeout=180s
5. Build and deploy the sandbox router

Because ADK is running on your host, the Python SDK uses local tunnel mode:

host Python → kubectl port-forward → router → sandbox pod

Local tunnel mode is specifically intended for Kind, Minikube, local development, and CI.

Build the router:

export ROUTER_IMAGE=sandbox-router:v0.5.2

docker build \
  -t "${ROUTER_IMAGE}" \
  clients/python/agentic-sandbox-client/sandbox-router

Load it into your existing default Kind cluster:

kind load docker-image "${ROUTER_IMAGE}"

Because you used:

kind create cluster

without --name, the cluster name is normally kind. You can be explicit:

kind load docker-image "${ROUTER_IMAGE}" --name kind

The supplied router manifest may default to pulling the image from a registry. Create a local copy:

cp \
  clients/python/agentic-sandbox-client/sandbox-router/sandbox_router.yaml \
  /tmp/sandbox-router.yaml

Replace the image and force use of the locally loaded image:

sed -i.bak \
  "s|image: .*sandbox-router.*|image: ${ROUTER_IMAGE}|" \
  /tmp/sandbox-router.yaml

Inspect the deployment section:

grep -A5 -B5 'image:' /tmp/sandbox-router.yaml

Ensure it contains:

image: sandbox-router:v0.5.2
imagePullPolicy: Never

Then apply it:

kubectl apply \
  -n agent-sandbox-system \
  -f /tmp/sandbox-router.yaml

Wait for it:

kubectl wait \
  --for=condition=Ready \
  pod \
  -l app=sandbox-router \
  -n agent-sandbox-system \
  --timeout=180s

Check the service:

kubectl get svc sandbox-router-svc -n agent-sandbox-system

Test it manually:

kubectl port-forward \
  -n agent-sandbox-system \
  svc/sandbox-router-svc \
  8080:8080

In another terminal:

curl http://127.0.0.1:8080/healthz

Expected:

{"status":"ok"}

Stop the manual port-forward afterward. The Python client will create its own port-forward automatically.

6. Install the Python client into your ADK environment

Inside the same virtual environment used by make adk-web:

pip install "k8s-agent-sandbox==0.5.2"

Or, when using uv:

uv add "k8s-agent-sandbox==0.5.2"

The package requires Python 3.10 or newer.

7. Test Kubernetes independently from ADK

Before involving the model, create a small test:

# test_sandbox.py

from k8s_agent_sandbox import SandboxClient
from k8s_agent_sandbox.models import SandboxLocalTunnelConnectionConfig


def main() -> None:
    client = SandboxClient(
        connection_config=SandboxLocalTunnelConnectionConfig()
    )

    sandbox = client.create_sandbox(
        warmpool="python-sandbox-pool",
        namespace="agent-sandbox-demo",
    )

    try:
        result = sandbox.commands.run(
            "python3 -c \"print('hello from a Kubernetes sandbox pod')\""
        )

        print("exit code:", result.exit_code)
        print("stdout:", result.stdout)
        print("stderr:", result.stderr)
    finally:
        sandbox.terminate()


if __name__ == "__main__":
    main()

Run it:

python test_sandbox.py

While it runs, watch the resources:

kubectl get \
  sandboxclaims,sandboxes,pods \
  -n agent-sandbox-demo \
  --watch

The default SandboxClient() also defaults to local tunnel mode, but using SandboxLocalTunnelConnectionConfig() explicitly makes the behavior clearer.

8. Integrate it with your ADK agent

Suppose your current structure is:

my_agents/
└── hello_agent/
    ├── __init__.py
    └── agent.py

Replace or extend agent.py:

from __future__ import annotations

import logging
from typing import Any

from google.adk.agents import Agent
from k8s_agent_sandbox import SandboxClient
from k8s_agent_sandbox.models import SandboxLocalTunnelConnectionConfig


logger = logging.getLogger(__name__)

SANDBOX_NAMESPACE = "agent-sandbox-demo"
SANDBOX_WARMPOOL = "python-sandbox-pool"

# This object knows how to:
# 1. invoke kubectl,
# 2. establish a port-forward to sandbox-router,
# 3. create SandboxClaim resources,
# 4. communicate with the claimed sandbox pod.
sandbox_client = SandboxClient(
    connection_config=SandboxLocalTunnelConnectionConfig()
)


def execute_python(code: str) -> dict[str, Any]:
    """Execute Python code in an isolated Kubernetes Agent Sandbox.

    Args:
        code: Complete Python source code to execute.

    Returns:
        A dictionary containing stdout, stderr, and the process exit code.
    """
    if not code.strip():
        return {
            "ok": False,
            "exit_code": None,
            "stdout": "",
            "stderr": "No Python code was provided.",
        }

    sandbox = None

    try:
        sandbox = sandbox_client.create_sandbox(
            warmpool=SANDBOX_WARMPOOL,
            namespace=SANDBOX_NAMESPACE,
            labels={
                "app.kubernetes.io/created-by": "google-adk",
            },
            pod_labels={
                "sandbox.seriousengineering.dev/workload": "python-code",
            },
        )

        # Avoid shell interpolation of model-generated source code.
        sandbox.files.write("run.py", code)

        result = sandbox.commands.run(
            "python3 -I -B run.py",
            timeout=30,
        )

        return {
            "ok": result.exit_code == 0,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    except Exception as exc:
        logger.exception("Kubernetes sandbox execution failed")

        return {
            "ok": False,
            "exit_code": None,
            "stdout": "",
            "stderr": f"Sandbox execution failed: {exc}",
        }

    finally:
        if sandbox is not None:
            try:
                sandbox.terminate()
            except Exception:
                logger.exception("Failed to terminate sandbox")


root_agent = Agent(
    name="hello_agent",
    model="gemini-2.5-flash",
    description=(
        "A greeting and Python assistant that can execute Python code "
        "inside a Kubernetes sandbox."
    ),
    instruction="""
You are a helpful assistant.

For normal greetings and general questions, answer directly.

When a request requires calculation, data processing, or execution of Python:
1. Write complete Python code.
2. Call execute_python with that code.
3. Inspect stdout, stderr, and exit_code.
4. Explain the result to the user.
5. Never claim code was executed unless execute_python returned ok=true.

Do not use execute_python for simple greetings.
""",
    tools=[execute_python],
)

The official Kubernetes example also exposes a normal Python function named execute_python to ADK and places that function in tools=[execute_python]. Inside the function it creates a sandbox, writes run.py, executes it, and terminates the sandbox.

Start your existing application:

make adk-web

Then ask:

Write Python code that calculates the first 20 Fibonacci numbers,
execute it, and show me the result.
9. Confirm that execution really happened in a pod

Run this in another terminal:

kubectl get pods \
  -n agent-sandbox-demo \
  --watch \
  -o wide

Also inspect claims:

kubectl get sandboxclaims \
  -n agent-sandbox-demo \
  --watch

During a tool invocation you should see:

ADK calls execute_python.
The SDK creates a SandboxClaim.
One warm-pool pod is claimed.
The code is written into that pod.
python3 -I -B run.py executes there.
sandbox.terminate() deletes the claim/sandbox.
The warm pool replenishes itself.

To prove the environment is Kubernetes, ask the agent to execute:

import os
import platform
import socket

print("hostname:", socket.gethostname())
print("platform:", platform.platform())
print("kubernetes service host:", os.getenv("KUBERNETES_SERVICE_HOST"))

The hostname should correspond to the sandbox pod rather than your workstation.

A more reusable implementation

Creating and destroying a sandbox for every tool call gives strong task separation, but state does not persist between calls.

For one sandbox per ADK session, you would need a session-to-sandbox mapping:

sandboxes: dict[str, Sandbox] = {}

Conceptually:

def execute_python(code: str, tool_context: ToolContext):
    session_id = tool_context.session.id

    sandbox = sandboxes.get(session_id)
    if sandbox is None:
        sandbox = sandbox_client.create_sandbox(...)
        sandboxes[session_id] = sandbox

    ...

Then terminate it on:

session completion;
inactivity timeout;
application shutdown;
explicit reset.

For your first implementation, one sandbox per call is much safer and simpler.

Security warning about ordinary Kind

A standard cluster created with:

kind create cluster

does not automatically provide gVisor or VM-level isolation. The official quickstart explicitly describes the default Kind setup as operating without stronger container isolation and offers separate gVisor or Kata paths.

Therefore, your current setup is useful for understanding:

CRDs;
claims;
warm pools;
pod lifecycle;
ADK integration;
file and command APIs.

It should not be treated as a hardened environment for hostile code.

At minimum, apply these controls before allowing arbitrary user prompts:

securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL

Also add:

CPU and memory limits;
process limits;
execution timeout;
no mounted service-account token;
no host paths;
no privileged containers;
deny-all egress NetworkPolicy;
gVisor or Kata runtime;
a dedicated sandbox namespace;
no credentials in environment variables.
Why your GkeCodeExecutor example does not map directly

This:

GkeCodeExecutor(
    sandbox_resource_name=(
        "projects/.../locations/.../sandboxEnvironments/..."
    )
)

refers to a Google Cloud-managed resource and expects a GCP resource name. kubectl credentials alone cannot produce that resource identifier.

For your environment, the equivalent abstraction is:

SandboxClient(
    connection_config=SandboxLocalTunnelConnectionConfig()
)

followed by:

sandbox_client.create_sandbox(
    warmpool="python-sandbox-pool",
    namespace="agent-sandbox-demo",
)

So the translation is:

GKE sandbox environment resource
    → Kubernetes SandboxTemplate + SandboxWarmPool

GkeCodeExecutor
    → ADK function tool wrapping SandboxClient

GCP API connection
    → local kubectl port-forward through sandbox-router

This is the most direct working architecture for ADK on your host + an existing local Kind cluster.