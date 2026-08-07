.PHONY: help setup install venv run adk-run adk-web test test-unit test-component lint format-check type-check check clean sandbox-cluster setup-sandbox sandbox-build-images sandbox-up sandbox-verify-egress sandbox-down sandbox-prune smoke-ilspy smoke-jadx

# Variables
SRC := src/arema src/greeter_agent src/reverse_engineering src/malware_analyst
TESTS := tests
# Ruff covers the smoke scripts too; mypy does not. They poke at JSON-RPC dicts
# and ADK context stand-ins, where strict annotations cost more than they catch.
LINT_SRC := $(SRC) scripts

# Default target
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Setup targets
venv: ## Create the virtual environment
	uv venv
	@echo "Virtual environment created. Run 'source .venv/bin/activate' to activate."

# --inexact keeps already-installed extras (e.g. the optional `sandbox` extra
# installed by setup-sandbox) instead of pruning them on a plain dev sync.
setup: ## Full project setup (dependencies + dev extra; preserves the sandbox extra)
	uv sync --extra dev --inexact
	@echo ""
	@echo "Setup complete. Run 'source .venv/bin/activate' to activate the environment."

install: ## Install project and dev dependencies (preserves the sandbox extra)
	uv sync --extra dev --inexact

# Run targets
run: ## Run a single query (usage: make run query="Are you operational?")
	@if [ -z "$(query)" ]; then \
		echo "Error: query variable is required"; \
		echo "Usage: make run query=\"your query here\""; \
		exit 1; \
	fi
	uv run arema --query "$(query)"

adk-run: ## Start an interactive session with the greeter (welcome router) agent
	uv run adk run src/greeter_agent

adk-web: ## Start the ADK developer web interface (default port 8000)
	uv run arema --web --port 8000

# Testing targets
test: ## Run the full test suite
	uv run --extra dev pytest $(TESTS)

test-unit: ## Run unit tests only
	uv run --extra dev pytest $(TESTS)/unit

test-component: ## Run component tests only
	uv run --extra dev pytest $(TESTS)/component

# Code quality targets
lint: ## Run the ruff linter
	uv run --extra dev ruff check $(LINT_SRC) $(TESTS)

format-check: ## Check formatting without making changes
	uv run --extra dev ruff format --check $(LINT_SRC) $(TESTS)

type-check: ## Run mypy type checking
	uv run --extra dev mypy $(SRC)

check: lint format-check type-check test ## Run all checks (lint, format, type-check, test)

# -- Sandbox ------------------------------------------------------------------
# Lifecycle: sandbox-cluster (once) -> setup-sandbox (once) -> sandbox-build-images
#            -> sandbox-up -> sandbox-verify-egress -> [run AREMA]
#            -> sandbox-prune (as needed) -> sandbox-down.
# The six engine pools (radare2-mcp, ghidra-rpc, deobfuscation-tools, ilspy-mcp, jadx,
# analysis-workbench) live in the agent-sandbox-demo namespace. The Agent Sandbox
# framework (controller
# + router) that setup-sandbox installs lives in agent-sandbox-system and is
# intentionally left running by sandbox-down.
#
# CNI PREREQUISITE: the analysis-workbench deny-all egress NetworkPolicy is only
# enforced by a policy-enforcing CNI. Kind's default (kindnet) ignores it, so the
# cluster MUST be created with the default CNI disabled (sandbox-cluster) and
# Calico installed (setup-sandbox). sandbox-verify-egress proves enforcement.
sandbox-cluster: ## Create a Kind cluster with the default CNI disabled (Calico added by setup-sandbox) so NetworkPolicy is enforced
	kind create cluster --config deploy/sandbox/kind-cluster.yaml

setup-sandbox: ## Install a policy-enforcing CNI (Calico) + the sandbox client deps + the Agent Sandbox framework (controller + router) into the current Kind cluster
	uv sync --extra dev --extra sandbox
	deploy/sandbox/install-agent-sandbox.sh

sandbox-build-images: ## Build all six engine images (radare2-mcp + ghidra-rpc + deobfuscation-tools + ilspy-mcp + jadx + analysis-workbench) and load them into kind
	docker build -t arema-radare2-mcp:0.1.0 images/radare2-mcp
	kind load docker-image arema-radare2-mcp:0.1.0
	docker build -t arema-ghidra-rpc:0.1.0 images/ghidra-rpc
	kind load docker-image arema-ghidra-rpc:0.1.0
	docker build -t arema-deobfuscation-tools:0.1.0 \
		--build-context arema-pure=src/reverse_engineering/tools/android \
		images/deobfuscation-tools
	kind load docker-image arema-deobfuscation-tools:0.1.0
	docker build -t arema-ilspy-mcp:0.1.0 images/ilspy-mcp
	kind load docker-image arema-ilspy-mcp:0.1.0
	docker build -t arema-jadx:0.1.0 images/jadx
	kind load docker-image arema-jadx:0.1.0
	docker build -t arema-analysis-workbench:0.1.0 images/analysis-workbench
	kind load docker-image arema-analysis-workbench:0.1.0

sandbox-up: ## Apply every engine SandboxTemplate + WarmPool and wait for the pods to be Ready
	kubectl apply -f deploy/sandbox/10-radare2-mcp-template.yaml
	kubectl apply -f deploy/sandbox/20-radare2-mcp-pool.yaml
	kubectl apply -f deploy/sandbox/10-ghidra-rpc-template.yaml
	kubectl apply -f deploy/sandbox/20-ghidra-rpc-pool.yaml
	kubectl apply -f deploy/sandbox/10-deobfuscation-tools-template.yaml
	kubectl apply -f deploy/sandbox/20-deobfuscation-tools-pool.yaml
	kubectl apply -f deploy/sandbox/10-ilspy-mcp-template.yaml
	kubectl apply -f deploy/sandbox/20-ilspy-mcp-pool.yaml
	kubectl apply -f deploy/sandbox/10-jadx-template.yaml
	kubectl apply -f deploy/sandbox/20-jadx-pool.yaml
	kubectl apply -f deploy/sandbox/10-analysis-workbench-template.yaml
	kubectl apply -f deploy/sandbox/20-analysis-workbench-pool.yaml
	kubectl apply -f deploy/sandbox/30-analysis-workbench-denyall-egress.yaml
	kubectl wait --for=condition=Ready pod -l arema.dev/pool=radare2-mcp \
		-n agent-sandbox-demo --timeout=180s
	kubectl wait --for=condition=Ready pod -l arema.dev/pool=ghidra-rpc \
		-n agent-sandbox-demo --timeout=300s
	kubectl wait --for=condition=Ready pod -l arema.dev/pool=deobfuscation-tools \
		-n agent-sandbox-demo --timeout=180s
	kubectl wait --for=condition=Ready pod -l arema.dev/pool=ilspy-mcp \
		-n agent-sandbox-demo --timeout=180s
	kubectl wait --for=condition=Ready pod -l arema.dev/pool=jadx \
		-n agent-sandbox-demo --timeout=180s
	kubectl wait --for=condition=Ready pod -l arema.dev/pool=analysis-workbench \
		-n agent-sandbox-demo --timeout=180s

sandbox-verify-egress: ## Prove the analysis-workbench deny-all egress NetworkPolicy is actually ENFORCED (not just present)
	deploy/sandbox/verify-egress-denied.sh

# The test suite monkeypatches kubectl, so it cannot see what an engine actually
# does to a real sample. These drive the production path against a live cluster
# with no model in the loop, so a failure is unambiguously plumbing.
smoke-ilspy: ## Drive the .NET/ILSpy route against a live cluster (usage: make smoke-ilspy SAMPLE=/path/to/assembly.dll)
	@if [ -z "$(SAMPLE)" ]; then \
		echo "Error: SAMPLE variable is required"; \
		echo "Usage: make smoke-ilspy SAMPLE=/path/to/assembly.dll"; \
		exit 1; \
	fi
	uv run python scripts/smoke/ilspy_route.py "$(SAMPLE)"

smoke-jadx: ## Drive the Java/Android jadx route against a live cluster (usage: make smoke-jadx SAMPLE=/path/to/app.apk)
	@if [ -z "$(SAMPLE)" ]; then \
		echo "Error: SAMPLE variable is required"; \
		echo "Usage: make smoke-jadx SAMPLE=/path/to/app.apk"; \
		exit 1; \
	fi
	uv run python scripts/smoke/jadx_route.py "$(SAMPLE)"

sandbox-down: ## Delete every engine WarmPool + SandboxTemplate (leaves the Agent Sandbox framework installed)
	kubectl delete -f deploy/sandbox/20-radare2-mcp-pool.yaml --ignore-not-found
	kubectl delete -f deploy/sandbox/10-radare2-mcp-template.yaml --ignore-not-found
	kubectl delete -f deploy/sandbox/20-ghidra-rpc-pool.yaml --ignore-not-found
	kubectl delete -f deploy/sandbox/10-ghidra-rpc-template.yaml --ignore-not-found
	kubectl delete -f deploy/sandbox/20-deobfuscation-tools-pool.yaml --ignore-not-found
	kubectl delete -f deploy/sandbox/10-deobfuscation-tools-template.yaml --ignore-not-found
	kubectl delete -f deploy/sandbox/20-ilspy-mcp-pool.yaml --ignore-not-found
	kubectl delete -f deploy/sandbox/10-ilspy-mcp-template.yaml --ignore-not-found
	kubectl delete -f deploy/sandbox/20-jadx-pool.yaml --ignore-not-found
	kubectl delete -f deploy/sandbox/10-jadx-template.yaml --ignore-not-found
	kubectl delete -f deploy/sandbox/30-analysis-workbench-denyall-egress.yaml --ignore-not-found
	kubectl delete -f deploy/sandbox/20-analysis-workbench-pool.yaml --ignore-not-found
	kubectl delete -f deploy/sandbox/10-analysis-workbench-template.yaml --ignore-not-found

sandbox-prune: ## Delete orphaned SandboxClaims (claimed pods whose session ended w/o cleanup)
	kubectl delete sandboxclaim --all -n agent-sandbox-demo --ignore-not-found

# Cleanup
clean: ## Remove build artifacts and caches
	rm -rf build dist *.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache .hypothesis
	rm -rf htmlcov .coverage coverage.xml
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
