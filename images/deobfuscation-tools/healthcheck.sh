#!/usr/bin/env bash
set -euo pipefail

upx_version="$(upx --version | awk 'NR == 1 { print $2; exit }')"
floss_version="$(floss --version | awk 'NR == 1 { print $2; exit }')"
de4dot_ok="$(de4dot 2>&1 | grep -c 'de4dot' || true)"
androguard_version="$(python -c 'from importlib.metadata import version; print(version("androguard"))')"

test "${upx_version}" = "5.2.0"
test "${floss_version}" = "3.1.1"
test "${de4dot_ok}" -ge 1
test "${androguard_version}" = "4.1.2"
# The in-pod triage entrypoint must import the vendored pure package + androguard.
python -c "from androguard_pure.report import build_report; import androguard"
