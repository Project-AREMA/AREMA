#!/usr/bin/env bash
set -euo pipefail

image="${1:-arema-deobfuscation-tools:0.1.0}"

docker run --rm "${image}" sh -ceu '
    test "$(id -u)" = "1000"
    test "$(id -g)" = "1000"
    test -w /work
    test -w /home/deobf
    test "$(upx --version | awk "NR == 1 { print \$2; exit }")" = "5.2.0"
    test "$(floss --version | awk "NR == 1 { print \$2; exit }")" = "3.1.1"
    deobfuscation-tools-healthcheck
    python -c "import binary2strings; assert binary2strings.__file__.endswith(\".so\")"
    ! command -v g++ >/dev/null
    ! command -v gcc >/dev/null
    ! command -v cc >/dev/null
    ! command -v c++ >/dev/null
    ! command -v cpp >/dev/null
    ! command -v as >/dev/null
    ! command -v ld >/dev/null
    ! command -v make >/dev/null
    ! command -v cmake >/dev/null
    ! dpkg-query -W -f="\${binary:Package} \${Status}\n" "*-dev" 2>/dev/null | grep -q "install ok installed"
'

docker run --rm "${image}" python -m pip check
docker run --rm "${image}" python -c '
from importlib.metadata import distributions
from pathlib import Path

normalize = lambda name: name.lower().replace("_", "-").replace(".", "-")
expected = {
    normalize(line.split("==", maxsplit=1)[0])
    for line in Path("/opt/runtime-requirements.lock").read_text().splitlines()
    if "==" in line and not line.startswith((" ", "#"))
}
installed = {normalize(dist.metadata["Name"]) for dist in distributions()}
assert expected == installed - {"pip"}, (expected - installed, installed - expected - {"pip"})
'
