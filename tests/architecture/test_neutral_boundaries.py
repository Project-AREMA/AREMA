"""Architecture guardrails keeping the AREMA shell domain-neutral.

These tests are executable invariants, not descriptions: they fail the build if
the project identity drifts back toward the legacy security package, if any
``src/arema`` module imports the legacy tree, or if the default composition root
names a concrete domain capability. They read the on-disk project files rather
than importing runtime objects, so they hold regardless of what is installed.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path


def test_project_metadata_is_arema() -> None:
    data = tomllib.loads(Path("pyproject.toml").read_text())
    packages = data["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"]
    assert "src/arema" in packages
    assert packages[0] == "src/arema"
    assert data["project"]["name"] == "arema"
    assert data["project"]["scripts"] == {"arema": "arema.cli:main"}


def test_arema_source_has_no_legacy_imports() -> None:
    source = "\n".join(path.read_text() for path in Path("src/arema").rglob("*.py"))
    assert "security_agent" not in source
    assert "security_tools" not in source


def test_default_composition_has_no_domain_registration_terms() -> None:
    source = Path("src/arema/composition.py").read_text().lower()
    for term in ("playwright", "radare2", "r2mcp", "nmap", "sqlmap", "assessment"):
        assert term not in source


def test_sandbox_module_has_no_registry_imports() -> None:
    """runtime/sandbox depends only downward on core/ -- never registry/."""
    sandbox_dir = Path("src/arema/runtime/sandbox")
    for path in sandbox_dir.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
                "arema.registry"
            ):
                raise AssertionError(
                    f"{path} imports {node.module} -- sandbox must not depend on registry"
                )
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("arema.registry"):
                        raise AssertionError(
                            f"{path} imports {alias.name} -- sandbox must not depend on registry"
                        )


def test_arema_source_names_no_concrete_domain_tool() -> None:
    """No src/arema module hardcodes a concrete domain tool/pool name."""
    source = "\n".join(path.read_text() for path in Path("src/arema").rglob("*.py"))
    for term in ("radare2", "r2mcp", "ghidra", "ilspycmd"):
        assert term not in source, f"src/arema must not name domain tool '{term}'"
