"""Structural tests for the Detect It Easy addition to the radare2-mcp image.

DIE runs in the radare2-mcp pod rather than its own: prepare_sandbox already
claims that pod at intake and has already copied the sample to /app/<sha256>, so
the scan costs one exec with no extra claim and no second copy. These assert on
the Dockerfile text; the live build and scan were verified on the cluster.
"""

from __future__ import annotations

from pathlib import Path

from reverse_engineering.tools.detect_it_easy import build_scan_argv

DOCKERFILE = Path("images/radare2-mcp/Dockerfile")
WORKBENCH_DOCKERFILE = Path("images/analysis-workbench/Dockerfile")


def test_image_installs_die_python() -> None:
    text = DOCKERFILE.read_text()
    assert "die-python==${DIE_PYTHON_VERSION}" in text
    assert "python3" in text


def test_die_version_matches_the_workbench_image() -> None:
    """Two images carry DIE; one pinned version keeps their verdicts comparable."""
    assert "DIE_PYTHON_VERSION=0.4.0" in DOCKERFILE.read_text()
    assert "die-python==0.4.0" in WORKBENCH_DOCKERFILE.read_text()


def test_image_installs_the_one_system_library_the_extension_needs() -> None:
    """Measured with ldd against the installed _die*.so: the wheel vendors Qt6
    and ICU 73 into die/lib/, and glib is the only thing it wants from the
    system. Without it the import dies with
    "libglib-2.0.so.0: cannot open shared object file"."""
    assert "libglib2.0-0" in DOCKERFILE.read_text()


def test_build_fails_on_a_broken_database_instead_of_shipping_it() -> None:
    """A silent DIE is the failure mode this whole tool exists to prevent, so the
    build scans a real binary and requires detects rather than only importing."""
    text = DOCKERFILE.read_text()
    assert "assert db.is_dir(), db" in text
    assert "assert json.loads(out).get('detects'), out" in text


def test_the_dockerfile_records_the_database_path_trap() -> None:
    """The default database path matches nothing and reports Unknown for every
    packer without erroring, so the qualifier has to be written down where the
    next person installing DIE will read it."""
    text = DOCKERFILE.read_text()
    assert 'die.database_path / "db"' in text
    assert "database=str(db)" in text


def test_the_scan_argv_only_needs_python3_from_the_image() -> None:
    """The tool shells `python3 -c <script> <path>`; nothing else is required of
    the image, so the two cannot drift apart."""
    assert build_scan_argv("/app/x")[0] == "python3"
