"""Package identity tests for the AREMA migration seam."""

from arema import __version__


def test_package_exposes_arema_version() -> None:
    assert __version__ == "0.1.0"
