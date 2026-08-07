"""Unit tests for the pure native/.NET packer-signature detector."""

from __future__ import annotations

import pytest

from reverse_engineering.tools.packer_signatures import detect_packer_bytes


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"MZ" + bytes(200) + b"UPX0\x00\x00\x00\x00" + bytes(40), "UPX"),
        (b"\x7fELF" + bytes(120) + b"UPX!" + bytes(16), "UPX"),
        (b"MZ" + bytes(200) + b".MPRESS1" + bytes(40), "MPRESS"),
        (b"MZ" + bytes(200) + b".themida" + bytes(40), "Themida/WinLicense"),
        (b"MZ" + bytes(200) + b".vmp0\x00\x00\x00" + bytes(40), "VMProtect"),
        (b"MZ" + bytes(300) + b"MEI\x0c\x0b\x0a\x0b\x0e", "PyInstaller"),
        (b"MZ" + bytes(400) + b"ConfusedByAttribute", "ConfuserEx"),
        (b"MZ" + bytes(400) + b"Eazfuscator.NET", "Eazfuscator.NET"),
        (b"MZ" + bytes(400) + b"SmartAssembly.Attributes", "SmartAssembly"),
        (b"MZ" + bytes(400) + b"CliSecureRd.dll", "Agile.NET"),
    ],
)
def test_names_the_protector_from_its_own_watermark(payload: bytes, expected: str) -> None:
    result = detect_packer_bytes(payload)

    assert result["detected"] is True
    assert result["name"] == expected
    assert result["signals"]


def test_an_unmarked_binary_is_not_detected() -> None:
    result = detect_packer_bytes(b"MZ" + bytes(512) + b"Hello from a plain program")

    assert result == {"detected": False, "name": None, "signals": []}


def test_a_section_name_needs_its_header_padding() -> None:
    """Bare text must not match: only the padded 8-byte section field counts."""
    assert detect_packer_bytes(b"this file mentions UPX0 and .aspack in prose")["detected"] is False


def test_the_outer_native_layer_wins_over_the_managed_protector() -> None:
    """A UPX-compressed ConfuserEx assembly reports UPX -- the layer to strip first."""
    both = b"MZ" + bytes(64) + b"UPX0\x00\x00\x00\x00" + bytes(64) + b"ConfusedByAttribute"

    assert detect_packer_bytes(both)["name"] == "UPX"


def test_signals_stay_printable_for_a_control_byte_marker() -> None:
    """Signals reach a report, so a raw cookie must render escaped, not as controls."""
    signals = detect_packer_bytes(b"MZ" + b"MEI\x0c\x0b\x0a\x0b\x0e")["signals"]

    assert signals == ["MEI\\x0c\\x0b\\n\\x0b\\x0e"]


def test_empty_input_is_safe() -> None:
    assert detect_packer_bytes(b"")["detected"] is False


def test_a_bare_product_name_is_not_admitted_as_a_marker() -> None:
    """Measured over 5,932 host ELF/PE binaries and 4,008 assemblies in the
    workbench pod. The only detections were de4dot's own de4dot.code.dll and
    de4dot.cui.dll, which hardcode the names they hunt for. The ILProtector entry
    matched on the bare product name alone, so it was dropped: a marker earns its
    place by being something the packer injects (a section name, a type or
    attribute it stamps in), not a name it is known by. That left one residual --
    de4dot.code.dll via DotfuscatorAttribute, a genuine injected type name -- and
    zero detections across every other file in both corpora.
    """
    prose = b"MZ" + bytes(64) + b"this tool can unpack ILProtector and Themida"

    assert detect_packer_bytes(prose)["detected"] is False
