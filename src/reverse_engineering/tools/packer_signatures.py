"""Pure packer/protector identification over a sample's raw bytes.

The native/managed sibling of :mod:`reverse_engineering.tools.android.packer_signatures`:
a table of literal byte markers matched with ``bytes.find``. No parsing, no
dependency, no sandbox -- so it runs in the AREMA process at ingest, before any
model turn, and is fully unit-testable. The markers are the packer's own
watermark (a PE section name it creates, or an attribute a .NET protector stamps
into the assembly), not a heuristic.

Precision-first, recall-second. A protector configured to strip its watermark
does not match, so a non-detection means "not named", never "not packed" --
callers must keep that distinction (see ``dotnet.py``'s ``protector_unsupported``
reason). The table is a starter set; extend it as new families are observed.

Admit only a marker the packer *injects* -- a section name it creates, a type or
attribute it stamps in -- never a product name it is merely known by. A bare
product name matches any file that mentions it, which is why a scan of 4,008
real assemblies flagged only de4dot's own binaries: they hardcode the names they
hunt for. ``signals`` reports what matched so that stays auditable.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class _PackerSignature:
    """One packer identity and the literal byte markers that betray it."""

    name: str
    markers: tuple[bytes, ...]


# Native packers first, managed protectors second: a UPX-compressed .NET assembly
# is UPX on the outside, and the outer layer is the one the deobfuscation loop has
# to strip first. PE section names are matched with their null padding to the
# 8-byte header field, so a file that merely mentions the text does not match.
_SIGNATURES: tuple[_PackerSignature, ...] = (
    _PackerSignature("UPX", (b"UPX0\x00\x00\x00\x00", b"UPX1\x00\x00\x00\x00", b"UPX!")),
    _PackerSignature("MPRESS", (b".MPRESS1", b".MPRESS2")),
    _PackerSignature("ASPack", (b".aspack\x00", b".adata\x00\x00")),
    _PackerSignature("Themida/WinLicense", (b".themida", b".winlice")),
    _PackerSignature("VMProtect", (b".vmp0\x00\x00\x00", b".vmp1\x00\x00\x00")),
    _PackerSignature("Enigma Protector", (b".enigma1", b".enigma2")),
    _PackerSignature("Petite", (b".petite\x00",)),
    _PackerSignature("PECompact", (b"PECompact2",)),
    _PackerSignature("PyInstaller", (b"MEI\x0c\x0b\x0a\x0b\x0e",)),
    _PackerSignature("ConfuserEx", (b"ConfusedByAttribute",)),
    _PackerSignature("Eazfuscator.NET", (b"Eazfuscator.NET",)),
    _PackerSignature("SmartAssembly", (b"SmartAssembly.Attributes",)),
    _PackerSignature("Dotfuscator", (b"DotfuscatorAttribute",)),
    _PackerSignature("Babel", (b"BabelObfuscatorAttribute", b"BabelAttribute")),
    _PackerSignature("Agile.NET", (b"CliSecureRd.dll",)),
)


def _signal(marker: bytes) -> str:
    """Render a marker as a printable signal (control bytes stay escaped)."""
    return repr(marker)[2:-1]


def detect_packer_bytes(data: bytes) -> dict[str, object]:
    """Return the first matching packer identity, or a not-detected result.

    ``{"detected": bool, "name": str | None, "signals": list[str]}`` -- the same
    shape the Android detector returns. ``detected: False`` means no watermark was
    found, which is NOT a claim that the sample is unpacked.
    """
    # ponytail: linear scan of the whole buffer per marker. memchr-backed, so a
    # 500 MB sample costs a couple of seconds once at ingest; bound the scan to
    # the PE header + metadata heap only if that ever shows up in a profile.
    for signature in _SIGNATURES:
        signals = [_signal(marker) for marker in signature.markers if marker in data]
        if signals:
            return {"detected": True, "name": signature.name, "signals": signals}
    return {"detected": False, "name": None, "signals": []}
