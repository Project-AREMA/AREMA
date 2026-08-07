"""Pure Android packer/protector detection over enumerated artifact names.

Given the native libraries, asset names, and application-class recovered from an
APK, match them against a table of known commercial-packer signatures (loader
``.so`` basenames, tell-tale assets, stub application classes). This module does
no parsing and pulls in no androguard dependency, so it is fully unit-testable in
the AREMA process; the hostile APK is parsed only inside the sandbox pod, which
feeds the resulting name lists here.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from fnmatch import fnmatch


@dataclass(frozen=True)
class _PackerSignature:
    """One packer identity and the artifact-name globs that betray it."""

    name: str
    lib_globs: tuple[str, ...] = ()
    asset_globs: tuple[str, ...] = ()
    class_globs: tuple[str, ...] = ()


# Starter table (extend as new packers are observed). Globs are matched
# case-insensitively against the *basename* of each native lib / asset with
# ``fnmatch`` so ``libjiagu_art.so`` matches ``libjiagu*.so``.
_SIGNATURES: tuple[_PackerSignature, ...] = (
    _PackerSignature(name="jiagu", lib_globs=("libjiagu*.so",)),
    _PackerSignature(
        name="bangcle",
        lib_globs=(
            "libsecexe.so",
            "libsecmain.so",
            "libSecShell.so",
            "libDexHelper.so",
        ),
    ),
    _PackerSignature(
        name="legu",
        lib_globs=("libtup.so", "libshell*.so", "libmobisec.so"),
    ),
    _PackerSignature(name="dexprotector", lib_globs=("libdexprotector*.so",)),
    _PackerSignature(name="apkprotect", lib_globs=("libAPKProtect.so",)),
)


def _matches(candidate: str, glob: str) -> bool:
    """Case-insensitive ``fnmatch`` on the basename of ``candidate``."""

    base = posixpath.basename(candidate.replace("\\", "/"))
    return fnmatch(base.lower(), glob.lower())


def detect_packer(
    native_libs: list[str],
    asset_names: list[str],
    app_class: str | None,
) -> dict[str, object]:
    """Return the first matching packer identity, or a not-detected result.

    Args:
        native_libs: ``lib/<abi>/*.so`` paths enumerated from the APK.
        asset_names: asset entry names enumerated from the APK.
        app_class: the declared ``application`` class, if any.

    Returns:
        ``{"detected": bool, "name": str | None, "signals": list[str]}``.
    """

    for signature in _SIGNATURES:
        signals: list[str] = []
        for lib in native_libs:
            for glob in signature.lib_globs:
                if _matches(lib, glob):
                    signals.append(posixpath.basename(lib.replace("\\", "/")))
        for asset in asset_names:
            for glob in signature.asset_globs:
                if _matches(asset, glob):
                    signals.append(posixpath.basename(asset.replace("\\", "/")))
        if app_class is not None:
            for glob in signature.class_globs:
                if fnmatch(app_class.lower(), glob.lower()):
                    signals.append(app_class)
        if signals:
            return {"detected": True, "name": signature.name, "signals": signals}

    return {"detected": False, "name": None, "signals": []}
