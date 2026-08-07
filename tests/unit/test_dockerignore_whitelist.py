"""Guard: a whitelist ``.dockerignore`` must re-include every local ``COPY`` source.

Several engine images use a deny-by-default ``.dockerignore`` (``*`` then a series
of ``!<path>`` re-includes) so that stray files (``__pycache__``, ``*.in`` sources,
smoke scripts) never enter the build context. That posture is correct, but it has a
sharp edge: a Dockerfile ``COPY`` of a file that was never whitelisted is silently
excluded from the context, so ``docker build`` fails at that ``COPY`` — and ``make
check`` never builds the images, so the gap is invisible to CI.

This exact omission has bitten three times while filling out the analysis matrix
(``androguard_triage.py`` was ``COPY``-d but not whitelisted, making the
deobfuscation-tools image un-buildable). This test closes that blind spot without
building anything: for every image whose ``.dockerignore`` is a whitelist, every
local-context ``COPY`` source in its Dockerfile must be re-included.

Only local-context ``COPY`` instructions are governed by ``.dockerignore``. A
``COPY --from=<stage>`` (or ``--from=<named-context>``) copies from another build
stage / named context and is exempt; a blacklist ``.dockerignore`` (one that does
not start with ``*``) is exempt too.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_IMAGES_DIR = Path(__file__).resolve().parents[2] / "images"


def _whitelist_reincludes(dockerignore: Path) -> set[str] | None:
    """Return the set of re-included paths if this is a whitelist, else ``None``.

    A whitelist ``.dockerignore`` has ``*`` as its first meaningful (non-comment,
    non-blank) line; its re-includes are the ``!<path>`` entries.
    """
    lines = [
        ln.strip()
        for ln in dockerignore.read_text().splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if not lines or lines[0] != "*":
        return None
    return {ln[1:].lstrip("/") for ln in lines if ln.startswith("!")}


def _local_copy_sources(dockerfile: Path) -> list[str]:
    """Every source path of a local-context ``COPY`` (skips ``--from=`` copies)."""
    sources: list[str] = []
    for raw in dockerfile.read_text().splitlines():
        line = raw.strip()
        if not line.upper().startswith("COPY "):
            continue
        tokens = line.split()[1:]  # drop the COPY keyword
        flags = [t for t in tokens if t.startswith("--")]
        if any(f.startswith("--from=") for f in flags):
            continue  # from another stage / named context — not the local context
        operands = [t for t in tokens if not t.startswith("--")]
        if len(operands) < 2:
            continue  # malformed; needs at least one src + a dest
        sources.extend(operands[:-1])  # all but the destination
    return sources


def _whitelist_images() -> list[Path]:
    return sorted(
        image
        for image in _IMAGES_DIR.iterdir()
        if (image / ".dockerignore").is_file()
        and (image / "Dockerfile").is_file()
        and _whitelist_reincludes(image / ".dockerignore") is not None
    )


def test_there_are_whitelist_images_to_guard() -> None:
    # If this ever hits zero the guard below is silently vacuous — fail instead.
    names = {p.name for p in _whitelist_images()}
    assert {"deobfuscation-tools", "analysis-workbench"} <= names


@pytest.mark.parametrize("image", _whitelist_images(), ids=lambda p: p.name)
def test_whitelist_dockerignore_reincludes_every_local_copy_source(image: Path) -> None:
    reincluded = _whitelist_reincludes(image / ".dockerignore")
    assert reincluded is not None  # guaranteed by _whitelist_images()
    missing = [
        src
        for src in _local_copy_sources(image / "Dockerfile")
        if src.lstrip("/") not in reincluded
    ]
    assert not missing, (
        f"{image.name}: Dockerfile COPY-s {missing} from the local build context, but "
        f".dockerignore (a whitelist) does not re-include them, so they are excluded and "
        f"the image cannot build. Add '!<path>' entries for: {missing}"
    )
