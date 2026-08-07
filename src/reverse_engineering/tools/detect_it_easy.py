"""Detect It Easy pre-validation of the sample under analysis.

Answers one question before any engine commits work: is this sample packed or
compressed, and by what? DIE ships ~1,400 signature files, two orders of
magnitude more coverage than the watermark table in
:mod:`reverse_engineering.tools.packer_signatures`, but it needs a pod. The two
are complementary -- the table always answers, DIE answers deeply.

Two halves, deliberately split. :data:`_SCAN_SCRIPT` is a fixed,
developer-authored snippet run inside the claimed pod, so the hostile bytes are
parsed only there and only by DIE. :func:`classify_die_output` is a pure
host-side function over the JSON it prints, so the verdict logic is unit-testable
without a cluster -- the same division ``android/packer_signatures.py`` states.

DIE reports a type for *every* file, so "DIE detected something" is not "packed".
Measured over 345 real files in the workbench pod: 291 ``Library`` (a clean ELF
is ``Library: GLIBC``), 54 ``Format``, 49 ``Script``, 30 ``Compiler``, 21
``Unknown``, 20 ``Linker``, and exactly one ``Packer`` -- the single UPX-packed
binary present. Only a type in :data:`_PACKING_TYPES` means the real code is not
directly visible, so that set is the verdict and everything else is toolchain
metadata.

The scan passes ``database=`` explicitly. die-python's default database path
matches no signature and reports Unknown for every packer without raising, so an
unqualified call is a silent false negative (see ``packer_analyst.md``).
"""

from __future__ import annotations

import json

from arema.core.logging import get_logger
from reverse_engineering.runtime.portforward import kubectl_exec

logger = get_logger(__name__)

# Measured median 22.5 ms and p95 104 ms over 345 real files, so this is a
# generous ceiling on a scan that sits on the intake critical path.
_SCAN_TIMEOUT_S = 120

# The verdict, and its prompt-injectable alias. A colon is not identifier-safe so
# ADK cannot resolve ``{sample:die?}``; the alias is what a prompt reads. Same
# pairing as SAMPLE_PACKER_KEY / SAMPLE_PACKER_PROMPT_KEY.
SAMPLE_DIE_KEY = "sample:die"
SAMPLE_DIE_PROMPT_KEY = "sample_die"

# The name a finding cites for this evidence. The scan is driven from
# prepare_sandbox, but the engine that produced the verdict is what a report
# reader needs to see, so that is what gets cited and what the critic allows.
DIE_TOOL_NAME = "detect_it_easy"

# Fixed scan program. No agent input reaches it: the only runtime value is the
# staged artifact path, passed as a separate argv token to `python3 -c` and never
# shell-interpreted. Failure prints a JSON error instead of raising, so the
# caller can degrade without a nonzero exit that would read as pod trouble.
_SCAN_SCRIPT = """
import json, sys
try:
    import die
    flags = die.ScanFlags.ALL_TYPES_SCAN | die.ScanFlags.RESULT_AS_JSON
    raw = die.scan_file(sys.argv[1], flags, database=str(die.database_path / "db"))
except Exception as exc:
    print(json.dumps({"arema_error": type(exc).__name__}))
else:
    print(raw.strip() or "{}")
"""

# DIE result types meaning the real code is not directly visible. Compared
# case-folded: the shipped signatures use both "Protector" and "protector".
# Installer/SFX are included because the payload sits inside a container that
# must be extracted before analysis, which is the same blocker as compression.
_PACKING_TYPES = frozenset({"packer", "protector", "cryptor", "sfx", "joiner", "installer"})

# DIE emits this as a real type and name for a file it cannot place. It carries
# no information, so it is dropped rather than reported as a detection.
_UNKNOWN = "unknown"

# A hostile sample can carry long strings in the fields DIE echoes back, and this
# result reaches a prompt. Bound every field and the number of detections.
_MAX_FIELD_CHARS = 100
_MAX_DETECTIONS = 12


def build_scan_argv(pod_path: str) -> list[str]:
    """Return the tokenized argv that runs the DIE scan against ``pod_path``."""
    return ["python3", "-c", _SCAN_SCRIPT, pod_path]


def _clean(value: object) -> str:
    """Coerce one DIE field to a bounded single-line string."""
    if not isinstance(value, str):
        return ""
    return value.replace("\n", " ").strip()[:_MAX_FIELD_CHARS]


def classify_die_output(raw: str) -> dict[str, object]:
    """Turn DIE's JSON into a packing verdict.

    Returns ``{"scanned": bool, "packed": bool, "detections": [...]}`` where each
    detection is ``{"type", "name", "version"}``. ``scanned`` is False when DIE
    did not run or its output could not be parsed -- which is not a verdict, and
    must never be read as "not packed".

    Every detect and every value is walked: a .NET assembly comes back as two
    detects (``MSDOS``/``Unknown`` and ``PE32``/``Library`` + ``Linker``), so
    stopping at the first would miss what a later one says.
    """
    unscanned: dict[str, object] = {"scanned": False, "packed": False, "detections": []}
    # The scan program always prints something, so no output at all means the
    # exec itself produced nothing -- a failure, not an empty result. DIE's own
    # "{}" is different: it ran and had nothing to say.
    if not isinstance(raw, str) or not raw.strip():
        return unscanned
    try:
        data = json.loads(raw)
    except ValueError:
        return unscanned
    if not isinstance(data, dict) or "arema_error" in data:
        return unscanned

    detections: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    detects = data.get("detects")
    for detect in detects if isinstance(detects, list) else []:
        values = detect.get("values") if isinstance(detect, dict) else None
        for value in values if isinstance(values, list) else []:
            if not isinstance(value, dict):
                continue
            kind, name = _clean(value.get("type")), _clean(value.get("name"))
            if kind.casefold() not in _PACKING_TYPES or name.casefold() == _UNKNOWN:
                continue
            key = (kind.casefold(), name.casefold())
            if key in seen:
                continue
            seen.add(key)
            detections.append({"type": kind, "name": name, "version": _clean(value.get("version"))})
    return {
        "scanned": True,
        "packed": bool(detections),
        "detections": detections[:_MAX_DETECTIONS],
    }


def summarize(verdict: dict[str, object]) -> str:
    """Render a verdict as one prompt-injectable line, or "" when there is none.

    Empty covers both "DIE found no packing" and "DIE did not run", because
    neither is evidence the sample is unpacked and the difference does not change
    what a downstream stage should claim.
    """
    detections = verdict.get("detections")
    if not verdict.get("packed") or not isinstance(detections, list):
        return ""
    parts = []
    for detection in detections:
        version = detection.get("version")
        parts.append(
            f"{detection['type']}: {detection['name']}" + (f" {version}" if version else "")
        )
    return ", ".join(parts)


def scan_staged_artifact(namespace: str, pod: str, pod_path: str) -> str:
    """Scan the staged artifact in ``pod`` and return the one-line verdict.

    Fail-open by construction, and that matters twice over. The caller runs
    inside ``prepare_sandbox``'s provision closure, where a raised exception is
    read as the pod being unhealthy and costs a fresh pod claim -- DIE being
    unavailable is not that. And a pre-validator must never be able to stop the
    pipeline it precedes: no verdict simply means no finding.
    """
    try:
        raw = kubectl_exec(build_scan_argv(pod_path), namespace, pod, timeout=_SCAN_TIMEOUT_S)
    except Exception as exc:
        logger.info(
            "detect_it_easy scan unavailable - continuing without a verdict",
            error_type=type(exc).__name__,
        )
        return ""
    return summarize(classify_die_output(raw))
