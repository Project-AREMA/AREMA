"""Extract an APK's bundled native libraries (one ABI) into registered artifacts.

An APK ships its JNI code as ``lib/<abi>/*.so`` entries -- often several ABIs of
the *same* library. This tool stages the (untrusted) APK **inside the
deobfuscation-tools sandbox pod** -- never in the AREMA process -- lists its
native entries, selects exactly one ABI (``arm64-v8a`` > ``armeabi-v7a`` > the
first present, so the same library is never analysed twice), extracts each
``.so`` under that ABI (bounded by :data:`MAX_NATIVE_LIBS` and each lib's size),
reads the bytes back, and registers each in the content-addressed
:class:`ArtifactStore` by SHA-256 so ``android_native_analysis`` can drive Ghidra
over each ``artifact_id``.

It mirrors :func:`reverse_engineering.tools.workbench.register.register_unpacked_artifact`'s
``ArtifactStore`` use (store bytes -> sha256 id) but deliberately does **NOT**
repoint ``CURRENT_ARTIFACT_KEY``: the extracted ``.so`` are a fan-out *alongside*
the APK, not a replacement of it -- the APK stays the current artifact so the
jadx (DEX) leg keeps analysing it. Self-gating: only an ``apk`` carries libs (a
bare ``dex``/``jar`` returns a skip without claiming a pod). Fail-open: any
staging, pod, or parse failure degrades to ``{"success": False, "error": ...}``
and never raises into the run. Only structured metadata (ABI, lib names, sha256
ids) is ever returned -- never raw ``.so`` bytes.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from google.adk.tools.tool_context import (
    ToolContext,  # noqa: TC002 - runtime import: ADK resolves this annotation via get_type_hints
)

from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from reverse_engineering.artifacts import ArtifactStore, default_artifacts_root
from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY
from reverse_engineering.tools.android.triage_scan import MAX_ANDROID_INPUT_BYTES
from reverse_engineering.tools.deobfuscation.runtime import (
    read_bounded_file,
    run_argv,
    run_argv_to_file,
    stage_artifact,
)

if TYPE_CHECKING:
    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext

_TOOL_NAME = "extract_android_native_libs"
# Never analyse the same library across ABIs: one ABI is chosen, preferring
# 64-bit arm, then 32-bit arm, then whatever is present first.
_ABI_PREFERENCE = ("arm64-v8a", "armeabi-v7a")
# Bound the fan-out: at most this many .so from the chosen ABI are extracted; the
# rest are recorded as a limitation. Ghidra analysis is the expensive stage
# downstream, so this cap protects the whole native leg, not just extraction.
MAX_NATIVE_LIBS = 8
# Per-.so byte cap. A native library above this is recorded as skipped rather
# than staged into an artifact; read_bounded_file enforces it via a size preflight
# and raises before transferring an oversized file.
MAX_NATIVE_LIB_BYTES = 64 * 1024 * 1024
# A native-library zip entry: exactly ``lib/<abi>/<name>.so`` (no nested dirs).
_LIB_ENTRY = re.compile(r"^lib/([^/]+)/([^/]+\.so)$")
# Info-ZIP zipinfo (``unzip -Z1``) exits 11 -- "no matching files were found" --
# for a valid APK that bundles NO ``lib/*`` entries (a pure Java/Kotlin app). That
# is a clean-empty listing, not a failure, so it falls through to the abi-is-None
# path rather than being reported as a listing error.
_ZIPINFO_NO_MATCH = 11


def _group_native_entries(listing: str) -> dict[str, list[str]]:
    """Group ``lib/<abi>/*.so`` entries by ABI, preserving first-seen ABI order."""
    grouped: dict[str, list[str]] = {}
    for raw in listing.splitlines():
        match = _LIB_ENTRY.match(raw.strip())
        if match is None:
            continue
        grouped.setdefault(match.group(1), []).append(raw.strip())
    return grouped


def _select_abi(grouped: dict[str, list[str]]) -> tuple[str | None, list[str]]:
    """Pick one ABI: arm64-v8a > armeabi-v7a > the first present; None if empty."""
    for preferred in _ABI_PREFERENCE:
        if preferred in grouped:
            return preferred, grouped[preferred]
    for abi, entries in grouped.items():
        return abi, entries
    return None, []


def build_extract_android_native_libs(context: ToolBuildContext) -> ToolLike:
    """Build ``extract_android_native_libs`` closing over the live sandbox executor."""

    def extract_android_native_libs(
        artifact_id: str, tool_context: ToolContext
    ) -> dict[str, object]:
        """Extract one ABI's ``.so`` from an APK into registered SHA-256 artifacts."""
        state = getattr(tool_context, "state", None)
        getter = getattr(state, "get", None)
        sample_format = getter(SAMPLE_FORMAT_KEY) if callable(getter) else None
        # Only an APK bundles native libs; a bare dex/jar carries none, so skip
        # without ever claiming a pod (mirrors android_triage_scan's self-gate).
        if sample_format != "apk":
            return {
                "success": False,
                "skipped": True,
                "error": f"extract_android_native_libs handles apk; got {sample_format}",
            }

        try:
            staged = stage_artifact(
                context,
                artifact_id,
                tool_context,
                tool_name=_TOOL_NAME,
                max_input_bytes=MAX_ANDROID_INPUT_BYTES,
            )
            listing = run_argv(staged, ["unzip", "-Z1", staged.input_path, "lib/*"])
            # Exit 11 means the APK simply has no native libs -> empty listing,
            # handled by the abi-is-None clean-empty path below; any other
            # non-zero code is a genuine listing failure.
            if listing.exit_code not in (0, _ZIPINFO_NO_MATCH):
                return {
                    "success": False,
                    "error": f"listing native libs exited {listing.exit_code}",
                }

            abi, entries = _select_abi(_group_native_entries(listing.stdout))
            skipped: list[dict[str, object]] = []
            libs: list[dict[str, object]] = []
            if abi is None:
                return {"success": True, "abi": None, "libs": libs, "skipped": skipped}

            # Bound the count: extras past the cap are recorded, not extracted.
            for extra in entries[MAX_NATIVE_LIBS:]:
                skipped.append({"name": extra.rsplit("/", 1)[-1], "reason": "over max lib count"})

            store = ArtifactStore(default_artifacts_root())
            for index, entry in enumerate(entries[:MAX_NATIVE_LIBS]):
                name = entry.rsplit("/", 1)[-1]
                out_path = f"{staged.work_dir}/native_{index}.so"
                extracted = run_argv_to_file(
                    staged, ["unzip", "-p", staged.input_path, entry], out_path
                )
                if extracted.exit_code != 0:
                    skipped.append(
                        {"name": name, "reason": f"extract exited {extracted.exit_code}"}
                    )
                    continue
                try:
                    payload = read_bounded_file(staged, out_path, MAX_NATIVE_LIB_BYTES)
                except ValueError:
                    # read_bounded_file's size preflight rejects an over-cap .so.
                    skipped.append({"name": name, "reason": "exceeds per-lib size cap"})
                    continue
                except (OSError, TimeoutError, RuntimeError) as exc:
                    skipped.append({"name": name, "reason": f"read failed: {exc}"})
                    continue
                # Store the .so bytes by SHA-256 -- a NEW artifact alongside the APK.
                # Deliberately NOT repointed onto CURRENT_ARTIFACT_KEY (unlike
                # register_unpacked_artifact): the APK stays current for the jadx leg.
                libs.append({"name": name, "artifact_id": store.acquire_bytes(payload)})

            return {"success": True, "abi": abi, "libs": libs, "skipped": skipped}
        except Exception as exc:  # fail-open: a hostile APK must never crash the run
            return {"success": False, "error": str(exc)}

    return extract_android_native_libs


EXTRACT_ANDROID_NATIVE_LIBS_TOOL = ToolDescriptor(
    id="extract_android_native_libs",
    description=(
        "Extract an APK's bundled native libraries for one ABI (arm64-v8a > "
        "armeabi-v7a > first present) inside the deobfuscation sandbox and register "
        "each .so in the artifact store by SHA-256. Bounds the count and per-lib "
        "size; does NOT change the current artifact (the APK stays current for the "
        "DEX leg). Returns only structured metadata (abi, lib names, artifact ids) "
        "-- never raw native bytes."
    ),
    factory=build_extract_android_native_libs,
    output_policy=OutputPolicy(max_chars=4_000, max_list_items=20),
)
