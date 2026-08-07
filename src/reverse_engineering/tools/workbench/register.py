"""The ``register_unpacked_artifact`` tool: admit a recovered payload downstream.

Mirrors the deferred-factory pattern of
:mod:`reverse_engineering.tools.workbench.run_python`: a plain function cannot
see :class:`RuntimeServices`, so :func:`build_register_unpacked_artifact` closes
over the live sandbox executor (via ``context``) and returns the callable ADK
injects at call time. The inner tool is named ``register_unpacked_artifact`` so
its ``__name__`` matches the descriptor id, which the :class:`OutputPolicy`
requires to bind at compaction time.

The tool is the hand-off from the scripted workbench back into the deobfuscation
pipeline (§4.3, §13). It measures the Shannon entropy of the current (packed)
artifact, reads the recovered dump the agent wrote under the persistent
workspace, and admits it only when it passes a size-sane check plus a
format-aware validation keyed on the sample's container format
(``SAMPLE_FORMAT_KEY``, decided at ingest by ``acquire_sample``): a managed
``dotnet`` sample is admitted on a valid, loadable CLR assembly (whole-file
entropy need not drop -- metadata/token repair can leave entropy roughly flat),
while every other (native) sample keeps the original entropy-dropped-by-a-
meaningful-margin plus PE/ELF/Mach-O container gate. Both branches additionally
reject a dump identical to the current artifact -- a no-op is not a recovery.
Only then does it store the dump by SHA-256, make it the current artifact via
``CURRENT_ARTIFACT_KEY`` (exactly as ``upx.py`` does the instant UPX unpacks, so
every downstream stage transparently analyses the recovered payload), and record
``recovered <- original`` provenance in the shared deobfuscation provenance slot.
Any dump that fails a validation is rejected and the current artifact is left
untouched -- a buggy script that writes 0 bytes or a constant-byte stub can never
fabricate a false recovery that poisons the downstream artifact. Only
structured, non-content metadata is ever returned -- never raw decrypted or
decompiled bytes (§5.1).
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from typing import TYPE_CHECKING

from google.adk.tools.tool_context import (
    ToolContext,  # noqa: TC002 - runtime import: ADK resolves this annotation via get_type_hints
)

from arema.registry.descriptors import OutputPolicy, ToolDescriptor
from reverse_engineering.artifacts import ArtifactStore, default_artifacts_root
from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY, detect_format_bytes
from reverse_engineering.tools.deobfuscation.runtime import (
    MAX_RECOVERED_BYTES,
    read_bounded_file,
    stage_persistent_workspace,
)
from reverse_engineering.tools.deobfuscation.state import (
    CURRENT_ARTIFACT_KEY,
    CURRENT_ARTIFACT_PROMPT_KEY,
    SCRIPTED_RESULT_KEY,
    UPX_PROVENANCE_PROMPT_KEY,
    advance_classification_artifact,
    parse_current_classification,
)
from reverse_engineering.tools.workbench.state import (
    REGISTER_UNPACKED_ARTIFACT_TOOL_NAME,
    WORKBENCH_POOL,
)

if TYPE_CHECKING:
    from pathlib import Path

    from arema.registry.descriptors import ToolLike
    from arema.runtime.agent_factory import ToolBuildContext

_TOOL_NAME = "analysis"
# Native-sample gate only: the recovered dump must be strictly lower entropy
# than the packed input; a dump whose entropy did not drop by at least this many
# bits/byte is still packed and is rejected rather than admitted as a spurious
# "recovery". Managed (.NET) samples are gated on valid-CLR instead -- metadata
# and token repair can leave whole-file entropy roughly flat.
_MIN_ENTROPY_DROP = 0.5
# Smallest plausible recovered payload, checked before either format branch. A
# degenerate dump (an empty or constant-byte file) has entropy 0.0, so it would
# trivially "drop" against a high-entropy packed input on the native branch; the
# size floor plus the format check (PE/ELF/Mach-O for native, dotnet for
# managed) close that hole. 64 bytes is the floor for a real container: a PE's
# DOS header alone is 64 bytes (it holds e_lfanew at offset 0x3C), and
# ELF/Mach-O headers are comparable.
_MIN_RECOVERED_BYTES = 64
# Bound the model-authored method label so a single free-text argument cannot bloat
# the persisted provenance string; control characters are stripped so it stays a
# single, greppable line.
_MAX_METHOD_CHARS = 200
_ENTROPY_CHUNK_SIZE = 64 * 1024


def _shannon(counts: Counter[int], total: int) -> float:
    """Return the Shannon entropy (bits/byte) of a byte histogram."""
    if total == 0:
        return 0.0
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _entropy_bytes(data: bytes) -> float:
    """Entropy of an in-memory byte string."""
    return _shannon(Counter(data), len(data))


def _entropy_of_file(path: Path) -> float:
    """Entropy of a file streamed through a byte histogram (memory-flat).

    The packed input can be up to :data:`MAX_RECOVERED_BYTES`; streaming avoids a
    second full-file load on top of the already-resident recovered dump.
    """
    counts: Counter[int] = Counter()
    total = 0
    with path.open("rb") as source:
        while chunk := source.read(_ENTROPY_CHUNK_SIZE):
            counts.update(chunk)
            total += len(chunk)
    return _shannon(counts, total)


def _bounded_method(method: str) -> str:
    """Collapse the model-supplied method label to a bounded single line."""
    single_line = " ".join(method.split())
    return single_line[:_MAX_METHOD_CHARS]


def build_register_unpacked_artifact(context: ToolBuildContext) -> ToolLike:
    """Build ``register_unpacked_artifact`` closing over the live sandbox executor."""

    def register_unpacked_artifact(
        workspace_path: str, method: str, tool_context: ToolContext
    ) -> dict[str, object]:
        state = tool_context.state
        getter = getattr(state, "get", None)
        setter = getattr(state, "__setitem__", None)
        current = getter(CURRENT_ARTIFACT_KEY) if callable(getter) else None
        if not isinstance(current, str) or not callable(setter):
            return {"registered": False, "error": "no current artifact"}

        sample_format = getter(SAMPLE_FORMAT_KEY) if callable(getter) else None
        store = ArtifactStore(default_artifacts_root())
        entropy_before = _entropy_of_file(store.path_for(current))

        staged = stage_persistent_workspace(
            context, current, tool_context, pool=WORKBENCH_POOL, tool_name=_TOOL_NAME
        )
        # The agent may pass the path it wrote as a path relative to $WORKDIR
        # ("out.dll"), the literal env reference it ran with ("$WORKDIR/out.dll" --
        # run_python exports $WORKDIR but this Python tool does not expand it), or
        # an already-expanded absolute path ("/work/.../out.dll"). Normalize all
        # three to an absolute staged path. ``read_bounded_file`` then validates it
        # is strictly inside the workspace, so it can never escape (an absolute path
        # outside the workspace is still rejected).
        wp = workspace_path.strip()
        for prefix in ("$WORKDIR/", "${WORKDIR}/"):
            if wp.startswith(prefix):
                wp = wp[len(prefix) :]
                break
        remote_path = wp if wp.startswith("/") else f"{staged.work_dir}/{wp}"
        recovered = read_bounded_file(staged, remote_path, MAX_RECOVERED_BYTES)
        # Entropy is always measured (informational, and it is the native gate
        # below), but a degenerate dump (empty, tiny, or constant-byte) also has
        # entropy ~0.0, so it would clear a naive entropy-drop gate against a
        # high-entropy packed input and be admitted as a false recovery --
        # repointing CURRENT_ARTIFACT_KEY at garbage that every downstream stage
        # (Ghidra, radare2, evidence) then reads. Spec §4.3 requires the recovery
        # also be a plausibly-sized payload, so enforce the size floor before
        # either format branch runs.
        entropy_after = _entropy_bytes(recovered)
        if len(recovered) < _MIN_RECOVERED_BYTES:
            return {
                "registered": False,
                "error": "recovered dump is implausibly small; not a valid payload",
                "size": len(recovered),
            }
        # ``detect_format_bytes`` is the single detector for both branches: a
        # managed (.NET) sample is admitted on a valid, loadable CLR assembly --
        # whole-file entropy need not drop for legitimate metadata/token repair --
        # while a native sample keeps the entropy-drop + PE/ELF/Mach-O gate.
        # ``detect_format_bytes`` itself may raise ``struct.error`` on a
        # structurally malformed/truncated header (an MZ+PE-prefixed dump cut
        # off before the optional header, for example) -- the recovered dump is
        # untrusted, agent-script-produced sandbox output like any other
        # workbench artifact, so that must degrade to "unknown" and fall
        # through to this function's own rejection branches below, never
        # escape register_unpacked_artifact as a raw exception. Mirrors
        # deobfuscation/dotnet.py's identical guard around this same call.
        try:
            recovered_format = detect_format_bytes(recovered)
        except struct.error:
            recovered_format = "unknown"
        if sample_format == "dotnet":
            if recovered_format != "dotnet":
                return {
                    "registered": False,
                    "error": "recovered dump is not a valid .NET assembly",
                    "format": recovered_format,
                    "size": len(recovered),
                }
        else:
            if entropy_before - entropy_after < _MIN_ENTROPY_DROP:
                return {
                    "registered": False,
                    "error": "entropy did not drop; dump is still packed",
                    "entropy_before": round(entropy_before, 3),
                    "entropy_after": round(entropy_after, 3),
                }
            if recovered_format not in {"pe", "elf", "macho"}:
                return {
                    "registered": False,
                    "error": "recovered dump does not parse as a PE/ELF/Mach-O container",
                    "format": recovered_format,
                    "size": len(recovered),
                }

        new_id = store.acquire_bytes(recovered)
        if new_id == current:
            return {
                "registered": False,
                "error": "recovered dump is identical to the current artifact",
                "size": len(recovered),
            }
        # Parse the current classification BEFORE repointing the artifact keys --
        # while it still names the packed artifact, so its self-consistency check
        # passes. When register runs outside the deobfuscation loop there is no
        # classification to advance, so degrade to None gracefully.
        try:
            plan = parse_current_classification(state)
        except (ValueError, TypeError):
            plan = None
        # Mirror upx.py's full success hand-off so every downstream stage tracks
        # the recovered artifact: the canonical key, the prompt-surfaced mirror,
        # and (when present) the strict classification authority.
        setter(CURRENT_ARTIFACT_KEY, new_id)
        setter(CURRENT_ARTIFACT_PROMPT_KEY, new_id)
        if plan is not None:
            advance_classification_artifact(state, plan, new_id)
        setter(
            UPX_PROVENANCE_PROMPT_KEY,
            f"scripted_recover source={current} destination={new_id} "
            f"method={_bounded_method(method)}",
        )
        # The deterministic input deobf_gate builds its recovery finding from
        # (spec §11.5). Bound to the recovered id, matching the classification we
        # just advanced, so the gate binds the finding to the current artifact.
        setter(
            SCRIPTED_RESULT_KEY,
            {
                "source_artifact_id": current,
                "artifact_id": new_id,
                "method": _bounded_method(method),
                "entropy_before": round(entropy_before, 3),
                "entropy_after": round(entropy_after, 3),
                "format": recovered_format,
                "size": len(recovered),
            },
        )
        return {
            "registered": True,
            "artifact_id": new_id,
            "size": len(recovered),
            "entropy_before": round(entropy_before, 3),
            "entropy_after": round(entropy_after, 3),
            "format": recovered_format,
        }

    return register_unpacked_artifact


REGISTER_UNPACKED_ARTIFACT_TOOL = ToolDescriptor(
    id=REGISTER_UNPACKED_ARTIFACT_TOOL_NAME,
    description=(
        "Admit a recovered payload written under $WORKDIR back into the pipeline: "
        "for a .NET sample, validates the dump is a valid, changed CLR assembly; "
        "for a native sample, validates its entropy dropped versus the packed "
        "input and it parses as a PE/ELF/Mach-O container. Stores it by SHA-256 "
        "and makes it the current artifact for the downstream stages. Returns "
        "only structured metadata (id, size, entropy_before/after, format) -- "
        "never raw recovered content."
    ),
    factory=build_register_unpacked_artifact,
    output_policy=OutputPolicy(max_chars=2_000, max_list_items=10),
)
