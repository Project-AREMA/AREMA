"""Contract tests for the ``extract_android_native_libs`` tool.

The tool stages an APK inside the deobfuscation-tools pod, lists its bundled
native libraries, selects exactly one ABI (``arm64-v8a`` > ``armeabi-v7a`` > the
first present), extracts each ``.so`` under the chosen ABI (bounded by count and
per-lib size), and registers each extracted payload in the content-addressed
:class:`ArtifactStore` by SHA-256. Unlike ``register_unpacked_artifact`` it must
NEVER repoint ``CURRENT_ARTIFACT_KEY`` -- the APK itself remains the current
artifact. It self-gates on ``SAMPLE_FORMAT_KEY == "apk"`` (a bare dex/jar carries
no libs) and fails open.

The pod-facing primitives (``run_argv``/``run_argv_to_file``/``read_bounded_file``)
are monkeypatched at the module boundary so the tool's selection/bounds/registration
logic is exercised without a live pod; ``default_artifacts_root`` is redirected to a
tmp store so ``acquire_bytes`` yields real SHA-256 ids.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from arema.core.config import LLMProvider, Settings
from arema.runtime.agent_factory import ToolBuildContext
from arema.runtime.sandbox.port import ExecutionResult, SandboxHandle
from arema.runtime.services import RuntimeServices
from arema.runtime.sessions import SessionKeys
from reverse_engineering.artifacts import ArtifactStore
from reverse_engineering.tools.acquire_sample import SAMPLE_FORMAT_KEY
from reverse_engineering.tools.android import native_libs
from reverse_engineering.tools.android.native_libs import (
    EXTRACT_ANDROID_NATIVE_LIBS_TOOL,
    MAX_NATIVE_LIBS,
    build_extract_android_native_libs,
)
from reverse_engineering.tools.deobfuscation.state import CURRENT_ARTIFACT_KEY

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    import pytest

    from arema.registry.catalog import CapabilityCatalog


class _FakeExecutor:
    def __init__(self) -> None:
        self.handle = SandboxHandle(
            key="case-1", pool="deobfuscation-tools", backend_id="deobfuscation-case-1"
        )

    def claim(self, *, key: str, pool: str) -> SandboxHandle:
        del key, pool
        return self.handle

    def run(self, handle: SandboxHandle, command: str, *, timeout: float) -> ExecutionResult:
        del handle, command, timeout
        return ExecutionResult(exit_code=0, stdout="", stderr="")

    def write_file(self, handle: SandboxHandle, path: str, data: bytes) -> None:
        del handle, path, data

    def read_file(self, handle: SandboxHandle, path: str) -> bytes:
        del handle, path
        return b""

    def terminate(self, handle: SandboxHandle) -> None:
        del handle

    def release_session(self, key: str) -> None:
        del key


class _FakeState:
    """Duck-typed ADK State stand-in, deliberately not a dict subclass."""

    def __init__(self, values: dict[str, object]) -> None:
        self.values = values

    def get(self, key: str, default: object = None) -> object:
        return self.values.get(key, default)

    def __getitem__(self, key: str) -> object:
        return self.values[key]

    def __setitem__(self, key: str, value: object) -> None:
        self.values[key] = value


class _FakeToolContext:
    def __init__(self, values: dict[str, object]) -> None:
        self.state = _FakeState(values)


def _build_context(executor: _FakeExecutor) -> ToolBuildContext:
    settings = Settings(
        _env_file=None,
        llm_provider=LLMProvider.OLLAMA,
        sandbox_backend="k8s",
        sandbox_run_timeout=45,
    )
    services = RuntimeServices.default()
    return ToolBuildContext(
        settings=settings,
        services=RuntimeServices(
            clock=services.clock,
            metrics=services.metrics,
            memory_sink=services.memory_sink,
            sandbox=executor,
        ),
        catalog=cast("CapabilityCatalog", object()),
    )


def _store_artifact(tmp_path: Path, data: bytes = b"PK\x03\x04-fake-apk") -> tuple[Path, str]:
    root = tmp_path / "artifacts"
    source = tmp_path / "sample.apk"
    source.write_bytes(data)
    return root, ArtifactStore(root).acquire(source)


def _patch_artifact_root(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    import reverse_engineering.tools.deobfuscation.runtime as runtime

    monkeypatch.setattr(runtime, "default_artifacts_root", lambda: root)
    monkeypatch.setattr(native_libs, "default_artifacts_root", lambda: root)


def _tool_context(*, sample_format: str) -> _FakeToolContext:
    return _FakeToolContext(
        {
            SAMPLE_FORMAT_KEY: sample_format,
            SessionKeys.SANDBOX_CASE_ID: "case-1",
            CURRENT_ARTIFACT_KEY: "c" * 64,
        }
    )


def _patch_listing(monkeypatch: pytest.MonkeyPatch, entries: Sequence[str]) -> list[list[str]]:
    """Redirect ``run_argv`` to a static ``unzip -Z1`` listing, recording calls."""
    calls: list[list[str]] = []

    def _fake_run_argv(staged: object, argv: Sequence[str]) -> ExecutionResult:
        del staged
        calls.append(list(argv))
        return ExecutionResult(exit_code=0, stdout="\n".join(entries), stderr="")

    monkeypatch.setattr(native_libs, "run_argv", _fake_run_argv)
    return calls


def _patch_extract(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_run_argv_to_file(
        staged: object, argv: Sequence[str], output_path: str
    ) -> ExecutionResult:
        del staged, argv, output_path
        return ExecutionResult(exit_code=0, stdout="", stderr="")

    monkeypatch.setattr(native_libs, "run_argv_to_file", _fake_run_argv_to_file)


def test_picks_arm64_then_armeabi(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_root(monkeypatch, root)
    _patch_listing(
        monkeypatch,
        [
            "lib/armeabi-v7a/libfoo.so",
            "lib/arm64-v8a/libfoo.so",
            "lib/arm64-v8a/libbar.so",
            "lib/x86/libfoo.so",
        ],
    )
    _patch_extract(monkeypatch)
    monkeypatch.setattr(native_libs, "read_bounded_file", lambda _staged, path, _cap: path.encode())

    result = build_extract_android_native_libs(_build_context(_FakeExecutor()))(  # type: ignore[operator]
        artifact_id, _tool_context(sample_format="apk")
    )

    assert result["success"] is True
    assert result["abi"] == "arm64-v8a"
    libs = cast("list[dict[str, object]]", result["libs"])
    assert {lib["name"] for lib in libs} == {"libfoo.so", "libbar.so"}


def test_registers_each_so_without_repointing_current_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_root(monkeypatch, root)
    _patch_listing(monkeypatch, ["lib/arm64-v8a/libnative.so"])
    _patch_extract(monkeypatch)
    monkeypatch.setattr(
        native_libs, "read_bounded_file", lambda _staged, _path, _cap: b"ELF-native-bytes"
    )
    tool_context = _tool_context(sample_format="apk")

    result = build_extract_android_native_libs(_build_context(_FakeExecutor()))(  # type: ignore[operator]
        artifact_id, tool_context
    )

    libs = cast("list[dict[str, object]]", result["libs"])
    assert len(libs) == 1
    registered_id = cast("str", libs[0]["artifact_id"])
    assert len(registered_id) == 64
    # The registered payload is a NEW artifact, distinct from the APK, and the
    # current artifact is left pointing at the APK -- the tool must not repoint it.
    assert registered_id != artifact_id
    assert tool_context.state.values[CURRENT_ARTIFACT_KEY] == "c" * 64
    assert ArtifactStore(root).path_for(registered_id).read_bytes() == b"ELF-native-bytes"


def test_no_native_libs_is_clean_empty_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pure-Java APK: zipinfo exits 11 ("no matching files") -> clean empty."""
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_root(monkeypatch, root)

    def _fake_run_argv(staged: object, argv: Sequence[str]) -> ExecutionResult:
        del staged, argv
        return ExecutionResult(exit_code=11, stdout="", stderr="caution: filename not matched")

    monkeypatch.setattr(native_libs, "run_argv", _fake_run_argv)

    result = build_extract_android_native_libs(_build_context(_FakeExecutor()))(  # type: ignore[operator]
        artifact_id, _tool_context(sample_format="apk")
    )

    assert result["success"] is True
    assert result["abi"] is None
    assert result["libs"] == []
    assert result["skipped"] == []


def test_listing_failure_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-11 non-zero zipinfo exit is a genuine listing failure, not empty."""
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_root(monkeypatch, root)

    def _fake_run_argv(staged: object, argv: Sequence[str]) -> ExecutionResult:
        del staged, argv
        return ExecutionResult(exit_code=9, stdout="", stderr="cannot find zipfile directory")

    monkeypatch.setattr(native_libs, "run_argv", _fake_run_argv)

    result = build_extract_android_native_libs(_build_context(_FakeExecutor()))(  # type: ignore[operator]
        artifact_id, _tool_context(sample_format="apk")
    )

    assert result["success"] is False
    assert "9" in cast("str", result["error"])
    assert "abi" not in result


def test_skips_non_apk(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_listing(monkeypatch, [])
    result = build_extract_android_native_libs(_build_context(_FakeExecutor()))(  # type: ignore[operator]
        "a" * 64, _tool_context(sample_format="dex")
    )

    assert result["success"] is False
    assert result["skipped"] is True
    assert "dex" in cast("str", result["error"])
    assert calls == []  # never staged, never listed


def test_bounds_lib_count_and_size(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_root(monkeypatch, root)
    entries = [f"lib/arm64-v8a/lib{i}.so" for i in range(MAX_NATIVE_LIBS + 2)]
    _patch_listing(monkeypatch, entries)
    _patch_extract(monkeypatch)

    def _read(staged: object, path: str, cap: int) -> bytes:
        del staged, cap
        # native_2.so is over the per-lib size cap -> read_bounded_file rejects it.
        if path.endswith("native_2.so"):
            raise ValueError("remote file exceeds maximum size")
        return path.encode()

    monkeypatch.setattr(native_libs, "read_bounded_file", _read)

    result = build_extract_android_native_libs(_build_context(_FakeExecutor()))(  # type: ignore[operator]
        artifact_id, _tool_context(sample_format="apk")
    )

    assert result["success"] is True
    libs = cast("list[dict[str, object]]", result["libs"])
    skipped = cast("list[dict[str, object]]", result["skipped"])
    # 8 considered, minus the one oversized = 7 registered; 2 over-count + 1 size = 3 skipped.
    assert len(libs) == MAX_NATIVE_LIBS - 1
    assert len(skipped) == 3
    reasons = " ".join(str(s.get("reason", "")) for s in skipped)
    assert "cap" in reasons.lower()


def test_fails_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, artifact_id = _store_artifact(tmp_path)
    _patch_artifact_root(monkeypatch, root)

    def _boom(staged: object, argv: object) -> ExecutionResult:
        del staged, argv
        raise RuntimeError("pod is gone")

    monkeypatch.setattr(native_libs, "run_argv", _boom)

    result = build_extract_android_native_libs(_build_context(_FakeExecutor()))(  # type: ignore[operator]
        artifact_id, _tool_context(sample_format="apk")
    )

    assert result["success"] is False
    assert "skipped" not in result
    assert "pod is gone" in cast("str", result["error"])


def test_factory_callable_name_matches_descriptor() -> None:
    tool = build_extract_android_native_libs(_build_context(_FakeExecutor()))

    assert EXTRACT_ANDROID_NATIVE_LIBS_TOOL.id == "extract_android_native_libs"
    assert tool.__name__ == EXTRACT_ANDROID_NATIVE_LIBS_TOOL.id  # type: ignore[union-attr]
