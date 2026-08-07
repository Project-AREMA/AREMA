"""Tests for the content-addressed ArtifactStore.

The store hashes a file's bytes with SHA-256, writes them to ``<root>/<sha256>``,
and returns the hex digest. Identical content always resolves to the same
artifact id and is never rewritten.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from reverse_engineering.artifacts.store import ArtifactStore

if TYPE_CHECKING:
    from pathlib import Path


def test_acquire_content_addresses_by_sha256(tmp_path: Path) -> None:
    store_dir = tmp_path / "store"
    store = ArtifactStore(store_dir)

    payload = b"arema-artifact-payload"
    src_a = tmp_path / "a.bin"
    src_b = tmp_path / "b.bin"
    src_a.write_bytes(payload)
    src_b.write_bytes(payload)

    id_a = store.acquire(src_a)
    id_b = store.acquire(src_b)

    expected = hashlib.sha256(payload).hexdigest()
    assert id_a == id_b == expected
    assert len(id_a) == 64
    assert all(c in "0123456789abcdef" for c in id_a)
    assert (store_dir / id_a).read_bytes() == payload


def test_acquire_dedups_identical_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import reverse_engineering.artifacts.store as store_mod

    store = ArtifactStore(tmp_path / "store")
    src = tmp_path / "sample.bin"
    src.write_bytes(b"duplicate-me")

    calls = 0
    real_copyfile = store_mod.shutil.copyfile

    def counting_copyfile(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return real_copyfile(*args, **kwargs)

    monkeypatch.setattr(store_mod.shutil, "copyfile", counting_copyfile)

    first = store.acquire(src)
    second = store.acquire(src)

    assert first == second
    assert calls == 1


def test_acquire_hashes_large_file_in_chunks(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "store")
    src = tmp_path / "big.bin"
    payload = bytes((i % 256) for i in range(70_000))
    src.write_bytes(payload)

    artifact_id = store.acquire(src)

    expected = hashlib.sha256(payload).hexdigest()
    assert artifact_id == expected
    assert (tmp_path / "store" / artifact_id).read_bytes() == payload


def test_acquire_missing_source_raises_file_not_found(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "store")

    with pytest.raises(FileNotFoundError):
        store.acquire(tmp_path / "does-not-exist.bin")


def test_path_for_resolves_under_root(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "store")

    assert store.path_for("deadbeef") == tmp_path / "store" / "deadbeef"


def test_acquire_creates_root_lazily(tmp_path: Path) -> None:
    store_dir = tmp_path / "nested" / "does-not-exist-yet" / "store"
    assert not store_dir.exists()

    store = ArtifactStore(store_dir)
    src = tmp_path / "sample.bin"
    src.write_bytes(b"lazy-root")

    artifact_id = store.acquire(src)

    assert store_dir.is_dir()
    assert (store_dir / artifact_id).read_bytes() == b"lazy-root"


def test_acquire_handles_empty_file(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "store")
    src = tmp_path / "empty.bin"
    src.write_bytes(b"")

    artifact_id = store.acquire(src)

    assert artifact_id == hashlib.sha256(b"").hexdigest()
    assert (tmp_path / "store" / artifact_id).read_bytes() == b""


def test_acquire_bytes_content_addresses_and_persists(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "store")
    payload = b"recovered-from-sandbox"

    artifact_id = store.acquire_bytes(payload)

    assert artifact_id == hashlib.sha256(payload).hexdigest()
    assert store.path_for(artifact_id).read_bytes() == payload


def test_acquire_bytes_is_idempotent(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "store")
    payload = b"same-recovery"

    first = store.acquire_bytes(payload)
    original_mtime = store.path_for(first).stat().st_mtime_ns
    second = store.acquire_bytes(payload)

    assert first == second
    assert store.path_for(second).stat().st_mtime_ns == original_mtime
