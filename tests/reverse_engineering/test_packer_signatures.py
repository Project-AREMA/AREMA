"""Unit tests for the pure Android packer-signature detector."""

from __future__ import annotations

from reverse_engineering.tools.android.packer_signatures import detect_packer


def test_detects_jiagu_by_loader_so():
    r = detect_packer(["lib/arm64-v8a/libjiagu.so", "lib/arm64-v8a/libapp.so"], [], None)
    assert (
        r["detected"] is True and r["name"] == "jiagu" and "libjiagu.so" in " ".join(r["signals"])
    )


def test_detects_legu_variant():
    assert detect_packer(["lib/armeabi-v7a/libshellx-super.2019.so"], [], None)["name"] == "legu"


def test_clean_app_is_not_flagged():
    r = detect_packer(["lib/arm64-v8a/libnative-lib.so"], ["assets/config.json"], "com.example.App")
    assert r["detected"] is False and r["name"] is None and r["signals"] == []
