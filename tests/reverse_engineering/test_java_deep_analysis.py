"""Unit tests for the composite ``java_deep_analysis`` route.

An APK is analysed on two legs: jadx over its Dalvik (DEX) bytecode, then Ghidra
over one ABI's bundled native ``.so``. ``java_deep_analysis`` is a fixed-order
``SequentialAgent`` running ``java_decompile`` then ``android_native_analysis``;
the ``deep_engine_router`` routes every JVM/Android container to it, so
``java_decompile`` is no longer a direct sub-agent of the router.
"""

from __future__ import annotations

from reverse_engineering.agents.format_router import DEEP_ENGINE_ROUTER_DESCRIPTOR
from reverse_engineering.agents.java_deep_analysis import JAVA_DEEP_ANALYSIS_DESCRIPTOR


def test_java_deep_analysis_is_sequential_jadx_then_native() -> None:
    d = JAVA_DEEP_ANALYSIS_DESCRIPTOR
    assert d.id == d.name == "java_deep_analysis"
    assert d.factory.__name__ == "build_sequential_agent"
    assert d.prompt_id is None
    assert d.sub_agent_ids == ("java_decompile", "android_native_analysis")


def test_router_routes_jvm_to_java_deep_analysis() -> None:
    d = DEEP_ENGINE_ROUTER_DESCRIPTOR
    engines = d.metadata["format_engines"]
    assert engines["apk"] == "java_deep_analysis"
    assert engines["dex"] == "java_deep_analysis"
    assert engines["jar"] == "java_deep_analysis"
    assert "java_deep_analysis" in d.sub_agent_ids
    # java_decompile now lives under java_deep_analysis, not directly under the router.
    assert "java_decompile" not in d.sub_agent_ids
