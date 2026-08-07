"""Reverse-engineering capability library (engines + generic RE agents).

This is an importable library, NOT a discoverable ADK domain (no ``agent.py``).
Mindset domains import the descriptors + :func:`register_re_infrastructure` and
compose their own agent tree.
"""

from __future__ import annotations

from reverse_engineering.agents.android_native_analysis import ANDROID_NATIVE_ANALYSIS_DESCRIPTOR
from reverse_engineering.agents.android_triage import ANDROID_TRIAGE_DESCRIPTOR
from reverse_engineering.agents.de4dot_deobfuscate import DE4DOT_DEOBFUSCATE_DESCRIPTOR
from reverse_engineering.agents.deep_analysis import DEEP_ANALYSIS_DESCRIPTOR
from reverse_engineering.agents.deep_analysis_gate import DEEP_ANALYSIS_GATE_DESCRIPTOR
from reverse_engineering.agents.deep_decompile import DEEP_DECOMPILE_WORKER_DESCRIPTOR
from reverse_engineering.agents.deobf_classify import DEOBF_CLASSIFY_DESCRIPTOR
from reverse_engineering.agents.deobf_gate import DEOBF_GATE_DESCRIPTOR
from reverse_engineering.agents.deobfuscation import (
    DEOBFUSCATION_DESCRIPTOR,
    DEOBFUSCATION_LOOP_DESCRIPTOR,
)
from reverse_engineering.agents.dnlib_roundtrip import DNLIB_ROUNDTRIP_DESCRIPTOR
from reverse_engineering.agents.dotnet_analyst import DOTNET_ANALYST_DESCRIPTOR
from reverse_engineering.agents.dotnet_decompile import DOTNET_DECOMPILE_DESCRIPTOR
from reverse_engineering.agents.dotnet_native_analysis import DOTNET_NATIVE_ANALYSIS_DESCRIPTOR
from reverse_engineering.agents.dotnet_native_pivot import (
    DOTNET_DEEP_ANALYSIS_DESCRIPTOR,
    DOTNET_NATIVE_PIVOT_DESCRIPTOR,
)
from reverse_engineering.agents.dotnet_scripted_recover import DOTNET_SCRIPTED_RECOVER_DESCRIPTOR
from reverse_engineering.agents.evidence_critic import EVIDENCE_CRITIC_DESCRIPTOR
from reverse_engineering.agents.floss_decode import FLOSS_DECODE_DESCRIPTOR
from reverse_engineering.agents.format_gate import DOTNET_RECOVER_DESCRIPTOR
from reverse_engineering.agents.format_router import DEEP_ENGINE_ROUTER_DESCRIPTOR
from reverse_engineering.agents.java_decompile import JAVA_DECOMPILE_DESCRIPTOR
from reverse_engineering.agents.java_deep_analysis import JAVA_DEEP_ANALYSIS_DESCRIPTOR
from reverse_engineering.agents.packer_analyst import PACKER_ANALYST_DESCRIPTOR
from reverse_engineering.agents.recover import RECOVER_DESCRIPTOR
from reverse_engineering.agents.recovery_skip import RECOVERY_SKIP_DESCRIPTOR
from reverse_engineering.agents.report_generator import REPORT_GENERATOR_DESCRIPTOR
from reverse_engineering.agents.retriage import RETRIAGE_DESCRIPTOR
from reverse_engineering.agents.sample_intake import SAMPLE_INTAKE_DESCRIPTOR
from reverse_engineering.agents.scripted_recover import SCRIPTED_RECOVER_DESCRIPTOR
from reverse_engineering.agents.triage_recon import TRIAGE_RECON_DESCRIPTOR
from reverse_engineering.agents.triage_router import TRIAGE_ROUTER_DESCRIPTOR
from reverse_engineering.agents.upx_unpack import UPX_UNPACK_DESCRIPTOR
from reverse_engineering.composition import register_re_infrastructure

__all__ = [
    "ANDROID_NATIVE_ANALYSIS_DESCRIPTOR",
    "ANDROID_TRIAGE_DESCRIPTOR",
    "DE4DOT_DEOBFUSCATE_DESCRIPTOR",
    "DNLIB_ROUNDTRIP_DESCRIPTOR",
    "DEOBF_CLASSIFY_DESCRIPTOR",
    "DEOBF_GATE_DESCRIPTOR",
    "DEOBFUSCATION_DESCRIPTOR",
    "DEOBFUSCATION_LOOP_DESCRIPTOR",
    "DEEP_ANALYSIS_DESCRIPTOR",
    "DEEP_ANALYSIS_GATE_DESCRIPTOR",
    "DEEP_DECOMPILE_WORKER_DESCRIPTOR",
    "DEEP_ENGINE_ROUTER_DESCRIPTOR",
    "DOTNET_ANALYST_DESCRIPTOR",
    "DOTNET_DECOMPILE_DESCRIPTOR",
    "DOTNET_DEEP_ANALYSIS_DESCRIPTOR",
    "DOTNET_NATIVE_ANALYSIS_DESCRIPTOR",
    "DOTNET_NATIVE_PIVOT_DESCRIPTOR",
    "DOTNET_RECOVER_DESCRIPTOR",
    "DOTNET_SCRIPTED_RECOVER_DESCRIPTOR",
    "EVIDENCE_CRITIC_DESCRIPTOR",
    "FLOSS_DECODE_DESCRIPTOR",
    "JAVA_DECOMPILE_DESCRIPTOR",
    "JAVA_DEEP_ANALYSIS_DESCRIPTOR",
    "PACKER_ANALYST_DESCRIPTOR",
    "RECOVER_DESCRIPTOR",
    "RECOVERY_SKIP_DESCRIPTOR",
    "REPORT_GENERATOR_DESCRIPTOR",
    "RETRIAGE_DESCRIPTOR",
    "SAMPLE_INTAKE_DESCRIPTOR",
    "SCRIPTED_RECOVER_DESCRIPTOR",
    "TRIAGE_RECON_DESCRIPTOR",
    "TRIAGE_ROUTER_DESCRIPTOR",
    "UPX_UNPACK_DESCRIPTOR",
    "register_re_infrastructure",
]
