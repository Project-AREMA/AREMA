"""Workbench session-state keys and resource-governor constants.

These name the small amount of cross-call state the sandboxed Python+radare2
workbench needs: the logical pool, the global ``run_python`` execution counter,
and the per-case execution cap. The seeded per-case input filename lives with the
sandbox runtime (``deobfuscation.runtime._INPUT_NAME``) that stages it, not here.
Also holds the thrash-detector key group (see the "Thrash detector" section below).
"""

from __future__ import annotations

WORKBENCH_POOL = "analysis-workbench"
WORKBENCH_EXEC_COUNT_KEY = "workbench:exec_count"
# Global run_python cap for one analysis, shared across every deep-agent pass in
# the deobfuscation loop. A multi-layer .NET sample (unpack the compressor shell ->
# retriage -> deobfuscate the inner assembly -> extract config) legitimately needs
# many small scripts across several layers; 100 gives that headroom while still
# bounding a runaway.
WORKBENCH_MAX_EXECUTIONS = 100

# Tokens spent since the workbench's first script, and the ceiling on them.
#
# The execution cap above bounds how MANY scripts run and says nothing about what
# they cost, which is a proxy that was wrong by two orders of magnitude. Measured
# on one sample across two runs: 49 executions cost 5.19M tokens, then 91 cost
# 11.6M -- the second run hit no cap, broke nothing, and still doubled. What ends
# a run is not the count; it is that every later stage inherits the conversation
# these scripts grew, so an unbounded workbench starves the stages behind it (see
# LESSONS_LEARNED #20, where the ILSpy stage was killed before its first call).
#
# The ceiling is a backstop, not a routine limit: it sits above both observed
# healthy runs so it never truncates work that was going to succeed, and below
# the next doubling so a genuine runaway stops. A baseline is snapshotted at the
# first script so this measures the workbench's OWN spend, not a run that merely
# had an expensive triage.
WORKBENCH_TOKEN_BASELINE_KEY = "workbench:token_baseline"
WORKBENCH_MAX_TOKENS = 16_000_000

# The workbench tool ids, kept beside the other workbench constants as the single
# source of truth: the SanitizationMembrane's binary-origin set (``profiles.py``)
# and the per-tool budget guard (``budget.py``) both import them rather than
# hardcoding literals, and each equals the ``ToolDescriptor.id`` of its tool, which
# in turn equals the tool-function ``__name__`` the OutputPolicy binds on. Sharing
# one constant is why the budget guard can safely gate on ``tool.name`` without
# drifting from run_python's registered id.
RUN_PYTHON_TOOL_NAME = "run_python"
REGISTER_UNPACKED_ARTIFACT_TOOL_NAME = "register_unpacked_artifact"
WORKBENCH_TOOL_NAMES = frozenset({RUN_PYTHON_TOOL_NAME, REGISTER_UNPACKED_ARTIFACT_TOOL_NAME})

# --- Thrash detector (run_python loop) ---------------------------------------
# A run is a "strike" only when BOTH the approach and the failure class repeat
# unchanged; success or a new artifact/layer resets the streak. Keys are global
# session state (like WORKBENCH_EXEC_COUNT_KEY) so they span deobfuscation-loop
# rounds; THRASH_ARTIFACT_KEY scopes the streak to one layer.
THRASH_SIGNATURE_KEY = "workbench:thrash_signature"
THRASH_REPEAT_COUNT_KEY = "workbench:thrash_repeats"
THRASH_ARTIFACT_KEY = "workbench:thrash_artifact"
# Consecutive identical failures before the before-model advisor fires.
THRASH_STRIKE_THRESHOLD = 3
