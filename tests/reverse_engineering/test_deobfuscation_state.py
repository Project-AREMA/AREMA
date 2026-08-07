from reverse_engineering.tools.deobfuscation.state import (
    DEOBF_MAX_ITERATIONS,
    SCRIPTED_ATTEMPTED_KEY,
    SCRIPTED_RESULT_KEY,
    reset_deobfuscation_state,
)


def test_de4dot_keys_defined_and_reset() -> None:
    from reverse_engineering.tools.deobfuscation.state import (
        DE4DOT_CALLED_KEY,
        DE4DOT_RESULT_KEY,
        reset_deobfuscation_state,
    )

    assert DE4DOT_RESULT_KEY == "deobf:de4dot_result"
    state: dict[str, object] = {
        DE4DOT_CALLED_KEY: True,
        DE4DOT_RESULT_KEY: {"x": 1},
    }
    reset_deobfuscation_state(state, "a" * 64)
    assert state[DE4DOT_RESULT_KEY] is None
    assert state[DE4DOT_CALLED_KEY] is False


def test_scripted_keys_and_cap_are_defined() -> None:
    assert SCRIPTED_RESULT_KEY == "deobf:scripted_result"
    assert SCRIPTED_ATTEMPTED_KEY == "deobf:scripted_attempted"
    assert DEOBF_MAX_ITERATIONS == 6


def test_reset_clears_scripted_keys() -> None:
    state: dict[str, object] = {
        SCRIPTED_RESULT_KEY: {"artifact_id": "b" * 64},
        SCRIPTED_ATTEMPTED_KEY: True,
    }
    reset_deobfuscation_state(state, "a" * 64)
    assert state[SCRIPTED_RESULT_KEY] is None
    assert state[SCRIPTED_ATTEMPTED_KEY] is False


def test_reset_clears_thrash_keys() -> None:
    from reverse_engineering.tools.workbench.state import (
        THRASH_ARTIFACT_KEY,
        THRASH_REPEAT_COUNT_KEY,
        THRASH_SIGNATURE_KEY,
    )

    state: dict[str, object] = {
        THRASH_SIGNATURE_KEY: "de4dot|InvalidCastException",
        THRASH_REPEAT_COUNT_KEY: 3,
        THRASH_ARTIFACT_KEY: "b" * 64,
    }
    reset_deobfuscation_state(state, "a" * 64)
    assert state[THRASH_SIGNATURE_KEY] == ""
    assert state[THRASH_REPEAT_COUNT_KEY] == 0
    assert state[THRASH_ARTIFACT_KEY] == ""
