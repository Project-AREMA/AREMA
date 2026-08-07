from __future__ import annotations

from types import SimpleNamespace

from arema.runtime.sessions import SessionKeys
from arema.runtime.token_pricing import ModelPrice, PriceTable
from arema.runtime.token_usage import (
    UsageSample,
    accumulate_usage,
    build_usage_record,
    render_usage_markdown,
    usage_sample_from_metadata,
)


def _meta(prompt: int, cached: int, candidates: int, thoughts: int, total: int) -> object:
    return SimpleNamespace(
        prompt_token_count=prompt,
        cached_content_token_count=cached,
        candidates_token_count=candidates,
        thoughts_token_count=thoughts,
        total_token_count=total,
    )


def test_sample_maps_fields_and_total_matches_provider() -> None:
    meta = _meta(prompt=812004, cached=640110, candidates=41220, thoughts=12880, total=866104)
    sample = usage_sample_from_metadata(meta)
    assert sample == UsageSample(input=171894, cached=640110, output=41220, thinking=12880)
    # invariant: computed total equals the provider's total_token_count
    assert sample.total == meta.total_token_count


def test_sample_missing_fields_default_to_zero() -> None:
    sample = usage_sample_from_metadata(
        SimpleNamespace(prompt_token_count=10, candidates_token_count=5)
    )
    assert sample == UsageSample(input=10, cached=0, output=5, thinking=0)


def test_sample_none_when_metadata_absent() -> None:
    assert usage_sample_from_metadata(None) is None


def test_sample_folds_reasoning_residual_into_thinking() -> None:
    # grok-4 shape (observed in a real run): no thoughts_token_count field, and
    # reasoning tokens live only inside total_token_count (total > prompt +
    # candidates). The residual is reconciled into thinking so the sample total
    # always equals the provider's authoritative total_token_count.
    meta = SimpleNamespace(
        prompt_token_count=951,
        cached_content_token_count=128,
        candidates_token_count=17,
        total_token_count=1242,
    )
    sample = usage_sample_from_metadata(meta)
    # input = 951 - 128 = 823; residual = 1242 - (823 + 128 + 17 + 0) = 274 -> thinking
    assert sample == UsageSample(input=823, cached=128, output=17, thinking=274)
    assert sample.total == 1242  # invariant holds by construction


def test_sample_folds_reasoning_on_top_of_existing_thoughts() -> None:
    # When a provider reports BOTH thoughts and an additional total residual, the
    # residual adds to thoughts (never replaces it).
    meta = SimpleNamespace(
        prompt_token_count=100,
        cached_content_token_count=0,
        candidates_token_count=20,
        thoughts_token_count=5,
        total_token_count=150,
    )
    sample = usage_sample_from_metadata(meta)
    # residual = 150 - (100 + 0 + 20 + 5) = 25 -> thinking = 5 + 25 = 30
    assert sample == UsageSample(input=100, cached=0, output=20, thinking=30)
    assert sample.total == 150


def test_sample_does_not_fold_negative_or_absent_total() -> None:
    # A provider whose total_token_count is below the sub-field sum (or absent = 0)
    # must never reduce thinking below thoughts_token_count.
    meta = SimpleNamespace(prompt_token_count=100, candidates_token_count=20, total_token_count=0)
    sample = usage_sample_from_metadata(meta)
    assert sample == UsageSample(input=100, cached=0, output=20, thinking=0)


class _State:
    """Minimal dict-backed stand-in for ADK State (duck-typed .get/__setitem__)."""

    def __init__(self) -> None:
        self._d: dict[str, object] = {}

    def get(self, key: str, default: object = None) -> object:
        return self._d.get(key, default)

    def __setitem__(self, key: str, value: object) -> None:
        self._d[key] = value


def test_accumulate_merges_same_model() -> None:
    state = _State()
    accumulate_usage(state, "opus", UsageSample(1, 2, 3, 4), run_id="r1")
    accumulate_usage(state, "opus", UsageSample(10, 20, 30, 40), run_id="r1")
    acc = state.get(SessionKeys.MODEL_USAGE)
    assert acc["run_id"] == "r1"
    assert acc["by_model"]["opus"] == {"input": 11, "cached": 22, "output": 33, "thinking": 44}


def test_accumulate_resets_on_new_run() -> None:
    state = _State()
    accumulate_usage(state, "opus", UsageSample(1, 1, 1, 1), run_id="r1")
    accumulate_usage(state, "opus", UsageSample(5, 5, 5, 5), run_id="r2")
    acc = state.get(SessionKeys.MODEL_USAGE)
    assert acc["run_id"] == "r2"
    assert acc["by_model"] == {"opus": {"input": 5, "cached": 5, "output": 5, "thinking": 5}}


_BY_MODEL = {
    "claude-opus-4-8": {"input": 171894, "cached": 640110, "output": 41220, "thinking": 12880},
    "claude-sonnet-5": {"input": 120300, "cached": 0, "output": 9880, "thinking": 0},
}
_PRICES = PriceTable(
    {
        "claude-opus-4-8": ModelPrice(15.0, 1.5, 75.0),
        "claude-sonnet-5": ModelPrice(3.0, 0.3, 15.0),
    }
)


def test_render_has_header_rows_and_bold_total() -> None:
    md = render_usage_markdown(_BY_MODEL, _PRICES)
    assert md.startswith("## Token Usage & Cost")
    assert "| claude-opus-4-8 |" in md
    assert "171,894" in md  # thousands separators
    assert "**Total**" in md


def test_a_wholly_unpriced_run_shows_tokens_and_no_cost_column() -> None:
    """Measured: an 11,492,189-token run on two unpriced models printed $0.00,
    which reads as "this was free" rather than "nobody knows". Counts are exact
    and always shown; only the money is withheld."""
    by_model = {"mystery": {"input": 100, "cached": 0, "output": 10, "thinking": 0}}
    md = render_usage_markdown(by_model, PriceTable({}))

    assert "$0.00" not in md
    assert "Est. cost" not in md
    assert "Cost could not be calculated" in md
    assert "mystery" in md
    assert "110" in md


def test_the_unpriced_note_says_how_to_fix_it() -> None:
    md = render_usage_markdown(
        {"m": {"input": 1, "cached": 0, "output": 0, "thinking": 0}}, PriceTable({})
    )

    assert "AREMA_MODEL_PRICE_OVERRIDES" in md


def test_render_empty_accumulator_is_neutral_line() -> None:
    md = render_usage_markdown({}, _PRICES)
    assert "## Token Usage & Cost" in md
    assert "No model usage was recorded" in md


def test_build_record_shape_and_grand_total() -> None:
    rec = build_usage_record(_BY_MODEL, _PRICES, run_id="r1")
    assert rec["run_id"] == "r1"
    assert rec["by_model"]["claude-opus-4-8"]["total"] == 866104
    assert rec["grand_total"]["total"] == 996284
    assert rec["unpriced_models"] == []


def test_build_record_folds_per_model_and_grand_total_cost() -> None:
    # opus: (171894*15 + 640110*1.5 + 54100*75)/1e6 == 7.596075 -> 7.60
    # sonnet: (120300*3 + 9880*15)/1e6 == 0.5091 -> 0.51
    # grand: sum of the priced per-model costs, NOT the last row's cost
    rec = build_usage_record(_BY_MODEL, _PRICES, run_id="r1")
    assert rec["by_model"]["claude-opus-4-8"]["cost_usd"] == 7.60
    assert rec["by_model"]["claude-sonnet-5"]["cost_usd"] == 0.51
    assert rec["grand_total"]["cost_usd"] == 8.11


def test_render_bold_total_sums_priced_row_costs() -> None:
    md = render_usage_markdown(_BY_MODEL, _PRICES)
    assert "| $7.60 |" in md
    assert "| $0.51 |" in md
    assert "**$8.11**" in md  # the aggregated total, not the last row's $0.51


_MIXED = {
    "claude-opus-4-8": {"input": 171894, "cached": 640110, "output": 41220, "thinking": 12880},
    "mystery": {"input": 100, "cached": 0, "output": 10, "thinking": 0},
}


def test_a_mixed_run_reports_no_grand_total_rather_than_a_partial_one() -> None:
    """A partial sum presented as "the" cost is the same lie in smaller print.
    ``cost_complete`` distinguishes "this run was free" from "prices missing"
    without a consumer having to infer it from a zero."""
    rec = build_usage_record(_MIXED, _PRICES, run_id="r2")

    assert rec["by_model"]["claude-opus-4-8"]["cost_usd"] == 7.60
    assert rec["by_model"]["mystery"]["cost_usd"] is None
    assert rec["grand_total"]["cost_usd"] is None
    assert rec["grand_total"]["cost_complete"] is False
    assert rec["unpriced_models"] == ["mystery"]


def test_a_fully_priced_run_still_reports_its_total() -> None:
    rec = build_usage_record(_BY_MODEL, _PRICES, run_id="r1")

    assert rec["grand_total"]["cost_usd"] == 8.11
    assert rec["grand_total"]["cost_complete"] is True


def test_a_mixed_run_keeps_the_priced_rows_but_not_the_total() -> None:
    md = render_usage_markdown(_MIXED, _PRICES)

    assert "| $7.60 |" in md
    assert "**$7.60**" not in md
    assert "$0.00" not in md
    assert "Cost could not be calculated" in md
