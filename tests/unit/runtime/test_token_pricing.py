from __future__ import annotations

from arema.runtime.token_pricing import DEFAULT_MODEL_PRICES, ModelPrice, PriceTable


def test_cost_for_known_model() -> None:
    table = PriceTable(DEFAULT_MODEL_PRICES)
    price = DEFAULT_MODEL_PRICES["claude-opus-4-8"]
    cost = table.cost_for("claude-opus-4-8", input=1_000_000, cached=0, output=0, thinking=0)
    assert cost == price.input  # 1M input tokens == exactly one input-rate unit


def test_cost_folds_thinking_into_output_rate() -> None:
    table = PriceTable({"m": ModelPrice(input=10.0, cached=1.0, output=20.0)})
    cost = table.cost_for("m", input=0, cached=0, output=500_000, thinking=500_000)
    assert cost == 20.0  # (500k + 500k) * 20/1e6


def test_provider_prefixed_model_normalizes_to_unqualified() -> None:
    table = PriceTable({"claude-opus-4-8": ModelPrice(15.0, 1.5, 75.0)})
    assert (
        table.cost_for("anthropic/claude-opus-4-8", input=1_000_000, cached=0, output=0, thinking=0)
        == 15.0
    )


def test_unpriced_model_returns_none() -> None:
    table = PriceTable({})
    assert table.cost_for("mystery-model", input=100, cached=0, output=0, thinking=0) is None


def test_bundled_table_prices_the_configured_default_models() -> None:
    # The defaults must be priced out of the box, not just the sample ids the
    # fixtures use. The default providers are google/gemini-2.0-flash and
    # anthropic/claude-sonnet-4-20250514 (config.py). A miss here means every
    # row renders "?" and the cost total is $0.00.
    table = PriceTable(DEFAULT_MODEL_PRICES)
    assert (
        table.cost_for("google/gemini-2.0-flash", input=1_000_000, cached=0, output=0, thinking=0)
        is not None
    )
    assert (
        table.cost_for(
            "anthropic/claude-sonnet-4-20250514",
            input=1_000_000,
            cached=0,
            output=0,
            thinking=0,
        )
        is not None
    )


def test_bracketed_variant_tag_shares_base_model_price() -> None:
    # A variant tag like the 1M-context marker must not fall through to unpriced.
    table = PriceTable({"claude-opus-4-8": ModelPrice(5.0, 0.5, 25.0)})
    assert (
        table.cost_for(
            "anthropic/claude-opus-4-8[1m]", input=1_000_000, cached=0, output=0, thinking=0
        )
        == 5.0
    )


def test_override_merges_over_defaults() -> None:
    from arema.core.config import Settings

    settings = Settings(
        model_price_overrides={"claude-opus-4-8": {"input": 1.0, "cached": 0.5, "output": 2.0}}
    )
    table = PriceTable.from_settings(settings)
    assert table.cost_for("claude-opus-4-8", input=1_000_000, cached=0, output=0, thinking=0) == 1.0


def test_malformed_override_is_ignored() -> None:
    from arema.core.config import Settings

    settings = Settings(model_price_overrides={"claude-opus-4-8": {"input": "not-a-number"}})  # type: ignore[dict-item]
    table = PriceTable.from_settings(settings)  # must not raise
    # falls back to the bundled default for that model
    assert (
        table.cost_for("claude-opus-4-8", input=1_000_000, cached=0, output=0, thinking=0)
        == DEFAULT_MODEL_PRICES["claude-opus-4-8"].input
    )
