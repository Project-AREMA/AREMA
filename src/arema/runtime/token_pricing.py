"""Neutral per-model token pricing.

Rates are expressed per 1,000,000 tokens. Thinking tokens are billed at the
output rate. A model absent from the table is *unpriced*: ``cost_for`` returns
``None`` and callers must exclude it from any cost total rather than assume zero.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from arema.core.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Mapping

    from arema.core.config import Settings

logger = get_logger(__name__)

_PER_MILLION = 1_000_000


@dataclass(frozen=True, slots=True)
class ModelPrice:
    """USD rates per 1,000,000 tokens."""

    input: float
    cached: float
    output: float


# Bundled defaults (USD per 1M tokens; cached == prompt-cache read, ~0.1x input).
# Keyed by the normalized model id (see ``_normalize``). Keep the ids the
# codebase actually configures priced out of the box -- the default providers
# (``gemini-2.0-flash``, ``claude-sonnet-4-20250514``) plus the current Claude
# generations agents can be pointed at via ``AREMA_AGENT_MODEL_OVERRIDES``.
# Any model not listed here is *unpriced* until an ``AREMA_MODEL_PRICE_OVERRIDES``
# entry supplies rates.
DEFAULT_MODEL_PRICES: dict[str, ModelPrice] = {
    # Anthropic Claude.
    "claude-opus-4-8": ModelPrice(input=5.0, cached=0.5, output=25.0),
    "claude-opus-4-7": ModelPrice(input=5.0, cached=0.5, output=25.0),
    "claude-opus-4-6": ModelPrice(input=5.0, cached=0.5, output=25.0),
    "claude-sonnet-5": ModelPrice(input=3.0, cached=0.3, output=15.0),
    "claude-sonnet-4-6": ModelPrice(input=3.0, cached=0.3, output=15.0),
    "claude-sonnet-4-20250514": ModelPrice(input=3.0, cached=0.3, output=15.0),
    "claude-haiku-4-5": ModelPrice(input=1.0, cached=0.1, output=5.0),
    "claude-fable-5": ModelPrice(input=10.0, cached=1.0, output=50.0),
    # Google Gemini.
    "gemini-2.0-flash": ModelPrice(input=0.1, cached=0.025, output=0.4),
}


def _normalize(model: str) -> str:
    """Normalize a model id for table lookup.

    Strips a provider prefix (``anthropic/claude-opus-4-8`` -> ``claude-opus-4-8``)
    and a trailing bracketed variant tag such as the 1M-context marker
    (``claude-opus-4-8[1m]`` -> ``claude-opus-4-8``), so a variant shares its base
    model's price rather than falling through to unpriced.
    """
    base = model.rsplit("/", 1)[-1]
    bracket = base.find("[")
    if bracket != -1:
        base = base[:bracket]
    return base


class PriceTable:
    """An immutable price lookup with provider-prefix normalization."""

    def __init__(self, prices: Mapping[str, ModelPrice]) -> None:
        self._prices = dict(prices)

    @classmethod
    def from_settings(cls, settings: Settings) -> PriceTable:
        prices = dict(DEFAULT_MODEL_PRICES)
        for model, raw in (settings.model_price_overrides or {}).items():
            try:
                prices[model] = ModelPrice(
                    input=float(raw["input"]),
                    cached=float(raw["cached"]),
                    output=float(raw["output"]),
                )
            except (KeyError, TypeError, ValueError):
                logger.warning("ignoring malformed price override", model=model)
        return cls(prices)

    def _lookup(self, model: str) -> ModelPrice | None:
        return self._prices.get(model) or self._prices.get(_normalize(model))

    def cost_for(
        self, model: str, *, input: int, cached: int, output: int, thinking: int
    ) -> float | None:
        """Return USD cost for the counts, or ``None`` when the model is unpriced."""
        price = self._lookup(model)
        if price is None:
            return None
        return (
            input * price.input + cached * price.cached + (output + thinking) * price.output
        ) / _PER_MILLION
