"""Neutral per-model token accounting: sampling, accumulation, rendering.

All numbers are computed from provider usage metadata; nothing here asks an LLM
to count anything. State access duck-types ``.get``/``__setitem__`` because ADK's
``State`` is a proxy, not a ``dict``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from arema.core.logging import get_logger
from arema.runtime.sessions import SessionKeys

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from arema.runtime.token_pricing import PriceTable

logger = get_logger(__name__)

_COUNTERS = ("input", "cached", "output", "thinking")


@dataclass(frozen=True, slots=True)
class UsageSample:
    """One model call's token counts (semantic columns)."""

    input: int
    cached: int
    output: int
    thinking: int

    @property
    def total(self) -> int:
        return self.input + self.cached + self.output + self.thinking


def _count(metadata: object, name: str) -> int:
    value = getattr(metadata, name, 0) or 0
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def usage_sample_from_metadata(metadata: object) -> UsageSample | None:
    """Map a ``GenerateContentResponseUsageMetadata`` to a :class:`UsageSample`.

    Returns ``None`` when ``metadata`` is falsy. Missing counts default to 0.
    ``Input`` is the *uncached* prompt (``prompt - cached``), clamped at 0.

    The sample is reconciled to the provider's authoritative ``total_token_count``.
    Reasoning models (e.g. grok-4) report generated reasoning tokens only inside
    ``total_token_count`` -- not in ``candidates_token_count``, and with no
    ``thoughts_token_count`` field -- so the four sub-fields undercount the
    provider total. Any positive residual ``total - (input + cached + output +
    thoughts)`` is folded into ``thinking`` (billed at the output rate, correct for
    reasoning tokens), so ``UsageSample.total`` equals the provider total by
    construction. The residual is 0 when the sub-fields already reconcile (e.g.
    Gemini) and is never folded when negative, so a provider that omits
    ``total_token_count`` is left unchanged.
    """
    if not metadata:
        return None
    cached = _count(metadata, "cached_content_token_count")
    prompt = _count(metadata, "prompt_token_count")
    output = _count(metadata, "candidates_token_count")
    thinking = _count(metadata, "thoughts_token_count")
    input_ = max(0, prompt - cached)
    residual = _count(metadata, "total_token_count") - (input_ + cached + output + thinking)
    if residual > 0:
        thinking += residual
    return UsageSample(input=input_, cached=cached, output=output, thinking=thinking)


def accumulate_usage(state: object, model: str, sample: UsageSample, run_id: str | None) -> None:
    """Fold ``sample`` into ``state[MODEL_USAGE]`` under ``model``.

    The accumulator is ``{"run_id": run_id, "by_model": {model: {counters}}}``.
    A sample whose ``run_id`` differs from the stored one re-initializes it, so a
    reused session running a second analysis never double-counts.
    """
    getter = getattr(state, "get", None)
    setter = getattr(state, "__setitem__", None)
    if not callable(getter) or not callable(setter):
        return
    acc = getter(SessionKeys.MODEL_USAGE, None)
    if not isinstance(acc, dict) or acc.get("run_id") != run_id:
        acc = {"run_id": run_id, "by_model": {}}
    by_model = acc["by_model"]
    row = by_model.get(model) or dict.fromkeys(_COUNTERS, 0)
    for name in _COUNTERS:
        row[name] += getattr(sample, name)
    by_model[model] = row
    setter(SessionKeys.MODEL_USAGE, acc)


def _row_total(row: Mapping[str, int]) -> int:
    return sum(row.get(c, 0) for c in _COUNTERS)


def _fmt(n: int) -> str:
    return f"{n:,}"


def _priced(
    by_model: Mapping[str, Mapping[str, int]], prices: PriceTable
) -> Iterator[tuple[str, Mapping[str, int], int, float | None]]:
    """Yield ``(model, row, total, cost | None)`` sorted by model id."""
    for model in sorted(by_model):
        row = by_model[model]
        cost = prices.cost_for(
            model,
            input=row.get("input", 0),
            cached=row.get("cached", 0),
            output=row.get("output", 0),
            thinking=row.get("thinking", 0),
        )
        yield model, row, _row_total(row), cost


def render_usage_markdown(by_model: Mapping[str, Mapping[str, int]], prices: PriceTable) -> str:
    """Render the per-model **Token Usage & Cost** section as a Markdown table.

    A run whose models are all unpriced reports **no** cost column rather than a
    column of ``?`` under a ``$0.00`` total. Measured: an 11,492,189-token run on
    two unpriced models printed ``$0.00``, which reads as "this was free" rather
    than "nobody knows". Token counts are always exact and always shown; only the
    money is ever withheld.
    """
    header = "## Token Usage & Cost"
    if not by_model:
        return f"{header}\n\n_No model usage was recorded for this run._"
    totals = dict.fromkeys(_COUNTERS, 0)
    cost_total = 0.0
    unpriced: list[str] = []
    rows: list[tuple[str, Mapping[str, int], int, float | None]] = []
    for model, row, total, cost in _priced(by_model, prices):
        for c in _COUNTERS:
            totals[c] += row.get(c, 0)
        if cost is None:
            unpriced.append(model)
        else:
            cost_total += cost
        rows.append((model, row, total, cost))

    priced_any = len(unpriced) < len(rows)
    cost_header = " Est. cost |" if priced_any else ""
    cost_rule = "-----------|" if priced_any else ""
    lines = [
        header,
        "",
        f"| Model | Input | Cached | Output | Thinking | Total |{cost_header}",
        f"|-------|-------|--------|--------|----------|-------|{cost_rule}",
    ]
    for model, row, total, cost in rows:
        cell = "" if not priced_any else (" ?|" if cost is None else f" ${cost:,.2f} |")
        lines.append(
            f"| {model} | {_fmt(row.get('input', 0))} | {_fmt(row.get('cached', 0))} "
            f"| {_fmt(row.get('output', 0))} | {_fmt(row.get('thinking', 0))} "
            f"| {_fmt(total)} |{cell}"
        )
    grand_total = sum(totals.values())
    # A partial sum presented as "the" cost is the same lie in smaller print, so
    # the total is money only when every model contributing to it had a price.
    total_cell = "" if not priced_any else (" n/a |" if unpriced else f" **${cost_total:,.2f}** |")
    lines.append(
        f"| **Total** | {_fmt(totals['input'])} | {_fmt(totals['cached'])} "
        f"| {_fmt(totals['output'])} | {_fmt(totals['thinking'])} "
        f"| {_fmt(grand_total)} |{total_cell}"
    )
    if unpriced:
        lines.append("")
        lines.append(
            f"_Cost could not be calculated: no price is configured for "
            f"{', '.join(unpriced)}. The token counts above are exact. "
            f"Set `AREMA_MODEL_PRICE_OVERRIDES` to price them._"
        )
    return "\n".join(lines)


def build_usage_record(
    by_model: Mapping[str, Mapping[str, int]], prices: PriceTable, run_id: str | None
) -> dict[str, object]:
    """Build the structured token-usage record persisted to session state."""
    out_models: dict[str, dict[str, object]] = {}
    totals = dict.fromkeys(_COUNTERS, 0)
    cost_total = 0.0
    unpriced: list[str] = []
    for model, row, total, cost in _priced(by_model, prices):
        for c in _COUNTERS:
            totals[c] += row.get(c, 0)
        entry: dict[str, object] = {c: row.get(c, 0) for c in _COUNTERS}
        entry["total"] = total
        if cost is None:
            entry["cost_usd"] = None
            unpriced.append(model)
        else:
            entry["cost_usd"] = round(cost, 2)
            cost_total += cost
        out_models[model] = entry
    grand: dict[str, object] = {c: totals[c] for c in _COUNTERS}
    grand["total"] = sum(totals.values())
    # ``None`` rather than a partial sum: a consumer that reads 0.0 cannot tell a
    # free run from an unpriced one, and the partial sum of a mixed run is not
    # the run's cost. ``cost_complete`` says which case this is without guessing.
    grand["cost_usd"] = None if unpriced else round(cost_total, 2)
    grand["cost_complete"] = not unpriced
    return {
        "run_id": run_id,
        "by_model": out_models,
        "grand_total": grand,
        "unpriced_models": unpriced,
    }
