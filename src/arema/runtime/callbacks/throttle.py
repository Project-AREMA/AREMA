"""Before-model callback that throttles consecutive model calls.

Enforces a minimum delay between model invocations to avoid rate-limit bursts.
The interval comes from ``Settings.llm_min_call_interval`` and is disabled
(no-op) when zero. A single module-level timestamp is shared across every
agent in the process, because provider rate limits are per credential, not
per agent. The callback is fail-open: any failure logs and lets the run
proceed without throttling.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

from arema.core.config import get_settings
from arema.core.logging import get_logger
from arema.runtime.callbacks.roles import ROLE_THROTTLE_MODEL, with_role

if TYPE_CHECKING:
    from google.adk.agents.callback_context import CallbackContext
    from google.adk.models.llm_request import LlmRequest
    from google.adk.models.llm_response import LlmResponse

logger = get_logger(__name__)

# Process-wide timestamp of the last model call, shared across all agents.
_last_call_time: float = 0.0


@with_role(ROLE_THROTTLE_MODEL)
async def throttle_model_calls(
    callback_context: CallbackContext,
    llm_request: LlmRequest,
) -> LlmResponse | None:
    """Sleep the remaining interval when model calls arrive too fast.

    Never short-circuits the chain -- always returns ``None``.
    """
    global _last_call_time

    del llm_request  # request contents are irrelevant to inter-call spacing
    try:
        interval = get_settings().llm_min_call_interval
        if interval <= 0:
            return None

        now = time.monotonic()
        elapsed = now - _last_call_time
        remaining = interval - elapsed

        if remaining > 0 and _last_call_time > 0:
            agent_name = getattr(callback_context, "agent_name", "unknown")
            logger.debug(
                "throttling model call",
                agent=agent_name,
                sleep_seconds=round(remaining, 3),
            )
            await asyncio.sleep(remaining)

        _last_call_time = time.monotonic()
    except Exception:
        logger.warning("throttle_model_calls failed - continuing", exc_info=True)

    return None
