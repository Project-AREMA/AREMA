"""Before-model callback that enforces per-agent turn limits.

Prevents any single agent from consuming an unbounded number of model calls,
which guarantees later steps in a multi-agent run still get to execute. Each
agent keeps an independent turn counter in session state. When the counter
reaches the agent's limit the callback injects a wrap-up directive (soft
stop); after a short grace window it returns a terminal response (hard stop)
so a controlling sequential runner advances to the next step.

Limits come from ``Settings.agent_turn_limits`` (per agent), falling back to
``Settings.default_turn_limit``. The callback is fail-open.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from google.adk.models.llm_response import LlmResponse
from google.genai import types as genai_types

from arema.core.config import get_settings
from arema.core.logging import get_logger
from arema.runtime.callbacks._llm_request import append_to_system_instruction
from arema.runtime.callbacks.roles import ROLE_ENFORCE_TURN_LIMIT, with_role
from arema.runtime.sessions import SessionKeys

if TYPE_CHECKING:
    from google.adk.agents.callback_context import CallbackContext
    from google.adk.models.llm_request import LlmRequest

logger = get_logger(__name__)

# Turns granted after the limit is first hit, during which the agent may still
# act (to save its work) before a hard stop forces advancement.
_GRACE_TURNS = 2


@with_role(ROLE_ENFORCE_TURN_LIMIT)
async def enforce_turn_limit(
    callback_context: CallbackContext,
    llm_request: LlmRequest,
) -> LlmResponse | None:
    """Increment the agent's turn counter and enforce its limit.

    Returns ``None`` below the limit and during the soft-stop grace window;
    returns a terminal ``LlmResponse`` once the grace window is exhausted.
    """
    try:
        settings = get_settings()
        agent_name = getattr(callback_context, "agent_name", "") or ""
        state = callback_context.state
        if state is None:
            return None

        turn_key = f"{SessionKeys.TURN_COUNT}:{agent_name}"
        turn_count = int(state.get(turn_key, 0)) + 1
        state[turn_key] = turn_count

        limit = settings.agent_turn_limits.get(agent_name, settings.default_turn_limit)

        if turn_count < limit:
            return None

        if turn_count < limit + _GRACE_TURNS:
            append_to_system_instruction(
                llm_request,
                (
                    f"\n\n[TURN LIMIT REACHED - {turn_count}/{limit}]\n"
                    "You have reached the turn limit for this run. Produce your "
                    "final summary response now and do not start new work.\n"
                ),
            )
            logger.info("turn limit soft stop", agent=agent_name, turn=turn_count, limit=limit)
            return None

        logger.warning("turn limit hard stop", agent=agent_name, turn=turn_count, limit=limit)
        return LlmResponse(
            content=genai_types.Content(
                role="model",
                parts=[
                    genai_types.Part(
                        text=(
                            f"[Run step '{agent_name}' stopped: turn limit ({limit}) exceeded. "
                            "Advancing to the next step.]"
                        )
                    )
                ],
            ),
        )
    except Exception:
        logger.warning("enforce_turn_limit failed - continuing", exc_info=True)
        return None
