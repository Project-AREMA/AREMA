"""Before-model callback that captures the run's originating user request.

Isolated agents (``context_mode = ISOLATED``) never see the user's message in
their conversation history. This callback runs early in the before-model chain
and stores the most recent user text in ``state[SessionKeys.USER_REQUEST]`` so
downstream agents can reference it through prompt substitution. It captures
once and never overwrites an existing value.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from arema.core.logging import get_logger
from arema.runtime.callbacks.roles import ROLE_CAPTURE_REQUEST, with_role
from arema.runtime.sessions import SessionKeys

if TYPE_CHECKING:
    from google.adk.agents.callback_context import CallbackContext
    from google.adk.models.llm_request import LlmRequest
    from google.adk.models.llm_response import LlmResponse

logger = get_logger(__name__)


@with_role(ROLE_CAPTURE_REQUEST)
async def capture_request(
    callback_context: CallbackContext,
    llm_request: LlmRequest,
) -> LlmResponse | None:
    """Store the latest non-empty user message text for downstream agents.

    Scans ``llm_request.contents`` in reverse for the most recent user turn
    carrying non-empty text and records it once. Never overwrites an existing
    capture and always returns ``None`` so the run proceeds normally.
    """
    state = callback_context.state
    if state is None:
        return None
    if state.get(SessionKeys.USER_REQUEST):
        return None

    for content in reversed(llm_request.contents or []):
        if getattr(content, "role", None) != "user":
            continue
        for part in getattr(content, "parts", None) or []:
            text = getattr(part, "text", None)
            if isinstance(text, str) and text.strip():
                state[SessionKeys.USER_REQUEST] = text
                logger.info("captured user request", text_length=len(text))
                return None

    return None
