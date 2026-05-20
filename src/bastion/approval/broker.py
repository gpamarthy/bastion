"""The approval broker: parks a tool call pending an out-of-band decision.

When a rule returns ``require_approval`` and no remembered decision applies,
the interceptor parks the call here and awaits a verdict. A resolver - the
dashboard, or an operator - calls :meth:`resolve`. If nobody resolves within
the timeout the call fails closed (or open, per ``default_on_timeout``).
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field

from bastion.core import logger
from bastion.core.models import Decision

log = logger.get_logger(__name__)


@dataclass(slots=True)
class PendingApproval:
    """A tool call awaiting an approval decision."""

    key: str
    server: str
    tool: str
    reason: str
    session_id: str
    future: asyncio.Future[Decision] = field(repr=False)


class ApprovalBroker:
    """Holds pending approvals and lets a resolver decide them."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 60.0,
        default_on_timeout: Decision = Decision.BLOCK,
    ) -> None:
        self._timeout = timeout_seconds
        self._default = default_on_timeout
        self._pending: dict[str, PendingApproval] = {}

    async def request(self, *, server: str, tool: str, reason: str, session_id: str) -> Decision:
        """Park a call and await a decision; time out to the default."""
        key = uuid.uuid4().hex[:12]
        loop = asyncio.get_running_loop()
        future: asyncio.Future[Decision] = loop.create_future()
        pending = PendingApproval(
            key=key,
            server=server,
            tool=tool,
            reason=reason,
            session_id=session_id,
            future=future,
        )
        self._pending[key] = pending
        log.info("approval pending", key=key, tool=tool, server=server)
        try:
            return await asyncio.wait_for(future, timeout=self._timeout)
        except asyncio.TimeoutError:
            log.warning("approval timed out", key=key, tool=tool, default=self._default.value)
            return self._default
        finally:
            self._pending.pop(key, None)

    def pending(self) -> list[PendingApproval]:
        """Return the currently parked approvals."""
        return list(self._pending.values())

    def resolve(self, key: str, decision: Decision) -> bool:
        """Resolve a parked approval. Returns True if ``key`` was pending."""
        pending = self._pending.get(key)
        if pending is None or pending.future.done():
            return False
        pending.future.set_result(decision)
        log.info("approval resolved", key=key, decision=decision.value)
        return True


__all__ = ["ApprovalBroker", "PendingApproval"]
