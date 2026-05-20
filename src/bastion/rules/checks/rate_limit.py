"""Rate-limit rule (MCP10).

Caps tool-call volume to bound a runaway or abusive agent: a per-tool
calls-per-minute ceiling and a per-session total. State lives on the rule
instance, which is long-lived for the gateway's lifetime.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any

from bastion.core.models import ToolCall
from bastion.core.taxonomy import Severity, ThreatClass
from bastion.rules.base import Rule
from bastion.rules.registry import register
from bastion.rules.types import RuleContext, RuleResult

_WINDOW_SECONDS = 60.0


@register("rate_limit")
class RateLimitRule(Rule):
    """Blocks tool calls that exceed per-tool or per-session ceilings."""

    threat_class = ThreatClass.RATE_ABUSE
    severity = Severity.MEDIUM

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._tool_calls: dict[str, deque[float]] = defaultdict(deque)
        self._session_calls: dict[str, int] = defaultdict(int)

    async def inspect_tool_call(self, call: ToolCall, ctx: RuleContext) -> RuleResult:
        per_tool = int(self.config.get("per_tool_per_min", 0))
        per_session = int(self.config.get("per_session", 0))
        now = time.monotonic()

        if per_session > 0:
            sid = ctx.session.session_id
            self._session_calls[sid] += 1
            if self._session_calls[sid] > per_session:
                return self._block(
                    f"session exceeded {per_session} tool calls",
                    evidence={"limit": per_session, "scope": "session"},
                )

        if per_tool > 0:
            window = self._tool_calls[call.tool_name]
            while window and now - window[0] > _WINDOW_SECONDS:
                window.popleft()
            window.append(now)
            if len(window) > per_tool:
                return self._block(
                    f"tool '{call.tool_name}' exceeded {per_tool} calls/min",
                    evidence={"tool": call.tool_name, "limit": per_tool},
                )

        return self._pass()


__all__ = ["RateLimitRule"]
