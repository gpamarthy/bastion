"""Capability-grant rule (MCP08).

Enforces the policy's per-tool capability table: each ``tools/call`` is matched
against the table's glob patterns and allowed, denied, or held for approval.
The most specific match wins (an exact name beats a glob; a longer literal
beats a shorter one); unmatched tools fall back to ``default_decision``.
"""

from __future__ import annotations

import fnmatch
from typing import Any

from bastion.core.models import Decision, ToolCall
from bastion.core.taxonomy import Severity, ThreatClass
from bastion.rules.base import Rule
from bastion.rules.registry import register
from bastion.rules.schema import PolicyConfig
from bastion.rules.types import RuleContext, RuleResult

_DECISION_MAP = {
    "allow": Decision.ALLOW,
    "deny": Decision.BLOCK,
    "require_approval": Decision.REQUIRE_APPROVAL,
}


@register("capability_grant")
class CapabilityGrantRule(Rule):
    """Allow / deny / require-approval per tool, from the capability table."""

    threat_class = ThreatClass.CAPABILITY_ESCALATION
    severity = Severity.HIGH

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._grants: list[tuple[str, str, str | None]] = []
        self._default = "require_approval"

    def bind_policy(self, policy: PolicyConfig) -> None:
        self._grants = [(g.tool, g.decision, g.note) for g in policy.capabilities]
        self._default = policy.default_decision

    def _match(self, tool_name: str) -> tuple[str, str | None]:
        """Return the (decision, note) of the most specific matching grant."""
        best_rank: tuple[bool, int] | None = None
        best: tuple[str, str | None] = (self._default, None)
        for pattern, decision, note in self._grants:
            if not fnmatch.fnmatchcase(tool_name, pattern):
                continue
            rank = (pattern == tool_name, len(pattern.replace("*", "").replace("?", "")))
            if best_rank is None or rank > best_rank:
                best_rank = rank
                best = (decision, note)
        return best

    async def inspect_tool_call(self, call: ToolCall, ctx: RuleContext) -> RuleResult:
        decision_name, note = self._match(call.tool_name)
        decision = _DECISION_MAP[decision_name]
        if decision is Decision.ALLOW:
            return self._pass()
        reason = f"tool '{call.tool_name}' capability decision: {decision_name}"
        if note:
            reason = f"{reason} ({note})"
        evidence = {"tool": call.tool_name, "decision": decision_name}
        if decision is Decision.BLOCK:
            return self._block(reason, evidence=evidence)
        return self._require_approval(reason, evidence=evidence)


__all__ = ["CapabilityGrantRule"]
