"""Rug-pull rule (MCP02).

A rug-pull attack ships a benign tool, waits for it to be approved, then
silently swaps in a malicious definition. This rule pins the fingerprint of
each tool the first time it is seen (trust on first use) and blocks any later
definition that drifts from the pinned baseline until it is re-approved.

Pinning a poisoned first-seen definition is not a gap: the tool-poisoning and
hidden-instruction rules inspect every definition on every list, drift or not.
"""

from __future__ import annotations

from bastion.catalog.diff import diff_tools
from bastion.catalog.fingerprint import fingerprint
from bastion.core.models import ToolDefinition
from bastion.core.taxonomy import Severity, ThreatClass
from bastion.rules.base import Rule
from bastion.rules.registry import register
from bastion.rules.types import RuleContext, RuleResult


@register("rug_pull")
class RugPullRule(Rule):
    """Blocks a tool definition that drifts from its pinned baseline."""

    threat_class = ThreatClass.RUG_PULL
    severity = Severity.CRITICAL

    async def inspect_tool_def(self, tool: ToolDefinition, ctx: RuleContext) -> RuleResult:
        server = ctx.server_label
        current = fingerprint(tool)
        pin = ctx.catalog.get_pin(server, tool.name)

        if pin is None:
            if self.config.get("pin_on_first_seen", True):
                ctx.catalog.pin(server, tool)
            return self._pass()

        if pin.fingerprint == current:
            ctx.catalog.touch(server, tool.name)
            return self._pass()

        drift = diff_tools(ToolDefinition.from_raw(pin.definition), tool)
        count = ctx.catalog.record_drift(server, tool.name)
        return self._block(
            f"tool '{tool.name}' definition changed since it was pinned "
            f"(drift in: {drift.summary()})",
            evidence={
                "tool": tool.name,
                "drift": drift.summary(),
                "pinned_fingerprint": pin.fingerprint,
                "current_fingerprint": current,
                "drift_count": count,
            },
        )


__all__ = ["RugPullRule"]
