"""Tool-shadowing rule (MCP03).

A shadowing attack registers a tool whose name collides with a trusted tool
from another server, hoping the agent calls the impostor. This rule flags a
tool definition whose name is already pinned under a *different* server and
holds it for approval.
"""

from __future__ import annotations

from bastion.core.models import ToolDefinition
from bastion.core.taxonomy import Severity, ThreatClass
from bastion.rules.base import Rule
from bastion.rules.registry import register
from bastion.rules.types import RuleContext, RuleResult


@register("shadowing")
class ShadowingRule(Rule):
    """Flags a tool whose name is also pinned by a different server."""

    threat_class = ThreatClass.TOOL_SHADOWING
    severity = Severity.MEDIUM

    async def inspect_tool_def(self, tool: ToolDefinition, ctx: RuleContext) -> RuleResult:
        others = ctx.catalog.pinned_servers_for(tool.name) - {ctx.server_label}
        if not others:
            return self._pass()
        return self._require_approval(
            f"tool '{tool.name}' is also pinned by another server "
            f"({', '.join(sorted(others))}); possible shadowing",
            evidence={"tool": tool.name, "other_servers": sorted(others)},
        )


__all__ = ["ShadowingRule"]
