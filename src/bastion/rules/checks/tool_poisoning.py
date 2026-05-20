"""Tool-poisoning rule (MCP01).

Scans a tool's human-readable ``description`` for instruction-injection
markers - the payload an attacker hides there to hijack the agent that reads
the catalog. Deep schema inspection is the job of the hidden-instructions rule.
"""

from __future__ import annotations

from bastion.core.models import ToolDefinition
from bastion.core.taxonomy import Severity, ThreatClass
from bastion.detectors.instructions import find_injection_markers
from bastion.rules.base import Rule
from bastion.rules.registry import register
from bastion.rules.types import RuleContext, RuleResult


@register("tool_poisoning")
class ToolPoisoningRule(Rule):
    """Blocks tool definitions whose description carries injected instructions."""

    threat_class = ThreatClass.TOOL_POISONING
    severity = Severity.CRITICAL

    async def inspect_tool_def(self, tool: ToolDefinition, ctx: RuleContext) -> RuleResult:
        markers = find_injection_markers(tool.description)
        if not markers:
            return self._pass()
        score = min(1.0, 0.5 + 0.15 * len(markers))
        return self._block(
            f"tool '{tool.name}' description contains injection markers: "
            + ", ".join(repr(m) for m in markers[:5]),
            score=score,
            evidence={"tool": tool.name, "markers": markers},
        )


__all__ = ["ToolPoisoningRule"]
