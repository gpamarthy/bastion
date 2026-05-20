"""Hidden-instructions rule (MCP04).

Two obfuscation vectors a tool-poisoning attacker uses to slip a payload past
a human reviewer:

* invisible / bidirectional code points anywhere in the definition, and
* instruction text buried in nested ``inputSchema`` nodes (``enum``,
  ``examples``, ``$comment``, per-property descriptions) rather than the
  top-level description.

This rule deep-walks the whole definition for both.
"""

from __future__ import annotations

from bastion.core.models import ToolDefinition
from bastion.core.taxonomy import Severity, ThreatClass
from bastion.detectors.instructions import find_injection_markers, find_invisible_chars
from bastion.detectors.patterns import iter_strings
from bastion.rules.base import Rule
from bastion.rules.registry import register
from bastion.rules.types import RuleContext, RuleResult


@register("hidden_instructions")
class HiddenInstructionsRule(Rule):
    """Blocks invisible characters and instructions buried in the schema."""

    threat_class = ThreatClass.HIDDEN_INSTRUCTIONS
    severity = Severity.HIGH

    async def inspect_tool_def(self, tool: ToolDefinition, ctx: RuleContext) -> RuleResult:
        invisible: list[str] = []
        for text in (tool.description, *iter_strings(tool.input_schema)):
            for name in find_invisible_chars(text):
                if name not in invisible:
                    invisible.append(name)

        nested: list[str] = []
        for text in iter_strings(tool.input_schema, include_keys=False):
            for marker in find_injection_markers(text):
                if marker not in nested:
                    nested.append(marker)

        findings: list[str] = []
        if invisible:
            findings.append("invisible characters [" + ", ".join(invisible[:5]) + "]")
        if nested:
            findings.append(
                "instructions hidden in inputSchema ["
                + ", ".join(repr(m) for m in nested[:5])
                + "]"
            )
        if not findings:
            return self._pass()
        return self._block(
            f"tool '{tool.name}': " + "; ".join(findings),
            evidence={
                "tool": tool.name,
                "invisible_chars": invisible,
                "nested_markers": nested,
            },
        )


__all__ = ["HiddenInstructionsRule"]
