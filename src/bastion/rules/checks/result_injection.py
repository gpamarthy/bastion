"""Result-injection rule (MCP07).

A tool result is untrusted data that the agent will read straight into its
context. This rule applies the same injection / obfuscation detectors used on
tool definitions to the *content* a server returns from ``tools/call``.
"""

from __future__ import annotations

from bastion.core.models import ToolCall, ToolResult
from bastion.core.taxonomy import Severity, ThreatClass
from bastion.detectors.instructions import find_injection_markers, find_invisible_chars
from bastion.detectors.patterns import iter_strings
from bastion.rules.base import Rule
from bastion.rules.registry import register
from bastion.rules.types import RuleContext, RuleResult


@register("result_injection")
class ResultInjectionRule(Rule):
    """Blocks tool results that carry injected instructions or obfuscation."""

    threat_class = ThreatClass.RESULT_INJECTION
    severity = Severity.HIGH

    async def inspect_tool_result(
        self, result: ToolResult, call: ToolCall | None, ctx: RuleContext
    ) -> RuleResult:
        markers: list[str] = []
        invisible: list[str] = []
        for text in iter_strings(result.content, include_keys=False):
            for marker in find_injection_markers(text):
                if marker not in markers:
                    markers.append(marker)
            for name in find_invisible_chars(text):
                if name not in invisible:
                    invisible.append(name)

        findings: list[str] = []
        if markers:
            findings.append("injection markers [" + ", ".join(repr(m) for m in markers[:5]) + "]")
        if invisible:
            findings.append("invisible characters [" + ", ".join(invisible[:5]) + "]")
        if not findings:
            return self._pass()

        tool = call.tool_name if call is not None else "unknown"
        return self._block(
            f"result of tool '{tool}' contains " + "; ".join(findings),
            evidence={"tool": tool, "markers": markers, "invisible_chars": invisible},
        )


__all__ = ["ResultInjectionRule"]
