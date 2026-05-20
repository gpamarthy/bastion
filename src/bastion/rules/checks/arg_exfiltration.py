"""Argument-exfiltration rule (MCP05).

Scans every string argument of a ``tools/call`` for credentials, sensitive
filesystem paths, and (opt-in) PII - the payload of a confused-deputy or
data-exfiltration attack that smuggles secrets out through a tool call.

Detectors default to ``secrets`` and ``sensitive_paths``; ``pii`` is opt-in
because honest tools routinely take an email or address as an argument.
"""

from __future__ import annotations

from bastion.core.models import ToolCall
from bastion.core.taxonomy import Severity, ThreatClass
from bastion.detectors.patterns import iter_strings
from bastion.detectors.pii import find_pii
from bastion.detectors.secrets import find_secrets, find_sensitive_paths
from bastion.rules.base import Rule
from bastion.rules.registry import register
from bastion.rules.types import RuleContext, RuleResult

_DEFAULT_DETECTORS = ("secrets", "sensitive_paths")


@register("arg_exfiltration")
class ArgExfiltrationRule(Rule):
    """Blocks tool calls whose arguments carry secrets or sensitive paths."""

    threat_class = ThreatClass.ARG_EXFILTRATION
    severity = Severity.CRITICAL

    async def inspect_tool_call(self, call: ToolCall, ctx: RuleContext) -> RuleResult:
        detectors = self.config.get("detectors", list(_DEFAULT_DETECTORS))
        max_bytes = int(self.config.get("max_arg_bytes", 65536))
        findings: list[tuple[str, str]] = []

        for value in iter_strings(call.arguments, include_keys=False):
            if len(value.encode("utf-8", "ignore")) > max_bytes:
                findings.append(("oversized_argument", f"{len(value)} chars"))
                continue
            if "secrets" in detectors:
                findings += [(f"secret:{k}", v) for k, v in find_secrets(value)]
            if "sensitive_paths" in detectors:
                findings += [("sensitive_path", p) for p in find_sensitive_paths(value)]
            if "pii" in detectors:
                findings += [(f"pii:{k}", v) for k, v in find_pii(value)]

        if not findings:
            return self._pass()
        kinds = sorted({kind for kind, _ in findings})
        return self._block(
            f"tool call '{call.tool_name}' arguments contain: {', '.join(kinds)}",
            evidence={"tool": call.tool_name, "findings": findings[:10]},
        )


__all__ = ["ArgExfiltrationRule"]
