"""Resource-guard rule (MCP09).

Constrains the filesystem paths and network hosts a tool call may reach.
``fs_allow`` and ``net_allow`` are allow-lists; when configured, any path or
URL argument outside them is blocked. With neither configured the rule is a
no-op, so it is safe to leave enabled.
"""

from __future__ import annotations

import fnmatch
from urllib.parse import urlparse

from bastion.core.models import ToolCall
from bastion.core.taxonomy import Severity, ThreatClass
from bastion.detectors.patterns import iter_strings
from bastion.rules.base import Rule
from bastion.rules.registry import register
from bastion.rules.types import RuleContext, RuleResult


def _is_url(value: str) -> bool:
    return value.startswith(("http://", "https://", "ftp://", "ws://", "wss://"))


def _looks_like_path(value: str) -> bool:
    if "\n" in value or len(value) > 4096:
        return False
    return value.startswith(("/", "~", "./", "../")) or ("/" in value and " " not in value.strip())


def _matches_any(value: str, globs: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(value, glob) for glob in globs)


@register("resource_guard")
class ResourceGuardRule(Rule):
    """Blocks tool-call arguments that reach outside the resource allow-lists."""

    threat_class = ThreatClass.RESOURCE_ABUSE
    severity = Severity.HIGH

    async def inspect_tool_call(self, call: ToolCall, ctx: RuleContext) -> RuleResult:
        fs_allow = list(self.config.get("fs_allow", []))
        net_allow = list(self.config.get("net_allow", []))
        if not fs_allow and not net_allow:
            return self._pass()

        violations: list[str] = []
        for value in iter_strings(call.arguments, include_keys=False):
            if _is_url(value):
                if not net_allow:
                    continue
                host = urlparse(value).hostname or ""
                if not _matches_any(host, net_allow):
                    violations.append(f"network egress to '{host}' not allowed")
            elif fs_allow and _looks_like_path(value) and not _matches_any(value, fs_allow):
                violations.append(f"filesystem path '{value}' outside allow-list")

        if not violations:
            return self._pass()
        return self._block(
            f"tool call '{call.tool_name}': {violations[0]}",
            evidence={"tool": call.tool_name, "violations": violations[:8]},
        )


__all__ = ["ResourceGuardRule"]
