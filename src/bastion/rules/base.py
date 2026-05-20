"""The :class:`Rule` abstract base class.

Every rule declares its taxonomy class and severity at class scope and
overrides one or more of the three inspection hooks. Hooks it does not
override default to a pass, so the engine can call all hooks uniformly.
"""

from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from bastion.core.models import Decision, ToolCall, ToolDefinition, ToolResult
from bastion.core.taxonomy import Severity, ThreatClass
from bastion.rules.types import RuleContext, RuleResult

if TYPE_CHECKING:
    from bastion.rules.schema import PolicyConfig

RuleQuality = Literal["experimental", "stable"]


class Rule(ABC):
    """Base class for every policy rule.

    Subclasses MUST declare ``rule_id`` and ``threat_class`` at class scope.
    """

    rule_id: ClassVar[str]
    threat_class: ClassVar[ThreatClass]
    severity: ClassVar[Severity] = Severity.MEDIUM
    quality: ClassVar[RuleQuality] = "stable"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config: dict[str, Any] = config or {}

    def bind_policy(self, policy: PolicyConfig) -> None:  # noqa: B027
        """Receive the full policy after instantiation. Default: no-op.

        Rules that depend on policy-level data (e.g. the capability table)
        override this to capture it. Intentionally concrete, not abstract.
        """

    async def inspect_tool_def(self, tool: ToolDefinition, ctx: RuleContext) -> RuleResult:
        """Inspect a tool definition from a ``tools/list`` result."""
        return self._pass()

    async def inspect_tool_call(self, call: ToolCall, ctx: RuleContext) -> RuleResult:
        """Inspect a ``tools/call`` request before it reaches the server."""
        return self._pass()

    async def inspect_tool_result(
        self, result: ToolResult, call: ToolCall | None, ctx: RuleContext
    ) -> RuleResult:
        """Inspect a ``tools/call`` result before it reaches the client."""
        return self._pass()

    def _pass(self) -> RuleResult:
        return RuleResult(
            rule_id=self.rule_id,
            decision=Decision.ALLOW,
            threat_class=self.threat_class,
            severity=self.severity,
        )

    def _block(
        self,
        reason: str,
        *,
        score: float | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> RuleResult:
        return RuleResult(
            rule_id=self.rule_id,
            decision=Decision.BLOCK,
            threat_class=self.threat_class,
            severity=self.severity,
            reason=reason,
            score=score,
            evidence=evidence or {},
        )

    def _require_approval(
        self, reason: str, *, evidence: dict[str, Any] | None = None
    ) -> RuleResult:
        return RuleResult(
            rule_id=self.rule_id,
            decision=Decision.REQUIRE_APPROVAL,
            threat_class=self.threat_class,
            severity=self.severity,
            reason=reason,
            evidence=evidence or {},
        )


__all__ = ["Rule", "RuleQuality"]
