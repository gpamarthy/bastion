"""Shared types for the rule engine: results, verdicts, and rule context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from bastion.core.models import Decision
from bastion.core.taxonomy import Severity, ThreatClass

if TYPE_CHECKING:
    from bastion.catalog.registry import ToolCatalog
    from bastion.proxy.session import MCPSession

# Ordered worst-first: a verdict aggregates to the most severe decision present.
_DECISION_RANK: dict[Decision, int] = {
    Decision.BLOCK: 2,
    Decision.REQUIRE_APPROVAL: 1,
    Decision.ALLOW: 0,
}


def worst(decisions: list[Decision]) -> Decision:
    """Return the most severe decision in ``decisions`` (ALLOW if empty)."""
    return max(decisions, key=lambda d: _DECISION_RANK[d], default=Decision.ALLOW)


@dataclass(frozen=True, slots=True)
class RuleResult:
    """The outcome of one rule inspecting one item."""

    rule_id: str
    decision: Decision
    threat_class: ThreatClass
    severity: Severity
    reason: str | None = None
    score: float | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return self.decision is Decision.ALLOW


@dataclass(frozen=True, slots=True)
class Verdict:
    """The aggregate decision of every rule that inspected one item."""

    decision: Decision
    results: tuple[RuleResult, ...] = ()
    reason: str | None = None
    total_latency_ms: float = 0.0

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.BLOCK

    @property
    def needs_approval(self) -> bool:
        return self.decision is Decision.REQUIRE_APPROVAL

    @property
    def triggered(self) -> tuple[RuleResult, ...]:
        """The non-passing rule results, in order."""
        return tuple(r for r in self.results if not r.passed)

    @staticmethod
    def allow() -> Verdict:
        return Verdict(decision=Decision.ALLOW)


@dataclass(slots=True)
class RuleContext:
    """Everything a rule may consult beyond the item it is inspecting."""

    session: MCPSession
    catalog: ToolCatalog
    server_label: str


__all__ = ["RuleContext", "RuleResult", "Verdict", "worst"]
