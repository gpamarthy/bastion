"""The policy engine.

The engine loads a :class:`PolicyConfig`, instantiates its rules, and runs them
against tool definitions, tool calls, and tool results. Invariants:

1. Tool-call rules run in declared order and short-circuit on the first block.
2. Tool-definition and tool-result rules continue-collect (every rule runs) so
   the verdict aggregates every finding.
3. Every rule runs under a per-rule timeout; a timeout is treated as a block.
4. A total budget is tracked; on breach the engine fails closed or open per
   ``on_budget_exceeded``.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import replace
from pathlib import Path

from bastion.catalog.registry import JsonFilePinStore, MemoryPinStore, ToolCatalog
from bastion.core import logger
from bastion.core.errors import PolicyConfigError, RuleTimeoutError
from bastion.core.models import Decision, ToolCall, ToolDefinition, ToolResult
from bastion.rules import checks as _checks  # noqa: F401  (populates the registry)
from bastion.rules import registry
from bastion.rules.base import Rule
from bastion.rules.budget import with_timeout
from bastion.rules.schema import PolicyConfig, load_policy
from bastion.rules.types import RuleContext, RuleResult, Verdict, worst

log = logger.get_logger(__name__)


def _build_catalog(policy: PolicyConfig) -> ToolCatalog:
    if policy.pin_store:
        return ToolCatalog(store=JsonFilePinStore(path=Path(policy.pin_store)))
    return ToolCatalog(store=MemoryPinStore())


class PolicyEngine:
    """A loaded, instantiated policy."""

    def __init__(self, policy: PolicyConfig, *, catalog: ToolCatalog | None = None) -> None:
        self.policy = policy
        self.catalog = catalog if catalog is not None else _build_catalog(policy)
        self._rules: list[Rule] = []
        for entry in policy.rules:
            if not entry.enabled:
                continue
            rule = registry.get(entry.id)(entry.config)
            rule.bind_policy(policy)
            self._rules.append(rule)

    @classmethod
    def from_policy_file(cls, path: Path | str) -> PolicyEngine:
        """Load a policy YAML and build the engine."""
        return cls(load_policy(Path(path)))

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    async def evaluate_tool_def(self, tool: ToolDefinition, ctx: RuleContext) -> Verdict:
        return await self._run(lambda r: r.inspect_tool_def(tool, ctx), short_circuit=False)

    async def evaluate_tool_call(self, call: ToolCall, ctx: RuleContext) -> Verdict:
        return await self._run(lambda r: r.inspect_tool_call(call, ctx), short_circuit=True)

    async def evaluate_tool_result(
        self, result: ToolResult, call: ToolCall | None, ctx: RuleContext
    ) -> Verdict:
        return await self._run(
            lambda r: r.inspect_tool_result(result, call, ctx), short_circuit=False
        )

    async def _run(
        self,
        make_coro: Callable[[Rule], Awaitable[RuleResult]],
        *,
        short_circuit: bool,
    ) -> Verdict:
        """Run every rule's hook. ``make_coro`` is called lazily per rule so a
        short-circuit never leaves an un-awaited coroutine behind."""
        results: list[RuleResult] = []
        total = 0.0
        for rule in self._rules:
            start = time.perf_counter()
            try:
                result = await with_timeout(
                    make_coro(rule),
                    timeout_ms=self.policy.per_rule_timeout_ms,
                )
            except RuleTimeoutError:
                latency = (time.perf_counter() - start) * 1000.0
                log.warning("rule timeout", rule=rule.rule_id, latency_ms=latency)
                result = RuleResult(
                    rule_id=rule.rule_id,
                    decision=Decision.BLOCK,
                    threat_class=rule.threat_class,
                    severity=rule.severity,
                    reason=f"rule timeout (>{self.policy.per_rule_timeout_ms}ms)",
                    latency_ms=latency,
                )
            else:
                if result.latency_ms <= 0.0:
                    result = replace(result, latency_ms=(time.perf_counter() - start) * 1000.0)
            results.append(result)
            total += result.latency_ms

            if short_circuit and result.decision is Decision.BLOCK:
                break
            if total > self.policy.budget_ms:
                log.warning(
                    "policy budget exceeded",
                    policy=self.policy.name,
                    total_ms=total,
                    mode=self.policy.on_budget_exceeded,
                )
                if self.policy.on_budget_exceeded == "fail_closed":
                    return Verdict(
                        decision=Decision.BLOCK,
                        results=tuple(results),
                        reason="policy evaluation budget exceeded",
                        total_latency_ms=total,
                    )
                break

        decision = worst([r.decision for r in results])
        reason = next((r.reason for r in results if not r.passed), None)
        return Verdict(
            decision=decision,
            results=tuple(results),
            reason=reason,
            total_latency_ms=total,
        )


def validate_policy(path: Path | str) -> tuple[bool, list[str]]:
    """Lightweight policy lint used by ``bastion lint``."""
    errors: list[str] = []
    try:
        policy = load_policy(Path(path))
    except PolicyConfigError as exc:
        return False, [str(exc)]
    for entry in policy.rules:
        try:
            registry.get(entry.id)
        except PolicyConfigError as exc:
            errors.append(str(exc))
    return not errors, errors


__all__ = ["PolicyEngine", "validate_policy"]
