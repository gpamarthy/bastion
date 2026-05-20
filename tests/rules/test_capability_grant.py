"""Tests for the capability-grant rule."""

from __future__ import annotations

from collections.abc import Callable

from bastion.core.models import Decision, ToolCall
from bastion.rules.checks.capability_grant import CapabilityGrantRule
from bastion.rules.schema import CapabilityGrant, DecisionName, PolicyConfig
from bastion.rules.types import RuleContext


def _policy(
    caps: list[tuple[str, DecisionName]], default: DecisionName = "require_approval"
) -> PolicyConfig:
    return PolicyConfig(
        name="test",
        default_decision=default,
        capabilities=[CapabilityGrant(tool=t, decision=d) for t, d in caps],
    )


def _rule(policy: PolicyConfig) -> CapabilityGrantRule:
    rule = CapabilityGrantRule()
    rule.bind_policy(policy)
    return rule


def _call(name: str) -> ToolCall:
    return ToolCall(tool_name=name, arguments={}, request_id=1, raw={})


async def test_deny_glob_blocks_call(rule_context: Callable[..., RuleContext]) -> None:
    rule = _rule(_policy([("*exec*", "deny")]))
    result = await rule.inspect_tool_call(_call("run_exec"), rule_context())
    assert result.decision is Decision.BLOCK


async def test_allow_glob_passes_call(rule_context: Callable[..., RuleContext]) -> None:
    rule = _rule(_policy([("read_*", "allow")]))
    assert (await rule.inspect_tool_call(_call("read_file"), rule_context())).passed


async def test_exact_match_beats_broader_glob(
    rule_context: Callable[..., RuleContext],
) -> None:
    rule = _rule(_policy([("*", "deny"), ("safe_tool", "allow")]))
    assert (await rule.inspect_tool_call(_call("safe_tool"), rule_context())).passed
    assert (await rule.inspect_tool_call(_call("other"), rule_context())).decision is Decision.BLOCK


async def test_unmatched_tool_uses_default_decision(
    rule_context: Callable[..., RuleContext],
) -> None:
    rule = _rule(_policy([], default="require_approval"))
    result = await rule.inspect_tool_call(_call("anything"), rule_context())
    assert result.decision is Decision.REQUIRE_APPROVAL
