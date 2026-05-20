"""Tests for the argument-inspection rules."""

from __future__ import annotations

from collections.abc import Callable

from bastion.core.models import Decision, ToolCall, ToolDefinition
from bastion.rules.checks.arg_exfiltration import ArgExfiltrationRule
from bastion.rules.checks.arg_schema import ArgSchemaRule
from bastion.rules.checks.resource_guard import ResourceGuardRule
from bastion.rules.types import RuleContext


def _call(name: str, arguments: dict) -> ToolCall:
    return ToolCall(tool_name=name, arguments=arguments, request_id=1, raw={})


# --- arg_exfiltration -----------------------------------------------------


async def test_arg_exfiltration_blocks_ssh_path(
    rule_context: Callable[..., RuleContext],
) -> None:
    rule = ArgExfiltrationRule()
    result = await rule.inspect_tool_call(
        _call("read", {"path": "/home/u/.ssh/id_rsa"}), rule_context()
    )
    assert result.decision is Decision.BLOCK


async def test_arg_exfiltration_blocks_aws_key(
    rule_context: Callable[..., RuleContext],
) -> None:
    rule = ArgExfiltrationRule()
    result = await rule.inspect_tool_call(
        _call("send", {"body": "key=AKIAIOSFODNN7EXAMPLE"}), rule_context()
    )
    assert result.decision is Decision.BLOCK


async def test_arg_exfiltration_allows_clean_arguments(
    rule_context: Callable[..., RuleContext],
) -> None:
    rule = ArgExfiltrationRule()
    result = await rule.inspect_tool_call(_call("echo", {"text": "hello world"}), rule_context())
    assert result.passed


# --- arg_schema -----------------------------------------------------------


def _pin_schema_tool(ctx: RuleContext) -> None:
    tool = ToolDefinition.from_raw(
        {
            "name": "read",
            "description": "Read a file.",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": False,
            },
        }
    )
    ctx.catalog.pin(ctx.server_label, tool)


async def test_arg_schema_blocks_type_violation(
    rule_context: Callable[..., RuleContext],
) -> None:
    ctx = rule_context()
    _pin_schema_tool(ctx)
    result = await ArgSchemaRule().inspect_tool_call(_call("read", {"path": 123}), ctx)
    assert result.decision is Decision.BLOCK


async def test_arg_schema_blocks_missing_required(
    rule_context: Callable[..., RuleContext],
) -> None:
    ctx = rule_context()
    _pin_schema_tool(ctx)
    result = await ArgSchemaRule().inspect_tool_call(_call("read", {}), ctx)
    assert result.decision is Decision.BLOCK


async def test_arg_schema_allows_valid_arguments(
    rule_context: Callable[..., RuleContext],
) -> None:
    ctx = rule_context()
    _pin_schema_tool(ctx)
    result = await ArgSchemaRule().inspect_tool_call(_call("read", {"path": "/tmp/ok"}), ctx)
    assert result.passed


async def test_arg_schema_passes_without_a_pin(
    rule_context: Callable[..., RuleContext],
) -> None:
    result = await ArgSchemaRule().inspect_tool_call(_call("x", {}), rule_context())
    assert result.passed


# --- resource_guard -------------------------------------------------------


async def test_resource_guard_blocks_path_outside_allowlist(
    rule_context: Callable[..., RuleContext],
) -> None:
    rule = ResourceGuardRule({"fs_allow": ["/workspace/*"]})
    result = await rule.inspect_tool_call(_call("read", {"path": "/etc/passwd"}), rule_context())
    assert result.decision is Decision.BLOCK


async def test_resource_guard_allows_path_inside_allowlist(
    rule_context: Callable[..., RuleContext],
) -> None:
    rule = ResourceGuardRule({"fs_allow": ["/workspace/*"]})
    result = await rule.inspect_tool_call(
        _call("read", {"path": "/workspace/notes.txt"}), rule_context()
    )
    assert result.passed


async def test_resource_guard_blocks_disallowed_network_egress(
    rule_context: Callable[..., RuleContext],
) -> None:
    rule = ResourceGuardRule({"net_allow": ["api.internal.example.com"]})
    result = await rule.inspect_tool_call(
        _call("fetch", {"url": "https://evil.example.com/steal"}), rule_context()
    )
    assert result.decision is Decision.BLOCK


async def test_resource_guard_is_noop_without_config(
    rule_context: Callable[..., RuleContext],
) -> None:
    rule = ResourceGuardRule()
    result = await rule.inspect_tool_call(_call("read", {"path": "/etc/passwd"}), rule_context())
    assert result.passed
