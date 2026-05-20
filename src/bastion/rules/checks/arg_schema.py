"""Argument-schema rule (MCP06).

Validates a ``tools/call``'s arguments against the tool's *own* declared
``inputSchema`` (taken from the pinned definition). A call that violates the
schema the server itself published is either a buggy client or a type-confusion
attack; either way it should not reach the server unexamined.

A deliberately small JSON-Schema subset is implemented inline - type, required,
and ``additionalProperties`` - so bastion needs no schema-validation
dependency.
"""

from __future__ import annotations

from typing import Any

from bastion.core.models import ToolCall
from bastion.core.taxonomy import Severity, ThreatClass
from bastion.rules.base import Rule
from bastion.rules.registry import register
from bastion.rules.types import RuleContext, RuleResult

_TYPE_CHECKS: dict[str, Any] = {
    "string": str,
    "boolean": bool,
    "object": dict,
    "array": list,
}


def _type_ok(value: Any, type_name: str) -> bool:
    if type_name == "null":
        return value is None
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    expected = _TYPE_CHECKS.get(type_name)
    if expected is None:
        return True  # unknown type keyword: do not flag
    if type_name == "boolean":
        return isinstance(value, bool)
    return isinstance(value, expected)


def validate(value: Any, schema: dict[str, Any], path: str = "") -> list[str]:
    """Return a list of human-readable schema violations (empty if valid)."""
    errors: list[str] = []
    declared = schema.get("type")
    types = declared if isinstance(declared, list) else [declared] if declared else []
    if types and not any(_type_ok(value, str(t)) for t in types):
        errors.append(f"{path or 'value'}: expected type {'/'.join(map(str, types))}")
        return errors

    if isinstance(value, dict) and (not types or "object" in types):
        props = schema.get("properties", {})
        props = props if isinstance(props, dict) else {}
        for required in schema.get("required", []) or []:
            if required not in value:
                errors.append(f"{path}{required}: required property missing")
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in props:
                    errors.append(f"{path}{key}: additional property not allowed")
        for key, subschema in props.items():
            if key in value and isinstance(subschema, dict):
                errors += validate(value[key], subschema, f"{path}{key}.")
    return errors


@register("arg_schema")
class ArgSchemaRule(Rule):
    """Blocks tool calls whose arguments violate the declared input schema."""

    threat_class = ThreatClass.SCHEMA_VIOLATION
    severity = Severity.MEDIUM

    async def inspect_tool_call(self, call: ToolCall, ctx: RuleContext) -> RuleResult:
        pin = ctx.catalog.get_pin(ctx.server_label, call.tool_name)
        if pin is None:
            return self._pass()  # no pinned schema to validate against
        schema = pin.definition.get("inputSchema")
        if not isinstance(schema, dict):
            return self._pass()
        violations = validate(call.arguments, schema)
        if not violations:
            return self._pass()
        return self._block(
            f"tool call '{call.tool_name}' violates its inputSchema: {violations[0]}",
            evidence={"tool": call.tool_name, "violations": violations[:8]},
        )


__all__ = ["ArgSchemaRule", "validate"]
