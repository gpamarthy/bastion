"""Tests for tool fingerprinting and diffing."""

from __future__ import annotations

from bastion.catalog.diff import diff_tools
from bastion.catalog.fingerprint import fingerprint
from bastion.core.models import ToolDefinition


def _tool(name: str = "t", desc: str = "d", schema: dict | None = None) -> ToolDefinition:
    return ToolDefinition.from_raw(
        {"name": name, "description": desc, "inputSchema": schema or {"type": "object"}}
    )


def test_fingerprint_is_stable_across_key_order() -> None:
    a = ToolDefinition.from_raw({"name": "t", "description": "d", "inputSchema": {"a": 1, "b": 2}})
    b = ToolDefinition.from_raw({"inputSchema": {"b": 2, "a": 1}, "description": "d", "name": "t"})
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_changes_on_description() -> None:
    assert fingerprint(_tool(desc="x")) != fingerprint(_tool(desc="y"))


def test_fingerprint_changes_on_schema() -> None:
    assert fingerprint(_tool(schema={"type": "object"})) != fingerprint(
        _tool(schema={"type": "string"})
    )


def test_diff_detects_description_change() -> None:
    d = diff_tools(_tool(desc="x"), _tool(desc="y"))
    assert d.description_changed
    assert d.changed
    assert "description" in d.summary()


def test_diff_detects_schema_change() -> None:
    d = diff_tools(_tool(schema={"a": 1}), _tool(schema={"a": 2}))
    assert d.schema_changed


def test_diff_reports_no_change_for_identical_tools() -> None:
    d = diff_tools(_tool(), _tool())
    assert not d.changed
    assert d.summary() == "no change"
