"""Tests for policy loading, the rule registry, validation, and reload."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from bastion.catalog.registry import ToolCatalog
from bastion.core.errors import PolicyConfigError
from bastion.core.models import ToolDefinition
from bastion.core.taxonomy import ThreatClass
from bastion.rules import registry
from bastion.rules.base import Rule
from bastion.rules.engine import PolicyEngine, validate_policy
from bastion.rules.reload import reload_engine
from bastion.rules.schema import (
    BUNDLED_POLICIES,
    PolicyConfig,
    RuleEntry,
    load_policy,
    resolve_policy_path,
)
from bastion.rules.types import RuleContext

# --- schema loading -------------------------------------------------------


def test_load_policy_missing_file_raises() -> None:
    with pytest.raises(PolicyConfigError):
        load_policy(Path("/no/such/policy.yaml"))


def test_load_policy_rejects_invalid_yaml(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: [unclosed", encoding="utf-8")
    with pytest.raises(PolicyConfigError):
        load_policy(bad)


def test_load_policy_rejects_non_mapping(tmp_path: Path) -> None:
    bad = tmp_path / "list.yaml"
    bad.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(PolicyConfigError):
        load_policy(bad)


def test_load_policy_rejects_unknown_field(tmp_path: Path) -> None:
    bad = tmp_path / "extra.yaml"
    bad.write_text("name: x\nbogus_field: 1\n", encoding="utf-8")
    with pytest.raises(PolicyConfigError):
        load_policy(bad)


def test_bundled_policies_load_and_are_valid() -> None:
    for name in BUNDLED_POLICIES:
        ok, errors = validate_policy(resolve_policy_path(name))
        assert ok, errors


def test_resolve_policy_path_handles_names_and_paths() -> None:
    assert resolve_policy_path("default").name == "default.yaml"
    assert resolve_policy_path("/x/y.yaml") == Path("/x/y.yaml")


# --- registry -------------------------------------------------------------


def test_registry_get_unknown_rule_raises() -> None:
    with pytest.raises(PolicyConfigError):
        registry.get("no_such_rule")


def test_registry_lists_the_builtin_rules() -> None:
    rules = registry.all_rules()
    assert "tool_poisoning" in rules
    assert len(rules) >= 10


def test_registry_rejects_id_collision() -> None:
    class Impostor(Rule):
        threat_class = ThreatClass.TOOL_POISONING

    with pytest.raises(PolicyConfigError, match="collision"):
        registry.register("tool_poisoning")(Impostor)


# --- validation + engine construction -------------------------------------


def test_validate_policy_flags_unknown_rule(tmp_path: Path) -> None:
    policy = tmp_path / "p.yaml"
    policy.write_text("name: x\nrules:\n  - id: no_such_rule\n", encoding="utf-8")
    ok, errors = validate_policy(policy)
    assert not ok
    assert errors


def test_engine_skips_disabled_rules() -> None:
    engine = PolicyEngine(
        PolicyConfig(
            name="t",
            rules=[
                RuleEntry(id="tool_poisoning", enabled=False),
                RuleEntry(id="rug_pull"),
            ],
        )
    )
    assert [r.rule_id for r in engine.rules] == ["rug_pull"]


async def test_engine_budget_fail_open_does_not_block(
    rule_context: Callable[..., RuleContext],
) -> None:
    engine = PolicyEngine(
        PolicyConfig(
            name="t",
            budget_ms=5,
            per_rule_timeout_ms=500,
            on_budget_exceeded="fail_open",
            rules=[
                RuleEntry(id="test_slow", config={"sleep_ms": 40}),
                RuleEntry(id="tool_poisoning"),
            ],
        )
    )
    tool = ToolDefinition.from_raw({"name": "t", "description": "ok", "inputSchema": {}})
    verdict = await engine.evaluate_tool_def(tool, rule_context())
    assert not verdict.blocked
    assert len(verdict.results) == 1  # stopped after the budget breach


# --- reload ---------------------------------------------------------------


def test_reload_engine_reuses_the_catalog() -> None:
    catalog = ToolCatalog()
    engine = reload_engine(resolve_policy_path("minimal"), catalog=catalog)
    assert engine.catalog is catalog
    assert engine.rules
