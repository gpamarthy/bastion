"""Pydantic models for the YAML policy file.

The on-disk YAML is the source of truth; see ``src/bastion/policies/*.yaml``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from bastion.core.errors import PolicyConfigError

DecisionName = Literal["allow", "deny", "require_approval"]


class CapabilityGrant(BaseModel):
    """One entry in the capability table: a tool glob and its decision."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    decision: DecisionName
    note: str | None = None


class RuleEntry(BaseModel):
    """One rule entry in the policy ``rules`` list."""

    model_config = ConfigDict(extra="forbid")

    id: str
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)


class AuditConfig(BaseModel):
    """Audit sink configuration."""

    model_config = ConfigDict(extra="forbid")

    sink: Literal["sqlite", "jsonl", "none"] = "sqlite"
    path: str | None = None
    retention_days: int = 90
    record_arguments: Literal["full", "redacted", "hashed"] = "redacted"


class ApprovalConfig(BaseModel):
    """Approval-flow configuration."""

    model_config = ConfigDict(extra="forbid")

    store: str | None = None
    timeout_seconds: float = 60.0
    on_unresolved: Literal["block", "allow"] = "block"


class PolicyConfig(BaseModel):
    """Top-level policy loaded from YAML."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: int = 1
    budget_ms: int = 500
    per_rule_timeout_ms: int = 100
    on_budget_exceeded: Literal["fail_open", "fail_closed"] = "fail_closed"
    default_decision: DecisionName = "require_approval"
    pin_store: str | None = None
    capabilities: list[CapabilityGrant] = Field(default_factory=list)
    rules: list[RuleEntry] = Field(default_factory=list)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    approval: ApprovalConfig = Field(default_factory=ApprovalConfig)


_BUNDLED_DIR = Path(__file__).resolve().parent.parent / "policies"
BUNDLED_POLICIES = ("default", "strict", "minimal")


def resolve_policy_path(name_or_path: str) -> Path:
    """Resolve a bundled policy name (``default``/``strict``/``minimal``) or a
    filesystem path to a concrete :class:`Path`."""
    if name_or_path in BUNDLED_POLICIES:
        return _BUNDLED_DIR / f"{name_or_path}.yaml"
    return Path(name_or_path)


def load_policy(path: Path) -> PolicyConfig:
    """Load and validate a policy YAML file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyConfigError(f"cannot read policy file: {path}: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyConfigError(f"policy file must be a YAML mapping: {path}")
    try:
        return PolicyConfig.model_validate(data)
    except Exception as exc:
        raise PolicyConfigError(f"invalid policy in {path}: {exc}") from exc


__all__ = [
    "BUNDLED_POLICIES",
    "ApprovalConfig",
    "AuditConfig",
    "CapabilityGrant",
    "DecisionName",
    "PolicyConfig",
    "RuleEntry",
    "load_policy",
    "resolve_policy_path",
]
