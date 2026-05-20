"""Exception hierarchy used across bastion."""

from __future__ import annotations


class BastionError(Exception):
    """Base exception for all bastion runtime errors."""


class TransportError(BastionError):
    """Raised when an MCP transport fails to read, write, or connect."""


class FramingError(BastionError):
    """Raised when a JSON-RPC frame cannot be decoded from the wire."""


class PolicyConfigError(BastionError):
    """Raised when a policy YAML is malformed or references unknown rules."""


class RuleTimeoutError(BastionError):
    """Raised when a rule exceeds its per-rule budget."""


class BudgetExceededError(BastionError):
    """Raised when the total policy evaluation budget is exceeded."""


__all__ = [
    "BastionError",
    "BudgetExceededError",
    "FramingError",
    "PolicyConfigError",
    "RuleTimeoutError",
    "TransportError",
]
