"""Built-in rule checks.

Importing this package registers every check with the rule registry.
"""

from __future__ import annotations

from bastion.rules.checks import (
    arg_exfiltration,
    arg_schema,
    capability_grant,
    hidden_instructions,
    rate_limit,
    resource_guard,
    result_injection,
    rug_pull,
    shadowing,
    tool_poisoning,
)

__all__ = [
    "arg_exfiltration",
    "arg_schema",
    "capability_grant",
    "hidden_instructions",
    "rate_limit",
    "resource_guard",
    "result_injection",
    "rug_pull",
    "shadowing",
    "tool_poisoning",
]
