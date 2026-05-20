"""Canonical fingerprinting of MCP tool definitions.

A fingerprint is a SHA-256 over the *canonical* JSON form of the security-
relevant fields of a tool definition (name, description, input schema). Two
definitions that are semantically identical produce the same fingerprint
regardless of key order or whitespace; any change a rug-pull attacker makes to
the description or schema changes it.
"""

from __future__ import annotations

import hashlib
import json

from bastion.core.models import ToolDefinition


def canonical_form(tool: ToolDefinition) -> str:
    """Return the canonical JSON string a fingerprint is taken over."""
    return json.dumps(
        {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.input_schema,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def fingerprint(tool: ToolDefinition) -> str:
    """Return the hex SHA-256 fingerprint of a tool definition."""
    return hashlib.sha256(canonical_form(tool).encode("utf-8")).hexdigest()


__all__ = ["canonical_form", "fingerprint"]
