"""Structural diff between two versions of a tool definition.

Used by the rug-pull rule to describe *what* drifted when a server changes a
tool after it was first pinned.
"""

from __future__ import annotations

from dataclasses import dataclass

from bastion.core.models import ToolDefinition


@dataclass(frozen=True, slots=True)
class ToolDiff:
    """What changed between a pinned tool definition and a freshly seen one."""

    name_changed: bool
    description_changed: bool
    schema_changed: bool

    @property
    def changed(self) -> bool:
        return self.name_changed or self.description_changed or self.schema_changed

    def summary(self) -> str:
        parts: list[str] = []
        if self.name_changed:
            parts.append("name")
        if self.description_changed:
            parts.append("description")
        if self.schema_changed:
            parts.append("inputSchema")
        return ", ".join(parts) if parts else "no change"


def diff_tools(old: ToolDefinition, new: ToolDefinition) -> ToolDiff:
    """Compare two tool definitions field by field."""
    return ToolDiff(
        name_changed=old.name != new.name,
        description_changed=old.description != new.description,
        schema_changed=old.input_schema != new.input_schema,
    )


__all__ = ["ToolDiff", "diff_tools"]
