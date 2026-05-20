"""JSON audit reporter."""

from __future__ import annotations

import json
from typing import Any


def render_json(events: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    """Render the audit trail as an indented JSON document."""
    return json.dumps({"summary": summary, "events": events}, indent=2, ensure_ascii=False)


__all__ = ["render_json"]
