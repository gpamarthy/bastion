"""Read-side access to the audit trail.

Reporters and the dashboard both read recorded events through these helpers.
Reads use the synchronous ``sqlite3`` driver - simple, and fine for the
read-only reporting path.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any

_COLUMNS = (
    "trace_id",
    "session_id",
    "timestamp",
    "server",
    "tool_name",
    "direction",
    "decision",
    "taxonomy_ids",
    "reason",
    "rule_results_json",
    "arg_hash",
    "arg_preview",
    "latency_ms",
)


def read_events(db_path: str | Path, *, limit: int = 5000) -> list[dict[str, Any]]:
    """Return recorded audit events, newest first."""
    path = Path(db_path)
    if not path.exists():
        return []
    conn = sqlite3.connect(path)
    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            f"SELECT {', '.join(_COLUMNS)} FROM tool_calls ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = [dict(row) for row in cursor.fetchall()]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()
    for row in rows:
        row["taxonomy_ids"] = [t for t in (row["taxonomy_ids"] or "").split(",") if t]
        try:
            row["rule_results"] = json.loads(row.pop("rule_results_json") or "[]")
        except json.JSONDecodeError:
            row["rule_results"] = []
    return rows


def summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate counts by decision, taxonomy class, and tool."""
    by_decision: Counter[str] = Counter()
    by_taxonomy: Counter[str] = Counter()
    by_tool: Counter[str] = Counter()
    for event in events:
        by_decision[event["decision"]] += 1
        by_tool[event["tool_name"]] += 1
        for code in event["taxonomy_ids"]:
            by_taxonomy[code] += 1
    return {
        "total": len(events),
        "by_decision": dict(by_decision),
        "by_taxonomy": dict(sorted(by_taxonomy.items())),
        "by_tool": dict(by_tool.most_common(20)),
        "blocked": by_decision.get("block", 0),
    }


__all__ = ["read_events", "summarize"]
