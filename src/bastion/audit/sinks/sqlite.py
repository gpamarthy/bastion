"""A SQLite audit sink.

Writes one indexed row per audit event to a ``tool_calls`` table. The
connection is opened lazily on first emit so constructing the sink never
touches the disk.
"""

from __future__ import annotations

import json
from pathlib import Path

import aiosqlite

from bastion.audit.models import AuditEvent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tool_calls (
    trace_id          TEXT PRIMARY KEY,
    session_id        TEXT NOT NULL,
    timestamp         TEXT NOT NULL,
    server            TEXT NOT NULL,
    tool_name         TEXT NOT NULL,
    direction         TEXT NOT NULL,
    decision          TEXT NOT NULL,
    taxonomy_ids      TEXT NOT NULL,
    reason            TEXT,
    rule_results_json TEXT NOT NULL,
    arg_hash          TEXT,
    arg_preview       TEXT,
    latency_ms        REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tc_session ON tool_calls (session_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_tc_decision ON tool_calls (decision);
CREATE INDEX IF NOT EXISTS idx_tc_tool ON tool_calls (tool_name);
"""

_INSERT = """
INSERT OR REPLACE INTO tool_calls (
    trace_id, session_id, timestamp, server, tool_name, direction, decision,
    taxonomy_ids, reason, rule_results_json, arg_hash, arg_preview, latency_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class SqliteAuditSink:
    """Persists audit events to a SQLite ``tool_calls`` table."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._conn: aiosqlite.Connection | None = None

    async def _connection(self) -> aiosqlite.Connection:
        if self._conn is None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = await aiosqlite.connect(self._path)
            await self._conn.executescript(_SCHEMA)
            await self._conn.commit()
        return self._conn

    async def emit(self, event: AuditEvent) -> None:
        conn = await self._connection()
        await conn.execute(
            _INSERT,
            (
                event.trace_id,
                event.session_id,
                event.timestamp,
                event.server,
                event.tool_name,
                event.direction,
                event.decision,
                ",".join(event.taxonomy_ids),
                event.reason,
                json.dumps(list(event.rule_results), ensure_ascii=False),
                event.arg_hash,
                event.arg_preview,
                event.latency_ms,
            ),
        )
        await conn.commit()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None


__all__ = ["SqliteAuditSink"]
