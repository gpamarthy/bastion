"""Tests for the audit event model and sinks."""

from __future__ import annotations

import json
from pathlib import Path

import aiosqlite

from bastion.audit.models import AuditEvent, make_event, summarize_arguments
from bastion.audit.sinks.jsonl import JsonlAuditSink
from bastion.audit.sinks.sqlite import SqliteAuditSink
from bastion.core.models import Decision, ToolCall
from bastion.core.taxonomy import Severity, ThreatClass
from bastion.rules.types import RuleResult, Verdict


def _event() -> AuditEvent:
    return AuditEvent(
        trace_id="trace-1",
        session_id="sess-1",
        timestamp="2026-05-19T00:00:00+00:00",
        server="srv",
        tool_name="read_file",
        direction="request",
        decision="block",
        taxonomy_ids=("MCP05",),
        reason="secret in argument",
        rule_results=(),
        arg_hash="abc123",
        arg_preview=None,
        latency_ms=1.5,
    )


def test_summarize_arguments_modes() -> None:
    args = {"path": "/tmp/x", "depth": 2}
    h_hash, h_prev = summarize_arguments(args, "hashed")
    assert h_hash and h_prev is None

    r_hash, r_prev = summarize_arguments(args, "redacted")
    assert r_prev is not None and json.loads(r_prev) == ["depth", "path"]

    f_hash, f_prev = summarize_arguments(args, "full")
    assert f_prev is not None and "/tmp/x" in f_prev
    assert h_hash == r_hash == f_hash  # hash is mode-independent


def test_make_event_extracts_taxonomy_from_verdict() -> None:
    verdict = Verdict(
        decision=Decision.BLOCK,
        results=(
            RuleResult(
                rule_id="arg_exfiltration",
                decision=Decision.BLOCK,
                threat_class=ThreatClass.ARG_EXFILTRATION,
                severity=Severity.CRITICAL,
                reason="secret found",
            ),
        ),
        reason="secret found",
    )
    call = ToolCall(tool_name="send", arguments={"k": "v"}, request_id=1, raw={})
    event = make_event(
        session_id="s",
        server="srv",
        tool_name="send",
        direction="request",
        verdict=verdict,
        call=call,
    )
    assert event.decision == "block"
    assert event.taxonomy_ids == ("MCP05",)
    assert event.arg_hash is not None
    assert len(event.rule_results) == 1


async def test_jsonl_sink_appends_one_line_per_event(tmp_path: Path) -> None:
    sink = JsonlAuditSink(tmp_path / "audit.jsonl")
    await sink.emit(_event())
    await sink.emit(_event())
    await sink.close()

    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["tool_name"] == "read_file"


async def test_sqlite_sink_writes_queryable_row(tmp_path: Path) -> None:
    db = tmp_path / "audit.db"
    sink = SqliteAuditSink(db)
    await sink.emit(_event())
    await sink.close()

    async with aiosqlite.connect(db) as conn:
        cursor = await conn.execute(
            "SELECT decision, taxonomy_ids FROM tool_calls WHERE trace_id = ?",
            ("trace-1",),
        )
        row = await cursor.fetchone()
    assert row is not None
    assert row[0] == "block"
    assert row[1] == "MCP05"
