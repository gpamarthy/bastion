"""Tests for the audit reporters."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bastion.audit.models import AuditEvent
from bastion.audit.query import read_events
from bastion.audit.sinks.sqlite import SqliteAuditSink
from bastion.reporters import render_report


def _event(trace: str, tool: str, decision: str, taxonomy: tuple[str, ...]) -> AuditEvent:
    return AuditEvent(
        trace_id=trace,
        session_id="sess-1",
        timestamp="2026-05-19T00:00:00+00:00",
        server="srv",
        tool_name=tool,
        direction="definition" if taxonomy else "request",
        decision=decision,
        taxonomy_ids=taxonomy,
        reason="poisoned tool" if decision == "block" else None,
        latency_ms=0.5,
    )


async def _make_db(tmp_path: Path) -> Path:
    db = tmp_path / "audit.db"
    sink = SqliteAuditSink(db)
    await sink.emit(_event("t1", "get_weather", "block", ("MCP01",)))
    await sink.emit(_event("t2", "echo", "allow", ()))
    await sink.close()
    return db


async def test_json_report_has_summary_and_events(tmp_path: Path) -> None:
    data = json.loads(render_report(await _make_db(tmp_path), "json"))
    assert data["summary"]["total"] == 2
    assert data["summary"]["blocked"] == 1
    assert len(data["events"]) == 2


async def test_sarif_report_is_valid_2_1_0(tmp_path: Path) -> None:
    log = json.loads(render_report(await _make_db(tmp_path), "sarif"))
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "bastion"
    assert len(run["results"]) == 1  # only the blocked event
    assert run["results"][0]["ruleId"] == "MCP01"


async def test_html_report_renders_the_tool_name(tmp_path: Path) -> None:
    html = render_report(await _make_db(tmp_path), "html")
    assert "<html" in html
    assert "get_weather" in html


def test_render_report_rejects_unknown_format() -> None:
    with pytest.raises(ValueError, match="unknown report format"):
        render_report("missing.db", "xml")


def test_read_events_on_missing_db_is_empty() -> None:
    assert read_events("/no/such/path.db") == []
