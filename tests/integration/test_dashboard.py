"""Tests for the audit dashboard."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from bastion.audit.models import AuditEvent
from bastion.audit.sinks.sqlite import SqliteAuditSink
from bastion.dashboard.server import build_dashboard_app

pytestmark = pytest.mark.integration


async def _make_db(tmp_path: Path) -> Path:
    db = tmp_path / "audit.db"
    sink = SqliteAuditSink(db)
    await sink.emit(
        AuditEvent(
            trace_id="t1",
            session_id="s1",
            timestamp="2026-05-19T00:00:00+00:00",
            server="srv",
            tool_name="get_weather",
            direction="definition",
            decision="block",
            taxonomy_ids=("MCP01",),
            reason="poisoned",
        )
    )
    await sink.close()
    return db


async def _client(app: object) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://dash")


async def test_dashboard_serves_index_and_apis(tmp_path: Path) -> None:
    app = build_dashboard_app(await _make_db(tmp_path))
    async with await _client(app) as client:
        index = await client.get("/")
        assert index.status_code == 200
        assert "bastion dashboard" in index.text

        summary = await client.get("/api/summary")
        assert summary.json()["total"] == 1
        assert summary.json()["blocked"] == 1

        calls = await client.get("/api/calls")
        assert calls.json()["events"][0]["tool_name"] == "get_weather"

        health = await client.get("/health")
        assert health.json()["status"] == "ok"


async def test_dashboard_token_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BASTION_DASHBOARD_TOKEN", "s3cret")
    app = build_dashboard_app(await _make_db(tmp_path))
    async with await _client(app) as client:
        assert (await client.get("/")).status_code == 401
        assert (await client.get("/?token=s3cret")).status_code == 200
