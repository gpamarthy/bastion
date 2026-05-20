"""The audit dashboard: a read-only view over the audit SQLite database.

``bastion dashboard --db <path>`` serves a live HTML view plus JSON APIs.
When ``BASTION_DASHBOARD_TOKEN`` is set, every route requires a matching
``?token=`` query parameter.

Requires the ``http`` extra.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from bastion.audit.query import read_events, summarize
from bastion.reporters.html_reporter import render_html

_TOKEN_ENV = "BASTION_DASHBOARD_TOKEN"


def _check_token(request: Request) -> None:
    expected = os.environ.get(_TOKEN_ENV)
    if expected and request.query_params.get("token") != expected:
        raise HTTPException(status_code=401, detail="invalid or missing dashboard token")


def build_dashboard_app(db_path: str | Path) -> FastAPI:
    """Build the dashboard FastAPI app reading the audit DB at ``db_path``."""
    app = FastAPI(title="bastion dashboard")
    path = Path(db_path)

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> str:
        _check_token(request)
        events = read_events(path)
        return render_html(events, summarize(events), refresh=10, title="bastion dashboard")

    @app.get("/api/calls")
    def api_calls(request: Request, limit: int = 200) -> dict[str, Any]:
        _check_token(request)
        return {"events": read_events(path, limit=limit)}

    @app.get("/api/summary")
    def api_summary(request: Request) -> dict[str, Any]:
        _check_token(request)
        return summarize(read_events(path))

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "db": str(path), "exists": str(path.exists())}

    return app


__all__ = ["build_dashboard_app"]
