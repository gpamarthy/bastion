"""Audit-trail reporters: JSON, HTML, and SARIF."""

from __future__ import annotations

from pathlib import Path

from bastion.audit.query import read_events, summarize
from bastion.reporters.html_reporter import render_html
from bastion.reporters.json_reporter import render_json
from bastion.reporters.sarif_reporter import render_sarif

_RENDERERS = {"json": render_json, "html": render_html, "sarif": render_sarif}


def render_report(db_path: str | Path, fmt: str) -> str:
    """Render the audit trail at ``db_path`` in the requested format."""
    if fmt not in _RENDERERS:
        raise ValueError(f"unknown report format: {fmt}")
    events = read_events(db_path)
    summary = summarize(events)
    return _RENDERERS[fmt](events, summary)


__all__ = ["render_html", "render_json", "render_report", "render_sarif"]
