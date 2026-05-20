"""HTML audit reporter: a self-contained static report page."""

from __future__ import annotations

import html
from typing import Any

_STYLE = """
body{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#1a1a1a;background:#fafafa}
h1{font-size:1.4rem} h2{font-size:1.05rem;margin-top:1.6rem}
table{border-collapse:collapse;width:100%;background:#fff}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #e3e3e3;font-size:13px}
th{background:#f0f0f0}
.cards{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}
.card{background:#fff;border:1px solid #e3e3e3;border-radius:6px;padding:.7rem 1.1rem;min-width:90px}
.card .n{font-size:1.5rem;font-weight:600}
.block{color:#c0392b;font-weight:600}
.require_approval{color:#b9770e;font-weight:600}
.allow{color:#1e8449}
code{background:#f0f0f0;padding:.1rem .3rem;border-radius:3px}
"""


def _decision_cell(decision: str) -> str:
    cls = html.escape(decision)
    return f'<span class="{cls}">{cls}</span>'


def _cards(summary: dict[str, Any]) -> str:
    by_decision = summary["by_decision"]
    cards = [("events", summary["total"]), ("blocked", summary["blocked"])]
    cards += [(k, v) for k, v in sorted(by_decision.items())]
    return "".join(
        f'<div class="card"><div class="n">{v}</div><div>{html.escape(k)}</div></div>'
        for k, v in cards
    )


def _rows(events: list[dict[str, Any]]) -> str:
    out: list[str] = []
    for event in events:
        taxonomy = ", ".join(event["taxonomy_ids"]) or "-"
        reason = html.escape(event.get("reason") or "")
        out.append(
            "<tr>"
            f"<td>{html.escape(event['timestamp'])}</td>"
            f"<td>{html.escape(event['direction'])}</td>"
            f"<td><code>{html.escape(event['tool_name'])}</code></td>"
            f"<td>{_decision_cell(event['decision'])}</td>"
            f"<td>{html.escape(taxonomy)}</td>"
            f"<td>{reason}</td>"
            "</tr>"
        )
    return "\n".join(out)


def render_html(
    events: list[dict[str, Any]],
    summary: dict[str, Any],
    *,
    refresh: int | None = None,
    title: str = "bastion audit report",
) -> str:
    """Render the audit trail as a standalone HTML report.

    ``refresh`` (seconds) adds a meta-refresh, used by the live dashboard.
    """
    taxonomy = summary["by_taxonomy"]
    taxonomy_rows = (
        "".join(
            f"<tr><td><code>{html.escape(k)}</code></td><td>{v}</td></tr>"
            for k, v in taxonomy.items()
        )
        or '<tr><td colspan="2">no findings</td></tr>'
    )
    refresh_tag = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">{refresh_tag}
<title>{html.escape(title)}</title><style>{_STYLE}</style></head>
<body>
<h1>{html.escape(title)}</h1>
<div class="cards">{_cards(summary)}</div>
<h2>Findings by threat class</h2>
<table><tr><th>Class</th><th>Count</th></tr>{taxonomy_rows}</table>
<h2>Events ({summary["total"]})</h2>
<table>
<tr><th>Timestamp</th><th>Direction</th><th>Tool</th><th>Decision</th>
<th>Threat</th><th>Reason</th></tr>
{_rows(events)}
</table>
</body></html>
"""


__all__ = ["render_html"]
