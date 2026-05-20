"""SARIF 2.1.0 audit reporter.

Emits a SARIF log so bastion findings can be ingested by code-scanning
dashboards (GitHub Advanced Security, etc.). Each blocked or approval-held
event becomes one SARIF result.
"""

from __future__ import annotations

import json
from typing import Any

from bastion import __version__
from bastion.core.taxonomy import THREAT_TITLES, ThreatClass

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _rules() -> list[dict[str, Any]]:
    return [
        {
            "id": cls.value,
            "name": THREAT_TITLES[cls].replace(" ", ""),
            "shortDescription": {"text": THREAT_TITLES[cls]},
        }
        for cls in ThreatClass
    ]


def _result(event: dict[str, Any]) -> dict[str, Any]:
    rule_id = event["taxonomy_ids"][0] if event["taxonomy_ids"] else "bastion"
    level = "error" if event["decision"] == "block" else "warning"
    message = event.get("reason") or f"{event['decision']} on {event['tool_name']}"
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "properties": {
            "tool": event["tool_name"],
            "server": event["server"],
            "direction": event["direction"],
            "decision": event["decision"],
            "sessionId": event["session_id"],
            "timestamp": event["timestamp"],
        },
    }


def render_sarif(events: list[dict[str, Any]], summary: dict[str, Any]) -> str:
    """Render flagged audit events as a SARIF 2.1.0 log."""
    flagged = [e for e in events if e["decision"] != "allow"]
    log = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "bastion",
                        "informationUri": "https://github.com/gpamarthy/bastion",
                        "version": __version__,
                        "rules": _rules(),
                    }
                },
                "results": [_result(e) for e in flagged],
                "properties": {"summary": summary},
            }
        ],
    }
    return json.dumps(log, indent=2, ensure_ascii=False)


__all__ = ["render_sarif"]
