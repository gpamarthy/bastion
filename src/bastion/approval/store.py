"""Persistent store of remembered approval decisions.

An operator pre-approves (or denies) a tool with ``bastion approvals``; the
running gateway consults this store before parking a call for live approval.
Records are keyed by ``(server, tool)`` and persisted as JSON.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from bastion.core import logger
from bastion.core.models import Decision

log = logger.get_logger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class ApprovalRecord:
    """A remembered allow/deny decision for one tool on one server."""

    server: str
    tool: str
    decision: str  # "allow" | "deny"
    note: str = ""
    created: str = ""


class ApprovalStore:
    """A JSON-file-backed table of remembered approval decisions."""

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path) if path is not None else None
        self._records: dict[tuple[str, str], ApprovalRecord] = {}
        self._load()

    def _load(self) -> None:
        if self._path is None:
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("approval store unreadable", path=str(self._path), error=str(exc))
            return
        if not isinstance(data, list):
            return
        for entry in data:
            if isinstance(entry, dict):
                record = ApprovalRecord(**entry)
                self._records[(record.server, record.tool)] = record

    def _save(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            [asdict(r) for r in self._records.values()], indent=2, ensure_ascii=False
        )
        self._path.write_text(payload, encoding="utf-8")

    def decision_for(self, server: str, tool: str) -> Decision | None:
        """Return the remembered decision for a tool, or ``None`` if unknown."""
        record = self._records.get((server, tool))
        if record is None:
            return None
        return Decision.ALLOW if record.decision == "allow" else Decision.BLOCK

    def remember(self, server: str, tool: str, decision: str, note: str = "") -> None:
        """Persist an allow/deny decision for ``(server, tool)``."""
        if decision not in ("allow", "deny"):
            raise ValueError(f"decision must be allow or deny, got {decision!r}")
        self._records[(server, tool)] = ApprovalRecord(
            server=server, tool=tool, decision=decision, note=note, created=_now()
        )
        self._save()

    def revoke(self, server: str, tool: str) -> bool:
        """Forget a remembered decision. Returns True if one was removed."""
        if (server, tool) in self._records:
            del self._records[(server, tool)]
            self._save()
            return True
        return False

    def all_records(self) -> list[ApprovalRecord]:
        return sorted(self._records.values(), key=lambda r: (r.server, r.tool))


__all__ = ["ApprovalRecord", "ApprovalStore"]
