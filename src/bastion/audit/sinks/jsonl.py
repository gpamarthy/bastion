"""A newline-delimited JSON audit sink."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from bastion.audit.models import AuditEvent


class JsonlAuditSink:
    """Appends one JSON object per audit event to a ``.jsonl`` file."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    async def emit(self, event: AuditEvent) -> None:
        line = json.dumps(event.as_dict(), ensure_ascii=False, separators=(",", ":"))
        async with self._lock:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    async def close(self) -> None:
        return None


__all__ = ["JsonlAuditSink"]
