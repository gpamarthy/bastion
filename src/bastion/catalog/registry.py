"""The tool catalog and its pin store.

The catalog remembers the first-approved fingerprint of every tool it has seen
(the *pin*) so the rug-pull rule can detect a later definition that drifts from
it. Pins persist between runs through a :class:`PinStore`; within a run the
catalog also tracks which servers expose which tool names, for shadowing
detection.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from bastion.catalog.fingerprint import fingerprint
from bastion.core import logger
from bastion.core.models import ToolDefinition

log = logger.get_logger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class PinnedTool:
    """The approved baseline definition of one tool on one server."""

    server: str
    name: str
    fingerprint: str
    definition: dict[str, object]
    first_seen: str
    last_seen: str
    approved: bool = True
    drift_count: int = 0


class PinStore(Protocol):
    """Persistence backend for tool pins."""

    def load(self) -> list[PinnedTool]: ...

    def save(self, pins: list[PinnedTool]) -> None: ...


class MemoryPinStore:
    """A non-persistent pin store. Pins live only for the process lifetime."""

    def load(self) -> list[PinnedTool]:
        return []

    def save(self, pins: list[PinnedTool]) -> None:  # noqa: ARG002
        return None


@dataclass
class JsonFilePinStore:
    """A pin store backed by a JSON file on disk."""

    path: Path

    def load(self) -> list[PinnedTool]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return []
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("pin store unreadable; starting empty", path=str(self.path), error=str(exc))
            return []
        if not isinstance(data, list):
            return []
        return [PinnedTool(**record) for record in data if isinstance(record, dict)]

    def save(self, pins: list[PinnedTool]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps([asdict(pin) for pin in pins], indent=2, ensure_ascii=False)
        self.path.write_text(payload, encoding="utf-8")


@dataclass
class ToolCatalog:
    """Tracks pinned tool baselines and tool names seen in the current run."""

    store: PinStore = field(default_factory=MemoryPinStore)
    _pins: dict[tuple[str, str], PinnedTool] = field(init=False, default_factory=dict)
    _seen: dict[str, set[str]] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        for pin in self.store.load():
            self._pins[(pin.server, pin.name)] = pin

    def get_pin(self, server: str, name: str) -> PinnedTool | None:
        return self._pins.get((server, name))

    def pin(self, server: str, tool: ToolDefinition) -> PinnedTool:
        """Create and persist a first-seen pin (trust on first use)."""
        now = _now()
        pinned = PinnedTool(
            server=server,
            name=tool.name,
            fingerprint=fingerprint(tool),
            definition=dict(tool.raw),
            first_seen=now,
            last_seen=now,
        )
        self._pins[(server, tool.name)] = pinned
        self.flush()
        return pinned

    def touch(self, server: str, name: str) -> None:
        """Mark a pinned tool as seen again without changing its baseline."""
        pin = self._pins.get((server, name))
        if pin is not None:
            pin.last_seen = _now()
            self.flush()

    def record_drift(self, server: str, name: str) -> int:
        """Increment and return the drift counter for a pinned tool."""
        pin = self._pins.get((server, name))
        if pin is None:
            return 0
        pin.drift_count += 1
        pin.last_seen = _now()
        self.flush()
        return pin.drift_count

    def record_seen(self, server: str, tool: ToolDefinition) -> None:
        """Note that ``server`` advertises ``tool`` (for shadowing detection)."""
        self._seen.setdefault(tool.name, set()).add(server)

    def servers_advertising(self, name: str) -> set[str]:
        return set(self._seen.get(name, set()))

    def pinned_servers_for(self, name: str) -> set[str]:
        """Return the servers that hold a pin for tool ``name``."""
        return {server for (server, pinned_name) in self._pins if pinned_name == name}

    def flush(self) -> None:
        self.store.save(list(self._pins.values()))


__all__ = [
    "JsonFilePinStore",
    "MemoryPinStore",
    "PinStore",
    "PinnedTool",
    "ToolCatalog",
]
