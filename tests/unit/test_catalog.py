"""Tests for the tool catalog and its pin stores."""

from __future__ import annotations

from pathlib import Path

from bastion.catalog.fingerprint import fingerprint
from bastion.catalog.registry import JsonFilePinStore, ToolCatalog
from bastion.core.models import ToolDefinition


def _tool(name: str = "t", desc: str = "d") -> ToolDefinition:
    return ToolDefinition.from_raw(
        {"name": name, "description": desc, "inputSchema": {"type": "object"}}
    )


def test_pin_then_get() -> None:
    catalog = ToolCatalog()
    tool = _tool()
    catalog.pin("srv", tool)
    pin = catalog.get_pin("srv", "t")
    assert pin is not None
    assert pin.fingerprint == fingerprint(tool)


def test_get_pin_missing_returns_none() -> None:
    assert ToolCatalog().get_pin("srv", "absent") is None


def test_drift_counter_increments() -> None:
    catalog = ToolCatalog()
    catalog.pin("srv", _tool())
    assert catalog.record_drift("srv", "t") == 1
    assert catalog.record_drift("srv", "t") == 2


def test_record_seen_tracks_servers_for_shadowing() -> None:
    catalog = ToolCatalog()
    catalog.record_seen("alpha", _tool())
    catalog.record_seen("beta", _tool())
    assert catalog.servers_advertising("t") == {"alpha", "beta"}


def test_json_file_store_persists_pins(tmp_path: Path) -> None:
    path = tmp_path / "pins.json"
    first = ToolCatalog(store=JsonFilePinStore(path=path))
    first.pin("srv", _tool())

    second = ToolCatalog(store=JsonFilePinStore(path=path))
    pin = second.get_pin("srv", "t")
    assert pin is not None
    assert pin.fingerprint == fingerprint(_tool())


def test_json_file_store_missing_file_starts_empty(tmp_path: Path) -> None:
    catalog = ToolCatalog(store=JsonFilePinStore(path=tmp_path / "absent.json"))
    assert catalog.get_pin("srv", "t") is None
