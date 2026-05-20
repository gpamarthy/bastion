"""Tests for the approval store and broker."""

from __future__ import annotations

import asyncio
from pathlib import Path

from bastion.approval.broker import ApprovalBroker
from bastion.approval.store import ApprovalStore
from bastion.core.models import Decision


def test_store_remembers_and_returns_decisions() -> None:
    store = ApprovalStore()
    assert store.decision_for("srv", "tool") is None
    store.remember("srv", "tool", "allow")
    assert store.decision_for("srv", "tool") is Decision.ALLOW
    store.remember("srv", "tool", "deny")
    assert store.decision_for("srv", "tool") is Decision.BLOCK


def test_store_revoke() -> None:
    store = ApprovalStore()
    store.remember("srv", "tool", "allow")
    assert store.revoke("srv", "tool") is True
    assert store.decision_for("srv", "tool") is None
    assert store.revoke("srv", "tool") is False


def test_store_persists_to_disk(tmp_path: Path) -> None:
    path = tmp_path / "approvals.json"
    ApprovalStore(path).remember("srv", "tool", "deny", note="risky")

    reloaded = ApprovalStore(path)
    assert reloaded.decision_for("srv", "tool") is Decision.BLOCK
    assert reloaded.all_records()[0].note == "risky"


async def test_broker_request_resolved_by_caller() -> None:
    broker = ApprovalBroker(timeout_seconds=5.0)

    async def resolve_soon() -> None:
        await asyncio.sleep(0.01)
        pending = broker.pending()
        assert len(pending) == 1
        assert broker.resolve(pending[0].key, Decision.ALLOW)

    decision, _ = await asyncio.gather(
        broker.request(server="s", tool="t", reason="r", session_id="sess"),
        resolve_soon(),
    )
    assert decision is Decision.ALLOW


async def test_broker_request_times_out_to_default() -> None:
    broker = ApprovalBroker(timeout_seconds=0.05, default_on_timeout=Decision.BLOCK)
    decision = await broker.request(server="s", tool="t", reason="r", session_id="sess")
    assert decision is Decision.BLOCK
    assert broker.pending() == []
