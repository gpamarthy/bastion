"""Tests for the stdio subprocess transport against the fake MCP server."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from bastion.core.errors import TransportError
from bastion.core.models import JsonRpcMessage
from bastion.transport.stdio import SubprocessServer

FAKE_SERVER = Path(__file__).parents[1] / "fixtures" / "fake_mcp_server.py"


async def test_spawn_rejects_empty_command() -> None:
    with pytest.raises(TransportError):
        await SubprocessServer.spawn([])


async def test_spawn_rejects_missing_binary() -> None:
    with pytest.raises(TransportError):
        await SubprocessServer.spawn(["/nonexistent/bastion-no-such-binary"])


async def test_subprocess_roundtrips_initialize() -> None:
    server = await SubprocessServer.spawn([sys.executable, str(FAKE_SERVER)])
    try:
        await server.transport.write_message(
            JsonRpcMessage.request("initialize", 1, {"protocolVersion": "2025-06-18"})
        )
        frame = await server.transport.read()
        assert frame is not None and frame.message is not None
        assert frame.message.id == 1
        assert frame.message.result["protocolVersion"] == "2025-06-18"
    finally:
        exit_code = await server.shutdown()
        assert exit_code is not None


async def test_shutdown_is_idempotent() -> None:
    server = await SubprocessServer.spawn([sys.executable, str(FAKE_SERVER)])
    first = await server.shutdown()
    second = await server.shutdown()
    assert first is not None and second is not None
