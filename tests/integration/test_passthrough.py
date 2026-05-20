"""End-to-end gateway tests against the fake MCP server.

These exercise the full M1 path: memory client transport -> pump ->
subprocess server transport, with both a passthrough and a blocking
interceptor.
"""

from __future__ import annotations

import pytest
from conftest import HarnessFactory

from bastion.core.models import (
    BLOCKED_ERROR_CODE,
    Direction,
    Frame,
    InterceptVerdict,
    MessageKind,
)
from bastion.proxy.session import MCPSession

pytestmark = pytest.mark.integration


class BlockMethodInterceptor:
    """Blocks every request for one method; forwards everything else."""

    def __init__(self, method: str) -> None:
        self.method = method

    async def inspect(
        self, frame: Frame, direction: Direction, session: MCPSession
    ) -> InterceptVerdict:
        msg = frame.message
        if msg is not None and msg.is_request and msg.method == self.method:
            return InterceptVerdict.block(f"{self.method} blocked for test")
        return InterceptVerdict.allow()


async def test_initialize_roundtrips_and_populates_session(
    harness_factory: HarnessFactory,
) -> None:
    harness = await harness_factory()
    response = await harness.initialize()

    assert response.id == 1
    assert response.kind is MessageKind.RESPONSE
    assert response.result["protocolVersion"] == "2025-06-18"

    session = harness.gateway.session
    assert session.protocol_version == "2025-06-18"
    assert session.server_info.get("name") == "fake-mcp-server"
    assert session.client_info.get("name") == "bastion-tests"


async def test_tools_list_passes_through_unchanged(
    harness_factory: HarnessFactory,
) -> None:
    harness = await harness_factory()
    await harness.initialize()
    response = await harness.request("tools/list", 2)

    names = {tool["name"] for tool in response.result["tools"]}
    assert names == {"echo", "add"}


async def test_tools_call_echo_roundtrips(harness_factory: HarnessFactory) -> None:
    harness = await harness_factory()
    await harness.initialize()
    response = await harness.request(
        "tools/call", 3, {"name": "echo", "arguments": {"text": "hello bastion"}}
    )
    assert response.result["content"][0]["text"] == "hello bastion"


async def test_custom_tool_catalog_is_forwarded(
    harness_factory: HarnessFactory,
) -> None:
    custom = [{"name": "deploy", "description": "Ship it.", "inputSchema": {"type": "object"}}]
    harness = await harness_factory(tools=custom)
    await harness.initialize()
    response = await harness.request("tools/list", 2)
    assert [t["name"] for t in response.result["tools"]] == ["deploy"]


async def test_blocked_request_returns_jsonrpc_error_and_keeps_session_alive(
    harness_factory: HarnessFactory,
) -> None:
    harness = await harness_factory(interceptor=BlockMethodInterceptor("tools/call"))
    await harness.initialize()

    blocked = await harness.request("tools/call", 2, {"name": "echo", "arguments": {"text": "hi"}})
    assert blocked.kind is MessageKind.ERROR
    assert blocked.id == 2
    assert blocked.error is not None
    assert blocked.error["code"] == BLOCKED_ERROR_CODE

    # The session must survive a block: an unrelated call still works.
    pong = await harness.request("ping", 3)
    assert pong.kind is MessageKind.RESPONSE
    assert pong.result == {}


async def test_eof_shuts_down_gateway_cleanly(
    harness_factory: HarnessFactory,
) -> None:
    harness = await harness_factory()
    await harness.initialize()
    exit_code = await harness.aclose()
    assert exit_code is not None
    assert harness.gateway.session.messages_seen > 0
