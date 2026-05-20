"""Shared pytest fixtures for the bastion suite."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from fixtures.memory_transport import MemoryTransport, memory_pair

from bastion.catalog.registry import ToolCatalog
from bastion.core.models import Frame, JsonRpcId, JsonRpcMessage, ToolDefinition
from bastion.core.taxonomy import Severity, ThreatClass
from bastion.proxy.gateway import MCPGateway
from bastion.proxy.pump import Interceptor, PassthroughInterceptor
from bastion.proxy.session import MCPSession
from bastion.rules.base import Rule
from bastion.rules.registry import register
from bastion.rules.types import RuleContext, RuleResult
from bastion.transport.stdio import SubprocessServer

FAKE_SERVER = Path(__file__).parent / "fixtures" / "fake_mcp_server.py"


@register("test_slow")
class SlowRule(Rule):
    """A rule that sleeps for ``sleep_ms``; used by timeout and budget tests."""

    threat_class = ThreatClass.RESOURCE_ABUSE
    severity = Severity.LOW
    quality = "experimental"

    async def inspect_tool_def(self, tool: ToolDefinition, ctx: RuleContext) -> RuleResult:
        await asyncio.sleep(self.config.get("sleep_ms", 50) / 1000.0)
        return self._pass()


INITIALIZE_PARAMS: dict[str, Any] = {
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "clientInfo": {"name": "bastion-tests", "version": "0.1.0"},
}


class GatewayHarness:
    """Drives a running gateway from the client side over a memory transport."""

    def __init__(
        self,
        test_side: MemoryTransport,
        gateway: MCPGateway,
        run_task: asyncio.Task[int],
    ) -> None:
        self._test = test_side
        self.gateway = gateway
        self._run_task = run_task

    async def send(self, message: JsonRpcMessage) -> None:
        await self._test.write_message(message)

    async def recv(self) -> Frame | None:
        return await asyncio.wait_for(self._test.read(), timeout=5.0)

    async def request(self, method: str, rid: JsonRpcId, params: Any = None) -> JsonRpcMessage:
        """Send a request and return the next frame's decoded response."""
        await self.send(JsonRpcMessage.request(method, rid, params))
        frame = await self.recv()
        assert frame is not None, f"no response to {method}"
        assert frame.message is not None, f"undecodable response to {method}"
        return frame.message

    async def initialize(self) -> JsonRpcMessage:
        return await self.request("initialize", 1, INITIALIZE_PARAMS)

    async def aclose(self) -> int:
        """Close the client side and await gateway shutdown."""
        await self._test.close()
        return await asyncio.wait_for(self._run_task, timeout=5.0)


HarnessFactory = Callable[..., Awaitable[GatewayHarness]]


@pytest.fixture
def fake_server_cmd() -> list[str]:
    """The command that runs the bundled fake MCP server."""
    return [sys.executable, str(FAKE_SERVER)]


@pytest.fixture
def rule_context() -> Callable[..., RuleContext]:
    """A factory for a fresh :class:`RuleContext` (session + catalog)."""

    def make(catalog: ToolCatalog | None = None, server: str = "test-server") -> RuleContext:
        return RuleContext(
            session=MCPSession(server_label=server),
            catalog=catalog if catalog is not None else ToolCatalog(),
            server_label=server,
        )

    return make


@pytest.fixture
async def harness_factory(
    fake_server_cmd: list[str],
) -> AsyncIterator[HarnessFactory]:
    """Yields a factory that builds a running gateway in front of the fake server."""
    created: list[GatewayHarness] = []

    async def make(
        *,
        interceptor: Interceptor | None = None,
        tools: list[dict[str, Any]] | None = None,
        env: Mapping[str, str] | None = None,
    ) -> GatewayHarness:
        child_env: dict[str, str] = dict(env or {})
        if tools is not None:
            child_env["FAKE_MCP_TOOLS"] = json.dumps(tools)
        subprocess = await SubprocessServer.spawn(fake_server_cmd, env=child_env or None)
        gateway_side, test_side = memory_pair()
        gateway = MCPGateway(
            client=gateway_side,
            server=subprocess.transport,
            session=MCPSession(server_label="fake"),
            interceptor=interceptor or PassthroughInterceptor(),
            subprocess=subprocess,
        )
        run_task: asyncio.Task[int] = asyncio.create_task(gateway.run())
        harness = GatewayHarness(test_side, gateway, run_task)
        created.append(harness)
        return harness

    yield make

    for harness in created:
        if not harness._run_task.done():
            await harness.aclose()
