"""A one-shot MCP client used by ``bastion scan``.

It performs the minimum handshake - ``initialize``, ``notifications/initialized``,
``tools/list`` - against a server, returns its advertised tool definitions, and
shuts the server down. No proxying, no long-lived session.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from bastion import __version__
from bastion.core.errors import TransportError
from bastion.core.models import JsonRpcId, JsonRpcMessage, ToolDefinition
from bastion.transport.stdio import SubprocessServer


@dataclass(slots=True)
class ProbeResult:
    """What a probe learned about an MCP server."""

    server_info: dict[str, Any] = field(default_factory=dict)
    protocol_version: str | None = None
    tools: list[ToolDefinition] = field(default_factory=list)


async def _await_response(
    server: SubprocessServer, want_id: JsonRpcId, timeout: float
) -> JsonRpcMessage:
    """Read frames until the response for ``want_id`` arrives."""
    while True:
        frame = await asyncio.wait_for(server.transport.read(), timeout=timeout)
        if frame is None:
            raise TransportError("MCP server closed before responding")
        msg = frame.message
        if msg is not None and msg.is_response and msg.id == want_id:
            if msg.error is not None:
                raise TransportError(f"MCP server returned an error: {msg.error}")
            return msg


async def probe_tools(
    server_command: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    timeout: float = 10.0,
) -> ProbeResult:
    """Connect to an MCP server and return its tool catalog."""
    server = await SubprocessServer.spawn(server_command, env=env)
    try:
        await server.transport.write_message(
            JsonRpcMessage.request(
                "initialize",
                1,
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "bastion-scan", "version": __version__},
                },
            )
        )
        init = await _await_response(server, 1, timeout)
        result = init.result if isinstance(init.result, dict) else {}

        await server.transport.write_message(
            JsonRpcMessage(raw={"jsonrpc": "2.0", "method": "notifications/initialized"})
        )
        await server.transport.write_message(JsonRpcMessage.request("tools/list", 2))
        listed = await _await_response(server, 2, timeout)
        listing = listed.result if isinstance(listed.result, dict) else {}
        raw_tools = listing.get("tools", [])

        tools = [ToolDefinition.from_raw(entry) for entry in raw_tools if isinstance(entry, dict)]
        return ProbeResult(
            server_info=result.get("serverInfo", {}),
            protocol_version=result.get("protocolVersion"),
            tools=tools,
        )
    finally:
        await server.shutdown()


__all__ = ["ProbeResult", "probe_tools"]
