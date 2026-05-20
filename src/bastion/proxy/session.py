"""Per-connection MCP session state.

One :class:`MCPSession` lives for the lifetime of a single client<->server
connection. It correlates JSON-RPC request ids to their methods (so a response
can be classified by what it answers) and records what the ``initialize``
handshake negotiated. Rules read this state; the pump keeps it current.
"""

from __future__ import annotations

import uuid
from typing import Any

from bastion.core.models import Direction, JsonRpcId, JsonRpcMessage


class MCPSession:
    """Mutable state for one MCP connection passing through the gateway."""

    def __init__(self, server_label: str, *, session_id: str | None = None) -> None:
        self.session_id: str = session_id or uuid.uuid4().hex[:16]
        self.server_label: str = server_label
        self.protocol_version: str | None = None
        self.client_info: dict[str, Any] = {}
        self.server_info: dict[str, Any] = {}
        self.client_capabilities: dict[str, Any] = {}
        self.server_capabilities: dict[str, Any] = {}
        # Outstanding request id -> method, for both directions.
        self._pending: dict[JsonRpcId, str] = {}
        self.messages_seen: int = 0

    def method_for(self, rid: JsonRpcId) -> str | None:
        """Return the method a still-pending request id was issued for."""
        return self._pending.get(rid)

    def observe(self, message: JsonRpcMessage | None, direction: Direction) -> None:
        """Fold one observed message into the session state."""
        self.messages_seen += 1
        if message is None:
            return
        if message.is_request:
            self._pending[message.id] = message.method or ""
            if message.method == "initialize":
                self._record_initialize_request(message)
        elif message.is_response:
            method = self._pending.pop(message.id, None)
            if method == "initialize" and direction == Direction.SERVER_TO_CLIENT:
                self._record_initialize_result(message)

    def _record_initialize_request(self, message: JsonRpcMessage) -> None:
        params = message.params
        if not isinstance(params, dict):
            return
        version = params.get("protocolVersion")
        if isinstance(version, str):
            self.protocol_version = version
        client_info = params.get("clientInfo")
        if isinstance(client_info, dict):
            self.client_info = client_info
        caps = params.get("capabilities")
        if isinstance(caps, dict):
            self.client_capabilities = caps

    def _record_initialize_result(self, message: JsonRpcMessage) -> None:
        result = message.result
        if not isinstance(result, dict):
            return
        version = result.get("protocolVersion")
        if isinstance(version, str):
            self.protocol_version = version
        server_info = result.get("serverInfo")
        if isinstance(server_info, dict):
            self.server_info = server_info
        caps = result.get("capabilities")
        if isinstance(caps, dict):
            self.server_capabilities = caps


__all__ = ["MCPSession"]
