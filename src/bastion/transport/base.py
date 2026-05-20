"""The :class:`Transport` abstraction shared by every MCP transport.

A transport is a bidirectional, frame-oriented channel. The proxy core only
ever sees this interface, so adding a new transport (HTTP, WebSocket) never
touches the gateway.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from bastion.core.models import Frame, JsonRpcMessage
from bastion.transport.framing import encode


class Transport(ABC):
    """A bidirectional JSON-RPC frame channel."""

    @abstractmethod
    async def read(self) -> Frame | None:
        """Return the next frame, or ``None`` once the peer has closed."""

    @abstractmethod
    async def write_bytes(self, raw: bytes) -> None:
        """Write raw frame bytes verbatim (byte-faithful passthrough)."""

    async def write_message(self, message: JsonRpcMessage) -> None:
        """Encode and write a message. Used when the gateway rewrites a frame."""
        await self.write_bytes(encode(message))

    @abstractmethod
    async def close(self) -> None:
        """Release the underlying resources. Idempotent."""


__all__ = ["Transport"]
