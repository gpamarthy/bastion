"""An in-memory :class:`Transport` for driving the gateway from tests.

The test process cannot rebind its own stdin/stdout, so integration tests
attach a :class:`MemoryTransport` where a real client would sit. Two paired
transports form a channel: a write on one surfaces as a read on the other.
``close()`` enqueues an EOF sentinel so the gateway's pump observes a clean
peer close exactly as it would on a real pipe.
"""

from __future__ import annotations

import asyncio

from bastion.core.models import Frame
from bastion.transport.base import Transport
from bastion.transport.framing import decode_line


class MemoryTransport(Transport):
    """A :class:`Transport` backed by a pair of asyncio queues."""

    def __init__(
        self,
        inbox: asyncio.Queue[Frame | None],
        outbox: asyncio.Queue[Frame | None],
    ) -> None:
        self._inbox = inbox
        self._outbox = outbox
        self._closed = False

    async def read(self) -> Frame | None:
        return await self._inbox.get()

    async def write_bytes(self, raw: bytes) -> None:
        await self._outbox.put(decode_line(raw))

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._outbox.put(None)


def memory_pair() -> tuple[MemoryTransport, MemoryTransport]:
    """Return two linked transports: ``(left, right)``."""
    left_to_right: asyncio.Queue[Frame | None] = asyncio.Queue()
    right_to_left: asyncio.Queue[Frame | None] = asyncio.Queue()
    left = MemoryTransport(inbox=right_to_left, outbox=left_to_right)
    right = MemoryTransport(inbox=left_to_right, outbox=right_to_left)
    return left, right


__all__ = ["MemoryTransport", "memory_pair"]
