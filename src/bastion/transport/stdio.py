"""stdio MCP transport.

In stdio mode the MCP client launches bastion as if it were the server.
bastion therefore plays two roles at once:

* **client side** - this process's own stdin/stdout, spoken to the real client.
  ``connect_process_stdio()`` builds the transport for it.
* **server side** - a child subprocess running the *real* MCP server.
  ``SubprocessServer.spawn()`` launches it and wires up its pipes.

The child's stderr is inherited, so the real server's diagnostics flow straight
to bastion's stderr untouched.

The client side uses asyncio pipe transports when stdin/stdout are pipes (the
normal case when an MCP client spawns bastion). When they are regular files -
e.g. redirected during a demo or test - asyncio cannot wrap them, so a
thread-backed transport is used instead. Both expose the same interface.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import stat
import sys
import threading
from asyncio.streams import FlowControlMixin
from collections.abc import Mapping, Sequence
from typing import BinaryIO

from bastion.core.errors import TransportError
from bastion.core.models import Frame
from bastion.transport.base import Transport
from bastion.transport.framing import DEFAULT_LIMIT, FrameReader, decode_line


class StdioTransport(Transport):
    """A :class:`Transport` over an asyncio reader/writer pipe pair."""

    def __init__(self, reader: FrameReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer
        self._closed = False

    async def read(self) -> Frame | None:
        return await self._reader.read()

    async def write_bytes(self, raw: bytes) -> None:
        if self._closed:
            raise TransportError("write on a closed stdio transport")
        try:
            self._writer.write(raw)
            await self._writer.drain()
        except (ConnectionResetError, BrokenPipeError) as exc:
            raise TransportError(f"stdio peer closed during write: {exc}") from exc

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except (OSError, asyncio.CancelledError):
            # The peer may have already gone; closing is best-effort.
            pass


class ThreadedStdioTransport(Transport):
    """Client-side transport for when stdin/stdout are regular files.

    A daemon thread drains stdin so process shutdown never blocks on it; writes
    go straight to stdout (a regular file never blocks a write).
    """

    def __init__(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._queue: asyncio.Queue[Frame | None] = asyncio.Queue()
        self._stdin: BinaryIO = sys.stdin.buffer
        self._stdout: BinaryIO = sys.stdout.buffer
        self._closed = False
        self._thread = threading.Thread(target=self._read_loop, name="bastion-stdin", daemon=True)
        self._thread.start()

    def _read_loop(self) -> None:
        try:
            for line in iter(self._stdin.readline, b""):
                self._post(decode_line(line))
        finally:
            self._post(None)

    def _post(self, item: Frame | None) -> None:
        # RuntimeError: the event loop is already closed during shutdown.
        with contextlib.suppress(RuntimeError):
            self._loop.call_soon_threadsafe(self._queue.put_nowait, item)

    async def read(self) -> Frame | None:
        return await self._queue.get()

    async def write_bytes(self, raw: bytes) -> None:
        if self._closed:
            raise TransportError("write on a closed stdio transport")
        self._stdout.write(raw)
        self._stdout.flush()

    async def close(self) -> None:
        self._closed = True


def _is_async_pipe(fileobj: BinaryIO) -> bool:
    """True when ``fileobj`` is a pipe/socket/char device asyncio can wrap."""
    try:
        mode = os.fstat(fileobj.fileno()).st_mode
    except (OSError, ValueError, AttributeError):
        return False
    return stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode) or stat.S_ISCHR(mode)


async def connect_process_stdio() -> Transport:
    """Build the client-side transport over this process's own stdin/stdout."""
    if not (_is_async_pipe(sys.stdin.buffer) and _is_async_pipe(sys.stdout.buffer)):
        return ThreadedStdioTransport()
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=DEFAULT_LIMIT)
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    w_transport, w_protocol = await loop.connect_write_pipe(FlowControlMixin, sys.stdout.buffer)
    writer = asyncio.StreamWriter(w_transport, w_protocol, reader, loop)
    return StdioTransport(FrameReader(reader), writer)


class SubprocessServer:
    """A child MCP server process and the transport that speaks to it."""

    def __init__(self, proc: asyncio.subprocess.Process, transport: StdioTransport) -> None:
        self.proc = proc
        self.transport = transport

    @classmethod
    async def spawn(
        cls,
        command: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
    ) -> SubprocessServer:
        """Launch ``command`` as a child MCP server.

        ``env`` entries are merged over the inherited environment rather than
        replacing it, so the child keeps PATH and friends.
        """
        if not command:
            raise TransportError("no server command given to spawn")
        child_env = {**os.environ, **env} if env else None
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=None,  # inherit bastion's stderr
                limit=DEFAULT_LIMIT,
                env=child_env,
            )
        except (OSError, ValueError) as exc:
            raise TransportError(f"cannot launch MCP server {command!r}: {exc}") from exc
        if proc.stdin is None or proc.stdout is None:
            raise TransportError("subprocess was created without stdio pipes")
        transport = StdioTransport(FrameReader(proc.stdout), proc.stdin)
        return cls(proc, transport)

    async def shutdown(self, *, grace_seconds: float = 3.0) -> int:
        """Close the server's stdin, then terminate it; return its exit code."""
        await self.transport.close()
        if self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=grace_seconds)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()
        return self.proc.returncode if self.proc.returncode is not None else -1


__all__ = [
    "StdioTransport",
    "SubprocessServer",
    "ThreadedStdioTransport",
    "connect_process_stdio",
]
