"""The bidirectional message pump.

Two independent async tasks move frames between the client and server
transports - one per direction - so neither direction can ever block the
other (a classic stdio-proxy deadlock). Each frame is offered to an
:class:`Interceptor` before it is forwarded.

In M1 the only interceptor is :class:`PassthroughInterceptor`, which forwards
every frame byte-for-byte; later milestones plug a policy engine in here
without touching the pump.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from typing import Protocol, runtime_checkable

from bastion.core import logger
from bastion.core.models import (
    BLOCKED_ERROR_CODE,
    Decision,
    Direction,
    Frame,
    InterceptVerdict,
    JsonRpcMessage,
)
from bastion.proxy.session import MCPSession
from bastion.transport.base import Transport

log = logger.get_logger(__name__)


@runtime_checkable
class Interceptor(Protocol):
    """Inspects a frame and decides whether the gateway forwards it."""

    async def inspect(
        self, frame: Frame, direction: Direction, session: MCPSession
    ) -> InterceptVerdict: ...


class PassthroughInterceptor:
    """Forwards every frame unchanged. The M1 baseline interceptor."""

    async def inspect(
        self,
        frame: Frame,  # noqa: ARG002 - baseline interceptor inspects nothing
        direction: Direction,  # noqa: ARG002
        session: MCPSession,  # noqa: ARG002
    ) -> InterceptVerdict:
        return InterceptVerdict.allow()


class MessagePump:
    """Runs the two directional forwarding loops for one connection."""

    def __init__(
        self,
        *,
        client: Transport,
        server: Transport,
        session: MCPSession,
        interceptor: Interceptor,
    ) -> None:
        self._client = client
        self._server = server
        self._session = session
        self._interceptor = interceptor

    async def run(self) -> None:
        """Pump both directions until either peer closes; then stop the other."""
        c2s = asyncio.create_task(
            self._pump(self._client, self._server, Direction.CLIENT_TO_SERVER),
            name="pump-c2s",
        )
        s2c = asyncio.create_task(
            self._pump(self._server, self._client, Direction.SERVER_TO_CLIENT),
            name="pump-s2c",
        )
        done, pending = await asyncio.wait({c2s, s2c}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in pending:
            with suppress(asyncio.CancelledError):
                await task
        # Surface a genuine failure (TransportError, etc.) from whichever
        # direction finished first; a clean EOF returns None and is ignored.
        for task in done:
            exc = task.exception()
            if exc is not None:
                raise exc

    async def _pump(self, src: Transport, dst: Transport, direction: Direction) -> None:
        while True:
            frame = await src.read()
            if frame is None:
                log.debug("eof", direction=direction.value, session=self._session.session_id)
                return
            self._session.observe(frame.message, direction)
            verdict = await self._interceptor.inspect(frame, direction, self._session)
            await self._apply(verdict, frame, src, dst, direction)

    async def _apply(
        self,
        verdict: InterceptVerdict,
        frame: Frame,
        src: Transport,
        dst: Transport,
        direction: Direction,
    ) -> None:
        if verdict.decision is Decision.ALLOW:
            if verdict.message is not None:
                await dst.write_message(verdict.message)
            else:
                await dst.write_bytes(frame.raw)
            return

        # BLOCK / REQUIRE_APPROVAL: never forward. Keep the session alive by
        # answering with a spec-valid JSON-RPC error carrying the original id.
        reason = verdict.reason or "blocked by bastion policy"
        msg = frame.message
        if msg is not None and msg.is_request:
            err = JsonRpcMessage.error_for(msg.id, BLOCKED_ERROR_CODE, reason)
            await src.write_message(err)
            log.warning(
                "blocked request",
                direction=direction.value,
                method=msg.method,
                reason=reason,
                session=self._session.session_id,
            )
        elif msg is not None and msg.is_response:
            # A blocked result still needs an answer downstream or the caller
            # hangs; replace it with an error response for the same id.
            err = JsonRpcMessage.error_for(msg.id, BLOCKED_ERROR_CODE, reason)
            await dst.write_message(err)
            log.warning(
                "blocked response",
                direction=direction.value,
                reason=reason,
                session=self._session.session_id,
            )
        else:
            log.warning(
                "dropped notification",
                direction=direction.value,
                reason=reason,
                session=self._session.session_id,
            )


__all__ = ["Interceptor", "MessagePump", "PassthroughInterceptor"]
