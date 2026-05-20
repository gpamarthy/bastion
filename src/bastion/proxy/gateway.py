"""The MCP gateway: wires transports, session, and pump into one connection.

:meth:`MCPGateway.for_stdio` is the M1 entry point - it spawns the real MCP
server, binds this process's stdin/stdout as the client side, and runs the
pump until either peer closes.
"""

from __future__ import annotations

from collections.abc import Sequence

from bastion.core import logger
from bastion.proxy.pump import Interceptor, MessagePump, PassthroughInterceptor
from bastion.proxy.session import MCPSession
from bastion.transport.base import Transport
from bastion.transport.stdio import SubprocessServer, connect_process_stdio

log = logger.get_logger(__name__)


class MCPGateway:
    """A single client<->server MCP connection mediated by bastion."""

    def __init__(
        self,
        *,
        client: Transport,
        server: Transport,
        session: MCPSession,
        interceptor: Interceptor,
        subprocess: SubprocessServer | None = None,
    ) -> None:
        self._client = client
        self._server = server
        self._session = session
        self._interceptor = interceptor
        self._subprocess = subprocess

    @property
    def session(self) -> MCPSession:
        return self._session

    @classmethod
    async def for_stdio(
        cls,
        server_command: Sequence[str],
        *,
        interceptor: Interceptor | None = None,
        server_label: str | None = None,
    ) -> MCPGateway:
        """Build a stdio-mode gateway in front of ``server_command``."""
        label = server_label or (server_command[0] if server_command else "mcp-server")
        subprocess = await SubprocessServer.spawn(server_command)
        client = await connect_process_stdio()
        session = MCPSession(server_label=label)
        log.info(
            "gateway started",
            session=session.session_id,
            server=label,
            transport="stdio",
        )
        return cls(
            client=client,
            server=subprocess.transport,
            session=session,
            interceptor=interceptor or PassthroughInterceptor(),
            subprocess=subprocess,
        )

    async def run(self) -> int:
        """Pump the connection to completion; return the server's exit code."""
        pump = MessagePump(
            client=self._client,
            server=self._server,
            session=self._session,
            interceptor=self._interceptor,
        )
        try:
            await pump.run()
        finally:
            exit_code = await self._shutdown()
        log.info(
            "gateway stopped",
            session=self._session.session_id,
            messages=self._session.messages_seen,
            server_exit=exit_code,
        )
        return exit_code

    async def _shutdown(self) -> int:
        await self._client.close()
        if self._subprocess is not None:
            return await self._subprocess.shutdown()
        await self._server.close()
        return 0


__all__ = ["MCPGateway"]
