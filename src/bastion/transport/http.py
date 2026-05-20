"""Streamable-HTTP MCP gateway.

bastion exposes an MCP ``POST /mcp`` endpoint and forwards each JSON-RPC
message to a configured upstream MCP server, running the same
:class:`~bastion.rules.interceptor.PolicyInterceptor` used in stdio mode. A
blocked request or result is answered with a spec-valid JSON-RPC error.

Scope: the JSON request/response path is fully intercepted. An upstream that
replies with a ``text/event-stream`` is streamed straight through without
per-event inspection - a documented limitation, not a silent gap.

Requires the ``http`` extra (``pip install 'bastion[http]'``).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse

from bastion.core import logger
from bastion.core.models import (
    BLOCKED_ERROR_CODE,
    Decision,
    Direction,
    Frame,
    JsonRpcMessage,
)
from bastion.proxy.session import MCPSession
from bastion.rules.interceptor import PolicyInterceptor
from bastion.transport.framing import decode_line

log = logger.get_logger(__name__)

_FORWARD_HEADERS = ("accept", "content-type", "mcp-session-id", "mcp-protocol-version")


def _encode(message: JsonRpcMessage) -> bytes:
    return json.dumps(message.raw, separators=(",", ":"), ensure_ascii=False).encode()


def _error_response(frame: Frame, reason: str) -> Response:
    rid = frame.message.id if frame.message is not None else None
    err = JsonRpcMessage.error_for(rid, BLOCKED_ERROR_CODE, reason)
    return Response(content=_encode(err), media_type="application/json")


def build_http_app(
    *,
    interceptor: PolicyInterceptor,
    upstream_url: str,
    server_label: str,
    request_timeout: float = 30.0,
    http_client: httpx.AsyncClient | None = None,
) -> FastAPI:
    """Build the FastAPI app for the HTTP gateway.

    ``http_client`` lets a test inject a client wired to an in-process
    upstream; when omitted the app owns and closes its own client.
    """
    sessions: dict[str, MCPSession] = {}
    state: dict[str, Any] = {}

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        owns_client = http_client is None
        state["client"] = http_client or httpx.AsyncClient(timeout=request_timeout)
        log.info("http gateway started", upstream=upstream_url, server=server_label)
        try:
            yield
        finally:
            if owns_client:
                await state["client"].aclose()

    app = FastAPI(title="bastion HTTP gateway", lifespan=lifespan)

    def _session(request: Request) -> MCPSession:
        sid = request.headers.get("mcp-session-id", "default")
        if sid not in sessions:
            sessions[sid] = MCPSession(server_label=server_label, session_id=sid[:32])
        return sessions[sid]

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "upstream": upstream_url}

    @app.post("/mcp")
    async def mcp(request: Request) -> Response:
        client: httpx.AsyncClient = state["client"]
        raw = await request.body()
        session = _session(request)
        request_frame = decode_line(raw)

        c2s = await interceptor.inspect(request_frame, Direction.CLIENT_TO_SERVER, session)
        if c2s.decision is not Decision.ALLOW:
            return _error_response(request_frame, c2s.reason or "blocked by policy")
        forward_body = _encode(c2s.message) if c2s.message is not None else raw

        fwd_headers = {k: v for k, v in request.headers.items() if k.lower() in _FORWARD_HEADERS}
        try:
            upstream = await client.post(upstream_url, content=forward_body, headers=fwd_headers)
        except httpx.HTTPError as exc:
            return _error_response(request_frame, f"upstream MCP server error: {exc}")

        out_headers = {}
        if "mcp-session-id" in upstream.headers:
            out_headers["mcp-session-id"] = upstream.headers["mcp-session-id"]

        content_type = upstream.headers.get("content-type", "")
        if content_type.startswith("text/event-stream"):
            # Streamed responses are passed through without per-event inspection.
            return StreamingResponse(
                upstream.aiter_bytes(),
                media_type="text/event-stream",
                headers=out_headers,
            )
        if not upstream.content:
            return Response(status_code=upstream.status_code, headers=out_headers)

        response_frame = decode_line(upstream.content)
        s2c = await interceptor.inspect(response_frame, Direction.SERVER_TO_CLIENT, session)
        if s2c.decision is not Decision.ALLOW:
            return _error_response(response_frame, s2c.reason or "blocked by policy")
        body = _encode(s2c.message) if s2c.message is not None else upstream.content
        return Response(content=body, media_type="application/json", headers=out_headers)

    return app


__all__ = ["build_http_app"]
