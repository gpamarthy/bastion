#!/usr/bin/env python3
"""A minimal but spec-shaped MCP server for tests and demos.

It speaks JSON-RPC 2.0 over stdio (newline-delimited). Behaviour is tunable
through environment variables so a single script backs both the clean
integration tests and later adversarial fixtures:

* ``FAKE_MCP_TOOLS``   - JSON array overriding the advertised tool catalog.
* ``FAKE_MCP_NAME``    - server name reported in ``initialize``.
* ``FAKE_MCP_EXIT_ON`` - method name after which the server exits abruptly
                         (used to test peer-close handling).
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

PROTOCOL_VERSION = "2025-06-18"

CLEAN_TOOLS: list[dict[str, Any]] = [
    {
        "name": "echo",
        "description": "Echo back the given text.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "add",
        "description": "Add two numbers and return the sum.",
        "inputSchema": {
            "type": "object",
            "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
            "required": ["a", "b"],
        },
    },
]


def _tools() -> list[dict[str, Any]]:
    override = os.environ.get("FAKE_MCP_TOOLS")
    if override:
        parsed = json.loads(override)
        if isinstance(parsed, list):
            return parsed
    return CLEAN_TOOLS


def _send(obj: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _result(rid: Any, result: Any) -> None:
    _send({"jsonrpc": "2.0", "id": rid, "result": result})


def _error(rid: Any, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}})


def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "echo":
        text = str(arguments.get("text", ""))
        return {"content": [{"type": "text", "text": text}]}
    if name == "add":
        total = float(arguments.get("a", 0)) + float(arguments.get("b", 0))
        return {"content": [{"type": "text", "text": str(total)}]}
    return {
        "content": [{"type": "text", "text": f"unknown tool: {name}"}],
        "isError": True,
    }


def _dispatch(msg: dict[str, Any]) -> None:
    method = msg.get("method")
    rid = msg.get("id")
    params = msg.get("params") or {}

    if method == "initialize":
        _result(
            rid,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {
                    "name": os.environ.get("FAKE_MCP_NAME", "fake-mcp-server"),
                    "version": "0.1.0",
                },
            },
        )
    elif method == "notifications/initialized":
        pass  # notification: no response
    elif method == "ping":
        _result(rid, {})
    elif method == "tools/list":
        _result(rid, {"tools": _tools()})
    elif method == "tools/call":
        name = str(params.get("name", ""))
        args = params.get("arguments") or {}
        _result(rid, _call_tool(name, args if isinstance(args, dict) else {}))
    elif rid is not None:
        _error(rid, -32601, f"method not found: {method}")

    if method and method == os.environ.get("FAKE_MCP_EXIT_ON"):
        sys.exit(0)


def main() -> None:
    for line in sys.stdin:
        payload = line.strip()
        if not payload:
            continue
        try:
            msg = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if isinstance(msg, dict):
            _dispatch(msg)


if __name__ == "__main__":
    main()
