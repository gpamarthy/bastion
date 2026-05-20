"""JSON-RPC 2.0 framing for the MCP stdio transport.

MCP's stdio transport is newline-delimited JSON: one JSON object per line, no
embedded raw newlines (string newlines are escaped as ``\\n`` by any conforming
encoder). :class:`FrameReader` reads one frame per line; :func:`encode`
produces a single newline-terminated line.
"""

from __future__ import annotations

import asyncio
import json

from bastion.core.errors import FramingError
from bastion.core.models import Frame, JsonRpcMessage

# StreamReader buffer ceiling. A `tools/list` result for a large server can be
# hundreds of KB; 16 MiB leaves generous headroom while still bounding memory.
DEFAULT_LIMIT = 16 * 1024 * 1024


def encode(message: JsonRpcMessage) -> bytes:
    """Serialise a message to a single newline-terminated UTF-8 line.

    ``ensure_ascii=False`` keeps the byte length predictable and the compact
    separators avoid gratuitous whitespace; neither affects JSON semantics.
    """
    text = json.dumps(message.raw, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8") + b"\n"


def decode_line(line: bytes) -> Frame:
    """Decode one wire line into a :class:`Frame`.

    A line that is not a JSON *object* (a batch array, a bare value, or
    malformed JSON) yields a frame with ``message=None``. The gateway forwards
    such frames verbatim rather than dropping them, so a non-conforming peer
    never has its session silently broken by the proxy.
    """
    stripped = line.rstrip(b"\r\n")
    if not stripped:
        return Frame(raw=line, message=None)
    try:
        obj = json.loads(stripped)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return Frame(raw=line, message=None)
    if not isinstance(obj, dict):
        return Frame(raw=line, message=None)
    return Frame(raw=line, message=JsonRpcMessage(raw=obj))


class FrameReader:
    """Reads :class:`Frame` objects, one per line, from an asyncio StreamReader."""

    def __init__(self, reader: asyncio.StreamReader) -> None:
        self._reader = reader

    async def read(self) -> Frame | None:
        """Return the next frame, or ``None`` at end of stream."""
        try:
            line = await self._reader.readuntil(b"\n")
        except asyncio.IncompleteReadError as exc:
            # Stream ended. A non-empty partial is a final unterminated line.
            if exc.partial:
                return decode_line(exc.partial)
            return None
        except asyncio.LimitOverrunError as exc:
            raise FramingError(
                f"JSON-RPC line exceeded the {DEFAULT_LIMIT}-byte frame limit"
            ) from exc
        except (ConnectionResetError, BrokenPipeError):
            return None
        if not line:
            return None
        return decode_line(line)


__all__ = ["DEFAULT_LIMIT", "FrameReader", "decode_line", "encode"]
