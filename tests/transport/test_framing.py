"""Tests for JSON-RPC framing: encode/decode and the streaming FrameReader."""

from __future__ import annotations

import asyncio
import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from bastion.core.models import JsonRpcMessage
from bastion.transport.framing import DEFAULT_LIMIT, FrameReader, decode_line, encode

# JSON-safe values with no surrogate code points (which break UTF-8 encoding).
_text = st.text(st.characters(exclude_categories=["Cs"]), max_size=40)
_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(10**9), max_value=10**9),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    _text,
)
_json_objects = st.dictionaries(
    _text,
    st.recursive(
        _scalars, lambda c: st.lists(c, max_size=4) | st.dictionaries(_text, c, max_size=4)
    ),
    max_size=6,
)


def test_encode_is_a_single_newline_terminated_line() -> None:
    raw = encode(JsonRpcMessage(raw={"id": 1, "method": "x", "note": "line\nbreak"}))
    assert raw.endswith(b"\n")
    assert raw.count(b"\n") == 1  # the embedded newline is escaped, not literal


def test_encode_decode_roundtrip() -> None:
    original = {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"a": 1}}
    frame = decode_line(encode(JsonRpcMessage(raw=original)))
    assert frame.message is not None
    assert frame.message.raw == original


def test_decode_non_object_yields_undecoded_frame() -> None:
    for line in (b"[1,2,3]\n", b'"bare"\n', b"42\n", b"not json\n", b"\n"):
        frame = decode_line(line)
        assert frame.message is None
        assert frame.raw == line


@given(_json_objects)
def test_roundtrip_property(obj: dict[str, object]) -> None:
    frame = decode_line(encode(JsonRpcMessage(raw=obj)))
    assert frame.message is not None
    assert frame.message.raw == obj


async def _reader_from(chunks: list[bytes]) -> FrameReader:
    reader = asyncio.StreamReader(limit=DEFAULT_LIMIT)
    for chunk in chunks:
        reader.feed_data(chunk)
    reader.feed_eof()
    return FrameReader(reader)


async def test_reader_reads_messages_then_eof() -> None:
    line_a = encode(JsonRpcMessage(raw={"id": 1}))
    line_b = encode(JsonRpcMessage(raw={"id": 2}))
    reader = await _reader_from([line_a + line_b])

    first = await reader.read()
    second = await reader.read()
    third = await reader.read()

    assert first is not None and first.message is not None and first.message.id == 1
    assert second is not None and second.message is not None and second.message.id == 2
    assert third is None  # EOF


async def test_reader_reassembles_partial_chunks() -> None:
    line = encode(JsonRpcMessage(raw={"id": 1, "method": "split"}))
    reader = await _reader_from([line[:5], line[5:9], line[9:]])

    frame = await reader.read()
    assert frame is not None and frame.message is not None
    assert frame.message.method == "split"


async def test_reader_decodes_unterminated_final_line() -> None:
    payload = json.dumps({"id": 5, "method": "no-newline"}).encode()
    reader = await _reader_from([payload])  # note: no trailing \n

    frame = await reader.read()
    assert frame is not None and frame.message is not None
    assert frame.message.id == 5
    assert await reader.read() is None


async def test_reader_handles_large_message() -> None:
    big = JsonRpcMessage(raw={"id": 1, "blob": "A" * (2 * 1024 * 1024)})
    reader = await _reader_from([encode(big)])

    frame = await reader.read()
    assert frame is not None and frame.message is not None
    assert len(frame.message.raw["blob"]) == 2 * 1024 * 1024


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
