"""Edge-case tests: settings, framing limits, model parsing, session state."""

from __future__ import annotations

import asyncio

import pytest

from bastion.core.errors import FramingError
from bastion.core.models import (
    Direction,
    JsonRpcMessage,
    MessageKind,
    ToolCall,
    ToolResult,
)
from bastion.proxy.session import MCPSession
from bastion.settings import Settings
from bastion.transport.framing import FrameReader, encode
from bastion.transport.stdio import _is_async_pipe

# --- settings -------------------------------------------------------------


def test_settings_defaults() -> None:
    settings = Settings.from_env()
    assert settings.log_level == "INFO"
    assert settings.log_format == "console"


def test_settings_read_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BASTION_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("BASTION_LOG_FORMAT", "json")
    settings = Settings.from_env()
    assert settings.log_level == "DEBUG"
    assert settings.log_format == "json"


# --- framing limits -------------------------------------------------------


async def test_frame_reader_rejects_oversized_line() -> None:
    reader = asyncio.StreamReader(limit=64)
    reader.feed_data(b"x" * 256 + b"\n")
    reader.feed_eof()
    with pytest.raises(FramingError):
        await FrameReader(reader).read()


# --- model parsing --------------------------------------------------------


def test_request_without_params_omits_the_field() -> None:
    msg = JsonRpcMessage.request("ping", 1)
    assert "params" not in msg.raw
    assert msg.kind is MessageKind.REQUEST


def test_message_with_non_scalar_id_reports_none() -> None:
    msg = JsonRpcMessage(raw={"id": {"weird": True}, "method": "x"})
    assert msg.id is None


def test_with_raw_returns_a_new_message() -> None:
    original = JsonRpcMessage.request("a", 1)
    rewritten = original.with_raw({"jsonrpc": "2.0", "id": 1, "method": "b"})
    assert rewritten.method == "b"
    assert original.method == "a"


def test_tool_call_from_request_rejects_bad_params() -> None:
    assert ToolCall.from_request(JsonRpcMessage.request("tools/call", 1, [])) is None
    assert (
        ToolCall.from_request(JsonRpcMessage.request("tools/call", 1, {"x": 1}))
        is None  # no "name"
    )


def test_tool_result_from_response_rejects_non_dict_result() -> None:
    assert ToolResult.from_response(JsonRpcMessage.result_for(1, "scalar")) is None


def test_tool_result_defaults_when_content_missing() -> None:
    result = ToolResult.from_response(JsonRpcMessage.result_for(1, {}))
    assert result is not None
    assert result.content == []
    assert result.is_error is False


# --- session state --------------------------------------------------------


def test_session_records_the_initialize_handshake() -> None:
    session = MCPSession(server_label="srv")
    init_request = JsonRpcMessage.request(
        "initialize",
        1,
        {
            "protocolVersion": "2025-06-18",
            "clientInfo": {"name": "client"},
            "capabilities": {"tools": {}},
        },
    )
    session.observe(init_request, Direction.CLIENT_TO_SERVER)
    assert session.method_for(1) == "initialize"
    assert session.client_info == {"name": "client"}

    init_result = JsonRpcMessage.result_for(
        1, {"protocolVersion": "2025-06-18", "serverInfo": {"name": "server"}}
    )
    session.observe(init_result, Direction.SERVER_TO_CLIENT)
    assert session.server_info == {"name": "server"}
    assert session.method_for(1) is None  # response cleared the pending entry


def test_session_ignores_undecoded_frames() -> None:
    session = MCPSession(server_label="srv")
    session.observe(None, Direction.CLIENT_TO_SERVER)
    assert session.messages_seen == 1


# --- transport helpers ----------------------------------------------------


def test_is_async_pipe_false_for_regular_file(tmp_path: object) -> None:
    path = tmp_path / "f"  # type: ignore[operator]
    path.write_text("x")
    with path.open("rb") as handle:
        assert _is_async_pipe(handle) is False


def test_encode_is_newline_terminated() -> None:
    assert encode(JsonRpcMessage.request("x", 1)).endswith(b"\n")
