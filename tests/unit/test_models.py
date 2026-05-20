"""Unit tests for the core JSON-RPC / intercept models."""

from __future__ import annotations

from bastion.core.models import (
    BLOCKED_ERROR_CODE,
    Decision,
    Frame,
    InterceptVerdict,
    JsonRpcMessage,
    MessageKind,
)


def test_request_classification() -> None:
    msg = JsonRpcMessage(raw={"jsonrpc": "2.0", "id": 7, "method": "tools/call"})
    assert msg.kind is MessageKind.REQUEST
    assert msg.is_request and not msg.is_notification and not msg.is_response
    assert msg.id == 7
    assert msg.method == "tools/call"


def test_notification_has_no_id() -> None:
    msg = JsonRpcMessage(raw={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert msg.kind is MessageKind.NOTIFICATION
    assert msg.is_notification
    assert msg.id is None


def test_response_with_null_result_is_a_response() -> None:
    msg = JsonRpcMessage(raw={"jsonrpc": "2.0", "id": 1, "result": None})
    assert msg.kind is MessageKind.RESPONSE
    assert msg.is_response


def test_error_response_classification() -> None:
    msg = JsonRpcMessage(
        raw={"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "nope"}}
    )
    assert msg.kind is MessageKind.ERROR
    assert msg.is_response
    assert msg.error == {"code": -32601, "message": "nope"}


def test_builders_roundtrip() -> None:
    req = JsonRpcMessage.request("ping", 3, {"x": 1})
    assert req.is_request and req.method == "ping" and req.params == {"x": 1}

    res = JsonRpcMessage.result_for(3, {"ok": True})
    assert res.is_response and res.result == {"ok": True}

    err = JsonRpcMessage.error_for(3, BLOCKED_ERROR_CODE, "blocked")
    assert err.error == {"code": BLOCKED_ERROR_CODE, "message": "blocked"}
    assert err.id == 3


def test_frame_decoded_flag() -> None:
    assert Frame(raw=b"{}", message=JsonRpcMessage(raw={})).decoded
    assert not Frame(raw=b"oops", message=None).decoded


def test_intercept_verdict_helpers() -> None:
    allow = InterceptVerdict.allow()
    assert allow.decision is Decision.ALLOW

    block = InterceptVerdict.block("tool poisoning")
    assert block.decision is Decision.BLOCK
    assert block.reason == "tool poisoning"
