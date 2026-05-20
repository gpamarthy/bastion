"""Core domain models: JSON-RPC messages, wire frames, and intercept verdicts.

A :class:`JsonRpcMessage` is a thin, immutable wrapper over the decoded JSON
object. bastion deliberately keeps the original ``raw`` mapping rather than a
fixed schema so it can forward any spec-valid MCP message byte-faithfully, even
fields it does not yet understand (forward-compatibility with protocol drift).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# JSON-RPC error code bastion returns when it blocks a request. Lives in the
# implementation-defined server-error range (-32000..-32099) per the spec.
BLOCKED_ERROR_CODE = -32099

JsonRpcId = str | int | None


class Direction(str, Enum):
    """Which way a message is travelling through the gateway."""

    CLIENT_TO_SERVER = "c2s"
    SERVER_TO_CLIENT = "s2c"


class MessageKind(str, Enum):
    """JSON-RPC message classification."""

    REQUEST = "request"
    NOTIFICATION = "notification"
    RESPONSE = "response"
    ERROR = "error"
    UNKNOWN = "unknown"


class Decision(str, Enum):
    """A policy decision about a single intercepted message."""

    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True, slots=True)
class JsonRpcMessage:
    """An immutable view over one decoded JSON-RPC object."""

    raw: dict[str, Any]

    @property
    def id(self) -> JsonRpcId:
        rid = self.raw.get("id")
        if rid is None or isinstance(rid, (str, int)):
            return rid
        return None

    @property
    def method(self) -> str | None:
        m = self.raw.get("method")
        return m if isinstance(m, str) else None

    @property
    def params(self) -> Any:
        return self.raw.get("params")

    @property
    def result(self) -> Any:
        return self.raw.get("result")

    @property
    def error(self) -> dict[str, Any] | None:
        err = self.raw.get("error")
        return err if isinstance(err, dict) else None

    @property
    def kind(self) -> MessageKind:
        has_method = "method" in self.raw
        has_id = "id" in self.raw
        if has_method:
            return MessageKind.REQUEST if has_id else MessageKind.NOTIFICATION
        if "error" in self.raw:
            return MessageKind.ERROR
        if "result" in self.raw:
            return MessageKind.RESPONSE
        return MessageKind.UNKNOWN

    @property
    def is_request(self) -> bool:
        return self.kind == MessageKind.REQUEST

    @property
    def is_notification(self) -> bool:
        return self.kind == MessageKind.NOTIFICATION

    @property
    def is_response(self) -> bool:
        return self.kind in (MessageKind.RESPONSE, MessageKind.ERROR)

    def with_raw(self, raw: dict[str, Any]) -> JsonRpcMessage:
        """Return a copy backed by a different raw mapping (used for rewrites)."""
        return JsonRpcMessage(raw=raw)

    @staticmethod
    def request(method: str, rid: JsonRpcId, params: Any = None) -> JsonRpcMessage:
        raw: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            raw["params"] = params
        return JsonRpcMessage(raw=raw)

    @staticmethod
    def result_for(rid: JsonRpcId, result: Any) -> JsonRpcMessage:
        return JsonRpcMessage(raw={"jsonrpc": "2.0", "id": rid, "result": result})

    @staticmethod
    def error_for(
        rid: JsonRpcId,
        code: int,
        message: str,
        data: Any = None,
    ) -> JsonRpcMessage:
        """Build a spec-valid JSON-RPC error response for a blocked request."""
        err: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return JsonRpcMessage(raw={"jsonrpc": "2.0", "id": rid, "error": err})


@dataclass(frozen=True, slots=True)
class Frame:
    """One unit read off the wire: the exact bytes plus its decoded message.

    ``message`` is ``None`` when the line was not a decodable JSON object (a
    JSON array batch, malformed JSON, or a non-object value). The gateway still
    forwards such frames verbatim so it never breaks an otherwise-valid session.
    """

    raw: bytes
    message: JsonRpcMessage | None = None

    @property
    def decoded(self) -> bool:
        return self.message is not None


@dataclass(frozen=True, slots=True)
class InterceptVerdict:
    """The gateway's decision about one intercepted frame.

    - ``ALLOW``  forward ``message`` (possibly rewritten) downstream.
    - ``BLOCK``  do not forward; if the frame was a request, the gateway
       synthesises a JSON-RPC error carrying the original id.
    - ``REQUIRE_APPROVAL`` park the message pending an out-of-band decision.
    """

    decision: Decision = Decision.ALLOW
    message: JsonRpcMessage | None = None
    reason: str | None = None
    rule_results: tuple[Any, ...] = field(default_factory=tuple)

    @staticmethod
    def allow(message: JsonRpcMessage | None = None) -> InterceptVerdict:
        return InterceptVerdict(decision=Decision.ALLOW, message=message)

    @staticmethod
    def block(reason: str, rule_results: tuple[Any, ...] = ()) -> InterceptVerdict:
        return InterceptVerdict(decision=Decision.BLOCK, reason=reason, rule_results=rule_results)


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """One tool as advertised in a ``tools/list`` result."""

    name: str
    description: str
    input_schema: dict[str, Any]
    raw: dict[str, Any]

    @staticmethod
    def from_raw(raw: dict[str, Any]) -> ToolDefinition:
        schema = raw.get("inputSchema")
        return ToolDefinition(
            name=str(raw.get("name", "")),
            description=str(raw.get("description") or ""),
            input_schema=schema if isinstance(schema, dict) else {},
            raw=raw,
        )


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A ``tools/call`` request: which tool, with what arguments."""

    tool_name: str
    arguments: dict[str, Any]
    request_id: JsonRpcId
    raw: dict[str, Any]

    @staticmethod
    def from_request(message: JsonRpcMessage) -> ToolCall | None:
        params = message.params
        if not isinstance(params, dict):
            return None
        name = params.get("name")
        if not isinstance(name, str):
            return None
        args = params.get("arguments")
        return ToolCall(
            tool_name=name,
            arguments=args if isinstance(args, dict) else {},
            request_id=message.id,
            raw=params,
        )


@dataclass(frozen=True, slots=True)
class ToolResult:
    """A ``tools/call`` response payload."""

    content: list[Any]
    is_error: bool
    raw: dict[str, Any]

    @staticmethod
    def from_response(message: JsonRpcMessage) -> ToolResult | None:
        result = message.result
        if not isinstance(result, dict):
            return None
        content = result.get("content")
        return ToolResult(
            content=content if isinstance(content, list) else [],
            is_error=bool(result.get("isError", False)),
            raw=result,
        )


__all__ = [
    "BLOCKED_ERROR_CODE",
    "Decision",
    "Direction",
    "Frame",
    "InterceptVerdict",
    "JsonRpcId",
    "JsonRpcMessage",
    "MessageKind",
    "ToolCall",
    "ToolDefinition",
    "ToolResult",
]
