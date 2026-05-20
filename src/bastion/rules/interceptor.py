"""The policy interceptor.

Bridges the :class:`~bastion.rules.engine.PolicyEngine` to the pump's
``Interceptor`` protocol. It classifies each frame and runs the matching
rule hooks:

* ``tools/list`` result  -> inspect every tool definition; redact any that a
  rule blocks so the poisoned tool never reaches the client.
* ``tools/call`` request -> inspect the call; block it if a rule says so.
* ``tools/call`` result  -> inspect the result before it reaches the client.

It keeps its own request-id maps (the session pops its correlation table
before the interceptor runs) so it can match a response to its request.
"""

from __future__ import annotations

from typing import Any

from bastion.approval.broker import ApprovalBroker
from bastion.approval.store import ApprovalStore
from bastion.audit.models import AuditDirection, make_event
from bastion.audit.sinks.base import AuditSink, NullSink
from bastion.core import logger
from bastion.core.models import (
    Decision,
    Direction,
    Frame,
    InterceptVerdict,
    JsonRpcId,
    JsonRpcMessage,
    ToolCall,
    ToolDefinition,
    ToolResult,
)
from bastion.proxy.session import MCPSession
from bastion.rules.engine import PolicyEngine
from bastion.rules.types import RuleContext, Verdict

log = logger.get_logger(__name__)


class PolicyInterceptor:
    """An ``Interceptor`` that enforces a :class:`PolicyEngine`."""

    def __init__(
        self,
        engine: PolicyEngine,
        *,
        server_label: str,
        audit_sink: AuditSink | None = None,
        record_arguments: str = "redacted",
        approval_store: ApprovalStore | None = None,
        approval_broker: ApprovalBroker | None = None,
        unresolved_decision: Decision = Decision.BLOCK,
    ) -> None:
        self._engine = engine
        self._server_label = server_label
        self._audit: AuditSink = audit_sink if audit_sink is not None else NullSink()
        self._record_arguments = record_arguments
        # An approval verdict is resolved against the store (remembered
        # decisions), then the broker (live decisions), then falls back to
        # ``unresolved_decision``.
        self._approval_store = approval_store
        self._approval_broker = approval_broker
        self._unresolved_decision = unresolved_decision
        self._inflight_methods: dict[JsonRpcId, str] = {}
        self._inflight_calls: dict[JsonRpcId, ToolCall] = {}
        self.stats: dict[str, int] = {
            "tool_defs_inspected": 0,
            "tools_redacted": 0,
            "calls_inspected": 0,
            "calls_blocked": 0,
        }

    async def _emit(
        self,
        session: MCPSession,
        direction: AuditDirection,
        tool_name: str,
        verdict: Verdict,
        call: ToolCall | None,
    ) -> None:
        await self._audit.emit(
            make_event(
                session_id=session.session_id,
                server=self._server_label,
                tool_name=tool_name,
                direction=direction,
                verdict=verdict,
                call=call,
                record_arguments=self._record_arguments,
            )
        )

    def _context(self, session: MCPSession) -> RuleContext:
        return RuleContext(
            session=session,
            catalog=self._engine.catalog,
            server_label=self._server_label,
        )

    async def inspect(
        self, frame: Frame, direction: Direction, session: MCPSession
    ) -> InterceptVerdict:
        msg = frame.message
        if msg is None:
            return InterceptVerdict.allow()

        if direction is Direction.CLIENT_TO_SERVER and msg.is_request:
            if msg.method is not None:
                self._inflight_methods[msg.id] = msg.method
            if msg.method == "tools/call":
                return await self._on_tool_call(msg, session)
            return InterceptVerdict.allow()

        if direction is Direction.SERVER_TO_CLIENT and msg.is_response:
            method = self._inflight_methods.pop(msg.id, None)
            if method == "tools/list":
                return await self._on_tools_list(msg, session)
            if method == "tools/call":
                return await self._on_tool_result(msg, session)

        return InterceptVerdict.allow()

    async def _on_tool_call(self, msg: JsonRpcMessage, session: MCPSession) -> InterceptVerdict:
        call = ToolCall.from_request(msg)
        if call is None:
            return InterceptVerdict.allow()
        self._inflight_calls[msg.id] = call
        self.stats["calls_inspected"] += 1
        verdict = await self._engine.evaluate_tool_call(call, self._context(session))
        await self._emit(session, "request", call.tool_name, verdict, call)
        return await self._realize_request(verdict, call, session)

    async def _on_tools_list(self, msg: JsonRpcMessage, session: MCPSession) -> InterceptVerdict:
        result = msg.result
        if not isinstance(result, dict):
            return InterceptVerdict.allow()
        tools = result.get("tools")
        if not isinstance(tools, list):
            return InterceptVerdict.allow()

        ctx = self._context(session)
        kept: list[Any] = []
        redacted: list[str] = []
        for entry in tools:
            if not isinstance(entry, dict):
                kept.append(entry)
                continue
            tool = ToolDefinition.from_raw(entry)
            ctx.catalog.record_seen(self._server_label, tool)
            self.stats["tool_defs_inspected"] += 1
            verdict = await self._engine.evaluate_tool_def(tool, ctx)
            if verdict.decision is not Decision.ALLOW:
                await self._emit(session, "definition", tool.name, verdict, None)
            if verdict.blocked:
                redacted.append(tool.name)
                self.stats["tools_redacted"] += 1
                log.warning(
                    "redacted poisoned tool",
                    tool=tool.name,
                    server=self._server_label,
                    reason=verdict.reason,
                    session=session.session_id,
                )
            else:
                kept.append(entry)

        if not redacted:
            return InterceptVerdict.allow()
        new_result = dict(result)
        new_result["tools"] = kept
        new_raw = dict(msg.raw)
        new_raw["result"] = new_result
        return InterceptVerdict.allow(JsonRpcMessage(raw=new_raw))

    async def _on_tool_result(self, msg: JsonRpcMessage, session: MCPSession) -> InterceptVerdict:
        call = self._inflight_calls.pop(msg.id, None)
        result = ToolResult.from_response(msg)
        if result is None:
            return InterceptVerdict.allow()
        verdict = await self._engine.evaluate_tool_result(result, call, self._context(session))
        tool_name = call.tool_name if call is not None else "unknown"
        await self._emit(session, "result", tool_name, verdict, call)
        if verdict.blocked:
            return InterceptVerdict.block(
                verdict.reason or "tool result blocked by bastion policy",
                rule_results=verdict.results,
            )
        return InterceptVerdict.allow()

    async def _realize_request(
        self, verdict: Verdict, call: ToolCall, session: MCPSession
    ) -> InterceptVerdict:
        if verdict.decision is Decision.BLOCK:
            self.stats["calls_blocked"] += 1
            return InterceptVerdict.block(
                verdict.reason or "tool call blocked by bastion policy",
                rule_results=verdict.results,
            )
        if verdict.decision is Decision.REQUIRE_APPROVAL:
            decision = await self._resolve_approval(verdict, call, session)
            if decision is Decision.BLOCK:
                self.stats["calls_blocked"] += 1
                return InterceptVerdict.block(
                    verdict.reason or "tool call denied by approval",
                    rule_results=verdict.results,
                )
        return InterceptVerdict.allow()

    async def _resolve_approval(
        self, verdict: Verdict, call: ToolCall, session: MCPSession
    ) -> Decision:
        """Resolve an approval verdict: remembered store, then live broker,
        then the configured fallback."""
        if self._approval_store is not None:
            remembered = self._approval_store.decision_for(self._server_label, call.tool_name)
            if remembered is not None:
                return remembered
        if self._approval_broker is not None:
            return await self._approval_broker.request(
                server=self._server_label,
                tool=call.tool_name,
                reason=verdict.reason or "tool call requires approval",
                session_id=session.session_id,
            )
        if self._unresolved_decision is Decision.BLOCK:
            log.warning(
                "tool call requires approval; denied (unresolved)",
                tool=call.tool_name,
                reason=verdict.reason,
            )
        else:
            log.warning(
                "tool call requires approval; allowed (unresolved)",
                tool=call.tool_name,
                reason=verdict.reason,
            )
        return self._unresolved_decision


__all__ = ["PolicyInterceptor"]
