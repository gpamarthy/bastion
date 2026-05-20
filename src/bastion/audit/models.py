"""The audit event model.

One :class:`AuditEvent` records a single intercepted item (a tool definition,
call, or result) and the verdict bastion reached on it.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from bastion.core.models import ToolCall
from bastion.rules.types import Verdict

AuditDirection = Literal["definition", "request", "result"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def summarize_arguments(arguments: dict[str, Any], mode: str) -> tuple[str | None, str | None]:
    """Return ``(arg_hash, arg_preview)`` for the configured record mode.

    * ``hashed``   - only the SHA-256 hash is kept.
    * ``redacted`` - hash plus the argument *keys* (values dropped).
    * ``full``     - hash plus the full JSON.
    """
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    arg_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if mode == "full":
        return arg_hash, canonical
    if mode == "redacted":
        return arg_hash, json.dumps(sorted(arguments.keys()))
    return arg_hash, None


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One row of the audit trail."""

    trace_id: str
    session_id: str
    timestamp: str
    server: str
    tool_name: str
    direction: AuditDirection
    decision: str
    taxonomy_ids: tuple[str, ...] = ()
    reason: str | None = None
    rule_results: tuple[dict[str, Any], ...] = ()
    arg_hash: str | None = None
    arg_preview: str | None = None
    latency_ms: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def make_event(
    *,
    session_id: str,
    server: str,
    tool_name: str,
    direction: AuditDirection,
    verdict: Verdict,
    call: ToolCall | None = None,
    record_arguments: str = "redacted",
) -> AuditEvent:
    """Build an :class:`AuditEvent` from an engine verdict."""
    arg_hash: str | None = None
    arg_preview: str | None = None
    if call is not None:
        arg_hash, arg_preview = summarize_arguments(call.arguments, record_arguments)
    taxonomy = tuple(dict.fromkeys(r.threat_class.value for r in verdict.results if not r.passed))
    rule_results = tuple(
        {
            "rule_id": r.rule_id,
            "decision": r.decision.value,
            "threat_class": r.threat_class.value,
            "severity": r.severity.value,
            "reason": r.reason,
            "evidence": r.evidence,
            "latency_ms": round(r.latency_ms, 3),
        }
        for r in verdict.results
        if not r.passed
    )
    return AuditEvent(
        trace_id=uuid.uuid4().hex,
        session_id=session_id,
        timestamp=_now(),
        server=server,
        tool_name=tool_name,
        direction=direction,
        decision=verdict.decision.value,
        taxonomy_ids=taxonomy,
        reason=verdict.reason,
        rule_results=rule_results,
        arg_hash=arg_hash,
        arg_preview=arg_preview,
        latency_ms=round(verdict.total_latency_ms, 3),
    )


__all__ = ["AuditDirection", "AuditEvent", "make_event", "summarize_arguments"]
