"""Evidence-grade audit logging.

Every intercepted tool definition, call, and result that triggers a finding
is recorded as an :class:`AuditEvent` and written to a pluggable sink.
"""

from __future__ import annotations

from bastion.audit.models import AuditEvent
from bastion.audit.sinks.base import AuditSink, NullSink
from bastion.audit.sinks.jsonl import JsonlAuditSink
from bastion.audit.sinks.sqlite import SqliteAuditSink
from bastion.rules.schema import AuditConfig

_DEFAULT_DB = "bastion-audit.db"
_DEFAULT_JSONL = "bastion-audit.jsonl"


def build_sink(config: AuditConfig) -> AuditSink:
    """Construct the audit sink described by an :class:`AuditConfig`."""
    if config.sink == "none":
        return NullSink()
    if config.sink == "jsonl":
        return JsonlAuditSink(path=config.path or _DEFAULT_JSONL)
    return SqliteAuditSink(path=config.path or _DEFAULT_DB)


__all__ = [
    "AuditEvent",
    "AuditSink",
    "JsonlAuditSink",
    "NullSink",
    "SqliteAuditSink",
    "build_sink",
]
