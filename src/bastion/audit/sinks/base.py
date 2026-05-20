"""The audit sink interface and a no-op sink."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from bastion.audit.models import AuditEvent


@runtime_checkable
class AuditSink(Protocol):
    """A destination for audit events."""

    async def emit(self, event: AuditEvent) -> None: ...

    async def close(self) -> None: ...


class NullSink:
    """An audit sink that discards every event."""

    async def emit(self, event: AuditEvent) -> None:  # noqa: ARG002
        return None

    async def close(self) -> None:
        return None


__all__ = ["AuditSink", "NullSink"]
