"""Per-rule timeout enforcement.

bastion sits in the hot path of every tool call, so a slow or hung rule must
never stall the gateway. Each rule runs under :func:`with_timeout`; the engine
additionally tracks a total budget across all rules.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from typing import TypeVar

from bastion.core.errors import RuleTimeoutError

T = TypeVar("T")


async def with_timeout(coro: Awaitable[T], *, timeout_ms: int) -> T:
    """Run ``coro`` with a per-rule timeout. Raises RuleTimeoutError on miss."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout_ms / 1000.0)
    except asyncio.TimeoutError as exc:
        raise RuleTimeoutError(f"rule exceeded {timeout_ms}ms budget") from exc


__all__ = ["with_timeout"]
