"""structlog configuration.

bastion logs to **stderr only** - stdout is reserved for the MCP JSON-RPC
stream in stdio mode, so any stray stdout write would corrupt the protocol.
Trace correlation (``session_id``) is bound via ``contextvars`` and propagated
to every log call automatically.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Literal

import structlog
from structlog.contextvars import merge_contextvars
from structlog.processors import (
    JSONRenderer,
    StackInfoRenderer,
    TimeStamper,
    UnicodeDecoder,
    add_log_level,
    format_exc_info,
)
from structlog.stdlib import BoundLogger

LogFormat = Literal["json", "console"]


def configure(*, level: str = "INFO", fmt: LogFormat = "console") -> None:
    """Configure structlog for the process. Idempotent. Always writes to stderr."""
    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, level.upper(), logging.INFO),
        stream=sys.stderr,
    )
    shared_processors: list[Any] = [
        merge_contextvars,
        add_log_level,
        TimeStamper(fmt="iso", utc=True),
        StackInfoRenderer(),
        format_exc_info,
        UnicodeDecoder(),
    ]
    renderer: Any = JSONRenderer() if fmt == "json" else structlog.dev.ConsoleRenderer(colors=True)
    structlog.configure(
        processors=[*shared_processors, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO),
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> BoundLogger:
    """Return a structlog BoundLogger. Configure once via :func:`configure`."""
    return structlog.get_logger(name)  # type: ignore[no-any-return]


__all__ = ["LogFormat", "configure", "get_logger"]
