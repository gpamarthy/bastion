"""Session capture and replay.

A :class:`SessionRecorder` writes every JSON-RPC frame the gateway sees to a
JSONL capture file. :func:`replay_capture` feeds a recorded capture back
through a fresh interceptor, so a policy change can be tested against real
traffic before it is deployed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from bastion.core import logger
from bastion.core.models import Direction, Frame, InterceptVerdict, JsonRpcMessage
from bastion.proxy.pump import Interceptor
from bastion.proxy.session import MCPSession

log = logger.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class CapturedFrame:
    """One recorded frame: its direction and decoded JSON-RPC message."""

    direction: Direction
    message: dict[str, object]


class SessionRecorder:
    """Appends every decoded frame to a JSONL capture file."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, direction: Direction, frame: Frame) -> None:
        if frame.message is None:
            return
        line = json.dumps(
            {"direction": direction.value, "message": frame.message.raw},
            separators=(",", ":"),
            ensure_ascii=False,
        )
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


class RecordingInterceptor:
    """Wraps an interceptor, recording every frame before delegating."""

    def __init__(self, inner: Interceptor, recorder: SessionRecorder) -> None:
        self._inner = inner
        self._recorder = recorder

    async def inspect(
        self, frame: Frame, direction: Direction, session: MCPSession
    ) -> InterceptVerdict:
        self._recorder.record(direction, frame)
        return await self._inner.inspect(frame, direction, session)


def load_capture(path: str | Path) -> list[CapturedFrame]:
    """Load a JSONL capture file into a list of :class:`CapturedFrame`."""
    frames: list[CapturedFrame] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        record = json.loads(stripped)
        direction = (
            Direction.CLIENT_TO_SERVER
            if record.get("direction") == Direction.CLIENT_TO_SERVER.value
            else Direction.SERVER_TO_CLIENT
        )
        message = record.get("message")
        if isinstance(message, dict):
            frames.append(CapturedFrame(direction=direction, message=message))
    return frames


async def replay_capture(
    frames: list[CapturedFrame], interceptor: Interceptor
) -> list[InterceptVerdict]:
    """Feed a recorded capture through ``interceptor`` and return its verdicts."""
    session = MCPSession(server_label="replay")
    verdicts: list[InterceptVerdict] = []
    for captured in frames:
        frame = Frame(raw=b"", message=JsonRpcMessage(raw=captured.message))
        session.observe(frame.message, captured.direction)
        verdicts.append(await interceptor.inspect(frame, captured.direction, session))
    return verdicts


__all__ = [
    "CapturedFrame",
    "RecordingInterceptor",
    "SessionRecorder",
    "load_capture",
    "replay_capture",
]
