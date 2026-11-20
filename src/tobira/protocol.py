"""Wire protocol for Tobira.

A single mutually-authenticated TLS connection carries both control messages and
multiplexed application data. This is what makes the zero trust model work: an
App Connector keeps exactly one *outbound* connection to the broker and every
user session is a stream inside it, so the private network never needs an
inbound firewall rule.

Frame layout (9 byte header, big endian)::

    +--------+-----------------+-----------------+============+
    | type:1 | stream_id:4     | length:4        | payload    |
    +--------+-----------------+-----------------+============+

``CONTROL`` frames carry UTF-8 JSON. ``DATA`` frames carry opaque application
bytes. ``CLOSE`` frames tear down a single stream without affecting the tunnel.
"""

from __future__ import annotations

import asyncio
import enum
import json
import struct
from dataclasses import dataclass, field
from typing import Any

HEADER = struct.Struct(">BII")
HEADER_SIZE = HEADER.size

#: Hard ceiling on a single frame. Prevents a hostile peer from asking us to
#: allocate an arbitrary amount of memory before authentication completes.
MAX_FRAME_SIZE = 1 << 20  # 1 MiB

#: Payload size used when relaying application bytes.
RELAY_CHUNK = 64 * 1024

PROTOCOL_VERSION = 1


class FrameType(enum.IntEnum):
    CONTROL = 0
    DATA = 1
    CLOSE = 2


class Msg(str, enum.Enum):
    """Control message types."""

    # handshake
    HELLO = "hello"
    HELLO_OK = "hello_ok"
    HELLO_FAIL = "hello_fail"

    # connector lifecycle
    REGISTER = "register"
    REGISTER_OK = "register_ok"
    REGISTER_FAIL = "register_fail"

    # client lifecycle
    AUTH = "auth"
    AUTH_OK = "auth_ok"
    AUTH_FAIL = "auth_fail"
    POSTURE_REFRESH = "posture_refresh"
    SESSION_TERMINATE = "session_terminate"

    # per-connection authorisation
    OPEN = "open"
    OPEN_OK = "open_ok"
    OPEN_FAIL = "open_fail"
    DIAL = "dial"
    DIAL_OK = "dial_ok"
    DIAL_FAIL = "dial_fail"

    # keepalive
    PING = "ping"
    PONG = "pong"


class Role(str, enum.Enum):
    CONNECTOR = "connector"
    CLIENT = "client"


class ProtocolError(Exception):
    """Raised when a peer sends something that violates the wire protocol."""


#: Exceptions that simply mean "the tunnel is gone". Catching them together
#: keeps the reader loops readable and makes teardown uniform.
TUNNEL_CLOSED = (
    asyncio.IncompleteReadError,
    ConnectionError,
    ProtocolError,
    asyncio.CancelledError,
)


@dataclass(slots=True)
class Frame:
    type: FrameType
    stream_id: int
    payload: bytes = b""

    def encode(self) -> bytes:
        if len(self.payload) > MAX_FRAME_SIZE:
            raise ProtocolError(f"frame payload too large: {len(self.payload)}")
        return HEADER.pack(int(self.type), self.stream_id, len(self.payload)) + self.payload

    @property
    def json(self) -> dict[str, Any]:
        if self.type is not FrameType.CONTROL:
            raise ProtocolError("only CONTROL frames carry JSON")
        try:
            obj = json.loads(self.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError(f"malformed control payload: {exc}") from exc
        if not isinstance(obj, dict):
            raise ProtocolError("control payload must be a JSON object")
        return obj


def control(msg: Msg | str, stream_id: int = 0, **fields: Any) -> Frame:
    """Build a CONTROL frame."""
    body = {"msg": msg.value if isinstance(msg, Msg) else msg, **fields}
    return Frame(FrameType.CONTROL, stream_id, json.dumps(body, separators=(",", ":")).encode())


def data(stream_id: int, payload: bytes) -> Frame:
    return Frame(FrameType.DATA, stream_id, payload)


def close(stream_id: int, reason: str = "") -> Frame:
    return Frame(FrameType.CLOSE, stream_id, reason.encode("utf-8")[:256])


async def read_frame(reader: asyncio.StreamReader) -> Frame:
    """Read exactly one frame. Raises ``asyncio.IncompleteReadError`` at EOF."""
    header = await reader.readexactly(HEADER_SIZE)
    raw_type, stream_id, length = HEADER.unpack(header)
    if length > MAX_FRAME_SIZE:
        raise ProtocolError(f"peer announced oversized frame: {length}")
    payload = await reader.readexactly(length) if length else b""
    try:
        ftype = FrameType(raw_type)
    except ValueError as exc:
        raise ProtocolError(f"unknown frame type {raw_type}") from exc
    return Frame(ftype, stream_id, payload)


class FrameWriter:
    """Serialises frame writes so multiplexed streams cannot interleave bytes."""

    __slots__ = ("_closed", "_lock", "_writer")

    def __init__(self, writer: asyncio.StreamWriter) -> None:
        self._writer = writer
        self._lock = asyncio.Lock()
        self._closed = False

    @property
    def transport_closing(self) -> bool:
        return self._closed or self._writer.is_closing()

    async def send(self, frame: Frame) -> None:
        if self.transport_closing:
            return
        async with self._lock:
            try:
                self._writer.write(frame.encode())
                await self._writer.drain()
            except (ConnectionError, RuntimeError):
                self._closed = True

    async def aclose(self) -> None:
        self._closed = True
        try:
            self._writer.close()
            # A TLS transport can wait indefinitely for the peer's close_notify;
            # we have already decided the tunnel is finished, so cap the wait.
            await asyncio.wait_for(self._writer.wait_closed(), 2.0)
        except (ConnectionError, RuntimeError, OSError, asyncio.TimeoutError):
            pass
        except asyncio.CancelledError:
            raise


@dataclass(slots=True)
class Stream:
    """One relayed TCP connection living inside a tunnel."""

    stream_id: int
    app: str
    queue: asyncio.Queue[bytes | None] = field(default_factory=asyncio.Queue)
    opened: asyncio.Future[bool] | None = None
    bytes_in: int = 0
    bytes_out: int = 0
