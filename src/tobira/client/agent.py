"""The Client Connector - the agent on a user's device.

Like the App Connector, it only dials *outbound*. After the broker accepts the
device certificate, the agent proves who the user is (a device-bound token) and
what state the device is in (a signed posture attestation over a nonce the
broker chose).

The broker answers with the list of applications this user may reach *right
now*. The agent then exposes each one on a loopback port, so ordinary tools
(``curl``, a database client, a browser) can use it without knowing anything
about zero trust. Nothing is routed; each connection is authorised on its own.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
from pathlib import Path
from typing import Any

from ..identity import IdentityProvider
from ..pki import Identity, client_context
from ..posture import DeviceState, attest
from ..protocol import (
    RELAY_CHUNK,
    TUNNEL_CLOSED,
    FrameType,
    FrameWriter,
    Msg,
    Role,
    control,
    read_frame,
)
from ..protocol import (
    close as close_frame,
)
from ..protocol import (
    data as data_frame,
)

OPEN_TIMEOUT = 15.0


class AccessDenied(Exception):
    """The broker refused a connection. ``reason`` is the policy verdict."""

    def __init__(self, app: str, reason: str) -> None:
        super().__init__(f"access to {app!r} denied: {reason}")
        self.app = app
        self.reason = reason


class SessionTerminated(Exception):
    """The broker tore the session down mid-flight."""


class RemoteStream:
    """One authorised TCP connection to a private application."""

    def __init__(self, stream_id: int, app: str, writer: FrameWriter) -> None:
        self.stream_id = stream_id
        self.app = app
        self._writer = writer
        self._inbox: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._closed = False
        self.close_reason = ""

    @property
    def closed(self) -> bool:
        """True once the broker, the application or we tore the stream down."""
        return self._closed

    async def send(self, payload: bytes) -> None:
        if self._closed:
            raise ConnectionResetError(f"stream to {self.app} is closed")
        await self._writer.send(data_frame(self.stream_id, payload))

    async def receive(self, timeout: float | None = 10.0) -> bytes | None:
        """Next chunk from the application, or ``None`` once it has closed."""
        if timeout is None:
            return await self._inbox.get()
        try:
            return await asyncio.wait_for(self._inbox.get(), timeout)
        except asyncio.TimeoutError:
            return b""

    async def read_all(self, timeout: float = 5.0) -> bytes:
        chunks: list[bytes] = []
        while True:
            chunk = await self.receive(timeout)
            if chunk is None or chunk == b"":
                break
            chunks.append(chunk)
        return b"".join(chunks)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            await self._writer.send(close_frame(self.stream_id, "client_closed"))

    # internal
    def _deliver(self, payload: bytes) -> None:
        self._inbox.put_nowait(payload)

    def _eof(self, reason: str) -> None:
        self._closed = True
        self.close_reason = reason
        self._inbox.put_nowait(None)


class ClientConnector:
    def __init__(
        self,
        device_id: str,
        identity: Identity,
        ca_cert: Path,
        broker_host: str,
        broker_port: int,
        *,
        device_state: DeviceState | None = None,
        server_hostname: str = "tobira-broker",
    ) -> None:
        self.device_id = device_id
        self.identity = identity
        self.ca_cert = ca_cert
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.state = device_state or DeviceState(device_id=device_id)
        self.server_hostname = server_hostname

        self.session_id = ""
        self.apps: list[str] = []
        self.auth_failure = ""
        self.terminated_reason = ""

        self._writer: FrameWriter | None = None
        self._reader: asyncio.StreamReader | None = None
        self._pump: asyncio.Task[None] | None = None
        self._ids = itertools.count(1)
        self._streams: dict[int, RemoteStream] = {}
        self._pending: dict[int, asyncio.Future[tuple[bool, str]]] = {}
        self._control_waiters: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._listeners: list[asyncio.AbstractServer] = []
        self._next_nonce = ""

    # ------------------------------------------------------------- lifecycle

    async def connect(self, token: str) -> bool:
        """Open the tunnel and authenticate. Returns ``False`` if refused."""
        ctx = client_context(self.identity, self.ca_cert)
        reader, writer = await asyncio.open_connection(
            self.broker_host, self.broker_port, ssl=ctx, server_hostname=self.server_hostname
        )
        self._reader = reader
        self._writer = FrameWriter(writer)

        await self._writer.send(control(Msg.HELLO, role=Role.CLIENT.value, name=self.device_id))
        hello = (await read_frame(reader)).json
        if hello.get("msg") != Msg.HELLO_OK.value:
            self.auth_failure = str(hello.get("reason", "hello_failed"))
            await self._writer.aclose()
            return False

        nonce = str(hello["nonce"])
        attestation = attest(self.state, nonce, self.identity.key_path)
        await self._writer.send(
            control(Msg.AUTH, token=token, nonce=nonce, posture=attestation)
        )

        reply = (await read_frame(reader)).json
        if reply.get("msg") != Msg.AUTH_OK.value:
            self.auth_failure = str(reply.get("reason", "auth_failed"))
            await self._writer.aclose()
            return False

        self.session_id = str(reply["session_id"])
        self.apps = list(reply.get("apps", []))
        self._next_nonce = str(reply.get("next_nonce", ""))
        self._pump = asyncio.create_task(self._run(), name=f"client-{self.device_id}")
        return True

    async def close(self) -> None:
        for server in self._listeners:
            server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(server.wait_closed(), 2.0)
        self._listeners.clear()
        if self._pump:
            self._pump.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._pump
            self._pump = None
        for stream in list(self._streams.values()):
            stream._eof("client_shutdown")
        self._streams.clear()
        if self._writer:
            await self._writer.aclose()

    # ------------------------------------------------------------- main loop

    async def _run(self) -> None:
        assert self._reader is not None
        try:
            while True:
                frame = await read_frame(self._reader)

                if frame.type is FrameType.CONTROL:
                    body = frame.json
                    msg = str(body.get("msg", ""))

                    if msg in (Msg.OPEN_OK.value, Msg.OPEN_FAIL.value):
                        future = self._pending.pop(frame.stream_id, None)
                        if future and not future.done():
                            future.set_result(
                                (msg == Msg.OPEN_OK.value, str(body.get("reason", "")))
                            )

                    elif msg == Msg.SESSION_TERMINATE.value:
                        self.terminated_reason = str(body.get("reason", "terminated"))
                        for stream in list(self._streams.values()):
                            stream._eof(self.terminated_reason)
                        self._streams.clear()

                    elif msg == Msg.PING.value and self._writer:
                        await self._writer.send(control(Msg.PONG))

                    else:
                        waiter = self._control_waiters.pop(msg, None)
                        if waiter and not waiter.done():
                            waiter.set_result(body)

                elif frame.type is FrameType.DATA:
                    stream = self._streams.get(frame.stream_id)
                    if stream:
                        stream._deliver(frame.payload)

                elif frame.type is FrameType.CLOSE:
                    stream = self._streams.pop(frame.stream_id, None)
                    if stream:
                        stream._eof(frame.payload.decode("utf-8", "replace"))

        except TUNNEL_CLOSED:
            for stream in list(self._streams.values()):
                stream._eof("tunnel_closed")
            self._streams.clear()

    # -------------------------------------------------------------- requests

    async def open(self, app: str) -> RemoteStream:
        """Ask the broker to authorise one connection to ``app``."""
        if self._writer is None:
            raise ConnectionError("client is not connected")
        if self.terminated_reason:
            raise SessionTerminated(self.terminated_reason)

        stream_id = next(self._ids)
        future: asyncio.Future[tuple[bool, str]] = asyncio.get_running_loop().create_future()
        self._pending[stream_id] = future
        await self._writer.send(control(Msg.OPEN, stream_id=stream_id, app=app))

        try:
            allowed, reason = await asyncio.wait_for(future, OPEN_TIMEOUT)
        except asyncio.TimeoutError:
            self._pending.pop(stream_id, None)
            raise AccessDenied(app, "timeout") from None

        if not allowed:
            raise AccessDenied(app, reason)

        stream = RemoteStream(stream_id, app, self._writer)
        self._streams[stream_id] = stream
        return stream

    async def request(self, app: str, payload: bytes, *, timeout: float = 5.0) -> bytes:
        """Convenience: open, send, read to EOF, close."""
        stream = await self.open(app)
        try:
            await stream.send(payload)
            return await stream.read_all(timeout=timeout)
        finally:
            await stream.close()

    # ------------------------------------------------- loopback app listeners

    async def listen(self, app: str, host: str = "127.0.0.1", port: int = 0) -> int:
        """Expose ``app`` on a local port, the way a real ZTNA agent does."""

        async def handle(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                stream = await self.open(app)
            except (AccessDenied, SessionTerminated):
                writer.close()
                return

            async def upstream() -> None:
                try:
                    while True:
                        chunk = await reader.read(RELAY_CHUNK)
                        if not chunk:
                            break
                        await stream.send(chunk)
                except (ConnectionError, asyncio.CancelledError):
                    pass

            async def downstream() -> None:
                try:
                    while True:
                        chunk = await stream.receive(timeout=None)
                        if chunk is None:
                            break
                        writer.write(chunk)
                        await writer.drain()
                except (ConnectionError, asyncio.CancelledError):
                    pass

            try:
                await asyncio.gather(upstream(), downstream())
            finally:
                await stream.close()
                with contextlib.suppress(Exception):
                    writer.close()

        server = await asyncio.start_server(handle, host, port)
        self._listeners.append(server)
        return int(server.sockets[0].getsockname()[1])

    # ---------------------------------------------- continuous re-attestation

    async def refresh_posture(self, state: DeviceState | None = None) -> dict[str, Any]:
        """Re-attest device posture; the broker may revoke live streams."""
        if self._writer is None:
            raise ConnectionError("client is not connected")
        if state is not None:
            self.state = state

        attestation = attest(self.state, self._next_nonce, self.identity.key_path)
        waiter: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._control_waiters["posture_refresh_ok"] = waiter
        await self._writer.send(control(Msg.POSTURE_REFRESH, posture=attestation))

        try:
            reply = await asyncio.wait_for(waiter, OPEN_TIMEOUT)
        except asyncio.TimeoutError:
            self._control_waiters.pop("posture_refresh_ok", None)
            if self.terminated_reason:
                raise SessionTerminated(self.terminated_reason) from None
            raise

        self._next_nonce = str(reply.get("next_nonce", ""))
        self.apps = list(reply.get("apps", self.apps))
        return reply


def issue_device_token(
    idp: IdentityProvider, username: str, identity: Identity, *, mfa: bool = False
) -> str:
    """Helper: mint a token bound to this device's certificate."""
    return idp.issue(username, identity.thumbprint, mfa=mfa)
