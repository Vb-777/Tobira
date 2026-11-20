"""The App Connector.

This process runs *inside* the private network, next to the applications. It
opens one outbound mTLS connection to the broker and never binds a listening
socket, which is the property that removes the applications from the attack
surface entirely: there is nothing for an attacker on the network to scan,
fingerprint or exploit.

Defence in depth: the connector keeps its own allow-list of the applications it
serves and resolves ``app name -> host:port`` locally. A broker that was itself
compromised still cannot use the connector as a general-purpose proxy into the
private network, because it can only name applications the connector already
publishes.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..pki import Identity, client_context
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

DIAL_CONNECT_TIMEOUT = 5.0


@dataclass(slots=True)
class PublishedApp:
    name: str
    host: str
    port: int


class AppConnector:
    def __init__(
        self,
        name: str,
        identity: Identity,
        ca_cert: Path,
        broker_host: str,
        broker_port: int,
        apps: list[PublishedApp],
        *,
        server_hostname: str = "tobira-broker",
    ) -> None:
        self.name = name
        self.identity = identity
        self.ca_cert = ca_cert
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.apps = {app.name: app for app in apps}
        self.server_hostname = server_hostname

        self._writer: FrameWriter | None = None
        self._reader: asyncio.StreamReader | None = None
        self._task: asyncio.Task[None] | None = None
        self._sockets: dict[int, asyncio.StreamWriter] = {}
        self._pumps: dict[int, asyncio.Task[None]] = {}
        self._dials: set[asyncio.Task[None]] = set()
        self.registered: asyncio.Event = asyncio.Event()
        self.last_error: str = ""

    # ------------------------------------------------------------- lifecycle

    async def start(self) -> None:
        ctx = client_context(self.identity, self.ca_cert)
        reader, writer = await asyncio.open_connection(
            self.broker_host, self.broker_port, ssl=ctx, server_hostname=self.server_hostname
        )
        self._reader = reader
        self._writer = FrameWriter(writer)

        await self._writer.send(control(Msg.HELLO, role=Role.CONNECTOR.value, name=self.name))
        hello = await read_frame(reader)
        body = hello.json
        if body.get("msg") != Msg.HELLO_OK.value:
            self.last_error = str(body.get("reason", "hello_failed"))
            await self._writer.aclose()
            raise ConnectionError(f"broker rejected connector: {self.last_error}")

        await self._writer.send(control(Msg.REGISTER, apps=sorted(self.apps)))
        reply = await read_frame(reader)
        body = reply.json
        if body.get("msg") != Msg.REGISTER_OK.value:
            self.last_error = str(body.get("reason", "register_failed"))
            await self._writer.aclose()
            raise ConnectionError(f"broker refused registration: {self.last_error}")

        self.registered.set()
        self._task = asyncio.create_task(self._run(), name=f"connector-{self.name}")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        for task in list(self._pumps.values()):
            task.cancel()
        self._pumps.clear()
        for sock in list(self._sockets.values()):
            with contextlib.suppress(Exception):
                sock.close()
        self._sockets.clear()
        if self._writer:
            await self._writer.aclose()
        self.registered.clear()

    # ------------------------------------------------------------- main loop

    async def _run(self) -> None:
        assert self._reader is not None and self._writer is not None
        try:
            while True:
                frame = await read_frame(self._reader)

                if frame.type is FrameType.CONTROL:
                    body = frame.json
                    msg = body.get("msg")
                    if msg == Msg.DIAL.value:
                        # The stream id always travels in the frame header, never
                        # in the JSON body, so control and data agree by design.
                        task = asyncio.create_task(
                            self._dial(frame.stream_id, str(body.get("app", "")))
                        )
                        self._dials.add(task)
                        task.add_done_callback(self._dials.discard)
                    elif msg == Msg.PING.value:
                        await self._writer.send(control(Msg.PONG))

                elif frame.type is FrameType.DATA:
                    sock = self._sockets.get(frame.stream_id)
                    if sock is None or sock.is_closing():
                        continue
                    try:
                        sock.write(frame.payload)
                        await sock.drain()
                    except (ConnectionError, RuntimeError):
                        await self._drop(frame.stream_id, "app_write_failed")

                elif frame.type is FrameType.CLOSE:
                    await self._drop(frame.stream_id, "broker_closed")

        except TUNNEL_CLOSED:
            self.registered.clear()

    # ------------------------------------------------------------ dial + pump

    async def _dial(self, stream_id: int, app_name: str) -> None:
        assert self._writer is not None
        app = self.apps.get(app_name)
        if app is None:
            # The broker named something this connector does not publish.
            await self._writer.send(
                control(Msg.DIAL_FAIL, stream_id=stream_id, reason="unknown_app")
            )
            return
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(app.host, app.port), DIAL_CONNECT_TIMEOUT
            )
        except (OSError, asyncio.TimeoutError):
            await self._writer.send(
                control(Msg.DIAL_FAIL, stream_id=stream_id, reason="connect_failed")
            )
            return

        self._sockets[stream_id] = writer
        await self._writer.send(control(Msg.DIAL_OK, stream_id=stream_id, app=app_name))
        self._pumps[stream_id] = asyncio.create_task(self._pump(stream_id, reader))

    async def _pump(self, stream_id: int, reader: asyncio.StreamReader) -> None:
        assert self._writer is not None
        try:
            while True:
                chunk = await reader.read(RELAY_CHUNK)
                if not chunk:
                    break
                await self._writer.send(data_frame(stream_id, chunk))
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            await self._drop(stream_id, "app_eof", notify=True)

    async def _drop(self, stream_id: int, reason: str, *, notify: bool = False) -> None:
        writer = self._sockets.pop(stream_id, None)
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()
        task = self._pumps.pop(stream_id, None)
        if task and task is not asyncio.current_task():
            task.cancel()
        if notify and self._writer and not self._writer.transport_closing:
            await self._writer.send(close_frame(stream_id, reason))

    # ------------------------------------------------------------- utilities

    @classmethod
    def from_app_config(
        cls,
        name: str,
        identity: Identity,
        ca_cert: Path,
        broker_host: str,
        broker_port: int,
        apps_doc: dict[str, Any],
        **kwargs: Any,
    ) -> AppConnector:
        published = [
            PublishedApp(entry["name"], entry["host"], int(entry["port"]))
            for entry in apps_doc.get("apps", [])
            if entry.get("connector") == name
        ]
        return cls(name, identity, ca_cert, broker_host, broker_port, published, **kwargs)
