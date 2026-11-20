"""In-memory state the broker keeps about live tunnels, sessions and relays."""

from __future__ import annotations

import asyncio
import datetime as dt
import itertools
from dataclasses import dataclass, field
from typing import Any

from ..protocol import FrameWriter


@dataclass(slots=True)
class Tunnel:
    """One authenticated mTLS connection from a connector or a device."""

    name: str
    role: str
    writer: FrameWriter
    peer_cert_der: bytes
    peer_ip: str
    peer_port: int
    connected_at: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))
    apps: set[str] = field(default_factory=set)
    #: Nonce issued to this peer in ``hello_ok``; the peer must sign it.
    nonce: str = ""
    _ids: Any = field(default_factory=lambda: itertools.count(1))

    def next_stream_id(self) -> int:
        return next(self._ids)


@dataclass(slots=True)
class Session:
    """An authenticated user session bound to one device and one tunnel."""

    session_id: str
    username: str
    groups: list[str]
    mfa: bool
    device_id: str
    device_thumbprint: str
    tunnel: Tunnel
    posture_attributes: dict[str, Any]
    posture_score: int
    nonce: str
    jti: str
    expires_at: dt.datetime
    created_at: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))
    last_posture_at: dt.datetime = field(
        default_factory=lambda: dt.datetime.now(dt.timezone.utc)
    )


@dataclass(slots=True)
class Link:
    """One relayed TCP connection: client stream <-> connector stream."""

    app: str
    session: Session
    client_tunnel: Tunnel
    client_stream: int
    connector_tunnel: Tunnel
    connector_stream: int
    opened_at: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))
    bytes_to_app: int = 0
    bytes_from_app: int = 0


class Registry:
    """Thread-confined (asyncio single-loop) registry of broker state."""

    def __init__(self) -> None:
        self.connectors: dict[str, Tunnel] = {}
        self.sessions: dict[str, Session] = {}
        self.links_by_client: dict[tuple[str, int], Link] = {}
        self.links_by_connector: dict[tuple[str, int], Link] = {}
        self.pending_dials: dict[tuple[str, int], asyncio.Future[bool]] = {}

    # ------------------------------------------------------------ connectors

    def register_connector(self, tunnel: Tunnel, apps: set[str]) -> None:
        tunnel.apps = set(apps)
        self.connectors[tunnel.name] = tunnel

    def drop_connector(self, name: str) -> list[Link]:
        self.connectors.pop(name, None)
        orphaned = [
            link for link in self.links_by_connector.values() if link.connector_tunnel.name == name
        ]
        for link in orphaned:
            self.unlink(link)
        return orphaned

    def connector_for(self, app: str) -> Tunnel | None:
        for tunnel in self.connectors.values():
            if app in tunnel.apps:
                return tunnel
        return None

    # -------------------------------------------------------------- sessions

    def add_session(self, session: Session) -> None:
        self.sessions[session.session_id] = session

    def session_for_tunnel(self, tunnel: Tunnel) -> Session | None:
        for session in self.sessions.values():
            if session.tunnel is tunnel:
                return session
        return None

    def drop_session(self, session_id: str) -> list[Link]:
        self.sessions.pop(session_id, None)
        affected = [
            link for link in self.links_by_client.values() if link.session.session_id == session_id
        ]
        for link in affected:
            self.unlink(link)
        return affected

    # ----------------------------------------------------------------- links

    def link(self, link: Link) -> None:
        self.links_by_client[(link.client_tunnel.name, link.client_stream)] = link
        self.links_by_connector[(link.connector_tunnel.name, link.connector_stream)] = link

    def unlink(self, link: Link) -> None:
        self.links_by_client.pop((link.client_tunnel.name, link.client_stream), None)
        self.links_by_connector.pop((link.connector_tunnel.name, link.connector_stream), None)

    def links_for_session(self, session_id: str) -> list[Link]:
        return [
            link for link in self.links_by_client.values() if link.session.session_id == session_id
        ]
