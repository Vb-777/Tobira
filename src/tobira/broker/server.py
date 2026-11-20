"""The Tobira broker - policy decision point, policy enforcement point, relay.

The broker is the single component in the lab that accepts inbound connections.
App Connectors and user devices both dial *out* to it over mutually
authenticated TLS 1.3, and the broker stitches an authorised pair of streams
together. Because the broker never initiates a connection into the private
network, and the connector never listens, a private application has no reachable
surface at all for anyone who is not already authorised.

Order of checks for a user session (fail closed at every step):

1. TLS: client certificate must chain to the lab CA and carry ``OU=device``.
2. Token: signature, issuer, audience, expiry, revocation.
3. Device binding: token ``cnf`` thumbprint == TLS peer certificate thumbprint.
4. Posture: signed attestation over a broker-chosen nonce, then profile check.
5. Policy: per-connection authorisation for the specific application.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import ssl
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..events import Event, EventEmitter, access_event, auth_event
from ..identity import AuthError, TokenVerifier
from ..pki import Identity, peer_name, server_context, thumbprint_from_der
from ..policy import PolicyEngine, Subject
from ..posture import PostureError, new_nonce, verify_attestation
from ..protocol import (
    FrameType,
    FrameWriter,
    Msg,
    ProtocolError,
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
from .registry import Link, Registry, Session, Tunnel

DIAL_TIMEOUT = 10.0
HANDSHAKE_TIMEOUT = 15.0
POSTURE_MAX_AGE = dt.timedelta(minutes=5)


@dataclass(slots=True)
class BrokerConfig:
    identity: Identity
    ca_cert: Path
    policy: PolicyEngine
    token_verifier: TokenVerifier
    emitter: EventEmitter
    host: str = "127.0.0.1"
    connector_port: int = 8443
    client_port: int = 8444


class Broker:
    def __init__(self, config: BrokerConfig) -> None:
        self.cfg = config
        self.registry = Registry()
        self._servers: list[asyncio.AbstractServer] = []
        self._tasks: set[asyncio.Task[Any]] = set()
        self.connector_port = config.connector_port
        self.client_port = config.client_port

    # --------------------------------------------------------------- startup

    async def start(self) -> None:
        ctx = server_context(self.cfg.identity, self.cfg.ca_cert)
        connector_server = await asyncio.start_server(
            self._accept_connector, self.cfg.host, self.cfg.connector_port, ssl=ctx
        )
        client_server = await asyncio.start_server(
            self._accept_client, self.cfg.host, self.cfg.client_port, ssl=ctx
        )
        self._servers = [connector_server, client_server]
        self.connector_port = connector_server.sockets[0].getsockname()[1]
        self.client_port = client_server.sockets[0].getsockname()[1]
        self.cfg.emitter.emit(
            Event(
                action="broker_started",
                outcome="success",
                category=["configuration"],
                type=["start"],
                message=f"broker listening on {self.cfg.host}:{self.connector_port} "
                f"(connectors) and :{self.client_port} (clients)",
                severity=2,
            )
        )

    async def stop(self) -> None:
        for server in self._servers:
            server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(server.wait_closed(), 2.0)
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self._servers.clear()

    def _spawn(self, coro: Any) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # ------------------------------------------------------------ connectors

    async def _accept_connector(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await self._accept(reader, writer, Role.CONNECTOR)

    async def _accept_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await self._accept(reader, writer, Role.CLIENT)

    async def _accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, expected: Role
    ) -> None:
        frames = FrameWriter(writer)
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        ssl_object: ssl.SSLObject | None = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object else None

        if not der:
            # Cannot happen with CERT_REQUIRED, but fail closed anyway.
            await self._reject(frames, "no_client_certificate", peer, expected)
            return

        common_name, org_unit = peer_name(der)
        required_ou = "connector" if expected is Role.CONNECTOR else "device"
        if org_unit != required_ou:
            # A device certificate must not be usable to publish applications.
            await self._reject(frames, "wrong_certificate_role", peer, expected, cn=common_name)
            return

        tunnel = Tunnel(
            name=common_name,
            role=expected.value,
            writer=frames,
            peer_cert_der=der,
            peer_ip=str(peer[0]),
            peer_port=int(peer[1]),
        )

        try:
            hello = await asyncio.wait_for(read_frame(reader), HANDSHAKE_TIMEOUT)
            body = hello.json
            if body.get("msg") != Msg.HELLO.value or body.get("role") != expected.value:
                await self._reject(frames, "bad_hello", peer, expected, cn=common_name)
                return
            tunnel.nonce = new_nonce()
            await frames.send(control(Msg.HELLO_OK, nonce=tunnel.nonce, broker="tobira"))
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ProtocolError):
            await frames.aclose()
            return

        try:
            if expected is Role.CONNECTOR:
                await self._serve_connector(tunnel, reader)
            else:
                await self._serve_client(tunnel, reader)
        except (asyncio.IncompleteReadError, ConnectionError, ProtocolError):
            pass
        finally:
            await self._teardown(tunnel)

    async def _reject(
        self,
        frames: FrameWriter,
        reason: str,
        peer: tuple[str, int],
        role: Role,
        *,
        cn: str = "",
    ) -> None:
        self.cfg.emitter.emit(
            auth_event(
                action="tunnel_rejected",
                outcome="failure",
                reason=reason,
                severity=7,
                source_ip=str(peer[0]),
                source_port=int(peer[1]),
                extra={"role": role.value, "presented_cn": cn},
                message=f"rejected {role.value} tunnel: {reason}",
            )
        )
        with contextlib.suppress(Exception):
            await frames.send(control(Msg.HELLO_FAIL, reason=reason))
        await frames.aclose()

    async def _teardown(self, tunnel: Tunnel) -> None:
        if tunnel.role == Role.CONNECTOR.value:
            orphaned = self.registry.drop_connector(tunnel.name)
            for link in orphaned:
                await link.client_tunnel.writer.send(
                    close_frame(link.client_stream, "connector_lost")
                )
            if orphaned or tunnel.apps:
                self.cfg.emitter.emit(
                    Event(
                        action="connector_disconnected",
                        outcome="unknown",
                        category=["network"],
                        connector=tunnel.name,
                        severity=5,
                        message=f"connector {tunnel.name} disconnected, "
                        f"{len(orphaned)} stream(s) dropped",
                    )
                )
        else:
            session = self.registry.session_for_tunnel(tunnel)
            if session:
                self.registry.drop_session(session.session_id)
                self.cfg.emitter.emit(
                    auth_event(
                        action="session_ended",
                        outcome="success",
                        type=["end"],
                        user=session.username,
                        device_id=session.device_id,
                        session_id=session.session_id,
                        severity=2,
                    )
                )
        await tunnel.writer.aclose()

    # ------------------------------------------------- connector message loop

    async def _serve_connector(self, tunnel: Tunnel, reader: asyncio.StreamReader) -> None:
        registered = False
        while True:
            frame = await read_frame(reader)

            if frame.type is FrameType.CONTROL:
                body = frame.json
                msg = body.get("msg")

                if msg == Msg.REGISTER.value:
                    claimed = set(body.get("apps", []))
                    owned = {
                        name
                        for name, app in self.cfg.policy.apps.items()
                        if app.connector == tunnel.name
                    }
                    rogue = claimed - owned
                    if rogue:
                        # The connector asked to publish applications that policy
                        # does not assign to it. Refuse the whole registration.
                        self.cfg.emitter.emit(
                            auth_event(
                                action="connector_registration_denied",
                                outcome="failure",
                                reason="unauthorised_app_claim",
                                severity=8,
                                connector=tunnel.name,
                                source_ip=tunnel.peer_ip,
                                source_port=tunnel.peer_port,
                                extra={"claimed_apps": sorted(rogue)},
                                message=f"connector {tunnel.name} tried to publish "
                                f"{sorted(rogue)}",
                            )
                        )
                        await tunnel.writer.send(
                            control(Msg.REGISTER_FAIL, reason="unauthorised_app_claim")
                        )
                        return
                    self.registry.register_connector(tunnel, claimed)
                    registered = True
                    await tunnel.writer.send(
                        control(Msg.REGISTER_OK, apps=sorted(claimed))
                    )
                    self.cfg.emitter.emit(
                        Event(
                            action="connector_registered",
                            outcome="success",
                            category=["configuration"],
                            connector=tunnel.name,
                            source_ip=tunnel.peer_ip,
                            source_port=tunnel.peer_port,
                            severity=2,
                            extra={"apps": sorted(claimed)},
                            message=f"connector {tunnel.name} published {sorted(claimed)}",
                        )
                    )

                elif msg in (Msg.DIAL_OK.value, Msg.DIAL_FAIL.value):
                    future = self.registry.pending_dials.pop(
                        (tunnel.name, frame.stream_id), None
                    )
                    if future and not future.done():
                        future.set_result(msg == Msg.DIAL_OK.value)

                elif msg == Msg.PING.value:
                    await tunnel.writer.send(control(Msg.PONG))

                elif not registered:
                    return

            elif frame.type is FrameType.DATA:
                link = self.registry.links_by_connector.get((tunnel.name, frame.stream_id))
                if link is None:
                    continue
                link.bytes_from_app += len(frame.payload)
                await link.client_tunnel.writer.send(
                    data_frame(link.client_stream, frame.payload)
                )

            elif frame.type is FrameType.CLOSE:
                link = self.registry.links_by_connector.get((tunnel.name, frame.stream_id))
                if link is None:
                    continue
                reason = frame.payload.decode("utf-8", "replace") or "app_closed"
                await self._close_link(link, reason)

    # ---------------------------------------------------- client message loop

    async def _serve_client(self, tunnel: Tunnel, reader: asyncio.StreamReader) -> None:
        session: Session | None = None
        thumbprint = thumbprint_from_der(tunnel.peer_cert_der)

        while True:
            frame = await read_frame(reader)

            if frame.type is FrameType.CONTROL:
                body = frame.json
                msg = body.get("msg")

                if msg == Msg.AUTH.value:
                    session = await self._authenticate(tunnel, body, thumbprint)
                    if session is None:
                        return

                elif session is None:
                    # Nothing but AUTH is accepted before authentication.
                    await tunnel.writer.send(
                        control(Msg.AUTH_FAIL, reason="not_authenticated")
                    )
                    return

                elif msg == Msg.OPEN.value:
                    await self._handle_open(session, tunnel, frame.stream_id, body)

                elif msg == Msg.POSTURE_REFRESH.value:
                    await self._handle_posture_refresh(session, tunnel, body)

                elif msg == Msg.PING.value:
                    await tunnel.writer.send(control(Msg.PONG))

            elif frame.type is FrameType.DATA:
                link = self.registry.links_by_client.get((tunnel.name, frame.stream_id))
                if link is None:
                    continue
                link.bytes_to_app += len(frame.payload)
                await link.connector_tunnel.writer.send(
                    data_frame(link.connector_stream, frame.payload)
                )

            elif frame.type is FrameType.CLOSE:
                link = self.registry.links_by_client.get((tunnel.name, frame.stream_id))
                if link is None:
                    continue
                await self._close_link(link, "client_closed")

    # -------------------------------------------------------- authentication

    async def _authenticate(
        self, tunnel: Tunnel, body: dict[str, Any], thumbprint: str
    ) -> Session | None:
        token = str(body.get("token", ""))
        attestation = body.get("posture") or {}
        nonce = str(body.get("nonce", ""))

        def fail(reason: str, user: str = "", severity: int = 7) -> None:
            self.cfg.emitter.emit(
                auth_event(
                    action="authentication_failed",
                    outcome="failure",
                    reason=reason,
                    severity=severity,
                    user=user,
                    device_id=tunnel.name,
                    source_ip=tunnel.peer_ip,
                    source_port=tunnel.peer_port,
                    message=f"device {tunnel.name} failed authentication: {reason}",
                )
            )

        # The nonce must be one *we* issued for this connection.
        if not nonce or nonce != tunnel.nonce:
            fail("nonce_mismatch")
            await tunnel.writer.send(control(Msg.AUTH_FAIL, reason="nonce_mismatch"))
            return None

        try:
            claims = self.cfg.token_verifier.verify(token, thumbprint)
        except AuthError as exc:
            peeked = ""
            with contextlib.suppress(Exception):
                import jwt as _jwt

                peeked = str(
                    _jwt.decode(token, options={"verify_signature": False}).get("sub", "")
                )
            fail(str(exc), user=peeked, severity=9 if "device_mismatch" in str(exc) else 7)
            await tunnel.writer.send(control(Msg.AUTH_FAIL, reason=str(exc)))
            return None

        try:
            attributes = verify_attestation(attestation, nonce, tunnel.peer_cert_der)
        except PostureError as exc:
            fail(str(exc), user=claims.subject, severity=8)
            await tunnel.writer.send(control(Msg.AUTH_FAIL, reason=str(exc)))
            return None

        if str(attributes.get("device_id", "")) != tunnel.name:
            fail("posture_device_mismatch", user=claims.subject, severity=9)
            await tunnel.writer.send(control(Msg.AUTH_FAIL, reason="posture_device_mismatch"))
            return None

        from ..posture import score as posture_score

        session = Session(
            session_id=uuid.uuid4().hex[:16],
            username=claims.subject,
            groups=claims.groups,
            mfa=claims.mfa,
            device_id=tunnel.name,
            device_thumbprint=thumbprint,
            tunnel=tunnel,
            posture_attributes=attributes,
            posture_score=posture_score(attributes),
            nonce=new_nonce(),
            jti=claims.jti,
            expires_at=claims.expires_at,
        )
        self.registry.add_session(session)

        visible = self.cfg.policy.visible_apps(self._subject(session))
        await tunnel.writer.send(
            control(
                Msg.AUTH_OK,
                session_id=session.session_id,
                apps=visible,
                next_nonce=session.nonce,
                expires_at=int(session.expires_at.timestamp()),
            )
        )
        self.cfg.emitter.emit(
            auth_event(
                action="authentication_succeeded",
                outcome="success",
                user=session.username,
                groups=session.groups,
                device_id=session.device_id,
                session_id=session.session_id,
                source_ip=tunnel.peer_ip,
                source_port=tunnel.peer_port,
                posture_score=session.posture_score,
                severity=2,
                extra={"mfa": session.mfa, "visible_apps": visible},
                message=f"{session.username} authenticated from {session.device_id}; "
                f"{len(visible)} application(s) visible",
            )
        )
        return session

    @staticmethod
    def _subject(session: Session) -> Subject:
        return Subject(
            username=session.username,
            groups=session.groups,
            mfa=session.mfa,
            device_id=session.device_id,
            posture_attributes=session.posture_attributes,
        )

    # ----------------------------------------------------- per-connection ACL

    async def _handle_open(
        self, session: Session, tunnel: Tunnel, stream_id: int, body: dict[str, Any]
    ) -> None:
        app_name = str(body.get("app", ""))

        if session.expires_at <= dt.datetime.now(dt.timezone.utc):
            await self._deny(session, tunnel, stream_id, app_name, "token_expired", severity=6)
            return

        if dt.datetime.now(dt.timezone.utc) - session.last_posture_at > POSTURE_MAX_AGE:
            await self._deny(session, tunnel, stream_id, app_name, "posture_stale", severity=6)
            return

        decision = self.cfg.policy.decide(self._subject(session), app_name)
        if not decision.allowed:
            await self._deny(
                session,
                tunnel,
                stream_id,
                app_name,
                decision.reason,
                rule=decision.rule,
                posture_score=decision.posture_score,
                posture_failures=decision.posture_failures,
            )
            return

        app = self.cfg.policy.apps[app_name]
        connector = self.registry.connector_for(app_name)
        if connector is None:
            await self._deny(
                session, tunnel, stream_id, app_name, "connector_unavailable", severity=5
            )
            return

        connector_stream = connector.next_stream_id()
        future: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
        self.registry.pending_dials[(connector.name, connector_stream)] = future
        await connector.writer.send(
            control(Msg.DIAL, stream_id=connector_stream, app=app_name)
        )

        try:
            dialled = await asyncio.wait_for(future, DIAL_TIMEOUT)
        except asyncio.TimeoutError:
            dialled = False
        finally:
            self.registry.pending_dials.pop((connector.name, connector_stream), None)

        if not dialled:
            await self._deny(
                session, tunnel, stream_id, app_name, "app_unreachable", severity=5
            )
            return

        link = Link(
            app=app_name,
            session=session,
            client_tunnel=tunnel,
            client_stream=stream_id,
            connector_tunnel=connector,
            connector_stream=connector_stream,
        )
        self.registry.link(link)
        await tunnel.writer.send(control(Msg.OPEN_OK, stream_id=stream_id, app=app_name))

        self.cfg.emitter.emit(
            access_event(
                action="access_granted",
                outcome="success",
                user=session.username,
                groups=session.groups,
                device_id=session.device_id,
                session_id=session.session_id,
                stream_id=stream_id,
                app=app_name,
                app_host=app.host,
                app_port=app.port,
                connector=connector.name,
                policy_rule=decision.rule,
                posture_score=decision.posture_score,
                source_ip=tunnel.peer_ip,
                source_port=tunnel.peer_port,
                severity=2,
                message=f"{session.username} -> {app_name} allowed by rule {decision.rule!r}",
            )
        )

    async def _deny(
        self,
        session: Session,
        tunnel: Tunnel,
        stream_id: int,
        app_name: str,
        reason: str,
        *,
        rule: str = "",
        posture_score: int = 0,
        posture_failures: list[str] | None = None,
        severity: int = 6,
    ) -> None:
        await tunnel.writer.send(
            control(Msg.OPEN_FAIL, stream_id=stream_id, app=app_name, reason=reason)
        )
        app = self.cfg.policy.apps.get(app_name)
        self.cfg.emitter.emit(
            access_event(
                action="access_denied",
                outcome="failure",
                reason=reason,
                user=session.username,
                groups=session.groups,
                device_id=session.device_id,
                session_id=session.session_id,
                stream_id=stream_id,
                app=app_name,
                app_host=app.host if app else "",
                app_port=app.port if app else 0,
                policy_rule=rule,
                posture_score=posture_score or None,
                posture_failures=posture_failures or [],
                source_ip=tunnel.peer_ip,
                source_port=tunnel.peer_port,
                severity=severity,
                message=f"{session.username} -> {app_name} denied ({reason})",
            )
        )

    # ------------------------------------------------- continuous evaluation

    async def _handle_posture_refresh(
        self, session: Session, tunnel: Tunnel, body: dict[str, Any]
    ) -> None:
        try:
            attributes = verify_attestation(
                body.get("posture") or {}, session.nonce, tunnel.peer_cert_der
            )
        except PostureError as exc:
            await self._terminate(session, str(exc))
            return

        from ..posture import score as posture_score

        session.posture_attributes = attributes
        session.posture_score = posture_score(attributes)
        session.last_posture_at = dt.datetime.now(dt.timezone.utc)
        session.nonce = new_nonce()

        # Re-authorise every stream that is currently open. Anything that would
        # not be granted now is torn down immediately.
        revoked: list[str] = []
        for link in self.registry.links_for_session(session.session_id):
            decision = self.cfg.policy.decide(self._subject(session), link.app)
            if not decision.allowed:
                revoked.append(link.app)
                await self._close_link(link, f"revoked:{decision.reason}")
                self.cfg.emitter.emit(
                    access_event(
                        action="access_revoked",
                        outcome="failure",
                        reason=decision.reason,
                        user=session.username,
                        device_id=session.device_id,
                        session_id=session.session_id,
                        app=link.app,
                        policy_rule=decision.rule,
                        posture_score=decision.posture_score,
                        posture_failures=decision.posture_failures,
                        severity=8,
                        message=f"live session for {link.app} revoked: {decision.reason}",
                    )
                )

        visible = self.cfg.policy.visible_apps(self._subject(session))
        await tunnel.writer.send(
            control(
                "posture_refresh_ok",
                next_nonce=session.nonce,
                score=session.posture_score,
                apps=visible,
                revoked=revoked,
            )
        )
        self.cfg.emitter.emit(
            Event(
                action="posture_reattested",
                outcome="success" if not revoked else "failure",
                category=["host"],
                type=["info"],
                user=session.username,
                device_id=session.device_id,
                session_id=session.session_id,
                posture_score=session.posture_score,
                severity=3 if not revoked else 7,
                extra={"revoked_apps": revoked},
                message=f"posture re-attested for {session.device_id} "
                f"(score {session.posture_score})",
            )
        )

    async def _terminate(self, session: Session, reason: str) -> None:
        for link in self.registry.links_for_session(session.session_id):
            await self._close_link(link, f"terminated:{reason}")
        self.registry.drop_session(session.session_id)
        await session.tunnel.writer.send(control(Msg.SESSION_TERMINATE, reason=reason))
        self.cfg.emitter.emit(
            auth_event(
                action="session_terminated",
                outcome="failure",
                reason=reason,
                type=["end"],
                user=session.username,
                device_id=session.device_id,
                session_id=session.session_id,
                severity=9,
                message=f"session {session.session_id} terminated: {reason}",
            )
        )

    # ----------------------------------------------------------------- relay

    async def _close_link(self, link: Link, reason: str) -> None:
        self.registry.unlink(link)
        await link.client_tunnel.writer.send(close_frame(link.client_stream, reason))
        await link.connector_tunnel.writer.send(close_frame(link.connector_stream, reason))
        app = self.cfg.policy.apps.get(link.app)
        self.cfg.emitter.emit(
            access_event(
                action="session_stream_closed",
                outcome="success",
                type=["end"],
                reason=reason,
                user=link.session.username,
                device_id=link.session.device_id,
                session_id=link.session.session_id,
                stream_id=link.client_stream,
                app=link.app,
                app_host=app.host if app else "",
                app_port=app.port if app else 0,
                connector=link.connector_tunnel.name,
                bytes_sent=link.bytes_to_app,
                bytes_received=link.bytes_from_app,
                severity=2,
                message=f"stream to {link.app} closed ({reason})",
            )
        )
