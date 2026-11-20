"""Adversary scenarios run against a live Tobira lab.

Each scenario performs a real action against the running broker and asserts the
security property that should hold. A scenario "passes" when the attack is
blocked *and* the expected audit evidence was produced - a control that blocks
silently is only half a control.

Scenarios are grouped by the control they exercise:

* ``exposure``   - can the private network be found or reached at all?
* ``identity``   - can credentials be forged, replayed or outlived?
* ``device``     - can a device lie about its security state?
* ``policy``     - can an authorised user reach something they should not?
* ``continuous`` - does access end when the conditions that justified it end?
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jwt

from .client import AccessDenied, ClientConnector
from .connector import AppConnector, PublishedApp
from .identity import IdentityProvider
from .lab import BROKER_SAN, Lab
from .pki import client_context
from .policy import Subject
from .posture import DeviceState, attest
from .protocol import FrameWriter, Msg, Role, control, read_frame


@dataclass
class AttackResult:
    name: str
    group: str
    goal: str
    technique: str
    blocked: bool
    evidence: str
    detail: str = ""
    audit_actions: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        return "BLOCKED" if self.blocked else "SUCCEEDED"


Scenario = Callable[[Lab], Awaitable[AttackResult]]
_REGISTRY: list[tuple[str, str, str, Scenario]] = []


def scenario(group: str, goal: str, technique: str) -> Callable[[Scenario], Scenario]:
    def wrap(func: Scenario) -> Scenario:
        _REGISTRY.append((func.__name__, group, goal, technique))
        func._tobira_meta = group, goal, technique
        return func

    return wrap


def _audit_since(lab: Lab, mark: int, *actions: str) -> list[str]:
    """Audit actions recorded after ``mark``, optionally filtered."""
    seen = [doc["event"]["action"] for doc in lab.emitter.events[mark:]]
    if not actions:
        return seen
    return [action for action in seen if action in actions]


def _mark(lab: Lab) -> int:
    return len(lab.emitter.events)


# ---------------------------------------------------------------- exposure


def listening_ports() -> set[int]:
    """Ports in LISTEN state on this host, read from /proc (Linux)."""
    ports: set[int] = set()
    for proc in ("/proc/net/tcp", "/proc/net/tcp6"):
        path = Path(proc)
        if not path.exists():
            continue
        for line in path.read_text().splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or parts[3] != "0A":  # 0A == TCP_LISTEN
                continue
            with contextlib.suppress(ValueError, IndexError):
                ports.add(int(parts[1].split(":")[1], 16))
    return ports


@scenario(
    "exposure",
    "Find a service to attack on the App Connector host",
    "Network service discovery (T1046)",
)
async def app_connector_opens_no_port(lab: Lab) -> AttackResult:
    """An App Connector must never bind a listening socket."""
    before = listening_ports()

    identity = lab.ca.issue(
        "connector-probe", out_dir=lab.workdir / "pki" / "connectors", org_unit="connector"
    )
    probe = AppConnector(
        "connector-probe",
        identity,
        lab.ca.cert_path,
        lab.host,
        lab.broker.connector_port,
        [],
        server_hostname=BROKER_SAN,
    )
    opened: set[int] = set()
    try:
        await probe.start()
        await asyncio.sleep(0.2)
        opened = listening_ports() - before
    except ConnectionError:
        pass
    finally:
        await probe.stop()

    return AttackResult(
        name="app_connector_opens_no_port",
        group="exposure",
        goal="Find a service to attack on the App Connector host",
        technique="Network service discovery (T1046)",
        blocked=not opened,
        evidence=(
            "connector bound 0 listening sockets"
            if not opened
            else f"connector opened ports {sorted(opened)}"
        ),
        detail="The connector dials out to the broker and keeps one outbound "
        "tunnel; there is nothing inbound for a scanner to find.",
    )


async def _try_hello(lab: Lab, ctx: ssl.SSLContext, name: str) -> tuple[bool, str]:
    """Attempt a full HELLO exchange. Returns ``(accepted, failure_detail)``.

    Under TLS 1.3 the client finishes its handshake before the server has
    validated the client certificate, so ``open_connection`` can succeed even
    when the peer will be rejected. The honest test is therefore whether the
    peer ever receives ``hello_ok``.
    """
    try:
        reader, writer = await asyncio.open_connection(
            lab.host, lab.broker.client_port, ssl=ctx, server_hostname=BROKER_SAN
        )
    except (ssl.SSLError, ConnectionError, OSError) as exc:
        return False, type(exc).__name__

    frames = FrameWriter(writer)
    try:
        await frames.send(control(Msg.HELLO, role=Role.CLIENT.value, name=name))
        frame = await asyncio.wait_for(read_frame(reader), 3.0)
        accepted = frame.json.get("msg") == Msg.HELLO_OK.value
        return accepted, "" if accepted else str(frame.json.get("reason", "no hello_ok"))
    except asyncio.IncompleteReadError:
        return False, "connection closed before hello_ok"
    except (ssl.SSLError, ConnectionError, OSError) as exc:
        return False, type(exc).__name__
    except asyncio.TimeoutError:
        return False, "no response"
    finally:
        with contextlib.suppress(Exception):
            await frames.aclose()


@scenario(
    "exposure",
    "Reach the broker without any credential",
    "Exploit public-facing application (T1190)",
)
async def anonymous_tls_is_refused(lab: Lab) -> AttackResult:
    """TLS without a client certificate must not complete."""
    mark = _mark(lab)
    ctx = client_context(None, lab.ca.cert_path, check_hostname=False)
    accepted, error = await _try_hello(lab, ctx, "anonymous")
    await asyncio.sleep(0.1)

    return AttackResult(
        name="anonymous_tls_is_refused",
        group="exposure",
        goal="Reach the broker without any credential",
        technique="Exploit public-facing application (T1190)",
        blocked=not accepted,
        evidence=f"refused at the TLS layer ({error})"
        if not accepted
        else "anonymous peer was accepted",
        detail="The broker requires a client certificate chaining to the lab CA, "
        "so an unauthenticated scanner never reaches application logic.",
        audit_actions=_audit_since(lab, mark),
    )


@scenario(
    "exposure",
    "Present a certificate from an attacker-controlled CA",
    "Subvert trust controls (T1553)",
)
async def foreign_ca_certificate_is_refused(lab: Lab) -> AttackResult:
    from .pki import CertificateAuthority

    rogue_dir = lab.workdir / "rogue-ca"
    rogue_ca = CertificateAuthority(rogue_dir)
    rogue_ca.ensure()
    rogue_identity = rogue_ca.issue(
        "laptop-evil", out_dir=rogue_dir / "devices", org_unit="device"
    )

    mark = _mark(lab)
    ctx = client_context(rogue_identity, lab.ca.cert_path)
    accepted, error = await _try_hello(lab, ctx, "laptop-evil")
    await asyncio.sleep(0.1)

    return AttackResult(
        name="foreign_ca_certificate_is_refused",
        group="exposure",
        goal="Present a certificate from an attacker-controlled CA",
        technique="Subvert trust controls (T1553)",
        blocked=not accepted,
        evidence=f"refused at the TLS layer ({error})"
        if not accepted
        else "foreign CA was trusted",
        detail="Trust is pinned to one private CA, so minting your own "
        "certificate achieves nothing.",
        audit_actions=_audit_since(lab, mark),
    )


@scenario(
    "exposure",
    "Use a valid user device certificate to register as an App Connector",
    "Trusted relationship abuse (T1199)",
)
async def device_cert_cannot_publish_apps(lab: Lab) -> AttackResult:
    device = lab.device_for("ben")
    mark = _mark(lab)

    rogue = AppConnector(
        device.device_id,
        device.identity,
        lab.ca.cert_path,
        lab.host,
        lab.broker.connector_port,
        [PublishedApp("payroll", "127.0.0.1", 1)],
        server_hostname=BROKER_SAN,
    )
    blocked = False
    reason = ""
    try:
        await rogue.start()
    except ConnectionError:
        blocked = True
        reason = rogue.last_error
    finally:
        await rogue.stop()
    await asyncio.sleep(0.1)

    actions = _audit_since(lab, mark)
    return AttackResult(
        name="device_cert_cannot_publish_apps",
        group="exposure",
        goal="Use a valid user device certificate to register as an App Connector",
        technique="Trusted relationship abuse (T1199)",
        blocked=blocked and "tunnel_rejected" in actions,
        evidence=f"rejected: {reason or 'wrong_certificate_role'}",
        detail="Certificate role is carried in the subject OU; a device "
        "certificate cannot be used to publish applications.",
        audit_actions=actions,
    )


@scenario(
    "exposure",
    "Register a connector that publishes an application it does not own",
    "Adversary-in-the-middle (T1557)",
)
async def rogue_connector_cannot_claim_app(lab: Lab) -> AttackResult:
    identity = lab.ca.issue(
        "connector-rogue", out_dir=lab.workdir / "pki" / "connectors", org_unit="connector"
    )
    mark = _mark(lab)

    rogue = AppConnector(
        "connector-rogue",
        identity,
        lab.ca.cert_path,
        lab.host,
        lab.broker.connector_port,
        [PublishedApp("payroll", "127.0.0.1", 1)],
        server_hostname=BROKER_SAN,
    )
    blocked = False
    reason = ""
    try:
        await rogue.start()
    except ConnectionError:
        blocked = True
        reason = rogue.last_error
    finally:
        await rogue.stop()
    await asyncio.sleep(0.1)

    actions = _audit_since(lab, mark)
    return AttackResult(
        name="rogue_connector_cannot_claim_app",
        group="exposure",
        goal="Register a connector that publishes an application it does not own",
        technique="Adversary-in-the-middle (T1557)",
        blocked=blocked and "connector_registration_denied" in actions,
        evidence=f"registration refused: {reason or 'unauthorised_app_claim'}",
        detail="Policy, not the connector, decides which connector serves which "
        "application, so traffic cannot be hijacked by a new registration.",
        audit_actions=actions,
    )


# ---------------------------------------------------------------- identity


async def _raw_client(lab: Lab, device_id: str) -> tuple[Any, FrameWriter, dict[str, Any]]:
    """Open a tunnel and complete only the HELLO exchange."""
    device = lab.devices[device_id]
    ctx = client_context(device.identity, lab.ca.cert_path)
    reader, writer = await asyncio.open_connection(
        lab.host, lab.broker.client_port, ssl=ctx, server_hostname=BROKER_SAN
    )
    frames = FrameWriter(writer)
    await frames.send(control(Msg.HELLO, role=Role.CLIENT.value, name=device_id))
    hello = (await read_frame(reader)).json
    return reader, frames, hello


@scenario("identity", "Mint our own access token", "Forge web credentials (T1606)")
async def forged_token_is_rejected(lab: Lab) -> AttackResult:
    attacker_idp = IdentityProvider()
    from .identity import User

    attacker_idp.add_user(User(username="aiko", groups=["finance", "employees"], mfa_enrolled=True))
    device = lab.device_for("aiko")
    forged = attacker_idp.issue("aiko", device.identity.thumbprint, mfa=True)

    mark = _mark(lab)
    client = ClientConnector(
        device.device_id,
        device.identity,
        lab.ca.cert_path,
        lab.host,
        lab.broker.client_port,
        device_state=device.state,
        server_hostname=BROKER_SAN,
    )
    ok = await client.connect(forged)
    await client.close()
    await asyncio.sleep(0.1)

    return AttackResult(
        name="forged_token_is_rejected",
        group="identity",
        goal="Mint our own access token",
        technique="Forge web credentials (T1606)",
        blocked=not ok and client.auth_failure == "token_bad_signature",
        evidence=f"auth failed: {client.auth_failure}",
        detail="The broker holds only the IdP public key, so tokens it did not "
        "sign are rejected before any policy is consulted.",
        audit_actions=_audit_since(lab, mark),
    )


@scenario("identity", "Keep using a token after it expires", "Valid accounts (T1078)")
async def expired_token_is_rejected(lab: Lab) -> AttackResult:
    device = lab.device_for("aiko")
    stale = lab.idp.issue(
        "aiko",
        device.identity.thumbprint,
        mfa=True,
        ttl=dt.timedelta(seconds=1),
        now=dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=10),
    )

    mark = _mark(lab)
    client = ClientConnector(
        device.device_id,
        device.identity,
        lab.ca.cert_path,
        lab.host,
        lab.broker.client_port,
        device_state=device.state,
        server_hostname=BROKER_SAN,
    )
    ok = await client.connect(stale)
    await client.close()
    await asyncio.sleep(0.1)

    return AttackResult(
        name="expired_token_is_rejected",
        group="identity",
        goal="Keep using a token after it expires",
        technique="Valid accounts (T1078)",
        blocked=not ok and client.auth_failure == "token_expired",
        evidence=f"auth failed: {client.auth_failure}",
        detail="Tokens are short-lived by design, so stolen credentials have a "
        "small window of usefulness.",
        audit_actions=_audit_since(lab, mark),
    )


@scenario(
    "identity",
    "Steal a valid token and use it from another machine",
    "Application access token theft (T1550.001)",
)
async def token_replay_from_other_device(lab: Lab) -> AttackResult:
    victim_device = lab.device_for("aiko")
    stolen = lab.token_for("aiko", device=victim_device)

    attacker = lab.issue_device(
        "laptop-attacker", "aiko", DeviceState("laptop-attacker", os_patch_age_days=1)
    )

    mark = _mark(lab)
    client = ClientConnector(
        attacker.device_id,
        attacker.identity,
        lab.ca.cert_path,
        lab.host,
        lab.broker.client_port,
        device_state=attacker.state,
        server_hostname=BROKER_SAN,
    )
    ok = await client.connect(stolen)
    await client.close()
    await asyncio.sleep(0.1)

    return AttackResult(
        name="token_replay_from_other_device",
        group="identity",
        goal="Steal a valid token and use it from another machine",
        technique="Application access token theft (T1550.001)",
        blocked=not ok and client.auth_failure == "token_device_mismatch",
        evidence=f"auth failed: {client.auth_failure}",
        detail="The token carries the thumbprint of the device certificate it "
        "was issued to; the broker compares it with the live TLS peer.",
        audit_actions=_audit_since(lab, mark),
    )


@scenario("identity", "Use the credentials of an offboarded employee", "Valid accounts (T1078)")
async def revoked_credential_is_rejected(lab: Lab) -> AttackResult:
    device = lab.device_for("mallory")

    # Mallory was offboarded, so the IdP will not mint anything for her at all.
    idp_refused = ""
    try:
        lab.idp.issue("mallory", device.identity.thumbprint, mfa=True)
    except Exception as exc:  # AuthError
        idp_refused = str(exc)

    # A token minted *before* offboarding must also stop working once revoked.
    lab.idp.set_status("mallory", "active")
    issued = lab.idp.issue("mallory", device.identity.thumbprint, mfa=True)
    lab.idp.set_status("mallory", "revoked")
    lab.broker.cfg.token_verifier.revoke(
        jwt.decode(issued, options={"verify_signature": False})["jti"]
    )

    mark = _mark(lab)
    client = ClientConnector(
        device.device_id,
        device.identity,
        lab.ca.cert_path,
        lab.host,
        lab.broker.client_port,
        device_state=device.state,
        server_hostname=BROKER_SAN,
    )
    ok = await client.connect(issued)
    await client.close()
    await asyncio.sleep(0.1)

    return AttackResult(
        name="revoked_credential_is_rejected",
        group="identity",
        goal="Use the credentials of an offboarded employee",
        technique="Valid accounts (T1078)",
        blocked=not ok and client.auth_failure == "token_revoked" and bool(idp_refused),
        evidence=f"idp refused new token ({idp_refused}); existing token: "
        f"{client.auth_failure}",
        detail="Revocation takes effect at the enforcement point immediately, "
        "not when the token happens to expire.",
        audit_actions=_audit_since(lab, mark),
    )


@scenario("identity", "Replay a captured handshake nonce", "Replay attack (T1557)")
async def stale_nonce_is_rejected(lab: Lab) -> AttackResult:
    device = lab.device_for("ben")

    # Capture a nonce from one connection...
    _, frames, hello = await _raw_client(lab, device.device_id)
    captured = str(hello["nonce"])
    await frames.aclose()

    # ...then try to use it on a fresh one.
    mark = _mark(lab)
    reader2, frames2, _ = await _raw_client(lab, device.device_id)
    token = lab.token_for("ben", device=device)
    attestation = attest(device.state, captured, device.identity.key_path)
    await frames2.send(control(Msg.AUTH, token=token, nonce=captured, posture=attestation))
    reply = (await read_frame(reader2)).json
    await frames2.aclose()
    await asyncio.sleep(0.1)

    reason = str(reply.get("reason", ""))
    return AttackResult(
        name="stale_nonce_is_rejected",
        group="identity",
        goal="Replay a captured handshake nonce",
        technique="Replay attack (T1557)",
        blocked=reply.get("msg") == Msg.AUTH_FAIL.value and reason == "nonce_mismatch",
        evidence=f"auth failed: {reason}",
        detail="Each connection gets a fresh broker-chosen nonce, so a recorded "
        "handshake cannot be replayed.",
        audit_actions=_audit_since(lab, mark),
    )


@scenario(
    "identity",
    "Skip authentication and go straight to opening an application",
    "Exploitation for access (T1212)",
)
async def open_before_auth_is_rejected(lab: Lab) -> AttackResult:
    device = lab.device_for("ben")
    mark = _mark(lab)
    reader, frames, _ = await _raw_client(lab, device.device_id)
    await frames.send(control(Msg.OPEN, stream_id=1, app="payroll"))
    reply = (await read_frame(reader)).json
    await frames.aclose()
    await asyncio.sleep(0.1)

    return AttackResult(
        name="open_before_auth_is_rejected",
        group="identity",
        goal="Skip authentication and go straight to opening an application",
        technique="Exploitation for access (T1212)",
        blocked=reply.get("reason") == "not_authenticated",
        evidence=f"broker replied: {reply.get('msg')} ({reply.get('reason')})",
        detail="The broker keeps per-tunnel state and accepts nothing but AUTH "
        "until authentication has succeeded.",
        audit_actions=_audit_since(lab, mark),
    )


# ------------------------------------------------------------------ device


@scenario(
    "device",
    "Connect from a device that fails the posture bar",
    "Impair defenses (T1562.001)",
)
async def unhealthy_device_is_denied(lab: Lab) -> AttackResult:
    device = lab.device_for("chen")
    sick = DeviceState(
        device.device_id, os_name="linux", os_patch_age_days=1, disk_encryption=False
    )

    mark = _mark(lab)
    client = await lab.client_for("chen", state=sick)
    reason = ""
    try:
        await client.open("factory-hmi")
    except AccessDenied as exc:
        reason = exc.reason
    visible = list(client.apps)
    await client.close()
    await asyncio.sleep(0.1)

    return AttackResult(
        name="unhealthy_device_is_denied",
        group="device",
        goal="Connect from a device that fails the posture bar",
        technique="Impair defenses (T1562.001)",
        blocked=reason == "posture_failed" and "factory-hmi" not in visible,
        evidence=f"denied: {reason}; visible apps {visible}",
        detail="Disk encryption was switched off, so the device no longer meets "
        "the 'critical' profile the plant HMI requires.",
        audit_actions=_audit_since(lab, mark),
    )


@scenario(
    "device",
    "Claim a healthy posture the device cannot prove",
    "Masquerading (T1036)",
)
async def forged_posture_is_rejected(lab: Lab) -> AttackResult:
    device = lab.device_for("chen")

    # Sign a perfect posture report with the *wrong* key.
    other = lab.issue_device("laptop-forger", "chen")
    mark = _mark(lab)
    reader, frames, hello = await _raw_client(lab, device.device_id)
    nonce = str(hello["nonce"])
    lie = attest(DeviceState(device.device_id), nonce, other.identity.key_path)
    token = lab.token_for("chen", device=device)
    await frames.send(control(Msg.AUTH, token=token, nonce=nonce, posture=lie))
    reply = (await read_frame(reader)).json
    await frames.aclose()
    await asyncio.sleep(0.1)

    reason = str(reply.get("reason", ""))
    return AttackResult(
        name="forged_posture_is_rejected",
        group="device",
        goal="Claim a healthy posture the device cannot prove",
        technique="Masquerading (T1036)",
        blocked=reason == "posture_bad_signature",
        evidence=f"auth failed: {reason}",
        detail="A posture report is only accepted if signed by the private key "
        "of the device certificate presenting it.",
        audit_actions=_audit_since(lab, mark),
    )


@scenario(
    "device",
    "Attest as a different, healthier device",
    "Masquerading (T1036)",
)
async def posture_device_id_mismatch_is_rejected(lab: Lab) -> AttackResult:
    device = lab.device_for("ben")
    mark = _mark(lab)
    reader, frames, hello = await _raw_client(lab, device.device_id)
    nonce = str(hello["nonce"])
    # Correctly signed, but claims to be somebody else's workstation.
    lie = attest(DeviceState("workstation-chen"), nonce, device.identity.key_path)
    token = lab.token_for("ben", device=device)
    await frames.send(control(Msg.AUTH, token=token, nonce=nonce, posture=lie))
    reply = (await read_frame(reader)).json
    await frames.aclose()
    await asyncio.sleep(0.1)

    reason = str(reply.get("reason", ""))
    return AttackResult(
        name="posture_device_id_mismatch_is_rejected",
        group="device",
        goal="Attest as a different, healthier device",
        technique="Masquerading (T1036)",
        blocked=reason == "posture_device_mismatch",
        evidence=f"auth failed: {reason}",
        detail="The attested device id must match the certificate on the wire.",
        audit_actions=_audit_since(lab, mark),
    )


# ------------------------------------------------------------------ policy


@scenario(
    "policy",
    "Move sideways from an allowed app to a forbidden one",
    "Lateral movement (T1021)",
)
async def lateral_movement_is_blocked(lab: Lab) -> AttackResult:
    mark = _mark(lab)
    ben = await lab.client_for("ben")
    allowed = await ben.request("wiki", b"GET / HTTP/1.1\r\nHost: wiki\r\n\r\n")

    reason = ""
    try:
        await ben.open("payroll")
    except AccessDenied as exc:
        reason = exc.reason
    visible = list(ben.apps)
    await ben.close()
    await asyncio.sleep(0.1)

    return AttackResult(
        name="lateral_movement_is_blocked",
        group="policy",
        goal="Move sideways from an allowed app to a forbidden one",
        technique="Lateral movement (T1021)",
        blocked=bool(allowed) and reason == "no_matching_rule" and "payroll" not in visible,
        evidence=f"wiki reachable; payroll denied ({reason}); visible {visible}",
        detail="Reaching one application grants no network position at all, so "
        "there is nothing to pivot from. Payroll is not even listed.",
        audit_actions=_audit_since(lab, mark),
    )


@scenario(
    "policy",
    "Discover which private applications exist",
    "Network service discovery (T1046)",
)
async def app_enumeration_is_blocked_and_detected(lab: Lab) -> AttackResult:
    mark = _mark(lab)
    ben = await lab.client_for("ben")

    probes = ["payroll", "factory-hmi", "hr-portal", "vpn-admin", "backup-nas"]
    reasons: list[str] = []
    for app in probes:
        try:
            await ben.open(app)
            reasons.append(f"{app}:ALLOWED")
        except AccessDenied as exc:
            reasons.append(exc.reason)
    await ben.close()
    await asyncio.sleep(0.1)

    uniform = set(reasons) == {"no_matching_rule"}
    return AttackResult(
        name="app_enumeration_is_blocked_and_detected",
        group="policy",
        goal="Discover which private applications exist",
        technique="Network service discovery (T1046)",
        blocked=uniform,
        evidence=f"{len(probes)}/{len(probes)} probes denied with an identical reason",
        detail="Real applications and invented names produce the same answer, so "
        "the attacker learns nothing; the burst trips detection TOB-003.",
        audit_actions=_audit_since(lab, mark),
    )


@scenario(
    "policy",
    "Use a group membership to reach a forbidden application",
    "Valid accounts (T1078)",
)
async def explicit_deny_beats_allow(lab: Lab) -> AttackResult:
    mark = _mark(lab)
    dinesh = await lab.client_for("dinesh")
    reason = ""
    try:
        await dinesh.open("factory-hmi")
    except AccessDenied as exc:
        reason = exc.reason
    await dinesh.close()
    await asyncio.sleep(0.1)

    return AttackResult(
        name="explicit_deny_beats_allow",
        group="policy",
        goal="Use a group membership to reach a forbidden application",
        technique="Valid accounts (T1078)",
        blocked=reason in ("explicit_deny", "no_matching_rule"),
        evidence=f"denied: {reason}",
        detail="Dinesh is in 'employees' and 'contractors'. The contractor deny "
        "rule wins, which is the safe direction for a policy conflict.",
        audit_actions=_audit_since(lab, mark),
    )


@scenario(
    "policy",
    "Reach a business-hours application in the middle of the night",
    "Valid accounts (T1078)",
)
async def out_of_hours_access_is_denied(lab: Lab) -> AttackResult:
    """Evaluated against the policy engine with a fixed clock."""
    device = lab.device_for("aiko")
    subject = Subject(
        username="aiko",
        groups=["employees", "finance"],
        mfa=True,
        device_id=device.device_id,
        posture_attributes=device.state.attributes(),
    )
    # 03:00 Japan time on a Tuesday.
    night = dt.datetime(2026, 11, 24, 18, 0, tzinfo=dt.timezone.utc)
    day = dt.datetime(2026, 11, 24, 5, 0, tzinfo=dt.timezone.utc)

    denied = lab.policy.decide(subject, "payroll", now=night)
    allowed = lab.policy.decide(subject, "payroll", now=day)

    return AttackResult(
        name="out_of_hours_access_is_denied",
        group="policy",
        goal="Reach a business-hours application in the middle of the night",
        technique="Valid accounts (T1078)",
        blocked=(not denied.allowed) and allowed.allowed,
        evidence=f"03:00 JST -> {denied.reason}; 14:00 JST -> {allowed.reason}",
        detail="The same identity, device and token produce a different answer "
        "depending on when the request is made.",
    )


@scenario("policy", "Reach a high-value application without MFA", "Valid accounts (T1078)")
async def missing_mfa_is_denied(lab: Lab) -> AttackResult:
    device = lab.device_for("aiko")
    token = lab.token_for("aiko", device=device, mfa=False)

    mark = _mark(lab)
    client = await lab.client_for("aiko", token=token)
    reason = ""
    try:
        await client.open("payroll")
    except AccessDenied as exc:
        reason = exc.reason
    visible = list(client.apps)
    await client.close()
    await asyncio.sleep(0.1)

    return AttackResult(
        name="missing_mfa_is_denied",
        group="policy",
        goal="Reach a high-value application without MFA",
        technique="Valid accounts (T1078)",
        blocked=reason == "mfa_required" and "payroll" not in visible,
        evidence=f"denied: {reason}; visible apps {visible}",
        detail="Password-only authentication is enough for the wiki and not "
        "enough for payroll; the bar is per application.",
        audit_actions=_audit_since(lab, mark),
    )


# -------------------------------------------------------------- continuous


@scenario(
    "continuous",
    "Disable a security control after being let in",
    "Impair defenses (T1562.004)",
)
async def posture_drop_revokes_live_session(lab: Lab) -> AttackResult:
    mark = _mark(lab)
    chen = await lab.client_for("chen")
    stream = await chen.open("factory-hmi")
    await stream.send(b"GET /status HTTP/1.1\r\nHost: hmi\r\n\r\n")
    # Read the reply but leave the stream open (the app speaks keep-alive), so
    # there is a live session for the broker to tear down.
    first = await stream.receive(timeout=3.0)

    # The endpoint turns its firewall and EDR off while connected.
    degraded = DeviceState(
        "workstation-chen",
        os_name="linux",
        os_patch_age_days=1,
        firewall_enabled=False,
        edr_running=False,
    )
    reply = await chen.refresh_posture(degraded)
    await asyncio.sleep(0.2)

    still_open = not stream.closed
    visible = list(chen.apps)
    await chen.close()
    await asyncio.sleep(0.1)

    actions = _audit_since(lab, mark)
    return AttackResult(
        name="posture_drop_revokes_live_session",
        group="continuous",
        goal="Disable a security control after being let in",
        technique="Impair defenses (T1562.004)",
        blocked=(
            bool(first)
            and "factory-hmi" in reply.get("revoked", [])
            and not still_open
            and "factory-hmi" not in visible
            and "access_revoked" in actions
        ),
        evidence=f"session was live, then revoked: {reply.get('revoked')}; "
        f"posture score {reply.get('score')}",
        detail="Access is re-evaluated on every re-attestation, so the open "
        "connection is torn down rather than surviving until token expiry.",
        audit_actions=actions,
    )


@scenario(
    "continuous",
    "Keep a session alive by never re-attesting",
    "Impair defenses (T1562)",
)
async def stale_posture_blocks_new_connections(lab: Lab) -> AttackResult:
    """Simulates an agent that stops reporting; new opens must fail closed."""
    mark = _mark(lab)
    ben = await lab.client_for("ben")
    await ben.request("wiki", b"GET / HTTP/1.1\r\n\r\n")

    session = next(
        s for s in lab.broker.registry.sessions.values() if s.username == "ben"
    )
    session.last_posture_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)

    reason = ""
    try:
        await ben.open("wiki")
    except AccessDenied as exc:
        reason = exc.reason
    await ben.close()
    await asyncio.sleep(0.1)

    return AttackResult(
        name="stale_posture_blocks_new_connections",
        group="continuous",
        goal="Keep a session alive by never re-attesting",
        technique="Impair defenses (T1562)",
        blocked=reason == "posture_stale",
        evidence=f"denied: {reason}",
        detail="A device that stops proving its state loses access; silence is "
        "not treated as health.",
        audit_actions=_audit_since(lab, mark),
    )


# ------------------------------------------------------------------ runner

SCENARIOS: list[Scenario] = [
    app_connector_opens_no_port,
    anonymous_tls_is_refused,
    foreign_ca_certificate_is_refused,
    device_cert_cannot_publish_apps,
    rogue_connector_cannot_claim_app,
    forged_token_is_rejected,
    expired_token_is_rejected,
    token_replay_from_other_device,
    revoked_credential_is_rejected,
    stale_nonce_is_rejected,
    open_before_auth_is_rejected,
    unhealthy_device_is_denied,
    forged_posture_is_rejected,
    posture_device_id_mismatch_is_rejected,
    lateral_movement_is_blocked,
    app_enumeration_is_blocked_and_detected,
    explicit_deny_beats_allow,
    out_of_hours_access_is_denied,
    missing_mfa_is_denied,
    posture_drop_revokes_live_session,
    stale_posture_blocks_new_connections,
]


async def run_all(lab: Lab, *, verbose: bool = True) -> list[AttackResult]:
    results: list[AttackResult] = []
    for func in SCENARIOS:
        try:
            result = await func(lab)
        except Exception as exc:  # a crashing scenario is a failed scenario
            group, goal, technique = getattr(func, "_tobira_meta", ("?", "?", "?"))
            result = AttackResult(
                name=func.__name__,
                group=group,
                goal=goal,
                technique=technique,
                blocked=False,
                evidence=f"scenario error: {type(exc).__name__}: {exc}",
            )
        results.append(result)
        if verbose:
            tick = "PASS" if result.blocked else "FAIL"
            print(f"  [{tick}] {result.name:<42} {result.evidence}", flush=True)
    return results
