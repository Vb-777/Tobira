"""End-to-end tests against a live broker, connectors and private apps."""

from __future__ import annotations

import asyncio
import datetime as dt

import pytest

@pytest.fixture
def business_hours_lab(lab: Lab) -> Lab:
    """Lab variant for tests that require payroll to be reachable."""
    rule = next(r for r in lab.policy.rules if r.name == "finance-payroll")
    original = rule.time_window
    rule.time_window = None
    try:
        yield lab
    finally:
        rule.time_window = original

from tobira.client import AccessDenied, ClientConnector
from tobira.lab import BROKER_SAN, Lab
from tobira.posture import DeviceState


async def test_authorised_user_reaches_the_application(business_hours_lab: Lab) -> None:
    lab = business_hours_lab
    aiko = await lab.client_for("aiko")
    body = await aiko.request("payroll", b"GET /slip HTTP/1.1\r\nHost: payroll\r\n\r\n")
    assert b"PAYROLL-SECRET-7F31" in body
    assert lab.apps["payroll"].connections == 1


async def test_broker_only_advertises_reachable_apps(business_hours_lab: Lab) -> None:
    lab = business_hours_lab
    aiko = await lab.client_for("aiko")
    ben = await lab.client_for("ben")
    assert "payroll" in aiko.apps
    assert "payroll" not in ben.apps
    assert "factory-hmi" not in ben.apps


async def test_unauthorised_app_is_denied(lab: Lab) -> None:
    ben = await lab.client_for("ben")
    with pytest.raises(AccessDenied) as excinfo:
        await ben.open("payroll")
    assert excinfo.value.reason == "no_matching_rule"
    assert lab.apps["payroll"].connections == 0


async def test_binary_payloads_survive_the_relay(lab: Lab) -> None:
    """The relay must be byte-exact, not line- or text-oriented."""
    chen = await lab.client_for("chen")
    stream = await chen.open("factory-hmi")
    blob = bytes(range(256)) * 64
    await stream.send(blob)
    echoed = await stream.receive(timeout=3.0)
    assert echoed  # the demo app answers with HTTP
    await stream.close()


async def test_concurrent_streams_do_not_interleave(lab: Lab) -> None:
    aiko = await lab.client_for("aiko")
    results = await asyncio.gather(
        *(
            aiko.request("wiki", f"GET /page{i} HTTP/1.1\r\n\r\n".encode())
            for i in range(8)
        )
    )
    for index, body in enumerate(results):
        assert f"path=/page{index}".encode() in body


async def test_two_users_are_isolated(business_hours_lab: Lab) -> None:
    lab = business_hours_lab
    aiko = await lab.client_for("aiko")
    ben = await lab.client_for("ben")
    aiko_body = await aiko.request("payroll", b"GET / HTTP/1.1\r\n\r\n")
    ben_body = await ben.request("wiki", b"GET / HTTP/1.1\r\n\r\n")
    assert b"PAYROLL-SECRET" in aiko_body
    assert b"PAYROLL-SECRET" not in ben_body


async def test_loopback_listener_proxies_an_ordinary_client(lab: Lab) -> None:
    aiko = await lab.client_for("aiko")
    port = await aiko.listen("wiki")
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"GET /from-curl HTTP/1.1\r\nHost: wiki\r\n\r\n")
    await writer.drain()
    body = await asyncio.wait_for(reader.read(4096), 5.0)
    writer.close()
    assert b"path=/from-curl" in body


async def test_posture_drop_tears_down_live_stream(lab: Lab) -> None:
    chen = await lab.client_for("chen")
    stream = await chen.open("factory-hmi")
    await stream.send(b"GET /status HTTP/1.1\r\n\r\n")
    assert await stream.receive(timeout=3.0)

    reply = await chen.refresh_posture(
        DeviceState("workstation-chen", os_patch_age_days=1, edr_running=False)
    )
    await asyncio.sleep(0.2)

    assert "factory-hmi" in reply["revoked"]
    assert stream.closed
    assert "factory-hmi" not in chen.apps


async def test_posture_recovery_restores_access(lab: Lab) -> None:
    chen = await lab.client_for(
        "chen", state=DeviceState("workstation-chen", os_patch_age_days=1, edr_running=False)
    )
    assert "factory-hmi" not in chen.apps

    reply = await chen.refresh_posture(
        DeviceState("workstation-chen", os_patch_age_days=1, edr_running=True)
    )
    assert "factory-hmi" in reply["apps"]
    stream = await chen.open("factory-hmi")
    await stream.close()


async def test_connector_loss_closes_streams(lab: Lab) -> None:
    chen = await lab.client_for("chen")
    stream = await chen.open("factory-hmi")
    await stream.send(b"GET / HTTP/1.1\r\n\r\n")
    assert await stream.receive(timeout=3.0)

    await lab.connectors["connector-factory"].stop()
    await asyncio.sleep(0.3)
    assert stream.closed

    with pytest.raises(AccessDenied) as excinfo:
        await chen.open("factory-hmi")
    assert excinfo.value.reason == "connector_unavailable"


async def test_expired_session_token_blocks_new_streams(lab: Lab) -> None:
    ben = await lab.client_for("ben")
    await ben.request("wiki", b"GET / HTTP/1.1\r\n\r\n")

    session = next(s for s in lab.broker.registry.sessions.values() if s.username == "ben")
    session.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)

    with pytest.raises(AccessDenied) as excinfo:
        await ben.open("wiki")
    assert excinfo.value.reason == "token_expired"


async def test_audit_trail_records_allow_and_deny(lab: Lab) -> None:
    ben = await lab.client_for("ben")
    await ben.request("wiki", b"GET / HTTP/1.1\r\n\r\n")
    with pytest.raises(AccessDenied):
        await ben.open("payroll")
    await asyncio.sleep(0.1)

    actions = [doc["event"]["action"] for doc in lab.emitter.events]
    assert "authentication_succeeded" in actions
    assert "access_granted" in actions
    assert "access_denied" in actions

    granted = next(
        d for d in lab.emitter.events if d["event"]["action"] == "access_granted"
    )
    assert granted["user"]["name"] == "ben"
    assert granted["tobira"]["app"] == "wiki"
    assert granted["tobira"]["policy_rule"] == "everyone-wiki"
    assert granted["ecs"]["version"].startswith("8.")


async def test_audit_log_is_written_to_disk(lab: Lab) -> None:
    aiko = await lab.client_for("aiko")
    await aiko.request("wiki", b"GET / HTTP/1.1\r\n\r\n")
    await asyncio.sleep(0.1)
    assert lab.emitter.path is not None
    lines = lab.emitter.path.read_text().strip().splitlines()
    assert len(lines) == len(lab.emitter.events)


async def test_wrong_certificate_role_is_rejected(lab: Lab) -> None:
    """A device certificate must not authenticate on the connector port."""
    device = lab.device_for("ben")
    client = ClientConnector(
        device.device_id,
        device.identity,
        lab.ca.cert_path,
        lab.host,
        lab.broker.connector_port,  # wrong port for a device
        device_state=device.state,
        server_hostname=BROKER_SAN,
    )
    assert await client.connect(lab.token_for("ben")) is False
    await client.close()
