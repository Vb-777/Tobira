"""Builds a complete Tobira environment in one process.

The lab stands up, in order:

* a private CA and certificates for the broker, two App Connectors and each
  enrolled device;
* four "private" applications bound to loopback on ephemeral ports;
* the broker;
* the App Connectors, which dial out and publish their applications.

Everything is wired from the YAML in ``lab/config``, so the demo, the test suite
and the attack suite all exercise exactly the same configuration an operator
would edit.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .broker import Broker, BrokerConfig
from .client import ClientConnector
from .connector import AppConnector, PublishedApp
from .events import EventEmitter
from .identity import IdentityProvider, TokenVerifier
from .pki import CertificateAuthority, Identity
from .policy import PolicyEngine
from .posture import DeviceState

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_DIR = REPO_ROOT / "lab" / "config"

BROKER_SAN = "tobira-broker"


# --------------------------------------------------------------- demo apps


class DemoApp:
    """A stand-in private application: a tiny line-oriented HTTP responder."""

    def __init__(self, name: str, banner: str, secret: str) -> None:
        self.name = name
        self.banner = banner
        self.secret = secret
        self.port = 0
        self.connections = 0
        self._server: asyncio.AbstractServer | None = None

    async def start(self, host: str = "127.0.0.1") -> int:
        self._server = await asyncio.start_server(self._handle, host, 0)
        self.port = int(self._server.sockets[0].getsockname()[1])
        return self.port

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), 2.0)
            self._server = None

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Keep-alive HTTP, so a session stays open long enough to be revoked."""
        self.connections += 1
        try:
            while True:
                try:
                    request = await asyncio.wait_for(reader.read(4096), 30.0)
                except (asyncio.TimeoutError, ConnectionError):
                    break
                if not request:
                    break

                path = b"/"
                if request.startswith(b"GET "):
                    parts = request.split(b" ")
                    if len(parts) > 1:
                        path = parts[1]
                body = (
                    f"{self.banner}\n"
                    f"app={self.name}\n"
                    f"path={path.decode('ascii', 'replace')}\n"
                    f"secret={self.secret}\n"
                ).encode()
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Connection: keep-alive\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
                )
                try:
                    writer.write(response)
                    await writer.drain()
                except (ConnectionError, RuntimeError):
                    break
        finally:
            with contextlib.suppress(Exception):
                writer.close()


# ------------------------------------------------------------------- lab


@dataclass
class Device:
    """An enrolled endpoint: certificate plus the posture it will attest."""

    device_id: str
    owner: str
    identity: Identity
    state: DeviceState


@dataclass
class Lab:
    workdir: Path
    config_dir: Path = DEFAULT_CONFIG_DIR
    host: str = "127.0.0.1"
    echo_audit: bool = False

    ca: CertificateAuthority = field(init=False)
    broker: Broker = field(init=False)
    idp: IdentityProvider = field(init=False)
    policy: PolicyEngine = field(init=False)
    emitter: EventEmitter = field(init=False)
    apps: dict[str, DemoApp] = field(default_factory=dict)
    connectors: dict[str, AppConnector] = field(default_factory=dict)
    devices: dict[str, Device] = field(default_factory=dict)
    _clients: list[ClientConnector] = field(default_factory=list)

    # ------------------------------------------------------------- bring-up

    async def start(self) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        pki_dir = self.workdir / "pki"

        self.ca = CertificateAuthority(pki_dir)
        self.ca.ensure()

        self.emitter = EventEmitter(self.workdir / "logs" / "tobira-ecs.json", echo=self.echo_audit)
        self.idp = IdentityProvider.from_yaml(self.config_dir / "users.yaml")

        await self._start_demo_apps()
        apps_path = self._write_effective_apps()
        self.policy = PolicyEngine.from_files(apps_path, self.config_dir / "policy.yaml")

        broker_identity = self.ca.issue(
            "tobira-broker",
            out_dir=pki_dir / "broker",
            org_unit="broker",
            server=True,
            client=False,
            sans=[BROKER_SAN, "localhost", "127.0.0.1"],
        )
        self.broker = Broker(
            BrokerConfig(
                identity=broker_identity,
                ca_cert=self.ca.cert_path,
                policy=self.policy,
                token_verifier=TokenVerifier(self.idp.public_key_pem),
                emitter=self.emitter,
                host=self.host,
                connector_port=0,
                client_port=0,
            )
        )
        await self.broker.start()
        await self._start_connectors(apps_path)
        await self._enrol_devices()

    async def _start_demo_apps(self) -> None:
        catalogue = {
            "payroll": ("Yamaha-style payroll service", "PAYROLL-SECRET-7F31"),
            "wiki": ("Engineering wiki", "WIKI-PUBLIC-NOTE"),
            "factory-hmi": ("Plant floor HMI gateway", "HMI-CONTROL-TOKEN-A9"),
            "build-server": ("CI build server", "BUILD-ARTIFACT-KEY-22"),
        }
        for name, (banner, secret) in catalogue.items():
            app = DemoApp(name, banner, secret)
            await app.start(self.host)
            self.apps[name] = app

    def _write_effective_apps(self) -> Path:
        """Copy the operator's apps.yaml, substituting the ports we just bound."""
        doc = yaml.safe_load((self.config_dir / "apps.yaml").read_text())
        for entry in doc.get("apps", []):
            demo = self.apps.get(entry["name"])
            if demo is not None:
                entry["host"] = self.host
                entry["port"] = demo.port
        out = self.workdir / "apps.effective.yaml"
        out.write_text(yaml.safe_dump(doc, sort_keys=False))
        return out

    async def _start_connectors(self, apps_path: Path) -> None:
        doc = yaml.safe_load(apps_path.read_text())
        names = sorted({entry["connector"] for entry in doc.get("apps", [])})
        for name in names:
            identity = self.ca.issue(
                name, out_dir=self.workdir / "pki" / "connectors", org_unit="connector"
            )
            published = [
                PublishedApp(entry["name"], entry["host"], int(entry["port"]))
                for entry in doc["apps"]
                if entry["connector"] == name
            ]
            connector = AppConnector(
                name,
                identity,
                self.ca.cert_path,
                self.host,
                self.broker.connector_port,
                published,
                server_hostname=BROKER_SAN,
            )
            await connector.start()
            await asyncio.wait_for(connector.registered.wait(), 5.0)
            self.connectors[name] = connector

    async def _enrol_devices(self) -> None:
        """Issue a device certificate per user, with a realistic posture."""
        profiles: dict[str, tuple[str, DeviceState]] = {
            "aiko": (
                "laptop-aiko",
                DeviceState("laptop-aiko", os_name="macos", os_patch_age_days=2),
            ),
            "ben": (
                "laptop-ben",
                DeviceState(
                    "laptop-ben",
                    os_name="windows",
                    os_patch_age_days=21,
                    secure_boot=False,
                    edr_running=True,
                ),
            ),
            "chen": (
                "workstation-chen",
                DeviceState("workstation-chen", os_name="linux", os_patch_age_days=1),
            ),
            "dinesh": (
                "laptop-dinesh",
                DeviceState("laptop-dinesh", os_name="windows", os_patch_age_days=5),
            ),
            "mallory": (
                "laptop-mallory",
                DeviceState("laptop-mallory", os_name="windows", os_patch_age_days=4),
            ),
        }
        for owner, (device_id, state) in profiles.items():
            identity = self.ca.issue(
                device_id, out_dir=self.workdir / "pki" / "devices", org_unit="device"
            )
            self.devices[device_id] = Device(device_id, owner, identity, state)

    # --------------------------------------------------------------- helpers

    def device_for(self, username: str) -> Device:
        for device in self.devices.values():
            if device.owner == username:
                return device
        raise KeyError(f"no enrolled device for {username!r}")

    def token_for(
        self,
        username: str,
        *,
        device: Device | None = None,
        mfa: bool | None = None,
        ttl: dt.timedelta | None = None,
    ) -> str:
        device = device or self.device_for(username)
        user = self.idp.get(username)
        want_mfa = user.mfa_enrolled if mfa is None else mfa
        kwargs: dict[str, Any] = {"mfa": want_mfa}
        if ttl is not None:
            kwargs["ttl"] = ttl
        return self.idp.issue(username, device.identity.thumbprint, **kwargs)

    async def client_for(
        self,
        username: str,
        *,
        device: Device | None = None,
        state: DeviceState | None = None,
        token: str | None = None,
    ) -> ClientConnector:
        """Connect and authenticate a device for ``username``."""
        device = device or self.device_for(username)
        client = ClientConnector(
            device.device_id,
            device.identity,
            self.ca.cert_path,
            self.host,
            self.broker.client_port,
            device_state=state or device.state,
            server_hostname=BROKER_SAN,
        )
        self._clients.append(client)
        await client.connect(token or self.token_for(username, device=device))
        return client

    def issue_device(
        self, device_id: str, owner: str, state: DeviceState | None = None
    ) -> Device:
        """Enrol an extra device at runtime (used by the attack suite)."""
        identity = self.ca.issue(
            device_id, out_dir=self.workdir / "pki" / "devices", org_unit="device"
        )
        device = Device(device_id, owner, identity, state or DeviceState(device_id))
        self.devices[device_id] = device
        return device

    # --------------------------------------------------------------- cleanup

    async def stop(self) -> None:
        for client in self._clients:
            with contextlib.suppress(Exception):
                await client.close()
        self._clients.clear()
        for connector in self.connectors.values():
            with contextlib.suppress(Exception):
                await connector.stop()
        self.connectors.clear()
        with contextlib.suppress(Exception):
            await self.broker.stop()
        for app in self.apps.values():
            await app.stop()
        self.apps.clear()

    async def __aenter__(self) -> Lab:
        await self.start()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.stop()


@contextlib.asynccontextmanager
async def temporary_lab(
    *, echo_audit: bool = False, config_dir: Path | None = None
) -> Any:
    """Async context manager that builds a lab in a throwaway directory."""
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="tobira-"))
    lab = Lab(
        workdir=tmp, config_dir=config_dir or DEFAULT_CONFIG_DIR, echo_audit=echo_audit
    )
    try:
        await lab.start()
        yield lab
    finally:
        await lab.stop()
        shutil.rmtree(tmp, ignore_errors=True)
