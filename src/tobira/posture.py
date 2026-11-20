"""Device posture: signed attestation and server-side evaluation.

"Is this the right user?" is only half of an access decision. The other half is
"is this device fit to hold the data?". A Tobira client collects a set of host
attributes and signs them with the **private key of its device certificate**,
over a nonce the broker chose for this connection. That gives two guarantees:

* the attestation cannot be lifted from one device and replayed on another, and
* it cannot be replayed later on the same device.

Posture is re-attested periodically while a session is open, so a device that
turns its firewall off mid-session loses access rather than keeping it until the
token expires.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_der_x509_certificate

#: Weight each attribute contributes to the 0-100 posture score.
ATTRIBUTE_WEIGHTS: dict[str, int] = {
    "disk_encryption": 25,
    "edr_running": 20,
    "firewall_enabled": 15,
    "screen_lock": 10,
    "secure_boot": 10,
    "os_supported": 10,
    "patched": 10,
}

#: How old an attestation may be before the broker rejects it.
MAX_ATTESTATION_AGE = dt.timedelta(seconds=120)


def new_nonce() -> str:
    return secrets.token_hex(16)


class PostureError(Exception):
    """Raised when an attestation cannot be trusted."""


@dataclass(slots=True)
class DeviceState:
    """Host facts a real agent would read from the OS."""

    device_id: str
    os_name: str = "linux"
    os_patch_age_days: int = 3
    disk_encryption: bool = True
    firewall_enabled: bool = True
    edr_running: bool = True
    screen_lock: bool = True
    secure_boot: bool = True
    os_supported: bool = True
    agent_version: str = "1.0.0"

    def attributes(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "os_name": self.os_name,
            "os_patch_age_days": self.os_patch_age_days,
            "disk_encryption": self.disk_encryption,
            "firewall_enabled": self.firewall_enabled,
            "edr_running": self.edr_running,
            "screen_lock": self.screen_lock,
            "secure_boot": self.secure_boot,
            "os_supported": self.os_supported,
            "agent_version": self.agent_version,
        }


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def attest(
    state: DeviceState,
    nonce: str,
    private_key_path: str | Path,
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Build a signed posture attestation for ``nonce``."""
    key = serialization.load_pem_private_key(Path(private_key_path).read_bytes(), password=None)
    body = {
        "nonce": nonce,
        "collected_at": (now or dt.datetime.now(dt.timezone.utc))
        .isoformat()
        .replace("+00:00", "Z"),
        "attributes": state.attributes(),
    }
    signature = key.sign(_canonical(body), ec.ECDSA(hashes.SHA256()))
    return {**body, "signature": base64.b64encode(signature).decode("ascii")}


def verify_attestation(
    attestation: dict[str, Any],
    expected_nonce: str,
    device_cert_der: bytes,
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Verify freshness, nonce binding and the device signature.

    Returns the attested attributes. Raises :class:`PostureError` otherwise.
    """
    if not isinstance(attestation, dict):
        raise PostureError("posture_malformed")

    for required in ("nonce", "collected_at", "attributes", "signature"):
        if required not in attestation:
            raise PostureError("posture_malformed")

    if not secrets.compare_digest(str(attestation["nonce"]), expected_nonce):
        raise PostureError("posture_nonce_mismatch")

    try:
        stamp = str(attestation["collected_at"]).replace("Z", "+00:00")
        collected = dt.datetime.fromisoformat(stamp)
    except ValueError as exc:
        raise PostureError("posture_bad_timestamp") from exc
    if collected.tzinfo is None:
        collected = collected.replace(tzinfo=dt.timezone.utc)

    reference = now or dt.datetime.now(dt.timezone.utc)
    if abs(reference - collected) > MAX_ATTESTATION_AGE:
        raise PostureError("posture_stale")

    body = {
        "nonce": attestation["nonce"],
        "collected_at": attestation["collected_at"],
        "attributes": attestation["attributes"],
    }
    try:
        cert = load_der_x509_certificate(device_cert_der)
        public_key = cert.public_key()
        public_key.verify(  # type: ignore[union-attr]
            base64.b64decode(attestation["signature"]),
            _canonical(body),
            ec.ECDSA(hashes.SHA256()),
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise PostureError("posture_bad_signature") from exc

    attrs = attestation["attributes"]
    if not isinstance(attrs, dict):
        raise PostureError("posture_malformed")
    return attrs


@dataclass(slots=True)
class PostureProfile:
    """A named posture bar that a policy rule can require."""

    name: str
    require: dict[str, Any] = field(default_factory=dict)
    min_score: int = 0

    @classmethod
    def from_dict(cls, name: str, doc: dict[str, Any]) -> PostureProfile:
        return cls(
            name=name,
            require=dict(doc.get("require", {})),
            min_score=int(doc.get("min_score", 0)),
        )


@dataclass(slots=True)
class PostureResult:
    passed: bool
    score: int
    failures: list[str] = field(default_factory=list)

    @property
    def reason(self) -> str:
        return "posture_failed:" + ",".join(self.failures) if self.failures else ""


def score(attributes: dict[str, Any], *, max_patch_age_days: int = 30) -> int:
    """Compute a 0-100 posture score from attested attributes."""
    total = 0
    for attribute, weight in ATTRIBUTE_WEIGHTS.items():
        if attribute == "patched":
            age = attributes.get("os_patch_age_days")
            if isinstance(age, (int, float)) and age <= max_patch_age_days:
                total += weight
        elif attributes.get(attribute) is True:
            total += weight
    return total


def evaluate(attributes: dict[str, Any], profile: PostureProfile) -> PostureResult:
    """Check attested attributes against a profile."""
    failures: list[str] = []

    for key, expectation in profile.require.items():
        actual = attributes.get(key)
        if isinstance(expectation, dict):
            if "max" in expectation and (
                not isinstance(actual, (int, float)) or actual > expectation["max"]
            ):
                failures.append(key)
            if "min" in expectation and (
                not isinstance(actual, (int, float)) or actual < expectation["min"]
            ):
                failures.append(key)
            if "in" in expectation and actual not in expectation["in"]:
                failures.append(key)
        elif actual != expectation:
            failures.append(key)

    max_age = 30
    patch_rule = profile.require.get("os_patch_age_days")
    if isinstance(patch_rule, dict) and "max" in patch_rule:
        max_age = int(patch_rule["max"])

    value = score(attributes, max_patch_age_days=max_age)
    if value < profile.min_score:
        failures.append(f"score<{profile.min_score}")

    return PostureResult(passed=not failures, score=value, failures=failures)
