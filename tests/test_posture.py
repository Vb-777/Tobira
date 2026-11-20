from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from tobira.pki import CertificateAuthority
from tobira.posture import (
    DeviceState,
    PostureError,
    PostureProfile,
    attest,
    evaluate,
    new_nonce,
    score,
    verify_attestation,
)

HIGH = PostureProfile.from_dict(
    "high",
    {
        "require": {
            "disk_encryption": True,
            "firewall_enabled": True,
            "edr_running": True,
            "os_patch_age_days": {"max": 14},
        },
        "min_score": 80,
    },
)


def _device(ca: CertificateAuthority, name: str, tmp_path: Path):
    identity = ca.issue(name, out_dir=tmp_path / "d", org_unit="device")
    der = identity.certificate.public_bytes(serialization.Encoding.DER)
    return identity, der


def test_attestation_round_trip(ca: CertificateAuthority, tmp_path: Path) -> None:
    identity, der = _device(ca, "laptop-aiko", tmp_path)
    nonce = new_nonce()
    attestation = attest(DeviceState("laptop-aiko"), nonce, identity.key_path)
    attributes = verify_attestation(attestation, nonce, der)
    assert attributes["device_id"] == "laptop-aiko"


def test_nonce_must_match(ca: CertificateAuthority, tmp_path: Path) -> None:
    identity, der = _device(ca, "laptop-aiko", tmp_path)
    attestation = attest(DeviceState("laptop-aiko"), new_nonce(), identity.key_path)
    with pytest.raises(PostureError, match="posture_nonce_mismatch"):
        verify_attestation(attestation, new_nonce(), der)


def test_signature_must_come_from_the_device(ca: CertificateAuthority, tmp_path: Path) -> None:
    _, victim_der = _device(ca, "laptop-aiko", tmp_path)
    forger, _ = _device(ca, "laptop-forger", tmp_path)
    nonce = new_nonce()
    attestation = attest(DeviceState("laptop-aiko"), nonce, forger.key_path)
    with pytest.raises(PostureError, match="posture_bad_signature"):
        verify_attestation(attestation, nonce, victim_der)


def test_stale_attestation_is_refused(ca: CertificateAuthority, tmp_path: Path) -> None:
    identity, der = _device(ca, "laptop-aiko", tmp_path)
    nonce = new_nonce()
    attestation = attest(
        DeviceState("laptop-aiko"),
        nonce,
        identity.key_path,
        now=dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=30),
    )
    with pytest.raises(PostureError, match="posture_stale"):
        verify_attestation(attestation, nonce, der)


def test_tampered_attributes_break_the_signature(
    ca: CertificateAuthority, tmp_path: Path
) -> None:
    identity, der = _device(ca, "laptop-ben", tmp_path)
    nonce = new_nonce()
    attestation = attest(
        DeviceState("laptop-ben", disk_encryption=False), nonce, identity.key_path
    )
    attestation["attributes"]["disk_encryption"] = True  # lie after signing
    with pytest.raises(PostureError, match="posture_bad_signature"):
        verify_attestation(attestation, nonce, der)


def test_malformed_attestation_is_refused(ca: CertificateAuthority, tmp_path: Path) -> None:
    _, der = _device(ca, "laptop-ben", tmp_path)
    with pytest.raises(PostureError, match="posture_malformed"):
        verify_attestation({"nonce": "x"}, "x", der)


def test_healthy_device_passes_high_profile() -> None:
    result = evaluate(DeviceState("d", os_patch_age_days=2).attributes(), HIGH)
    assert result.passed
    assert result.score == 100


def test_unencrypted_disk_fails_and_is_named() -> None:
    result = evaluate(
        DeviceState("d", disk_encryption=False, os_patch_age_days=2).attributes(), HIGH
    )
    assert not result.passed
    assert "disk_encryption" in result.failures
    assert result.score == 75


def test_patch_age_is_a_range_check() -> None:
    result = evaluate(DeviceState("d", os_patch_age_days=40).attributes(), HIGH)
    assert not result.passed
    assert "os_patch_age_days" in result.failures


def test_score_weights_sum_to_100() -> None:
    assert score(DeviceState("d", os_patch_age_days=1).attributes()) == 100
