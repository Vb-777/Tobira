from __future__ import annotations

import os
from pathlib import Path

import pytest

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tobira.pki import CertificateAuthority, cert_thumbprint, peer_name


def test_ca_is_created_once(tmp_path: Path) -> None:
    ca = CertificateAuthority(tmp_path / "pki")
    assert not ca.exists
    ca.ensure()
    assert ca.exists
    first = ca.cert_path.read_bytes()
    ca.ensure()
    assert ca.cert_path.read_bytes() == first, "ensure() must not re-issue"


def test_ca_cannot_issue_intermediates(ca: CertificateAuthority) -> None:
    cert = x509.load_pem_x509_certificate(ca.cert_path.read_bytes())
    constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert constraints.ca is True
    assert constraints.path_length == 0


def test_leaf_is_not_a_ca(ca: CertificateAuthority, tmp_path: Path) -> None:
    identity = ca.issue("laptop-a", out_dir=tmp_path / "d", org_unit="device")
    cert = identity.certificate
    constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert constraints.ca is False


def test_role_is_carried_in_the_subject(ca: CertificateAuthority, tmp_path: Path) -> None:
    device = ca.issue("laptop-a", out_dir=tmp_path / "d", org_unit="device")
    connector = ca.issue("connector-hq", out_dir=tmp_path / "c", org_unit="connector")

    from cryptography.hazmat.primitives import serialization

    cn, ou = peer_name(device.certificate.public_bytes(serialization.Encoding.DER))
    assert (cn, ou) == ("laptop-a", "device")
    cn, ou = peer_name(connector.certificate.public_bytes(serialization.Encoding.DER))
    assert (cn, ou) == ("connector-hq", "connector")


def test_broker_certificate_has_server_auth_and_sans(
    ca: CertificateAuthority, tmp_path: Path
) -> None:
    broker = ca.issue(
        "tobira-broker",
        out_dir=tmp_path / "b",
        org_unit="broker",
        server=True,
        client=False,
        sans=["tobira-broker", "127.0.0.1"],
    )
    cert = broker.certificate
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    assert ExtendedKeyUsageOID.CLIENT_AUTH not in eku

    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "tobira-broker" in san.get_values_for_type(x509.DNSName)


def test_thumbprints_are_unique_per_device(ca: CertificateAuthority, tmp_path: Path) -> None:
    a = ca.issue("laptop-a", out_dir=tmp_path / "d", org_unit="device")
    b = ca.issue("laptop-b", out_dir=tmp_path / "d", org_unit="device")
    assert a.thumbprint != b.thumbprint
    assert len(a.thumbprint) == 64
    assert cert_thumbprint(a.certificate) == a.thumbprint


def test_private_keys_are_not_world_readable(ca: CertificateAuthority, tmp_path: Path) -> None:
    identity = ca.issue("laptop-a", out_dir=tmp_path / "d", org_unit="device")

    if os.name == "nt":
        pytest.skip("POSIX permission bits are not meaningful on Windows")

    assert (identity.key_path.stat().st_mode & 0o077) == 0

def test_subject_names_are_what_we_asked_for(ca: CertificateAuthority, tmp_path: Path) -> None:
    identity = ca.issue("laptop-a", out_dir=tmp_path / "d", org_unit="device")
    subject = identity.certificate.subject
    assert subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "laptop-a"
