"""Private PKI for Tobira.

Every participant - broker, App Connector, and each enrolled user device - holds
an X.509 certificate issued by the lab CA, and every tunnel is mutually
authenticated. Two properties matter for the zero trust model:

* The broker refuses any peer that cannot present a certificate chaining to the
  CA, so an attacker who merely reaches the broker port learns nothing.
* A device certificate is the **device identity**. Access tokens are bound to
  the SHA-256 thumbprint of that certificate (RFC 8705 style ``cnf`` claim), so
  a stolen token cannot be replayed from a different machine.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import ssl
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CURVE = ec.SECP256R1()
_ONE_DAY = dt.timedelta(days=1)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


@dataclass(frozen=True, slots=True)
class Identity:
    """A key pair plus certificate on disk."""

    name: str
    cert_path: Path
    key_path: Path

    @property
    def certificate(self) -> x509.Certificate:
        return x509.load_pem_x509_certificate(self.cert_path.read_bytes())

    @property
    def thumbprint(self) -> str:
        """SHA-256 fingerprint of the DER certificate, lowercase hex."""
        return cert_thumbprint(self.certificate)


def cert_thumbprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def thumbprint_from_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


class CertificateAuthority:
    """Minimal offline CA. Good enough for a lab, structured like a real one."""

    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        self.cert_path = self.dir / "ca.crt"
        self.key_path = self.dir / "ca.key"

    # ------------------------------------------------------------------ setup

    @property
    def exists(self) -> bool:
        return self.cert_path.exists() and self.key_path.exists()

    def create(self, common_name: str = "Tobira Lab Root CA", days: int = 825) -> None:
        key = ec.generate_private_key(CURVE)
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "JP"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Tobira Lab"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_now() - _ONE_DAY)
            .not_valid_after(_now() + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .sign(key, hashes.SHA256())
        )
        _write_key(self.key_path, key)
        _write_cert(self.cert_path, cert)

    def ensure(self) -> None:
        if not self.exists:
            self.create()

    # ----------------------------------------------------------------- issuing

    def _load(self) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
        cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
        key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
        return cert, key  # type: ignore[return-value]

    def issue(
        self,
        common_name: str,
        *,
        out_dir: Path,
        org_unit: str,
        server: bool = False,
        client: bool = True,
        sans: list[str] | None = None,
        days: int = 365,
        not_before: dt.datetime | None = None,
        not_after: dt.datetime | None = None,
    ) -> Identity:
        """Issue a leaf certificate.

        ``org_unit`` carries the participant role (``broker``/``connector``/
        ``device``) so the broker can reject, for example, a device certificate
        that tries to register itself as an App Connector.
        """
        ca_cert, ca_key = self._load()
        key = ec.generate_private_key(CURVE)

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Tobira Lab"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

        eku = []
        if server:
            eku.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if client:
            eku.append(ExtendedKeyUsageOID.CLIENT_AUTH)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before or (_now() - _ONE_DAY))
            .not_valid_after(not_after or (_now() + dt.timedelta(days=days)))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
        )

        alt_names: list[x509.GeneralName] = []
        for san in sans or []:
            try:
                alt_names.append(x509.IPAddress(ipaddress.ip_address(san)))
            except ValueError:
                alt_names.append(x509.DNSName(san))
        if alt_names:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(alt_names), critical=False
            )

        cert = builder.sign(ca_key, hashes.SHA256())

        out_dir = Path(out_dir)
        cert_path = out_dir / f"{common_name}.crt"
        key_path = out_dir / f"{common_name}.key"
        _write_cert(cert_path, cert)
        _write_key(key_path, key)
        return Identity(common_name, cert_path, key_path)


# --------------------------------------------------------------- TLS contexts


def server_context(identity: Identity, ca_cert: Path) -> ssl.SSLContext:
    """TLS context for the broker: TLS 1.3 and a *required* client certificate."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(identity.cert_path, identity.key_path)
    ctx.load_verify_locations(cafile=str(ca_cert))
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def client_context(
    identity: Identity | None, ca_cert: Path | None, *, check_hostname: bool = True
) -> ssl.SSLContext:
    """TLS context for a connector or device dialling the broker.

    ``identity=None`` / ``ca_cert=None`` are deliberately supported so the attack
    suite can prove that anonymous and untrusting peers are rejected.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if ca_cert is not None:
        ctx.load_verify_locations(cafile=str(ca_cert))
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = check_hostname
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if identity is not None:
        ctx.load_cert_chain(identity.cert_path, identity.key_path)
    return ctx


def peer_certificate_der(transport_ssl_object: ssl.SSLObject | None) -> bytes | None:
    if transport_ssl_object is None:
        return None
    return transport_ssl_object.getpeercert(binary_form=True)


def peer_name(der: bytes) -> tuple[str, str]:
    """Return ``(common_name, organizational_unit)`` of a peer certificate."""
    cert = x509.load_der_x509_certificate(der)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    return (
        str(cn[0].value) if cn else "",
        str(ou[0].value) if ou else "",
    )
