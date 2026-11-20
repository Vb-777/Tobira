from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from tobira.identity import AuthError, IdentityProvider, TokenVerifier, User
from tobira.pki import CertificateAuthority


@pytest.fixture
def idp() -> IdentityProvider:
    provider = IdentityProvider()
    provider.add_user(User("aiko", groups=["finance", "employees"], mfa_enrolled=True))
    provider.add_user(User("ben", groups=["employees"]))
    provider.add_user(User("mallory", groups=["employees"], status="revoked"))
    return provider


def _thumb(ca: CertificateAuthority, name: str, tmp_path: Path) -> str:
    return ca.issue(name, out_dir=tmp_path / "d", org_unit="device").thumbprint


def test_token_round_trip(idp: IdentityProvider, ca: CertificateAuthority, tmp_path: Path) -> None:
    thumb = _thumb(ca, "laptop-aiko", tmp_path)
    token = idp.issue("aiko", thumb, mfa=True)
    claims = TokenVerifier(idp.public_key_pem).verify(token, thumb)
    assert claims.subject == "aiko"
    assert claims.mfa is True
    assert set(claims.groups) == {"finance", "employees"}


def test_token_is_bound_to_its_device(
    idp: IdentityProvider, ca: CertificateAuthority, tmp_path: Path
) -> None:
    issued_for = _thumb(ca, "laptop-aiko", tmp_path)
    attacker = _thumb(ca, "laptop-attacker", tmp_path)
    token = idp.issue("aiko", issued_for, mfa=True)

    verifier = TokenVerifier(idp.public_key_pem)
    with pytest.raises(AuthError, match="token_device_mismatch"):
        verifier.verify(token, attacker)


def test_expired_token_is_refused(
    idp: IdentityProvider, ca: CertificateAuthority, tmp_path: Path
) -> None:
    thumb = _thumb(ca, "laptop-aiko", tmp_path)
    token = idp.issue(
        "aiko",
        thumb,
        mfa=True,
        ttl=dt.timedelta(seconds=1),
        now=dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1),
    )
    with pytest.raises(AuthError, match="token_expired"):
        TokenVerifier(idp.public_key_pem).verify(token, thumb)


def test_token_from_another_issuer_is_refused(
    idp: IdentityProvider, ca: CertificateAuthority, tmp_path: Path
) -> None:
    thumb = _thumb(ca, "laptop-aiko", tmp_path)
    attacker = IdentityProvider()
    attacker.add_user(User("aiko", groups=["finance"], mfa_enrolled=True))
    forged = attacker.issue("aiko", thumb, mfa=True)

    with pytest.raises(AuthError, match="token_bad_signature"):
        TokenVerifier(idp.public_key_pem).verify(forged, thumb)


def test_revoked_user_gets_no_token(
    idp: IdentityProvider, ca: CertificateAuthority, tmp_path: Path
) -> None:
    thumb = _thumb(ca, "laptop-mallory", tmp_path)
    with pytest.raises(AuthError, match="revoked"):
        idp.issue("mallory", thumb)


def test_revoked_jti_is_refused(
    idp: IdentityProvider, ca: CertificateAuthority, tmp_path: Path
) -> None:
    thumb = _thumb(ca, "laptop-ben", tmp_path)
    token = idp.issue("ben", thumb)
    verifier = TokenVerifier(idp.public_key_pem)
    claims = verifier.verify(token, thumb)

    verifier.revoke(claims.jti)
    with pytest.raises(AuthError, match="token_revoked"):
        verifier.verify(token, thumb)


def test_mfa_cannot_be_claimed_without_enrolment(
    idp: IdentityProvider, ca: CertificateAuthority, tmp_path: Path
) -> None:
    thumb = _thumb(ca, "laptop-ben", tmp_path)
    with pytest.raises(AuthError, match="not enrolled"):
        idp.issue("ben", thumb, mfa=True)


def test_unknown_user_is_refused(idp: IdentityProvider) -> None:
    with pytest.raises(AuthError, match="unknown user"):
        idp.issue("nobody", "deadbeef")
