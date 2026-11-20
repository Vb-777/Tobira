"""Identity provider: users, groups, MFA, and certificate-bound access tokens.

Tokens are short-lived JWTs signed with Ed25519. Each token carries a ``cnf``
confirmation claim holding the SHA-256 thumbprint of the device certificate it
was issued to (the pattern from RFC 8705 / RFC 7800). The broker checks that the
thumbprint matches the certificate presented on the TLS connection, so a token
copied off one laptop is useless on another.
"""

from __future__ import annotations

import datetime as dt
import secrets
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jwt
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ISSUER = "tobira-idp"
AUDIENCE = "tobira-broker"
ALGORITHM = "EdDSA"
DEFAULT_TTL = dt.timedelta(minutes=15)


class AuthError(Exception):
    """Raised when a credential cannot be issued or verified."""


@dataclass(slots=True)
class User:
    username: str
    groups: list[str] = field(default_factory=list)
    mfa_enrolled: bool = False
    status: str = "active"  # active | suspended | revoked
    display_name: str = ""

    @property
    def active(self) -> bool:
        return self.status == "active"


@dataclass(slots=True)
class TokenClaims:
    """Verified token contents."""

    subject: str
    groups: list[str]
    device_thumbprint: str
    mfa: bool
    jti: str
    issued_at: dt.datetime
    expires_at: dt.datetime
    raw: dict[str, Any]


class IdentityProvider:
    """Issues and verifies access tokens for enrolled users.

    The signing key never leaves this object; the broker is given only the public
    key, which keeps token *minting* and token *acceptance* separate the way a
    real IdP and a real policy enforcement point are separate.
    """

    def __init__(self, users: dict[str, User] | None = None) -> None:
        self._users: dict[str, User] = users or {}
        self._signing_key = ed25519.Ed25519PrivateKey.generate()
        self._revoked_jti: set[str] = set()

    # ------------------------------------------------------------- user store

    @classmethod
    def from_yaml(cls, path: str | Path) -> IdentityProvider:
        doc = yaml.safe_load(Path(path).read_text()) or {}
        users: dict[str, User] = {}
        for entry in doc.get("users", []):
            user = User(
                username=entry["username"],
                groups=list(entry.get("groups", [])),
                mfa_enrolled=bool(entry.get("mfa", False)),
                status=entry.get("status", "active"),
                display_name=entry.get("display_name", ""),
            )
            users[user.username] = user
        return cls(users)

    def add_user(self, user: User) -> None:
        self._users[user.username] = user

    def get(self, username: str) -> User | None:
        return self._users.get(username)

    @property
    def users(self) -> dict[str, User]:
        return dict(self._users)

    def set_status(self, username: str, status: str) -> None:
        user = self._users.get(username)
        if user is None:
            raise AuthError(f"unknown user {username!r}")
        user.status = status

    # ---------------------------------------------------------------- signing

    @property
    def public_key_pem(self) -> bytes:
        return self._signing_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def issue(
        self,
        username: str,
        device_thumbprint: str,
        *,
        mfa: bool = False,
        ttl: dt.timedelta = DEFAULT_TTL,
        now: dt.datetime | None = None,
    ) -> str:
        user = self._users.get(username)
        if user is None:
            raise AuthError(f"unknown user {username!r}")
        if not user.active:
            raise AuthError(f"user {username!r} is {user.status}")
        if mfa and not user.mfa_enrolled:
            raise AuthError(f"user {username!r} is not enrolled for MFA")

        issued = now or dt.datetime.now(dt.timezone.utc)
        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": user.username,
            "iat": int(issued.timestamp()),
            "nbf": int(issued.timestamp()),
            "exp": int((issued + ttl).timestamp()),
            "jti": uuid.uuid4().hex,
            "groups": list(user.groups),
            "amr": ["pwd", "mfa"] if mfa else ["pwd"],
            # RFC 7800 proof-of-possession: this token is only valid on the
            # device whose client certificate hashes to this value.
            "cnf": {"x5t#S256": device_thumbprint},
        }
        return jwt.encode(claims, self._signing_key, algorithm=ALGORITHM)

    def revoke_token(self, token: str) -> None:
        """Add a token's ``jti`` to the deny list without verifying expiry."""
        claims = jwt.decode(token, options={"verify_signature": False})
        self._revoked_jti.add(claims.get("jti", ""))

    @property
    def revoked_jti(self) -> set[str]:
        return set(self._revoked_jti)


class TokenVerifier:
    """The broker side: validates a token and binds it to the TLS peer."""

    def __init__(
        self,
        public_key_pem: bytes,
        *,
        revoked_jti: set[str] | None = None,
        leeway: int = 5,
    ) -> None:
        self._public_key = serialization.load_pem_public_key(public_key_pem)
        self._revoked = revoked_jti if revoked_jti is not None else set()
        self._leeway = leeway

    def revoke(self, jti: str) -> None:
        self._revoked.add(jti)

    def verify(self, token: str, device_thumbprint: str) -> TokenClaims:
        """Verify signature, lifetime, audience and device binding.

        Raises :class:`AuthError` with a short machine-readable reason, which is
        what ends up in the SIEM event.
        """
        try:
            claims = jwt.decode(
                token,
                self._public_key,
                algorithms=[ALGORITHM],
                audience=AUDIENCE,
                issuer=ISSUER,
                leeway=self._leeway,
                options={"require": ["exp", "iat", "sub", "jti", "aud", "iss"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("token_expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise AuthError("token_wrong_audience") from exc
        except jwt.InvalidIssuerError as exc:
            raise AuthError("token_wrong_issuer") from exc
        except jwt.InvalidSignatureError as exc:
            raise AuthError("token_bad_signature") from exc
        except jwt.InvalidTokenError as exc:
            raise AuthError("token_invalid") from exc

        jti = claims.get("jti", "")
        if jti in self._revoked:
            raise AuthError("token_revoked")

        bound = (claims.get("cnf") or {}).get("x5t#S256")
        if not bound:
            raise AuthError("token_not_device_bound")
        if not secrets.compare_digest(str(bound), device_thumbprint):
            # The token is cryptographically valid but was minted for a
            # different device: this is a replay from stolen credentials.
            raise AuthError("token_device_mismatch")

        return TokenClaims(
            subject=claims["sub"],
            groups=list(claims.get("groups", [])),
            device_thumbprint=str(bound),
            mfa="mfa" in claims.get("amr", []),
            jti=jti,
            issued_at=dt.datetime.fromtimestamp(claims["iat"], dt.timezone.utc),
            expires_at=dt.datetime.fromtimestamp(claims["exp"], dt.timezone.utc),
            raw=claims,
        )
