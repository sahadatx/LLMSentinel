"""Small HS256 JWT verifier used to derive trusted tenant and role context.

This intentionally supports only HS256. Production deployments should manage the
signing key through a secret manager and rotate it; never trust tenant IDs from a
prompt, query parameter, or tool argument.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


class AuthenticationError(ValueError):
    pass


_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
MAX_TOKEN_LIFETIME_SECONDS = 24 * 60 * 60
CLOCK_SKEW_SECONDS = 60


def _decode_segment(segment: str) -> dict[str, object]:
    if not segment or not _SEGMENT.fullmatch(segment):
        raise ValueError("invalid token encoding")
    decoded = base64.b64decode(
        segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True
    )

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JWT claim")
            result[key] = value
        return result

    value = json.loads(decoded, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError("JWT segment must be a JSON object")
    return value


@dataclass(frozen=True)
class AuthContext:
    tenant_id: str
    role: str = "user"
    subject: str = "anonymous"
    authenticated: bool = False
    principal: str | None = None

    @property
    def principal_id(self) -> str:
        """Stable human/service principal behind a bearer token or API key."""
        return self.principal or self.subject


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def issue_local_token(tenant_id: str, role: str = "user", secret: str | None = None) -> str:
    """Create a short lived token for local demos only."""
    secret_value = secret if secret is not None else os.getenv("SENTINEL_JWT_SECRET")
    if not secret_value:
        raise ValueError("provide a signing secret explicitly or set SENTINEL_JWT_SECRET")
    key = secret_value.encode()
    if len(key) < 32:
        raise ValueError("JWT signing secret must contain at least 32 bytes")
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(
        json.dumps({"tenant_id": tenant_id, "role": role, "sub": "local-demo", "iat": now, "exp": now + 3600}, separators=(",", ":")).encode()
    )
    signature = _b64url(hmac.new(key, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def verify_bearer(
    token: str,
    secret: str | None = None,
    expected_issuer: str | None = None,
    expected_audience: str | None = None,
) -> AuthContext:
    if len(token) > 8192:
        raise AuthenticationError("Bearer token is too large")
    try:
        header_part, payload_part, signature_part = token.split(".")
        header = _decode_segment(header_part)
        claims = _decode_segment(payload_part)
    except (ValueError, binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AuthenticationError("Malformed bearer token") from exc
    if header.get("alg") != "HS256":
        raise AuthenticationError("Only HS256 bearer tokens are accepted")
    secret_value = secret if secret is not None else os.getenv("SENTINEL_JWT_SECRET")
    if not secret_value:
        raise AuthenticationError("JWT signing secret is not configured")
    if len(secret_value.encode()) < 32:
        raise AuthenticationError("JWT signing secret must contain at least 32 bytes")
    if not _SEGMENT.fullmatch(signature_part):
        raise AuthenticationError("Malformed bearer token signature")
    key = secret_value.encode()
    expected = _b64url(hmac.new(key, f"{header_part}.{payload_part}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(signature_part, expected):
        raise AuthenticationError("Invalid bearer token signature")
    expires_at = claims.get("exp")
    not_before = claims.get("nbf", 0)
    issued_at = claims.get("iat")
    if (
        isinstance(expires_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(not_before, bool)
        or not isinstance(not_before, int)
        or isinstance(issued_at, bool)
        or not isinstance(issued_at, int)
    ):
        raise AuthenticationError("Bearer token has invalid time claims")
    now = int(time.time())
    if issued_at > now + CLOCK_SKEW_SECONDS or expires_at <= issued_at or expires_at - issued_at > MAX_TOKEN_LIFETIME_SECONDS:
        raise AuthenticationError("Bearer token lifetime is invalid")
    if expires_at <= now:
        raise AuthenticationError("Bearer token has expired")
    if not_before > now + CLOCK_SKEW_SECONDS:
        raise AuthenticationError("Bearer token is not active yet")
    if expected_issuer and claims.get("iss") != expected_issuer:
        raise AuthenticationError("Bearer token issuer is not trusted")
    if expected_audience:
        audience = claims.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        if expected_audience not in audiences:
            raise AuthenticationError("Bearer token audience is not trusted")
    tenant_id = claims.get("tenant_id")
    if (
        not isinstance(tenant_id, str)
        or not tenant_id.strip()
        or len(tenant_id) > 256
        or any(ord(char) < 32 for char in tenant_id)
    ):
        raise AuthenticationError("Bearer token has no tenant_id")
    role = claims.get("role", "user")
    subject = claims.get("sub", "")
    if not isinstance(role, str) or not role or len(role) > 64:
        raise AuthenticationError("Bearer token has an invalid role")
    if not isinstance(subject, str) or len(subject) > 256:
        raise AuthenticationError("Bearer token has an invalid subject")
    return AuthContext(tenant_id=tenant_id, role=role, subject=subject, authenticated=True)


class OIDCVerifier:
    """Verify an IdP-issued JWT using a cached JWKS signing key.

    The issuer, audience, key set URL, and claim names are operator supplied.
    The caller never supplies the tenant or role independently of this token.
    PyJWT is an optional dependency so the local mock remains dependency-light.
    """

    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_url: str,
        tenant_claim: str = "tenant_id",
        role_claim: str = "role",
        role_mappings: dict[str, list[str]] | None = None,
        algorithms: tuple[str, ...] = ("RS256", "ES256"),
        max_lifetime_seconds: int = MAX_TOKEN_LIFETIME_SECONDS,
    ) -> None:
        parsed = urlsplit(jwks_url)
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("OIDC JWKS URL has an invalid port") from exc
        hostname = (parsed.hostname or "").lower()
        try:
            loopback = bool(hostname) and ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            loopback = hostname == "localhost"
        if (
            parsed.scheme not in {"http", "https"}
            or not hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or (parsed.scheme != "https" and not loopback)
            or not algorithms
            or any(algorithm not in {"RS256", "ES256", "EdDSA"} for algorithm in algorithms)
        ):
            raise ValueError("OIDC requires a valid HTTPS JWKS URL and supported asymmetric algorithms")
        if not issuer or not audience or not tenant_claim or not role_claim:
            raise ValueError("OIDC issuer, audience, tenant claim, and role claim must be configured")
        if not 60 <= max_lifetime_seconds <= MAX_TOKEN_LIFETIME_SECONDS:
            raise ValueError("OIDC maximum token lifetime must be from 60 seconds through 24 hours")
        try:
            import jwt
        except ImportError as exc:  # pragma: no cover - depends on the optional install
            raise RuntimeError("Install LLMSentinel with the 'enterprise' extra to enable OIDC") from exc

        self._jwt: Any = jwt
        self._jwks = jwt.PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=300, timeout=3)
        self.issuer = issuer
        self.audience = audience
        self.tenant_claim = tenant_claim
        self.role_claim = role_claim
        self.role_mappings = role_mappings or {}
        self.algorithms = algorithms
        self.max_lifetime_seconds = max_lifetime_seconds

    def verify(self, token: str) -> AuthContext:
        if not token or len(token) > 16_384:
            raise AuthenticationError("Bearer token is empty or too large")
        try:
            signing_key = self._jwks.get_signing_key_from_jwt(token)
            claims = self._jwt.decode(
                token,
                signing_key.key,
                algorithms=list(self.algorithms),
                audience=self.audience,
                issuer=self.issuer,
                leeway=CLOCK_SKEW_SECONDS,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except Exception as exc:  # PyJWT and JWKS transport errors share a deny path.
            raise AuthenticationError("Bearer token could not be verified by the configured identity provider") from exc

        issued_at = claims.get("iat")
        expires_at = claims.get("exp")
        now = int(time.time())
        if (
            isinstance(issued_at, bool)
            or not isinstance(issued_at, int)
            or isinstance(expires_at, bool)
            or not isinstance(expires_at, int)
            or issued_at > now + CLOCK_SKEW_SECONDS
            or expires_at <= issued_at
            or expires_at - issued_at > self.max_lifetime_seconds
        ):
            raise AuthenticationError("Bearer token lifetime is invalid")

        tenant_id = claims.get(self.tenant_claim)
        subject = claims.get("sub")
        raw_role = claims.get(self.role_claim)
        if (
            not isinstance(tenant_id, str)
            or not tenant_id.strip()
            or len(tenant_id) > 256
            or any(ord(char) < 32 for char in tenant_id)
        ):
            raise AuthenticationError("Bearer token has no valid tenant claim")
        if (
            not isinstance(subject, str)
            or not subject.strip()
            or len(subject) > 256
            or any(ord(char) < 32 for char in subject)
        ):
            raise AuthenticationError("Bearer token has no valid subject")
        role: str | None = None
        if isinstance(raw_role, str):
            role = raw_role
        elif isinstance(raw_role, list) and all(isinstance(item, str) for item in raw_role):
            caller_roles = set(raw_role)
            # Prefer the explicitly configured platform-wide role when an IdP
            # user belongs to both a tenant-admin and platform-admin group.
            mapped_roles = sorted(
                self.role_mappings.items(),
                key=lambda item: (item[0] != "platform_admin", item[0]),
            )
            role = next(
                (
                    mapped_role
                    for mapped_role, groups in mapped_roles
                    if caller_roles.intersection(groups)
                ),
                None,
            )
        if not role or len(role) > 64:
            raise AuthenticationError("Bearer token has no role accepted by the configured mapping")
        return AuthContext(tenant_id=tenant_id, role=role, subject=subject, authenticated=True)
