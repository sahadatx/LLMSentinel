"""Action-bound HMAC approvals for critical tool decisions.

Approval tokens are issued by a trusted human approval service. This module
only verifies them; it does not provide an approval UI or issuer endpoint.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import rfc8785

from sentinel.gateway.auth import AuthContext

_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")


def _encode(value: dict[str, Any]) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode(segment: str) -> dict[str, Any]:
    if not segment or not _SEGMENT.fullmatch(segment):
        raise ValueError("invalid token encoding")
    raw = base64.b64decode(segment + "=" * (-len(segment) % 4), altchars=b"-_", validate=True)

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON claim")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise ValueError("token segment must be a JSON object")
    return value


def _action_digest(tool: str, arguments: dict[str, Any]) -> str:
    canonical = rfc8785.dumps({"tool": tool, "arguments": arguments})
    return hashlib.sha256(canonical).hexdigest()


def issue_approval_token(
    auth: AuthContext,
    tool: str,
    arguments: dict[str, Any],
    secret: str,
    ttl_seconds: int = 60,
) -> str:
    """Create a token for an external approval service or local verification."""
    if len(secret.encode()) < 32:
        raise ValueError("approval signing secret must contain at least 32 bytes")
    now = int(time.time())
    header = _encode({"alg": "HS256", "typ": "JWT"})
    claims = _encode(
        {
            "purpose": "tool_approval",
            "tenant_id": auth.tenant_id,
            "sub": auth.subject,
            "role": auth.role,
            "tool": tool,
            "args_sha256": _action_digest(tool, arguments),
            "iat": now,
            "exp": now + max(1, min(ttl_seconds, 300)),
            "jti": secrets.token_urlsafe(18),
        }
    )
    signature = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), f"{header}.{claims}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode("ascii")
    return f"{header}.{claims}.{signature}"


class ApprovalVerifier:
    """Verify action-bound approvals and atomically reject token replay.

    SQLite is suitable for a single host and persists replay state across worker
    restarts. Multi-host deployments can use Redis with an atomic SET NX/EX.
    If the configured store is unavailable, approval verification fails closed.
    """

    def __init__(
        self,
        secret: str | None = None,
        max_lifetime_seconds: int = 300,
        replay_db_path: str | Path | None = None,
        redis_url: str | None = None,
    ):
        self.secret = secret if secret is not None else os.getenv("SENTINEL_APPROVAL_SECRET")
        self.max_lifetime_seconds = max_lifetime_seconds
        self._lock = threading.Lock()
        self._redis: Any | None = None
        self._replay_db_path: str | None = None
        selected_redis = redis_url or os.getenv("SENTINEL_APPROVAL_REPLAY_REDIS_URL")
        if selected_redis:
            parsed = urlsplit(selected_redis)
            hostname = (parsed.hostname or "").lower()
            try:
                import ipaddress

                loopback = bool(hostname) and ipaddress.ip_address(hostname).is_loopback
            except ValueError:
                loopback = hostname == "localhost"
            if parsed.scheme not in {"redis", "rediss"} or not hostname or (
                parsed.scheme == "redis" and not loopback
            ):
                raise ValueError("Approval replay Redis must use rediss:// outside loopback development")
            try:
                import redis
            except ImportError as exc:  # pragma: no cover - depends on the optional install
                raise RuntimeError("Install LLMSentinel with the 'enterprise' extra to use Redis replay storage") from exc
            self._redis = redis.Redis.from_url(
                selected_redis,
                decode_responses=True,
                socket_connect_timeout=1,
                socket_timeout=1,
                health_check_interval=30,
            )
            self.replay_backend = "redis"
        else:
            selected_path = str(
                replay_db_path
                or os.getenv("SENTINEL_APPROVAL_REPLAY_DB")
                or ".sentinel/approval-replays.sqlite3"
            )
            db_path = Path(selected_path)
            if selected_path != ":memory:":
                db_path.parent.mkdir(parents=True, exist_ok=True)
                self._replay_db_path = str(db_path)
            else:
                raise ValueError("Approval replay storage must be durable; :memory: is not supported")
            self.replay_backend = "sqlite"
            connection = sqlite3.connect(self._replay_db_path, timeout=2)
            try:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS used_approvals (jti TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)"
                )
            finally:
                connection.close()
            if db_path.exists():
                try:
                    db_path.chmod(0o600)
                except OSError:
                    pass

    def _consume_replay_id(self, token_id: str, expires_at: int, now: int) -> tuple[bool, str]:
        if self._redis is not None:
            try:
                ttl = max(1, expires_at - now)
                inserted = self._redis.set(f"llmsentinel:approval:{token_id}", "1", ex=ttl, nx=True)
            except Exception:
                return False, "approval_replay_store_unavailable"
            return (True, "approval_token_verified") if inserted else (False, "approval_token_replayed")
        if self._replay_db_path is None:
            return False, "approval_replay_store_unavailable"
        connection: sqlite3.Connection | None = None
        try:
            with self._lock:
                connection = sqlite3.connect(self._replay_db_path, timeout=2, isolation_level=None)
                connection.execute("PRAGMA busy_timeout=2000")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("DELETE FROM used_approvals WHERE expires_at <= ?", (now,))
                connection.execute(
                    "INSERT INTO used_approvals (jti, expires_at) VALUES (?, ?)",
                    (token_id, expires_at),
                )
                connection.execute("COMMIT")
        except sqlite3.IntegrityError:
            return False, "approval_token_replayed"
        except sqlite3.Error:
            return False, "approval_replay_store_unavailable"
        finally:
            if connection is not None:
                connection.close()
        return True, "approval_token_verified"

    def check_health(self) -> bool:
        try:
            if self._redis is not None:
                return bool(self._redis.ping())
            if self._replay_db_path is None:
                return False
            connection = sqlite3.connect(self._replay_db_path, timeout=1)
            try:
                return bool(connection.execute("SELECT 1").fetchone() == (1,))
            finally:
                connection.close()
        except Exception:
            return False

    def verify(
        self, token: str, auth: AuthContext, tool: str, arguments: dict[str, Any]
    ) -> tuple[bool, str]:
        if not self.secret or len(self.secret.encode()) < 32:
            return False, "approval_verifier_not_configured"
        if len(token) > 8192:
            return False, "approval_token_invalid"
        try:
            header_part, claims_part, signature_part = token.split(".")
            header = _decode(header_part)
            claims = _decode(claims_part)
            expected = base64.urlsafe_b64encode(
                hmac.new(
                    self.secret.encode(),
                    f"{header_part}.{claims_part}".encode(),
                    hashlib.sha256,
                ).digest()
            ).rstrip(b"=").decode("ascii")
            if not hmac.compare_digest(signature_part, expected):
                return False, "approval_token_invalid"
            if header.get("alg") != "HS256" or header.get("typ") != "JWT":
                return False, "approval_token_invalid"
            now = int(time.time())
            issued_at, expires_at = claims.get("iat"), claims.get("exp")
            if (
                isinstance(issued_at, bool)
                or not isinstance(issued_at, int)
                or isinstance(expires_at, bool)
                or not isinstance(expires_at, int)
                or issued_at > now
                or expires_at <= now
                or expires_at <= issued_at
                or expires_at - issued_at > self.max_lifetime_seconds
            ):
                return False, "approval_token_expired_or_invalid"
            if (
                claims.get("purpose") != "tool_approval"
                or claims.get("tenant_id") != auth.tenant_id
                or claims.get("sub") != auth.subject
                or claims.get("role") != auth.role
                or claims.get("tool") != tool
            ):
                return False, "approval_token_action_mismatch"
            try:
                action_digest = _action_digest(tool, arguments)
            except rfc8785.CanonicalizationError:
                return False, "approval_arguments_not_canonicalizable"
            if claims.get("args_sha256") != action_digest:
                return False, "approval_token_action_mismatch"
            token_id = claims.get("jti")
            if not isinstance(token_id, str) or not token_id:
                return False, "approval_token_invalid"
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError, rfc8785.CanonicalizationError):
            return False, "approval_token_invalid"

        return self._consume_replay_id(token_id, expires_at, now)
