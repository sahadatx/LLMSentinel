"""At-least-once delivery of hash-chained audit records to a configured webhook."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
from starlette.concurrency import run_in_threadpool

from sentinel.gateway.audit import HashChainAuditLog
from sentinel.gateway.control_plane import ControlPlaneStore

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuditWebhookConfig:
    url: str
    token: str | None
    retention_days: int

    @classmethod
    def from_environment(cls) -> AuditWebhookConfig | None:
        url = os.getenv("SENTINEL_SIEM_WEBHOOK_URL", "").strip()
        if not url:
            return None
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower()
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("SENTINEL_SIEM_WEBHOOK_URL contains an invalid port") from exc
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
        ):
            raise ValueError("SENTINEL_SIEM_WEBHOOK_URL must be an HTTP(S) endpoint without embedded credentials, query, or fragment")
        if parsed.scheme != "https" and not loopback:
            raise ValueError("Remote SIEM webhook endpoints must use HTTPS")
        token = os.getenv("SENTINEL_SIEM_WEBHOOK_TOKEN", "").strip() or None
        if not loopback and not token:
            raise ValueError("SENTINEL_SIEM_WEBHOOK_TOKEN is required for a remote SIEM webhook")
        try:
            retention_days = int(os.getenv("SENTINEL_SIEM_OUTBOX_RETENTION_DAYS", "30"))
        except ValueError as exc:
            raise ValueError("SENTINEL_SIEM_OUTBOX_RETENTION_DAYS must be an integer") from exc
        if not 1 <= retention_days <= 3650:
            raise ValueError("SENTINEL_SIEM_OUTBOX_RETENTION_DAYS must be from 1 through 3650")
        normalized_host = f"[{hostname}]" if ":" in hostname else hostname
        netloc = normalized_host
        if port is not None and not (
            (parsed.scheme == "http" and port == 80)
            or (parsed.scheme == "https" and port == 443)
        ):
            netloc = f"{netloc}:{port}"
        normalized = f"{parsed.scheme}://{netloc}{parsed.path or '/'}"
        return cls(normalized, token, retention_days)


class AuditWebhookDispatcher:
    """Reconcile the local hash chain into SQLite, then retry webhook batches in order."""

    def __init__(self, audit: HashChainAuditLog, store: ControlPlaneStore, config: AuditWebhookConfig) -> None:
        self.audit = audit
        self.store = store
        self.config = config
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            follow_redirects=False,
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
        )

    async def run(self) -> None:
        next_prune = 0.0
        while True:
            inflight_hashes: list[str] = []
            try:
                if asyncio.get_running_loop().time() >= next_prune:
                    await run_in_threadpool(self.store.prune_audit_outbox, self.config.retention_days)
                    next_prune = asyncio.get_running_loop().time() + 86400
                cursor = await run_in_threadpool(self.store.get_audit_export_cursor)
                export = await run_in_threadpool(self.audit.export_after, cursor, 1000)
                if export["events"]:
                    await run_in_threadpool(
                        self.store.enqueue_audit_export,
                        export["events"],
                        export["next_cursor"],
                    )

                events, retry_after = await run_in_threadpool(self.store.pending_audit_export, 100)
                if not events:
                    await asyncio.sleep(max(0.5, min(retry_after, 30.0)))
                    continue

                inflight_hashes = [str(event["hash"]) for event in events]
                idempotency_key = hashlib.sha256("\n".join(inflight_hashes).encode()).hexdigest()
                headers = {
                    "Content-Type": "application/json",
                    "Idempotency-Key": idempotency_key,
                }
                if self.config.token:
                    headers["Authorization"] = f"Bearer {self.config.token}"
                request = self.client.build_request(
                    "POST",
                    self.config.url,
                    json={
                        "source": "llmsentinel",
                        "events": events,
                        "next_cursor": inflight_hashes[-1],
                    },
                    headers=headers,
                )
                response = await self.client.send(request, stream=True)
                try:
                    response.raise_for_status()
                finally:
                    await response.aclose()
                await run_in_threadpool(
                    self.store.mark_audit_export_attempt,
                    inflight_hashes,
                    None,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if inflight_hashes:
                    try:
                        await run_in_threadpool(
                            self.store.mark_audit_export_attempt,
                            inflight_hashes,
                            type(exc).__name__,
                        )
                    except Exception:
                        logger.exception("Audit export retry state could not be persisted")
                logger.warning("Audit webhook delivery attempt failed (%s)", type(exc).__name__)
                await asyncio.sleep(1.0)

    async def close(self) -> None:
        await self.client.aclose()

