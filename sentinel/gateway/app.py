"""FastAPI gateway with mock chat, policy-gated tool calls and telemetry."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import ipaddress
import json
import math
import os
import sqlite3
import tempfile
import threading
import time
import uuid
import copy
import datetime as dt
from collections import OrderedDict, deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Literal, NoReturn, cast
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.responses import StreamingResponse

from sentinel.gateway.approvals import ApprovalVerifier
from sentinel.gateway.audit import HashChainAuditLog
from sentinel.gateway.audit_delivery import AuditWebhookConfig, AuditWebhookDispatcher
from sentinel.gateway.auth import AuthContext, AuthenticationError, OIDCVerifier, verify_bearer
from sentinel.gateway.control_plane import ControlPlaneStore, canonical_digest
from sentinel.gateway.mcp import call_mcp_tool, load_tool_endpoints, load_tool_tokens
from sentinel.gateway.pipeline import SecurityPipeline
from sentinel.gateway.policy import DEFAULT_POLICY_PATH, load_policy, policy_signature_path, validate_policy, verify_policy_signature_record
from sentinel.gateway.rag import ChromaRAGAdapter
from sentinel.gateway.resilience import CircuitBreaker
from sentinel.gateway.telemetry import OpenTelemetryRuntime
from sentinel.gateway.streaming import sanitize_openai_sse
from sentinel.reporting.formats import json_report, markdown_report, sarif_report
from sentinel.reporting.pdf import pdf_report
from sentinel.scanner.model_artifacts import scan_model_path
from sentinel.scanner.source import scan_path

DEFAULT_CORS_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
)
MAX_REQUEST_JSON_NODES = 20_000
MAX_OUTPUT_JSON_NODES = 100_000
MAX_JSON_NESTING = 64
MAX_SCAN_REQUEST_BYTES = 12 * 1024 * 1024
MAX_SCAN_TOTAL_BYTES = 8 * 1024 * 1024
MAX_SCAN_FILE_BYTES = 2 * 1024 * 1024
MAX_SCAN_FILES = 50
MAX_SCAN_FINDINGS = 1_000
MAX_TENANT_METRIC_KEYS = 256
MAX_METRIC_SAMPLES_PER_SERIES = 1_000


def _runtime_policy_static_projection(candidate: dict[str, Any]) -> dict[str, Any]:
    """Remove only fields the input-policy regression corpus can actually exercise."""
    static = copy.deepcopy(candidate)
    for field in ("name", "description", "revision"):
        static.pop(field, None)
    layers = static.get("layers")
    if isinstance(layers, dict):
        layers.pop("l1", None)
        layers.pop("l2", None)
    return static


def _cors_origins() -> list[str]:
    configured = os.getenv("SENTINEL_CORS_ORIGINS", "")
    if not configured.strip():
        return list(DEFAULT_CORS_ORIGINS)
    raw_origins = [origin.strip().rstrip("/") for origin in configured.split(",")]
    raw_origins = [origin for origin in raw_origins if origin]
    if not raw_origins or len(raw_origins) > 100:
        raise ValueError("SENTINEL_CORS_ORIGINS must contain 1 to 100 explicit origins")

    origins: list[str] = []
    for origin in raw_origins:
        parsed = urlsplit(origin)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("SENTINEL_CORS_ORIGINS contains an invalid port") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
            or "?" in origin
            or "#" in origin
            or "*" in origin
        ):
            raise ValueError(
                "SENTINEL_CORS_ORIGINS must contain exact HTTP(S) origins without paths"
            )
        hostname = parsed.hostname.lower()
        try:
            is_loopback = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            is_loopback = hostname == "localhost"
            hostname = hostname.encode("idna").decode("ascii")
        if parsed.scheme == "http" and not is_loopback:
            raise ValueError("Non-loopback SENTINEL_CORS_ORIGINS must use HTTPS")
        netloc = f"[{hostname}]" if ":" in hostname else hostname
        if port is not None and not (
            (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)
        ):
            netloc = f"{netloc}:{port}"
        origins.append(f"{parsed.scheme}://{netloc}")
    return list(dict.fromkeys(origins))


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    messages: list[dict[str, Any]] = Field(min_length=1)
    model: str = "sentinel-mock"


class ToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class RAGQueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=16_000)
    top_k: int = Field(default=5, ge=1, le=20)


class ScanInputFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=256)
    content_base64: str = Field(min_length=1, max_length=11_200_000)


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    files: list[ScanInputFile] = Field(min_length=1, max_length=MAX_SCAN_FILES)


class PolicyStageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy: dict[str, Any]
    signature: dict[str, Any] | None = None


class IncidentCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=3, max_length=200)
    summary: str = Field(default="", max_length=4000)
    severity: Literal["critical", "high", "medium", "low"] = "medium"


class IncidentUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "triaged", "contained", "resolved", "false_positive"]
    assignee: str | None = Field(default=None, max_length=256)
    comment: str | None = Field(default=None, max_length=2000)


class EvaluationSampleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=96)
    category: str = Field(min_length=1, max_length=96)
    prompt: str = Field(min_length=1, max_length=16_000)
    expected_disposition: Literal["allow", "block"]
    attack_family: str = Field(min_length=1, max_length=96)
    technique: str = Field(min_length=1, max_length=96)
    language: str = Field(min_length=2, max_length=16)
    source: str = Field(min_length=1, max_length=200)
    split: Literal["train", "validation", "holdout"] = "train"
    label_version: str = Field(default="2.0", min_length=1, max_length=16)


class EvaluationReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: str = Field(min_length=1, max_length=96)
    expected_disposition: Literal["allow", "block"]
    attack_family: str = Field(min_length=1, max_length=96)
    technique: str = Field(min_length=1, max_length=96)
    language: str = Field(min_length=2, max_length=16)


class EvaluationRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    split: Literal["train", "validation", "holdout"] = "validation"
    reviewed_only: bool = False


class APIKeyCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=100)
    tenant_id: str | None = Field(default=None, max_length=256)
    role: Literal["user", "analyst", "admin"] = "user"
    expires_in_days: int = Field(default=90, ge=1, le=365)


class RequestBodySizeLimit:
    """Bound request bytes including chunked bodies before JSON parsing."""

    def __init__(self, app: Any, max_bytes: int, path_limits: dict[str, int] | None = None):
        self.app = app
        self.max_bytes = max_bytes
        self.path_limits = path_limits or {}

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        max_bytes = self.path_limits.get(scope.get("path", ""), self.max_bytes)
        chunks: list[dict[str, Any]] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunks.append(message)
            total += len(message.get("body", b""))
            if total > max_bytes:
                payload = b'{"detail":"Request body exceeds configured byte limit"}'
                await send(
                    {
                        "type": "http.response.start",
                        "status": 413,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", str(len(payload)).encode()),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": payload})
                return
            if not message.get("more_body", False):
                break
        index = 0

        async def replay() -> dict[str, Any]:
            nonlocal index
            if index < len(chunks):
                message = chunks[index]
                index += 1
                return message
            return cast(dict[str, Any], await receive())

        await self.app(scope, replay, send)


def _strings_in(value: Any) -> list[str]:
    strings: list[str] = []
    pending: list[tuple[Any, int]] = [(value, 0)]
    visited = 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if visited > MAX_REQUEST_JSON_NODES or depth > MAX_JSON_NESTING:
            raise HTTPException(status_code=413, detail="Request JSON exceeds the configured complexity limit")
        if isinstance(item, str):
            strings.append(item)
        elif isinstance(item, dict):
            children: list[tuple[Any, int]] = []
            for key, child in item.items():
                if isinstance(key, str):
                    children.append((key, depth + 1))
                children.append((child, depth + 1))
            pending.extend(reversed(children))
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in reversed(item))
    return strings


def _sanitize_message(value: Any, pipeline: SecurityPipeline) -> tuple[Any, list[str]]:
    labels: list[str] = []
    if isinstance(value, str):
        clean, found = pipeline.sanitize_output(value)
        return clean, found
    if not isinstance(value, (list, dict)):
        return value, labels

    root: Any = [] if isinstance(value, list) else {}
    pending: list[tuple[Any, Any, int]] = [(value, root, 0)]
    visited = 1
    while pending:
        source, destination, depth = pending.pop()
        if depth > MAX_JSON_NESTING:
            raise ValueError("Upstream response JSON exceeds the nesting safety limit")
        if isinstance(source, dict):
            for key, item in source.items():
                visited += 2
                if visited > MAX_OUTPUT_JSON_NODES:
                    raise ValueError("Upstream response JSON exceeds the node safety limit")
                safe_key, key_labels = pipeline.sanitize_output(key)
                labels.extend(key_labels)
                if safe_key in destination:
                    raise ValueError("Output sanitization caused a JSON object key collision")
                if isinstance(item, str):
                    safe, found = pipeline.sanitize_output(item)
                    destination[safe_key] = safe
                    labels.extend(found)
                elif isinstance(item, (dict, list)):
                    child: Any = [] if isinstance(item, list) else {}
                    destination[safe_key] = child
                    pending.append((item, child, depth + 1))
                else:
                    destination[safe_key] = item
        else:
            for item in source:
                visited += 1
                if visited > MAX_OUTPUT_JSON_NODES:
                    raise ValueError("Upstream response JSON exceeds the node safety limit")
                if isinstance(item, str):
                    safe, found = pipeline.sanitize_output(item)
                    destination.append(safe)
                    labels.extend(found)
                elif isinstance(item, (dict, list)):
                    child = [] if isinstance(item, list) else {}
                    destination.append(child)
                    pending.append((item, child, depth + 1))
                else:
                    destination.append(item)
    return root, labels


def create_app(
    policy_path: str | None = None,
    upstream_url: str | None = None,
    audit_path: str | Path | None = None,
) -> FastAPI:
    policy = load_policy(policy_path)
    auth_settings = policy.get("auth", {})
    oidc_verifier: OIDCVerifier | None = None
    auth_mode = str(auth_settings.get("mode", "hs256"))
    if auth_settings.get("require_auth", False) and auth_mode == "hs256":
        secret_name = str(auth_settings.get("secret_env", "SENTINEL_JWT_SECRET"))
        jwt_secret = os.getenv(secret_name)
        if not jwt_secret or len(jwt_secret.encode()) < 32:
            raise ValueError(f"Required JWT secret {secret_name} must be configured with at least 32 bytes before startup")
    if auth_settings.get("require_auth", False) and auth_mode == "oidc":
        jwks_url = os.getenv(str(auth_settings["jwks_url_env"]))
        issuer = os.getenv(str(auth_settings["issuer_env"]))
        audience = os.getenv(str(auth_settings["audience_env"]))
        if not jwks_url or not issuer or not audience:
            raise ValueError("OIDC JWKS URL, issuer, and audience environment values are required before startup")
        mappings = auth_settings.get("role_mappings", {})
        oidc_verifier = OIDCVerifier(
            issuer=issuer,
            audience=audience,
            jwks_url=jwks_url,
            tenant_claim=str(auth_settings.get("tenant_claim", "tenant_id")),
            role_claim=str(auth_settings.get("role_claim", "role")),
            role_mappings=mappings if isinstance(mappings, dict) else {},
            algorithms=tuple(auth_settings.get("algorithms", ["RS256", "ES256"])),
        )
    approval_secret_env = str(
        policy.get("approval", {}).get("secret_env", "SENTINEL_APPROVAL_SECRET")
    )
    rate_limit_redis_url = os.getenv("SENTINEL_RATE_LIMIT_REDIS_URL")
    if policy.get("limits", {}).get("require_shared_rate_limit", False) and not rate_limit_redis_url:
        raise ValueError("SENTINEL_RATE_LIMIT_REDIS_URL is required by this policy")
    if policy.get("approval", {}).get("require_shared_replay", False) and not os.getenv("SENTINEL_APPROVAL_REPLAY_REDIS_URL"):
        raise ValueError("SENTINEL_APPROVAL_REPLAY_REDIS_URL is required by this policy")
    approval_verifier = ApprovalVerifier(
        os.getenv(approval_secret_env),
        replay_db_path=os.getenv("SENTINEL_APPROVAL_REPLAY_DB"),
        redis_url=os.getenv("SENTINEL_APPROVAL_REPLAY_REDIS_URL"),
    )
    pipeline = SecurityPipeline(policy, approval_verifier, rate_limit_redis_url)
    if policy.get("limits", {}).get("require_shared_rate_limit", False) and not pipeline.bucket.check_health():
        raise RuntimeError("Shared Redis rate-limit store is unavailable")
    if policy.get("approval", {}).get("require_shared_replay", False) and not approval_verifier.check_health():
        raise RuntimeError("Shared Redis approval replay store is unavailable")
    allowlisted_tools = set(policy.get("tools", {}).get("allow", []))
    mcp_endpoints = load_tool_endpoints(
        os.getenv("SENTINEL_MCP_TOOL_ENDPOINTS", ""), allowlisted_tools
    )
    mcp_tokens = load_tool_tokens(os.getenv("SENTINEL_MCP_TOOL_TOKENS", ""))
    if set(mcp_tokens) - set(mcp_endpoints):
        raise ValueError("SENTINEL_MCP_TOOL_TOKENS contains tools without configured endpoints")
    for tool, endpoint in mcp_endpoints.items():
        endpoint_host = (urlsplit(endpoint).hostname or "").lower()
        try:
            endpoint_is_loopback = bool(endpoint_host) and ipaddress.ip_address(endpoint_host).is_loopback
        except ValueError:
            endpoint_is_loopback = endpoint_host == "localhost"
        if not endpoint_is_loopback and not mcp_tokens.get(tool):
            raise ValueError(f"A dedicated SENTINEL_MCP_TOOL_TOKENS entry is required for external tool {tool}")
    breaker_threshold = int(policy["limits"].get("circuit_breaker_failures", 5))
    breaker_reset_seconds = float(policy["limits"].get("circuit_breaker_reset_seconds", 15))
    model_breaker = CircuitBreaker(breaker_threshold, breaker_reset_seconds)
    rag_breaker = CircuitBreaker(breaker_threshold, breaker_reset_seconds)
    mcp_breakers = {
        tool: CircuitBreaker(breaker_threshold, breaker_reset_seconds) for tool in mcp_endpoints
    }
    rag_adapter: ChromaRAGAdapter | None = None
    if os.getenv("SENTINEL_CHROMA_URL", "").strip():
        rag_adapter = ChromaRAGAdapter()
    telemetry = OpenTelemetryRuntime()
    audit = HashChainAuditLog(
        audit_path or os.getenv("SENTINEL_AUDIT_PATH") or ".sentinel/audit.jsonl"
    )
    control_store = ControlPlaneStore()
    audit_webhook_config = AuditWebhookConfig.from_environment()
    deployment_policy = copy.deepcopy(policy)
    active_policy = control_store.get_active_policy()
    if active_policy is not None:
        candidate = active_policy["policy"]
        if canonical_digest(candidate) != active_policy["sha256"]:
            raise RuntimeError("Persisted active policy digest does not match its policy body")
        deployed_static = _runtime_policy_static_projection(deployment_policy)
        candidate_static = _runtime_policy_static_projection(candidate)
        if candidate_static == deployed_static:
            validate_policy(candidate)
            integrity = candidate.get("integrity", {})
            signature = active_policy.get("signature")
            if integrity.get("require_signature", False) or signature is not None:
                key_name = str(integrity.get("verification_key_env", integrity.get("signature_env", "SENTINEL_POLICY_VERIFY_KEY")))
                valid, reason = verify_policy_signature_record(candidate, signature, os.getenv(key_name, ""))
                if not valid:
                    raise RuntimeError(f"Persisted active policy signature is invalid: {reason}")
            policy = candidate
            pipeline.replace_runtime_policy(policy)
    selected_policy_path = Path(policy_path) if policy_path else DEFAULT_POLICY_PATH
    deployed_signature: dict[str, Any] | None = None
    try:
        signature_value = json.loads(policy_signature_path(selected_policy_path).read_text(encoding="utf-8"))
        if isinstance(signature_value, dict) and signature_value.get("policy_sha256") == canonical_digest(policy):
            integrity = policy.get("integrity", {})
            key_name = str(integrity.get("verification_key_env", integrity.get("signature_env", "SENTINEL_POLICY_VERIFY_KEY")))
            signature_valid, _ = verify_policy_signature_record(policy, signature_value, os.getenv(key_name, ""))
            if signature_valid:
                deployed_signature = signature_value
    except (OSError, json.JSONDecodeError):
        pass
    control_store.ensure_active_policy(policy, deployed_signature)
    if control_store.sample_count() == 0:
        seed_path = Path(
            os.getenv(
                "SENTINEL_EVAL_DATASET_PATH",
                str(Path(__file__).resolve().parents[2] / "benchmarks" / "dataset_v1.jsonl"),
            )
        )
        if seed_path.is_file():
            seed_rows = [
                json.loads(line)
                for line in seed_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            control_store.seed_samples(seed_rows)
    timings: deque[float] = deque(maxlen=5000)
    overhead_timings: deque[float] = deque(maxlen=5000)
    upstream_timings: deque[float] = deque(maxlen=5000)
    tool_timings: deque[float] = deque(maxlen=5000)
    tenant_counts: dict[str, dict[str, int]] = {}
    tenant_timings: dict[str, dict[str, deque[float]]] = {}
    tenant_metric_lru: OrderedDict[str, None] = OrderedDict()
    counts = {
        "requests": 0,
        "blocked": 0,
        "policy_denials": 0,
        "rate_limited": 0,
        "redactions": 0,
        "tool_calls": 0,
        "upstream_errors": 0,
        "circuit_open": 0,
    }
    metrics_lock = threading.Lock()

    def touch_tenant_metrics(tenant_id: str) -> None:
        tenant_metric_lru.pop(tenant_id, None)
        tenant_metric_lru[tenant_id] = None
        while len(tenant_metric_lru) > MAX_TENANT_METRIC_KEYS:
            expired_tenant, _ = tenant_metric_lru.popitem(last=False)
            tenant_counts.pop(expired_tenant, None)
            tenant_timings.pop(expired_tenant, None)

    def increment_metric(name: str, amount: int = 1, tenant_id: str | None = None) -> None:
        with metrics_lock:
            counts[name] += amount
            if tenant_id is not None:
                touch_tenant_metrics(tenant_id)
                scoped = tenant_counts.setdefault(tenant_id, {name: 0 for name in counts})
                scoped[name] += amount

    def record_denial(rate_limited: bool = False, tenant_id: str | None = None) -> None:
        with metrics_lock:
            counts["blocked"] += 1
            denial_name = "rate_limited" if rate_limited else "policy_denials"
            counts[denial_name] += 1
            if tenant_id is not None:
                touch_tenant_metrics(tenant_id)
                scoped = tenant_counts.setdefault(tenant_id, {name: 0 for name in counts})
                scoped["blocked"] += 1
                scoped[denial_name] += 1

    def record_latency(elapsed_ms: float, tenant_id: str | None = None) -> None:
        with metrics_lock:
            timings.append(elapsed_ms)
            if tenant_id is not None:
                touch_tenant_metrics(tenant_id)
                scoped = tenant_timings.setdefault(tenant_id, {})
                scoped.setdefault("latency", deque(maxlen=MAX_METRIC_SAMPLES_PER_SERIES)).append(elapsed_ms)

    def record_stage_latency(
        stage: str, samples: deque[float], elapsed_ms: float, tenant_id: str | None = None
    ) -> None:
        with metrics_lock:
            bounded_elapsed = max(0.0, elapsed_ms)
            samples.append(bounded_elapsed)
            if tenant_id is not None:
                touch_tenant_metrics(tenant_id)
                scoped = tenant_timings.setdefault(tenant_id, {})
                scoped.setdefault(stage, deque(maxlen=MAX_METRIC_SAMPLES_PER_SERIES)).append(bounded_elapsed)
    upstream_url = upstream_url or os.getenv("SENTINEL_UPSTREAM_URL")
    if upstream_url:
        try:
            parsed_upstream = urlsplit(upstream_url)
            if parsed_upstream.scheme not in {"http", "https"} or not parsed_upstream.hostname:
                raise ValueError("upstream URL must use http or https and include a host")
            if parsed_upstream.username or parsed_upstream.password or parsed_upstream.fragment or parsed_upstream.query:
                raise ValueError("upstream URL cannot include credentials, a query, or a fragment")
            _ = parsed_upstream.port  # Force validation of malformed ports during startup.
            host = parsed_upstream.hostname.lower()
            try:
                local_host = ipaddress.ip_address(host).is_loopback
            except ValueError:
                local_host = host == "localhost"
            if parsed_upstream.scheme != "https" and not local_host:
                raise ValueError("non-loopback upstreams must use HTTPS")
        except ValueError as exc:
            raise ValueError(f"Invalid upstream URL: {exc}") from exc

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        audit_dispatcher: AuditWebhookDispatcher | None = None
        audit_delivery_task: asyncio.Task[None] | None = None
        if upstream_url:
            application.state.upstream_client = httpx.AsyncClient(
                timeout=httpx.Timeout(
                    float(policy.get("limits", {}).get("upstream_timeout_seconds", 30))
                ),
                follow_redirects=False,
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            )
        if mcp_endpoints:
            application.state.mcp_client = httpx.AsyncClient(
                timeout=httpx.Timeout(float(policy.get("limits", {}).get("upstream_timeout_seconds", 30))),
                follow_redirects=False,
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            )
        if audit_webhook_config is not None:
            audit_dispatcher = AuditWebhookDispatcher(audit, control_store, audit_webhook_config)
            audit_delivery_task = asyncio.create_task(audit_dispatcher.run(), name="llmsentinel-audit-export")
        try:
            yield
        finally:
            if audit_delivery_task is not None:
                audit_delivery_task.cancel()
                await asyncio.gather(audit_delivery_task, return_exceptions=True)
            if audit_dispatcher is not None:
                await audit_dispatcher.close()
            client = getattr(application.state, "upstream_client", None)
            if client is not None:
                await client.aclose()
            mcp_client = getattr(application.state, "mcp_client", None)
            if mcp_client is not None:
                await mcp_client.aclose()
            telemetry.shutdown()

    app = FastAPI(
        title="LLMSentinel Gateway",
        version="3.0.0",
        description="Deterministic AI request and tool controls",
        lifespan=lifespan,
    )
    if telemetry.enabled:
        app.middleware("http")(telemetry.instrument)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Approval-Token"],
    )
    app.add_middleware(
        RequestBodySizeLimit,
        max_bytes=int(policy.get("limits", {}).get("max_request_bytes", 65536)),
        path_limits={"/v1/security/scan": MAX_SCAN_REQUEST_BYTES},
    )
    app.state.pipeline = pipeline
    app.state.audit = audit

    def record_auth_event(request: Request, event_type: str, reason: str, role: str | None = None) -> None:
        client_host = request.client.host if request.client else "local"
        if not pipeline.bucket.allow(f"{event_type}:{client_host}"):
            return
        try:
            if not audit.verify_chain()[0]:
                return
            audit.append(
                {
                    "type": event_type,
                    "allowed": False,
                    "layer": "IDENTITY",
                    "reason": reason,
                    "method": request.method,
                    "route": request.url.path,
                    **({"role": role} if role else {}),
                }
            )
        except (OSError, RuntimeError):
            # Identity rejection must still return 401/403 when audit storage
            # itself is unavailable; readiness and protected operations fail closed.
            return

    def reject_auth(request: Request, reason: str) -> NoReturn:
        record_auth_event(request, "auth_failure", reason)
        raise HTTPException(status_code=401, detail=reason)

    async def context_from_header(authorization: str | None, request: Request) -> AuthContext:
        require_auth = bool(policy.get("auth", {}).get("require_auth", False))
        if not authorization:
            if require_auth:
                reject_auth(request, "bearer_token_required")
            return AuthContext(tenant_id="public", role="user")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            reject_auth(request, "bearer_scheme_required")
        if token.startswith("ls_"):
            try:
                api_identity = await run_in_threadpool(control_store.authenticate_api_key, token)
            except Exception as exc:
                raise HTTPException(status_code=503, detail="API key identity store is unavailable") from exc
            if api_identity is None:
                record_auth_event(request, "auth_failure", "api_key_invalid_or_expired")
                raise HTTPException(status_code=401, detail="api_key_invalid_or_expired")
            return api_identity
        try:
            secret = os.getenv(str(policy.get("auth", {}).get("secret_env", "SENTINEL_JWT_SECRET")))
            if auth_mode == "oidc":
                if oidc_verifier is None:
                    raise AuthenticationError("OIDC bearer verification is not configured")
                return await run_in_threadpool(oidc_verifier.verify, token)
            if not secret and policy.get("auth", {}).get("require_auth", False):
                raise AuthenticationError("JWT signing secret is not configured")
            if not secret:
                raise AuthenticationError("JWT signing secret is not configured")
            if len(secret.encode()) < 32:
                raise AuthenticationError("JWT signing secret must contain at least 32 bytes")
            return verify_bearer(
                token,
                secret,
                str(policy["auth"]["issuer"]) if policy.get("auth", {}).get("issuer") else None,
                str(policy["auth"]["audience"]) if policy.get("auth", {}).get("audience") else None,
            )
        except AuthenticationError as exc:
            record_auth_event(request, "auth_failure", "bearer_token_invalid")
            raise HTTPException(status_code=401, detail="bearer_token_invalid") from exc

    async def telemetry_context(authorization: str | None, request: Request) -> AuthContext:
        auth = await context_from_header(authorization, request)
        allowed_roles = set(policy.get("telemetry", {}).get("roles", ["admin", "analyst", "platform_admin"]))
        if auth.authenticated and auth.role not in allowed_roles:
            record_auth_event(request, "authorization_denied", "telemetry_role_required", auth.role)
            raise HTTPException(status_code=403, detail="Role is not authorized to view telemetry")
        return auth

    async def control_identity(
        request: Request,
        authorization: str | None,
        roles: set[str],
    ) -> AuthContext:
        if not bool(auth_settings.get("require_auth", False)):
            raise HTTPException(status_code=503, detail="Control-plane administration requires gateway authentication to be enabled")
        auth = await context_from_header(authorization, request)
        if not auth.authenticated:
            record_auth_event(request, "authorization_denied", "authenticated_control_identity_required")
            raise HTTPException(status_code=401, detail="Authenticated identity is required")
        if auth.role not in roles:
            record_auth_event(request, "authorization_denied", "control_plane_role_required", auth.role)
            raise HTTPException(status_code=403, detail="Role is not authorized for this control-plane operation")
        return auth

    def require_healthy_audit() -> None:
        valid, _ = audit.verify_chain()
        if not valid:
            raise HTTPException(
                status_code=503, detail="Audit integrity check failed; request processing is paused"
            )

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": "3.0.0", "policy_version": policy["version"]}

    @app.get("/ready")
    def readiness() -> dict[str, Any]:
        audit_valid, audit_error = audit.verify_chain()
        checks = {
            "audit_chain": audit_valid,
            "control_plane_store": control_store.check_health(),
            "approval_replay_store": approval_verifier.check_health(),
            "shared_rate_limit_store": pipeline.bucket.check_health(),
            "required_shared_replay": (
                approval_verifier.check_health()
                if policy.get("approval", {}).get("require_shared_replay", False)
                else True
            ),
            "required_shared_rate_limit": (
                pipeline.bucket.check_health()
                if policy.get("limits", {}).get("require_shared_rate_limit", False)
                else True
            ),
        }
        if not audit_valid or not all(checks.values()):
            raise HTTPException(
                status_code=503,
                detail={"status": "not_ready", "checks": checks, "audit_error": audit_error},
            )
        return {"status": "ready", "version": "3.0.0", "checks": checks}

    @app.get("/v1/security/posture")
    async def security_posture(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        await telemetry_context(authorization, request)
        audit_valid, audit_error = audit.verify_chain()
        shared_rate_limit = bool(rate_limit_redis_url)
        replay_healthy = approval_verifier.check_health()
        rate_limit_healthy = pipeline.bucket.check_health()
        auth_mode_name = (
            "OIDC/JWKS" if auth_mode == "oidc" else "HS256" if auth_settings.get("require_auth") else "disabled"
        )
        configured_upstream = bool(upstream_url)
        configured_chroma = rag_adapter is not None
        try:
            audit_delivery = control_store.audit_export_status()
        except sqlite3.Error:
            audit_delivery = {"pending": 0, "delivered": 0, "oldest_pending": None, "last_delivered": None, "last_error": "control_plane_store_unavailable"}
        model_breaker_state = model_breaker.state()
        mcp_breaker_states = {tool: breaker.state() for tool, breaker in mcp_breakers.items()}
        rag_breaker_state = rag_breaker.state()
        controls = [
            {
                "id": "streaming_output",
                "name": "Streaming response inspection",
                "status": "enforced" if policy["layers"].get("l4", {}).get("enabled", True) else "disabled",
                "evidence": "OpenAI-compatible SSE assistant text is inspected across chunk boundaries; tool calls and unsupported structured output fail closed" if policy["layers"].get("l4", {}).get("enabled", True) else "Output DLP is disabled by the active policy",
            },
            {
                "id": "control_plane_store",
                "name": "Governance workflow storage",
                "status": "configured" if control_store.check_health() else "failed",
                "evidence": "Policy lifecycle, incidents, reviewer votes, evaluation evidence and API-key digests use local SQLite; multi-replica coordination is not configured" if control_store.check_health() else "Control-plane database is unavailable",
            },
            {
                "id": "identity",
                "name": "Identity verification",
                "status": "enforced" if auth_settings.get("require_auth") else "development_only",
                "evidence": f"{auth_mode_name} · issuer/audience/tenant claims verified on authenticated requests",
            },
            {
                "id": "tenant_rag",
                "name": "Tenant-scoped RAG retrieval",
                "status": ("failed" if rag_breaker_state == "open" else "enforced") if configured_chroma and auth_settings.get("require_auth") else "not_configured",
                "evidence": f"Chroma applies and rechecks verified tenant_id metadata; circuit is {rag_breaker_state}" if configured_chroma else "No Chroma endpoint configured; filter preview is not datastore isolation",
            },
            {
                "id": "mcp",
                "name": "MCP execution firewall",
                "status": ("failed" if "open" in mcp_breaker_states.values() else "enforced") if mcp_endpoints else "not_configured",
                "evidence": f"{len(mcp_endpoints)} allowlisted endpoint(s); per-tool circuits {mcp_breaker_states}; authorization and approval run before JSON-RPC" if mcp_endpoints else "No MCP tool endpoints configured; authorization endpoint remains decision-only",
            },
            {
                "id": "approval_replay",
                "name": "Single-use human approval",
                "status": "enforced" if approval_verifier.secret and len(approval_verifier.secret.encode()) >= 32 and replay_healthy else "failed" if not replay_healthy else "not_configured",
                "evidence": f"Action-bound approval · {approval_verifier.replay_backend} replay store · {'healthy' if replay_healthy else 'unavailable'}",
            },
            {
                "id": "rate_limit",
                "name": "Request rate limiting",
                "status": "enforced" if shared_rate_limit and rate_limit_healthy else "process_local" if rate_limit_healthy else "failed",
                "evidence": "Shared Redis token bucket with fail-closed behavior" if shared_rate_limit and rate_limit_healthy else "Process-local token bucket; quotas are not shared across replicas" if rate_limit_healthy else "Rate-limit state store is unavailable",
            },
            {
                "id": "audit_integrity",
                "name": "Audit integrity",
                "status": "pull_export_available" if audit_valid else "failed",
                "evidence": "Local SHA-256 chain verified; cursor-based metadata export is available for external SIEM/WORM ingestion, but remote anchoring is not configured" if audit_valid else (audit_error or "Audit chain verification failed"),
            },
            {
                "id": "audit_delivery",
                "name": "Durable SIEM delivery",
                "status": "not_configured" if audit_webhook_config is None else "healthy" if audit_delivery["pending"] == 0 and audit_delivery["last_error"] is None else "pending",
                "evidence": "No push destination configured; cursor export remains available" if audit_webhook_config is None else f"At-least-once HTTPS webhook delivery · {audit_delivery['pending']} pending · oldest {audit_delivery['oldest_pending'] or 'none'} · {audit_delivery['delivered']} retained delivered · last error {audit_delivery['last_error'] or 'none'}",
            },
            {
                "id": "policy_integrity",
                "name": "Policy artifact signature",
                "status": "enforced" if policy.get("integrity", {}).get("require_signature") else "not_required",
                "evidence": "Signed policy was verified before gateway startup" if policy.get("integrity", {}).get("require_signature") else "Policy signature enforcement is disabled for this policy",
            },
            {
                "id": "upstream",
                "name": "Model upstream",
                "status": "configured" if configured_upstream else "local_mock",
                "evidence": "Requests use the configured upstream with response size and timeout limits" if configured_upstream else "Deterministic local mock; no external model API is contacted",
            },
            {
                "id": "upstream_circuit",
                "name": "Upstream circuit breaker",
                "status": ("healthy" if model_breaker_state == "closed" else model_breaker_state) if configured_upstream else "not_configured",
                "evidence": f"{breaker_threshold} consecutive failures open the circuit for {breaker_reset_seconds:g}s; one half-open recovery probe is allowed",
            },
            {
                "id": "content_logging",
                "name": "Prompt and response logging",
                "status": "minimized",
                "evidence": "Audit events store policy metadata; request and response content are not recorded by the gateway",
            },
            {
                "id": "latency_evidence",
                "name": "Latency evidence",
                "status": "observed" if len(timings) else "not_measured",
                "evidence": "Rolling in-process p50/p95/p99 includes upstream; gateway overhead and upstream are reported separately. No load-test SLA is asserted.",
            },
            {
                "id": "telemetry_export",
                "name": "Telemetry export",
                "status": "otlp_configured" if telemetry.enabled else "json_api_only",
                "evidence": "OTLP request spans and metrics omit prompt bodies, tenant IDs, subjects, and token values" if telemetry.enabled else "Role-gated JSON metrics are available; set OTEL_EXPORTER_OTLP_ENDPOINT to enable OTLP spans and metrics",
            },
        ]
        return {
            "version": "3.0.0",
            "policy": {
                "name": policy.get("name", "unnamed"),
                "version": policy["version"],
                "revision": policy.get("revision", "1"),
                "sha256": hashlib.sha256(
                    json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                ).hexdigest(),
            },
            "overall": "ready" if all(item["status"] in {"enforced", "healthy", "configured", "minimized", "not_required", "otlp_configured"} for item in controls) else "action_required",
            "controls": controls,
            "integrations": {
                "model_upstream": configured_upstream,
                "chroma": configured_chroma,
                "mcp_tool_count": len(mcp_endpoints),
                "audit_chain_valid": audit_valid,
                "otlp": telemetry.enabled,
            },
        }

    @app.get("/metrics")
    async def metrics(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        auth = await telemetry_context(authorization, request)
        with metrics_lock:
            if auth.role == "platform_admin":
                snapshot = counts.copy()
                samples = {
                    "latency": sorted(timings),
                    "overhead": sorted(overhead_timings),
                    "upstream": sorted(upstream_timings),
                    "tool": sorted(tool_timings),
                }
            else:
                snapshot = tenant_counts.get(auth.tenant_id, {name: 0 for name in counts}).copy()
                scoped_samples = tenant_timings.get(auth.tenant_id, {})
                samples = {
                    "latency": sorted(scoped_samples.get("latency", ())),
                    "overhead": sorted(scoped_samples.get("overhead", ())),
                    "upstream": sorted(scoped_samples.get("upstream", ())),
                    "tool": sorted(scoped_samples.get("tool", ())),
                }

        def pct(values: list[float], percentile: float) -> float:
            if not values:
                return 0.0
            index = max(0, math.ceil(len(values) * percentile) - 1)
            return round(values[min(len(values) - 1, index)], 3)

        def percentiles(values: list[float]) -> dict[str, float]:
            return {"p50": pct(values, 0.50), "p95": pct(values, 0.95), "p99": pct(values, 0.99)}

        return {
            **snapshot,
            "latency_ms": percentiles(samples["latency"]),
            "gateway_overhead_ms": percentiles(samples["overhead"]),
            "upstream_ms": percentiles(samples["upstream"]),
            "tool_policy_ms": percentiles(samples["tool"]),
            "window": len(samples["latency"]),
            "stage_windows": {
                "gateway_overhead": len(samples["overhead"]),
                "upstream": len(samples["upstream"]),
                "tool_policy": len(samples["tool"]),
            },
        }

    @app.get("/audit")
    async def get_audit(
        request: Request, limit: int = 50, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        auth = await telemetry_context(authorization, request)
        valid, error = audit.verify_chain()
        events = (
            audit.recent(max(1, min(limit, 500)))
            if auth.role == "platform_admin"
            else audit.recent_for_tenant(auth.tenant_id, max(1, min(limit, 500)))
        )
        return {
            "chain_valid": valid,
            "chain_error": error,
            "events": events,
        }

    @app.get("/v1/security/audit/export")
    async def export_audit(
        request: Request,
        after_hash: str = "0" * 64,
        limit: int = 500,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Pull ordered metadata-only audit batches into a SIEM or WORM sink."""
        auth = await telemetry_context(authorization, request)
        if auth.role != "platform_admin":
            record_auth_event(request, "authorization_denied", "platform_admin_required", auth.role)
            raise HTTPException(status_code=403, detail="Platform administrator role is required for global audit export")
        try:
            return audit.export_after(after_hash, limit)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Audit export cursor was not found") from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail="Audit chain integrity check failed") from exc

    @app.post("/v1/security/scan")
    async def security_scan(
        body: ScanRequest, request: Request, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        """Analyze explicitly uploaded files in an isolated temporary directory."""
        auth = await telemetry_context(authorization, request)
        require_healthy_audit()
        if not pipeline.bucket.allow(auth.tenant_id):
            record_denial(rate_limited=True, tenant_id=auth.tenant_id)
            audit.append({"type": "scan", "allowed": False, "layer": "L1", "reason": "rate_limit_exceeded", "tenant_id": auth.tenant_id, "subject": auth.subject})
            raise HTTPException(status_code=429, detail="Request rate limit exceeded")
        if len(body.files) > MAX_SCAN_FILES:
            raise HTTPException(status_code=413, detail="Scan file-count limit exceeded")
        total_bytes = 0
        seen_paths: set[str] = set()
        decoded_files: list[tuple[str, bytes]] = []
        allowed_suffixes = {".py", ".pkl", ".pickle", ".pt", ".pth"}
        for item in body.files:
            normalized_path = item.path.replace("\\", "/")
            relative = PurePosixPath(normalized_path)
            windows_path = PureWindowsPath(item.path)
            if (
                relative.is_absolute()
                or windows_path.is_absolute()
                or windows_path.drive
                or any(part in {"", ".", ".."} for part in relative.parts)
                or any(ord(character) < 32 for character in normalized_path)
                or len(relative.parts) > 8
            ):
                raise HTTPException(status_code=422, detail="Scan paths must be safe relative file names")
            display_path = relative.as_posix()
            if display_path in seen_paths:
                raise HTTPException(status_code=422, detail="Duplicate scan file path")
            seen_paths.add(display_path)
            suffix = Path(display_path).suffix.lower()
            if suffix not in allowed_suffixes:
                raise HTTPException(
                    status_code=422,
                    detail="Supported scan files are .py, .pkl, .pickle, .pt and .pth",
                )
            try:
                file_bytes = base64.b64decode(item.content_base64, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise HTTPException(status_code=422, detail="A scan file is not valid base64") from exc
            max_file_bytes = MAX_SCAN_FILE_BYTES if suffix == ".py" else MAX_SCAN_TOTAL_BYTES
            if not file_bytes or len(file_bytes) > max_file_bytes:
                raise HTTPException(status_code=413, detail="A scan file is empty or exceeds its size limit")
            total_bytes += len(file_bytes)
            if total_bytes > MAX_SCAN_TOTAL_BYTES:
                raise HTTPException(status_code=413, detail="Scan upload exceeds the 8 MiB total limit")
            decoded_files.append((display_path, file_bytes))

        started = time.perf_counter()
        with tempfile.TemporaryDirectory(prefix="llmsentinel-scan-") as temporary_directory:
            root = Path(temporary_directory)
            for display_path, file_bytes in decoded_files:
                destination = root.joinpath(*PurePosixPath(display_path).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as output:
                    output.write(file_bytes)
            findings = scan_path(root) + scan_model_path(root)
            for finding in findings:
                try:
                    finding.path = Path(finding.path).resolve().relative_to(root.resolve()).as_posix()
                except (OSError, ValueError):
                    finding.path = Path(finding.path).name

        total_findings = len(findings)
        reported_findings = findings[:MAX_SCAN_FINDINGS]
        severity_counts = {
            severity: 0
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OTHER")
        }
        for finding in findings:
            severity = finding.severity.upper()
            severity_counts[severity if severity in severity_counts else "OTHER"] += 1
        reports = {
            "json": json_report(reported_findings),
            "sarif": sarif_report(reported_findings),
            "markdown": markdown_report(reported_findings),
            "pdf_base64": base64.b64encode(pdf_report(reported_findings)).decode("ascii"),
        }
        scan_id = str(uuid.uuid4())
        duration_ms = round((time.perf_counter() - started) * 1000, 3)
        audit.append(
            {
                "type": "scan",
                "allowed": True,
                "layer": "SCANNER",
                "scan_id": scan_id,
                "tenant_id": auth.tenant_id,
                "subject": auth.subject,
                "scanned_files": len(decoded_files),
                "scanned_bytes": total_bytes,
                "finding_count": total_findings,
                "reported_finding_count": len(reported_findings),
                "severity_counts": severity_counts,
                "truncated": total_findings > len(reported_findings),
                "duration_ms": duration_ms,
            }
        )
        return {
            "scan_id": scan_id,
            "scanned_files": len(decoded_files),
            "scanned_bytes": total_bytes,
            "duration_ms": duration_ms,
            "finding_count": total_findings,
            "severity_counts": severity_counts,
            "reported_finding_count": len(reported_findings),
            "truncated": total_findings > len(reported_findings),
            "findings": [finding.as_dict() for finding in reported_findings],
            "reports": reports,
        }

    @app.post("/v1/chat/completions")
    async def chat(
        body: ChatRequest, request: Request, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        started = time.perf_counter()
        require_healthy_audit()
        stream_requested = body.model_dump().get("stream") is True
        auth = await context_from_header(authorization, request)
        request_id = uuid.uuid4().hex
        request_payload = body.model_dump()
        tool_choice = request_payload.get("tool_choice")
        if request_payload.get("tools") or (tool_choice is not None and tool_choice != "none"):
            raise HTTPException(
                status_code=422,
                detail="Provider-managed tools are disabled; call registered tools through /v1/mcp/tools/call",
            )
        increment_metric("requests", tenant_id=auth.tenant_id)
        # Every client-supplied message is untrusted, including tool results,
        # multimodal text parts, and caller-provided system/developer roles.
        try:
            prompt_chunks = _strings_in(body.model_dump())
        except HTTPException:
            record_denial(tenant_id=auth.tenant_id)
            audit.append({"type": "request", "request_id": request_id, "allowed": False, "layer": "L1", "reason": "json_complexity_limit", "tenant_id": auth.tenant_id, "subject": auth.subject})
            elapsed = (time.perf_counter() - started) * 1000
            record_latency(elapsed, auth.tenant_id)
            record_stage_latency("overhead", overhead_timings, elapsed, auth.tenant_id)
            raise
        prompt = "\n".join(prompt_chunks)
        decision = pipeline.inspect_input(
            prompt_chunks,
            auth,
            auth.tenant_id,
        )
        event: dict[str, Any] = {
            "type": "request",
            "request_id": request_id,
            "allowed": decision.allowed,
            "layer": decision.layer,
            "reason": decision.reason,
            "tenant_id": auth.tenant_id,
            "subject": auth.subject,
        }
        if not decision.allowed:
            record_denial(decision.reason == "rate_limit_exceeded", auth.tenant_id)
            audit.append(event)
            elapsed = (time.perf_counter() - started) * 1000
            record_latency(elapsed, auth.tenant_id)
            record_stage_latency("overhead", overhead_timings, elapsed, auth.tenant_id)
            raise HTTPException(
                status_code=403, detail={"blocked": True, "request_id": request_id, "decision": decision.as_dict()}
            )
        # Record the allow decision before any request is sent to the model.
        audit.append({**event, "phase": "authorized"})
        if upstream_url:
            if not model_breaker.allow_request():
                increment_metric("circuit_open", tenant_id=auth.tenant_id)
                audit.append({**event, "type": "upstream_error", "error": "upstream_circuit_open"})
                elapsed = (time.perf_counter() - started) * 1000
                record_latency(elapsed, auth.tenant_id)
                record_stage_latency("overhead", overhead_timings, elapsed, auth.tenant_id)
                raise HTTPException(status_code=503, detail="Configured model upstream circuit is open")
            headers = {}
            upstream_key = os.getenv("SENTINEL_UPSTREAM_API_KEY")
            if upstream_key:
                headers["Authorization"] = f"Bearer {upstream_key}"
            upstream_body = body.model_dump()
            upstream_body.pop("tenant_id", None)
            metadata = upstream_body.get("metadata")
            if isinstance(metadata, dict):
                metadata.pop("tenant_id", None)
            if stream_requested:
                upstream_body["stream"] = True
                upstream_started = time.perf_counter()
                try:
                    client: httpx.AsyncClient = request.app.state.upstream_client
                    upstream_request = client.build_request(
                        "POST", upstream_url, json=upstream_body, headers=headers
                    )
                    upstream_response = await client.send(upstream_request, stream=True)
                    if upstream_response.status_code < 200 or upstream_response.status_code >= 300:
                        await upstream_response.aclose()
                        raise httpx.HTTPStatusError(
                            "upstream rejected streaming request",
                            request=upstream_request,
                            response=upstream_response,
                        )
                    if "text/event-stream" not in upstream_response.headers.get("content-type", "").lower():
                        await upstream_response.aclose()
                        raise ValueError("upstream did not return a streaming event response")
                except (httpx.HTTPError, ValueError) as exc:
                    model_breaker.record_failure()
                    increment_metric("upstream_errors", tenant_id=auth.tenant_id)
                    upstream_elapsed_ms = (time.perf_counter() - upstream_started) * 1000
                    record_stage_latency("upstream", upstream_timings, upstream_elapsed_ms, auth.tenant_id)
                    await run_in_threadpool(
                        audit.append,
                        {**event, "type": "upstream_error", "error": type(exc).__name__},
                    )
                    elapsed = (time.perf_counter() - started) * 1000
                    record_latency(elapsed, auth.tenant_id)
                    record_stage_latency("overhead", overhead_timings, elapsed - upstream_elapsed_ms, auth.tenant_id)
                    raise HTTPException(status_code=502, detail="Configured streaming upstream request failed") from exc

                redaction_labels: set[str] = set()

                async def stream_upstream() -> AsyncIterator[bytes]:
                    stream_complete = False
                    try:
                        async for safe_chunk in sanitize_openai_sse(
                            upstream_response,
                            pipeline,
                            int(policy["limits"].get("max_upstream_response_bytes", 2 * 1024 * 1024)),
                            {"request_id": request_id, "decision": decision.as_dict()},
                            redaction_labels,
                        ):
                            yield safe_chunk
                        stream_complete = True
                        model_breaker.record_success()
                    except (httpx.HTTPError, ValueError, UnicodeDecodeError, RecursionError) as exc:
                        model_breaker.record_failure()
                        increment_metric("upstream_errors", tenant_id=auth.tenant_id)
                        # The client gets a terminal SSE error after any already-reviewed chunks;
                        # buffered, incomplete candidates are discarded by the sanitizer.
                        error_payload = json.dumps(
                            {"error": {"message": "Streaming response stopped by the security gateway", "type": "gateway_stream_error"}},
                            separators=(",", ":"),
                        )
                        yield f"event: error\ndata: {error_payload}\n\n".encode("utf-8")
                        await run_in_threadpool(
                            audit.append,
                            {**event, "type": "upstream_error", "error": type(exc).__name__, "stream": True, "redactions": sorted(redaction_labels)},
                        )
                    finally:
                        await upstream_response.aclose()
                        elapsed = (time.perf_counter() - started) * 1000
                        upstream_elapsed_ms = (time.perf_counter() - upstream_started) * 1000
                        record_latency(elapsed, auth.tenant_id)
                        record_stage_latency("upstream", upstream_timings, upstream_elapsed_ms, auth.tenant_id)
                        record_stage_latency("overhead", overhead_timings, elapsed - upstream_elapsed_ms, auth.tenant_id)
                        if stream_complete:
                            increment_metric("redactions", len(redaction_labels), auth.tenant_id)
                            await run_in_threadpool(
                                audit.append,
                                {
                                    **event,
                                    "type": "request_result",
                                    "phase": "completed",
                                    "stream": True,
                                    "output_layer": "L4" if policy["layers"].get("l4", {}).get("enabled", True) else None,
                                    "upstream_host": urlsplit(upstream_url).netloc,
                                },
                            )
                        elif redaction_labels:
                            increment_metric("redactions", len(redaction_labels), auth.tenant_id)

                return StreamingResponse(
                    stream_upstream(),
                    media_type="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
                )
            upstream_started = time.perf_counter()
            upstream_elapsed_ms = 0.0
            try:
                client: httpx.AsyncClient = request.app.state.upstream_client
                async with client.stream(
                    "POST", upstream_url, json=upstream_body, headers=headers
                ) as upstream_response:
                    upstream_response.raise_for_status()
                    response_chunks: list[bytes] = []
                    response_bytes = 0
                    max_response_bytes = int(
                        policy["limits"].get("max_upstream_response_bytes", 2 * 1024 * 1024)
                    )
                    async for chunk in upstream_response.aiter_bytes():
                        response_bytes += len(chunk)
                        if response_bytes > max_response_bytes:
                            raise ValueError("upstream response exceeds configured byte limit")
                        response_chunks.append(chunk)
                    result = json.loads(b"".join(response_chunks))
                if not isinstance(result, dict) or not isinstance(result.get("choices"), list):
                    raise ValueError("upstream response is not a chat completion object")
            except (httpx.HTTPError, ValueError, RecursionError) as exc:
                model_breaker.record_failure()
                increment_metric("upstream_errors", tenant_id=auth.tenant_id)
                upstream_elapsed_ms = (time.perf_counter() - upstream_started) * 1000
                record_stage_latency("upstream", upstream_timings, upstream_elapsed_ms, auth.tenant_id)
                audit.append({**event, "type": "upstream_error", "error": type(exc).__name__})
                elapsed = (time.perf_counter() - started) * 1000
                record_latency(elapsed, auth.tenant_id)
                record_stage_latency("overhead", overhead_timings, elapsed - upstream_elapsed_ms, auth.tenant_id)
                raise HTTPException(
                    status_code=502, detail="Configured upstream request failed"
                ) from exc
            model_breaker.record_success()
            upstream_elapsed_ms = (time.perf_counter() - upstream_started) * 1000
            record_stage_latency("upstream", upstream_timings, upstream_elapsed_ms, auth.tenant_id)
            choices = cast(list[Any], result.get("choices"))
            if any(
                isinstance(choice, dict)
                and isinstance(choice.get("message"), dict)
                and (choice["message"].get("tool_calls") or choice["message"].get("function_call"))
                for choice in choices
            ):
                model_breaker.record_failure()
                increment_metric("upstream_errors", tenant_id=auth.tenant_id)
                audit.append({**event, "type": "upstream_error", "error": "provider_tool_call_rejected"})
                elapsed = (time.perf_counter() - started) * 1000
                record_latency(elapsed, auth.tenant_id)
                record_stage_latency("overhead", overhead_timings, elapsed - upstream_elapsed_ms, auth.tenant_id)
                raise HTTPException(
                    status_code=502,
                    detail="Upstream returned a tool call; provider-managed tool execution is disabled",
                )
            redactions: list[str] = []
            try:
                cleaned_result, labels = _sanitize_message(result, pipeline)
                if not isinstance(cleaned_result, dict):
                    raise ValueError("Upstream response root changed type during output sanitization")
                result = cleaned_result
                redactions.extend(labels)
            except (ValueError, RecursionError) as exc:
                audit.append({**event, "type": "upstream_error", "error": type(exc).__name__})
                elapsed = (time.perf_counter() - started) * 1000
                record_latency(elapsed, auth.tenant_id)
                record_stage_latency("overhead", overhead_timings, elapsed - upstream_elapsed_ms, auth.tenant_id)
                raise HTTPException(
                    status_code=502, detail="Configured upstream response exceeded output safety limits"
                ) from exc
            redaction_labels = sorted(set(redactions))
            increment_metric("redactions", len(redaction_labels), auth.tenant_id)
            result["sentinel"] = {
                "decision": decision.as_dict(),
                "redactions": redaction_labels,
                "request_id": request_id,
            }
            upstream_host = urlsplit(upstream_url).netloc
            audit.append(
                {
                    **event,
                    "type": "request_result",
                    "phase": "completed",
                    **(
                        {"output_layer": "L4"}
                        if policy["layers"].get("l4", {}).get("enabled", True)
                        else {}
                    ),
                    "redactions": redaction_labels,
                    "upstream_host": upstream_host,
                }
            )
            elapsed = (time.perf_counter() - started) * 1000
            record_latency(elapsed, auth.tenant_id)
            record_stage_latency("overhead", overhead_timings, elapsed - upstream_elapsed_ms, auth.tenant_id)
            result["sentinel"]["latency_ms"] = round(elapsed, 3)
            return result
        # The local mock is deterministic and requires no external credentials.
        response_text = f"Local deterministic response for tenant {auth.tenant_id}: {prompt[:240]}"
        clean, redactions = pipeline.sanitize_output(response_text)
        redaction_labels = sorted(set(redactions))
        increment_metric("redactions", len(redaction_labels), auth.tenant_id)
        audit.append(
            {
                **event,
                **(
                    {"output_layer": "L4"}
                    if policy["layers"].get("l4", {}).get("enabled", True)
                    else {}
                ),
                "redactions": redaction_labels,
            }
        )
        elapsed = (time.perf_counter() - started) * 1000
        record_latency(elapsed, auth.tenant_id)
        record_stage_latency("overhead", overhead_timings, elapsed, auth.tenant_id)
        if stream_requested:
            async def stream_mock() -> AsyncIterator[bytes]:
                for offset in range(0, len(clean), 24):
                    chunk = json.dumps(
                        {"choices": [{"index": 0, "delta": {"content": clean[offset : offset + 24]}}]},
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    yield f"data: {chunk}\n\n".encode("utf-8")
                yield f"event: sentinel\ndata: {json.dumps({'request_id': request_id, 'decision': decision.as_dict(), 'redactions': redaction_labels}, separators=(',', ':'))}\n\n".encode("utf-8")
                yield b"data: [DONE]\n\n"

            return StreamingResponse(
                stream_mock(),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
            )
        return {
            "id": f"sentinel-{int(time.time() * 1000)}",
            "object": "chat.completion",
            "model": body.model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": clean},
                    "finish_reason": "stop",
                }
            ],
            "sentinel": {
                "decision": decision.as_dict(),
                "redactions": redaction_labels,
                "latency_ms": round(elapsed, 3),
                "request_id": request_id,
            },
        }

    @app.post("/v1/tools/call")
    async def call_tool(
        body: ToolRequest,
        request: Request,
        authorization: str | None = Header(default=None),
        x_approval_token: str | None = Header(default=None),
    ) -> dict[str, Any]:
        require_healthy_audit()
        auth = await context_from_header(authorization, request)
        increment_metric("requests", tenant_id=auth.tenant_id)
        if not pipeline.bucket.allow(auth.tenant_id):
            record_denial(rate_limited=True, tenant_id=auth.tenant_id)
            audit.append(
                {
                    "type": "tool",
                    "allowed": False,
                    "layer": "L1",
                    "reason": "rate_limit_exceeded",
                    "tool": body.tool,
                    "tenant_id": auth.tenant_id,
                    "subject": auth.subject,
                    "role": auth.role,
                }
            )
            raise HTTPException(status_code=429, detail="Request rate limit exceeded")
        tool_policy_started = time.perf_counter()
        decision = pipeline.inspect_tool(body.tool, body.arguments, auth, x_approval_token)
        increment_metric("tool_calls", tenant_id=auth.tenant_id)
        audit.append(
            {
                "type": "tool",
                "allowed": decision.allowed,
                "layer": decision.layer,
                "reason": decision.reason,
                "tool": body.tool,
                "tenant_id": auth.tenant_id,
                "subject": auth.subject,
                "role": auth.role,
            }
        )
        if not decision.allowed:
            record_denial(tenant_id=auth.tenant_id)
            raise HTTPException(
                status_code=403, detail={"blocked": True, "decision": decision.as_dict()}
            )
        record_stage_latency("tool", tool_timings, (time.perf_counter() - tool_policy_started) * 1000, auth.tenant_id)
        # No arbitrary execution: this endpoint only returns the policy decision.
        return {"status": "authorized", "decision": decision.as_dict(), "arguments": body.arguments}

    @app.post("/v1/mcp/tools/call")
    async def execute_mcp_tool(
        body: ToolRequest,
        request: Request,
        authorization: str | None = Header(default=None),
        x_approval_token: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Execute only an allowlisted MCP tool after identity and policy checks."""
        require_healthy_audit()
        auth = await context_from_header(authorization, request)
        if not auth.authenticated:
            raise HTTPException(status_code=401, detail="Authenticated identity is required for MCP execution")
        endpoint = mcp_endpoints.get(body.tool)
        if endpoint is None:
            raise HTTPException(status_code=503, detail="No MCP server is configured for this tool")
        increment_metric("requests", tenant_id=auth.tenant_id)
        if not pipeline.bucket.allow(auth.tenant_id):
            record_denial(rate_limited=True, tenant_id=auth.tenant_id)
            audit.append({"type": "mcp_tool_execution", "allowed": False, "layer": "L1", "reason": "rate_limit_exceeded", "tool": body.tool, "tenant_id": auth.tenant_id, "subject": auth.subject})
            raise HTTPException(status_code=429, detail="Request rate limit exceeded")

        tool_policy_started = time.perf_counter()
        preflight = pipeline.inspect_tool(body.tool, body.arguments, auth)
        if not preflight.allowed and preflight.reason != "human_approval_required":
            effective_arguments = body.arguments
            decision = preflight
        else:
            effective_arguments = pipeline.bind_tool_tenant(body.tool, body.arguments, auth)
            decision = pipeline.inspect_tool(body.tool, effective_arguments, auth, x_approval_token)
        increment_metric("tool_calls", tenant_id=auth.tenant_id)
        record_stage_latency("tool", tool_timings, (time.perf_counter() - tool_policy_started) * 1000, auth.tenant_id)
        if not decision.allowed:
            record_denial(tenant_id=auth.tenant_id)
            audit.append({"type": "mcp_tool_execution", "allowed": False, "layer": decision.layer, "reason": decision.reason, "tool": body.tool, "tenant_id": auth.tenant_id, "subject": auth.subject, "role": auth.role})
            raise HTTPException(status_code=403, detail={"blocked": True, "decision": decision.as_dict()})

        # Persist authorization before the side-effecting MCP operation.
        audit.append({"type": "mcp_tool_authorized", "allowed": True, "layer": "L3", "reason": decision.reason, "tool": body.tool, "tenant_id": auth.tenant_id, "subject": auth.subject, "role": auth.role})
        breaker = mcp_breakers[body.tool]
        if not breaker.allow_request():
            increment_metric("circuit_open", tenant_id=auth.tenant_id)
            increment_metric("upstream_errors", tenant_id=auth.tenant_id)
            audit.append({"type": "mcp_tool_execution", "allowed": False, "reason": "mcp_circuit_open", "tool": body.tool, "tenant_id": auth.tenant_id, "subject": auth.subject})
            raise HTTPException(status_code=503, detail="Configured MCP tool circuit is open")
        client: httpx.AsyncClient = request.app.state.mcp_client
        try:
            mcp_result = await call_mcp_tool(
                client,
                endpoint,
                body.tool,
                effective_arguments,
                mcp_tokens.get(body.tool),
                str(policy.get("integrations", {}).get("mcp", {}).get("protocol_version", "2025-06-18")),
                int(policy["limits"].get("max_upstream_response_bytes", 2 * 1024 * 1024)),
            )
            breaker.record_success()
            cleaned_result, redaction_labels = _sanitize_message(mcp_result, pipeline)
            if not isinstance(cleaned_result, dict):
                raise ValueError("MCP result root changed type during output sanitization")
        except (httpx.HTTPError, ValueError, RuntimeError, RecursionError) as exc:
            breaker.record_failure()
            increment_metric("upstream_errors", tenant_id=auth.tenant_id)
            audit.append({"type": "mcp_tool_execution", "allowed": False, "policy_allowed": True, "reason": "mcp_upstream_error", "error": type(exc).__name__, "tool": body.tool, "tenant_id": auth.tenant_id, "subject": auth.subject, "upstream_host": urlsplit(endpoint).netloc})
            raise HTTPException(status_code=502, detail="Configured MCP tool execution failed") from exc

        redactions = sorted(set(redaction_labels))
        increment_metric("redactions", len(redactions), auth.tenant_id)
        audit.append({"type": "mcp_tool_execution", "allowed": True, "policy_allowed": True, "layer": "L3", "reason": "tool_policy_allowed", "tool": body.tool, "tenant_id": auth.tenant_id, "subject": auth.subject, "role": auth.role, "output_layer": "L4" if policy["layers"].get("l4", {}).get("enabled", True) else None, "redactions": redactions, "upstream_host": urlsplit(endpoint).netloc})
        return {"status": "executed", "decision": decision.as_dict(), "result": cleaned_result, "redactions": redactions}

    @app.get("/v1/rag/filter")
    async def rag_filter(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
        auth = await context_from_header(authorization, request)
        if not auth.authenticated:
            reject_auth(request, "authenticated_identity_required")
        return {
            "where": {"tenant_id": auth.tenant_id},
            "source": "verified_jwt_claim",
        }

    @app.post("/v1/rag/query")
    async def rag_query(
        body: RAGQueryRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Run an operator-configured Chroma query with gateway-owned tenancy."""
        require_healthy_audit()
        auth = await context_from_header(authorization, request)
        if not auth.authenticated:
            reject_auth(request, "authenticated_identity_required")
        if rag_adapter is None:
            raise HTTPException(status_code=503, detail="No Chroma RAG adapter is configured")
        started = time.perf_counter()
        decision = pipeline.inspect_input(body.query, auth, auth.tenant_id)
        increment_metric("requests", tenant_id=auth.tenant_id)
        if not decision.allowed:
            record_denial(decision.reason == "rate_limit_exceeded", auth.tenant_id)
            audit.append({"type": "rag_query", "allowed": False, "layer": decision.layer, "reason": decision.reason, "tenant_id": auth.tenant_id, "subject": auth.subject})
            record_latency((time.perf_counter() - started) * 1000, auth.tenant_id)
            raise HTTPException(status_code=403, detail={"blocked": True, "decision": decision.as_dict()})
        audit.append({"type": "rag_query_authorized", "allowed": True, "layer": "L3", "reason": "verified_tenant_scope_applied", "tenant_id": auth.tenant_id, "subject": auth.subject})
        if not rag_breaker.allow_request():
            increment_metric("circuit_open", tenant_id=auth.tenant_id)
            increment_metric("upstream_errors", tenant_id=auth.tenant_id)
            audit.append({"type": "rag_query", "allowed": False, "reason": "rag_circuit_open", "tenant_id": auth.tenant_id, "subject": auth.subject})
            raise HTTPException(status_code=503, detail="Configured RAG retrieval circuit is open")
        retrieval_started = time.perf_counter()
        try:
            query_result = await run_in_threadpool(
                rag_adapter.query, body.query, auth.tenant_id, body.top_k
            )
            rag_breaker.record_success()
            cleaned_result, labels = _sanitize_message(query_result, pipeline)
            if not isinstance(cleaned_result, dict) or not isinstance(cleaned_result.get("matches"), list):
                raise ValueError("Chroma returned an invalid tenant-scoped response")
        except (ValueError, RuntimeError, RecursionError, OSError) as exc:
            rag_breaker.record_failure()
            increment_metric("upstream_errors", tenant_id=auth.tenant_id)
            retrieval_elapsed_ms = (time.perf_counter() - retrieval_started) * 1000
            record_stage_latency("upstream", upstream_timings, retrieval_elapsed_ms, auth.tenant_id)
            audit.append({"type": "rag_query", "allowed": False, "reason": "rag_upstream_error", "error": type(exc).__name__, "tenant_id": auth.tenant_id, "subject": auth.subject})
            elapsed = (time.perf_counter() - started) * 1000
            record_latency(elapsed, auth.tenant_id)
            record_stage_latency("overhead", overhead_timings, elapsed - retrieval_elapsed_ms, auth.tenant_id)
            raise HTTPException(status_code=502, detail="Configured tenant-scoped retrieval failed") from exc
        retrieval_elapsed_ms = (time.perf_counter() - retrieval_started) * 1000
        record_stage_latency("upstream", upstream_timings, retrieval_elapsed_ms, auth.tenant_id)
        discarded = int(cleaned_result.get("discarded_unscoped", 0))
        if discarded:
            audit.append({"type": "rag_scope_violation", "allowed": False, "reason": "chroma_returned_unscoped_records", "discarded_count": discarded, "tenant_id": auth.tenant_id, "subject": auth.subject})
        redactions = sorted(set(labels))
        increment_metric("redactions", len(redactions), auth.tenant_id)
        for match in cleaned_result["matches"]:
            if isinstance(match, dict):
                match["trust_boundary"] = "untrusted_retrieved_content"
        elapsed = (time.perf_counter() - started) * 1000
        record_latency(elapsed, auth.tenant_id)
        record_stage_latency("overhead", overhead_timings, elapsed - retrieval_elapsed_ms, auth.tenant_id)
        audit.append({"type": "rag_query", "allowed": True, "layer": "L3", "reason": "verified_tenant_scope_applied", "tenant_id": auth.tenant_id, "subject": auth.subject, "result_count": len(cleaned_result["matches"]), "discarded_unscoped": discarded, "redactions": redactions, "latency_ms": round(elapsed, 3)})
        return {"tenant_id": auth.tenant_id, "matches": cleaned_result["matches"], "result_count": len(cleaned_result["matches"]), "discarded_unscoped": discarded, "redactions": redactions, "retrieved_content_trust": "untrusted", "model_prompt_composition": "not_performed_by_gateway", "latency_ms": round(elapsed, 3)}

    def verify_dynamic_policy_signature(candidate: dict[str, Any], signature: dict[str, Any] | None) -> None:
        integrity = candidate.get("integrity", {})
        if not integrity.get("require_signature", False):
            if signature is not None:
                key_name = str(integrity.get("verification_key_env", integrity.get("signature_env", "SENTINEL_POLICY_VERIFY_KEY")))
                key = os.getenv(key_name, "")
                valid, reason = verify_policy_signature_record(candidate, signature, key)
                if not valid:
                    raise HTTPException(status_code=422, detail=f"Policy signature verification failed: {reason}")
            return
        key_name = str(integrity.get("verification_key_env", integrity.get("signature_env", "SENTINEL_POLICY_VERIFY_KEY")))
        key = os.getenv(key_name, "")
        valid, reason = verify_policy_signature_record(candidate, signature, key)
        if not valid:
            raise HTTPException(status_code=422, detail=f"Policy signature verification failed: {reason}")

    def ensure_runtime_policy_compatible(candidate: dict[str, Any]) -> None:
        current_static = _runtime_policy_static_projection(policy)
        candidate_static = _runtime_policy_static_projection(candidate)
        if current_static != candidate_static:
            raise HTTPException(
                status_code=409,
                detail="This policy changes controls outside the input regression gate. Only L1/L2 input policy may change live; deploy output DLP, L3/L4, identity, tools, quotas, integrations, and signature changes through a signed gateway rollout.",
            )
        if candidate.get("revision") == policy.get("revision"):
            raise HTTPException(status_code=409, detail="A policy update must use a new revision")

    @app.get("/v1/control/policies")
    async def policy_versions(
        request: Request,
        limit: int = 50,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth = await control_identity(request, authorization, {"platform_admin"})
        records = await run_in_threadpool(control_store.list_policies, limit)
        for record in records:
            record["dry_run_complete"] = await run_in_threadpool(control_store.policy_has_dry_run, record["sha256"])
        return {"active_revision": policy.get("revision", "1"), "active_sha256": canonical_digest(policy), "active_policy": policy, "versions": records, "requested_by": auth.subject}

    @app.post("/v1/control/policies", status_code=201)
    async def stage_policy(
        body: PolicyStageRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth = await control_identity(request, authorization, {"platform_admin"})
        require_healthy_audit()
        try:
            validate_policy(body.policy)
            verify_dynamic_policy_signature(body.policy, body.signature)
            ensure_runtime_policy_compatible(body.policy)
            record = await run_in_threadpool(control_store.stage_policy, body.policy, body.signature, auth.principal_id)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="An identical policy digest already exists") from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        await run_in_threadpool(audit.append, {"type": "policy_version_staged", "allowed": True, "policy_id": record["id"], "revision": record["revision"], "sha256": record["sha256"], "tenant_id": auth.tenant_id, "subject": auth.subject})
        return record

    @app.post("/v1/control/policies/{policy_id}/approve")
    async def approve_policy(
        policy_id: str,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth = await control_identity(request, authorization, {"platform_admin"})
        require_healthy_audit()
        try:
            record = await run_in_threadpool(control_store.approve_policy, policy_id, auth.principal_id)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if record is None:
            raise HTTPException(status_code=404, detail="Policy version was not found")
        await run_in_threadpool(audit.append, {"type": "policy_version_approved", "allowed": True, "policy_id": policy_id, "revision": record["revision"], "subject": auth.subject})
        return record

    @app.post("/v1/control/policies/{policy_id}/activate")
    async def activate_policy(
        policy_id: str,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        nonlocal policy
        auth = await control_identity(request, authorization, {"platform_admin"})
        require_healthy_audit()
        record = await run_in_threadpool(control_store.get_policy, policy_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Policy version was not found")
        candidate = record["policy"]
        try:
            validate_policy(candidate)
            verify_dynamic_policy_signature(candidate, record["signature"])
            ensure_runtime_policy_compatible(candidate)
            active_record = await run_in_threadpool(control_store.activate_policy, policy_id)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if active_record is None:
            raise HTTPException(status_code=404, detail="Policy version was not found")
        policy = candidate
        pipeline.replace_runtime_policy(policy)
        app.state.policy = policy
        await run_in_threadpool(audit.append, {"type": "policy_activated", "allowed": True, "policy_id": policy_id, "revision": policy.get("revision"), "sha256": canonical_digest(policy), "subject": auth.subject})
        return {"status": "active", "id": policy_id, "revision": policy.get("revision"), "sha256": canonical_digest(policy)}

    @app.post("/v1/control/incidents", status_code=201)
    async def create_incident(
        body: IncidentCreateRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth = await control_identity(request, authorization, {"analyst", "admin", "tenant_admin", "platform_admin"})
        require_healthy_audit()
        safe_title, _ = pipeline.sanitize_output(body.title.strip())
        safe_summary, labels = pipeline.sanitize_output(body.summary.strip())
        incident = await run_in_threadpool(control_store.create_incident, auth.tenant_id, safe_title, safe_summary, body.severity, auth.principal_id)
        await run_in_threadpool(audit.append, {"type": "incident_created", "allowed": True, "incident_id": incident["id"], "severity": incident["severity"], "redactions": sorted(set(labels)), "tenant_id": auth.tenant_id, "subject": auth.subject})
        return incident

    @app.get("/v1/control/incidents")
    async def list_incidents(
        request: Request,
        limit: int = 100,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth = await control_identity(request, authorization, {"analyst", "admin", "tenant_admin", "platform_admin"})
        scope = None if auth.role == "platform_admin" else auth.tenant_id
        records = await run_in_threadpool(control_store.list_incidents, scope, limit)
        return {"incidents": records, "scope": "platform" if scope is None else "tenant", "tenant_id": scope}

    @app.patch("/v1/control/incidents/{incident_id}")
    async def update_incident(
        incident_id: str,
        body: IncidentUpdateRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth = await control_identity(request, authorization, {"analyst", "admin", "tenant_admin", "platform_admin"})
        require_healthy_audit()
        existing = await run_in_threadpool(control_store.get_incident, incident_id)
        if existing is None or (auth.role != "platform_admin" and existing["tenant_id"] != auth.tenant_id):
            raise HTTPException(status_code=404, detail="Incident was not found")
        safe_comment = pipeline.sanitize_output(body.comment.strip())[0] if body.comment else None
        safe_assignee = pipeline.sanitize_output(body.assignee.strip())[0] if body.assignee else None
        incident = await run_in_threadpool(control_store.update_incident, incident_id, body.status, safe_assignee, auth.principal_id, safe_comment)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident was not found")
        await run_in_threadpool(audit.append, {"type": "incident_updated", "allowed": True, "incident_id": incident_id, "status": body.status, "tenant_id": existing["tenant_id"], "subject": auth.subject})
        return incident

    @app.get("/v1/control/evaluations/samples")
    async def evaluation_samples(
        request: Request,
        split: Literal["train", "validation", "holdout"] | None = None,
        limit: int = 200,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth = await control_identity(request, authorization, {"analyst", "admin", "evaluator", "platform_admin"})
        if split == "holdout" and auth.role != "platform_admin":
            raise HTTPException(status_code=403, detail="Holdout labels are restricted to platform administrators; evaluators may run aggregate holdout evaluations")
        rows = await run_in_threadpool(control_store.list_samples, split, limit)
        if auth.role != "platform_admin":
            rows = [row for row in rows if row["split"] != "holdout"]
        return {"samples": rows, "count": len(rows), "dataset_sha256": canonical_digest(rows), "holdout_access": auth.role == "platform_admin"}

    @app.post("/v1/control/evaluations/samples", status_code=201)
    async def add_evaluation_sample(
        body: EvaluationSampleRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth = await control_identity(request, authorization, {"evaluator", "platform_admin"})
        require_healthy_audit()
        sample = body.model_dump()
        sample["review_status"] = "ambiguous"
        expected_labels = {
            "benign": ("allow", "benign", "none"),
            "prompt-injection": ("block", "prompt_injection", "direct_instruction_override"),
            "secret-disclosure": ("block", "sensitive_information_disclosure", "direct_exfiltration_request"),
            "roleplay-injection": ("block", "prompt_injection", "roleplay_jailbreak"),
            "developer-override": ("block", "prompt_injection", "developer_role_override"),
            "encoded-injection": ("block", "prompt_injection", "encoded_instruction_payload"),
        }
        labels = expected_labels.get(sample["category"])
        if labels != (sample["expected_disposition"], sample["attack_family"], sample["technique"]):
            raise HTTPException(status_code=422, detail="Category, disposition, attack family, and technique labels are inconsistent")
        if sample["split"] == "holdout" and auth.role != "platform_admin":
            raise HTTPException(status_code=403, detail="Only a platform administrator can add holdout samples")
        try:
            result = await run_in_threadpool(control_store.create_sample, sample, auth.principal_id)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="Evaluation sample ID already exists") from exc
        await run_in_threadpool(audit.append, {"type": "evaluation_sample_added", "allowed": True, "sample_id": result["id"], "category": result["category"], "split": result["split"], "review_status": result["review_status"], "subject": auth.subject})
        return result

    @app.post("/v1/control/evaluations/samples/{sample_id}/review")
    async def review_evaluation_sample(
        sample_id: str,
        body: EvaluationReviewRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth = await control_identity(request, authorization, {"evaluator", "platform_admin"})
        require_healthy_audit()
        sample = await run_in_threadpool(control_store.get_sample, sample_id)
        if sample is None:
            raise HTTPException(status_code=404, detail="Evaluation sample was not found")
        if sample["split"] == "holdout" and auth.role != "platform_admin":
            raise HTTPException(status_code=403, detail="Only a platform administrator can review holdout labels")
        sample_labels = body.model_dump()
        expected_labels = {
            "benign": ("allow", "benign", "none"),
            "prompt-injection": ("block", "prompt_injection", "direct_instruction_override"),
            "secret-disclosure": ("block", "sensitive_information_disclosure", "direct_exfiltration_request"),
            "roleplay-injection": ("block", "prompt_injection", "roleplay_jailbreak"),
            "developer-override": ("block", "prompt_injection", "developer_role_override"),
            "encoded-injection": ("block", "prompt_injection", "encoded_instruction_payload"),
        }
        if expected_labels.get(sample_labels["category"]) != (sample_labels["expected_disposition"], sample_labels["attack_family"], sample_labels["technique"]):
            raise HTTPException(status_code=422, detail="Reviewed label fields do not match the declared category taxonomy")
        try:
            result = await run_in_threadpool(control_store.review_sample, sample_id, sample_labels, auth.principal_id)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="This reviewer already submitted a vote for the sample") from exc
        await run_in_threadpool(audit.append, {"type": "evaluation_label_reviewed", "allowed": True, "sample_id": sample_id, "review_status": result["review_status"] if result else "unknown", "review_count": result["review_count"] if result else 0, "inter_reviewer_agreement": result["inter_reviewer_agreement"] if result else None, "split": sample["split"], "subject": auth.subject})
        return result or {}

    def evaluate_rows(rows: list[dict[str, Any]], selected_policy: dict[str, Any], actor: AuthContext) -> dict[str, Any]:
        scorer = SecurityPipeline(selected_policy, approval_verifier)
        outcomes: dict[str, bool] = {}
        for sample in rows:
            decision = scorer.inspect_input(sample["prompt"], actor, f"evaluation:{sample['id']}")
            outcomes[sample["id"]] = not decision.allowed

        def metrics_for(group: list[dict[str, Any]]) -> dict[str, Any]:
            tp = fp = tn = fn = 0
            for sample in group:
                expected_block = sample["expected_disposition"] == "block"
                blocked = outcomes[sample["id"]]
                if expected_block and blocked:
                    tp += 1
                elif expected_block:
                    fn += 1
                elif blocked:
                    fp += 1
                else:
                    tn += 1
            attack_total, benign_total = tp + fn, fp + tn
            return {"samples": len(group), "tp": tp, "fp": fp, "tn": tn, "fn": fn, "tpr": round(tp / attack_total, 4) if attack_total else None, "fpr": round(fp / benign_total, 4) if benign_total else None, "precision": round(tp / (tp + fp), 4) if tp + fp else None, "benign_block_rate": round(fp / benign_total, 4) if benign_total else None}

        categories = sorted({sample["category"] for sample in rows})
        languages = sorted({sample["language"] for sample in rows})
        review_states = {status: sum(1 for row in rows if row["review_status"] == status) for status in ("human_reviewed", "synthetic_unreviewed", "ambiguous", "in_review", "adjudication_required")}
        return {"overall": metrics_for(rows), "by_category": {category: metrics_for([row for row in rows if row["category"] == category]) for category in categories}, "by_language": {language: metrics_for([row for row in rows if row["language"] == language]) for language in languages}, "review_status_counts": review_states, "human_reviewed_samples": sum(1 for row in rows if row["review_status"] == "human_reviewed" and row.get("review_count", 0) >= 2), "evidence_quality": "human_reviewed" if rows and all(row["review_status"] == "human_reviewed" and row.get("review_count", 0) >= 2 for row in rows) else "mixed_or_synthetic"}

    @app.post("/v1/control/evaluations/run", status_code=201)
    async def run_evaluation(
        body: EvaluationRunRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth = await control_identity(request, authorization, {"evaluator", "platform_admin"})
        require_healthy_audit()
        rows = await run_in_threadpool(control_store.list_samples, body.split, 1000)
        if body.reviewed_only:
            rows = [row for row in rows if row["review_status"] == "human_reviewed" and row.get("review_count", 0) >= 2]
        dataset_digest = canonical_digest(rows)
        policy_digest = canonical_digest(policy)
        metrics = evaluate_rows(rows, policy, auth)
        record = await run_in_threadpool(control_store.save_evaluation_run, dataset_digest, policy_digest, auth.principal_id, {"split": body.split, "reviewed_only": body.reviewed_only, **metrics})
        await run_in_threadpool(audit.append, {"type": "evaluation_run", "allowed": True, "run_id": record["id"], "dataset_sha256": dataset_digest, "policy_sha256": policy_digest, "sample_count": metrics["overall"]["samples"], "evidence_quality": metrics["evidence_quality"], "subject": auth.subject})
        return record

    @app.get("/v1/control/evaluations/runs")
    async def evaluation_runs(
        request: Request,
        limit: int = 50,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        await control_identity(request, authorization, {"evaluator", "platform_admin"})
        records = await run_in_threadpool(control_store.list_evaluation_runs, limit)
        return {"runs": records}

    @app.post("/v1/control/policies/{policy_id}/evaluate", status_code=201)
    async def evaluate_policy_candidate(
        policy_id: str,
        body: EvaluationRunRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth = await control_identity(request, authorization, {"evaluator", "platform_admin"})
        require_healthy_audit()
        record = await run_in_threadpool(control_store.get_policy, policy_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Policy version was not found")
        if body.split != "validation":
            raise HTTPException(status_code=422, detail="Policy promotion dry-runs must use the validation split")
        if not body.reviewed_only:
            raise HTTPException(status_code=422, detail="Policy promotion dry-runs require human-reviewed validation samples")
        try:
            validate_policy(record["policy"])
            verify_dynamic_policy_signature(record["policy"], record["signature"])
            ensure_runtime_policy_compatible(record["policy"])
        except (HTTPException, ValueError) as exc:
            if isinstance(exc, HTTPException):
                raise
            raise HTTPException(status_code=422, detail="Candidate policy is invalid") from exc
        rows = await run_in_threadpool(control_store.list_samples, body.split, 1000)
        if body.reviewed_only:
            rows = [row for row in rows if row["review_status"] == "human_reviewed" and row.get("review_count", 0) >= 2]
        if not rows:
            raise HTTPException(status_code=409, detail="No human-reviewed validation samples are available for this policy dry-run")
        results = evaluate_rows(rows, record["policy"], auth)
        run = await run_in_threadpool(
            control_store.save_evaluation_run,
            canonical_digest(rows),
            record["sha256"],
            auth.principal_id,
            {"split": body.split, "reviewed_only": body.reviewed_only, "candidate_policy_id": policy_id, **results},
        )
        await run_in_threadpool(audit.append, {"type": "policy_dry_run", "allowed": True, "policy_id": policy_id, "run_id": run["id"], "policy_sha256": record["sha256"], "dataset_sha256": canonical_digest(rows), "sample_count": results["overall"]["samples"], "subject": auth.subject})
        return {"policy_id": policy_id, "policy_revision": record["revision"], "policy_sha256": record["sha256"], "dataset_sha256": canonical_digest(rows), "split": body.split, "metrics": results, "run_id": run["id"]}

    @app.post("/v1/identity/api-keys", status_code=201)
    async def create_api_key(
        body: APIKeyCreateRequest,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth = await control_identity(request, authorization, {"admin", "tenant_admin", "platform_admin"})
        require_healthy_audit()
        if auth.role == "platform_admin":
            tenant_id = body.tenant_id
            if not tenant_id:
                raise HTTPException(status_code=422, detail="Platform administrators must specify a tenant_id")
            role = body.role
        else:
            if body.tenant_id and body.tenant_id != auth.tenant_id:
                raise HTTPException(status_code=403, detail="A tenant administrator cannot mint a key for another tenant")
            if body.role == "admin":
                raise HTTPException(status_code=403, detail="Tenant administrators can mint user or analyst keys only")
            tenant_id = auth.tenant_id
            role = body.role
        expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=body.expires_in_days)).isoformat()
        record, token_value = await run_in_threadpool(control_store.issue_api_key, tenant_id, role, body.name, auth.principal_id, expires_at)
        await run_in_threadpool(audit.append, {"type": "api_key_issued", "allowed": True, "key_id": record["id"], "role": role, "tenant_id": tenant_id, "subject": auth.subject})
        return {"key": record, "token": token_value, "warning": "Copy this token now. It will not be shown again."}

    @app.get("/v1/identity/api-keys")
    async def list_api_keys(
        request: Request,
        limit: int = 100,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth = await control_identity(request, authorization, {"admin", "tenant_admin", "platform_admin"})
        scope = None if auth.role == "platform_admin" else auth.tenant_id
        keys = await run_in_threadpool(control_store.list_api_keys, scope, limit)
        return {"keys": keys, "scope": "platform" if scope is None else "tenant"}

    @app.delete("/v1/identity/api-keys/{key_id}", status_code=204)
    async def revoke_api_key(
        key_id: str,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> None:
        auth = await control_identity(request, authorization, {"admin", "tenant_admin", "platform_admin"})
        require_healthy_audit()
        scope = None if auth.role == "platform_admin" else auth.tenant_id
        revoked = await run_in_threadpool(control_store.revoke_api_key, key_id, scope)
        if not revoked:
            raise HTTPException(status_code=404, detail="API key was not found or was already revoked")
        await run_in_threadpool(audit.append, {"type": "api_key_revoked", "allowed": True, "key_id": key_id, "tenant_id": scope or "platform", "subject": auth.subject})
        return None

    @app.post("/v1/identity/api-keys/{key_id}/rotate", status_code=201)
    async def rotate_api_key(
        key_id: str,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        auth = await control_identity(request, authorization, {"admin", "tenant_admin", "platform_admin"})
        require_healthy_audit()
        scope = None if auth.role == "platform_admin" else auth.tenant_id
        rotated = await run_in_threadpool(control_store.rotate_api_key, key_id, scope)
        if rotated is None:
            raise HTTPException(status_code=404, detail="Active API key was not found in this scope")
        record, token_value = rotated
        await run_in_threadpool(audit.append, {"type": "api_key_rotated", "allowed": True, "key_id": record["id"], "rotated_from": key_id, "tenant_id": record["tenant_id"], "subject": auth.subject})
        return {"key": record, "token": token_value, "warning": "The previous key was revoked. Copy this replacement token now; it will not be shown again."}

    return app


app = create_app(os.getenv("SENTINEL_POLICY"))
