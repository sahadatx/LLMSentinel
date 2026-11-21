"""Deterministic L1-L4 request and response controls."""

from __future__ import annotations

import ast
import base64
import binascii
import hashlib
import ipaddress
import math
import re
import threading
import time
import unicodedata
from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit

from sentinel.gateway.approvals import ApprovalVerifier
from sentinel.gateway.auth import AuthContext

_HOMOGLYPHS = str.maketrans({"а": "a", "е": "e", "і": "i", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y"})
_SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
]
_JAILBREAK_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
    re.compile(r"(reveal|print|show|repeat)\s+(the\s+)?(system\s+prompt|hidden\s+instructions|secret|credentials?)", re.I),
    re.compile(r"(developer|system)\s+message\s*:\s*", re.I),
    re.compile(r"\bDAN\s+mode\b", re.I),
]
_INJECTION_CHARS = re.compile(r"(?:\.\./|%2e%2e%2f|\bunion\s+select\b|;\s*(?:drop|delete)\s+table\b)", re.I)
_ACTIVE_HTML = re.compile(r"<\s*(script|iframe|object|embed)\b[^>]*>[\s\S]*?<\s*/\s*\1\s*>", re.I)
_JAVASCRIPT_URL = re.compile(r"javascript\s*:", re.I)
_PYTHON_FENCE = re.compile(r"```(?:python|py)\s*\n([\s\S]*?)```", re.I)
_RISKY_PYTHON_CALLS = {"eval", "exec", "os.system", "subprocess.run", "subprocess.Popen", "pickle.loads"}


def _ast_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _has_unsafe_python(code: str) -> bool:
    if len(code) > 65_536:
        return True
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False
    except RecursionError:
        return True
    pending: list[ast.AST] = [tree]
    visited = 0
    while pending:
        node = pending.pop()
        visited += 1
        if visited > 50_000:
            return True
        if isinstance(node, ast.Call) and _ast_name(node.func) in _RISKY_PYTHON_CALLS:
            return True
        pending.extend(ast.iter_child_nodes(node))
    return False


def _bounded_argument_text(arguments: dict[str, Any]) -> str | None:
    parts: list[str] = []
    pending: list[tuple[Any, int]] = [(arguments, 0)]
    visited = 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        if visited > 10_000 or depth > 32:
            return None
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            children: list[tuple[Any, int]] = []
            for key, child in value.items():
                if isinstance(key, str):
                    children.append((key, depth + 1))
                children.append((child, depth + 1))
            pending.extend(reversed(children))
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in reversed(value))
        elif value is None or isinstance(value, (bool, int)):
            continue
        elif isinstance(value, float) and math.isfinite(value):
            continue
        else:
            return None
    return "\n".join(parts)


@dataclass
class Decision:
    allowed: bool
    layer: str
    reason: str
    normalized_text: str
    score: float = 0.0
    tenant_id: str = "public"
    details: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        # Never echo normalized prompt content in routine policy responses.
        result = asdict(self)
        result.pop("normalized_text", None)
        return result


class TokenBucket:
    _REDIS_SCRIPT = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_per_second = tonumber(ARGV[2])
local now_parts = redis.call('TIME')
local now_ms = tonumber(now_parts[1]) * 1000 + math.floor(tonumber(now_parts[2]) / 1000)
local state = redis.call('HMGET', key, 'tokens', 'updated_ms')
local tokens = tonumber(state[1]) or capacity
local updated_ms = tonumber(state[2]) or now_ms
tokens = math.min(capacity, tokens + math.max(0, now_ms - updated_ms) * refill_per_second / 1000)
if tokens < 1 then
  redis.call('HMSET', key, 'tokens', tokens, 'updated_ms', now_ms)
  redis.call('PEXPIRE', key, math.ceil((capacity / refill_per_second) * 2000))
  return 0
end
tokens = tokens - 1
redis.call('HMSET', key, 'tokens', tokens, 'updated_ms', now_ms)
redis.call('PEXPIRE', key, math.ceil((capacity / refill_per_second) * 2000))
return 1
"""

    def __init__(self, capacity: int, refill_per_second: float, redis_url: str | None = None):
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._state: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()
        self._redis: Any | None = None
        if redis_url:
            parsed = urlsplit(redis_url)
            hostname = (parsed.hostname or "").lower()
            try:
                loopback = bool(hostname) and ipaddress.ip_address(hostname).is_loopback
            except ValueError:
                loopback = hostname == "localhost"
            if parsed.scheme not in {"redis", "rediss"} or not hostname or (
                parsed.scheme == "redis" and not loopback
            ):
                raise ValueError("Shared rate-limit Redis must use rediss:// outside loopback development")
            try:
                import redis
            except ImportError as exc:  # pragma: no cover - depends on the optional install
                raise RuntimeError("Install LLMSentinel with the 'enterprise' extra to use shared rate limits") from exc
            self._redis = redis.Redis.from_url(
                redis_url,
                decode_responses=True,
                socket_connect_timeout=1,
                socket_timeout=1,
                health_check_interval=30,
            )

    def allow(self, key: str) -> bool:
        if self._redis is not None:
            redis_key = "llmsentinel:rate:" + hashlib.sha256(key.encode()).hexdigest()
            try:
                result = self._redis.eval(
                    self._REDIS_SCRIPT, 1, redis_key, self.capacity, self.refill_per_second
                )
                return bool(int(result))
            except Exception:
                # Shared-state failure is fail-closed; never silently reset quotas per worker.
                return False
        now = time.monotonic()
        with self._lock:
            if key not in self._state and len(self._state) >= 10_000:
                stale = [old_key for old_key, (_, last_seen) in self._state.items() if now - last_seen > 120]
                for old_key in stale:
                    self._state.pop(old_key, None)
                if len(self._state) >= 10_000:
                    self._state.pop(next(iter(self._state)))
            tokens, last = self._state.get(key, (float(self.capacity), now))
            tokens = min(float(self.capacity), tokens + (now - last) * self.refill_per_second)
            if tokens < 1:
                self._state[key] = (tokens, now)
                return False
            self._state[key] = (tokens - 1, now)
            return True

    def check_health(self) -> bool:
        if self._redis is None:
            return True
        try:
            return bool(self._redis.ping())
        except Exception:
            return False


def _decode_layers(value: str, decode_base64: bool = True, decode_hex: bool = True) -> str:
    chunks = [value]
    candidate = value.strip()
    if decode_base64:
        for _ in range(2):
            try:
                decoded = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
            except (binascii.Error, ValueError):
                break
            if not decoded or decoded == candidate:
                break
            chunks.append(decoded)
            candidate = decoded.strip()
    if decode_hex:
        hex_match = re.fullmatch(r"(?:[0-9a-fA-F]{2}[\s:]*){8,}", candidate)
        if hex_match:
            try:
                chunks.append(bytes.fromhex(re.sub(r"[\s:]", "", candidate)).decode("utf-8", errors="ignore"))
            except ValueError:
                pass
    return "\n".join(chunks)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in Counter(value).values())


class SecurityPipeline:
    def __init__(
        self,
        policy: dict[str, Any],
        approval_verifier: ApprovalVerifier | None = None,
        rate_limit_redis_url: str | None = None,
    ):
        self.policy = policy
        self.approval_verifier = approval_verifier or ApprovalVerifier()
        limits = policy["limits"]
        rpm = int(limits["requests_per_minute"])
        self.bucket = TokenBucket(rpm, rpm / 60, rate_limit_redis_url)
        self._custom_patterns = [
            re.compile(re.escape(phrase.strip()).replace(r"\ ", r"\s+"), re.I)
            for phrase in policy["layers"]["l2"].get("block_patterns", [])
            if phrase.strip()
        ]

    def replace_runtime_policy(self, policy: dict[str, Any]) -> None:
        """Atomically replace the validated runtime policy sections used by inspectors."""
        self.policy = policy
        self._custom_patterns = [
            re.compile(re.escape(phrase.strip()).replace(r"\ ", r"\s+"), re.I)
            for phrase in policy["layers"]["l2"].get("block_patterns", [])
            if phrase.strip()
        ]

    def inspect_input(self, text: str | Sequence[str], auth: AuthContext, client_key: str = "local") -> Decision:
        layer1 = self.policy["layers"].get("l1", {})
        chunks = [text] if isinstance(text, str) else list(text)
        limits = self.policy["limits"]
        if not self.bucket.allow(client_key):
            return Decision(False, "L1", "rate_limit_exceeded", "", tenant_id=auth.tenant_id)
        max_input_chars = int(limits["max_input_chars"])
        if sum(len(chunk) for chunk in chunks) > max_input_chars:
            return Decision(False, "L1", "input_too_large", "", tenant_id=auth.tenant_id)
        normalized_chunks = [
            unicodedata.normalize("NFKC", chunk).translate(_HOMOGLYPHS)
            if layer1.get("normalize_unicode", True)
            else chunk
            for chunk in chunks
        ]
        if sum(len(chunk) for chunk in normalized_chunks) > max_input_chars:
            return Decision(False, "L1", "input_too_large", "", tenant_id=auth.tenant_id)
        normalized = "\n".join(normalized_chunks)
        decoded = "\n".join(
            _decode_layers(chunk, bool(layer1.get("decode_base64", True)), bool(layer1.get("decode_hex", True)))
            for chunk in normalized_chunks
        )
        evidence = (normalized + "\n" + decoded).lower()
        if layer1.get("enabled", True):
            if _INJECTION_CHARS.search(evidence):
                return Decision(False, "L1", "encoded_or_injection_pattern", normalized, 1.0, auth.tenant_id)
            # Entropy is a triage signal only; block only long, high-entropy opaque strings.
            tokens = re.findall(r"[A-Za-z0-9+/=_-]{80,}", normalized)
            threshold = float(layer1.get("block_opaque_entropy_bits_per_char", 5.85))
            if any(_entropy(token) >= threshold for token in tokens):
                return Decision(False, "L1", "opaque_high_entropy_payload", normalized, 0.85, auth.tenant_id)
        if self.policy["layers"].get("l2", {}).get("enabled", True):
            patterns = [*_JAILBREAK_PATTERNS, *self._custom_patterns]
            matched = [pattern.pattern for pattern in patterns if pattern.search(evidence)]
            if matched:
                return Decision(False, "L2", "prompt_injection_heuristic", normalized, min(0.99, 0.78 + 0.05 * len(matched)), auth.tenant_id, {"patterns": matched})
        return Decision(True, "ALLOW", "no_policy_violation", normalized, 0.0, auth.tenant_id)

    def inspect_tool(self, tool_name: str, arguments: dict[str, Any], auth: AuthContext, approval_token: str | None = None) -> Decision:
        tool_policy = self.policy["tools"]
        if not self.policy["layers"].get("l3", {}).get("enabled", True):
            return Decision(False, "L3", "tool_policy_disabled", "", 1.0, auth.tenant_id)
        allowed_tools = set(tool_policy.get("allow", []))
        roles = tool_policy.get("roles", {})
        if tool_name not in allowed_tools:
            return Decision(False, "L3", "tool_not_allowlisted", "", 1.0, auth.tenant_id, {"tool": tool_name})
        permitted_roles = roles.get(tool_name, ["admin"])
        if auth.role not in permitted_roles:
            return Decision(False, "L3", "role_not_authorized", "", 1.0, auth.tenant_id, {"tool": tool_name, "role": auth.role})
        if tool_name in tool_policy.get("tenant_bound", []):
            requested_tenant = arguments.get("tenant_id")
            if requested_tenant is not None and requested_tenant != auth.tenant_id:
                return Decision(False, "L3", "tenant_scope_mismatch", "", 1.0, auth.tenant_id, {"tool": tool_name})
        serialized = _bounded_argument_text(arguments)
        if serialized is None:
            return Decision(False, "L3", "tool_argument_complexity_limit", "", 1.0, auth.tenant_id, {"tool": tool_name})
        if _INJECTION_CHARS.search(serialized):
            return Decision(False, "L3", "unsafe_tool_argument", "", 1.0, auth.tenant_id, {"tool": tool_name})
        schema = tool_policy.get("schemas", {}).get(tool_name)
        if schema:
            required = schema.get("required", [])
            properties = schema.get("properties", {})
            missing = [name for name in required if name not in arguments]
            unknown = [name for name in arguments if name not in properties] if schema.get("additionalProperties") is False else []
            wrong_types = []
            for name, value in arguments.items():
                expected = properties.get(name, {}).get("type")
                actual = "boolean" if isinstance(value, bool) else "integer" if isinstance(value, int) else "number" if isinstance(value, float) else "string" if isinstance(value, str) else "object" if isinstance(value, dict) else "array" if isinstance(value, list) else "null"
                if expected and actual != expected and not (expected == "number" and actual == "integer"):
                    wrong_types.append(name)
            if missing or unknown or wrong_types:
                return Decision(False, "L3", "tool_argument_schema_violation", "", 1.0, auth.tenant_id, {"tool": tool_name, "missing": missing, "unknown": unknown, "wrong_types": wrong_types})
        critical = set(tool_policy.get("critical", []))
        if tool_name in critical:
            if not auth.authenticated or not auth.subject:
                return Decision(False, "L3", "authentication_required_for_critical_tool", "", 1.0, auth.tenant_id, {"tool": tool_name})
            if not approval_token:
                return Decision(False, "L3", "human_approval_required", "", 1.0, auth.tenant_id, {"tool": tool_name})
            approved, reason = self.approval_verifier.verify(approval_token, auth, tool_name, arguments)
            if not approved:
                return Decision(False, "L3", reason, "", 1.0, auth.tenant_id, {"tool": tool_name})
        return Decision(True, "L3", "tool_policy_allowed", "", 0.0, auth.tenant_id, {"tool": tool_name, "injected_tenant_id": auth.tenant_id})

    def bind_tool_tenant(self, tool_name: str, arguments: dict[str, Any], auth: AuthContext) -> dict[str, Any]:
        """Inject verified tenant identity into explicitly tenant-bound tools."""
        if tool_name not in self.policy["tools"].get("tenant_bound", []):
            return dict(arguments)
        requested_tenant = arguments.get("tenant_id")
        if requested_tenant is not None and requested_tenant != auth.tenant_id:
            raise ValueError("tool arguments attempted to override the verified tenant")
        bound = dict(arguments)
        bound["tenant_id"] = auth.tenant_id
        return bound

    def sanitize_output(self, text: str) -> tuple[str, list[str]]:
        if not self.policy["layers"].get("l4", {}).get("enabled", True):
            return text, []
        redactions: list[str] = []
        clean = text
        configured_redactions = set(self.policy["output"].get("redact", [label for label, _ in _SECRET_PATTERNS]))
        for label, pattern in _SECRET_PATTERNS:
            if label not in configured_redactions:
                continue
            clean, count = pattern.subn(f"[REDACTED:{label}]", clean)
            if count:
                redactions.append(label)
        clean, html_count = _ACTIVE_HTML.subn("[REDACTED:active_html]", clean)
        if html_count:
            redactions.append("active_html")
        clean, js_count = _JAVASCRIPT_URL.subn("[REDACTED:javascript_url]", clean)
        if js_count:
            redactions.append("javascript_url")
        unsafe_code = False

        def redact_code(match: re.Match[str]) -> str:
            nonlocal unsafe_code
            if _has_unsafe_python(match.group(1)):
                unsafe_code = True
                return "[REDACTED:unsafe_executable_code]"
            return match.group(0)

        clean = _PYTHON_FENCE.sub(redact_code, clean)
        if unsafe_code:
            redactions.append("unsafe_executable_code")
        canary = str(self.policy["output"].get("canary", "CANARY_SECRET_9941_ALPHA"))
        if canary and canary in clean:
            clean = clean.replace(canary, "[REDACTED:canary]")
            redactions.append("canary")
        return clean, redactions
