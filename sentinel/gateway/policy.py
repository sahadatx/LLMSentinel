"""Policy loading and validation for the gateway."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import re
from pathlib import Path
from typing import Any

import yaml

_REPOSITORY_POLICY = Path(__file__).resolve().parents[2] / "policies" / "default-strict.yaml"
_PACKAGED_POLICY = Path(__file__).resolve().parents[1] / "policies" / "default-strict.yaml"
DEFAULT_POLICY_PATH = _REPOSITORY_POLICY if _REPOSITORY_POLICY.exists() else _PACKAGED_POLICY
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def load_policy(path: str | Path | None = None, verify_signature: bool = True) -> dict[str, Any]:
    policy_path = Path(path) if path else DEFAULT_POLICY_PATH
    with policy_path.open(encoding="utf-8") as stream:
        data = yaml.safe_load(stream)
    if not isinstance(data, dict):
        raise ValueError(f"Policy must be a YAML mapping: {policy_path}")
    validate_policy(data)
    integrity = data.get("integrity", {})
    if verify_signature and integrity.get("require_signature", False):
        key_name = str(integrity.get("verification_key_env", integrity.get("signature_env", "SENTINEL_POLICY_SIGNING_KEY")))
        key = os.getenv(key_name)
        if not key or len(key.encode()) < 32:
            raise ValueError(f"Required policy verification key {key_name} is missing or too short")
        valid, reason = verify_policy_signature(policy_path, data, key)
        if not valid:
            raise ValueError(f"Policy signature verification failed: {reason}")
    return data


def _canonical_policy(policy: dict[str, Any]) -> bytes:
    return json.dumps(
        policy,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def policy_signature_path(path: str | Path) -> Path:
    selected = Path(path)
    return selected.with_name(f"{selected.name}.sig.json")


def write_policy_signature(
    path: str | Path,
    policy: dict[str, Any],
    key: str,
    key_id: str = "default",
    algorithm: str | None = None,
) -> Path:
    """Write a detached HMAC or Ed25519 signature for a validated policy."""
    validate_policy(policy)
    if len(key.encode()) < 32:
        raise ValueError("Policy signing key must contain at least 32 bytes")
    if not key_id or len(key_id) > 128:
        raise ValueError("Policy signing key id must contain 1 to 128 characters")
    payload = _canonical_policy(policy)
    digest = hashlib.sha256(payload).hexdigest()
    selected_algorithm = algorithm or str(policy.get("integrity", {}).get("algorithm", "HMAC-SHA256"))
    if selected_algorithm == "HMAC-SHA256":
        signature = hmac.new(key.encode(), payload, hashlib.sha256).hexdigest()
    elif selected_algorithm == "Ed25519":
        try:
            private_key_bytes = base64.b64decode(key, validate=True)
            if len(private_key_bytes) != 32:
                raise ValueError("Ed25519 private key must be a base64-encoded 32-byte seed")
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            signature = Ed25519PrivateKey.from_private_bytes(private_key_bytes).sign(payload).hex()
        except (binascii.Error, ImportError) as exc:
            raise ValueError("Ed25519 signing requires a valid base64 seed and the enterprise extra") from exc
    else:
        raise ValueError("Policy signature algorithm must be HMAC-SHA256 or Ed25519")
    sidecar = policy_signature_path(path)
    sidecar.write_text(
        json.dumps(
            {
                "algorithm": selected_algorithm,
                "key_id": key_id,
                "policy_sha256": digest,
                "signature": signature,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    try:
        sidecar.chmod(0o600)
    except OSError:
        pass
    return sidecar


def verify_policy_signature(
    path: str | Path, policy: dict[str, Any], key: str
) -> tuple[bool, str | None]:
    """Verify the signed canonical policy body and its detached SHA-256 digest."""
    sidecar = policy_signature_path(path)
    try:
        signature_record = json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, "signature sidecar is missing or malformed"
    return verify_policy_signature_record(policy, signature_record, key)


def verify_policy_signature_record(
    policy: dict[str, Any], signature_record: Any, key: str
) -> tuple[bool, str | None]:
    """Verify a detached signature supplied with an immutable policy candidate."""
    if len(key.encode()) < 32:
        return False, "signing key is missing or too short"
    if not isinstance(signature_record, dict):
        return False, "unsupported signature record"
    try:
        payload = _canonical_policy(policy)
    except (TypeError, ValueError):
        return False, "policy cannot be canonicalized"
    digest = hashlib.sha256(payload).hexdigest()
    if signature_record.get("policy_sha256") != digest:
        return False, "policy digest does not match signature sidecar"
    algorithm = str(policy.get("integrity", {}).get("algorithm", "HMAC-SHA256"))
    if signature_record.get("algorithm") != algorithm:
        return False, "signature algorithm does not match policy"
    signature_value = str(signature_record.get("signature", ""))
    if algorithm == "HMAC-SHA256":
        expected = hmac.new(key.encode(), payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature_value, expected):
            return False, "policy signature is invalid"
    elif algorithm == "Ed25519":
        try:
            public_key_bytes = base64.b64decode(key, validate=True)
            signature_bytes = bytes.fromhex(signature_value)
            if len(public_key_bytes) != 32 or len(signature_bytes) != 64:
                return False, "Ed25519 key or signature has an invalid length"
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            try:
                Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature_bytes, payload)
            except InvalidSignature:
                return False, "policy signature is invalid"
        except (binascii.Error, ImportError, ValueError) as exc:
            return False, f"invalid Ed25519 public key or signature: {type(exc).__name__}"
    else:
        return False, "unsupported signature algorithm"
    return True, None


def validate_policy(policy: dict[str, Any]) -> None:
    required = {"version", "limits", "layers", "tools", "output"}
    missing = required - policy.keys()
    if missing:
        raise ValueError(f"Policy is missing required sections: {', '.join(sorted(missing))}")
    version = policy["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise ValueError("Unsupported policy version; expected 1")
    revision = policy.get("revision", "1")
    if not isinstance(revision, str) or not revision or len(revision) > 64:
        raise ValueError("revision must be a non-empty string of at most 64 characters")
    for section in ("limits", "layers", "tools", "output"):
        if not isinstance(policy[section], dict):
            raise ValueError(f"{section} must be a mapping")

    limits = policy["limits"]
    for key in ("max_request_bytes", "max_input_chars", "requests_per_minute"):
        value = limits.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"limits.{key} must be a positive integer")
    if limits["max_request_bytes"] > 16 * 1024 * 1024:
        raise ValueError("limits.max_request_bytes cannot exceed 16 MiB")
    if limits["max_input_chars"] > 16 * 1024 * 1024:
        raise ValueError("limits.max_input_chars cannot exceed 16 Mi characters")
    if limits["requests_per_minute"] > 1_000_000:
        raise ValueError("limits.requests_per_minute cannot exceed 1,000,000")
    if "require_shared_rate_limit" in limits and not isinstance(limits["require_shared_rate_limit"], bool):
        raise ValueError("limits.require_shared_rate_limit must be a boolean")
    timeout = limits.get("upstream_timeout_seconds", 30)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 600:
        raise ValueError("limits.upstream_timeout_seconds must be a positive finite number no greater than 600 seconds")
    response_bytes = limits.get("max_upstream_response_bytes", 2 * 1024 * 1024)
    if isinstance(response_bytes, bool) or not isinstance(response_bytes, int) or not 1 <= response_bytes <= 16 * 1024 * 1024:
        raise ValueError("limits.max_upstream_response_bytes must be an integer from 1 byte through 16 MiB")
    breaker_failures = limits.get("circuit_breaker_failures", 5)
    if isinstance(breaker_failures, bool) or not isinstance(breaker_failures, int) or not 1 <= breaker_failures <= 100:
        raise ValueError("limits.circuit_breaker_failures must be an integer from 1 through 100")
    breaker_reset = limits.get("circuit_breaker_reset_seconds", 15)
    if isinstance(breaker_reset, bool) or not isinstance(breaker_reset, (int, float)) or not math.isfinite(breaker_reset) or not 0.1 <= breaker_reset <= 300:
        raise ValueError("limits.circuit_breaker_reset_seconds must be from 0.1 through 300 seconds")

    layers = policy["layers"]
    missing_layers = {"l1", "l2", "l3", "l4"} - layers.keys()
    if missing_layers:
        raise ValueError(f"layers is missing: {', '.join(sorted(missing_layers))}")
    for name in ("l1", "l2", "l3", "l4"):
        layer = layers[name]
        if not isinstance(layer, dict):
            raise ValueError(f"layers.{name} must be a mapping")
        if "enabled" in layer and not isinstance(layer["enabled"], bool):
            raise ValueError(f"layers.{name}.enabled must be a boolean")
    for key in ("decode_base64", "decode_hex", "normalize_unicode"):
        if key in layers["l1"] and not isinstance(layers["l1"][key], bool):
            raise ValueError(f"layers.l1.{key} must be a boolean")
    block_patterns = layers["l2"].get("block_patterns", [])
    if not isinstance(block_patterns, list) or len(block_patterns) > 100 or any(not isinstance(item, str) or len(item) > 256 for item in block_patterns):
        raise ValueError("layers.l2.block_patterns must contain at most 100 strings of up to 256 characters")
    if layers["l2"].get("mode", "deterministic_heuristics") != "deterministic_heuristics":
        raise ValueError("layers.l2.mode must be deterministic_heuristics; no local classifier is configured")
    if not layers["l3"].get("enabled", True):
        raise ValueError("layers.l3 cannot be disabled; tool policy must fail closed")
    for key in ("require_tenant_from_verified_jwt", "reject_path_traversal", "validate_json_schema"):
        if key in layers["l3"] and layers["l3"][key] is not True:
            raise ValueError(f"layers.l3.{key} is a required security invariant and cannot be disabled")
    if set(layers["l4"]) - {"enabled"}:
        raise ValueError("layers.l4 supports only the enabled flag; configure output.redact for DLP categories")
    entropy = layers["l1"].get("block_opaque_entropy_bits_per_char", 5.85)
    if isinstance(entropy, bool) or not isinstance(entropy, (int, float)) or not 0 < entropy <= 8:
        raise ValueError("layers.l1.block_opaque_entropy_bits_per_char must be in (0, 8]")

    tools = policy["tools"]
    allow = tools.get("allow")
    if not isinstance(allow, list) or any(not isinstance(name, str) or not name.strip() for name in allow):
        raise ValueError("tools.allow must be a list of non-empty tool names")
    if len(set(allow)) != len(allow):
        raise ValueError("tools.allow cannot contain duplicates")
    allow_set = set(allow)
    tenant_bound = tools.get("tenant_bound", [])
    if not isinstance(tenant_bound, list) or any(not isinstance(name, str) for name in tenant_bound):
        raise ValueError("tools.tenant_bound must be a list of tool names")
    if not set(tenant_bound).issubset(allow_set):
        raise ValueError("tools.tenant_bound must reference only allowlisted tools")
    for group in ("critical",):
        values = tools.get(group, [])
        if not isinstance(values, list) or any(not isinstance(name, str) for name in values):
            raise ValueError(f"tools.{group} must be a list of tool names")
        if not set(values).issubset(allow_set):
            raise ValueError(f"tools.{group} must reference only allowlisted tools")
    roles = tools.get("roles", {})
    if not isinstance(roles, dict):
        raise ValueError("tools.roles must be a mapping")
    for name, values in roles.items():
        if name not in allow_set or not isinstance(values, list) or not values or any(not isinstance(role, str) or not role for role in values):
            raise ValueError(f"tools.roles.{name} must list one or more roles for an allowlisted tool")
    schemas = tools.get("schemas", {})
    if not isinstance(schemas, dict):
        raise ValueError("tools.schemas must be a mapping")
    valid_types = {"string", "integer", "number", "boolean", "object", "array", "null"}
    for name, schema in schemas.items():
        if name not in allow_set or not isinstance(schema, dict):
            raise ValueError(f"tools.schemas.{name} must describe an allowlisted tool")
        if set(schema) - {"required", "properties", "additionalProperties"}:
            raise ValueError(f"tools.schemas.{name} uses unsupported schema keywords")
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list) or any(not isinstance(key, str) for key in required):
            raise ValueError(f"tools.schemas.{name} has invalid properties or required fields")
        if len(set(required)) != len(required):
            raise ValueError(f"tools.schemas.{name}.required cannot contain duplicates")
        if not set(required).issubset(properties):
            raise ValueError(f"tools.schemas.{name}.required must be declared in properties")
        if not isinstance(schema.get("additionalProperties", True), bool):
            raise ValueError(f"tools.schemas.{name}.additionalProperties must be a boolean")
        for field, definition in properties.items():
            if not isinstance(field, str) or not isinstance(definition, dict) or set(definition) != {"type"} or definition.get("type") not in valid_types:
                raise ValueError(f"tools.schemas.{name}.properties.{field} has an unsupported type")
    for name in tenant_bound:
        schema = schemas.get(name)
        if (
            isinstance(schema, dict)
            and schema.get("additionalProperties") is False
            and "tenant_id" not in schema.get("properties", {})
        ):
            raise ValueError(f"tools.schemas.{name} must declare tenant_id for tenant-bound tools")

    auth = policy.get("auth", {})
    if not isinstance(auth, dict):
        raise ValueError("auth must be a mapping")
    if "require_auth" in auth and not isinstance(auth["require_auth"], bool):
        raise ValueError("auth.require_auth must be a boolean")
    for key in ("secret_env", "issuer", "audience", "jwks_url_env", "issuer_env", "audience_env", "tenant_claim", "role_claim"):
        if key in auth and not isinstance(auth[key], str):
            raise ValueError(f"auth.{key} must be a string")
    if not _ENVIRONMENT_NAME.fullmatch(str(auth.get("secret_env", "SENTINEL_JWT_SECRET"))):
        raise ValueError("auth.secret_env must be a valid environment variable name")
    auth_mode = auth.get("mode", "hs256")
    if not isinstance(auth_mode, str) or auth_mode not in {"hs256", "oidc"}:
        raise ValueError("auth.mode must be hs256 or oidc")
    if auth.get("require_auth", False):
        if auth_mode == "hs256" and (not auth.get("issuer") or not auth.get("audience")):
            raise ValueError("Authenticated HS256 policy requires explicit issuer and audience")
        if auth_mode == "oidc":
            for env_field in ("jwks_url_env", "issuer_env", "audience_env"):
                if not _ENVIRONMENT_NAME.fullmatch(str(auth.get(env_field, ""))):
                    raise ValueError(f"auth.{env_field} must name a configured environment variable")
            algorithms = auth.get("algorithms", ["RS256", "ES256"])
            if not isinstance(algorithms, list) or not algorithms or any(
                algorithm not in {"RS256", "ES256", "EdDSA"} for algorithm in algorithms
            ):
                raise ValueError("auth.algorithms must be a non-empty list of supported asymmetric algorithms")
    role_mappings = auth.get("role_mappings", {})
    if not isinstance(role_mappings, dict) or any(
        not isinstance(role, str)
        or not role
        or not isinstance(groups, list)
        or not groups
        or any(not isinstance(group, str) or not group for group in groups)
        for role, groups in role_mappings.items()
    ):
        raise ValueError("auth.role_mappings must map role names to non-empty group lists")
    for key in ("issuer", "audience"):
        if key in auth and (not auth[key] or len(auth[key]) > 512):
            raise ValueError(f"auth.{key} must be a non-empty string of at most 512 characters")
    redact = policy["output"].get("redact", [])
    known_redactors = {"aws_access_key", "openai_key", "private_key", "email"}
    if not isinstance(redact, list) or any(not isinstance(item, str) or item not in known_redactors for item in redact):
        raise ValueError("output.redact must list supported redactor names")
    if len(set(redact)) != len(redact):
        raise ValueError("output.redact cannot contain duplicates")
    if "canary" in policy["output"] and not isinstance(policy["output"]["canary"], str):
        raise ValueError("output.canary must be a string")
    integrity = policy.get("integrity", {})
    if not isinstance(integrity, dict):
        raise ValueError("integrity must be a mapping")
    if "require_signature" in integrity and not isinstance(integrity["require_signature"], bool):
        raise ValueError("integrity.require_signature must be a boolean")
    signature_env = integrity.get("signature_env", "SENTINEL_POLICY_SIGNING_KEY")
    if not isinstance(signature_env, str) or not _ENVIRONMENT_NAME.fullmatch(signature_env):
        raise ValueError("integrity.signature_env must be a valid environment variable name")
    verification_key_env = integrity.get("verification_key_env", signature_env)
    if not isinstance(verification_key_env, str) or not _ENVIRONMENT_NAME.fullmatch(verification_key_env):
        raise ValueError("integrity.verification_key_env must be a valid environment variable name")
    signature_algorithm = integrity.get("algorithm", "HMAC-SHA256")
    if not isinstance(signature_algorithm, str) or signature_algorithm not in {"HMAC-SHA256", "Ed25519"}:
        raise ValueError("integrity.algorithm must be HMAC-SHA256 or Ed25519")
    integrations = policy.get("integrations", {})
    if not isinstance(integrations, dict):
        raise ValueError("integrations must be a mapping")
    mcp = integrations.get("mcp", {})
    if not isinstance(mcp, dict) or not isinstance(mcp.get("protocol_version", "2025-06-18"), str):
        raise ValueError("integrations.mcp must be a mapping with a protocol_version string")
    approval = policy.get("approval", {})
    if not isinstance(approval, dict) or not isinstance(approval.get("secret_env", "SENTINEL_APPROVAL_SECRET"), str):
        raise ValueError("approval.secret_env must be a string")
    if "require_shared_replay" in approval and not isinstance(approval["require_shared_replay"], bool):
        raise ValueError("approval.require_shared_replay must be a boolean")
    if not _ENVIRONMENT_NAME.fullmatch(approval.get("secret_env", "SENTINEL_APPROVAL_SECRET")):
        raise ValueError("approval.secret_env must be a valid environment variable name")
    telemetry = policy.get("telemetry", {})
    if not isinstance(telemetry, dict):
        raise ValueError("telemetry must be a mapping")
    telemetry_roles = telemetry.get("roles", ["admin", "analyst", "platform_admin"])
    if not isinstance(telemetry_roles, list) or any(not isinstance(role, str) or not role for role in telemetry_roles):
        raise ValueError("telemetry.roles must be a list of non-empty role names")
