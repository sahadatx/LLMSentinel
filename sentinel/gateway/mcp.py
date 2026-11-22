"""Bounded, policy-gated proxy calls to operator-configured MCP servers."""

from __future__ import annotations

import ipaddress
import json
from typing import Any
from urllib.parse import urlsplit

import httpx


def load_tool_endpoints(raw: str, allowlisted_tools: set[str]) -> dict[str, str]:
    if not raw.strip():
        return {}
    if len(raw) > 32_768:
        raise ValueError("SENTINEL_MCP_TOOL_ENDPOINTS exceeds 32 KiB")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("SENTINEL_MCP_TOOL_ENDPOINTS must be a JSON object") from exc
    if not isinstance(value, dict) or len(value) > 100:
        raise ValueError("SENTINEL_MCP_TOOL_ENDPOINTS must map at most 100 tool names to URLs")
    endpoints: dict[str, str] = {}
    for tool, endpoint in value.items():
        if not isinstance(tool, str) or tool not in allowlisted_tools:
            raise ValueError(f"MCP endpoint references non-allowlisted tool: {tool}")
        if not isinstance(endpoint, str) or len(endpoint) > 2048:
            raise ValueError(f"MCP endpoint for {tool} must be an HTTP(S) URL")
        parsed = urlsplit(endpoint)
        hostname = (parsed.hostname or "").lower()
        try:
            _ = parsed.port
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
        ):
            raise ValueError(f"MCP endpoint for {tool} must use HTTPS outside loopback and contain no credentials/query")
        endpoints[tool] = endpoint.rstrip("/")
    return endpoints


def load_tool_tokens(raw: str) -> dict[str, str]:
    if not raw.strip():
        return {}
    if len(raw) > 32_768:
        raise ValueError("SENTINEL_MCP_TOOL_TOKENS exceeds 32 KiB")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("SENTINEL_MCP_TOOL_TOKENS must be a JSON object") from exc
    if not isinstance(value, dict) or len(value) > 100:
        raise ValueError("SENTINEL_MCP_TOOL_TOKENS must map at most 100 tool names to tokens")
    tokens: dict[str, str] = {}
    for tool, token in value.items():
        if not isinstance(tool, str) or not isinstance(token, str) or not token or len(token) > 8192:
            raise ValueError("MCP service tokens must be non-empty strings no longer than 8 KiB")
        tokens[tool] = token
    return tokens


async def _read_json_rpc_response(
    response: httpx.Response, max_response_bytes: int, expected_id: int | None = None
) -> dict[str, Any]:
    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError("MCP server returned a non-success status")
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > max_response_bytes:
            raise RuntimeError("MCP response exceeded the configured byte limit")
        chunks.append(chunk)
    raw = b"".join(chunks).decode("utf-8", errors="strict")
    content_type = response.headers.get("content-type", "").lower()
    if "text/event-stream" in content_type:
        events = [line[5:].strip() for line in raw.splitlines() if line.startswith("data:")]
        parsed_events: list[Any] = []
        for event in events:
            if event and event != "[DONE]":
                parsed_events.append(json.loads(event))
        message = next(
            (item for item in reversed(parsed_events) if isinstance(item, dict) and ("result" in item or "error" in item)),
            None,
        )
    elif "application/json" in content_type:
        message = json.loads(raw) if raw else {}
    else:
        raise RuntimeError("MCP server returned an unsupported content type")
    if not isinstance(message, dict):
        raise RuntimeError("MCP server returned an invalid JSON-RPC response")
    if expected_id is not None and message.get("id") != expected_id:
        raise RuntimeError("MCP server returned an unexpected JSON-RPC response id")
    return message


async def _discard_bounded_body(response: httpx.Response, max_response_bytes: int) -> None:
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > max_response_bytes:
            raise RuntimeError("MCP notification response exceeded the configured byte limit")


async def _close_mcp_session(
    client: httpx.AsyncClient,
    endpoint: str,
    headers: dict[str, str],
    max_response_bytes: int,
) -> None:
    """Best-effort cleanup for servers that issued stateful sessions."""
    try:
        async with client.stream("DELETE", endpoint, headers=headers, timeout=httpx.Timeout(2.0)) as response:
            await _discard_bounded_body(response, max_response_bytes)
    except Exception:
        # Session cleanup is advisory in the MCP transport specification. A
        # server that does not implement DELETE must not erase a tool result.
        return


async def call_mcp_tool(
    client: httpx.AsyncClient,
    endpoint: str,
    tool: str,
    arguments: dict[str, Any],
    service_token: str | None,
    protocol_version: str,
    max_response_bytes: int,
) -> dict[str, Any]:
    """Negotiate a fresh Streamable HTTP session and execute one JSON-RPC call.

    The gateway never forwards the caller's bearer token. Only the dedicated
    service credential configured for this exact tool is sent upstream.
    """
    init_headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if service_token:
        init_headers["Authorization"] = f"Bearer {service_token}"

    async with client.stream(
        "POST",
        endpoint,
        headers=init_headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "llmsentinel-gateway", "version": "3.0.0"},
            },
        },
    ) as response:
        initialized = await _read_json_rpc_response(response, max_response_bytes, expected_id=1)
        session_id = response.headers.get("mcp-session-id")
    if "error" in initialized:
        raise RuntimeError("MCP initialization was rejected")
    init_result = initialized.get("result")
    negotiated_value = init_result.get("protocolVersion") if isinstance(init_result, dict) else None
    if negotiated_value != protocol_version:
        raise RuntimeError("MCP server negotiated an unsupported protocol version")
    if session_id is not None and (
        not session_id or len(session_id) > 4096 or any(not 0x21 <= ord(char) <= 0x7E for char in session_id)
    ):
        raise RuntimeError("MCP server returned an invalid session id")
    request_headers: dict[str, str] = {
        **init_headers,
        "MCP-Protocol-Version": protocol_version,
    }
    if isinstance(session_id, str) and session_id:
        request_headers["Mcp-Session-Id"] = session_id

    try:
        async with client.stream(
            "POST",
            endpoint,
            headers=request_headers,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        ) as response:
            if response.status_code < 200 or response.status_code >= 300:
                raise RuntimeError("MCP server rejected the initialized notification")
            # Notification responses normally have no body; consume only a bounded
            # diagnostic body if the server sends one.
            await _discard_bounded_body(response, max_response_bytes)

        async with client.stream(
            "POST",
            endpoint,
            headers=request_headers,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments},
            },
        ) as response:
            result = await _read_json_rpc_response(response, max_response_bytes, expected_id=2)
        if "error" in result:
            error = result.get("error")
            if isinstance(error, dict):
                raise RuntimeError("MCP tool call returned a JSON-RPC error")
            raise RuntimeError("MCP tool call failed")
        body = result.get("result")
        if not isinstance(body, dict):
            raise RuntimeError("MCP tool call returned an invalid result")
        return body
    finally:
        if isinstance(session_id, str) and session_id:
            await _close_mcp_session(client, endpoint, request_headers, max_response_bytes)
