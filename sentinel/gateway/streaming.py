"""Fail-closed OpenAI-compatible SSE response inspection and redaction."""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from typing import Any

from sentinel.gateway.pipeline import SecurityPipeline


_PRIVATE_KEY_START = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_PRIVATE_KEY_END = re.compile(r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_PARTIAL_PRIVATE_KEY = re.compile(r"-----BEGIN(?: [A-Z]+){0,3}(?: PRIVATE(?: KEY)?)?\s*$")
_ACTIVE_HTML_START = re.compile(r"<\s*(script|iframe|object|embed)\b[^>]*>", re.I)
_PYTHON_FENCE_START = re.compile(r"```(?:python|py)\s*\n", re.I)
_MAX_PENDING = 64 * 1024
_LOOKBEHIND = 256


class StreamingOutputGuard:
    """Delay incomplete tokens so secrets split across provider chunks are never emitted."""

    def __init__(self, pipeline: SecurityPipeline) -> None:
        self.pipeline = pipeline
        self.pending = ""
        self.in_private_key = False
        self.pending_block: tuple[str, re.Pattern[str]] | None = None
        self.labels: set[str] = set()

    def _sanitize(self, value: str) -> str:
        safe, labels = self.pipeline.sanitize_output(value)
        self.labels.update(labels)
        return safe

    def feed(self, fragment: str, final: bool = False) -> str:
        self.pending += fragment
        output: list[str] = []

        while self.pending:
            if self.pending_block is not None:
                label, ending = self.pending_block
                footer = ending.search(self.pending)
                if footer is None:
                    if len(self.pending) > _MAX_PENDING:
                        raise ValueError(f"streamed {label} candidate exceeded the safety limit")
                    if final:
                        output.append(f"[REDACTED:{label}]")
                        self.labels.add(label)
                        self.pending = ""
                        self.pending_block = None
                    break
                block_end = footer.end()
                block = self.pending[:block_end]
                output.append(self._sanitize(block))
                self.pending = self.pending[block_end:]
                self.pending_block = None
                continue

            if self.in_private_key:
                footer = _PRIVATE_KEY_END.search(self.pending)
                if footer is None:
                    if len(self.pending) > _MAX_PENDING:
                        raise ValueError("streamed private-key candidate exceeded the safety limit")
                    if final:
                        self.pending = ""
                    break
                self.pending = self.pending[footer.end() :]
                self.in_private_key = False
                continue

            header = _PRIVATE_KEY_START.search(self.pending)
            if header is not None:
                output.append(self._sanitize(self.pending[: header.start()]))
                output.append("[REDACTED:private_key]")
                self.labels.add("private_key")
                self.pending = self.pending[header.end() :]
                self.in_private_key = True
                continue

            html_start = _ACTIVE_HTML_START.search(self.pending)
            python_start = _PYTHON_FENCE_START.search(self.pending)
            candidates: list[tuple[int, str, re.Pattern[str]]] = []
            if html_start is not None:
                candidates.append(
                    (
                        html_start.start(),
                        "active_html",
                        re.compile(r"<\s*/\s*" + html_start.group(1) + r"\s*>", re.I),
                    )
                )
            if python_start is not None:
                candidates.append((python_start.start(), "unsafe_executable_code", re.compile(r"```")))
            if candidates:
                start, label, ending = min(candidates, key=lambda item: item[0])
                output.append(self._sanitize(self.pending[:start]))
                self.pending = self.pending[start:]
                self.pending_block = (label, ending)
                continue

            if final:
                # A truncated PEM header is treated as sensitive and discarded.
                partial = _PARTIAL_PRIVATE_KEY.search(self.pending)
                if partial is not None:
                    output.append(self._sanitize(self.pending[: partial.start()]))
                    output.append("[REDACTED:private_key]")
                    self.labels.add("private_key")
                    self.pending = ""
                else:
                    output.append(self._sanitize(self.pending))
                    self.pending = ""
                break

            if len(self.pending) > _MAX_PENDING:
                raise ValueError("streamed output candidate exceeded the safety limit")
            safe_limit = len(self.pending) - _LOOKBEHIND
            if safe_limit <= 0:
                break
            boundary = max(self.pending.rfind(" ", 0, safe_limit + 1), self.pending.rfind("\n", 0, safe_limit + 1), self.pending.rfind("\t", 0, safe_limit + 1), self.pending.rfind("\r", 0, safe_limit + 1))
            if boundary < 0:
                break
            output.append(self._sanitize(self.pending[: boundary + 1]))
            self.pending = self.pending[boundary + 1 :]
        return "".join(output)


def _sse_frame(data: str) -> bytes:
    return f"data: {data}\n\n".encode("utf-8")


def _sentinel_frame(metadata: dict[str, Any]) -> bytes:
    return f"event: sentinel\ndata: {json.dumps(metadata, separators=(',', ':'))}\n\n".encode("utf-8")


def _assistant_delta(content: str, index: int = 0) -> bytes:
    return _sse_frame(json.dumps({"choices": [{"index": index, "delta": {"content": content}}]}, separators=(",", ":")))


async def sanitize_openai_sse(
    response: Any,
    pipeline: SecurityPipeline,
    max_bytes: int,
    metadata: dict[str, Any] | None = None,
    redaction_labels: set[str] | None = None,
) -> AsyncIterator[bytes]:
    """Parse complete SSE events, sanitize assistant deltas, and bound stream bytes."""

    guards: dict[int, StreamingOutputGuard] = {}
    buffer = b""
    total = 0
    done = False

    async def emit_frame(frame: bytes) -> AsyncIterator[bytes]:
        nonlocal done
        text = frame.decode("utf-8", errors="strict")
        lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        data_lines = [line[5:].lstrip(" ") for line in lines if line.startswith("data:")]
        if not data_lines:
            # Never reflect provider comments, event names, or extension fields. They
            # are not part of the normalized chat contract and could carry raw data.
            if frame.lstrip().startswith(b":"):
                yield b": keep-alive\n\n"
            return
        data = "\n".join(data_lines)
        if data == "[DONE]":
            labels: set[str] = set()
            for index, guard in guards.items():
                remaining = guard.feed("", final=True)
                labels.update(guard.labels)
                if remaining:
                    yield _assistant_delta(remaining, index)
            if redaction_labels is not None:
                redaction_labels.update(labels)
            yield _sentinel_frame({**(metadata or {}), "redactions": sorted(labels)})
            yield _sse_frame("[DONE]")
            done = True
            return
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as exc:
            raise ValueError("upstream emitted an invalid SSE JSON event") from exc
        if not isinstance(payload, dict):
            raise ValueError("upstream emitted a non-object SSE event")
        if "error" in payload:
            raise ValueError("upstream returned a streaming error event")
        choices = payload.get("choices")
        if not isinstance(choices, list):
            # Ignore provider usage/extension events: they are outside the user-facing
            # text contract and are not needed to complete a chat response.
            return
        safe_choices: list[dict[str, Any]] = []
        for choice in choices:
            if not isinstance(choice, dict):
                raise ValueError("upstream emitted an invalid streaming choice")
            index = choice.get("index", 0)
            if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index <= 8:
                raise ValueError("upstream emitted an invalid streaming choice index")
            delta = choice.get("delta", {})
            if not isinstance(delta, dict):
                raise ValueError("upstream emitted an invalid streaming delta")
            if "tool_calls" in delta or "function_call" in delta:
                raise ValueError("provider-managed tool execution is disabled")
            unsupported = set(delta) - {"role", "content", "refusal"}
            if unsupported:
                # Fail closed for audio, reasoning, and provider-specific fields until
                # they have an explicit inspection and redaction contract.
                raise ValueError("upstream emitted an unsupported streaming output field")
            role = delta.get("role")
            if role is not None and role != "assistant":
                raise ValueError("upstream emitted a non-assistant streaming role")
            guard = guards.setdefault(index, StreamingOutputGuard(pipeline))
            safe_delta: dict[str, str] = {}
            if role is not None:
                safe_delta["role"] = "assistant"
            content = delta.get("content")
            if content is not None:
                if not isinstance(content, str):
                    raise ValueError("upstream emitted non-text streaming content")
                safe_delta["content"] = guard.feed(content)
            refusal = delta.get("refusal")
            if refusal is not None:
                if not isinstance(refusal, str):
                    raise ValueError("upstream emitted an invalid refusal field")
                safe_delta["refusal"] = guard.feed(refusal)
            safe_choice: dict[str, Any] = {"index": index, "delta": safe_delta}
            finish_reason = choice.get("finish_reason")
            if finish_reason is not None:
                if not isinstance(finish_reason, str) or finish_reason not in {"stop", "length", "content_filter"}:
                    raise ValueError("upstream emitted an unsupported streaming finish reason")
                safe_choice["finish_reason"] = finish_reason
            safe_choices.append(safe_choice)
        if redaction_labels is not None:
            for guard in guards.values():
                redaction_labels.update(guard.labels)
        if safe_choices:
            safe_payload: dict[str, Any] = {"choices": safe_choices}
            for key in ("id", "object", "model", "system_fingerprint"):
                value = payload.get(key)
                if isinstance(value, str) and len(value) <= 256:
                    safe_payload[key] = value
            created = payload.get("created")
            if isinstance(created, int) and not isinstance(created, bool) and created >= 0:
                safe_payload["created"] = created
            yield _sse_frame(json.dumps(safe_payload, ensure_ascii=False, separators=(",", ":")))

    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > max_bytes:
            raise ValueError("upstream stream exceeded the configured byte limit")
        buffer += chunk
        while True:
            lf = buffer.find(b"\n\n")
            crlf = buffer.find(b"\r\n\r\n")
            if crlf >= 0 and (lf < 0 or crlf < lf):
                end, separator = crlf, 4
            elif lf >= 0:
                end, separator = lf, 2
            else:
                break
            frame = buffer[:end]
            buffer = buffer[end + separator :]
            async for safe_frame in emit_frame(frame):
                yield safe_frame
            if done:
                return

    if buffer.strip():
        async for safe_frame in emit_frame(buffer):
            yield safe_frame
    if not done:
        # Never turn a truncated provider response into a successful completion.
        # In particular, do not flush look-behind buffers here: they can contain
        # a secret or active payload whose terminator was lost with the stream.
        raise ValueError("upstream stream ended without the required [DONE] marker")
