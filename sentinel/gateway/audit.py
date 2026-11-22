"""Append-only, hash-chained JSONL audit trail.

The chain detects edits and reordering within the file. It is not tamper-proof
against an operator who can rewrite the entire file; periodically anchor the
head hash in a separately controlled system for stronger forensic assurance.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:  # Linux production containers use this to serialize Uvicorn workers.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX local development
    fcntl = None  # type: ignore[assignment]


class HashChainAuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.is_symlink():
            raise ValueError("audit path must not be a symbolic link")
        self._lock = threading.RLock()
        self._last_hash = self._read_head()
        self._verified_signature: tuple[int, int, int, int] | None = None
        self._verified_result: tuple[bool, str | None] | None = None
        self.verify_chain()

    def _read_head(self) -> str:
        if not self.path.exists():
            return "0" * 64
        try:
            with self.path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                position = stream.tell()
                buffer = b""
                while position > 0 and b"\n" not in buffer:
                    size = min(4096, position)
                    position -= size
                    stream.seek(position)
                    buffer = stream.read(size) + buffer
                lines = [line for line in buffer.splitlines() if line.strip()]
                record = json.loads(lines[-1]) if lines else {}
                return str(record.get("hash", "0" * 64)) if isinstance(record, dict) else "0" * 64
        except (OSError, json.JSONDecodeError, AttributeError):
            return "0" * 64

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.path, flags, 0o600)
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            try:
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_EX)
                stat = self.path.stat()
                current_signature = (stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
                if current_signature != self._verified_signature:
                    self._verified_signature = None
                    self.verify_chain()
                chain_was_valid = self._verified_result == (True, None)
                if not chain_was_valid:
                    raise RuntimeError("audit chain is invalid; refusing to append and obscure the integrity failure")
                # Another worker may have appended while this instance was idle.
                self._last_hash = self._read_head()
                record = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "prev_hash": self._last_hash,
                    "event": event,
                }
                canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                digest = hashlib.sha256(canonical.encode()).hexdigest()
                record["hash"] = digest
                payload = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
                written = 0
                while written < len(payload):
                    written += os.write(descriptor, payload[written:])
                os.fsync(descriptor)
                self._last_hash = digest
                stat = self.path.stat()
                self._verified_signature = (stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
                if chain_was_valid:
                    self._verified_result = (True, None)
                return record
            finally:
                if fcntl is not None:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def recent(self, count: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            if not self.path.exists():
                return []
            count = max(1, count)
            with self.path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                position = stream.tell()
                buffer = b""
                while position > 0 and buffer.count(b"\n") <= count:
                    size = min(8192, position)
                    position -= size
                    stream.seek(position)
                    buffer = stream.read(size) + buffer
            lines = [line for line in buffer.splitlines() if line.strip()][-count:]
            records = []
            for line in reversed(lines):
                try:
                    item = json.loads(line)
                    if isinstance(item, dict):
                        records.append(item)
                except json.JSONDecodeError:
                    continue
            return records

    def recent_for_tenant(self, tenant_id: str, count: int = 50) -> list[dict[str, Any]]:
        """Return only one tenant's records without truncating before filtering."""
        count = max(1, count)
        records: deque[dict[str, Any]] = deque(maxlen=count)
        with self._lock:
            if not self.path.exists():
                return []
            with self.path.open(encoding="utf-8") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    event = record.get("event") if isinstance(record, dict) else None
                    if isinstance(event, dict) and event.get("tenant_id") == tenant_id:
                        records.append(record)
        return list(reversed(records))

    def export_after(self, after_hash: str = "0" * 64, limit: int = 500) -> dict[str, Any]:
        """Return an ordered, hash-linked pull batch for an external SIEM."""
        if len(after_hash) != 64 or any(char not in "0123456789abcdef" for char in after_hash.lower()):
            raise ValueError("after_hash must be a 64-character SHA-256 hash")
        limit = max(1, min(limit, 1000))
        with self._lock:
            valid, error = self._verify_chain_locked()
            if not valid:
                raise RuntimeError(error or "audit chain integrity check failed")
            if not self.path.exists():
                if after_hash != "0" * 64:
                    raise KeyError("audit cursor was not found")
                return {"events": [], "next_cursor": after_hash, "has_more": False}
            found_cursor = after_hash == "0" * 64
            rows: list[dict[str, Any]] = []
            with self.path.open(encoding="utf-8") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    if not found_cursor:
                        if record.get("hash") == after_hash:
                            found_cursor = True
                        continue
                    rows.append(record)
                    if len(rows) > limit:
                        break
            if not found_cursor:
                raise KeyError("audit cursor was not found")
            has_more = len(rows) > limit
            events = rows[:limit]
            next_cursor = str(events[-1].get("hash")) if events else after_hash
            return {"events": events, "next_cursor": next_cursor, "has_more": has_more}

    def verify_chain(self) -> tuple[bool, str | None]:
        with self._lock:
            return self._verify_chain_locked()

    def _verify_chain_locked(self) -> tuple[bool, str | None]:
        previous = "0" * 64
        if not self.path.exists():
            self._verified_signature = (0, 0, 0, 0)
            self._verified_result = (True, None)
            return self._verified_result
        stat = self.path.stat()
        signature = (stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
        if signature == self._verified_signature and self._verified_result is not None:
            return self._verified_result
        with self.path.open(encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    self._verified_signature = signature
                    self._verified_result = (False, f"malformed record at line {number}")
                    return self._verified_result
                if not isinstance(record, dict):
                    self._verified_signature = signature
                    self._verified_result = (False, f"record is not an object at line {number}")
                    return self._verified_result
                actual = record.pop("hash", None)
                if record.get("prev_hash") != previous:
                    self._verified_signature = signature
                    self._verified_result = (False, f"broken previous hash at line {number}")
                    return self._verified_result
                canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                expected = hashlib.sha256(canonical.encode()).hexdigest()
                if actual != expected:
                    self._verified_signature = signature
                    self._verified_result = (False, f"record hash mismatch at line {number}")
                    return self._verified_result
                previous = str(actual)
        current_stat = self.path.stat()
        current_signature = (
            current_stat.st_ino,
            current_stat.st_size,
            current_stat.st_mtime_ns,
            current_stat.st_ctime_ns,
        )
        if current_signature != signature:
            self._verified_signature = current_signature
            self._verified_result = (False, "audit file changed during verification")
            return self._verified_result
        self._verified_signature = signature
        self._verified_result = (True, None)
        return self._verified_result
