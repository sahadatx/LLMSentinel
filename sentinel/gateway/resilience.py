"""Small process-local circuit breaker for configured service dependencies."""

from __future__ import annotations

import threading
import time


class CircuitBreaker:
    """Stop forwarding calls during an outage and allow one recovery probe."""

    def __init__(self, failure_threshold: int = 5, reset_timeout_seconds: float = 15.0) -> None:
        if failure_threshold < 1 or reset_timeout_seconds <= 0:
            raise ValueError("Circuit breaker threshold and reset timeout must be positive")
        self.failure_threshold = failure_threshold
        self.reset_timeout_seconds = reset_timeout_seconds
        self._failures = 0
        self._open_until = 0.0
        self._probe_in_progress = False
        self._lock = threading.Lock()

    def allow_request(self) -> bool:
        now = time.monotonic()
        with self._lock:
            if self._open_until > now:
                return False
            if self._failures >= self.failure_threshold:
                if self._probe_in_progress:
                    return False
                self._probe_in_progress = True
            return True

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._open_until = 0.0
            self._probe_in_progress = False

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._probe_in_progress or self._failures >= self.failure_threshold:
                self._open_until = time.monotonic() + self.reset_timeout_seconds
                self._probe_in_progress = False

    def state(self) -> str:
        now = time.monotonic()
        with self._lock:
            if self._open_until > now:
                return "open"
            if self._failures >= self.failure_threshold:
                return "half_open" if self._probe_in_progress else "half_open_ready"
            return "closed"
