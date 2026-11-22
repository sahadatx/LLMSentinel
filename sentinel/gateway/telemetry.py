"""Optional OpenTelemetry request instrumentation with privacy-safe attributes."""

from __future__ import annotations

import os
import time
from contextlib import nullcontext
from typing import Any
from urllib.parse import urlsplit


class OpenTelemetryRuntime:
    def __init__(self) -> None:
        self.enabled = False
        self.tracer: Any = None
        self._request_counter: Any = None
        self._request_duration: Any = None
        self._trace_provider: Any = None
        self._meter_provider: Any = None
        endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
        if not endpoint:
            return
        parsed = urlsplit(endpoint)
        hostname = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"} or not hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("OTEL_EXPORTER_OTLP_ENDPOINT must be a valid HTTP(S) collector URL without credentials")
        if parsed.scheme != "https" and hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Remote OpenTelemetry collectors must use HTTPS")
        try:
            from opentelemetry import metrics, trace
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
        except ImportError as exc:  # pragma: no cover - depends on the optional install
            raise RuntimeError("Install LLMSentinel with the 'observability' extra to configure OTLP") from exc

        service_name = os.getenv("OTEL_SERVICE_NAME", "llmsentinel-gateway")
        resource = Resource.create({"service.name": service_name, "service.version": "3.0.0"})
        trace_provider = TracerProvider(resource=resource)
        trace_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(trace_provider)
        metric_reader = PeriodicExportingMetricReader(OTLPMetricExporter())
        meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        metrics.set_meter_provider(meter_provider)
        meter = metrics.get_meter("llmsentinel.gateway")
        self.tracer = trace.get_tracer("llmsentinel.gateway")
        self._request_counter = meter.create_counter("llmsentinel.http.server.requests")
        self._request_duration = meter.create_histogram(
            "llmsentinel.http.server.duration", unit="ms", description="Gateway HTTP handler duration"
        )
        self._trace_provider = trace_provider
        self._meter_provider = meter_provider
        self.enabled = True

    async def instrument(self, request: Any, call_next: Any) -> Any:
        if not self.enabled:
            return await call_next(request)
        started = time.perf_counter()
        method = str(request.method)
        with self.tracer.start_as_current_span("llmsentinel.http.request") as span:
            span.set_attribute("http.request.method", method)
            try:
                response = await call_next(request)
            except Exception as exc:
                elapsed = (time.perf_counter() - started) * 1000
                span.record_exception(exc)
                span.set_attribute("error.type", type(exc).__name__)
                self._record(method, "5xx", "unresolved", elapsed)
                raise
            elapsed = (time.perf_counter() - started) * 1000
            route = getattr(request.scope.get("route"), "path", "unresolved")
            status = str(response.status_code)
            span.set_attribute("http.response.status_code", response.status_code)
            span.set_attribute("http.route", route)
            self._record(method, status, route, elapsed)
            return response

    def _record(self, method: str, status: str, route: str, elapsed_ms: float) -> None:
        # Route templates and status classes are bounded-cardinality. No body,
        # prompt, tenant, subject, token, or query attributes are exported.
        attributes = {
            "http.request.method": method,
            "http.response.status_code": status,
            "http.route": route if route.startswith("/") else "unresolved",
        }
        self._request_counter.add(1, attributes)
        self._request_duration.record(elapsed_ms, attributes)

    def span(self, name: str) -> Any:
        if not self.enabled:
            return nullcontext()
        return self.tracer.start_as_current_span(name)

    def shutdown(self) -> None:
        if self._trace_provider is not None:
            self._trace_provider.force_flush(timeout_millis=3000)
            self._trace_provider.shutdown()
        if self._meter_provider is not None:
            self._meter_provider.force_flush(timeout_millis=3000)
            self._meter_provider.shutdown()
