"""Measure a running gateway without silently invoking a paid model upstream."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import statistics
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))
    return round(ordered[index], 3)


def percentiles(values: list[float]) -> dict[str, float]:
    return {
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "mean": round(statistics.mean(values), 3) if values else 0.0,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://127.0.0.1:8000", help="Gateway base URL")
    parser.add_argument("--requests", type=int, default=100, help="Measured request count, max 50000")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrent requests, max 1000")
    parser.add_argument("--warmup", type=int, default=10, help="Warm-up requests, max 1000")
    parser.add_argument("--token", help="Bearer token for an authenticated gateway")
    parser.add_argument("--allow-remote-target", action="store_true", help="Allow a non-loopback HTTPS target")
    parser.add_argument("--allow-provider-upstream", action="store_true", help="Allow load requests to reach the configured model provider")
    parser.add_argument("--output", type=Path, help="Optional JSON result path")
    args = parser.parse_args()
    if not 1 <= args.requests <= 50_000:
        parser.error("--requests must be from 1 through 50000")
    if not 1 <= args.concurrency <= 1000:
        parser.error("--concurrency must be from 1 through 1000")
    if not 0 <= args.warmup <= 1000:
        parser.error("--warmup must be from 0 through 1000")
    parsed = urlsplit(args.target)
    hostname = (parsed.hostname or "").lower()
    try:
        import ipaddress

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
        or parsed.path not in {"", "/"}
    ):
        parser.error("--target must be a gateway base URL without credentials, path, query, or fragment")
    if not loopback and (parsed.scheme != "https" or not args.allow_remote_target):
        parser.error("Remote targets require HTTPS and --allow-remote-target")
    return args


async def main_async(args: argparse.Namespace) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {args.token}"} if args.token else {}
    target = args.target.rstrip("/")
    timeout = httpx.Timeout(30)
    latencies: list[float] = []
    gateway_latencies: list[float] = []
    status_counts: dict[str, int] = {}
    limiter = asyncio.Semaphore(args.concurrency)

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        posture_response = await client.get(f"{target}/v1/security/posture", headers=headers)
        posture_response.raise_for_status()
        posture = posture_response.json()
        upstream_control: dict[str, Any] = next(
            (control for control in posture.get("controls", []) if control.get("id") == "upstream"),
            {},
        )
        upstream_status = upstream_control.get("status", "unknown")
        if upstream_status == "configured" and not args.allow_provider_upstream:
            raise SystemExit(
                "This gateway uses a configured model provider. Pass --allow-provider-upstream only when provider cost and load are approved."
            )

        async def send_one(index: int, collect: bool = True) -> None:
            async with limiter:
                body = {
                    "model": "sentinel-mock",
                    "messages": [{"role": "user", "content": f"Load sample {index}: summarize this short benign sentence."}],
                }
                started = time.perf_counter()
                try:
                    response = await client.post(f"{target}/v1/chat/completions", headers=headers, json=body)
                    elapsed_ms = (time.perf_counter() - started) * 1000
                    if collect:
                        status_counts[str(response.status_code)] = status_counts.get(str(response.status_code), 0) + 1
                        latencies.append(elapsed_ms)
                    if collect and response.is_success:
                        payload = response.json()
                        measured = payload.get("sentinel", {}).get("latency_ms")
                        if isinstance(measured, (int, float)):
                            gateway_latencies.append(float(measured))
                except (httpx.HTTPError, ValueError):
                    status_counts["error"] = status_counts.get("error", 0) + 1

        for index in range(args.warmup):
            await send_one(-index - 1, collect=False)
        started = time.perf_counter()
        await asyncio.gather(*(send_one(index) for index in range(args.requests)))
        elapsed_seconds = time.perf_counter() - started
        try:
            metrics_response = await client.get(f"{target}/metrics", headers=headers)
            metrics = metrics_response.json() if metrics_response.is_success else None
        except (httpx.HTTPError, ValueError):
            metrics = None

    total_success = status_counts.get("200", 0)
    return {
        "target": target,
        "policy": posture.get("policy"),
        "upstream_status": upstream_status,
        "requests_requested": args.requests,
        "requests_completed": len(latencies),
        "successful_responses": total_success,
        "status_counts": status_counts,
        "concurrency": args.concurrency,
        "elapsed_seconds": round(elapsed_seconds, 3),
        "throughput_rps": round(args.requests / elapsed_seconds, 3) if elapsed_seconds else 0.0,
        "client_round_trip_ms": percentiles(latencies),
        "gateway_reported_ms": percentiles(gateway_latencies),
        "gateway_runtime_metrics": metrics,
        "notes": "Observed gateway run; failed/rate-limited requests are excluded from gateway-reported response percentiles. Results are environment-specific and are not an SLA unless the traffic profile and acceptance criteria are published.",
    }


def main() -> None:
    args = parse_args()
    result = asyncio.run(main_async(args))
    rendered = json.dumps(result, indent=2)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
