"""Prometheus metrics middleware for FastAPI."""

import time
from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    generate_latest,
    CONTENT_TYPE_LATEST,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


# ── Metric Definitions ────────────────────────────────────────────

REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)

REQUEST_DURATION = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

REQUESTS_IN_PROGRESS = Gauge(
    "http_requests_in_progress",
    "Number of HTTP requests currently being processed",
    ["method", "endpoint"],
)


# ── Helpers ───────────────────────────────────────────────────────

def _normalize_path(path: str) -> str:
    """Collapse variable path segments to reduce cardinality.

    e.g. /api/cwe/79 → /api/cwe/{id}
         /api/cve/CVE-2024-1234 → /api/cve/{id}
         /api/cwe/79/cves → /api/cwe/{id}/cves
    """
    parts = path.strip("/").split("/")
    normalized = []
    for i, part in enumerate(parts):
        if i >= 2 and parts[0] == "api":
            # Detect numeric IDs or CVE-* patterns
            if part.isdigit() or part.startswith("CVE-"):
                normalized.append("{id}")
                continue
        normalized.append(part)
    return "/" + "/".join(normalized) if normalized else "/"


# ── Middleware ────────────────────────────────────────────────────

class PrometheusMiddleware(BaseHTTPMiddleware):
    """Records request count, latency histogram, and in-progress gauge."""

    async def dispatch(self, request: Request, call_next):
        # Skip instrumenting the metrics endpoint itself
        if request.url.path == "/metrics":
            return await call_next(request)

        method = request.method
        endpoint = _normalize_path(request.url.path)

        REQUESTS_IN_PROGRESS.labels(method=method, endpoint=endpoint).inc()
        start = time.perf_counter()

        try:
            response = await call_next(request)
        except Exception:
            REQUEST_COUNT.labels(
                method=method, endpoint=endpoint, status="500"
            ).inc()
            raise
        finally:
            duration = time.perf_counter() - start
            REQUESTS_IN_PROGRESS.labels(
                method=method, endpoint=endpoint
            ).dec()
            REQUEST_DURATION.labels(
                method=method, endpoint=endpoint
            ).observe(duration)

        REQUEST_COUNT.labels(
            method=method, endpoint=endpoint, status=str(response.status_code)
        ).inc()

        return response


# ── /metrics Endpoint ─────────────────────────────────────────────

async def metrics_endpoint(request: Request) -> Response:
    """Expose Prometheus metrics at /metrics."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
