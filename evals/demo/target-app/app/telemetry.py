"""Structured JSON logging + Prometheus metrics (slice S3)."""

import os
import time
from collections.abc import Awaitable, Callable

import structlog
from fastapi import APIRouter, Request, Response
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, Histogram, generate_latest

REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "Fixture request latency by method, route and status.",
    ["method", "path", "status"],
)
ISSUE_COUNT = Gauge("app_issues_total", "Issues in the store.")

metrics_router = APIRouter(tags=["telemetry"])


@metrics_router.get("/metrics")
def metrics() -> Response:
    if os.environ.get("TARGET_APP_SCRAPE_GAUGE") == "1":
        _refresh_issue_gauge_best_effort()
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def _refresh_issue_gauge_best_effort() -> None:
    """True COUNT(*) at scrape time. Compose-only (env-gated) so unit tests
    (which override get_db per test) never touch the working-tree database."""
    try:
        from sqlalchemy import func, select

        from app.models import Issue, SessionLocal

        db = SessionLocal()
        try:
            total = db.execute(select(func.count()).select_from(Issue)).scalar()
        finally:
            db.close()
        ISSUE_COUNT.set(float(total or 0))
    except Exception as exc:
        get_logger().warning("issue_gauge_refresh_failed", error=str(exc))


def configure_logging() -> None:
    """JSON lines on stdout — teed to the shared log volume promtail scrapes."""
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )


def get_logger() -> structlog.BoundLogger:
    return structlog.get_logger("fixture-target-app")


async def telemetry_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        elapsed = time.perf_counter() - start
        route = request.scope.get("route")
        path = route.path if route is not None else "__unmatched__"
        REQUEST_LATENCY.labels(request.method, path, "500").observe(elapsed)
        get_logger().info(
            "request",
            method=request.method,
            path=request.url.path,
            status_code=500,
            duration_ms=round(elapsed * 1000, 3),
        )
        raise
    elapsed = time.perf_counter() - start
    route = request.scope.get("route")
    path = route.path if route is not None else "__unmatched__"
    REQUEST_LATENCY.labels(request.method, path, str(response.status_code)).observe(
        elapsed
    )
    if request.method == "POST" and path in ("/issues", "/issues/new"):
        # 201 = JSON create, 303 = UI form create (redirects to the list page).
        if response.status_code in (200, 201, 303):
            ISSUE_COUNT.inc()
    get_logger().info(
        "request",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=round(elapsed * 1000, 3),
    )
    return response


__all__ = [
    "ISSUE_COUNT",
    "REQUEST_LATENCY",
    "configure_logging",
    "get_logger",
    "metrics_router",
    "telemetry_middleware",
]
