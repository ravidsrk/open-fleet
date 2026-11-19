"""Prometheus /metrics contract (slice S3).

Seam: HTTP via TestClient against an Alembic-migrated throwaway SQLite DB.
(No conftest.py: the S3 slice scope allows only tests/test_telemetry_*.py, so
each test module carries its own fixture.)
"""

from collections.abc import Generator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.models import get_db
from app.telemetry import ISSUE_COUNT

FIXTURE_DIR = Path(__file__).resolve().parent.parent


def _migrated_url(tmp_path: Path) -> str:
    cfg = Config()
    cfg.set_main_option("script_location", str(FIXTURE_DIR / "alembic"))
    url = f"sqlite:///{tmp_path / 'test.db'}"
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")
    return url


@pytest.fixture()
def client(tmp_path: Path) -> Generator[TestClient, None, None]:
    url = _migrated_url(tmp_path)
    engine = create_engine(url)
    testing_sessions = sessionmaker(bind=engine, autoflush=False)

    def _override():  # type: ignore[no-untyped-def]
        db = testing_sessions()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_metrics_exposes_histogram_and_gauge(client: TestClient) -> None:
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    body = response.text
    assert "http_request_duration_seconds_bucket" in body
    assert "app_issues_total" in body


def test_issue_create_increments_gauge(client: TestClient) -> None:
    ISSUE_COUNT.set(0)
    assert client.post("/issues", json={"title": "one"}).status_code == 201
    assert client.post("/issues", json={"title": "two"}).status_code == 201
    body = client.get("/metrics").text
    assert "app_issues_total 2.0" in body


def test_latency_histogram_observes_requests(client: TestClient) -> None:
    assert client.get("/issues").status_code == 200
    body = client.get("/metrics").text
    line = next(
        line
        for line in body.splitlines()
        if line.startswith(
            'http_request_duration_seconds_count{method="GET",path="/issues"'
        )
    )
    assert float(line.rsplit(" ", 1)[1]) >= 1


def test_middleware_records_error_path() -> None:
    """Route exceptions still emit a 500 latency sample (Greptile P2 fix)."""
    import asyncio
    from types import SimpleNamespace

    from fastapi import Request

    from app import telemetry as T

    async def boom(_request: Request):  # type: ignore[no-untyped-def]
        raise RuntimeError("boom")

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/issues/1",
        "headers": [],
        "route": SimpleNamespace(path="/issues/1"),
    }
    before = _hist_count("GET", "/issues/1", "500")
    with pytest.raises(RuntimeError, match="boom"):
        asyncio.run(T.telemetry_middleware(Request(scope), boom))
    assert _hist_count("GET", "/issues/1", "500") == before + 1


def _hist_count(method: str, path: str, status: str) -> float:
    from app import telemetry as T

    for metric in T.REQUEST_LATENCY.collect():
        for sample in metric.samples:
            if (
                sample.name.endswith("_count")
                and sample.labels.get("method") == method
                and sample.labels.get("path") == path
                and sample.labels.get("status") == status
            ):
                return float(sample.value)
    return 0.0


def test_ui_form_create_increments_gauge(client: TestClient) -> None:
    ISSUE_COUNT.set(0)
    response = client.post(
        "/issues/new",
        data={"title": "via-ui", "body": "", "status": "open", "priority": "2"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    body = client.get("/metrics").text
    assert "app_issues_total 1.0" in body


def test_unmatched_route_uses_bounded_prometheus_label(
    client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    import json

    from app.telemetry import configure_logging

    configure_logging()
    before_unmatched = _hist_count("GET", "__unmatched__", "404")
    probe = "/no-such-route-cardinality-probe"
    response = client.get(probe)
    assert response.status_code == 404
    assert _hist_count("GET", "__unmatched__", "404") == before_unmatched + 1
    assert _hist_count("GET", probe, "404") == 0.0
    captured = capsys.readouterr()
    entries = [json.loads(ln) for ln in captured.out.splitlines() if ln.startswith("{")]
    assert any(e.get("path") == probe and e.get("status_code") == 404 for e in entries)


def test_unmatched_route_exception_uses_bounded_prometheus_label(
    capsys: pytest.CaptureFixture[str],
) -> None:
    import asyncio
    import json

    from fastapi import Request, Response

    from app import telemetry as T

    T.configure_logging()

    async def boom(_request: Request) -> Response:
        raise RuntimeError("unmatched-boom")

    probe = "/unmatched-error-probe"
    scope = {
        "type": "http",
        "method": "GET",
        "path": probe,
        "headers": [],
        "route": None,
    }
    before_unmatched = _hist_count("GET", "__unmatched__", "500")
    with pytest.raises(RuntimeError, match="unmatched-boom"):
        asyncio.run(T.telemetry_middleware(Request(scope), boom))
    assert _hist_count("GET", "__unmatched__", "500") == before_unmatched + 1
    assert _hist_count("GET", probe, "500") == 0.0
    captured = capsys.readouterr()
    entries = [json.loads(ln) for ln in captured.out.splitlines() if ln.startswith("{")]
    assert any(e.get("path") == probe and e.get("status_code") == 500 for e in entries)


def test_alembic_env_wires_base_metadata() -> None:
    from app.models import Base

    env_text = (FIXTURE_DIR / "alembic" / "env.py").read_text(encoding="utf-8")
    assert "from app.models import Base" in env_text
    assert "target_metadata = Base.metadata" in env_text
    assert {"issues", "comments"} <= set(Base.metadata.tables)
