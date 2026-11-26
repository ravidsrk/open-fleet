# fixture target app

A small issue-tracker fixture for open-fleet mission runs: FastAPI JSON API +
server-rendered UI on SQLite, with Prometheus metrics, structured JSON logs,
and an 8-service compose stack (volume-init, app, staging, Prometheus, Grafana,
Loki, Promtail, Alertmanager).

Start here, then read `SCOPE.md` (journeys + budgets — the mission inputs) and
`FLAWS.md` (the frozen imperfection set F1–F4; read it before "fixing"
anything that looks wrong — it is wrong on purpose).

## Quick start

Requirements: `uv`, `docker compose`. All commands run from `evals/demo/target-app/`.

```sh
cd evals/demo/target-app
uv run alembic upgrade 0002   # create app.db at the frozen schema (F3: 0003 stays pending)
uv run uvicorn app.main:app   # serve on http://127.0.0.1:8000
```

What you get:

- UI: `/` (issue list), `/issues/new`, `/issues/{id}/view`, `/issues/{id}/edit`
- API: `POST /issues`, `GET /issues`, `GET /issues/{id}`, `PATCH /issues/{id}`,
  `POST /issues/{id}/comments`, `GET /issues/{id}/comments`; OpenAPI at `/docs`
- Ops: `/healthz`, `/metrics` (Prometheus), `/hooks/alerts/last` (last
  Alertmanager receipt)

Seed a demo DB (1k issues x 50 comments each):

```sh
DATABASE_URL=sqlite:///./demo.db uv run python -m app.seed --count 1000
DATABASE_URL=sqlite:///./demo.db uv run uvicorn app.main:app
```

## Commands

| Command | Description |
|---|---|
| `uv run uvicorn app.main:app` | Run the API + UI on :8000 |
| `uv run pytest` | Full test suite (55 tests: API + UI + shape + telemetry) |
| `ruff check .` | Lint (ruff on PATH, e.g. via mise) |
| `uv run alembic upgrade 0002` | Migrate an empty DB to the frozen schema |
| `uv run alembic current` | Reads `0002` after boot; `alembic heads` shows pending `0003` |
| `docker compose up --build -d` | Full stack: app :8000, staging :8001 (own DB), Prometheus :9090, Grafana :3000 |
| `docker compose down -v` | Teardown: leaves no containers or volumes |

## Staging + observability smoke

```sh
docker compose up --build -d
curl -s http://127.0.0.1:8000/healthz   # app
curl -s http://127.0.0.1:8001/healthz   # staging (own DB file)
curl -s 'http://127.0.0.1:9090/api/v1/query?query=app_issues_total'   # PromQL
docker compose down -v   # teardown
```

> Local runs: set `TARGET_APP_SCRAPE_GAUGE=1` to refresh `app_issues_total`
> from a live `COUNT(*)` at scrape time (compose sets this; without it the
> gauge tracks increments since boot only).

## Database

SQLite for local dev (`app.db`, created by the migrate step above); PostgreSQL
in production — point `DATABASE_URL` at your Postgres DSN and the app connects
as-is (same models, same migrations).

## Architecture

```text
app/main.py          FastAPI app: /healthz + router includes (S0–S3 regions)
app/routers/         issues (JSON CRUD), comments, pages (Jinja UI), hooks (alerts)
app/models.py        SQLAlchemy models + session wiring (DATABASE_URL, sqlite default)
app/seed.py          deterministic seed + F1 timing oracle (see docstring)
app/telemetry.py     structlog JSON logs + /metrics (latency histogram, issue gauge)
app/templates/       Jinja pages: list, detail, new/edit forms (no JS build)
alembic/versions/    0001 (issues), 0002 (comments), 0003 (pending index — F3)
observability/       prometheus/alertmanager/loki/promtail configs + Grafana dashboard
compose.yaml         8-service stack; boot migrates then serves (seed --count 0)
```

CI (`.github/workflows/fixture-target-app.yml`, fixture-owned — not coupled to
catalog gates): pytest, ruff, migration round-trip (frozen at 0002, 0003
pending), compose smoke (build + /healthz + PromQL + LogQL + teardown).
