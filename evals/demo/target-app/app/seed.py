"""Deterministic seed + F1 timing oracle (slice S3).

F1 ORACLE — issue-list N+1, measurable >500ms at 1k rows (documented flaw;
fix only inside a mission run):

  1. cd evals/demo/target-app
  2. rm -f /tmp/f1.db && DATABASE_URL=sqlite:////tmp/f1.db \\
       uv run python -m app.seed --count 1000
  3. DATABASE_URL=sqlite:////tmp/f1.db \\
       uv run uvicorn app.main:app --port 8123 & sleep 3
  4. time curl -s http://127.0.0.1:8123/issues -o /tmp/f1-issues.json
  5. kill %1   # stop the probe server

Expected: step 4 wall time >500ms (1 ids query + 1 SELECT per row), and
/tmp/f1-issues.json holds 1000 issues. If the machine is faster than the
flaw, raise --count: time grows linearly with rows (that linearity IS the
N+1 signal a speed-it run must flatten).
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from alembic import command as alembic_command
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Comment, Issue

FIXTURE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_COUNT = 1000
COMMENTS_PER_ISSUE = 50


def ensure_migrated(database_url: str) -> None:
    cfg = Config()
    cfg.set_main_option("script_location", str(FIXTURE_DIR / "alembic"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    # F3 (frozen flaw; see FLAWS.md): boot pins 0002 — 0003 exists on disk
    # but stays unapplied until a migrate-it mission run applies it.
    alembic_command.upgrade(cfg, "0002")


def seed(count: int = DEFAULT_COUNT, database_url: str | None = None) -> int:
    if count < 0:
        raise ValueError("count must be >= 0")
    url = database_url or os.environ.get("DATABASE_URL", "sqlite:///./app.db")
    ensure_migrated(url)
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, connect_args=connect_args)
    sessions = sessionmaker(bind=engine, autoflush=False)
    db = sessions()
    try:
        issues = [
            Issue(
                title=f"seeded issue {i:04d}",
                body=f"Seeded body for issue {i}: two sentences of fixture text.",
                status="closed" if i % 7 == 0 else "open",
                priority=(i % 3) + 1,
            )
            for i in range(1, count + 1)
        ]
        db.add_all(issues)
        db.flush()
        comments: list[Comment] = []
        for issue in issues:
            assert issue.id is not None
            for n in range(COMMENTS_PER_ISSUE):
                comments.append(
                    Comment(
                        issue_id=issue.id,
                        body=f"Seeded comment {n + 1} on issue #{issue.id}.",
                    )
                )
        db.add_all(comments)
        db.commit()
        return count
    finally:
        db.close()
        engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed the fixture issue tracker.")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--database-url", default=None)
    args = parser.parse_args(argv)
    seeded = seed(count=args.count, database_url=args.database_url)
    print(f"seeded {seeded} issues")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
