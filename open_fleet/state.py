"""Read-only operational state inspection over SQLite runtime.db, merge queue, events, and decisions."""

import hashlib
import json
import os
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

from open_fleet import find_catalog_root


def _git_common_dir(repo_dir: Path) -> Path | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "--git-common-dir"],
            capture_output=True,
            text=True,
            timeout=10,
            env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    raw = Path(proc.stdout.strip())
    return (repo_dir / raw).resolve() if not raw.is_absolute() else raw.resolve()


def resolve_state_db_path(
    repo_dir: Path | None = None,
    *,
    db_override: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> Path:
    """Resolve the posix LocalStateStore SQLite path matching runtime/providers/local_state.py."""
    src = os.environ if env is None else env
    if db_override:
        return Path(db_override).expanduser().resolve()
    for var in ("OPEN_FLEET_STATE_DB", "ORCA_FLEET_STATE_DB"):
        val = (src.get(var) or "").strip()
        if val:
            return Path(val).expanduser().resolve()
    state_dir = ""
    for var in ("OPEN_FLEET_STATE_DIR", "ORCA_FLEET_STATE_DIR"):
        val = (src.get(var) or "").strip()
        if val:
            state_dir = val
            break
    target = (repo_dir or Path.cwd()).resolve()
    common = _git_common_dir(target)
    key_source = str(common or target)
    repo_id = hashlib.sha256(key_source.encode("utf-8")).hexdigest()[:16]
    if state_dir:
        return Path(state_dir).expanduser().resolve() / repo_id / "runtime.db"
    home = Path(src.get("HOME") or Path.home()).expanduser()
    return home / ".open-fleet" / "state" / repo_id / "runtime.db"


def _connect_readonly(db_path: Path) -> sqlite3.Connection | None:
    if not db_path.is_file():
        return None
    try:
        uri = db_path.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=2.0)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error:
        return None


def _table_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {str(r[0]) for r in rows}


def _rows_to_dicts(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    try:
        cur = conn.execute(sql, params)
        return [dict(row) for row in cur.fetchall()]
    except sqlite3.Error:
        return []


def read_runtime_state(
    repo_dir: Path | None = None,
    *,
    db_override: str | Path | None = None,
    env: dict[str, str] | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Read runs, tasks, dispatches, terminals, gates, messages, and merge queue state."""
    db_path = resolve_state_db_path(repo_dir, db_override=db_override, env=env)
    empty: dict[str, Any] = {
        "db_path": str(db_path),
        "db_exists": False,
        "runs": [],
        "tasks": [],
        "dispatches": [],
        "terminals": [],
        "gates": [],
        "messages": [],
        "launch_intents": [],
        "merge_queue": {"queues": [], "leases": [], "entries": [], "receipts": []},
        "summary": {
            "runs": 0,
            "tasks_total": 0,
            "tasks_by_status": {},
            "active_dispatches": 0,
            "open_gates": 0,
            "queued_merges": 0,
        },
    }
    conn = _connect_readonly(db_path)
    if conn is None:
        return empty
    try:
        tables = _table_names(conn)
        runs = _rows_to_dicts(conn, "SELECT * FROM runs ORDER BY rowid DESC LIMIT ?", (limit,)) if "runs" in tables else []
        tasks = _rows_to_dicts(conn, "SELECT * FROM tasks ORDER BY rowid DESC LIMIT ?", (limit,)) if "tasks" in tables else []
        dispatches = (
            _rows_to_dicts(conn, "SELECT * FROM dispatches ORDER BY rowid DESC LIMIT ?", (limit,))
            if "dispatches" in tables
            else []
        )
        terminals = (
            _rows_to_dicts(conn, "SELECT * FROM terminals ORDER BY rowid DESC LIMIT ?", (limit,))
            if "terminals" in tables
            else []
        )
        gates = _rows_to_dicts(conn, "SELECT * FROM gates ORDER BY rowid DESC LIMIT ?", (limit,)) if "gates" in tables else []
        messages = (
            _rows_to_dicts(conn, "SELECT * FROM messages ORDER BY rowid DESC LIMIT ?", (limit,))
            if "messages" in tables
            else []
        )
        intents = (
            _rows_to_dicts(conn, "SELECT * FROM launch_intents ORDER BY rowid DESC LIMIT ?", (limit,))
            if "launch_intents" in tables
            else []
        )
        mq = {
            "queues": _rows_to_dicts(conn, "SELECT * FROM mq_queues LIMIT ?", (limit,)) if "mq_queues" in tables else [],
            "leases": _rows_to_dicts(conn, "SELECT * FROM mq_leases LIMIT ?", (limit,)) if "mq_leases" in tables else [],
            "entries": (
                _rows_to_dicts(conn, "SELECT * FROM mq_entries ORDER BY rowid DESC LIMIT ?", (limit,))
                if "mq_entries" in tables
                else []
            ),
            "receipts": (
                _rows_to_dicts(conn, "SELECT * FROM mq_receipts ORDER BY rowid DESC LIMIT ?", (limit,))
                if "mq_receipts" in tables
                else []
            ),
        }
        status_counts: dict[str, int] = {}
        for t in tasks:
            st = str(t.get("status") or "unknown")
            status_counts[st] = status_counts.get(st, 0) + 1
        active_dispatches = sum(
            1 for d in dispatches if str(d.get("state") or "").lower() in ("running", "ready", "dispatched", "active")
        )
        open_gates = sum(1 for g in gates if str(g.get("status") or "").lower() in ("open", "pending", "waiting"))
        queued_merges = sum(1 for e in mq["entries"] if str(e.get("state") or "").upper() in ("QUEUED", "TESTING"))
        return {
            "db_path": str(db_path),
            "db_exists": True,
            "runs": runs,
            "tasks": tasks,
            "dispatches": dispatches,
            "terminals": terminals,
            "gates": gates,
            "messages": messages,
            "launch_intents": intents,
            "merge_queue": mq,
            "summary": {
                "runs": len(runs),
                "tasks_total": len(tasks),
                "tasks_by_status": status_counts,
                "active_dispatches": active_dispatches,
                "open_gates": open_gates,
                "queued_merges": queued_merges,
            },
        }
    finally:
        conn.close()


def read_jsonl_tail(path: Path, *, limit: int = 50) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    entries: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for raw in lines[-limit:]:
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                entries.append(obj)
        except ValueError:
            continue
    return entries


def read_decisions(repo_dir: Path | None = None, *, limit: int = 60) -> dict[str, Any]:
    """Parse docs/DECISIONS.md durable gate entries (`ts · id · class · answer · why · task?`)."""
    root = (repo_dir or find_catalog_root()).resolve()
    path = root / "docs" / "DECISIONS.md"
    if not path.is_file():
        return {"path": str(path), "exists": False, "total": 0, "by_class": {}, "entries": []}
    rows: list[dict[str, Any]] = []
    by_class: dict[str, int] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {"path": str(path), "exists": False, "total": 0, "by_class": {}, "entries": []}
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if " · " not in stripped:
            continue
        parts = [p.strip() for p in stripped.split(" · ")]
        if len(parts) < 5:
            continue
        ts, gate_id, klass, answer, why = parts[:5]
        task_id = parts[5] if len(parts) > 5 else ""
        by_class[klass] = by_class.get(klass, 0) + 1
        rows.append({
            "line": lineno,
            "ts": ts,
            "id": gate_id,
            "class": klass,
            "answer": answer,
            "why": why,
            "task_id": task_id,
        })
    return {
        "path": str(path),
        "exists": True,
        "total": len(rows),
        "by_class": by_class,
        "entries": list(reversed(rows[-limit:])),
    }


def read_workspace_status(
    repo_dir: Path | None = None,
    *,
    db_override: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Combined operational snapshot for `open-fleet status`, MCP, and Mission Control UI."""
    target = (repo_dir or Path.cwd()).resolve()
    runtime_state = read_runtime_state(target, db_override=db_override, env=env)
    events_path = target / ".orca" / "events.jsonl"
    egress_path = target / ".orca" / "egress.jsonl"
    events = read_jsonl_tail(events_path, limit=40)
    egress = read_jsonl_tail(egress_path, limit=40)
    decisions = read_decisions(target, limit=40)
    return {
        "repo": str(target),
        "runtime_state": runtime_state,
        "events": {"path": str(events_path), "exists": events_path.is_file(), "count": len(events), "recent": list(reversed(events))},
        "egress": {"path": str(egress_path), "exists": egress_path.is_file(), "count": len(egress), "recent": list(reversed(egress))},
        "decisions": decisions,
    }
