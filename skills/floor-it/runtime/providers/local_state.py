#!/usr/bin/env python3
"""local_state.py — Portable SQLite WAL Run, Task DAG, Typed Mailbox, Gate & File-Touch Engine.

Provides a zero-daemon, stdlib-only (`sqlite3` in WAL mode) state store shared by
`PosixWorktreeProvider` and external orchestrator providers that need:
  1. Task DAG with automatic `deps[]` -> `ready` / `blocked` promotion (#579).
  2. At-least-once typed mailbox (`send`, `check --wait --ack`, `reply`) with consumer fencing
     (`consumer_fenced`) and 15-second `{"_keepalive": true}` heartbeats (#579).
  3. Durable HITL `gates` (`ask`) (#579).
  4. Real-time line-range `file_touches` conflict detection (`overlapping_hunk` vs
     `same_file_disjoint_hunk`, learned from `1jehuang/jcode`) (#590).
  5. Synthetic `worker_died` guarantee when a headless turn exits without sending terminal mail
     (learned from `jayminwest/overstory`) (#590).
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from .base import ProviderError, env_get

TERMINAL_MESSAGE_TYPES = ("worker_done", "merge_ready", "escalation")
# task_ops.py vocabulary (pending|ready|dispatched|completed|failed) plus the DAG hold `blocked`.
TASK_STATUSES = ("pending", "ready", "dispatched", "completed", "failed", "blocked")
FENCED_DISPATCH_STATES = ("stopped", "abandoned", "released")
COORDINATOR_ALIAS = "coordinator"


def _repo_state_id(start: str | None = None) -> str:
    """Stable per-repository id shared by the main checkout and all of its linked worktrees."""
    cwd = start or os.getcwd()
    root = ""
    try:
        proc = subprocess.run(
            ["git", "-C", cwd, "rev-parse", "--path-format=absolute", "--git-common-dir"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            root = str(Path(proc.stdout.strip()).resolve())
    except (OSError, subprocess.SubprocessError):
        root = ""
    root = root or str(Path(cwd).resolve())
    name = Path(root).parent.name if Path(root).name == ".git" else Path(root).name
    slug = "".join(c if c.isalnum() or c in "._-" else "-" for c in name).strip("-") or "repo"
    return f"{slug}-{hashlib.sha256(root.encode()).hexdigest()[:12]}"


def default_db_path(env: dict[str, str] | None = None) -> Path:
    custom = env_get("OPEN_FLEET_STATE_DB", "ORCA_FLEET_STATE_DB", env, "")
    if custom:
        return Path(custom).expanduser().resolve()
    root = env_get("OPEN_FLEET_STATE_DIR", "ORCA_FLEET_STATE_DIR", env, "")
    if root:
        return (Path(root).expanduser().resolve() / "runtime.db")
    # Per-repository default (#579): `~/.open-fleet/state/<repo-id>/runtime.db`, keyed on the git
    # common dir so a coordinator and the workers in its linked worktrees share ONE store while
    # unrelated repositories never share a DB.
    start = (env or os.environ).get("OPEN_FLEET_REPO_ROOT") or env_get("OPEN_FLEET_CLI_CWD", "ORCA_CLI_CWD", env, "")
    return Path.home() / ".open-fleet" / "state" / _repo_state_id(start or None) / "runtime.db"


class _ClosingConnection(sqlite3.Connection):
    """A connection whose `with` block also CLOSES it (sqlite3's own __exit__ only commits)."""

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        try:
            return super().__exit__(exc_type, exc, tb)
        finally:
            self.close()


class LocalStateStore:
    """Thread-safe / process-safe SQLite WAL state engine for runs, tasks, dispatches, mailbox, and file touches."""

    def __init__(self, db_path: str | Path | None = None, env: dict[str, str] | None = None):
        self.env = dict(os.environ if env is None else env)
        self.db_path = Path(db_path) if db_path else default_db_path(env)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        # `with sqlite3.connect(...) as conn` only commits; it never closes, so every store
        # call leaked a connection until GC (a ResourceWarning on 3.13). _ClosingConnection
        # closes when its `with` block ends.
        conn = sqlite3.connect(str(self.db_path), timeout=30.0, isolation_level=None, factory=_ClosingConnection)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=30000;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY,
                    coordinator_handle TEXT,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL DEFAULT 'default',
                    title TEXT,
                    display_name TEXT,
                    spec TEXT NOT NULL,
                    status TEXT NOT NULL,
                    parent_id TEXT,
                    result_json TEXT,
                    sender TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS task_deps (
                    task_id TEXT NOT NULL,
                    dep_id TEXT NOT NULL,
                    PRIMARY KEY (task_id, dep_id)
                );
                CREATE TABLE IF NOT EXISTS dispatches (
                    dispatch_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    run_id TEXT NOT NULL DEFAULT 'default',
                    worktree TEXT NOT NULL,
                    agent TEXT NOT NULL,
                    profile TEXT NOT NULL DEFAULT 'rw',
                    terminal_handle TEXT NOT NULL,
                    state TEXT NOT NULL,
                    terminal_state TEXT NOT NULL DEFAULT 'active',
                    pid INTEGER,
                    backend TEXT DEFAULT 'setsid',
                    launch_effective TEXT,
                    lane_dir TEXT,
                    session_id TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS terminals (
                    handle TEXT PRIMARY KEY,
                    worktree TEXT,
                    title TEXT,
                    command TEXT,
                    shell TEXT,
                    pid INTEGER,
                    backend TEXT DEFAULT 'setsid',
                    log_path TEXT,
                    state TEXT NOT NULL DEFAULT 'running',
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL DEFAULT 'default',
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    msg_type TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    outcome TEXT,
                    payload TEXT,
                    attrs_json TEXT,
                    reply_to TEXT,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS deliveries (
                    delivery_id TEXT PRIMARY KEY,
                    message_id TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    run_id TEXT NOT NULL DEFAULT 'default',
                    acked INTEGER NOT NULL DEFAULT 0,
                    acked_at REAL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS gates (
                    gate_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL DEFAULT 'default',
                    sender TEXT,
                    recipient TEXT,
                    question TEXT NOT NULL,
                    options_json TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    answer TEXT,
                    created_at REAL NOT NULL,
                    resolved_at REAL
                );
                CREATE TABLE IF NOT EXISTS requests (
                    request_id TEXT PRIMARY KEY,
                    method TEXT NOT NULL,
                    state TEXT NOT NULL,
                    response_json TEXT,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS file_touches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL DEFAULT 'default',
                    worker_id TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    start_line INTEGER NOT NULL DEFAULT 1,
                    end_line INTEGER NOT NULL DEFAULT 999999,
                    op TEXT NOT NULL DEFAULT 'write',
                    created_at REAL NOT NULL
                );
                """
            )
            self._migrate(conn)

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Additive column migrations for stores created by an older schema."""
        wanted = {
            "gates": {"task_id": "TEXT", "message_id": "TEXT", "prev_status": "TEXT", "kind": "TEXT DEFAULT 'ask'"},
            "runs": {"objective": "TEXT"},
            "terminals": {"backend_ref": "TEXT"},
            "dispatches": {"backend_ref": "TEXT", "head_sha": "TEXT"},
        }
        for table, cols in wanted.items():
            have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            for col, decl in cols.items():
                if col not in have:
                    try:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
                    except sqlite3.OperationalError as exc:  # concurrent migrator won the race
                        if "duplicate column" not in str(exc).lower():
                            raise

    # --- Idempotent request tracking ---
    def get_or_record_request(self, request_id: str | None, method: str) -> dict[str, Any] | None:
        if not request_id:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT method, state, response_json FROM requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if not row:
                return None
            if row["method"] != method:
                raise ProviderError("request_mismatch", f"retry-request {request_id!r} bound to {row['method']}, not {method}")
            if row["response_json"]:
                return json.loads(row["response_json"])
            return {"state": row["state"], "requestId": request_id}

    def save_request(self, request_id: str | None, method: str, state: str, response: dict[str, Any]) -> None:
        if not request_id:
            return
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO requests(request_id, method, state, response_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (request_id, method, state, json.dumps(response), time.time()),
            )

    def request_show(self, request_id: str) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT state, response_json FROM requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if not row:
                return {"requestId": request_id, "state": "absent"}
            return {"requestId": request_id, "state": row["state"]}

    # --- Run & Task DAG ---
    def task_create(
        self,
        *,
        spec: str,
        title: str | None = None,
        display_name: str | None = None,
        deps: list[str] | None = None,
        parent: str | None = None,
        run: str | None = None,
        sender: str | None = None,
        retry_request: str | None = None,
        initial_status: str | None = None,
    ) -> dict[str, Any]:
        cached = self.get_or_record_request(retry_request, "task-create")
        if cached:
            return cached
        run_id = run or "default"
        deps_list = list(deps or [])
        now = time.time()
        task_id = f"task_{uuid.uuid4().hex[:10]}"
        if initial_status is not None and initial_status not in TASK_STATUSES:
            raise ProviderError("invalid_status", f"unknown task status {initial_status!r} (want {'|'.join(TASK_STATUSES)})")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if initial_status is not None:
                status = initial_status
            elif not deps_list:
                status = "ready"
            else:
                placeholders = ",".join("?" for _ in deps_list)
                rows = conn.execute(
                    f"SELECT id, status FROM tasks WHERE id IN ({placeholders})",
                    deps_list,
                ).fetchall()
                by_id = {r["id"]: r["status"] for r in rows}
                missing = [d for d in deps_list if d not in by_id]
                if missing:
                    conn.execute("ROLLBACK")
                    raise ProviderError("task_not_found", f"dependency task(s) not found: {', '.join(missing)}")
                if any(by_id.get(d) in ("failed", "blocked") for d in deps_list):
                    status = "blocked"
                elif all(by_id.get(d) == "completed" for d in deps_list):
                    status = "ready"
                else:
                    status = "pending"
            conn.execute(
                """
                INSERT INTO tasks(id, run_id, title, display_name, spec, status, parent_id, sender, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (task_id, run_id, title, display_name, spec, status, parent, sender, now, now),
            )
            for dep in deps_list:
                conn.execute(
                    "INSERT OR IGNORE INTO task_deps(task_id, dep_id) VALUES (?, ?)",
                    (task_id, dep),
                )
            conn.execute("COMMIT")
        res = {
            "task": {
                "id": task_id,
                "status": status,
                "spec": spec,
                "title": title or display_name or task_id,
                "deps": deps_list,
                "parent": parent,
                "runId": run_id,
            }
        }
        self.save_request(retry_request, "task-create", "completed", res)
        return res

    def _recompute_dependents(self, conn: sqlite3.Connection, changed_task_id: str) -> list[str]:
        """Re-derive every transitive dependent's DAG status after `changed_task_id` changed.

        A failure blocks the WHOLE downstream closure (not just direct children), and a later
        completion of a failed dependency un-blocks them again (#579 audit: grandchildren of a
        failed task used to stay `pending` forever). Tasks a gate holds (`gates.task_id` pending)
        stay `blocked`. Returns the ids promoted to `ready`.
        """
        promoted: list[str] = []
        now = time.time()
        queue = [changed_task_id]
        seen: set[str] = set()
        while queue:
            cur = queue.pop(0)
            if cur in seen:
                continue
            seen.add(cur)
            for r in conn.execute("SELECT task_id FROM task_deps WHERE dep_id = ?", (cur,)).fetchall():
                child_id = r["task_id"]
                child = conn.execute("SELECT status FROM tasks WHERE id = ?", (child_id,)).fetchone()
                if not child or child["status"] not in ("pending", "ready", "blocked"):
                    continue
                statuses = [
                    x["status"]
                    for x in conn.execute(
                        "SELECT t.status FROM task_deps d LEFT JOIN tasks t ON t.id = d.dep_id WHERE d.task_id = ?",
                        (child_id,),
                    ).fetchall()
                ]
                if self._gate_holds(conn, child_id) or any(st in ("failed", "blocked") for st in statuses):
                    new_status = "blocked"
                elif statuses and all(st == "completed" for st in statuses):
                    new_status = "ready"
                else:
                    new_status = "pending"
                if new_status != child["status"]:
                    conn.execute(
                        "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
                        (new_status, now, child_id),
                    )
                    if new_status == "ready":
                        promoted.append(child_id)
                    queue.append(child_id)
        return promoted

    @staticmethod
    def _gate_holds(conn: sqlite3.Connection, task_id: str) -> bool:
        row = conn.execute(
            "SELECT 1 FROM gates WHERE task_id = ? AND status = 'pending' LIMIT 1",
            (task_id,),
        ).fetchone()
        return bool(row)

    def task_update(
        self,
        *,
        task_id: str,
        status: str,
        result: str | None = None,
        run: str | None = None,
        sender: str | None = None,
        retry_request: str | None = None,
    ) -> dict[str, Any]:
        cached = self.get_or_record_request(retry_request, "task-update")
        if cached:
            return cached
        if status not in TASK_STATUSES:
            raise ProviderError("invalid_status", f"unknown task status {status!r} (want {'|'.join(TASK_STATUSES)})")
        now = time.time()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT id FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if not row:
                conn.execute("ROLLBACK")
                raise ProviderError("task_not_found", f"task {task_id!r} not found")
            conn.execute(
                "UPDATE tasks SET status = ?, result_json = COALESCE(?, result_json), updated_at = ? WHERE id = ?",
                (status, result, now, task_id),
            )
            promoted = self._recompute_dependents(conn, task_id)
            conn.execute("COMMIT")
        res = {"task": {"id": task_id, "status": status, "promotedDependents": promoted}}
        self.save_request(retry_request, "task-update", "completed", res)
        return res

    def task_list(
        self,
        *,
        run: str | None = None,
        sender: str | None = None,
        brief: bool = False,
    ) -> dict[str, Any]:
        with self._connect() as conn:
            if run:
                rows = conn.execute(
                    "SELECT * FROM tasks WHERE run_id = ? ORDER BY created_at ASC",
                    (run,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM tasks ORDER BY created_at ASC").fetchall()
            tasks: list[dict[str, Any]] = []
            for r in rows:
                dep_rows = conn.execute(
                    "SELECT dep_id FROM task_deps WHERE task_id = ? ORDER BY dep_id ASC",
                    (r["id"],),
                ).fetchall()
                item: dict[str, Any] = {
                    "id": r["id"],
                    "status": r["status"],
                    "deps": [d["dep_id"] for d in dep_rows],
                    "runId": r["run_id"],
                }
                if not brief:
                    item["spec"] = r["spec"]
                    item["title"] = r["title"] or r["display_name"] or r["id"]
                    item["parent"] = r["parent_id"]
                tasks.append(item)
        return {"tasks": tasks}

    # --- Runs & coordinator fencing ---
    def _worker_handles(self, conn: sqlite3.Connection) -> set[str]:
        rows = conn.execute("SELECT terminal_handle, dispatch_id FROM dispatches").fetchall()
        out: set[str] = set()
        for r in rows:
            out.update(x for x in (r["terminal_handle"], r["dispatch_id"]) if x)
        return out

    def _resolve_terminal(self, terminal: str | None) -> str | None:
        return terminal or env_get("OPEN_FLEET_TERMINAL_HANDLE", "ORCA_TERMINAL_HANDLE", self.env, "") or None

    def _claim_coordinator(self, conn: sqlite3.Connection, run_id: str, terminal: str) -> str:
        """Fence `run_id`'s coordinator inbox to the first non-worker handle that reads it.

        Atomic under `BEGIN IMMEDIATE` (`INSERT OR IGNORE` + re-read), so N concurrent claimers
        yield exactly one owner and N-1 `consumer_fenced` errors — never a raw IntegrityError.
        """
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT OR IGNORE INTO runs(id, coordinator_handle, created_at) VALUES (?, ?, ?)",
                (run_id, terminal, time.time()),
            )
            row = conn.execute("SELECT coordinator_handle FROM runs WHERE id = ?", (run_id,)).fetchone()
            owner = row["coordinator_handle"] if row else None
            if not owner:
                conn.execute("UPDATE runs SET coordinator_handle = ? WHERE id = ?", (terminal, run_id))
                owner = terminal
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        if owner != terminal:
            raise ProviderError(
                "consumer_fenced",
                f"run {run_id!r} inbox is already fenced to coordinator {owner!r} (rejected {terminal!r})",
            )
        return owner

    def _own_worker_identity(self) -> list[str]:
        """Handles of the worker THIS process runs as (set by the launcher), else []."""
        dispatch = env_get("OPEN_FLEET_DISPATCH_ID", "ORCA_DISPATCH_ID", self.env, "")
        if not dispatch:
            return []
        handle = env_get("OPEN_FLEET_TERMINAL_HANDLE", "ORCA_TERMINAL_HANDLE", self.env, "")
        return [h for h in (handle, dispatch) if h]

    def _mailbox_scope(self, conn: sqlite3.Connection, run_id: str, terminal: str | None) -> list[str]:
        """Recipients a caller may read/ack. Workers get ONLY their own mail; the `coordinator`
        alias resolves for the run's fenced coordinator (or an anonymous operator shell) only."""
        own = self._own_worker_identity()
        if own:
            # A launched worker is pinned to its own mailbox whatever --terminal it passes
            # (`--terminal coordinator` used to hand it the coordinator inbox, #591 re-review).
            return own
        if terminal and terminal != COORDINATOR_ALIAS:
            if terminal in self._worker_handles(conn):
                return [terminal]
            env_coord = env_get("OPEN_FLEET_COORDINATOR_HANDLE", "ORCA_COORDINATOR_HANDLE", self.env, "")
            if run_id != "default" or (env_coord and terminal == env_coord):
                self._claim_coordinator(conn, run_id, terminal)
            return [terminal, COORDINATOR_ALIAS]
        # No handle at all (operator shell) or the literal alias: the coordinator mailbox. A
        # fenced run refuses this anonymous reader, so a fenced coordinator cannot be bypassed.
        row = conn.execute("SELECT coordinator_handle FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row and row["coordinator_handle"] and run_id != "default":
            raise ProviderError(
                "consumer_fenced",
                f"run {run_id!r} inbox is fenced to coordinator {row['coordinator_handle']!r}; pass --terminal",
            )
        return [COORDINATOR_ALIAS]

    def run_create(self, *, objective: str | None = None, run: str | None = None, sender: str | None = None) -> dict[str, Any]:
        run_id = run or f"run_{uuid.uuid4().hex[:10]}"
        coordinator = self._resolve_terminal(sender)
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO runs(id, coordinator_handle, objective, created_at) VALUES (?, ?, ?, ?)",
                (run_id, coordinator, objective or "", time.time()),
            )
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return {"run": {"id": run_id, "objective": row["objective"], "coordinator": row["coordinator_handle"]}}

    def run_use(self, *, run: str, sender: str | None = None, takeover: bool = False) -> dict[str, Any]:
        terminal = self._resolve_terminal(sender)
        if not run:
            raise ProviderError("invalid_argument", "run-use needs --id <run>")
        if not terminal:
            raise ProviderError("invalid_argument", "run-use needs the adopting terminal (--from or OPEN_FLEET_TERMINAL_HANDLE)")
        with self._connect() as conn:
            row = conn.execute("SELECT coordinator_handle FROM runs WHERE id = ?", (run,)).fetchone()
            if not row:
                raise ProviderError("run_not_found", f"run {run!r} not found")
            if takeover and row["coordinator_handle"] != terminal:
                conn.execute("UPDATE runs SET coordinator_handle = ? WHERE id = ?", (terminal, run))
            else:
                self._claim_coordinator(conn, run, terminal)
        return {"run": {"id": run, "coordinator": terminal, "takeover": bool(takeover)}}

    # --- Typed Mailbox & Blocking Wait ---
    @staticmethod
    def _insert_message(
        conn: sqlite3.Connection,
        *,
        run_id: str,
        sender: str,
        recipient: str,
        msg_type: str,
        subject: str,
        outcome: str | None,
        payload: str | None,
        attrs: dict[str, Any] | None,
        reply_to: str | None = None,
    ) -> tuple[str, str]:
        msg_id = f"msg_{uuid.uuid4().hex[:12]}"
        deliv_id = f"dlv_{uuid.uuid4().hex[:12]}"
        now = time.time()
        conn.execute(
            """
            INSERT INTO messages(id, run_id, sender, recipient, msg_type, subject, outcome, payload, attrs_json, reply_to, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (msg_id, run_id, sender, recipient, msg_type, subject, outcome, payload, json.dumps(attrs or {}), reply_to, now),
        )
        conn.execute(
            "INSERT INTO deliveries(delivery_id, message_id, recipient, run_id, acked, created_at) VALUES (?, ?, ?, ?, 0, ?)",
            (deliv_id, msg_id, recipient, run_id, now),
        )
        return msg_id, deliv_id

    def send_message(
        self,
        *,
        subject: str,
        msg_type: str,
        to: str | None = None,
        outcome: str | None = None,
        sender: str | None = None,
        payload: str | None = None,
        run: str | None = None,
        attrs: dict[str, Any] | None = None,
        reply_to: str | None = None,
    ) -> dict[str, Any]:
        run_id = run or "default"
        recipient = to or COORDINATOR_ALIAS
        sender_id = sender or self._resolve_terminal(None) or "worker"
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            msg_id, deliv_id = self._insert_message(
                conn,
                run_id=run_id,
                sender=sender_id,
                recipient=recipient,
                msg_type=msg_type,
                subject=subject,
                outcome=outcome,
                payload=payload,
                attrs=attrs,
                reply_to=reply_to,
            )
            conn.execute("COMMIT")
        message = {
            "id": msg_id,
            "deliveryId": deliv_id,
            "type": msg_type,
            "subject": subject,
            "from": sender_id,
            "to": recipient,
            "outcome": outcome,
        }
        return {
            "sent": True,
            "messageId": msg_id,
            "deliveryId": deliv_id,
            "message": message,
            # send_msg.py reads `relay.messageId` (Orca's receipt shape, #578 audit).
            "relay": {"messageId": msg_id, "deliveryId": deliv_id, "to": recipient},
        }

    def check_messages(
        self,
        *,
        terminal: str | None = None,
        run: str | None = None,
        ack: str | list[str] | None = None,
        mode: str = "unread",
        types: str | None = None,
        fmt: bool = False,
        wait: bool = False,
        timeout_ms: int | None = None,
        retry_request: str | None = None,
    ) -> dict[str, Any]:
        run_id = run or "default"
        terminal = self._resolve_terminal(terminal)
        ack_ids: list[str] = []
        if isinstance(ack, str) and ack:
            ack_ids = [x.strip() for x in ack.split(",") if x.strip()]
        elif isinstance(ack, list):
            ack_ids = [str(x).strip() for x in ack if str(x).strip()]

        type_filter = {x.strip() for x in types.split(",") if x.strip()} if types else None
        deadline = time.time() + ((timeout_ms or 5000) / 1000.0 if wait else 0.0)
        last_keepalive = time.time()

        with self._connect() as conn:
            allowed_recipients = self._mailbox_scope(conn, run_id, terminal)
            if ack_ids:
                now = time.time()
                placeholders = ",".join("?" for _ in allowed_recipients)
                for aid in ack_ids:
                    # Acks are ALWAYS scoped to the caller's own mailbox and run: a worker can
                    # never drain the coordinator's unread inbox (#591 review).
                    conn.execute(
                        "UPDATE deliveries SET acked = 1, acked_at = ? "
                        f"WHERE (delivery_id = ? OR message_id = ?) AND run_id = ? AND recipient IN ({placeholders})",
                        [now, aid, aid, run_id, *allowed_recipients],
                    )

        while True:
            with self._connect() as conn:
                placeholders = ",".join("?" for _ in allowed_recipients)
                query = f"""
                    SELECT d.delivery_id, d.acked, m.*
                    FROM deliveries d
                    JOIN messages m ON m.id = d.message_id
                    WHERE d.run_id = ? AND d.recipient IN ({placeholders})
                """
                params: list[Any] = [run_id, *allowed_recipients]
                if mode != "all":
                    query += " AND d.acked = 0"
                query += " ORDER BY m.created_at ASC"
                rows = conn.execute(query, params).fetchall()
                items: list[dict[str, Any]] = []
                for r in rows:
                    if type_filter and r["msg_type"] not in type_filter:
                        continue
                    items.append(
                        {
                            "id": r["id"],
                            "messageId": r["id"],
                            "deliveryId": r["delivery_id"],
                            "type": r["msg_type"],
                            "subject": r["subject"],
                            "from": r["sender"],
                            "from_handle": r["sender"],
                            "to": r["recipient"],
                            "outcome": r["outcome"],
                            "payload": r["payload"],
                            "body": r["payload"] or r["subject"],
                            "replyTo": r["reply_to"],
                            "attrs": json.loads(r["attrs_json"] or "{}"),
                            "acked": bool(r["acked"]),
                            "createdAt": r["created_at"],
                        }
                    )
                if items or not wait or time.time() >= deadline:
                    return {
                        "messages": items,
                        "deliveries": items,
                        "count": len(items),
                        "deliveryId": items[-1]["deliveryId"] if items else None,
                        "acked": len(ack_ids),
                        "waited": bool(wait),
                        "timedOut": bool(wait and not items),
                    }
            now = time.time()
            if now - last_keepalive >= 15.0:
                print('{"_keepalive": true}', file=sys.stderr, flush=True)
                last_keepalive = now
            time.sleep(min(0.1, max(0.01, deadline - now)))

    def reply_message(
        self,
        *,
        msg_id: str,
        body: str,
        run: str | None = None,
        sender: str | None = None,
        retry_request: str | None = None,
    ) -> dict[str, Any]:
        cached = self.get_or_record_request(retry_request, "reply")
        if cached:
            return cached
        with self._connect() as conn:
            orig = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()
            gate = None
            if not orig:
                # `reply --id <gate_id>` is accepted for gates whose id the caller holds.
                gate = conn.execute("SELECT * FROM gates WHERE gate_id = ?", (msg_id,)).fetchone()
                if gate and gate["message_id"]:
                    orig = conn.execute("SELECT * FROM messages WHERE id = ?", (gate["message_id"],)).fetchone()
            if not orig:
                raise ProviderError("message_not_found", f"message {msg_id!r} not found")
            attrs = json.loads(orig["attrs_json"] or "{}")
            gate_id = gate["gate_id"] if gate else attrs.get("gateId")
            replier = sender or self._resolve_terminal(None) or COORDINATOR_ALIAS
            if gate_id:
                gate_row = gate or conn.execute("SELECT * FROM gates WHERE gate_id = ?", (gate_id,)).fetchone()
                if gate_row:
                    # Refuse BEFORE the reply message is sent, not only at resolution.
                    self._check_gate_answerer(conn, gate_row, replier)
            recipient = orig["sender"]
            subject = f"Re: {orig['subject']}"
            run_id = run or orig["run_id"]
        sent = self.send_message(
            subject=subject,
            msg_type="info",
            to=recipient,
            sender=replier,
            payload=body,
            run=run_id,
            attrs={"replyTo": orig["id"], **({"gateId": gate_id} if gate_id else {})},
            reply_to=orig["id"],
        )
        resolved = None
        if gate_id:
            # Answering a worker's `ask` question by message id resolves its durable gate, so
            # `ask --resume <id>` returns the human's answer (#591 review: gates never completed).
            resolved = self.resolve_gate(gate_id, body, status="answered", resolver=replier)
        res = {
            "replied": True,
            "messageId": sent["messageId"],
            "replyMessageId": sent["messageId"],
            "to": recipient,
            "gate": resolved,
        }
        self.save_request(retry_request, "reply", "completed", res)
        return res

    # --- HITL Gate Transport ---
    def _gate_receipt(self, row: sqlite3.Row, options: list[Any] | None = None) -> dict[str, Any]:
        ans = row["answer"]
        status = row["status"]
        return {
            "gateId": row["gate_id"],
            "requestId": row["gate_id"],
            "messageId": row["message_id"] or row["gate_id"],
            "state": status,
            "status": status,
            "answer": ans,
            "timedOut": ans is None and status == "pending",
            "question": row["question"],
            "options": options if options is not None else json.loads(row["options_json"] or "[]"),
        }

    def _find_gate(self, conn: sqlite3.Connection, ident: str) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM gates WHERE gate_id = ? OR message_id = ? LIMIT 1",
            (ident, ident),
        ).fetchone()

    def _wait_gate(self, gate_id: str, timeout_ms: int | None) -> None:
        if not timeout_ms or int(timeout_ms) <= 0:
            return
        # hitl_ask.py blocks up to the 1 800 000 ms cap (gate-classification.md).
        deadline = time.time() + min(int(timeout_ms), 1_800_000) / 1000.0
        last_keepalive = time.time()
        while time.time() < deadline:
            with self._connect() as conn:
                r = conn.execute("SELECT status, answer FROM gates WHERE gate_id = ?", (gate_id,)).fetchone()
            if not r or r["answer"] is not None or r["status"] != "pending":
                return
            now = time.time()
            if now - last_keepalive >= 15.0:
                print('{"_keepalive": true}', file=sys.stderr, flush=True)
                last_keepalive = now
            time.sleep(min(0.25, max(0.01, deadline - now)))

    def ask_human(
        self,
        *,
        question: str | None = None,
        resume: str | None = None,
        to: str | None = None,
        run: str | None = None,
        options: str | None = None,
        timeout_ms: int | None = None,
        sender: str | None = None,
        retry_request: str | None = None,
    ) -> dict[str, Any]:
        """A worker's blocking `ask`: a durable gate + a `question` message to the run.

        The answer comes ONLY from a real reply (`reply --id <messageId>`) or `gate-resolve`;
        nothing in the fleet fabricates one (AGENTS.md: a fleet never fakes a human answer).
        """
        run_id = run or "default"
        if resume:
            with self._connect() as conn:
                row = self._find_gate(conn, resume)
            if not row:
                raise ProviderError("gate_not_found", f"gate/message {resume!r} not found")
            self._wait_gate(row["gate_id"], timeout_ms)
            with self._connect() as conn:
                row = self._find_gate(conn, resume)
            return self._gate_receipt(row)
        if not question:
            raise ProviderError("invalid_argument", "ask needs --question (or --resume <id>)")
        gate_id = retry_request or f"gate_{uuid.uuid4().hex[:10]}"
        if isinstance(options, str) and options.strip().startswith("["):
            opts = json.loads(options)
        else:
            opts = [o.strip() for o in options.split(",") if o.strip()] if options else []
        asker = sender or self._resolve_terminal(None) or "worker"
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT * FROM gates WHERE gate_id = ?", (gate_id,)).fetchone()
            if existing is None:
                msg_id, _ = self._insert_message(
                    conn,
                    run_id=run_id,
                    sender=asker,
                    recipient=to or COORDINATOR_ALIAS,
                    msg_type="question",
                    subject=question,
                    outcome=None,
                    payload=json.dumps({"gateId": gate_id, "question": question, "options": opts}),
                    attrs={"gateId": gate_id},
                )
                # INSERT OR IGNORE semantics: a retried ask (same --retry-request) never wipes
                # an answer that already arrived and never posts a duplicate question.
                conn.execute(
                    """
                    INSERT INTO gates(gate_id, run_id, sender, recipient, question, options_json, status, message_id, kind, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, 'ask', ?)
                    """,
                    (gate_id, run_id, asker, to or "human", question, json.dumps(opts), msg_id, time.time()),
                )
            conn.execute("COMMIT")
        self._wait_gate(gate_id, timeout_ms)
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM gates WHERE gate_id = ?", (gate_id,)).fetchone()
        return self._gate_receipt(row)

    def gate_create(
        self,
        *,
        task_id: str,
        question: str,
        options: str | None = None,
        run: str | None = None,
        sender: str | None = None,
        retry_request: str | None = None,
    ) -> dict[str, Any]:
        """DAG gate (gate-classification.md): the task is `blocked` until `gate-resolve`."""
        if not task_id or not question:
            raise ProviderError("invalid_argument", "gate-create needs both --task and --question")
        cached = self.get_or_record_request(retry_request, "gate-create")
        if cached:
            return cached
        opts: list[Any] = []
        if options:
            try:
                opts = json.loads(options)
            except json.JSONDecodeError as exc:
                raise ProviderError("invalid_argument", "gate-create --options takes a JSON array") from exc
            if not isinstance(opts, list):
                raise ProviderError("invalid_argument", "gate-create --options takes a JSON array")
        gate_id = f"gate_{uuid.uuid4().hex[:10]}"
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            t = conn.execute("SELECT status, run_id FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if not t:
                conn.execute("ROLLBACK")
                raise ProviderError("task_not_found", f"task {task_id!r} not found")
            active = conn.execute(
                "SELECT dispatch_id FROM dispatches WHERE task_id = ? AND state NOT IN "
                "('stopped','abandoned','released','died','completed') LIMIT 1",
                (task_id,),
            ).fetchone()
            if active:
                conn.execute("ROLLBACK")
                raise ProviderError(
                    "task_not_startable",
                    f"task {task_id!r} has active dispatch {active['dispatch_id']!r}; stop or settle it first",
                )
            conn.execute(
                """
                INSERT INTO gates(gate_id, run_id, sender, recipient, question, options_json, status, task_id, prev_status, kind, created_at)
                VALUES (?, ?, ?, 'human', ?, ?, 'pending', ?, ?, 'dag', ?)
                """,
                (gate_id, run or t["run_id"], sender or COORDINATOR_ALIAS, question, json.dumps(opts), task_id, t["status"], time.time()),
            )
            conn.execute("UPDATE tasks SET status = 'blocked', updated_at = ? WHERE id = ?", (time.time(), task_id))
            self._recompute_dependents(conn, task_id)
            conn.execute("COMMIT")
        res = {"gate": {"id": gate_id, "taskId": task_id, "status": "pending", "question": question, "options": opts}}
        self.save_request(retry_request, "gate-create", "completed", res)
        return res

    def gate_resolve(
        self,
        *,
        gate_id: str,
        resolution: str,
        sender: str | None = None,
        retry_request: str | None = None,
    ) -> dict[str, Any]:
        if not gate_id or resolution is None:
            raise ProviderError("invalid_argument", "gate-resolve needs --id and --resolution")
        res = self.resolve_gate(gate_id, resolution, status="resolved", resolver=sender)
        return {"gate": {"id": gate_id, "status": res["status"], "resolution": resolution, "taskId": res.get("taskId")}}

    def gate_list(self, *, run: str | None = None, task_id: str | None = None, status: str | None = None) -> dict[str, Any]:
        q = "SELECT * FROM gates WHERE 1=1"
        params: list[Any] = []
        for col, val in (("run_id", run), ("task_id", task_id), ("status", status)):
            if val:
                q += f" AND {col} = ?"
                params.append(val)
        with self._connect() as conn:
            rows = conn.execute(q + " ORDER BY created_at ASC", params).fetchall()
        return {
            "gates": [
                {
                    "id": r["gate_id"],
                    "taskId": r["task_id"],
                    "kind": r["kind"] or "ask",
                    "status": r["status"],
                    "question": r["question"],
                    "answer": r["answer"],
                    "messageId": r["message_id"],
                }
                for r in rows
            ]
        }

    def _check_gate_answerer(self, conn: sqlite3.Connection, gate_row: sqlite3.Row, resolver: str) -> None:
        """Only the coordinator/human answers a gate: never a launched worker, never the asker."""
        # The asker test applies to a worker's `ask`; a DAG gate's sender is the coordinator
        # that created it, and resolving its own hold is exactly its job.
        is_ask = (gate_row["kind"] or "ask") != "dag"
        if self._own_worker_identity() or (is_ask and resolver == gate_row["sender"]) or resolver in self._worker_handles(conn):
            raise ProviderError(
                "gate_answer_refused",
                f"{resolver!r} cannot answer gate {gate_row['gate_id']!r}: only the coordinator/human may",
            )

    def resolve_gate(
        self,
        gate_id: str,
        answer: str,
        status: str = "answered",
        resolver: str | None = None,
    ) -> dict[str, Any]:
        """The ONE boundary every answer path (reply, gate-resolve, ask) crosses (#592 review)."""
        who = resolver or self._resolve_terminal(None) or COORDINATOR_ALIAS
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = self._find_gate(conn, gate_id)
            if not row:
                conn.execute("ROLLBACK")
                raise ProviderError("gate_not_found", f"gate {gate_id!r} not found")
            try:
                self._check_gate_answerer(conn, row, who)
            except ProviderError:
                conn.execute("ROLLBACK")
                raise
            if row["status"] != "pending":
                conn.execute("COMMIT")
                return {"gateId": row["gate_id"], "status": row["status"], "answer": row["answer"], "taskId": row["task_id"], "alreadyResolved": True}
            conn.execute(
                "UPDATE gates SET status = ?, answer = ?, resolved_at = ? WHERE gate_id = ?",
                (status, answer, time.time(), row["gate_id"]),
            )
            if row["message_id"]:
                # The question is handled: it must stop reading as unread inbox work (and as
                # `waiting_input` to the watchdog) once its gate is answered (#592 review).
                conn.execute(
                    "UPDATE deliveries SET acked = 1, acked_at = ? WHERE message_id = ? AND acked = 0",
                    (time.time(), row["message_id"]),
                )
            if row["task_id"]:
                # Release the DAG hold: re-derive the task's status from its deps.
                t = conn.execute("SELECT status FROM tasks WHERE id = ?", (row["task_id"],)).fetchone()
                if t and t["status"] == "blocked" and not self._gate_holds(conn, row["task_id"]):
                    deps = [
                        x["status"]
                        for x in conn.execute(
                            "SELECT t.status FROM task_deps d LEFT JOIN tasks t ON t.id = d.dep_id WHERE d.task_id = ?",
                            (row["task_id"],),
                        ).fetchall()
                    ]
                    if any(st in ("failed", "blocked") for st in deps):
                        new_status = "blocked"
                    elif not deps or all(st == "completed" for st in deps):
                        # Deps are done NOW: runnable, whatever it was when gated. Restoring a
                        # stale `pending` left it undispatchable forever (#592 review).
                        prev = row["prev_status"]
                        new_status = prev if prev in ("completed", "failed") else "ready"
                    else:
                        new_status = "pending"
                    conn.execute(
                        "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
                        (new_status, time.time(), row["task_id"]),
                    )
                    self._recompute_dependents(conn, row["task_id"])
            conn.execute("COMMIT")
        return {"gateId": row["gate_id"], "status": status, "answer": answer, "taskId": row["task_id"]}

    def has_pending_question(self, worker_id: str, run_id: str | None = None) -> bool:
        """Return True if `worker_id` has an unresolved HITL question gate (`waiting_input`)."""
        with self._connect() as conn:
            q = "SELECT COUNT(*) AS c FROM gates WHERE sender = ? AND status = 'pending'"
            params: list[Any] = [worker_id]
            if run_id:
                q += " AND run_id = ?"
                params.append(run_id)
            row = conn.execute(q, params).fetchone()
            if row and row["c"] > 0:
                return True
            # Also check unread `question` messages from this worker
            mq = """
                SELECT COUNT(*) AS c
                FROM deliveries d
                JOIN messages m ON m.id = d.message_id
                WHERE m.sender = ? AND m.msg_type = 'question' AND d.acked = 0
            """
            mparams: list[Any] = [worker_id]
            if run_id:
                mq += " AND d.run_id = ?"
                mparams.append(run_id)
            mrow = conn.execute(mq, mparams).fetchone()
            return bool(mrow and mrow["c"] > 0)

    def dispatch_state(self, dispatch_id: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute("SELECT state FROM dispatches WHERE dispatch_id = ?", (dispatch_id,)).fetchone()
        return row["state"] if row else None

    # --- #590: Real-Time Line-Range File-Touch Conflict Detection (learned from JCode) ---
    def record_file_touch(
        self,
        *,
        worker_id: str,
        file_path: str,
        start_line: int = 1,
        end_line: int = 999999,
        op: str = "write",
        run_id: str = "default",
    ) -> dict[str, Any]:
        norm_path = os.path.normpath(file_path)
        s_line = max(1, int(start_line))
        e_line = max(s_line, int(end_line))
        now = time.time()
        overlapping: list[dict[str, Any]] = []
        disjoint: list[dict[str, Any]] = []
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            others = conn.execute(
                """
                SELECT worker_id, start_line, end_line, op, created_at
                FROM file_touches
                WHERE run_id = ? AND file_path = ? AND worker_id != ?
                """,
                (run_id, norm_path, worker_id),
            ).fetchall()
            for o in others:
                o_start, o_end = int(o["start_line"]), int(o["end_line"])
                if max(s_line, o_start) <= min(e_line, o_end):
                    overlapping.append(
                        {
                            "kind": "overlapping_hunk",
                            "file": norm_path,
                            "worker": worker_id,
                            "otherWorker": o["worker_id"],
                            "lines": [s_line, e_line],
                            "otherLines": [o_start, o_end],
                        }
                    )
                else:
                    disjoint.append(
                        {
                            "kind": "same_file_disjoint_hunk",
                            "file": norm_path,
                            "worker": worker_id,
                            "otherWorker": o["worker_id"],
                            "lines": [s_line, e_line],
                            "otherLines": [o_start, o_end],
                        }
                    )
            conn.execute(
                """
                INSERT INTO file_touches(run_id, worker_id, file_path, start_line, end_line, op, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, worker_id, norm_path, s_line, e_line, op, now),
            )
            conn.execute("COMMIT")
        return {
            "recorded": True,
            "file": norm_path,
            "conflict": bool(overlapping),
            "conflicts": overlapping,
            "disjointTouches": disjoint,
        }

    # --- #590: Synthetic `worker_died` Guarantee on Exit Without Terminal Mail (learned from Overstory) ---
    def ensure_terminal_or_died(
        self,
        *,
        dispatch_id: str,
        worker_handle: str | None = None,
        exit_code: int = 1,
        last_tail: str = "",
        worktree_head_sha: str = "",
        run_id: str = "default",
    ) -> dict[str, Any]:
        """Atomically check if the worker sent terminal mail; if not, enqueue a synthetic `worker_died` escalation.

        One transaction covers the check, the dispatch state change and the escalation insert, so a
        racing second caller (exit monitor vs. liveness sweep) can never send it twice. A dispatch
        the coordinator fenced (stop/abandon/release) is left alone: its exit is expected.
        """
        senders = [s for s in {dispatch_id, worker_handle or ""} if s]
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            disp = conn.execute("SELECT state, run_id FROM dispatches WHERE dispatch_id = ?", (dispatch_id,)).fetchone()
            if disp is None:
                # Withdrawn before it launched (claim released): nothing died that anyone owns.
                conn.execute("COMMIT")
                return {"syntheticDied": False, "unknownDispatch": True}
            if disp["state"] in FENCED_DISPATCH_STATES:
                conn.execute("COMMIT")
                return {"syntheticDied": False, "fenced": disp["state"]}
            if disp and disp["state"] == "died":
                conn.execute("COMMIT")
                return {"syntheticDied": False, "alreadyDied": True}
            placeholders = ",".join("?" for _ in senders)
            row = conn.execute(
                f"""
                SELECT id, msg_type FROM messages
                WHERE run_id = ? AND sender IN ({placeholders})
                  AND msg_type IN ('worker_done', 'merge_ready', 'escalation')
                  AND COALESCE(attrs_json, '') NOT LIKE '%"fileTouchConflict"%'
                LIMIT 1
                """,
                [run_id, *senders],
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE dispatches SET state = 'completed', terminal_state = 'exited', head_sha = COALESCE(NULLIF(?, ''), head_sha), "
                    "updated_at = ? WHERE dispatch_id = ? AND state NOT IN ('stopped','abandoned','released')",
                    (worktree_head_sha, time.time(), dispatch_id),
                )
                conn.execute("COMMIT")
                return {"syntheticDied": False, "existingMessageId": row["id"], "type": row["msg_type"]}
            conn.execute(
                "UPDATE dispatches SET state = 'died', terminal_state = 'failed', head_sha = COALESCE(NULLIF(?, ''), head_sha), "
                "updated_at = ? WHERE dispatch_id = ?",
                (worktree_head_sha, time.time(), dispatch_id),
            )
            payload = json.dumps(
                {
                    "event": "worker_died",
                    "dispatchId": dispatch_id,
                    "exitCode": exit_code,
                    "lastTail": last_tail[-500:] if last_tail else "",
                    "headSha": worktree_head_sha,
                },
                sort_keys=True,
            )
            msg_id, deliv_id = self._insert_message(
                conn,
                run_id=run_id,
                sender=worker_handle or dispatch_id,
                recipient=COORDINATOR_ALIAS,
                msg_type="escalation",
                subject=f"worker_died:{dispatch_id} (exit={exit_code})",
                outcome="failed",
                payload=payload,
                attrs={"synthetic": "worker_died", "dispatchId": dispatch_id, "exitCode": str(exit_code)},
            )
            conn.execute("COMMIT")
        return {"syntheticDied": True, "messageId": msg_id, "deliveryId": deliv_id}
