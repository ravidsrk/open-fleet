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

import json
import os
import sqlite3
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from .base import ProviderError, env_get

TERMINAL_MESSAGE_TYPES = ("worker_done", "merge_ready", "escalation")


def default_db_path(env: dict[str, str] | None = None) -> Path:
    custom = env_get("OPEN_FLEET_STATE_DB", "ORCA_FLEET_STATE_DB", env, "")
    if custom:
        return Path(custom).expanduser().resolve()
    root = env_get("OPEN_FLEET_STATE_DIR", "ORCA_FLEET_STATE_DIR", env, "")
    if root:
        return (Path(root).expanduser().resolve() / "runtime.db")
    return Path.home() / ".open-fleet" / "state" / "runtime.db"


class LocalStateStore:
    """Thread-safe / process-safe SQLite WAL state engine for runs, tasks, dispatches, mailbox, and file touches."""

    def __init__(self, db_path: str | Path | None = None, env: dict[str, str] | None = None):
        self.env = dict(os.environ if env is None else env)
        self.db_path = Path(db_path) if db_path else default_db_path(env)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0, isolation_level=None)
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
        """Atomically promote `pending` dependents to `ready` (or `blocked` on failure)."""
        promoted: list[str] = []
        dep_rows = conn.execute(
            "SELECT task_id FROM task_deps WHERE dep_id = ?",
            (changed_task_id,),
        ).fetchall()
        now = time.time()
        for r in dep_rows:
            child_id = r["task_id"]
            child = conn.execute("SELECT status FROM tasks WHERE id = ?", (child_id,)).fetchone()
            if not child or child["status"] not in ("pending", "ready"):
                continue
            all_deps = conn.execute(
                """
                SELECT d.dep_id, t.status
                FROM task_deps d
                LEFT JOIN tasks t ON t.id = d.dep_id
                WHERE d.task_id = ?
                """,
                (child_id,),
            ).fetchall()
            statuses = [x["status"] for x in all_deps]
            if any(s in ("failed", "blocked") for s in statuses):
                conn.execute(
                    "UPDATE tasks SET status = 'blocked', updated_at = ? WHERE id = ?",
                    (now, child_id),
                )
            elif statuses and all(s == "completed" for s in statuses) and child["status"] == "pending":
                conn.execute(
                    "UPDATE tasks SET status = 'ready', updated_at = ? WHERE id = ?",
                    (now, child_id),
                )
                promoted.append(child_id)
        return promoted

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

    # --- Typed Mailbox & Blocking Wait ---
    def _fence_consumer(self, conn: sqlite3.Connection, run_id: str, terminal: str | None) -> None:
        if not terminal or not run_id or run_id == "default":
            return
        # Only fence coordinator inbox handles (handles starting with coord / orchestrator)
        if not (terminal.startswith("coord") or terminal.startswith("orchestrator")):
            return
        row = conn.execute("SELECT coordinator_handle FROM runs WHERE id = ?", (run_id,)).fetchone()
        if not row:
            conn.execute(
                "INSERT INTO runs(id, coordinator_handle, created_at) VALUES (?, ?, ?)",
                (run_id, terminal, time.time()),
            )
        elif row["coordinator_handle"] and row["coordinator_handle"] != terminal:
            raise ProviderError(
                "consumer_fenced",
                f"run {run_id!r} inbox is already fenced to coordinator {row['coordinator_handle']!r} (rejected {terminal!r})",
            )

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
    ) -> dict[str, Any]:
        run_id = run or "default"
        msg_id = f"msg_{uuid.uuid4().hex[:12]}"
        deliv_id = f"dlv_{uuid.uuid4().hex[:12]}"
        recipient = to or "coordinator"
        sender_id = sender or "worker"
        now = time.time()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO messages(id, run_id, sender, recipient, msg_type, subject, outcome, payload, attrs_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    msg_id,
                    run_id,
                    sender_id,
                    recipient,
                    msg_type,
                    subject,
                    outcome,
                    payload,
                    json.dumps(attrs or {}),
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO deliveries(delivery_id, message_id, recipient, run_id, acked, created_at)
                VALUES (?, ?, ?, ?, 0, ?)
                """,
                (deliv_id, msg_id, recipient, run_id, now),
            )
            conn.execute("COMMIT")
        return {
            "sent": True,
            "messageId": msg_id,
            "deliveryId": deliv_id,
            "message": {
                "id": msg_id,
                "deliveryId": deliv_id,
                "type": msg_type,
                "subject": subject,
                "from": sender_id,
                "to": recipient,
                "outcome": outcome,
            },
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
        ack_ids: list[str] = []
        if isinstance(ack, str) and ack:
            ack_ids = [x.strip() for x in ack.split(",") if x.strip()]
        elif isinstance(ack, list):
            ack_ids = [str(x).strip() for x in ack if str(x).strip()]

        type_filter = {x.strip() for x in types.split(",") if x.strip()} if types else None
        deadline = time.time() + ((timeout_ms or 5000) / 1000.0 if wait else 0.0)
        last_keepalive = time.time()

        with self._connect() as conn:
            self._fence_consumer(conn, run_id, terminal)
            coord_row = conn.execute("SELECT coordinator_handle FROM runs WHERE id = ?", (run_id,)).fetchone()
            fenced_coord = coord_row["coordinator_handle"] if coord_row else None
            env_coord = self.env.get("OPEN_FLEET_COORDINATOR_HANDLE") or self.env.get("ORCA_COORDINATOR_HANDLE")
            is_coord = bool(
                terminal
                and (
                    terminal == "coordinator"
                    or terminal.startswith("coord")
                    or terminal.startswith("orchestrator")
                    or (fenced_coord and terminal == fenced_coord)
                    or (env_coord and terminal == env_coord)
                )
            )
            allowed_recipients: list[str] | None = None
            if terminal:
                allowed_recipients = [terminal, "coordinator"] if is_coord and terminal != "coordinator" else [terminal]

            if ack_ids:
                now = time.time()
                for aid in ack_ids:
                    ack_q = "UPDATE deliveries SET acked = 1, acked_at = ? WHERE (delivery_id = ? OR message_id = ?)"
                    ack_params: list[Any] = [now, aid, aid]
                    if run:
                        ack_q += " AND run_id = ?"
                        ack_params.append(run_id)
                    if allowed_recipients:
                        placeholders = ",".join("?" for _ in allowed_recipients)
                        ack_q += f" AND recipient IN ({placeholders})"
                        ack_params.extend(allowed_recipients)
                    conn.execute(ack_q, ack_params)

        while True:
            with self._connect() as conn:
                query = """
                    SELECT d.delivery_id, d.acked, m.*
                    FROM deliveries d
                    JOIN messages m ON m.id = d.message_id
                    WHERE 1=1
                """
                params: list[Any] = []
                if run:
                    query += " AND d.run_id = ?"
                    params.append(run_id)
                if allowed_recipients:
                    placeholders = ",".join("?" for _ in allowed_recipients)
                    query += f" AND d.recipient IN ({placeholders})"
                    params.extend(allowed_recipients)
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
        with self._connect() as conn:
            orig = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()
            if not orig:
                raise ProviderError("message_not_found", f"message {msg_id!r} not found")
            recipient = orig["sender"]
            subject = f"Re: {orig['subject']}"
            run_id = run or orig["run_id"]
        sent = self.send_message(
            subject=subject,
            msg_type="info",
            to=recipient,
            sender=sender or "coordinator",
            payload=body,
            run=run_id,
            attrs={"replyTo": msg_id},
        )
        return {
            "replied": True,
            "messageId": sent["messageId"],
            "replyMessageId": sent["messageId"],
            "to": recipient,
        }

    # --- HITL Gate Transport ---
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
        run_id = run or "default"
        now = time.time()
        with self._connect() as conn:
            if resume:
                row = conn.execute("SELECT * FROM gates WHERE gate_id = ?", (resume,)).fetchone()
                if not row:
                    raise ProviderError("gate_not_found", f"gate {resume!r} not found")
                ans = row["answer"]
                return {
                    "gateId": row["gate_id"],
                    "requestId": row["gate_id"],
                    "messageId": row["gate_id"],
                    "state": row["status"],
                    "status": row["status"],
                    "answer": ans,
                    "timedOut": ans is None,
                    "question": row["question"],
                }
            gate_id = retry_request or f"gate_{uuid.uuid4().hex[:10]}"
            opts = json.loads(options) if isinstance(options, str) and options.startswith("[") else (options.split(",") if options else [])
            conn.execute(
                """
                INSERT OR REPLACE INTO gates(gate_id, run_id, sender, recipient, question, options_json, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
                """,
                (gate_id, run_id, sender or "coordinator", to or "human", question or "", json.dumps(opts), now),
            )
        self.send_message(
            subject=question or "HITL gate question",
            msg_type="question",
            to=to or "coordinator",
            sender=sender or "worker",
            payload=json.dumps({"gateId": gate_id, "question": question or "", "options": opts}),
            run=run_id,
            attrs={"gateId": gate_id},
        )
        preset_answer = self.env.get("OPEN_FLEET_ASK_ANSWER") or self.env.get("ORCA_ASK_ANSWER")
        if preset_answer is not None:
            self.resolve_gate(gate_id, preset_answer, status="answered")
        elif timeout_ms and int(timeout_ms) > 0:
            wait_deadline = time.time() + min(int(timeout_ms) / 1000.0, 0.2)
            while time.time() < wait_deadline:
                with self._connect() as conn:
                    r = conn.execute("SELECT status, answer FROM gates WHERE gate_id = ?", (gate_id,)).fetchone()
                    if r and r["answer"] is not None:
                        break
                time.sleep(0.02)
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM gates WHERE gate_id = ?", (gate_id,)).fetchone()
        ans = row["answer"] if row else None
        status = row["status"] if row else "pending"
        return {
            "gateId": gate_id,
            "requestId": gate_id,
            "messageId": gate_id,
            "state": status,
            "status": status,
            "answer": ans,
            "timedOut": ans is None,
            "question": question or "",
            "options": opts,
        }

    def resolve_gate(self, gate_id: str, answer: str, status: str = "answered") -> dict[str, Any]:
        with self._connect() as conn:
            conn.execute(
                "UPDATE gates SET status = ?, answer = ?, resolved_at = ? WHERE gate_id = ?",
                (status, answer, time.time(), gate_id),
            )
        return {"gateId": gate_id, "status": status, "answer": answer}

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
        """Atomically check if the worker sent terminal mail; if not, enqueue a synthetic `worker_died` escalation."""
        senders = [s for s in {dispatch_id, worker_handle or ""} if s]
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            placeholders = ",".join("?" for _ in senders)
            row = conn.execute(
                f"""
                SELECT id, msg_type FROM messages
                WHERE run_id = ? AND sender IN ({placeholders})
                  AND msg_type IN ('worker_done', 'merge_ready', 'escalation')
                LIMIT 1
                """,
                [run_id, *senders],
            ).fetchone()
            if row:
                conn.execute("COMMIT")
                return {"syntheticDied": False, "existingMessageId": row["id"], "type": row["msg_type"]}
            conn.execute(
                "UPDATE dispatches SET state = 'died', terminal_state = 'failed', updated_at = ? WHERE dispatch_id = ?",
                (time.time(), dispatch_id),
            )
            conn.execute("COMMIT")

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
        sent = self.send_message(
            subject=f"worker_died:{dispatch_id} (exit={exit_code})",
            msg_type="escalation",
            to="coordinator",
            outcome="failed",
            sender=worker_handle or dispatch_id,
            payload=payload,
            run=run_id,
            attrs={"synthetic": "worker_died", "dispatchId": dispatch_id, "exitCode": str(exit_code)},
        )
        return {"syntheticDied": True, "messageId": sent["messageId"], "deliveryId": sent["deliveryId"]}
