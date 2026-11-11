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

import contextlib
import contextvars
import hashlib
import importlib.util
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from .base import ProviderError, env_get

_gitexec_spec = importlib.util.spec_from_file_location(
    "local_state_gitexec", Path(__file__).resolve().parent.parent / "scripts" / "gitexec.py"
)
assert _gitexec_spec and _gitexec_spec.loader
gitexec = importlib.util.module_from_spec(_gitexec_spec)
_gitexec_spec.loader.exec_module(gitexec)

TERMINAL_MESSAGE_TYPES = ("worker_done", "merge_ready", "escalation")
# task_ops.py vocabulary (pending|ready|dispatched|completed|failed) plus the DAG hold `blocked`.
TASK_STATUSES = ("pending", "ready", "dispatched", "completed", "failed", "blocked")
FENCED_DISPATCH_STATES = ("stopped", "abandoned", "released")
COORDINATOR_ALIAS = "coordinator"
ACTIVE_REQUEST_PAYLOAD_SHA: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "active_request_payload_sha", default=None
)


def request_payload_sha256(payload: dict[str, Any]) -> str:
    """Canonical SHA-256 of a request's semantic arguments (#750 C33)."""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _repo_state_id(start: str | None = None, env: dict[str, str] | None = None) -> str:
    """Stable per-repository id shared by the main checkout and all of its linked worktrees."""
    cwd = start or os.getcwd()
    root = ""
    try:
        proc = subprocess.run(
            gitexec.argv("-C", cwd, "rev-parse", "--path-format=absolute", "--git-common-dir"),
            capture_output=True,
            timeout=10,
            env=gitexec.custody_env(env),
        )
        # Bytes, minus the one trailing newline: a `\r`, a trailing space or a non-UTF-8 byte in
        # the path is the path (text mode turned `\r` into `\n`, and died on the byte).
        out = proc.stdout[:-1] if proc.stdout.endswith(b"\n") else proc.stdout
        if proc.returncode == 0 and out:
            root = str(Path(os.fsdecode(out)).resolve())
    except (OSError, subprocess.SubprocessError):
        root = ""
    root = root or str(Path(cwd).resolve())
    name = Path(root).parent.name if Path(root).name == ".git" else Path(root).name
    slug = "".join(c if c.isalnum() or c in "._-" else "-" for c in name).strip("-") or "repo"
    return f"{slug}-{hashlib.sha256(os.fsencode(root)).hexdigest()[:12]}"


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
    return Path.home() / ".open-fleet" / "state" / _repo_state_id(start or None, env) / "runtime.db"


class _ClosingConnection(sqlite3.Connection):
    """A connection whose `with` block also CLOSES it (sqlite3's own __exit__ only commits)."""

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        try:
            return super().__exit__(exc_type, exc, tb)
        finally:
            self.close()


# A pending request claim older than this belongs to a caller that crashed mid-flight and is
# reclaimed by the next caller (get_or_record_request); live claims complete in seconds.
PENDING_STALE_S = 600.0
BUSY_SECONDS = 30.0
# Stamped into `PRAGMA user_version` by _init_db. 0 is a store from before the stamp (migrated in
# place, as always); a store stamped HIGHER than this was written by a newer open-fleet and is
# refused rather than silently read with an older layout (2026-10-26 review). Bump it with any
# change to the schema or to `_migrate`.
SCHEMA_VERSION = 1


def _ensure_wal(conn: sqlite3.Connection, seconds: float = BUSY_SECONDS) -> None:
    """Put the store in WAL mode, once per database file, surviving concurrent openers.

    The switch upgrades the switcher's read lock to a write lock, and SQLite refuses that upgrade
    with `database is locked` at once, never through the busy handler, so when processes opened a
    fresh (or older rollback-journal) store together, an opener that lost the switch died (PR
    #647's race in #599's queue, here on main). WAL persists in the file: the first switch is every later
    opener's no-op, so a loser backs off and re-reads the mode. Only a lock is retried; a mode
    SQLite settles on without error (an in-memory database) ends the loop, as it always did.
    """
    deadline = time.monotonic() + seconds
    delay = 0.005
    while True:
        try:
            if str(conn.execute("PRAGMA journal_mode;").fetchone()[0]).lower() == "wal":
                return
            conn.execute("PRAGMA journal_mode=WAL;").fetchone()
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.2)


def _pid_alive(pid: int) -> bool:
    """Whether a process with `pid` exists on this host (one we may not signal still exists)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _statements(script: str) -> list[str]:
    """Split a DDL script into statements; a `;` inside a `--` comment ends none."""
    out: list[str] = []
    buf = ""
    for line in script.splitlines(keepends=True):
        buf += line
        if sqlite3.complete_statement(buf):
            out.append(buf)
            buf = ""
    if buf.strip():  # a last statement with no `;` still runs (and fails loudly if malformed)
        out.append(buf)
    return out


class LocalStateStore:
    """Thread-safe / process-safe SQLite WAL state engine for runs, tasks, dispatches, mailbox, and file touches."""

    def __init__(self, db_path: str | Path | None = None, env: dict[str, str] | None = None):
        self.env = dict(os.environ if env is None else env)
        self.db_path = Path(db_path) if db_path else default_db_path(env)
        # The state dir holds every worker's transcript, launch env and the mailbox: private to
        # the user that runs the fleet (2026-10-26 review). Only a dir or file this store creates
        # is restricted; an operator's existing layout is left as they set it.
        self.db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if str(self.db_path) != ":memory:" and not self.db_path.exists():
            # Created 0600 before SQLite opens it: the -wal and -shm files copy the db's mode.
            with contextlib.suppress(OSError):
                os.close(os.open(self.db_path, os.O_RDWR | os.O_CREAT, 0o600))
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        # `with sqlite3.connect(...) as conn` only commits; it never closes, so every store
        # call leaked a connection until GC (a ResourceWarning on 3.13). _ClosingConnection
        # closes when its `with` block ends.
        conn = sqlite3.connect(str(self.db_path), timeout=BUSY_SECONDS, isolation_level=None, factory=_ClosingConnection)
        conn.row_factory = sqlite3.Row
        try:
            # The busy timeout first (connect's `timeout` installs it too), so every statement
            # below and after waits out a lock. It cannot save the WAL switch: see _ensure_wal.
            conn.execute(f"PRAGMA busy_timeout={int(BUSY_SECONDS * 1000)};")
            _ensure_wal(conn)
            conn.execute("PRAGMA foreign_keys=ON;")
        except BaseException:
            conn.close()  # a setup that gave up must not leak the connection it opened
            raise
        return conn

    def _init_db(self) -> None:
        # Schema and migration in ONE `BEGIN IMMEDIATE` transaction: concurrent openers take
        # turns, each re-reads the columns under the lock, and an upgrade that fails leaves the
        # store as it found it. Not executescript, which COMMITs first and runs each statement
        # in autocommit, letting another opener interleave and a failure half-upgrade the store.
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            for statement in _statements(
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
                -- A worker launch's identity, written BEFORE its first external side effect
                -- (#597). `phase` is the last committed launch boundary; `outcome` is NULL while
                -- the launch is open. `owner_token`/`epoch` fence a coordinator that was taken over.
                CREATE TABLE IF NOT EXISTS launch_intents (
                    intent_id TEXT PRIMARY KEY,
                    request_id TEXT,
                    payload_sha256 TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    run_id TEXT NOT NULL DEFAULT 'default',
                    dispatch_id TEXT NOT NULL,
                    terminal_handle TEXT NOT NULL,
                    lane_dir TEXT NOT NULL,
                    worktree TEXT,
                    backend TEXT,
                    phase TEXT NOT NULL,
                    outcome TEXT,
                    owner_token TEXT NOT NULL,
                    owner_pid INTEGER,
                    owner_host TEXT,
                    epoch INTEGER NOT NULL DEFAULT 1,
                    receipt_json TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                """
            ):
                conn.execute(statement)
            self._migrate(conn)
            stamped = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if stamped > SCHEMA_VERSION:
                raise ProviderError(
                    "state_schema_newer",
                    f"{self.db_path} carries schema version {stamped}, newer than this open-fleet's "
                    f"{SCHEMA_VERSION}: refusing to read it with an older layout (upgrade open-fleet)",
                )
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Additive column migrations for stores created by an older schema.

        Runs inside `_init_db`'s `BEGIN IMMEDIATE`, so the columns read here are current."""
        wanted = {
            "gates": {"task_id": "TEXT", "message_id": "TEXT", "prev_status": "TEXT", "kind": "TEXT DEFAULT 'ask'"},
            "runs": {"objective": "TEXT"},
            "terminals": {"backend_ref": "TEXT"},
            # monitor_pid: the monitor that holds the launch gate (cleared when it exits);
            # monitor_started_at: set by the FIRST gate claim and never cleared (#597);
            # gate_closed_at: set when a fence lands before any claim, and never cleared (#597).
            "dispatches": {
                "backend_ref": "TEXT",
                "head_sha": "TEXT",
                "monitor_pid": "INTEGER",
                "monitor_started_at": "REAL",
                "intent_id": "TEXT",
                "gate_closed_at": "REAL",
            },
            # claim_pid/claim_host: who holds a pending claim, so a claimer that died on this host
            # is reclaimed at once instead of after PENDING_STALE_S (2026-10-26 review).
            "requests": {"payload_sha256": "TEXT", "intent_id": "TEXT", "claim_pid": "INTEGER", "claim_host": "TEXT"},
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
    def get_or_record_request(
        self,
        request_id: str | None,
        method: str,
        payload_sha256: str | None = None,
    ) -> dict[str, Any] | None:
        """The recorded outcome of `request_id`, or None when this caller has just CLAIMED it.

        Claiming inserts the `pending` row inside the same transaction as the read (2026-10-26
        review): the read-then-act version let eight concurrent callers sharing one request id
        each create a task, and every external adapter's worker_start was the same race. A row
        another caller holds mid-flight comes back as the pending marker, which the caller
        returns rather than acting on (the posix worker_start already answers this way). A
        pending row older than PENDING_STALE_S, or one whose claimer (recorded by pid and host)
        is no longer running on this host, is a crashed caller's claim and is reclaimed. A caller
        that fails after claiming calls release_request so a retry can act at once."""
        if not request_id:
            return None
        if payload_sha256 is None:
            payload_sha256 = ACTIVE_REQUEST_PAYLOAD_SHA.get()
        now = time.time()
        host = socket.gethostname()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT method, state, response_json, payload_sha256, created_at, claim_pid, claim_host "
                "FROM requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row and row["state"] == "pending" and not row["response_json"]:
                stale = now - float(row["created_at"] or now) > PENDING_STALE_S
                claimer_gone = (row["claim_host"] == host and int(row["claim_pid"] or 0) > 0
                                and not _pid_alive(int(row["claim_pid"])))
                if stale or claimer_gone:
                    conn.execute("DELETE FROM requests WHERE request_id = ?", (request_id,))
                    row = None
            if not row:
                conn.execute(
                    "INSERT INTO requests(request_id, method, state, response_json, created_at, payload_sha256, "
                    "claim_pid, claim_host) VALUES (?, ?, 'pending', NULL, ?, ?, ?, ?)",
                    (request_id, method, now, payload_sha256, os.getpid(), host),
                )
                conn.execute("COMMIT")
                return None
            conn.execute("COMMIT")
        if row["method"] != method:
            raise ProviderError("request_mismatch", f"retry-request {request_id!r} bound to {row['method']}, not {method}")
        self.check_request_payload(request_id, row["payload_sha256"], payload_sha256)
        if row["response_json"]:
            return json.loads(row["response_json"])
        return {"state": row["state"], "requestId": request_id}

    def release_request(self, request_id: str | None) -> None:
        """Drop a pending claim this caller could not complete, so a retry acts instead of
        reading a marker for PENDING_STALE_S. A completed row is never released."""
        if not request_id:
            return
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM requests WHERE request_id = ? AND state = 'pending' AND response_json IS NULL",
                (request_id,),
            )

    @staticmethod
    def check_request_payload(request_id: str, recorded: str | None, offered: str | None) -> None:
        """A request id binds its payload: a changed payload never reuses a result (#597)."""
        if recorded and offered and recorded != offered:
            raise ProviderError(
                "request_mismatch",
                f"retry-request {request_id!r} was recorded with a different payload; use a new request id",
                {"requestId": request_id},
            )

    def request_row(self, request_id: str | None) -> dict[str, Any] | None:
        if not request_id:
            return None
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM requests WHERE request_id = ?", (request_id,)).fetchone()
        return dict(row) if row else None

    def _save_request_in_tx(
        self,
        conn: sqlite3.Connection,
        request_id: str | None,
        method: str,
        state: str,
        response: dict[str, Any],
        payload_sha256: str | None = None,
    ) -> None:
        """Upsert the request record inside the caller's active transaction (#750 C31)."""
        if not request_id:
            return
        if payload_sha256 is None:
            payload_sha256 = ACTIVE_REQUEST_PAYLOAD_SHA.get()
        conn.execute(
            "INSERT INTO requests(request_id, method, state, response_json, created_at, payload_sha256) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(request_id) DO UPDATE SET method = excluded.method, state = excluded.state, "
            "response_json = excluded.response_json, "
            "payload_sha256 = COALESCE(requests.payload_sha256, excluded.payload_sha256)",
            (request_id, method, state, json.dumps(response), time.time(), payload_sha256),
        )

    def save_request(
        self,
        request_id: str | None,
        method: str,
        state: str,
        response: dict[str, Any],
        payload_sha256: str | None = None,
    ) -> None:
        """Complete the claimed request: an upsert that keeps the claim's payload digest and intent."""
        if not request_id:
            return
        with self._connect() as conn:
            self._save_request_in_tx(conn, request_id, method, state, response, payload_sha256)

    def request_show(self, request_id: str) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT state, response_json, intent_id FROM requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if not row:
                return {"requestId": request_id, "state": "absent"}
            out: dict[str, Any] = {"requestId": request_id, "state": row["state"]}
            intent = conn.execute(
                "SELECT intent_id, phase, outcome, dispatch_id, task_id FROM launch_intents WHERE intent_id = ?",
                (row["intent_id"],),
            ).fetchone() if row["intent_id"] else None
            if intent:
                # Read-only triage: which launch attempt this request names, and how far it got.
                out["intent"] = {
                    "id": intent["intent_id"],
                    "phase": intent["phase"],
                    "outcome": intent["outcome"],
                    "dispatchId": intent["dispatch_id"],
                    "taskId": intent["task_id"],
                }
            return out

    # --- #597: launch intents (crash-recoverable worker launch) ---
    def launch_intent(self, intent_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM launch_intents WHERE intent_id = ?", (intent_id,)).fetchone()
        return dict(row) if row else None

    def open_launch_intents(self, task_id: str | None = None) -> list[dict[str, Any]]:
        """Launches with no final outcome yet (`unknown` stays open: reconcile visits it again)."""
        q = "SELECT * FROM launch_intents WHERE (outcome IS NULL OR outcome = 'unknown')"
        params: list[Any] = []
        if task_id:
            q += " AND task_id = ?"
            params.append(task_id)
        with self._connect() as conn:
            rows = conn.execute(q + " ORDER BY created_at ASC", params).fetchall()
        return [dict(r) for r in rows]

    def claim_monitor(self, dispatch_id: str, pid: int) -> bool:
        """The launch gate as a compare-and-set: one monitor, and only for a live dispatch (#597).

        Refuses a dispatch that is fenced or withdrawn (#591 review) AND one another monitor
        holds, so a monitor that a dead coordinator's launcher starts late can never run the
        agent beside the one recovery adopted, nor after recovery abandoned the dispatch. It
        also refuses, for good, a dispatch whose gate a fence closed before any claim: a later
        `retain` rewrites the state but never reopens the gate. `gate_refusal` says which.
        """
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE dispatches SET monitor_pid = ?, monitor_started_at = COALESCE(monitor_started_at, ?) "
                "WHERE dispatch_id = ? AND state IN ('ready', 'running', 'retained') AND COALESCE(monitor_pid, 0) = 0 "
                "AND gate_closed_at IS NULL",
                (int(pid), time.time(), dispatch_id),
            )
            conn.execute("COMMIT")
        return cur.rowcount == 1

    def gate_refusal(self, dispatch_id: str) -> str:
        """Why `claim_monitor` refused this dispatch, for the refused monitor's own log (#597)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT state, monitor_pid, gate_closed_at FROM dispatches WHERE dispatch_id = ?", (dispatch_id,)
            ).fetchone()
        if row is None:
            return "dispatch withdrawn before launch"
        if row["gate_closed_at"] is not None:
            return f"launch gate closed for good: a fence landed before any monitor claimed it (state now {row['state']})"
        if int(row["monitor_pid"] or 0):
            return f"held by monitor pid {row['monitor_pid']}"
        return f"dispatch is {row['state']}, not launchable"

    def abandon_unlaunched(self, dispatch_id: str) -> bool:
        """Recovery's side of the gate: abandon a dispatch no monitor has EVER claimed (#597).

        Exactly one of this and `claim_monitor` wins; the loser sees rowcount 0. The winner
        closes the gate for good, as any fence before a claim does.
        """
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = time.time()
            cur = conn.execute(
                "UPDATE dispatches SET state = 'abandoned', terminal_state = 'abandoned', updated_at = ?, "
                "gate_closed_at = COALESCE(gate_closed_at, ?) "
                "WHERE dispatch_id = ? AND state IN ('ready', 'retained') AND COALESCE(monitor_pid, 0) = 0 "
                "AND monitor_started_at IS NULL",
                (now, now, dispatch_id),
            )
            if cur.rowcount == 1:
                conn.execute(
                    "UPDATE terminals SET state = 'abandoned' WHERE handle = "
                    "(SELECT terminal_handle FROM dispatches WHERE dispatch_id = ?)",
                    (dispatch_id,),
                )
            conn.execute("COMMIT")
        return cur.rowcount == 1

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
        run_id = self._resolve_caller_run(run, default_run="default") or "default"
        deps_list = list(deps or [])
        payload_sha = request_payload_sha256(
            {
                "spec": spec,
                "title": title,
                "display_name": display_name,
                "deps": deps_list,
                "parent": parent,
                "run": run_id,
                "initial_status": initial_status,
            }
        )
        cached = self.get_or_record_request(retry_request, "task-create", payload_sha)
        if cached:
            return cached
        try:
            now = time.time()
            task_id = f"task_{uuid.uuid4().hex[:10]}"
            if initial_status is not None and initial_status not in TASK_STATUSES:
                raise ProviderError("invalid_status", f"unknown task status {initial_status!r} (want {'|'.join(TASK_STATUSES)})")
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                if parent is not None:
                    p_row = conn.execute("SELECT run_id FROM tasks WHERE id = ?", (parent,)).fetchone()
                    if not p_row:
                        conn.execute("ROLLBACK")
                        raise ProviderError("task_not_found", f"parent task {parent!r} not found")
                    if p_row["run_id"] != run_id:
                        conn.execute("ROLLBACK")
                        raise ProviderError(
                            "cross_run_access",
                            f"parent task {parent!r} belongs to run {p_row['run_id']!r}, not {run_id!r}",
                        )
                if initial_status is not None:
                    status = initial_status
                elif not deps_list:
                    status = "ready"
                else:
                    placeholders = ",".join("?" for _ in deps_list)
                    rows = conn.execute(
                        f"SELECT id, status, run_id FROM tasks WHERE id IN ({placeholders})",
                        deps_list,
                    ).fetchall()
                    by_id = {r["id"]: r["status"] for r in rows}
                    by_run = {r["id"]: r["run_id"] for r in rows}
                    missing = [d for d in deps_list if d not in by_id]
                    if missing:
                        conn.execute("ROLLBACK")
                        raise ProviderError("task_not_found", f"dependency task(s) not found: {', '.join(missing)}")
                    foreign = [d for d in deps_list if by_run.get(d) != run_id]
                    if foreign:
                        conn.execute("ROLLBACK")
                        raise ProviderError(
                            "cross_run_access",
                            f"dependency task(s) {', '.join(foreign)} belong to another run, not {run_id!r}",
                        )
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
                self._save_request_in_tx(conn, retry_request, "task-create", "completed", res, payload_sha)
                conn.execute("COMMIT")
        except BaseException:
            self.release_request(retry_request)  # a failed claim must not block the retry
            raise
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
        root_row = conn.execute("SELECT run_id FROM tasks WHERE id = ?", (changed_task_id,)).fetchone()
        if not root_row:
            return promoted
        run_id = root_row["run_id"]
        queue = [changed_task_id]
        seen: set[str] = set()
        while queue:
            cur = queue.pop(0)
            if cur in seen:
                continue
            seen.add(cur)
            for r in conn.execute("SELECT task_id FROM task_deps WHERE dep_id = ?", (cur,)).fetchall():
                child_id = r["task_id"]
                child = conn.execute(
                    "SELECT status, run_id FROM tasks WHERE id = ?", (child_id,)
                ).fetchone()
                if not child or child["run_id"] != run_id or child["status"] not in ("pending", "ready", "blocked"):
                    continue
                statuses = [
                    x["status"]
                    for x in conn.execute(
                        "SELECT t.status FROM task_deps d LEFT JOIN tasks t ON t.id = d.dep_id AND t.run_id = ? WHERE d.task_id = ?",
                        (run_id, child_id),
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
            "SELECT 1 FROM gates g JOIN tasks t ON t.id = g.task_id "
            "WHERE g.task_id = ? AND g.run_id = t.run_id AND g.status = 'pending' LIMIT 1",
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
        eff_run = self._resolve_caller_run(run, default_run=None)
        payload_sha = request_payload_sha256(
            {"task_id": task_id, "status": status, "result": result, "run": eff_run}
        )
        cached = self.get_or_record_request(retry_request, "task-update", payload_sha)
        if cached:
            return cached
        try:
            if status not in TASK_STATUSES:
                raise ProviderError("invalid_status", f"unknown task status {status!r} (want {'|'.join(TASK_STATUSES)})")
            now = time.time()
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("SELECT id, run_id FROM tasks WHERE id = ?", (task_id,)).fetchone()
                if not row:
                    conn.execute("ROLLBACK")
                    raise ProviderError("task_not_found", f"task {task_id!r} not found")
                if eff_run is not None and row["run_id"] != eff_run:
                    conn.execute("ROLLBACK")
                    raise ProviderError(
                        "cross_run_access",
                        f"task {task_id!r} belongs to run {row['run_id']!r}, not {eff_run!r}",
                    )
                conn.execute(
                    "UPDATE tasks SET status = ?, result_json = COALESCE(?, result_json), updated_at = ? WHERE id = ?",
                    (status, result, now, task_id),
                )
                promoted = self._recompute_dependents(conn, task_id)
                res = {"task": {"id": task_id, "status": status, "promotedDependents": promoted}}
                self._save_request_in_tx(conn, retry_request, "task-update", "completed", res, payload_sha)
                conn.execute("COMMIT")
        except BaseException:
            self.release_request(retry_request)  # a failed claim must not block the retry
            raise
        return res

    def task_list(
        self,
        *,
        run: str | None = None,
        sender: str | None = None,
        brief: bool = False,
    ) -> dict[str, Any]:
        eff_run = self._resolve_caller_run(run, default_run=None)
        with self._connect() as conn:
            if eff_run:
                rows = conn.execute(
                    "SELECT * FROM tasks WHERE run_id = ? ORDER BY created_at ASC",
                    (eff_run,),
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
        if self._own_worker_identity() or terminal in self._worker_handles(conn):
            raise ProviderError(
                "worker_cannot_be_coordinator",
                f"worker handle {terminal!r} cannot claim or adopt run {run_id!r}'s coordinator binding",
            )
        own_tx = not conn.in_transaction
        if own_tx:
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
            if own_tx:
                conn.execute("COMMIT")
        except BaseException:
            if own_tx:
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

    def _worker_bound_run(self, conn: sqlite3.Connection | None = None) -> str | None:
        dispatch = env_get("OPEN_FLEET_DISPATCH_ID", "ORCA_DISPATCH_ID", self.env, "")
        if not dispatch:
            return None
        if conn is not None:
            row = conn.execute(
                "SELECT run_id FROM dispatches WHERE dispatch_id = ? LIMIT 1",
                (dispatch,),
            ).fetchone()
            return row["run_id"] if row else None
        with self._connect() as c:
            row = c.execute(
                "SELECT run_id FROM dispatches WHERE dispatch_id = ? LIMIT 1",
                (dispatch,),
            ).fetchone()
            return row["run_id"] if row else None

    def _resolve_caller_run(
        self,
        explicit_run: str | None,
        *,
        default_run: str | None = "default",
    ) -> str | None:
        bound = self._worker_bound_run()
        if bound:
            if explicit_run is not None and explicit_run != bound:
                raise ProviderError(
                    "cross_run_access",
                    f"launched worker is bound to run {bound!r}, cannot access {explicit_run!r}",
                )
            return bound
        return explicit_run if explicit_run is not None else default_run

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
            row = conn.execute("SELECT coordinator_handle FROM runs WHERE id = ?", (run_id,)).fetchone()
            bound = row["coordinator_handle"] if row else None
            if bound and bound != terminal:
                raise ProviderError(
                    "consumer_fenced",
                    f"run {run_id!r} inbox is already fenced to coordinator {bound!r} (rejected {terminal!r})",
                )
            if run_id != "default" or (env_coord and terminal == env_coord):
                self._claim_coordinator(conn, run_id, terminal)
            return [terminal, COORDINATOR_ALIAS]
        # No handle at all (operator shell) or the literal alias: the coordinator mailbox. A
        # fenced run refuses this anonymous reader, so a fenced coordinator cannot be bypassed.
        row = conn.execute("SELECT coordinator_handle FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row and row["coordinator_handle"]:
            raise ProviderError(
                "consumer_fenced",
                f"run {run_id!r} inbox is fenced to coordinator {row['coordinator_handle']!r}; pass --terminal",
            )
        return [COORDINATOR_ALIAS]

    def run_create(self, *, objective: str | None = None, run: str | None = None, sender: str | None = None) -> dict[str, Any]:
        run_id = run or f"run_{uuid.uuid4().hex[:10]}"
        coordinator = self._resolve_terminal(sender)
        with self._connect() as conn:
            if self._own_worker_identity() or (coordinator and coordinator in self._worker_handles(conn)):
                raise ProviderError(
                    "worker_cannot_be_coordinator",
                    f"worker handle {coordinator!r} cannot create or claim coordinator binding for run {run_id!r}",
                )
            conn.execute(
                "INSERT OR IGNORE INTO runs(id, coordinator_handle, objective, created_at) VALUES (?, ?, ?, ?)",
                (run_id, coordinator, objective or "", time.time()),
            )
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if coordinator and row["coordinator_handle"] and row["coordinator_handle"] != coordinator:
                raise ProviderError(
                    "consumer_fenced",
                    f"run {run_id!r} is already bound to coordinator {row['coordinator_handle']!r} (rejected {coordinator!r})",
                )
        return {"run": {"id": run_id, "objective": row["objective"], "coordinator": row["coordinator_handle"]}}

    def run_use(self, *, run: str, sender: str | None = None, takeover: bool = False) -> dict[str, Any]:
        terminal = self._resolve_terminal(sender)
        if not run:
            raise ProviderError("invalid_argument", "run-use needs --id <run>")
        if not terminal:
            raise ProviderError("invalid_argument", "run-use needs the adopting terminal (--from or OPEN_FLEET_TERMINAL_HANDLE)")
        with self._connect() as conn:
            if self._own_worker_identity() or terminal in self._worker_handles(conn):
                raise ProviderError(
                    "worker_cannot_be_coordinator",
                    f"worker handle {terminal!r} cannot adopt or take over run {run!r}",
                )
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

    def _settle_dispatch_task(
        self,
        conn: sqlite3.Connection,
        dispatch_id: str,
        *,
        succeeded: bool,
        now: float,
    ) -> list[str]:
        """Settle the task owned by `dispatch_id` and recompute its dependents (#750 C30)."""
        row = conn.execute(
            "SELECT rowid AS rid, task_id, run_id, created_at FROM dispatches WHERE dispatch_id = ?",
            (dispatch_id,),
        ).fetchone()
        if not row or not row["task_id"]:
            return []
        task_id = row["task_id"]
        newer = conn.execute(
            "SELECT 1 FROM dispatches WHERE task_id = ? AND dispatch_id != ? "
            "AND rowid > ? LIMIT 1",
            (task_id, dispatch_id, row["rid"]),
        ).fetchone()
        if newer:
            return []
        t_row = conn.execute("SELECT status FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not t_row or t_row["status"] != "dispatched":
            return []
        target_status = "completed" if succeeded else "failed"
        if target_status == "completed" and self._gate_holds(conn, task_id):
            target_status = "blocked"
        conn.execute(
            "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
            (target_status, now, task_id),
        )
        return self._recompute_dependents(conn, task_id)

    def _is_dispatch_settled(self, conn: sqlite3.Connection, run_id: str, row: Any) -> bool:
        if row["state"] in (*FENCED_DISPATCH_STATES, "died", "completed"):
            return True
        if row["task_id"]:
            t_st = conn.execute("SELECT status FROM tasks WHERE id = ?", (row["task_id"],)).fetchone()
            if t_st and t_st["status"] != "dispatched":
                return True
        senders = [s for s in {row["dispatch_id"], row["terminal_handle"] or ""} if s]
        return self._terminal_report(conn, run_id, senders, dispatch_id=row["dispatch_id"]) is not None

    def _resolve_sender_dispatch(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        sender_id: str,
        *,
        hint_task_id: str | None = None,
    ) -> Any:
        env_disp = env_get("OPEN_FLEET_DISPATCH_ID", "ORCA_DISPATCH_ID", self.env, "")
        if env_disp:
            disp_row = conn.execute(
                "SELECT rowid AS rid, dispatch_id, state, task_id, terminal_handle FROM dispatches "
                "WHERE run_id = ? AND dispatch_id = ? LIMIT 1",
                (run_id, env_disp),
            ).fetchone()
            if disp_row and disp_row["terminal_handle"] and self._is_dispatch_settled(conn, run_id, disp_row):
                siblings = conn.execute(
                    "SELECT rowid AS rid, dispatch_id, state, task_id, terminal_handle FROM dispatches "
                    "WHERE run_id = ? AND terminal_handle = ? AND rowid > ? AND state IN ('ready', 'running') "
                    "ORDER BY rowid ASC",
                    (run_id, disp_row["terminal_handle"], disp_row["rid"]),
                ).fetchall()
                unsettled = [
                    s
                    for s in siblings
                    if (disp_row["task_id"] is None or s["task_id"] != disp_row["task_id"])
                    and not self._is_dispatch_settled(conn, run_id, s)
                ]
                if hint_task_id:
                    for s in unsettled:
                        if s["task_id"] == hint_task_id:
                            return s
                if unsettled:
                    return unsettled[0]
            return disp_row
        if sender_id not in ("worker", COORDINATOR_ALIAS):
            exact = conn.execute(
                "SELECT rowid AS rid, dispatch_id, state, task_id, terminal_handle FROM dispatches "
                "WHERE run_id = ? AND dispatch_id = ? LIMIT 1",
                (run_id, sender_id),
            ).fetchone()
            if exact is not None:
                return exact
            by_handle = conn.execute(
                "SELECT rowid AS rid, dispatch_id, state, task_id, terminal_handle FROM dispatches "
                "WHERE run_id = ? AND terminal_handle = ? "
                "ORDER BY CASE WHEN state IN ('ready', 'running') THEN 0 ELSE 1 END, rowid ASC",
                (run_id, sender_id),
            ).fetchall()
            unsettled_h = [
                r for r in by_handle if r["state"] in ("ready", "running") and not self._is_dispatch_settled(conn, run_id, r)
            ]
            if hint_task_id:
                for r in unsettled_h:
                    if r["task_id"] == hint_task_id:
                        return r
            if unsettled_h:
                return unsettled_h[0]
            return by_handle[-1] if by_handle else None
        return None

    def send_message(
        self,
        *,
        subject: str,
        msg_type: str,
        to: str | None = None,
        outcome: str | None = None,
        sender: str | None = None,
        payload: str | None = None,
        body: str | None = None,
        run: str | None = None,
        attrs: dict[str, Any] | None = None,
        reply_to: str | None = None,
        retry_request: str | None = None,
    ) -> dict[str, Any]:
        run_id = self._resolve_caller_run(run, default_run="default") or "default"
        recipient = to or COORDINATOR_ALIAS
        sender_id = sender or self._resolve_terminal(None) or "worker"
        clean_attrs = dict(attrs or {})
        body_from_attrs = clean_attrs.pop("body", None) if "body" in clean_attrs and payload is None and body is None else None
        if retry_request is None and "retry-request" in clean_attrs:
            retry_request = str(clean_attrs.pop("retry-request"))
        effective_payload = payload if payload is not None else (body if body is not None else body_from_attrs)
        payload_sha = request_payload_sha256(
            {
                "subject": subject,
                "msg_type": msg_type,
                "to": recipient,
                "outcome": outcome,
                "sender": sender_id,
                "payload": effective_payload,
                "run": run_id,
                "attrs": clean_attrs,
                "reply_to": reply_to,
            }
        )
        cached = self.get_or_record_request(retry_request, "send", payload_sha)
        if cached:
            return cached
        try:
            now = time.time()
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                is_term_mail = msg_type in TERMINAL_MESSAGE_TYPES and "fileTouchConflict" not in clean_attrs
                hint_task = next(
                    (
                        clean_attrs[k]
                        for k in ("taskId", "task_id", "task-id")
                        if isinstance(clean_attrs.get(k), str) and clean_attrs[k]
                    ),
                    None,
                )
                disp_row = (
                    self._resolve_sender_dispatch(conn, run_id, sender_id, hint_task_id=hint_task)
                    if is_term_mail
                    else None
                )
                stored_attrs = dict(clean_attrs)
                if is_term_mail:
                    for dk in ("dispatchId", "dispatch_id", "dispatch-id"):
                        stored_attrs.pop(dk, None)
                    if disp_row is not None:
                        stored_attrs["dispatchId"] = disp_row["dispatch_id"]
                msg_id, deliv_id = self._insert_message(
                    conn,
                    run_id=run_id,
                    sender=sender_id,
                    recipient=recipient,
                    msg_type=msg_type,
                    subject=subject,
                    outcome=outcome,
                    payload=effective_payload,
                    attrs=stored_attrs,
                    reply_to=reply_to,
                )
                if msg_type == "worker_done" and outcome in ("succeeded", "failed"):
                    if disp_row and disp_row["state"] not in (*FENCED_DISPATCH_STATES, "died", "completed"):
                        self._settle_dispatch_task(conn, disp_row["dispatch_id"], succeeded=(outcome == "succeeded"), now=now)
                message = {
                    "id": msg_id,
                    "deliveryId": deliv_id,
                    "type": msg_type,
                    "subject": subject,
                    "from": sender_id,
                    "to": recipient,
                    "outcome": outcome,
                    "payload": effective_payload,
                    "body": effective_payload if effective_payload is not None else subject,
                }
                res = {
                    "sent": True,
                    "messageId": msg_id,
                    "deliveryId": deliv_id,
                    "message": message,
                    # send_msg.py reads `relay.messageId` (Orca's receipt shape, #578 audit).
                    "relay": {"messageId": msg_id, "deliveryId": deliv_id, "to": recipient},
                }
                self._save_request_in_tx(conn, retry_request, "send", "completed", res, payload_sha)
                conn.execute("COMMIT")
        except BaseException:
            self.release_request(retry_request)
            raise
        return res

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
        run_id = self._resolve_caller_run(run, default_run="default") or "default"
        terminal = self._resolve_terminal(terminal)
        ack_ids: list[str] = []
        if isinstance(ack, str) and ack:
            ack_ids = [x.strip() for x in ack.split(",") if x.strip()]
        elif isinstance(ack, list):
            ack_ids = [str(x).strip() for x in ack if str(x).strip()]

        payload_sha = request_payload_sha256(
            {"terminal": terminal, "run": run_id, "ack": ack_ids, "mode": mode, "types": types}
        )
        cached = self.get_or_record_request(retry_request, "check", payload_sha)
        if cached:
            return cached

        type_filter = {x.strip() for x in types.split(",") if x.strip()} if types else None
        deadline = time.time() + ((timeout_ms or 5000) / 1000.0 if wait else 0.0)
        last_keepalive = time.time()

        try:
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
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
                conn.execute("COMMIT")

            while True:
                with self._connect() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    allowed_recipients = self._mailbox_scope(conn, run_id, terminal)
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
                        res = {
                            "messages": items,
                            "deliveries": items,
                            "count": len(items),
                            "deliveryId": items[-1]["deliveryId"] if items else None,
                            "acked": len(ack_ids),
                            "waited": bool(wait),
                            "timedOut": bool(wait and not items),
                        }
                        self._save_request_in_tx(conn, retry_request, "check", "completed", res, payload_sha)
                        conn.execute("COMMIT")
                        return res
                    conn.execute("COMMIT")
                now = time.time()
                if now - last_keepalive >= 15.0:
                    print('{"_keepalive": true}', file=sys.stderr, flush=True)
                    last_keepalive = now
                time.sleep(min(0.1, max(0.01, deadline - now)))
        except BaseException:
            self.release_request(retry_request)
            raise

    def reply_message(
        self,
        *,
        msg_id: str,
        body: str,
        run: str | None = None,
        sender: str | None = None,
        retry_request: str | None = None,
    ) -> dict[str, Any]:
        eff_run = self._resolve_caller_run(run, default_run=None)
        payload_sha = request_payload_sha256(
            {"msg_id": msg_id, "body": body, "run": eff_run, "sender": sender}
        )
        cached = self.get_or_record_request(retry_request, "reply", payload_sha)
        if cached:
            return cached
        try:
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                orig = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()
                gate = None
                if not orig:
                    # `reply --id <gate_id>` is accepted for gates whose id the caller holds.
                    gate = conn.execute("SELECT * FROM gates WHERE gate_id = ?", (msg_id,)).fetchone()
                    if gate and gate["message_id"]:
                        orig = conn.execute("SELECT * FROM messages WHERE id = ?", (gate["message_id"],)).fetchone()
                if not orig:
                    conn.execute("ROLLBACK")
                    raise ProviderError("message_not_found", f"message {msg_id!r} not found")
                if eff_run is not None and orig["run_id"] != eff_run:
                    conn.execute("ROLLBACK")
                    raise ProviderError(
                        "cross_run_access",
                        f"message {msg_id!r} belongs to run {orig['run_id']!r}, not {eff_run!r}",
                    )
                attrs = json.loads(orig["attrs_json"] or "{}")
                gate_id = gate["gate_id"] if gate else attrs.get("gateId")
                replier = sender or self._resolve_terminal(None) or COORDINATOR_ALIAS
                gate_row = None
                if gate_id:
                    gate_row = gate or conn.execute("SELECT * FROM gates WHERE gate_id = ?", (gate_id,)).fetchone()
                    if gate_row:
                        if gate_row["run_id"] != orig["run_id"]:
                            conn.execute("ROLLBACK")
                            raise ProviderError(
                                "cross_run_access",
                                f"gate {gate_id!r} belongs to run {gate_row['run_id']!r}, not {orig['run_id']!r}",
                            )
                        try:
                            # Refuse BEFORE the reply message is sent, not only at resolution.
                            self._check_gate_answerer(conn, gate_row, replier)
                        except ProviderError:
                            conn.execute("ROLLBACK")
                            raise
                recipient = orig["sender"]
                subject = f"Re: {orig['subject']}"
                run_id = orig["run_id"]
                reply_msg_id, _ = self._insert_message(
                    conn,
                    run_id=run_id,
                    sender=replier,
                    recipient=recipient,
                    msg_type="info",
                    subject=subject,
                    outcome=None,
                    payload=body,
                    attrs={"replyTo": orig["id"], **({"gateId": gate_id} if gate_id else {})},
                    reply_to=orig["id"],
                )
                resolved = None
                if gate_id and gate_row:
                    # Answering a worker's `ask` question by message id resolves its durable gate, so
                    # `ask --resume <id>` returns the human's answer (#591 review: gates never completed).
                    resolved = self._resolve_gate_in_tx(conn, gate_row, body, status="answered", who=replier)
                res = {
                    "replied": True,
                    "messageId": reply_msg_id,
                    "replyMessageId": reply_msg_id,
                    "to": recipient,
                    "gate": resolved,
                }
                self._save_request_in_tx(conn, retry_request, "reply", "completed", res, payload_sha)
                conn.execute("COMMIT")
        except BaseException:
            self.release_request(retry_request)  # a failed claim must not block the retry
            raise
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
        eff_run = self._resolve_caller_run(run, default_run=None)
        run_id = eff_run or "default"
        if resume:
            with self._connect() as conn:
                row = self._find_gate(conn, resume)
            if not row:
                raise ProviderError("gate_not_found", f"gate/message {resume!r} not found")
            if eff_run is not None and row["run_id"] != eff_run:
                raise ProviderError(
                    "cross_run_access",
                    f"gate {row['gate_id']!r} belongs to run {row['run_id']!r}, not {eff_run!r}",
                )
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
            else:
                existing_opts = json.loads(existing["options_json"] or "[]")
                if (
                    existing["question"] != question
                    or existing_opts != opts
                    or existing["run_id"] != run_id
                    or existing["recipient"] != (to or "human")
                ):
                    conn.execute("ROLLBACK")
                    raise ProviderError(
                        "request_mismatch",
                        f"retry-request {retry_request!r} payload does not match original ask",
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
        eff_run = self._resolve_caller_run(run, default_run=None)
        payload_sha = request_payload_sha256(
            {"task_id": task_id, "question": question, "options": options, "run": eff_run, "sender": sender}
        )
        cached = self.get_or_record_request(retry_request, "gate-create", payload_sha)
        if cached:
            return cached
        try:
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
                if eff_run is not None and t["run_id"] != eff_run:
                    conn.execute("ROLLBACK")
                    raise ProviderError(
                        "cross_run_access",
                        f"task {task_id!r} belongs to run {t['run_id']!r}, not {eff_run!r}",
                    )
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
                    (gate_id, t["run_id"], sender or COORDINATOR_ALIAS, question, json.dumps(opts), task_id, t["status"], time.time()),
                )
                conn.execute("UPDATE tasks SET status = 'blocked', updated_at = ? WHERE id = ?", (time.time(), task_id))
                self._recompute_dependents(conn, task_id)
                res = {"gate": {"id": gate_id, "taskId": task_id, "status": "pending", "question": question, "options": opts}}
                self._save_request_in_tx(conn, retry_request, "gate-create", "completed", res, payload_sha)
                conn.execute("COMMIT")
        except BaseException:
            self.release_request(retry_request)  # a failed claim must not block the retry
            raise
        return res

    def gate_resolve(
        self,
        *,
        gate_id: str,
        resolution: str,
        run: str | None = None,
        sender: str | None = None,
        retry_request: str | None = None,
    ) -> dict[str, Any]:
        if not gate_id or resolution is None:
            raise ProviderError("invalid_argument", "gate-resolve needs --id and --resolution")
        eff_run = self._resolve_caller_run(run, default_run=None)
        payload_sha = request_payload_sha256(
            {"gate_id": gate_id, "resolution": resolution, "run": eff_run, "sender": sender}
        )
        cached = self.get_or_record_request(retry_request, "gate-resolve", payload_sha)
        if cached:
            return cached
        try:
            who = sender or self._resolve_terminal(None) or COORDINATOR_ALIAS
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                row = self._find_gate(conn, gate_id)
                if not row:
                    conn.execute("ROLLBACK")
                    raise ProviderError("gate_not_found", f"gate {gate_id!r} not found")
                if eff_run is not None and row["run_id"] != eff_run:
                    conn.execute("ROLLBACK")
                    raise ProviderError(
                        "cross_run_access",
                        f"gate {row['gate_id']!r} belongs to run {row['run_id']!r}, not {eff_run!r}",
                    )
                try:
                    res = self._resolve_gate_in_tx(conn, row, resolution, status="resolved", who=who)
                except ProviderError:
                    conn.execute("ROLLBACK")
                    raise
                out = {"gate": {"id": gate_id, "status": res["status"], "resolution": resolution, "taskId": res.get("taskId")}}
                self._save_request_in_tx(conn, retry_request, "gate-resolve", "completed", out, payload_sha)
                conn.execute("COMMIT")
        except BaseException:
            self.release_request(retry_request)
            raise
        return out

    def gate_list(self, *, run: str | None = None, task_id: str | None = None, status: str | None = None) -> dict[str, Any]:
        eff_run = self._resolve_caller_run(run, default_run=None)
        q = "SELECT * FROM gates WHERE 1=1"
        params: list[Any] = []
        for col, val in (("run_id", eff_run), ("task_id", task_id), ("status", status)):
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
        """Only the coordinator/human answers a gate: never a launched worker, never the asker,
        and never a stale coordinator handle after run takeover (#750 C35)."""
        # The asker test applies to a worker's `ask`; a DAG gate's sender is the coordinator
        # that created it, and resolving its own hold is exactly its job.
        is_ask = (gate_row["kind"] or "ask") != "dag"
        if self._own_worker_identity() or (is_ask and resolver == gate_row["sender"]) or resolver in self._worker_handles(conn):
            raise ProviderError(
                "gate_answer_refused",
                f"{resolver!r} cannot answer gate {gate_row['gate_id']!r}: only the coordinator/human may",
            )
        run_row = conn.execute(
            "SELECT coordinator_handle FROM runs WHERE id = ?",
            (gate_row["run_id"],),
        ).fetchone()
        bound = run_row["coordinator_handle"] if run_row else None
        if bound and resolver != bound:
            raise ProviderError(
                "consumer_fenced",
                f"{resolver!r} cannot answer gate {gate_row['gate_id']!r}: run {gate_row['run_id']!r} is fenced to coordinator {bound!r}; pass --from {bound!r}",
            )

    def _resolve_gate_in_tx(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        answer: str,
        *,
        status: str = "answered",
        who: str,
    ) -> dict[str, Any]:
        """Resolve `row` inside the caller's active transaction (#750 C31)."""
        self._check_gate_answerer(conn, row, who)
        if row["status"] != "pending":
            return {
                "gateId": row["gate_id"],
                "status": row["status"],
                "answer": row["answer"],
                "taskId": row["task_id"],
                "alreadyResolved": True,
            }
        now = time.time()
        conn.execute(
            "UPDATE gates SET status = ?, answer = ?, resolved_at = ? WHERE gate_id = ?",
            (status, answer, now, row["gate_id"]),
        )
        if row["message_id"]:
            # The question is handled: it must stop reading as unread inbox work (and as
            # `waiting_input` to the watchdog) once its gate is answered (#592 review).
            conn.execute(
                "UPDATE deliveries SET acked = 1, acked_at = ? WHERE message_id = ? AND acked = 0",
                (now, row["message_id"]),
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
                    (new_status, now, row["task_id"]),
                )
                self._recompute_dependents(conn, row["task_id"])
        return {"gateId": row["gate_id"], "status": status, "answer": answer, "taskId": row["task_id"]}

    def resolve_gate(
        self,
        gate_id: str,
        answer: str,
        status: str = "answered",
        resolver: str | None = None,
        run: str | None = None,
    ) -> dict[str, Any]:
        """The ONE boundary every answer path (reply, gate-resolve, ask) crosses (#592 review)."""
        who = resolver or self._resolve_terminal(None) or COORDINATOR_ALIAS
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = self._find_gate(conn, gate_id)
            if not row:
                conn.execute("ROLLBACK")
                raise ProviderError("gate_not_found", f"gate {gate_id!r} not found")
            if run is not None and row["run_id"] != run:
                conn.execute("ROLLBACK")
                raise ProviderError(
                    "cross_run_access",
                    f"gate {row['gate_id']!r} belongs to run {row['run_id']!r}, not {run!r}",
                )
            try:
                res = self._resolve_gate_in_tx(conn, row, answer, status=status, who=who)
            except ProviderError:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")
        return res

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
    @staticmethod
    def _terminal_report(
        conn: sqlite3.Connection,
        run_id: str,
        senders: list[str],
        *,
        dispatch_id: str | None = None,
    ) -> Any:
        """The worker's own terminal mail (or the worker_died already sent for it), bound to `dispatch_id`."""
        if not senders:
            return None
        placeholders = ",".join("?" for _ in senders)
        rows = conn.execute(
            f"""
            SELECT id, sender, msg_type, outcome, attrs_json, created_at FROM messages
            WHERE run_id = ? AND sender IN ({placeholders})
              AND msg_type IN ('worker_done', 'merge_ready', 'escalation')
              AND COALESCE(attrs_json, '') NOT LIKE '%"fileTouchConflict"%'
            ORDER BY created_at DESC, rowid DESC
            """,
            [run_id, *senders],
        ).fetchall()
        if not dispatch_id:
            return rows[0] if rows else None
        disp = conn.execute(
            "SELECT rowid AS rid, dispatch_id, task_id, terminal_handle, created_at "
            "FROM dispatches WHERE dispatch_id = ?",
            (dispatch_id,),
        ).fetchone()
        other_disp_ids = {
            r["dispatch_id"]
            for r in conn.execute(
                "SELECT dispatch_id FROM dispatches WHERE run_id = ? AND dispatch_id != ?",
                (run_id, dispatch_id),
            ).fetchall()
        }
        sibling_count = 0
        if disp and disp["terminal_handle"]:
            sibling_row = conn.execute(
                "SELECT COUNT(*) AS c FROM dispatches WHERE run_id = ? AND terminal_handle = ? AND dispatch_id != ?",
                (run_id, disp["terminal_handle"], dispatch_id),
            ).fetchone()
            sibling_count = int(sibling_row["c"] or 0) if sibling_row else 0
        for m in rows:
            try:
                attrs = json.loads(m["attrs_json"] or "{}")
            except ValueError:
                attrs = {}
            if not isinstance(attrs, dict):
                attrs = {}
            msg_disp = next(
                (
                    attrs[k]
                    for k in ("dispatchId", "dispatch_id", "dispatch-id")
                    if isinstance(attrs.get(k), str) and attrs[k]
                ),
                None,
            )
            if msg_disp is not None:
                if msg_disp != dispatch_id:
                    continue
                return m
            if m["sender"] in other_disp_ids:
                continue
            msg_task = next(
                (
                    attrs[k]
                    for k in ("taskId", "task_id", "task-id")
                    if isinstance(attrs.get(k), str) and attrs[k]
                ),
                None,
            )
            if msg_task is not None and disp and disp["task_id"] and msg_task != disp["task_id"]:
                continue
            if disp and m["created_at"] < disp["created_at"]:
                continue
            if m["sender"] != dispatch_id and sibling_count > 0:
                continue
            return m
        return None

    def terminal_report(self, *, dispatch_id: str, worker_handle: str | None = None, run_id: str = "default") -> str | None:
        """The id of the terminal mail this dispatch already reported, or None (#596)."""
        senders = [s for s in {dispatch_id, worker_handle or ""} if s]
        with self._connect() as conn:
            row = self._terminal_report(conn, run_id, senders, dispatch_id=dispatch_id)
        return row["id"] if row else None

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
            disp = conn.execute(
                "SELECT state, run_id, intent_id, gate_closed_at, monitor_started_at FROM dispatches WHERE dispatch_id = ?",
                (dispatch_id,),
            ).fetchone()
            if disp is None:
                # Withdrawn before it launched (claim released): nothing died that anyone owns.
                conn.execute("COMMIT")
                return {"syntheticDied": False, "unknownDispatch": True}
            if disp["state"] in FENCED_DISPATCH_STATES:
                conn.execute("COMMIT")
                return {"syntheticDied": False, "fenced": disp["state"]}
            if disp["intent_id"] and disp["gate_closed_at"] is not None and disp["monitor_started_at"] is None:
                # A fence closed its launch gate before any monitor claimed it, and a later retain
                # never reopens it: no gated worker ever ran under it, so none died (#597).
                conn.execute("COMMIT")
                return {"syntheticDied": False, "gateClosed": True}
            if disp and disp["state"] == "died":
                conn.execute("COMMIT")
                return {"syntheticDied": False, "alreadyDied": True}
            now = time.time()
            eff_run = disp["run_id"] or run_id
            row = self._terminal_report(conn, eff_run, senders, dispatch_id=dispatch_id)
            if row:
                if disp["state"] != "completed":
                    conn.execute(
                        "UPDATE dispatches SET state = 'completed', terminal_state = 'exited', head_sha = COALESCE(NULLIF(?, ''), head_sha), "
                        "updated_at = ? WHERE dispatch_id = ? AND state NOT IN ('stopped','abandoned','released')",
                        (worktree_head_sha, now, dispatch_id),
                    )
                    if row["msg_type"] in ("worker_done", "merge_ready"):
                        succeeded = (row["msg_type"] == "merge_ready" and row["outcome"] != "failed") or (
                            row["msg_type"] == "worker_done" and row["outcome"] == "succeeded"
                        )
                        self._settle_dispatch_task(conn, dispatch_id, succeeded=succeeded, now=now)
                conn.execute("COMMIT")
                return {"syntheticDied": False, "existingMessageId": row["id"], "type": row["msg_type"]}
            if disp["state"] == "completed":
                conn.execute("COMMIT")
                return {"syntheticDied": False, "alreadyCompleted": True}
            conn.execute(
                "UPDATE dispatches SET state = 'died', terminal_state = 'failed', head_sha = COALESCE(NULLIF(?, ''), head_sha), "
                "updated_at = ? WHERE dispatch_id = ?",
                (worktree_head_sha, now, dispatch_id),
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
                run_id=eff_run,
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

    # --- #596: a PROFILE=ro worker's completion line, relayed as its `worker_done` ---
    def relay_worker_done(
        self,
        *,
        dispatch_id: str,
        worker_handle: str,
        outcome: str,
        run_id: str = "default",
        head_sha: str = "",
    ) -> dict[str, Any]:
        """Send the `worker_done` a PROFILE=ro worker reported in its own output (#596).

        A ro launch has no tool that can run send_msg.py or write this database, so the exit
        monitor relays the worker's completion line here, AS its terminal and only for its own
        dispatch. One transaction, like ensure_terminal_or_died: a fenced or settled dispatch, or
        one whose worker already sent terminal mail, gets nothing, so the relay never speaks twice
        and never for a dispatch the coordinator stopped. It is the worker's claim, relayed; the
        coordinator verifies it like any other `worker_done`.
        """
        if outcome not in ("succeeded", "failed"):
            raise ProviderError("invalid_outcome", f"worker_done outcome must be succeeded|failed, got {outcome!r}")
        senders = [s for s in {dispatch_id, worker_handle} if s]
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            disp = conn.execute("SELECT state, run_id FROM dispatches WHERE dispatch_id = ?", (dispatch_id,)).fetchone()
            if disp is None or disp["state"] in (*FENCED_DISPATCH_STATES, "died", "completed"):
                conn.execute("COMMIT")
                return {"relayed": False, "state": disp["state"] if disp else None}
            eff_run = disp["run_id"] or run_id
            row = self._terminal_report(conn, eff_run, senders, dispatch_id=dispatch_id)
            if row:
                conn.execute("COMMIT")
                return {"relayed": False, "existingMessageId": row["id"]}
            now = time.time()
            succeeded = outcome == "succeeded"
            conn.execute(
                "UPDATE dispatches SET state = 'completed', terminal_state = 'exited', head_sha = COALESCE(NULLIF(?, ''), head_sha), "
                "updated_at = ? WHERE dispatch_id = ?",
                (head_sha, now, dispatch_id),
            )
            self._settle_dispatch_task(conn, dispatch_id, succeeded=succeeded, now=now)
            msg_id, deliv_id = self._insert_message(
                conn,
                run_id=eff_run,
                sender=worker_handle,
                recipient=COORDINATOR_ALIAS,
                msg_type="worker_done",
                subject=f"worker_done:{dispatch_id}",
                outcome=outcome,
                # The outcome rides the payload too: check_reply.py prints the payload, not the column.
                payload=json.dumps({"dispatchId": dispatch_id, "headSha": head_sha, "outcome": outcome,
                                    "via": "ro-completion-line"}, sort_keys=True),
                attrs={"relayed": "ro-completion-line", "dispatchId": dispatch_id},
            )
            conn.execute("COMMIT")
        return {"relayed": True, "messageId": msg_id, "deliveryId": deliv_id}
