#!/usr/bin/env python3
"""merge_queue.py — the persisted, fenced single-conductor merge queue (#599).

merge-serialization.md says one conductor owns every merge to an integration BASE, in arrival
order, behind an expected-head guard. Until #599 that was discipline only: nothing stopped two
coordinators merging onto one BASE, and a conductor that crashed mid-train left no record of
what it had already sent. This script is the serialized merge-effect boundary that cooperating
fleet writers route their merges through. It is provider-neutral: a `merge_ready` from Orca's
mailbox or the posix provider's boards the same way.

What holds, and for whom
  * ONE conductor per (repository, BASE). `acquire` issues a lease with a fencing token and a
    monotonic epoch. Every queue mutation checks that token inside its own SQLite write
    transaction (`_fence`), so a superseded conductor is refused `fenced`: it cannot board,
    plan, dequeue, merge, acknowledge, resolve or release.
  * The remote merge happens inside the EFFECT LOCK, an exclusive flock per (repository, BASE),
    after a token-checked compare-and-set that records the merge intent (`merging`). A handoff
    must hold the same lock to bump the epoch. A conductor paused after its lease check
    therefore resumes into a refused compare-and-set and never sends. One paused INSIDE the
    boundary blocks the handoff (`merge_in_flight`) instead of being raced. Every remote write's
    child (the merge, and a branch deletion) inherits the lock, so a conductor killed mid-call
    holds the boundary until the call ends.
  * A handoff first reconciles every in-flight merge against authoritative state
    (`gh pr view`, or `git ls-remote` plus ancestry). One it cannot decide, because the remote
    is unreachable, blocks the handoff (`in_flight_unknown`). Nothing is guessed.
  * Before every merge it revalidates the expected heads and the tested merge tree. A head that
    moved to different content is returned to review. A content-identical move
    (reviewed-sha-freshness.md) keeps the review and pins the new head. A moved BASE, or a merge
    tree that is no longer the tested one, returns the entry to `plan` (`retest_required`).
  * Every remote read and write is bound to the queue's repository: the remote's fetch and push
    URLs must name the repository the lease names, and every `gh` call passes it as `--repo`
    (never GH_REPO or gh's own default), so no call can act on a fork or another repository.
    Identities follow git's own URL rules, a relative path resolved against the clone's toplevel
    as git resolves it, in one spelling (`normalize_identity`: GitHub names fold case), so one
    remote is one queue from whatever directory or spelling a conductor starts with.
  * Scope: cooperating fleet writers that share this store on one host. A local lease cannot
    fence an arbitrary GitHub user, or a writer that bypasses this script. Their writes surface
    as a moved BASE or a moved head, which the guards refuse; they never land untested content
    silently. In gh mode GitHub alone decides which BASE commit it merges onto, so a merge whose
    first parent is not the expected BASE head is recorded `treeMatchesTested: false`, and `ack`
    then requires an explicit `--accept-untested-tree`.
  * Default-branch promotion is human-only. `init` refuses a BASE equal to the default branch,
    boarding refuses a payload aimed at it, and no command ever writes to it.

Entry states
    queued -> merging -> merged -> landed      (the train)
    queued -> bounced                          (head moved to new content: back to review)
    queued -> failed                           (conflict, failed gate, refused merge: the train
                                                FREEZES behind it until `resolve`)
    queued -> superseded                       (the unit re-boarded at a newer reviewed SHA)
    failed -> queued | bounced | dropped       (`resolve`, the conductor's recorded decision)

Modes
    gh   GitHub's merges endpoint, `POST repos/<owner>/<name>/merges` with base=<BASE> and
         head=<the accepted commit>: the write names BASE, so a PR retargeted after the last
         read cannot take the merge to another branch (PR #647; `gh pr merge` merges into
         whatever the PR targets when it runs). PR facts come from `gh pr view`; the result is
         verified by ancestry on BASE. This is the default path.
    git  the no-gh lane (merge-serialization.md "No-gh fallback"): the merge commit is
         `commit-tree` of the TESTED tree, pushed with `--force-with-lease=<BASE>:<expected>`
         (a true compare-and-swap on the remote ref). Its receipts say `no-gh: local-merge`.

Every remote merge is preceded by an egress receipt (egress.py, fail-closed: no receipt, no
send). Receipts for every transition land in the queue's own table (`receipts`).

Usage: merge_queue.py [--db PATH] [--repo-dir DIR] [--repo ID] <command> ...
Commands: init, acquire, release, enqueue, plan, merge, ack, resolve, reconcile, status,
receipts, drain. Every command prints one JSON object.

Exit: 0 ok · 1 blocked (frozen, ack owed, retest, returned to review, offline, in flight) ·
2 usage or refused input · 3 not the owner (fenced, lease held, unknown token).
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import functools
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Callable

EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_USAGE = 2
EXIT_FENCED = 3

QUEUED, MERGING, MERGED, LANDED = "queued", "merging", "merged", "landed"
BOUNCED, FAILED, SUPERSEDED, DROPPED = "bounced", "failed", "superseded", "dropped"
# The states that occupy the train. Its head, the lowest arrival seq among them, is the only
# entry that may merge (arrival order only; merge-serialization.md "Rules").
LINE_STATES = (QUEUED, MERGING, MERGED, FAILED)
# One merge's committed boundaries, in order. `on_boundary` observes each one (the drills).
MERGE_BOUNDARIES = ("lease_checked", "intent_recorded", "remote_merged", "merged_recorded")
MODES = ("gh", "git")
RESOLVE_ACTIONS = {"requeue": QUEUED, "bounce": BOUNCED, "drop": DROPPED}
DEFAULT_TTL = 900.0
OBJECT_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
# A repository GitHub can name: exactly host/owner/name (the shape `gh --repo HOST/OWNER/REPO` takes).
GH_REPO_RE = re.compile(r"[A-Za-z0-9.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
# A branch name that is safe inside a refspec: no `:`, whitespace, `..`, glob or revision syntax.
BRANCH_RE = re.compile(r"(?!-)(?!refs/)(?!.*\.\.)(?!.*\.lock$)[A-Za-z0-9._/-]+")
PRIVATE_REFS = "refs/open-fleet/merge-queue"
# Prefix commits exist only to give a gate a checkout. A fixed identity and date make them
# reproducible, and they are never pushed.
PREFIX_IDENTITY = {
    "GIT_AUTHOR_NAME": "open-fleet merge-queue", "GIT_AUTHOR_EMAIL": "merge-queue@open-fleet.invalid",
    "GIT_COMMITTER_NAME": "open-fleet merge-queue", "GIT_COMMITTER_EMAIL": "merge-queue@open-fleet.invalid",
    "GIT_AUTHOR_DATE": "@0 +0000", "GIT_COMMITTER_DATE": "@0 +0000",
}
HERE = Path(__file__).resolve().parent


def _sibling(name: str, filename: str) -> Any:
    """Load a sibling runtime script by path (the bundle ships them side by side)."""
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


egress = _sibling("_mq_egress", "egress.py")
diff_scope = _sibling("_mq_diff_scope", "diff_scope.py")  # #590's in-memory merge prediction


class QueueError(Exception):
    """A refusal with a stable code; `exit_code` is what the CLI exits with."""

    def __init__(self, code: str, message: str, data: dict[str, Any] | None = None, exit_code: int = EXIT_BLOCKED):
        super().__init__(message)
        self.code, self.message, self.data, self.exit_code = code, message, dict(data or {}), exit_code

    def as_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"ok": False, "code": self.code, "message": self.message}
        if self.data:
            out["data"] = self.data
        return out


class Offline(QueueError):
    """The authoritative remote (GitHub or the git remote) could not be read or written."""

    def __init__(self, what: str, detail: str = ""):
        tail = f": {detail.strip()[-300:]}" if detail and detail.strip() else ""
        super().__init__("offline", f"{what} is unreachable{tail}", {"what": what})


def default_db_path(env: dict[str, str]) -> Path:
    if env.get("OPEN_FLEET_MERGE_QUEUE_DB"):
        return Path(env["OPEN_FLEET_MERGE_QUEUE_DB"]).expanduser().resolve()
    root = env.get("OPEN_FLEET_STATE_DIR") or env.get("ORCA_FLEET_STATE_DIR")
    if root:
        return Path(root).expanduser().resolve() / "merge-queue.db"
    # ONE store per host, not per clone: two conductors in two clones of one repository must
    # contend for the same lease row, or "one conductor per BASE" holds per checkout only.
    return Path.home() / ".open-fleet" / "state" / "merge-queue.db"


# Hosts whose owner and repository names are case-insensitive, as GitHub's are. github.com always;
# a GitHub Enterprise host once configured here (comma-separated) or once a gh-lane queue names it.
GITHUB_HOSTS_ENV = "OPEN_FLEET_GITHUB_HOSTS"
DEFAULT_GITHUB_HOSTS = frozenset({"github.com"})


def normalize_identity(identity: str, github_hosts: frozenset[str] | set[str] = frozenset()) -> str:
    """One spelling per repository (PR #647: `Team/Repo` and `team/repo` split the queue).

    A network identity's host is lowercased (`www.github.com` is `github.com`), a trailing `/`
    and `.git` are dropped, and on a GitHub host the owner and name are lowercased too, because
    GitHub serves every casing as the same repository. Another forge keeps its casing. A local
    path is returned as it is: `repo_identity` has already spelled it as the disk does.
    """
    if identity.startswith("/"):
        return identity
    host, _, path = identity.partition("/")
    host = host.lower()
    host = "github.com" if host == "www.github.com" else host
    path = path.strip("/")
    path = path[:-4].rstrip("/") if path.endswith(".git") else path
    if host in DEFAULT_GITHUB_HOSTS or host in {h.lower() for h in github_hosts}:
        path = path.lower()
    return f"{host}/{path}"


def _on_disk_case(path: Path) -> Path:
    """The path with each existing component spelled as its directory lists it.

    On a case-insensitive filesystem `Remote.git` and `remote.git` are one directory, so they must
    be one identity. A component is respelled only when the listed name is the SAME file, so on
    a case-sensitive filesystem the path stays byte-exact.
    """
    out = Path(path.parts[0])
    parts = path.parts[1:]
    for i, name in enumerate(parts):
        try:
            entries = os.listdir(out)
        except OSError:
            return out.joinpath(*parts[i:])
        if name not in entries:
            same = [e for e in entries if e.casefold() == name.casefold()]
            with contextlib.suppress(OSError):  # the spelled path does not exist: keep its bytes
                if len(same) == 1 and os.path.samefile(out / same[0], out / name):
                    name = same[0]
        out = out / name
    return out


def repo_identity(url: str, base: str | Path | None = None, home: str | None = None,
                  github_hosts: frozenset[str] | set[str] = frozenset()) -> str:
    """The repository a remote URL names, by git's own rules: `host/owner/name`, or a local path
    resolved to its real absolute path.

    The rules are git's, not a guess (PR #647: one remote must never be two queues):
      * `scheme://` is a network URL, except `file://`, which is a local path;
      * otherwise a colon BEFORE any slash is scp syntax, `[user@]host:path`, which git sends
        over ssh with or without `user@`; a slash first (`./a:b`, `dir/with:colon`) is local;
      * a local path is expanded for `~` (git does) and, when relative, resolved against `base`:
        git resolves it against the toplevel of the worktree it runs in (the git dir of a bare
        repository), never the caller's working directory. The queue passes its clone's
        (`MergeQueue._identity`); `base=None` means the current directory, for callers outside.
    """
    u = url.strip()
    if "://" in u and not u.startswith("file://"):
        parts = urllib.parse.urlsplit(u)
        host, path = parts.hostname or "", parts.path
    elif "://" not in u and 0 < u.find(":") and (u.find("/") == -1 or u.find(":") < u.find("/")):
        hostpart, path = u.split(":", 1)
        host = hostpart.rsplit("@", 1)[-1].strip("[]")
    else:
        local = urllib.parse.unquote(urllib.parse.urlsplit(u).path) if u.startswith("file://") else u
        if local == "~" or local.startswith("~/"):
            local = (home or os.path.expanduser("~")) + local[1:]
        elif local.startswith("~"):
            local = os.path.expanduser(local)
        path_ = Path(local)
        if not path_.is_absolute():
            path_ = Path(base if base is not None else os.getcwd()) / path_
        return str(_on_disk_case(path_.resolve()))
    return normalize_identity(f"{host}/{path}", github_hosts)


def identity_host(identity: str) -> str:
    """The host of an identity (`localhost` for a local path)."""
    return identity.split("/", 1)[0] if not identity.startswith("/") else "localhost"


def _digest(*parts: Any) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode("utf-8")).hexdigest()


class _ClosingConnection(sqlite3.Connection):
    """A connection whose `with` block also closes it (local_state.py's rule)."""

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        try:
            return super().__exit__(exc_type, exc, tb)
        finally:
            self.close()


def lock_file(lock_dir: Path, identity: str, base: str) -> Path:
    """The effect lock's file for a queue. Callers pass the NORMALIZED identity, so every spelling
    of one repository maps to one lock (PR #647). The formula is the one earlier versions used,
    so a lock held under a queue's stored, already-normal spelling is the same file on both sides
    of an upgrade."""
    name = hashlib.sha256(f"{identity}\0{base}".encode("utf-8")).hexdigest()[:24]
    return lock_dir / f"{name}.lock"


def _statements(script: str) -> list[str]:
    """Split a DDL script into statements by SQLite's own rule: a `;` inside a comment or a
    string ends nothing (`str.split(";")` did, so a commented schema broke the store's opening)."""
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


class Store:
    """SQLite WAL store. Every write is ONE `BEGIN IMMEDIATE` transaction (`tx`)."""

    SCHEMA = """
        CREATE TABLE IF NOT EXISTS mq_queues (
            repo TEXT NOT NULL, base TEXT NOT NULL, default_branch TEXT NOT NULL,
            mode TEXT NOT NULL, remote TEXT NOT NULL, host TEXT NOT NULL, consent TEXT NOT NULL,
            next_seq INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL,
            PRIMARY KEY (repo, base)
        );
        CREATE TABLE IF NOT EXISTS mq_leases (
            repo TEXT NOT NULL, base TEXT NOT NULL, holder TEXT NOT NULL, token TEXT NOT NULL,
            epoch INTEGER NOT NULL, pid INTEGER, host TEXT, ttl REAL NOT NULL,
            acquired_at REAL NOT NULL, expires_at REAL NOT NULL, released_at REAL,
            PRIMARY KEY (repo, base)
        );
        CREATE TABLE IF NOT EXISTS mq_tokens (
            token TEXT PRIMARY KEY, repo TEXT NOT NULL, base TEXT NOT NULL,
            epoch INTEGER NOT NULL, holder TEXT NOT NULL, issued_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mq_entries (
            entry_id TEXT PRIMARY KEY, repo TEXT NOT NULL, base TEXT NOT NULL,
            seq INTEGER NOT NULL, run_id TEXT NOT NULL, unit TEXT NOT NULL, pr INTEGER,
            branch TEXT NOT NULL, reviewed_sha TEXT NOT NULL, reviewed_tree TEXT,
            delivery_key TEXT NOT NULL, payload_fp TEXT NOT NULL, deliveries_json TEXT NOT NULL,
            state TEXT NOT NULL, reason TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL,
            UNIQUE (repo, base, delivery_key), UNIQUE (repo, base, seq)
        );
        CREATE TABLE IF NOT EXISTS mq_receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, repo TEXT NOT NULL, base TEXT NOT NULL,
            entry_id TEXT, kind TEXT NOT NULL, epoch INTEGER, holder TEXT,
            body_json TEXT NOT NULL, created_at REAL NOT NULL
        );
    """
    # Additive columns, migrated in place (local_state.py's `_migrate` rule): a store written by
    # an older schema gains them on open. Schema and migration run in ONE `BEGIN IMMEDIATE`
    # transaction, so concurrent openers take turns and each re-reads the columns under the lock.
    COLUMNS = {
        "mq_entries": {
            "accepted_head": "TEXT", "expected_base": "TEXT", "tested_base_tree": "TEXT",
            "tested_tree": "TEXT", "prefix_commit": "TEXT", "gate_json": "TEXT",
            "merging_epoch": "INTEGER", "merging_pid": "INTEGER", "merge_sha": "TEXT",
            "merged_tree": "TEXT", "tree_matches_tested": "INTEGER", "reviewed_tree_source": "TEXT",
            # The branch teardown, persisted with the merge intent so a restart finishes it (PR #647):
            # 'delete' or 'keep' while owed, then its final outcome. NULL: none (the no-gh lane).
            "teardown": "TEXT",
        },
    }

    BUSY_SECONDS = 30.0

    IDENTITY_TABLES = ("mq_queues", "mq_leases", "mq_tokens", "mq_entries", "mq_receipts")

    def __init__(self, path: Path, github_hosts: frozenset[str] | set[str] = DEFAULT_GITHUB_HOSTS):
        self.path = Path(path)
        self.github_hosts = frozenset(h.lower() for h in github_hosts) | DEFAULT_GITHUB_HOSTS
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_dir = self.path.parent / "merge-queue-locks"
        held: list[EffectLock] = []
        try:
            with self.tx() as conn:
                # Not executescript: it COMMITs first and runs each statement in autocommit, which
                # would let another opener interleave between the CREATEs and the migration.
                for statement in _statements(self.SCHEMA):
                    if statement.strip():
                        conn.execute(statement)
                self._migrate(conn)
                self._normalize_identities(conn, held)
        finally:
            for lock in held:  # released only after the respelling committed (or rolled back)
                lock.release()

    def hosts(self, conn: sqlite3.Connection) -> frozenset[str]:
        """The GitHub hosts: configured ones, plus every host a gh-lane queue already names."""
        named = {r["repo"].split("/", 1)[0] for r in conn.execute("SELECT repo FROM mq_queues WHERE mode = 'gh'")}
        return self.github_hosts | frozenset(named)

    def _normalize_identities(self, conn: sqlite3.Connection, held: list[EffectLock]) -> None:
        """Respell an identity an older store holds the way `normalize_identity` does (PR #647).

        Every table that carries the identity moves together, so a lease never splits from its
        queue. Renaming a queue changes its lock file, so it is renamed only while this opener
        holds the effect lock of the old spelling AND the new one, until the rename commits. A
        conductor (or its merge or deletion child) still holding either refuses the opening with
        `migration_blocked`: no handoff can begin under a send still in flight. When the
        normalized spelling is already a queue of its own, nothing is merged: the store holds
        one repository as two queues, and `MergeQueue._config` refuses it by name.
        """
        hosts = self.hosts(conn)
        for row in conn.execute("SELECT repo, base FROM mq_queues").fetchall():
            folded = normalize_identity(row["repo"], hosts)
            if folded == row["repo"]:
                continue
            if conn.execute("SELECT 1 FROM mq_queues WHERE repo = ? AND base = ?", (folded, row["base"])).fetchone():
                continue
            for spelling in (row["repo"], folded):
                lock = EffectLock(lock_file(self.lock_dir, spelling, row["base"]))
                held.append(lock)
                if not lock.acquire(0.0):
                    raise QueueError(
                        "migration_blocked",
                        f"the store respells {row['repo']} as {folded}, but a conductor or its child still holds "
                        f"the merge boundary of {spelling!r} (BASE {row['base']!r}); nothing was renamed: retry once "
                        "that send has ended",
                        {"from": row["repo"], "to": folded, "base": row["base"], "lock": str(lock.path)},
                    )
            for table in self.IDENTITY_TABLES:
                conn.execute(f"UPDATE {table} SET repo = ? WHERE repo = ? AND base = ?", (folded, row["repo"], row["base"]))

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=self.BUSY_SECONDS, isolation_level=None,
                               factory=_ClosingConnection)
        conn.row_factory = sqlite3.Row
        # The busy timeout first, so every statement below (and after) waits out a lock.
        conn.execute(f"PRAGMA busy_timeout={int(self.BUSY_SECONDS * 1000)};")
        self._wal(conn)
        return conn

    def _wal(self, conn: sqlite3.Connection) -> None:
        """Put the store in WAL mode, once per database file, surviving concurrent openers.

        Switching the journal mode needs an exclusive lock, and SQLite answers a contender
        `database is locked` at once rather than through the busy handler. Several conductors
        opening a fresh store together hit exactly that (#599 CI: openers exiting 1 at random).
        WAL is persistent, so the first opener's switch is every later connection's no-op.
        Only a lock is retried, with backoff, up to BUSY_SECONDS, then refused as
        `store_locked`. Any mode SQLite answers without error ends the switch: WAL, or one it
        keeps a database in (`memory` for an in-memory one). The queue's guarantees rest on
        `BEGIN IMMEDIATE` and the busy timeout, which every journal mode honours; WAL only lets
        readers run beside a writer. Before, a non-WAL answer was asked again forever, with no
        deadline (the same defect main's local_state.py fixed).
        """
        deadline = time.monotonic() + self.BUSY_SECONDS
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
                    raise QueueError(
                        "store_locked",
                        f"{self.path}: could not switch the store to WAL within {self.BUSY_SECONDS:g}s; "
                        f"another process kept it locked ({exc})",
                        {"store": str(self.path)},
                    ) from exc
                time.sleep(delay)
                delay = min(delay * 2, 0.2)

    @classmethod
    def _migrate(cls, conn: sqlite3.Connection) -> None:
        for table, cols in cls.COLUMNS.items():
            have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            for col, decl in cols.items():
                if col in have:
                    continue
                try:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
                except sqlite3.OperationalError as exc:  # added already: the outcome we wanted
                    if "duplicate column" not in str(exc).lower():
                        raise

    @contextlib.contextmanager
    def tx(self):
        """One write transaction; an exception (a refusal included) rolls it back whole."""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def read(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]


class EffectLock:
    """The serialized merge-effect boundary for one (repository, BASE): an exclusive flock (#599).

    Held from the fenced intent compare-and-set through the remote merge and its record, and by
    every handoff. The kernel drops it when its last holder dies, however it dies. The merge child
    inherits the descriptor (`pass_fds`), so a conductor killed mid-call keeps the boundary held
    until the remote call itself ends. A handoff can never reconcile a merge that is still being
    sent. Never take two of these for one queue in one process: flock locks are per open file.
    """

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.fd: int | None = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)

    def acquire(self, wait: float = 0.0) -> bool:
        deadline = time.monotonic() + max(0.0, wait)
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except OSError:
                if time.monotonic() >= deadline:
                    return False
                time.sleep(0.05)

    def release(self) -> None:
        # Close, never LOCK_UN: an unlock would drop the lock a still-running merge child shares.
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class Git:
    """git in the conductor's clone, under the caller's identity and credentials, never prompting."""

    HARDENED_CONFIG = (
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false",
        "-c", "core.symlinks=false",
    )

    def __init__(self, repo_dir: Path, env: dict[str, str]):
        self.repo_dir = str(repo_dir)
        found = shutil.which("git", path=env.get("PATH"))
        self.bin = os.path.abspath(found) if found else "git"
        self.env = {
            **env,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        }

    def run(self, *args: str, check: bool = True, env: dict[str, str] | None = None,
            pass_fds: tuple[int, ...] = (), timeout: float = 300.0, cwd: str | None = None) -> subprocess.CompletedProcess:
        try:
            proc = subprocess.run([self.bin, *self.HARDENED_CONFIG, "-C", cwd or self.repo_dir, *args],
                                  capture_output=True, text=True,
                                  env={**self.env, **(env or {})}, pass_fds=pass_fds, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            raise QueueError("git_failed", f"git {' '.join(args[:2])} could not run: {exc}") from exc
        if check and proc.returncode != 0:
            raise QueueError("git_failed", f"git {' '.join(args[:3])} failed: {(proc.stderr or proc.stdout).strip()[-300:]}")
        return proc

    def out(self, *args: str) -> str:
        return self.run(*args).stdout.strip()

    def fetch(self, remote: str, src: str, private: str) -> str | None:
        """Fetch `src` from `remote` into a private ref; its sha, or None when the remote lacks it."""
        dst = f"{PRIVATE_REFS}/{private}"
        proc = self.run("fetch", "--no-tags", "--quiet", remote, f"+{src}:{dst}", check=False)
        if proc.returncode != 0:
            err = (proc.stderr or "").lower()
            if "couldn't find remote ref" in err or "not our ref" in err or "invalid refspec" in err:
                return None
            raise Offline(f"git remote {remote!r}", proc.stderr)
        return self.out("rev-parse", "--verify", f"{dst}^{{commit}}")

    def remote_urls(self, remote: str) -> tuple[list[str], list[str]]:
        """The remote's configured fetch URLs and push URLs, as written (before `insteadOf`)."""
        def values(key: str) -> list[str]:
            proc = self.run("config", "--get-all", key, check=False)
            return [v.strip() for v in proc.stdout.splitlines() if v.strip()]
        return values(f"remote.{remote}.url"), values(f"remote.{remote}.pushurl")

    def has_commit(self, sha: str | None) -> bool:
        return bool(sha) and self.run("cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode == 0

    def tree(self, rev: str) -> str:
        return self.out("rev-parse", "--verify", f"{rev}^{{tree}}")

    def is_ancestor(self, a: str, b: str) -> bool:
        proc = self.run("merge-base", "--is-ancestor", a, b, check=False)
        if proc.returncode not in (0, 1):
            raise QueueError("git_failed", f"merge-base --is-ancestor failed: {proc.stderr.strip()[-200:]}")
        return proc.returncode == 0

    def parents(self, sha: str) -> list[str]:
        return self.out("rev-list", "--parents", "-n", "1", sha).split()[1:]

    def commit_tree(self, tree: str, parents: list[str], message: str, env: dict[str, str] | None = None,
                    sign: bool = True) -> str:
        args = ["commit-tree", tree] if sign else ["commit-tree", "--no-gpg-sign", tree]
        for parent in parents:
            args += ["-p", parent]
        return self.run(*args, "-m", message, env=env).stdout.strip()

    def keep(self, name: str, sha: str) -> None:
        """Pin an object under the private namespace so gc never prunes what a receipt names."""
        self.run("update-ref", f"{PRIVATE_REFS}/{name}", sha)


class Gh:
    """The GitHub seam: the `gh` CLI, resolved once to an absolute path from the caller's PATH."""

    FIELDS = ("number,state,headRefOid,headRefName,baseRefName,mergeCommit,url,"
              "headRepository,headRepositoryOwner,isCrossRepository")

    def __init__(self, repo_dir: Path, env: dict[str, str]):
        found = shutil.which("gh", path=env.get("PATH"))
        self.bin = os.path.abspath(found) if found else None
        self.repo_dir, self.env = str(repo_dir), env

    def _run(self, args: list[str], pass_fds: tuple[int, ...] = ()) -> subprocess.CompletedProcess:
        if self.bin is None:
            raise Offline("GitHub (no gh on PATH)")
        try:
            # GH_REPO dropped: every call names its repository with --repo, so nothing in the
            # environment can redirect a read or a merge to another repository (PR #647).
            env = {k: v for k, v in self.env.items() if k != "GH_REPO"}
            return subprocess.run([self.bin, *args], capture_output=True, text=True, cwd=self.repo_dir,
                                  env={**env, "GH_PROMPT_DISABLED": "1"}, pass_fds=pass_fds, timeout=300)
        except (OSError, subprocess.SubprocessError) as exc:
            raise Offline("GitHub", str(exc)) from exc

    def pr_view(self, repo: str, pr: int) -> dict[str, Any]:
        proc = self._run(["pr", "view", str(pr), "--repo", repo, "--json", self.FIELDS])
        if proc.returncode != 0:
            raise Offline("GitHub", proc.stderr)
        try:
            data = json.loads(proc.stdout)
        except ValueError as exc:
            raise Offline("GitHub", f"unparseable pr view: {exc}") from exc
        if not isinstance(data, dict) or not OBJECT_RE.fullmatch(str(data.get("headRefOid", ""))):
            raise Offline("GitHub", "pr view returned no headRefOid")
        return data

    def merge_into(self, repo: str, base: str, head: str, message: str,
                   pass_fds: tuple[int, ...]) -> subprocess.CompletedProcess:
        """GitHub's merges endpoint: merge the commit `head` into the branch `base`, BY NAME (PR #647).

        Not `gh pr merge`: GitHub's PR merge (REST or GraphQL) can pin the head SHA but never the
        target, and merges into whatever the PR targets when it runs. A PR retargeted after the
        conductor's last read (at the default branch, say) would take the merge with it. This call
        names the branch and the exact accepted commit, so nothing about the PR can redirect it.
        GitHub marks a PR merged once its head reaches the branch it targets.
        """
        host, owner_name = repo.split("/", 1)
        return self._run(["api", "--method", "POST", "--hostname", host, f"repos/{owner_name}/merges",
                          "-f", f"base={base}", "-f", f"head={head}", "-f", f"commit_message={message}"],
                         pass_fds=pass_fds)


class MergeQueue:
    """The queue for every (repository, BASE) in one store, driven from one conductor clone."""

    def __init__(self, db_path: str | Path | None = None, repo_dir: str | Path = ".", env: dict[str, str] | None = None):
        self.env = dict(os.environ if env is None else env)
        self.db_path = Path(db_path) if db_path else default_db_path(self.env)
        configured = {h.strip().lower() for h in self.env.get(GITHUB_HOSTS_ENV, "").split(",") if h.strip()}
        self.store = Store(self.db_path, DEFAULT_GITHUB_HOSTS | configured)
        self.repo_dir = Path(repo_dir).resolve()
        self.git = Git(self.repo_dir, self.env)
        self.gh = Gh(self.repo_dir, self.env)
        self.clock: Callable[[], float] = time.time
        # Observer for the committed merge boundaries (MERGE_BOUNDARIES); the drills park here.
        self.on_boundary: Callable[[str, dict[str, Any]], None] | None = None

    # --- identity, config, receipts -------------------------------------------------------
    def _url_base(self) -> Path:
        """Where git resolves a relative remote URL for this clone: its worktree toplevel, or the
        git dir of a bare repository. Never this process's working directory (PR #647)."""
        if getattr(self, "_url_base_cached", None) is None:
            top = self.git.run("rev-parse", "--show-toplevel", check=False)
            if top.returncode == 0 and top.stdout.strip():
                self._url_base_cached = Path(top.stdout.strip())
            else:
                gitdir = self.git.run("rev-parse", "--absolute-git-dir", check=False)
                self._url_base_cached = Path(gitdir.stdout.strip()) if gitdir.returncode == 0 and gitdir.stdout.strip() \
                    else self.repo_dir
        return self._url_base_cached

    def github_hosts(self) -> frozenset[str]:
        with self.store.connect() as conn:
            return self.store.hosts(conn)

    def normalize(self, value: str) -> str:
        """Any spelling of a repository a caller or a payload gives, as the queue stores it (PR #647).

        A URL (`scheme://`, scp `[user@]host:path`) or a local path (absolute or `~`) is read by
        git's rules (`_identity`); anything else is an identity (`host/owner/name`) and is only
        respelled. Every repository that enters from outside goes through here before it is
        compared, looked up or hashed into a lock.
        """
        v = value.strip()
        colon, slash = v.find(":"), v.find("/")
        scp = "://" not in v and 0 < colon and (slash == -1 or colon < slash)
        if "://" in v or scp or v.startswith(("/", "~")):
            return self._identity(v)
        return normalize_identity(v, self.github_hosts())

    def _identity(self, url: str, extra_github_host: str | None = None) -> str:
        """`repo_identity` of a URL configured in this clone, resolved exactly as git resolves it,
        in the one spelling the queue stores (`normalize_identity`)."""
        hosts = self.github_hosts() | ({extra_github_host} if extra_github_host else set())
        return repo_identity(url, self._url_base(), home=self.env.get("HOME"), github_hosts=hosts)

    def default_repo(self, remote: str = "origin") -> str:
        urls, _push = self.git.remote_urls(remote)
        if not urls:
            raise QueueError("usage", f"no --repo given and remote {remote!r} has no URL in {self.repo_dir}",
                             exit_code=EXIT_USAGE)
        return self._identity(urls[0])

    def _bound_remote(self, cfg: dict[str, Any], extra_github_host: str | None = None) -> str:
        """The queue's remote, after proving it still names the queue's repository (PR #647).

        The lease, the entries and every receipt name `cfg["repo"]`. A remote re-pointed after
        `init`, or a push URL aimed elsewhere, would read one repository and write another, so
        every URL the remote is configured with (fetch and push, as written) must name it.
        Called before every remote read and write; a mismatch refuses before anything is sent.
        """
        remote = cfg["remote"]
        urls, push = self.git.remote_urls(remote)
        named = {f"url {u}": self._identity(u, extra_github_host) for u in urls}
        named.update({f"pushurl {u}": self._identity(u, extra_github_host) for u in push})
        wrong = {k: v for k, v in named.items() if v != cfg["repo"]}
        if not urls or wrong:
            raise QueueError(
                "repo_mismatch",
                f"remote {remote!r} does not name the queue's repository {cfg['repo']} "
                f"({', '.join(f'{k} -> {v}' for k, v in wrong.items()) or 'no URL'}); nothing was read or sent",
                {"remote": remote, "queue": cfg["repo"], "named": named},
            )
        return remote

    def _split_check(self, conn: sqlite3.Connection, repo: str, base: str) -> None:
        """Refuse a store that holds this repository as two queues for one BASE (PR #647).

        Two STORED spellings that normalize alike are a split. The caller's own spelling never
        counts as one: a query in another spelling of a single stored queue is not a split.
        """
        hosts = self.store.hosts(conn)
        mine = normalize_identity(repo, hosts)
        stored = sorted({r["repo"] for r in conn.execute("SELECT repo FROM mq_queues WHERE base = ?", (base,))
                         if normalize_identity(r["repo"], hosts) == mine})
        if len(stored) > 1:
            raise QueueError("queue_split", f"the store holds {mine} as more than one queue for BASE {base!r} "
                             f"({', '.join(stored)}); one remote must be one queue: settle and merge them by hand",
                             {"spellings": stored}, exit_code=EXIT_USAGE)

    def _config(self, conn: sqlite3.Connection, repo: str, base: str) -> dict[str, Any]:
        self._split_check(conn, repo, base)
        row = conn.execute("SELECT * FROM mq_queues WHERE repo = ? AND base = ?", (repo, base)).fetchone()
        if row is None:
            raise QueueError("queue_not_found", f"no merge queue for {repo} BASE {base!r}: run init first",
                             exit_code=EXIT_USAGE)
        return dict(row)

    def _receipt(self, conn: sqlite3.Connection, repo: str, base: str, kind: str, body: dict[str, Any],
                 entry_id: str | None = None, lease: dict[str, Any] | None = None) -> None:
        conn.execute(
            "INSERT INTO mq_receipts(repo, base, entry_id, kind, epoch, holder, body_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (repo, base, entry_id, kind, lease["epoch"] if lease else None, lease["holder"] if lease else None,
             json.dumps(body, sort_keys=True, default=str), self.clock()),
        )

    def _lock(self, repo: str, base: str) -> EffectLock:
        """The effect lock of a queue, keyed on its NORMALIZED identity: one lock per repository,
        whatever spelling a caller holds (PR #647)."""
        return EffectLock(lock_file(self.store.lock_dir, self.normalize(repo), base))

    def _boundary(self, stage: str, info: dict[str, Any]) -> None:
        if self.on_boundary is not None:
            self.on_boundary(stage, dict(info))

    @staticmethod
    def _check_branch(name: str, flag: str) -> str:
        if not isinstance(name, str) or not BRANCH_RE.fullmatch(name):
            raise QueueError("usage", f"{flag} {name!r} is not a plain branch name", exit_code=EXIT_USAGE)
        return name

    def init(self, *, repo: str, base: str, default: str, consent: str, mode: str = "gh",
             remote: str = "origin", host: str | None = None) -> dict[str, Any]:
        self._check_branch(base, "--base")
        self._check_branch(default, "--default")
        if base == default:
            raise QueueError("promotion_is_human", f"BASE {base!r} is the default branch: promotion to it is a "
                             "one-way human gate, and this queue never merges to it", exit_code=EXIT_USAGE)
        if mode not in MODES:
            raise QueueError("usage", f"--mode must be one of {MODES}", exit_code=EXIT_USAGE)
        if not consent or not consent.strip():
            raise QueueError("usage", "--consent names the standing grant every merge's egress receipt cites",
                             exit_code=EXIT_USAGE)
        urls, _push = self.git.remote_urls(remote)
        # The gh lane's host IS a GitHub host (GitHub Enterprise included): its names fold case.
        gh_host = identity_host(self._identity(urls[0])) if mode == "gh" and urls else None
        named = self._identity(urls[0], gh_host) if urls else None
        repo = normalize_identity(self.normalize(repo), self.github_hosts() | ({gh_host} if gh_host else set()))
        if named != repo:
            raise QueueError("repo_mismatch", f"--repo {repo} is not the repository remote {remote!r} names "
                             f"({named or 'no URL'}): the lease and every merge must name one repository",
                             {"repo": repo, "remote": remote, "named": named}, exit_code=EXIT_USAGE)
        if mode == "gh" and not GH_REPO_RE.fullmatch(repo):
            raise QueueError("repo_mismatch", f"the gh lane merges through GitHub, but remote {remote!r} names "
                             f"{repo}, not a host/owner/name repository (use --mode git for a local remote)",
                             {"repo": repo, "remote": remote}, exit_code=EXIT_USAGE)
        try:
            self._bound_remote({"remote": remote, "repo": repo}, gh_host)
        except QueueError as exc:
            raise QueueError(exc.code, exc.message, exc.data, exit_code=EXIT_USAGE) from exc
        if host is None:
            host = identity_host(repo)
        want = {"default_branch": default, "mode": mode, "remote": remote, "host": host, "consent": consent}
        with self.store.tx() as conn:
            self._split_check(conn, repo, base)
            row = conn.execute("SELECT * FROM mq_queues WHERE repo = ? AND base = ?", (repo, base)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO mq_queues(repo, base, default_branch, mode, remote, host, consent, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (repo, base, default, mode, remote, host, consent, self.clock()),
                )
                self._receipt(conn, repo, base, "queue_opened",
                              {**want, "promotion": f"{base}->{default} is human-only; never merged here"})
                created = True
            else:
                have = {k: row[k] for k in want}
                if have != want:
                    raise QueueError("queue_config_mismatch", f"queue {repo} {base!r} exists with other settings",
                                     {"have": have, "want": want}, exit_code=EXIT_USAGE)
                created = False
        return {"ok": True, "repo": repo, "base": base, "created": created, **want}

    # --- the lease and its fencing token ---------------------------------------------------
    def _fence(self, conn: sqlite3.Connection, token: str) -> dict[str, Any]:
        """Inside an open write transaction: refuse a token that is not the current owner's.

        This is the fencing check every queue mutation runs. A conductor whose lease was taken
        over or re-acquired (a new epoch), or released, is refused here, and the whole
        transaction rolls back with it. A live owner's lease is renewed by the same write.
        """
        tok = conn.execute("SELECT * FROM mq_tokens WHERE token = ?", (token,)).fetchone()
        if tok is None:
            raise QueueError("unknown_token", "this token was never issued by this store", exit_code=EXIT_FENCED)
        lease = conn.execute("SELECT * FROM mq_leases WHERE repo = ? AND base = ?", (tok["repo"], tok["base"])).fetchone()
        if lease is None or lease["token"] != token or lease["released_at"] is not None:
            raise QueueError(
                "fenced",
                f"epoch {tok['epoch']} ({tok['holder']}) no longer owns {tok['base']!r}: "
                f"{'released' if lease is not None and lease['token'] == token else 'superseded'}; this conductor "
                "stops and leaves the queue to the current owner",
                {"epoch": tok["epoch"], "currentEpoch": lease["epoch"] if lease else None,
                 "currentHolder": lease["holder"] if lease else None},
                exit_code=EXIT_FENCED,
            )
        conn.execute("UPDATE mq_leases SET expires_at = ? WHERE repo = ? AND base = ?",
                     (self.clock() + lease["ttl"], lease["repo"], lease["base"]))
        return dict(lease)

    def _owner(self, token: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """(queue config, lease) for a token that is still the owner's; a fenced read."""
        with self.store.tx() as conn:
            lease = self._fence(conn, token)
            return self._config(conn, lease["repo"], lease["base"]), lease

    def acquire(self, *, repo: str, base: str, holder: str, ttl: float = DEFAULT_TTL,
                takeover: bool = False, wait: float = 0.0) -> dict[str, Any]:
        """Become the conductor: reconcile every in-flight merge, THEN bump the epoch.

        A live lease held by another holder is refused unless `takeover`. The same holder
        re-acquiring is a restart and also bumps the epoch, which fences any older process
        still using the old token. The handoff holds the effect lock throughout, so no merge
        can be sent while it decides, and one still being sent blocks it.
        """
        repo = self.normalize(repo)  # any spelling a caller holds is the one stored queue (PR #647)
        if not holder or not holder.strip():
            raise QueueError("usage", "--holder names the conductor (its terminal handle)", exit_code=EXIT_USAGE)
        if ttl <= 0:
            raise QueueError("usage", "--ttl must be positive", exit_code=EXIT_USAGE)
        with self.store.connect() as conn:
            cfg = self._config(conn, repo, base)
        lock = self._lock(repo, base)
        try:
            if not lock.acquire(wait):
                flying = self.store.read("SELECT entry_id, unit, merging_pid, merging_epoch FROM mq_entries "
                                         "WHERE repo = ? AND base = ? AND state = ?", (repo, base, MERGING))
                raise QueueError(
                    "merge_in_flight",
                    "a conductor is inside the merge boundary; ownership is handed off only after its remote "
                    "merge settles (retry with --wait, or inspect the process holding it)",
                    {"inFlight": flying, "lock": str(lock.path)},
                )
            now = self.clock()
            with self.store.connect() as conn:
                prev = conn.execute("SELECT * FROM mq_leases WHERE repo = ? AND base = ?", (repo, base)).fetchone()
            prev = dict(prev) if prev else None
            live = bool(prev and prev["released_at"] is None and prev["expires_at"] > now)
            if live and prev["holder"] != holder and not takeover:
                raise QueueError(
                    "lease_held",
                    f"{prev['holder']} holds the lease on {base!r} (epoch {prev['epoch']}) until it expires; "
                    "--takeover fences that conductor",
                    {"holder": prev["holder"], "epoch": prev["epoch"], "expiresAt": prev["expires_at"]},
                    exit_code=EXIT_FENCED,
                )
            # Reconcile BEFORE handing off (#599): an in-flight merge is settled from authoritative
            # state, never inherited as a guess. Undecidable means no handoff.
            decisions = [self._reconcile_decision(cfg, e) for e in self._entries(repo, base, (MERGING,))]
            unknown = [d for d in decisions if d["resolution"] == "unknown"]
            if unknown:
                raise QueueError(
                    "in_flight_unknown",
                    "an in-flight merge cannot be reconciled (the remote is unreachable); ownership is not "
                    "handed off until it can be",
                    {"unknown": unknown},
                )
            token = uuid.uuid4().hex
            with self.store.tx() as conn:
                again = conn.execute("SELECT epoch FROM mq_leases WHERE repo = ? AND base = ?", (repo, base)).fetchone()
                if (again["epoch"] if again else 0) != (prev["epoch"] if prev else 0):
                    raise QueueError("lease_raced", "the lease changed during the handoff; retry", exit_code=EXIT_FENCED)
                epoch = (prev["epoch"] if prev else 0) + 1
                lease = {"repo": repo, "base": base, "holder": holder, "token": token, "epoch": epoch}
                for d in decisions:
                    self._apply_reconcile(conn, cfg, d, lease)
                conn.execute(
                    "INSERT INTO mq_leases(repo, base, holder, token, epoch, pid, host, ttl, acquired_at, expires_at, "
                    "released_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL) ON CONFLICT(repo, base) DO UPDATE SET "
                    "holder = excluded.holder, token = excluded.token, epoch = excluded.epoch, pid = excluded.pid, "
                    "host = excluded.host, ttl = excluded.ttl, acquired_at = excluded.acquired_at, "
                    "expires_at = excluded.expires_at, released_at = NULL",
                    (repo, base, holder, token, epoch, os.getpid(), socket.gethostname(), ttl, now, now + ttl),
                )
                conn.execute("INSERT INTO mq_tokens(token, repo, base, epoch, holder, issued_at) VALUES (?, ?, ?, ?, ?, ?)",
                             (token, repo, base, epoch, holder, now))
                previous = ({"holder": prev["holder"], "epoch": prev["epoch"], "live": live} if prev else None)
                self._receipt(conn, repo, base, "lease_acquired",
                              {"previous": previous, "takeover": bool(takeover and live), "reconciled": decisions},
                              lease=lease)
        finally:
            lock.release()
        return {"ok": True, "token": token, "epoch": epoch, "holder": holder, "repo": repo, "base": base,
                "previous": previous, "reconciled": decisions}

    def release(self, token: str) -> dict[str, Any]:
        with self.store.tx() as conn:
            lease = self._fence(conn, token)
            flying = conn.execute("SELECT entry_id FROM mq_entries WHERE repo = ? AND base = ? AND state = ?",
                                  (lease["repo"], lease["base"], MERGING)).fetchall()
            if flying:
                raise QueueError("merge_in_flight", "an in-flight merge must settle before the lease is released",
                                 {"inFlight": [r["entry_id"] for r in flying]})
            conn.execute("UPDATE mq_leases SET released_at = ? WHERE repo = ? AND base = ?",
                         (self.clock(), lease["repo"], lease["base"]))
            self._receipt(conn, lease["repo"], lease["base"], "lease_released", {}, lease=lease)
        return {"ok": True, "released": True, "epoch": lease["epoch"]}

    # --- boarding ---------------------------------------------------------------------------
    @staticmethod
    def parse_payload(raw: str | dict[str, Any]) -> dict[str, Any]:
        """A `merge_ready` payload (merge-serialization.md "Signal"), validated before any write."""
        try:
            p = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except ValueError as exc:
            raise QueueError("invalid_payload", f"--payload is not JSON: {exc}", exit_code=EXIT_USAGE) from exc
        if not isinstance(p, dict):
            raise QueueError("invalid_payload", "--payload must be a JSON object", exit_code=EXIT_USAGE)
        bad = []
        unit, branch, base = p.get("unit"), p.get("branch"), p.get("base")
        sha, tree, pr = p.get("reviewed_sha"), p.get("reviewed_wtree"), p.get("pr")
        if not isinstance(unit, str) or not unit.strip():
            bad.append("unit")
        if not isinstance(branch, str) or not BRANCH_RE.fullmatch(branch):
            bad.append("branch (a plain branch name)")
        if not isinstance(base, str) or not BRANCH_RE.fullmatch(base):
            bad.append("base (a plain branch name)")
        if not isinstance(sha, str) or not OBJECT_RE.fullmatch(sha):
            bad.append("reviewed_sha (a full commit id)")
        if tree is not None and not (isinstance(tree, str) and OBJECT_RE.fullmatch(tree)):
            bad.append("reviewed_wtree (a full tree id, or absent)")
        if pr is not None and not (type(pr) is int and pr > 0):
            bad.append("pr (a positive integer, or null on the no-gh lane)")
        if p.get("repo") is not None and not (isinstance(p["repo"], str) and p["repo"].strip()):
            bad.append("repo (the repository identity, or absent)")
        if bad:
            raise QueueError("invalid_payload", f"merge_ready payload: bad {', '.join(bad)}", exit_code=EXIT_USAGE)
        return {"unit": unit, "branch": branch, "base": base, "reviewed_sha": sha, "reviewed_tree": tree,
                "pr": pr, "run": p.get("run"), "repo": p.get("repo")}

    def enqueue(self, token: str, payload: str | dict[str, Any], *, run: str | None = None,
                delivery: str | None = None) -> dict[str, Any]:
        """Board one `merge_ready` at the back of the train; a duplicate delivery is a no-op."""
        p = self.parse_payload(payload)
        run_id = run or p["run"] or "default"
        if self.git.has_commit(p["reviewed_sha"]) and p["reviewed_tree"]:
            # The payload's tree is checked whenever the reviewed commit is at hand (verify.py's rule:
            # both trees are recomputed, so a forged reviewed_wtree cannot buy equivalence).
            if self.git.tree(p["reviewed_sha"]) != p["reviewed_tree"]:
                raise QueueError("reviewed_tree_mismatch", "reviewed_wtree is not the tree of reviewed_sha",
                                 exit_code=EXIT_USAGE)
        key = _digest("merge_ready", run_id, p["unit"], p["reviewed_sha"])
        fingerprint = _digest(p["pr"], p["branch"], p["reviewed_tree"], p["base"])
        now = self.clock()
        with self.store.tx() as conn:
            lease = self._fence(conn, token)
            repo, base = lease["repo"], lease["base"]
            cfg = self._config(conn, repo, base)
            if p["base"] == cfg["default_branch"]:
                raise QueueError("promotion_is_human", f"payload targets the default branch {p['base']!r}: "
                                 "promotion is a one-way human gate", exit_code=EXIT_USAGE)
            if p["base"] != base:
                raise QueueError("wrong_base", f"payload targets {p['base']!r}, this queue is {base!r}",
                                 exit_code=EXIT_USAGE)
            if p["repo"] is not None and self.normalize(p["repo"]) != repo:
                # An optional field, checked when a sender states it (PR #647): a PR number means
                # nothing outside its repository.
                raise QueueError("repo_mismatch", f"payload names repository {p['repo']}, this queue is {repo}",
                                 exit_code=EXIT_USAGE)
            if cfg["mode"] == "gh" and p["pr"] is None:
                raise QueueError("invalid_payload", "the gh lane needs a PR number (null is the no-gh lane)",
                                 exit_code=EXIT_USAGE)
            row = conn.execute("SELECT * FROM mq_entries WHERE repo = ? AND base = ? AND delivery_key = ?",
                               (repo, base, key)).fetchone()
            if row is not None:
                if row["payload_fp"] != fingerprint:
                    raise QueueError("payload_mismatch", f"unit {p['unit']!r} at {p['reviewed_sha'][:12]} is already "
                                     "boarded with a different PR, branch or tree", {"entry": row["entry_id"]},
                                     exit_code=EXIT_USAGE)
                seen = json.loads(row["deliveries_json"])
                if delivery and delivery not in seen:
                    seen.append(delivery)
                    conn.execute("UPDATE mq_entries SET deliveries_json = ? WHERE entry_id = ?",
                                 (json.dumps(seen), row["entry_id"]))
                self._receipt(conn, repo, base, "duplicate_delivery", {"delivery": delivery}, row["entry_id"], lease)
                return {"ok": True, "duplicate": True, "entry": self._entry_view(dict(row))}
            superseded = []
            for other in conn.execute("SELECT * FROM mq_entries WHERE repo = ? AND base = ? AND run_id = ? AND unit = ? "
                                      "AND state IN (?, ?, ?, ?, ?)",
                                      (repo, base, run_id, p["unit"], *LINE_STATES, LANDED)).fetchall():
                if other["state"] == QUEUED:
                    conn.execute("UPDATE mq_entries SET state = ?, reason = ?, updated_at = ? WHERE entry_id = ?",
                                 (SUPERSEDED, f"re-boarded at {p['reviewed_sha']}", now, other["entry_id"]))
                    superseded.append(other["entry_id"])
                    continue
                code = {MERGING: "unit_in_flight", MERGED: "ack_owed", FAILED: "unit_frozen",
                        LANDED: "unit_already_landed"}[other["state"]]
                raise QueueError(code, f"unit {p['unit']!r} already has entry {other['entry_id']} in state "
                                 f"{other['state']!r}; settle it before boarding a new reviewed SHA",
                                 {"entry": other["entry_id"]}, exit_code=EXIT_USAGE if other["state"] == LANDED else EXIT_BLOCKED)
            seq = cfg["next_seq"]
            conn.execute("UPDATE mq_queues SET next_seq = next_seq + 1 WHERE repo = ? AND base = ?", (repo, base))
            entry_id = f"mq_{uuid.uuid4().hex[:12]}"
            conn.execute(
                "INSERT INTO mq_entries(entry_id, repo, base, seq, run_id, unit, pr, branch, reviewed_sha, reviewed_tree, "
                "delivery_key, payload_fp, deliveries_json, state, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (entry_id, repo, base, seq, run_id, p["unit"], p["pr"], p["branch"], p["reviewed_sha"], p["reviewed_tree"],
                 key, fingerprint, json.dumps([delivery] if delivery else []), QUEUED, now, now),
            )
            for old in superseded:
                self._receipt(conn, repo, base, "superseded", {"by": entry_id}, old, lease)
            self._receipt(conn, repo, base, "boarded", {"seq": seq, "run": run_id, "unit": p["unit"], "pr": p["pr"],
                                                        "branch": p["branch"], "reviewedSha": p["reviewed_sha"],
                                                        "reviewedTree": p["reviewed_tree"], "base": base,
                                                        "delivery": delivery}, entry_id, lease)
            row = conn.execute("SELECT * FROM mq_entries WHERE entry_id = ?", (entry_id,)).fetchone()
        if not self.git.has_commit(p["reviewed_sha"]):
            # Fetched while the branch still carries it (boarding is when it does): a later
            # content-identical move keeps its tree recomputable, so plan never has to take the
            # payload's word for what was reviewed (2026-10-26 review). Best effort: offline here
            # is not a refusal, and plan fetches again before it bounces.
            with contextlib.suppress(QueueError):
                self.git.fetch(self._cfg_remote({"repo": repo, "base": base}), p["reviewed_sha"],
                               f"entry/{entry_id}/reviewed")
        return {"ok": True, "duplicate": False, "superseded": superseded, "entry": self._entry_view(dict(row))}

    # --- authoritative remote state ----------------------------------------------------------
    def _base_head(self, cfg: dict[str, Any]) -> str:
        head = self.git.fetch(self._bound_remote(cfg), f"refs/heads/{cfg['base']}", f"base/{cfg['base']}")
        if head is None:
            raise QueueError("base_missing", f"BASE {cfg['base']!r} does not exist on {cfg['remote']!r}")
        return head

    def _unit_state(self, cfg: dict[str, Any], e: dict[str, Any]) -> dict[str, Any]:
        """The unit's head and PR facts, read from GitHub (gh) or the remote branch (git)."""
        remote = self._bound_remote(cfg)
        if cfg["mode"] == "gh":
            view = self.gh.pr_view(cfg["repo"], e["pr"])
            reported = self._identity(str(view.get("url") or "").split("/pull/", 1)[0]) if view.get("url") else None
            if reported != cfg["repo"]:
                raise QueueError("repo_mismatch", f"GitHub reported PR #{e['pr']} in {reported or 'no repository'}, "
                                 f"not the queue's {cfg['repo']}; nothing was sent",
                                 {"queue": cfg["repo"], "reported": reported, "pr": e["pr"]})
            head = view["headRefOid"]
            if not self.git.has_commit(head):
                got = self.git.fetch(remote, f"refs/pull/{e['pr']}/head", f"pr/{e['pr']}")
                if got != head and view.get("headRefName"):
                    self.git.fetch(remote, f"refs/heads/{view['headRefName']}", f"pr/{e['pr']}")
            merge = view.get("mergeCommit") or {}
            # Where the head branch lives, as GitHub reports it: a cross-repository PR's head is in
            # a fork, and a same-named branch in the queue's repository is someone else's (PR #647).
            owner = (view.get("headRepositoryOwner") or {}).get("login")
            name = (view.get("headRepository") or {}).get("name")
            head_repo = f"{cfg['repo'].split('/', 1)[0]}/{owner}/{name}" if owner and name else None
            return {"head": head if self.git.has_commit(head) else None, "reported": head,
                    "state": str(view.get("state", "")).upper(), "baseRefName": view.get("baseRefName"),
                    "headRefName": view.get("headRefName"), "headRepository": head_repo,
                    "crossRepository": bool(view.get("isCrossRepository")),
                    "mergeCommit": merge.get("oid") if isinstance(merge, dict) else None}
        head = self.git.fetch(remote, f"refs/heads/{e['branch']}", f"branch/{e['branch']}")
        return {"head": head, "reported": head, "state": "OPEN" if head else "MISSING",
                "baseRefName": cfg["base"], "mergeCommit": None}

    def _reviewed_tree(self, e: dict[str, Any]) -> tuple[str | None, str]:
        """The reviewed content's tree: recomputed when the reviewed commit is at hand, else the payload's."""
        if not self.git.has_commit(e["reviewed_sha"]):
            remote = self._cfg_remote(e)  # a repository mismatch refuses; only the fetch is best-effort
            with contextlib.suppress(QueueError):
                self.git.fetch(remote, e["reviewed_sha"], f"entry/{e['entry_id']}/reviewed")
        if self.git.has_commit(e["reviewed_sha"]):
            return self.git.tree(e["reviewed_sha"]), "recomputed"
        return e["reviewed_tree"], "payload"

    def _cfg_remote(self, e: dict[str, Any]) -> str:
        rows = self.store.read("SELECT * FROM mq_queues WHERE repo = ? AND base = ?", (e["repo"], e["base"]))
        if not rows:
            raise QueueError("queue_not_found", f"no merge queue for {e['repo']} BASE {e['base']!r}")
        return self._bound_remote(rows[0])

    def _fresh_head(self, e: dict[str, Any], head: str) -> tuple[str | None, str | None]:
        """reviewed-sha-freshness.md: (accepted head, how) or (None, why it returns to review).

        The review binds `reviewed_sha`. Exactly one equivalence class keeps it: a head whose tree
        IS the reviewed tree (a content-identical rebase or amend). Any content change voids it.
        """
        if head == e["reviewed_sha"]:
            return head, "reviewed_sha"
        reviewed_tree, source = self._reviewed_tree(e)
        if source != "recomputed":
            # The reviewed commit is nowhere this queue can see, so the payload's tree is the only
            # witness to what was reviewed — and the payload is the enqueuer's. A head that merely
            # matches it is not proven reviewed: a fabricated reviewed_sha beside the unreviewed
            # head's tree rode as content_equivalent (2026-10-26 review). Back to review.
            return None, "reviewed_sha_unavailable"
        if reviewed_tree and self.git.tree(head) == reviewed_tree:
            return head, "content_equivalent"
        return None, "content_changed"

    def _bounce_reason(self, cfg: dict[str, Any], e: dict[str, Any], st: dict[str, Any]) -> str | None:
        """Why this unit cannot ride the train as reviewed (None when it can)."""
        if st["state"] == "MISSING":
            return "branch_missing"
        if st["state"] == "CLOSED":
            return "closed_unmerged"
        if st["baseRefName"] != cfg["base"] or st["baseRefName"] == cfg["default_branch"]:
            return "wrong_base"
        if st.get("headRefName") is not None and st["headRefName"] != e["branch"]:
            return "pr_branch_mismatch"  # the PR number names another unit's PR
        if st["head"] is None:
            return "head_unavailable"
        return None

    # --- the train: plan, merge, reconcile, ack, resolve ---------------------------------------
    def _entries(self, repo: str, base: str, states: tuple[str, ...]) -> list[dict[str, Any]]:
        marks = ",".join("?" for _ in states)
        return self.store.read(f"SELECT * FROM mq_entries WHERE repo = ? AND base = ? AND state IN ({marks}) "
                               "ORDER BY seq ASC", (repo, base, *states))

    def _line(self, repo: str, base: str) -> list[dict[str, Any]]:
        return self._entries(repo, base, LINE_STATES)

    @staticmethod
    def _clear_tested(conn: sqlite3.Connection, repo: str, base: str, after_seq: int = 0) -> None:
        """A prefix changed: every queued entry behind it must be planned (tested) again."""
        conn.execute("UPDATE mq_entries SET tested_base_tree = NULL, tested_tree = NULL, prefix_commit = NULL, "
                     "gate_json = NULL WHERE repo = ? AND base = ? AND state = ? AND seq > ?",
                     (repo, base, QUEUED, after_seq))

    def _guard_head(self, line: list[dict[str, Any]], entry_id: str | None = None) -> dict[str, Any] | None:
        if not line:
            return None
        head = line[0]
        if head["state"] == FAILED:
            raise QueueError("queue_frozen", f"the train is frozen behind failed entry {head['entry_id']} "
                             f"({head['reason']}): resolve it (requeue, bounce or drop) first",
                             {"entry": head["entry_id"], "unit": head["unit"], "reason": head["reason"]})
        if head["state"] == MERGED:
            raise QueueError("ack_owed", f"entry {head['entry_id']} merged at {head['merge_sha']} and is not "
                             "acknowledged yet: ack it before the next merge", {"entry": head["entry_id"]})
        if entry_id and entry_id != head["entry_id"]:
            raise QueueError("not_head", f"{entry_id} is not the head of the train ({head['entry_id']} is): "
                             "arrival order only", {"head": head["entry_id"]}, exit_code=EXIT_USAGE)
        return head

    def settle_in_flight(self, token: str) -> list[dict[str, Any]]:
        """The owner's own reconcile: settle a `merging` entry an earlier attempt left behind."""
        cfg, _lease = self._owner(token)
        settled: list[dict[str, Any]] = []
        if self._entries(cfg["repo"], cfg["base"], (MERGING,)):
            lock = self._lock(cfg["repo"], cfg["base"])
            try:
                if not lock.acquire(30.0):
                    raise QueueError("merge_in_flight", "another process holds the merge boundary")
                settled = self._settle_locked(token, cfg)
            finally:
                lock.release()
        self.retry_teardowns(token, cfg)
        return settled

    def retry_teardowns(self, token: str, cfg: dict[str, Any], entry_id: str | None = None) -> list[dict[str, Any]]:
        """Finish every branch teardown still owed by a merged entry, inside the merge boundary (PR #647).

        The request was persisted with the merge intent, so a conductor that died after the remote
        merge, or before its acknowledgement, leaves it for the next owner. Idempotent: the owed
        entries are read only once the lock is held (a list read before it goes stale while
        another command finishes the same deletion), and each deletion is claimed again in its
        own transaction before it is sent (`_claim_deletion`), so one owed deletion leaves at most
        once (PR #647).
        """
        q = ("SELECT * FROM mq_entries WHERE repo = ? AND base = ? AND state IN (?, ?) "
             "AND teardown IN ('delete', 'keep', 'deleting')")
        params: list[Any] = [cfg["repo"], cfg["base"], MERGED, LANDED]
        if entry_id:
            q += " AND entry_id = ?"
            params.append(entry_id)
        if not self.store.read(q + " LIMIT 1", tuple(params)):
            return []  # nothing owed: no need to wait for the boundary
        lock = self._lock(cfg["repo"], cfg["base"])
        try:
            if not lock.acquire(30.0):
                raise QueueError("merge_in_flight", "another process holds the merge boundary")
            owed = self.store.read(q + " ORDER BY seq ASC", tuple(params))  # re-read under the lock
            return [{"entry": e["entry_id"], "outcome": self._teardown_branch(token, cfg, e, lock)} for e in owed]
        finally:
            lock.release()

    def _settle_locked(self, token: str, cfg: dict[str, Any]) -> list[dict[str, Any]]:
        decisions = [self._reconcile_decision(cfg, e) for e in self._entries(cfg["repo"], cfg["base"], (MERGING,))]
        with self.store.tx() as conn:
            lease = self._fence(conn, token)
            for d in decisions:
                self._apply_reconcile(conn, cfg, d, lease)
        unknown = [d for d in decisions if d["resolution"] == "unknown"]
        if unknown:
            raise QueueError("merge_outcome_unknown", "an in-flight merge cannot be reconciled yet (remote "
                             "unreachable); nothing merges until it can", {"unknown": unknown})
        return decisions

    def _reconcile_decision(self, cfg: dict[str, Any], e: dict[str, Any]) -> dict[str, Any]:
        """Decide an in-flight merge from authoritative state alone. Writes nothing."""
        out: dict[str, Any] = {"entry": e["entry_id"], "unit": e["unit"], "acceptedHead": e["accepted_head"],
                               "expectedBase": e["expected_base"]}
        try:
            # Both lanes adopt a merge only by ancestry on the queue's BASE: the accepted head is in
            # BASE, and the adopted merge commit is on BASE's first-parent chain. A PR state alone
            # never adopts one: GitHub may report MERGED for a merge into another branch (PR #647).
            base_head = self._base_head(cfg)
            head = e["accepted_head"]
            if head and self.git.has_commit(head) and self.git.is_ancestor(head, base_head):
                merge_sha = self._find_merge(e, base_head)
                return {**out, **self._merged_facts(e, merge_sha), "resolution": "merged"}
            if cfg["mode"] == "gh":
                st = self._unit_state(cfg, e)
                if st["state"] == "MERGED":
                    return {**out, "resolution": "failed", "reason": "merged_not_on_base",
                            "mergeSha": st["mergeCommit"], "prBase": st["baseRefName"]}
                if st["state"] != "OPEN":
                    return {**out, "resolution": "failed", "reason": "closed_unmerged"}
            return {**out, "resolution": "requeued", "reason": "remote merge never landed"}
        except Offline as exc:
            return {**out, "resolution": "unknown", "reason": exc.message}

    def _find_merge(self, e: dict[str, Any], base_head: str) -> str:
        """The first-parent commit on BASE whose other parent is the merged head (git lane)."""
        span = f"{e['expected_base']}..{base_head}" if e["expected_base"] else base_head
        for line in self.git.out("rev-list", "--first-parent", "--parents", span).splitlines():
            shas = line.split()
            if e["accepted_head"] in shas[2:]:
                return shas[0]
        return base_head

    def _merged_facts(self, e: dict[str, Any], merge_sha: str) -> dict[str, Any]:
        parents = self.git.parents(merge_sha)
        tree = self.git.tree(merge_sha)
        exact = bool(parents[:1] == [e["expected_base"]] and tree == e["tested_tree"])
        return {"mergeSha": merge_sha, "mergedTree": tree, "parents": parents, "treeMatchesTested": exact}

    def _apply_reconcile(self, conn: sqlite3.Connection, cfg: dict[str, Any], d: dict[str, Any],
                         lease: dict[str, Any]) -> None:
        now = self.clock()
        if d["resolution"] == "merged":
            conn.execute("UPDATE mq_entries SET state = ?, merge_sha = ?, merged_tree = ?, tree_matches_tested = ?, "
                         "updated_at = ? WHERE entry_id = ? AND state = ?",
                         (MERGED, d["mergeSha"], d["mergedTree"], int(d["treeMatchesTested"]), now, d["entry"], MERGING))
        elif d["resolution"] == "requeued":
            conn.execute("UPDATE mq_entries SET state = ?, updated_at = ? WHERE entry_id = ? AND state = ?",
                         (QUEUED, now, d["entry"], MERGING))
        elif d["resolution"] == "failed":
            conn.execute("UPDATE mq_entries SET state = ?, reason = ?, updated_at = ? WHERE entry_id = ? AND state = ?",
                         (FAILED, d["reason"], now, d["entry"], MERGING))
        self._receipt(conn, cfg["repo"], cfg["base"], "reconciled", d, d["entry"], lease)

    def plan(self, token: str, *, gate_cmd: str | None = None, gate_timeout: float = 1800.0) -> dict[str, Any]:
        """Test the prefix: BASE + each queued entry in arrival order, as in-memory merges (#590).

        Each entry records the BASE tree it expects to merge onto, the merge tree it was tested
        as, and the head it accepted. With `--gate-cmd`, the command runs in a detached checkout
        of each prefix commit, and a failure FAILS that entry, which freezes the train behind it.
        """
        self.settle_in_flight(token)
        cfg, _lease = self._owner(token)
        repo, base = cfg["repo"], cfg["base"]
        line = self._line(repo, base)
        self._guard_head(line)
        base_head = self._base_head(cfg)
        prev = base_head
        decisions: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        for e in line:
            if e["state"] != QUEUED:
                break
            st = self._unit_state(cfg, e)
            if st["state"] == "MERGED":
                decisions.append(("fail", e, {"reason": "merged_outside_queue", "mergeCommit": st["mergeCommit"]}))
                break
            why = self._bounce_reason(cfg, e, st)
            accepted, how = (None, why) if why else self._fresh_head(e, st["head"])
            if accepted is None:
                decisions.append(("bounce", e, {"reason": how, "head": st["reported"], "reviewedSha": e["reviewed_sha"]}))
                continue
            pred = self._predict(e, prev, accepted)
            if not pred["clean"]:
                decisions.append(("fail", e, {"reason": "conflict", "conflicts": pred["conflicts"]}))
                break
            commit = self.git.commit_tree(pred["tree_oid"], [prev, accepted],
                                          f"merge-queue prefix: {e['unit']} onto {base}", env=PREFIX_IDENTITY,
                                          sign=False)
            self.git.keep(f"entry/{e['entry_id']}/prefix", commit)
            tested = {"acceptedHead": accepted, "how": how, "testedBaseTree": self.git.tree(prev),
                      "testedTree": pred["tree_oid"], "prefixCommit": commit, "gate": None}
            if gate_cmd:
                gate = self._run_gate(gate_cmd, commit, e, gate_timeout)
                tested["gate"] = gate
                if gate["exit"] != 0:
                    decisions.append(("fail", e, {"reason": "gate_failed", **tested}))
                    break
            decisions.append(("tested", e, tested))
            prev = commit
        now = self.clock()
        out = []
        with self.store.tx() as conn:
            lease = self._fence(conn, token)
            self._clear_tested(conn, repo, base)
            for kind, e, body in decisions:
                cur = conn.execute("SELECT state FROM mq_entries WHERE entry_id = ?", (e["entry_id"],)).fetchone()
                if cur["state"] != QUEUED:
                    raise QueueError("queue_changed", f"{e['entry_id']} changed state while planning; plan again")
                if kind == "tested":
                    conn.execute("UPDATE mq_entries SET accepted_head = ?, tested_base_tree = ?, tested_tree = ?, "
                                 "prefix_commit = ?, gate_json = ?, updated_at = ? WHERE entry_id = ?",
                                 (body["acceptedHead"], body["testedBaseTree"], body["testedTree"], body["prefixCommit"],
                                  json.dumps(body["gate"]), now, e["entry_id"]))
                    self._receipt(conn, repo, base, "tested", {"baseHead": base_head, **body}, e["entry_id"], lease)
                elif kind == "bounce":
                    conn.execute("UPDATE mq_entries SET state = ?, reason = ?, updated_at = ? WHERE entry_id = ?",
                                 (BOUNCED, body["reason"], now, e["entry_id"]))
                    self._receipt(conn, repo, base, "returned_to_review", body, e["entry_id"], lease)
                else:
                    conn.execute("UPDATE mq_entries SET state = ?, reason = ?, updated_at = ? WHERE entry_id = ?",
                                 (FAILED, body["reason"], now, e["entry_id"]))
                    self._receipt(conn, repo, base, "failed", {**body, "frozen": True}, e["entry_id"], lease)
                out.append({"entry": e["entry_id"], "unit": e["unit"], "result": kind, **body})
        return {"ok": True, "baseHead": base_head, "planned": out}

    def _predict(self, e: dict[str, Any], base: str, head: str) -> dict[str, Any]:
        """#590's in-memory merge (`git merge-tree --write-tree`): HEAD, index and worktree untouched."""
        try:
            return diff_scope.predict_merge(str(self.repo_dir), base, head)
        except diff_scope.ScopeError as exc:
            raise QueueError("predict_failed", f"could not predict the merge of {e['entry_id']}: {exc}") from exc

    # What a gate command sees (2026-10-26 review): the process-hygiene floor and the MQ_* facts,
    # never the conductor's credentials (GH_TOKEN, SSH_AUTH_SOCK, …) — the gate runs the UNIT's own
    # test code — plus whatever the operator lists in MQ_GATE_ENV_KEEP (comma-separated names, e.g.
    # a proxy setting the tests need). The same floor verify.py gives an executed control.
    GATE_ENV_KEEP = ("PATH", "LANG", "TERM", "SHELL")
    GATE_ENV_KEEP_PREFIX = ("LC_",)
    GATE_ENV_FORBID_PREFIX = (
        "GH_", "GITHUB_", "GIT_", "SSH_", "ORCA_", "OPEN_FLEET_", "MQ_", "AWS_",
        "ANTHROPIC_", "OPENAI_", "CLAUDE_",
    )
    GATE_ENV_FORBID_SUFFIX = ("_TOKEN", "_SECRET", "_KEY", "_PASSWORD", "_CREDENTIAL", "_CREDENTIALS")
    GATE_ENV_ISOLATED_KEYS = ("HOME", "TMPDIR", "TMP", "TEMP", "XDG_CONFIG_HOME", "GH_CONFIG_DIR")
    _SHELL_NAMES = frozenset({"sh", "bash", "dash", "zsh", "ksh", "ash", "csh", "tcsh"})
    _SHELL_BUILTINS = frozenset({
        "true", "false", "test", "[", "echo", "printf", "exit", "cd", "pwd",
        "export", "set", "unset", "shift", "return", "break", "continue", ":",
        "read", "umask", "wait", "trap", "local", "readonly",
        "getopts", "hash", "type", "ulimit", "times", "alias", "unalias",
    })
    _SHELL_KEYWORDS = frozenset({
        "if", "then", "else", "elif", "fi", "for", "select", "in", "while", "until",
        "do", "done", "case", "esac",
    })
    _SAFE_SHELL_O_OPTIONS = frozenset({
        "allexport", "braceexpand", "errexit", "errtrace", "functrace",
        "hashall", "histexpand", "monitor", "noclobber", "noexec",
        "noglob", "notify", "nounset", "physical", "pipefail", "posix",
        "verbose", "xtrace",
    })
    _MUX_WRAPPERS = frozenset({
        "busybox", "xargs", "stdbuf", "setsid", "flock", "chrt", "ionice",
        "taskset", "parallel", "watch", "time", "script", "su", "sudo",
        "chroot", "nsenter", "unshare", "bwrap", "strace", "ltrace",
    })
    _COMPOUND_PREFIX_KEYWORDS = frozenset({
        "!", "{", "}", "if", "then", "elif", "else", "while", "until", "do",
    })
    _COMPOUND_CLOSE_KEYWORDS = frozenset({"fi", "done"})
    _REDIR_OPS = (
        "&>>", "&>", "<<<", "<<-", ">>", ">&", "<>", "<<", "<&", ">|", ">", "<",
    )
    _LOOKUP_VARS = frozenset({
        "PATH", "IFS", "CDPATH", "ENV", "BASH_ENV",
        "SHELLOPTS", "BASHOPTS", "BASH_LOADABLES_PATH", "BASH_COMPAT",
        "POSIXLY_CORRECT", "ZDOTDIR", "FPATH", "GLOBIGNORE", "EXECIGNORE",
        "PROMPT_COMMAND", "PS0", "PS4",
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "GLIBC_TUNABLES",
        "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONSAFEPATH",
        "PYTHONPYCACHEPREFIX", "PYTHONWARNINGS", "PYTHONINSPECT",
        "PYTHONUSERBASE", "VIRTUAL_ENV",
        "NODE_OPTIONS", "NODE_PATH", "NODE_REPL_EXTERNAL_MODULE",
        "DENO_DIR", "BUN_INSTALL",
        "PERL5OPT", "PERL5LIB", "PERLLIB",
        "RUBYOPT", "RUBYLIB", "GEM_HOME", "GEM_PATH", "BUNDLE_GEMFILE",
        "AWKPATH", "AWKLIBPATH",
        "PHPRC", "PHP_INI_SCAN_DIR",
        "R_PROFILE", "R_PROFILE_USER", "R_ENVIRON", "R_ENVIRON_USER",
        "R_LIBS", "R_LIBS_USER", "R_LIBS_SITE",
    })
    _LOOKUP_PREFIXES = ("BASH_FUNC_", "LD_", "DYLD_", "LUA_")

    @classmethod
    def _touches_lookup_var(cls, raw_target: str) -> bool:
        """True if `raw_target` (plain, `+=`, or subscripted `NAME[idx]`) names a lookup variable,
        or uses an array subscript expression (which Bash evaluates as arithmetic)."""
        if "[" in raw_target or "]" in raw_target:
            return True
        base = re.split(r"[\+=]", raw_target, maxsplit=1)[0]
        if base.upper() in cls._LOOKUP_VARS or base.upper().startswith(cls._LOOKUP_PREFIXES):
            return True
        return any(
            ident.upper() in cls._LOOKUP_VARS or ident.upper().startswith(cls._LOOKUP_PREFIXES)
            for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", base)
        )

    @classmethod
    def _allowed_extra_keep(cls, name: str) -> bool:
        up = name.upper()
        if up in cls.GATE_ENV_ISOLATED_KEYS or up in cls._LOOKUP_VARS or up.startswith(cls._LOOKUP_PREFIXES):
            return False
        if up.startswith(cls.GATE_ENV_FORBID_PREFIX) or up.endswith(cls.GATE_ENV_FORBID_SUFFIX):
            return False
        return True

    def _clean_gate_path(self) -> str:
        raw = self.env.get("PATH") or "/usr/bin:/bin"
        return os.pathsep.join(
            os.path.normpath(p)
            for p in raw.split(os.pathsep)
            if p and os.path.isabs(p)
        )

    def _gate_env(self, e: dict[str, Any], commit: str, *, gate_home: Path | None = None,
                  gate_tmp: Path | None = None) -> dict[str, str]:
        extra = {
            k.strip()
            for k in (self.env.get("MQ_GATE_ENV_KEEP") or "").split(",")
            if k.strip() and self._allowed_extra_keep(k.strip())
        }
        keep = set(self.GATE_ENV_KEEP) | extra
        env = {k: v for k, v in self.env.items() if k in keep or k.startswith(self.GATE_ENV_KEEP_PREFIX)}
        env.setdefault("USER", "gate")
        env.setdefault("LOGNAME", "gate")
        env["PATH"] = self._clean_gate_path()
        if gate_home is not None:
            xdg = gate_home / ".config"
            gh_cfg = xdg / "gh"
            xdg.mkdir(mode=0o700, parents=True, exist_ok=True)
            gh_cfg.mkdir(mode=0o700, parents=True, exist_ok=True)
            env.update({
                "HOME": str(gate_home),
                "XDG_CONFIG_HOME": str(xdg),
                "GH_CONFIG_DIR": str(gh_cfg),
            })
        if gate_tmp is not None:
            env.update({
                "TMPDIR": str(gate_tmp),
                "TMP": str(gate_tmp),
                "TEMP": str(gate_tmp),
            })
        env.update({
            "MQ_ENTRY": e["entry_id"],
            "MQ_UNIT": e["unit"],
            "MQ_PREFIX_COMMIT": commit,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        })
        return env

    @staticmethod
    def _fold_line_continuations(cmd: str) -> str:
        """Remove POSIX `\\<newline>` line continuations outside single quotes and `#` comments."""
        out: list[str] = []
        i, n = 0, len(cmd)
        in_sq = False
        in_dq = False
        at_tok = True
        sub_stack: list[tuple[bool, bool, bool]] = []
        while i < n:
            ch = cmd[i]
            if in_sq:
                out.append(ch)
                if ch == "'":
                    in_sq = False
                i += 1
                at_tok = False
                continue
            if not in_dq and at_tok and ch == "#":
                while i < n and cmd[i] != "\n":
                    out.append(cmd[i])
                    i += 1
                continue
            if ch == "\\" and i + 1 < n:
                if cmd[i + 1] == "\n":
                    i += 2
                    continue
                out.append(cmd[i:i + 2])
                i += 2
                at_tok = False
                continue
            if ch == "$" and i + 1 < n and cmd[i + 1] == "(":
                sub_stack.append((True, in_sq, in_dq))
                in_sq = False
                in_dq = False
                at_tok = True
                out.append("$(")
                i += 2
                continue
            if sub_stack and not in_dq and ch == "(":
                sub_stack.append((False, False, False))
                at_tok = True
                out.append(ch)
                i += 1
                continue
            if sub_stack and not in_dq and ch == ")":
                is_cmdsub, prev_sq, prev_dq = sub_stack.pop()
                if is_cmdsub:
                    in_sq, in_dq = prev_sq, prev_dq
                    at_tok = False
                else:
                    at_tok = True
                out.append(ch)
                i += 1
                continue
            if ch == "'" and not in_dq:
                in_sq = True
                at_tok = False
            elif ch == '"':
                in_dq = not in_dq
                at_tok = False
            else:
                at_tok = (not in_dq) and (ch in " \t\n;|&()><")
            out.append(ch)
            i += 1
        return "".join(out)

    _ALLOWED_PARAM_OPS = (":-", "-", ":+", "+", ":=", "=", ":?", "?", "##", "#", "%%", "%")

    @classmethod
    def _consume_param_expansion(cls, cmd: str, start: int) -> tuple[int, list[str], list[str]]:
        """Parse `${...}` starting at `start` (`cmd[start:start+2] == "${"`), allowing only safe scalar
        POSIX forms and extracting inner command substitutions while failing closed on indirect,
        subscripted, transformation (`@P`), substring (`:offset`), or quote-ambiguous forms."""
        n = len(cmd)
        if start + 2 >= n:
            return -1, [], ["unterminated ${...} parameter expansion"]
        if cmd[start + 2] == "#":
            if start + 3 < n and cmd[start + 3] == "}":
                return start + 4, [], []
            m_len = re.match(r"^(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[?$*@-])", cmd[start + 3:])
            if not m_len:
                return -1, [], ["unsupported ${#...} parameter expansion cannot be statically fingerprinted"]
            end_len = start + 3 + len(m_len.group(0))
            if end_len >= n or cmd[end_len] != "}":
                return -1, [], ["subscripted or complex ${#...} parameter expansion cannot be statically fingerprinted"]
            return end_len + 1, [], []
        m_param = re.match(r"^(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[?$*@-])", cmd[start + 2:])
        if not m_param:
            return -1, [], ["unsupported ${...} parameter expansion cannot be statically fingerprinted"]
        param = m_param.group(0)
        k = start + 2 + len(param)
        if k >= n:
            return -1, [], ["unterminated ${...} parameter expansion"]
        if cmd[k] == "}":
            return k + 1, [], []
        op = next((cand for cand in cls._ALLOWED_PARAM_OPS if cmd.startswith(cand, k)), None)
        if op is None:
            return -1, [], ["unsupported ${...} parameter expansion operator cannot be statically fingerprinted"]
        if op in (":=", "="):
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", param) or cls._touches_lookup_var(param):
                return -1, [], [
                    f"parameter expansion assigning to {param!r} alters executable lookup context or is invalid"
                ]
        subs: list[str] = []
        problems: list[str] = []
        j = k + len(op)
        while j < n:
            ch = cmd[j]
            if ch == "}":
                return j + 1, subs, problems
            if ch in ("'", '"', "\\", "{", "(", ")"):
                return -1, subs, [
                    "quotes, escapes, or bare braces/parens inside ${...} parameter expansion cannot be portably fingerprinted"
                ]
            if ch == "$" and j + 1 < n and cmd[j + 1] in ("'", '"'):
                return -1, subs, ["ANSI-C or locale $'...' / $\"...\" quoting cannot be statically fingerprinted"]
            if ch == "$" and j + 1 < n and cmd[j + 1] == "{":
                nj, nsubs, nprobs = cls._consume_param_expansion(cmd, j)
                subs.extend(nsubs)
                problems.extend(nprobs)
                if nj < 0:
                    return -1, subs, problems
                j = nj
                continue
            if ch == "$" and j + 1 < n and cmd[j + 1] == "(":
                if j + 2 < n and cmd[j + 2] == "(":
                    ic, ip = cls._find_matching_paren(cmd, j + 3)
                    if ic < 0:
                        return -1, subs, problems + ip
                    if ic + 1 < n and cmd[ic + 1] == ")":
                        arith_body = cmd[j + 3:ic]
                        arith_san, arith_subs, arith_probs = cls._strip_cmd_substitutions(arith_body)
                        subs.extend(arith_subs)
                        problems.extend(arith_probs)
                        arith_check = arith_san.replace("__MQ_CMDSUB__", " 0 ")
                        if (
                            any(ch_a in arith_check for ch_a in ("$", "'", '"', "[", "]"))
                            or re.search(r"(?<![=!<>])=(?!=)", arith_check)
                            or re.search(r"(?<![0-9A-Za-z_#@])[A-Za-z_][A-Za-z0-9_]*", arith_check)
                        ):
                            return -1, subs, problems + [
                                "variable, indirect, or mutating expression inside arithmetic expansion cannot be statically fingerprinted"
                            ]
                        j = ic + 2
                        continue
                ec, ep = cls._find_matching_paren(cmd, j + 2)
                if ec < 0:
                    return -1, subs, problems + ep
                subs.append(cmd[j + 2:ec])
                j = ec + 1
                continue
            if ch == "`":
                bt = j + 1
                buf: list[str] = []
                while bt < n and cmd[bt] != "`":
                    if cmd[bt] == "\\" and bt + 1 < n and cmd[bt + 1] in ("\\", "`", "$", '"'):
                        buf.append(cmd[bt + 1])
                        bt += 2
                        continue
                    buf.append(cmd[bt])
                    bt += 1
                if bt >= n:
                    return -1, subs, problems + ["unterminated backtick command substitution"]
                subs.append("".join(buf))
                j = bt + 1
                continue
            j += 1
        return -1, subs, problems + ["unterminated ${...} parameter expansion"]

    @classmethod
    def _find_matching_paren(cls, cmd: str, start: int) -> tuple[int, list[str]]:
        """Find the index of `)` matching the `(` at `start - 1`, respecting shell quotes, comments, and nesting."""
        n = len(cmd)
        j = start
        at_tok = True
        while j < n:
            c = cmd[j]
            if c == "\\":
                j += 2
                at_tok = False
                continue
            if at_tok and c == "#":
                while j < n and cmd[j] != "\n":
                    j += 1
                continue
            if c == "$" and j + 1 < n and cmd[j + 1] in ("'", '"'):
                return -1, ["ANSI-C or locale $'...' / $\"...\" quoting cannot be statically fingerprinted"]
            if c == "'":
                j += 1
                while j < n and cmd[j] != "'":
                    j += 1
                if j >= n:
                    return -1, ["unterminated single quote in command substitution"]
                j += 1
                at_tok = False
                continue
            if c == '"':
                j += 1
                while j < n and cmd[j] != '"':
                    if cmd[j] == "\\":
                        j += 2
                        continue
                    if cmd[j] == "$" and j + 1 < n and cmd[j + 1] == "{":
                        nj, _ns, np = cls._consume_param_expansion(cmd, j)
                        if nj < 0:
                            return -1, np
                        j = nj
                        continue
                    if cmd[j] == "$" and j + 1 < n and cmd[j + 1] == "(":
                        ec, ep = cls._find_matching_paren(cmd, j + 2)
                        if ec < 0:
                            return -1, ep
                        j = ec + 1
                        continue
                    if cmd[j] == "`":
                        j += 1
                        while j < n and cmd[j] != "`":
                            j += 2 if (cmd[j] == "\\" and j + 1 < n and cmd[j + 1] in ("\\", "`", "$", '"')) else 1
                        if j >= n:
                            return -1, ["unterminated backtick command substitution"]
                        j += 1
                        continue
                    j += 1
                if j >= n:
                    return -1, ["unterminated double quote in command substitution"]
                j += 1
                at_tok = False
                continue
            if c == "`":
                j += 1
                while j < n and cmd[j] != "`":
                    j += 2 if (cmd[j] == "\\" and j + 1 < n and cmd[j + 1] in ("\\", "`", "$", '"')) else 1
                if j >= n:
                    return -1, ["unterminated backtick command substitution"]
                j += 1
                at_tok = False
                continue
            if c == "$" and j + 1 < n and cmd[j + 1] == "{":
                nj, _ns, np = cls._consume_param_expansion(cmd, j)
                if nj < 0:
                    return -1, np
                j = nj
                at_tok = False
                continue
            if c == "$" and j + 1 < n and cmd[j + 1] == "(":
                ec, ep = cls._find_matching_paren(cmd, j + 2)
                if ec < 0:
                    return -1, ep
                j = ec + 1
                at_tok = False
                continue
            if c == "(":
                ec, ep = cls._find_matching_paren(cmd, j + 1)
                if ec < 0:
                    return -1, ep
                j = ec + 1
                at_tok = True
                continue
            if c == ")":
                return j, []
            at_tok = c in " \t\n;|&()><"
            j += 1
        return -1, ["unterminated $(...) command substitution"]

    @classmethod
    def _strip_cmd_substitutions(cls, cmd: str) -> tuple[str, list[str], list[str]]:
        """Replace `$(...)`, `$((...))`, `<(...)`/`>(...)`, and backtick substitutions outside single
        quotes with a dynamic sentinel token while returning every inner command string for recursive
        fingerprinting."""
        cmd = cls._fold_line_continuations(cmd)
        out: list[str] = []
        subs: list[str] = []
        problems: list[str] = []
        i, n = 0, len(cmd)
        in_sq = False
        in_dq = False
        at_tok = True
        while i < n:
            ch = cmd[i]
            if in_sq:
                out.append(ch)
                if ch == "'":
                    in_sq = False
                i += 1
                at_tok = False
                continue
            if not in_dq and at_tok and ch == "#":
                while i < n and cmd[i] != "\n":
                    out.append(cmd[i])
                    i += 1
                continue
            if ch == "\\":
                out.append(cmd[i:i + 2])
                i += 2
                at_tok = False
                continue
            if not in_dq and ch == "$" and i + 1 < n and cmd[i + 1] in ("'", '"'):
                problems.append("ANSI-C or locale $'...' / $\"...\" quoting cannot be statically fingerprinted")
                break
            if ch == "'" and not in_dq:
                in_sq = True
                out.append(ch)
                i += 1
                at_tok = False
                continue
            if ch == '"':
                in_dq = not in_dq
                out.append(ch)
                i += 1
                at_tok = False
                continue
            if not in_dq and at_tok and ch == "(" and i + 1 < n and cmd[i + 1] == "(":
                ic_s, ip_s = cls._find_matching_paren(cmd, i + 2)
                if ic_s < 0:
                    problems.extend(ip_s)
                    break
                if ic_s + 1 < n and cmd[ic_s + 1] == ")":
                    problems.append(
                        "standalone ((...)) arithmetic command cannot be portably fingerprinted"
                    )
                    i = ic_s + 2
                    at_tok = False
                    continue
            if not in_dq and ch in ("<", ">") and i + 1 < n and cmd[i + 1] == "(":
                ec, ep = cls._find_matching_paren(cmd, i + 2)
                if ec < 0:
                    problems.extend(ep)
                    break
                subs.append(cmd[i + 2:ec])
                out.append("__MQ_CMDSUB__")
                i = ec + 1
                at_tok = False
                continue
            if ch == "$" and i + 1 < n and cmd[i + 1] == "{":
                nj, p_subs, p_probs = cls._consume_param_expansion(cmd, i)
                subs.extend(p_subs)
                problems.extend(p_probs)
                if nj < 0:
                    break
                out.append("__MQ_CMDSUB__")
                i = nj
                at_tok = False
                continue
            if ch == "$" and i + 1 < n and cmd[i + 1] == "(":
                if i + 2 < n and cmd[i + 2] == "(":
                    # Distinguish `$(( arith ))` from `$( (subshell); cmd )` by matching the second `(`.
                    ic, ip = cls._find_matching_paren(cmd, i + 3)
                    if ic < 0:
                        problems.extend(ip)
                        break
                    if ic + 1 < n and cmd[ic + 1] == ")":
                        arith_body = cmd[i + 3:ic]
                        arith_san, arith_subs, arith_probs = cls._strip_cmd_substitutions(arith_body)
                        subs.extend(arith_subs)
                        problems.extend(arith_probs)
                        arith_check = arith_san.replace("__MQ_CMDSUB__", " 0 ")
                        if (
                            any(ch_a in arith_check for ch_a in ("$", "'", '"', "[", "]"))
                            or re.search(r"(?<![=!<>])=(?!=)", arith_check)
                            or re.search(r"(?<![0-9A-Za-z_#@])[A-Za-z_][A-Za-z0-9_]*", arith_check)
                        ):
                            problems.append(
                                "variable, indirect, or mutating expression inside arithmetic expansion cannot be statically fingerprinted"
                            )
                        out.append("__MQ_CMDSUB__")
                        i = ic + 2
                        at_tok = False
                        continue
                ec, ep = cls._find_matching_paren(cmd, i + 2)
                if ec < 0:
                    problems.extend(ep)
                    break
                subs.append(cmd[i + 2:ec])
                out.append("__MQ_CMDSUB__")
                i = ec + 1
                at_tok = False
                continue
            if ch == "`":
                j = i + 1
                buf: list[str] = []
                while j < n and cmd[j] != "`":
                    if cmd[j] == "\\" and j + 1 < n and cmd[j + 1] in ("\\", "`", "$", '"'):
                        buf.append(cmd[j + 1])
                        j += 2
                        continue
                    buf.append(cmd[j])
                    j += 1
                if j >= n:
                    problems.append("unterminated backtick command substitution")
                    break
                subs.append("".join(buf))
                out.append("__MQ_CMDSUB__")
                i = j + 1
                at_tok = False
                continue
            at_tok = (not in_dq) and (ch in " \t\n;|&()><")
            out.append(ch)
            i += 1
        if in_sq or in_dq:
            problems.append("unterminated quote in gate command")
        return "".join(out), subs, problems

    @classmethod
    def _lex_gate_tokens(cls, cmd: str) -> tuple[list[tuple[str, str, Any]], list[str]]:
        """Return `[(kind, text, quote_or_dynamic_flag)]` where `kind` is `'op'`, `'redir'`, or `'word'`."""
        cmd = cls._fold_line_continuations(cmd)
        tokens: list[tuple[str, str, Any]] = []
        problems: list[str] = []
        i, n = 0, len(cmd)
        ctrl_ops = (";;&", ";&", ";;", "&&", "||", "|&", ";", "&", "|", "(", ")")
        while i < n:
            ch = cmd[i]
            if ch in (" ", "\t"):
                i += 1
                continue
            if ch == "#":
                while i < n and cmd[i] != "\n":
                    i += 1
                continue
            if ch == "\n":
                tokens.append(("op", ";", False))
                i += 1
                continue
            # Optional fd digits before a redirection operator (e.g. `2>&1`, `0</dev/null`)
            fd_end = i
            while fd_end < n and cmd[fd_end].isdigit():
                fd_end += 1
            if fd_end > i and fd_end < n and cmd[fd_end] in (">", "<"):
                matched_redir = next((op for op in cls._REDIR_OPS if cmd.startswith(op, fd_end)), None)
                if matched_redir:
                    if matched_redir in ("<<", "<<-"):
                        problems.append("heredoc redirection in gate command cannot be statically fingerprinted")
                    tokens.append(("redir", cmd[i:fd_end] + matched_redir, False))
                    i = fd_end + len(matched_redir)
                    continue
            matched_redir = next((op for op in cls._REDIR_OPS if cmd.startswith(op, i)), None)
            if matched_redir:
                if matched_redir in ("<<", "<<-"):
                    problems.append("heredoc redirection in gate command cannot be statically fingerprinted")
                tokens.append(("redir", matched_redir, False))
                i += len(matched_redir)
                continue
            matched_op = next((op for op in ctrl_ops if cmd.startswith(op, i)), None)
            if matched_op:
                tokens.append(("op", matched_op, False))
                i += len(matched_op)
                continue
            # Read one shell word; detect unquoted assignment prefix (`NAME=`, `NAME+=`, `NAME[idx]=`) before quotes
            m_asgn = re.match(r"^([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?)\+?=", cmd[i:])
            assign_var = m_asgn.group(1) if m_asgn else None
            buf: list[str] = []
            quoted = False
            dynamic = False
            saw_unquoted_bracket = False
            saw_unquoted_brace = False
            while i < n:
                c = cmd[i]
                if c in (" ", "\t", "\n"):
                    break
                if any(cmd.startswith(op, i) for op in (*ctrl_ops, *cls._REDIR_OPS)):
                    break
                if c == "\\":
                    quoted = True
                    if i + 1 < n:
                        buf.append(cmd[i + 1])
                        i += 2
                    else:
                        i += 1
                    continue
                if c == "'":
                    quoted = True
                    i += 1
                    while i < n and cmd[i] != "'":
                        buf.append(cmd[i])
                        i += 1
                    if i >= n:
                        problems.append("unterminated single quote")
                        break
                    i += 1
                    continue
                if c == '"':
                    quoted = True
                    i += 1
                    while i < n and cmd[i] != '"':
                        if cmd[i] == "\\" and i + 1 < n and cmd[i + 1] in ('"', "\\", "$", "`", "\n"):
                            buf.append(cmd[i + 1])
                            i += 2
                            continue
                        if cmd[i] == "$":
                            dynamic = True
                        buf.append(cmd[i])
                        i += 1
                    if i >= n:
                        problems.append("unterminated double quote")
                        break
                    i += 1
                    continue
                if c in ("~", "$", "*", "?"):
                    dynamic = True
                elif c == "[":
                    saw_unquoted_bracket = True
                elif c in ("{", "}"):
                    saw_unquoted_brace = True
                buf.append(c)
                i += 1
            word = "".join(buf)
            if saw_unquoted_bracket and (quoted or word != "["):
                dynamic = True
            if saw_unquoted_brace and (quoted or word not in ("{", "}")):
                dynamic = True
            if "__MQ_CMDSUB__" in word:
                dynamic = True
            flag_val: dict[str, Any] = {
                "quoted": quoted,
                "dynamic": dynamic,
                "assign_var": assign_var,
            }
            tokens.append(("word", word, flag_val))
        return tokens, problems

    @classmethod
    def _analyze_gate_command(cls, gate_cmd: str, _depth: int = 0) -> tuple[list[str], list[str], list[str]]:
        """Extract `(executables, sourced_files, problems)` across simple and compound shell syntax."""
        if _depth > 6:
            return [], [], ["gate command recursion depth exceeded"]
        if any((ord(ch_c) < 32 and ch_c not in ("\t", "\n")) or ord(ch_c) == 127 for ch_c in gate_cmd):
            return [], [], ["ASCII control character (e.g. CR/NUL) in gate command cannot be statically fingerprinted"]
        sanitized, subs, sub_problems = cls._strip_cmd_substitutions(gate_cmd)
        executables: list[str] = []
        sourced: list[str] = []
        problems: list[str] = list(sub_problems)
        for sub in subs:
            s_exe, s_src, s_prob = cls._analyze_gate_command(sub, _depth + 1)
            executables.extend(s_exe)
            sourced.extend(s_src)
            problems.extend(s_prob)
        lex_tokens, lex_problems = cls._lex_gate_tokens(sanitized)
        problems.extend(lex_problems)

        def is_unquoted(flag: Any) -> bool:
            return isinstance(flag, dict) and not flag.get("quoted") and not flag.get("dynamic")

        def is_dynamic(flag: Any) -> bool:
            return bool(isinstance(flag, dict) and flag.get("dynamic"))

        def assign_var_of(flag: Any) -> str | None:
            return flag.get("assign_var") if isinstance(flag, dict) else None

        expect_cmd = True
        in_for_header = False
        in_case_header = False
        case_depth = 0
        paren_depth = 0
        in_case_pattern = False
        in_double_bracket = False
        defined_funcs: set[str] = set()
        idx, total = 0, len(lex_tokens)

        while idx < total:
            kind, tok, flag = lex_tokens[idx]
            if in_double_bracket:
                if kind == "word" and is_unquoted(flag) and tok == "]]":
                    in_double_bracket = False
                elif kind == "word" and (
                    tok in ("-eq", "-ne", "-lt", "-le", "-gt", "-ge", "=~", "-v", "-R")
                    or "[" in tok
                    or "]" in tok
                    or any(
                        ident != "__MQ_CMDSUB__" and cls._touches_lookup_var(ident)
                        for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tok)
                    )
                ):
                    problems.append(
                        "[[ ... ]] conditional using arithmetic/regex or lookup/subscripted variable cannot be statically fingerprinted"
                    )
                idx += 1
                continue
            if kind == "redir":
                idx += 1
                if idx >= total or lex_tokens[idx][0] != "word":
                    problems.append("redirection missing target word in gate command")
                    continue
                idx += 1  # skip redirection target ( never an executable )
                continue
            if kind == "op":
                if tok in (";;", ";&", ";;&"):
                    if case_depth <= 0:
                        problems.append(f"unmatched {tok!r} outside case statement")
                    else:
                        in_case_pattern = True
                        expect_cmd = False
                        in_for_header = False
                elif tok == "(" and in_case_pattern:
                    pass
                elif tok == ")" and in_case_pattern:
                    in_case_pattern = False
                    expect_cmd = True
                elif tok == "(":
                    paren_depth += 1
                    in_for_header = False
                    expect_cmd = True
                elif tok == ")":
                    paren_depth -= 1
                    if paren_depth < 0:
                        problems.append("unmatched ')' in gate command")
                    in_for_header = False
                    expect_cmd = False
                else:
                    in_for_header = False
                    expect_cmd = True
                idx += 1
                continue

            # kind == "word"
            if in_for_header:
                idx += 1
                continue
            if in_case_header:
                if is_unquoted(flag) and tok == "in":
                    in_case_header = False
                    case_depth += 1
                    in_case_pattern = True
                idx += 1
                continue
            if in_case_pattern:
                if is_unquoted(flag) and tok == "esac" and case_depth > 0:
                    case_depth -= 1
                    in_case_pattern = False
                    expect_cmd = False
                idx += 1
                continue
            if not expect_cmd:
                idx += 1
                continue

            # Command position: peel assignments and compound keywords
            avar = assign_var_of(flag)
            if avar is not None:
                if cls._touches_lookup_var(avar):
                    problems.append(
                        f"assignment to {avar!r} alters executable lookup context and cannot be statically fingerprinted"
                    )
                idx += 1
                continue
            if is_unquoted(flag) and tok in cls._COMPOUND_PREFIX_KEYWORDS:
                idx += 1
                continue
            if is_unquoted(flag) and tok in cls._COMPOUND_CLOSE_KEYWORDS:
                expect_cmd = False
                idx += 1
                continue
            if is_unquoted(flag) and tok == "esac":
                if case_depth <= 0:
                    problems.append("unmatched 'esac' in gate command")
                else:
                    case_depth -= 1
                expect_cmd = False
                idx += 1
                continue
            if is_unquoted(flag) and tok in ("for", "select"):
                if idx + 1 >= total or lex_tokens[idx + 1][0] != "word":
                    problems.append(f"{tok}: non-POSIX header cannot be statically fingerprinted")
                else:
                    loop_var, loop_flag = lex_tokens[idx + 1][1], lex_tokens[idx + 1][2]
                    if is_dynamic(loop_flag) or cls._touches_lookup_var(loop_var):
                        problems.append(
                            f"{tok} loop variable {loop_var!r} alters executable lookup context"
                        )
                in_for_header = True
                expect_cmd = False
                idx += 1
                continue
            if is_unquoted(flag) and tok == "case":
                in_case_header = True
                expect_cmd = False
                idx += 1
                continue
            if is_unquoted(flag) and tok == "[[":
                in_double_bracket = True
                expect_cmd = False
                idx += 1
                continue
            if is_unquoted(flag) and tok == "function":
                idx += 1
                if idx < total and lex_tokens[idx][0] == "word":
                    defined_funcs.add(lex_tokens[idx][1])
                    idx += 1
                if idx + 1 < total and lex_tokens[idx][:2] == ("op", "(") and lex_tokens[idx + 1][:2] == ("op", ")"):
                    idx += 2
                continue
            # POSIX function definition `fname () { ... }`
            if (is_unquoted(flag) and idx + 2 < total
                    and lex_tokens[idx + 1][:2] == ("op", "(") and lex_tokens[idx + 2][:2] == ("op", ")")):
                defined_funcs.add(tok)
                idx += 3
                expect_cmd = True
                continue

            if is_dynamic(flag):
                problems.append(f"dynamic command word {tok!r} cannot be statically fingerprinted")
                expect_cmd = False
                idx += 1
                continue

            # Collect remaining words of this simple command (skipping redirections + their targets)
            cmd_words: list[tuple[str, Any]] = [(tok, flag)]
            scan = idx + 1
            while scan < total and lex_tokens[scan][0] != "op":
                if lex_tokens[scan][0] == "redir":
                    scan += 2 if (scan + 1 < total and lex_tokens[scan + 1][0] == "word") else 1
                    continue
                cmd_words.append((lex_tokens[scan][1], lex_tokens[scan][2]))
                scan += 1
            idx = scan
            expect_cmd = False

            # Peel command-executing wrappers (`env`, `nice`, `timeout`, `nohup`, `command`, `exec`)
            wi = 0
            force_external = False
            skip_funcs = False
            while wi < len(cmd_words):
                cw, cflag = cmd_words[wi]
                c_avar = assign_var_of(cflag)
                if c_avar is not None and not force_external:
                    if cls._touches_lookup_var(c_avar):
                        problems.append(
                            f"assignment to {c_avar!r} alters executable lookup context and cannot be statically fingerprinted"
                        )
                    wi += 1
                    continue
                if is_dynamic(cflag):
                    problems.append(f"dynamic command word {cw!r} cannot be statically fingerprinted")
                    wi = len(cmd_words)
                    break
                cw_base = Path(cw).name
                if cw_base in cls._MUX_WRAPPERS:
                    problems.append(
                        f"{cw!r} multiplexes or wraps inner commands whose targets cannot be statically fingerprinted"
                    )
                    wi = len(cmd_words)
                    break
                if cw_base == "env":
                    executables.append(cw)
                    force_external = True
                    wi += 1
                    broke_env_s = False
                    # Phase A: env options
                    while wi < len(cmd_words):
                        a, aflag = cmd_words[wi]
                        if a == "--":
                            wi += 1
                            break
                        if a == "-" or a == "--ignore-environment":
                            problems.append("env -i/--ignore-environment alters PATH lookup context")
                            wi += 1
                            continue
                        if not a.startswith("-"):
                            break
                        if is_dynamic(aflag):
                            problems.append(f"env: dynamic option {a!r} cannot be fingerprinted")
                            wi += 1
                            continue
                        if a in ("-S", "--split-string") or a.startswith("--split-string="):
                            problems.append(
                                "env -S/--split-string performs runtime word splitting and cannot be statically fingerprinted"
                            )
                            wi = len(cmd_words)
                            broke_env_s = True
                            break
                        if a in ("-C", "--chdir") or a.startswith("--chdir="):
                            problems.append("env -C/--chdir alters working-directory lookup context")
                            wi += 2 if a in ("-C", "--chdir") and wi + 1 < len(cmd_words) else 1
                            continue
                        if a in ("-P", "--default-path") or a.startswith("--default-path="):
                            problems.append("env -P/--default-path alters PATH lookup context")
                            wi += 2 if a in ("-P", "--default-path") and wi + 1 < len(cmd_words) else 1
                            continue
                        if a in ("-u", "--unset") or a.startswith("--unset="):
                            if a.startswith("--unset="):
                                uvar, udyn = a.split("=", 1)[1], False
                                wi += 1
                            elif wi + 1 < len(cmd_words):
                                uvar, udyn = cmd_words[wi + 1][0], is_dynamic(cmd_words[wi + 1][1])
                                wi += 2
                            else:
                                uvar, udyn = "", True
                                wi += 1
                            if udyn or cls._touches_lookup_var(uvar):
                                problems.append("env -u/--unset alters executable lookup variable")
                            continue
                        if a.startswith("--"):
                            if a in ("--null", "--debug", "--list-signal-handling") or a.startswith(
                                ("--block-signal", "--default-signal", "--ignore-signal")
                            ):
                                wi += 1
                                continue
                            problems.append(f"env: unsupported option {a!r} cannot be statically fingerprinted")
                            wi += 1
                            continue
                        # Short option cluster (`-i`, `-uPATH`, `-C/dir`, `-S...`, etc.)
                        short = a[1:]
                        si = 0
                        consumed_next = False
                        while si < len(short):
                            ch_opt = short[si]
                            rest = short[si + 1:]
                            if ch_opt in ("0", "v"):
                                si += 1
                                continue
                            if ch_opt == "i":
                                problems.append("env -i alters PATH lookup context")
                                si += 1
                                continue
                            if ch_opt == "C":
                                problems.append("env -C alters working-directory lookup context")
                                if not rest and wi + 1 < len(cmd_words):
                                    consumed_next = True
                                break
                            if ch_opt == "P":
                                problems.append("env -P alters PATH lookup context")
                                if not rest and wi + 1 < len(cmd_words):
                                    consumed_next = True
                                break
                            if ch_opt == "u":
                                if rest:
                                    uvar, udyn = rest, False
                                elif wi + 1 < len(cmd_words):
                                    uvar, udyn = cmd_words[wi + 1][0], is_dynamic(cmd_words[wi + 1][1])
                                    consumed_next = True
                                else:
                                    uvar, udyn = "", True
                                if udyn or cls._touches_lookup_var(uvar):
                                    problems.append("env -u alters executable lookup variable")
                                break
                            if ch_opt == "S":
                                problems.append(
                                    "env -S performs runtime word splitting and cannot be statically fingerprinted"
                                )
                                broke_env_s = True
                                break
                            problems.append(f"env: unsupported short option -{ch_opt} cannot be statically fingerprinted")
                            break
                        if broke_env_s:
                            wi = len(cmd_words)
                            break
                        wi += 2 if consumed_next else 1
                    if broke_env_s:
                        break
                    # Phase B: env NAME=VALUE operands (honored by env even when shell-quoted)
                    while wi < len(cmd_words) and "=" in cmd_words[wi][0]:
                        ea, eaflag = cmd_words[wi]
                        lhs = ea.split("=", 1)[0]
                        if is_dynamic(eaflag):
                            problems.append("env: dynamic variable assignment cannot be statically fingerprinted")
                        elif cls._touches_lookup_var(lhs):
                            problems.append(
                                f"env {lhs}=... alters executable lookup context and cannot be statically fingerprinted"
                            )
                        wi += 1
                    continue
                if cw_base == "nice":
                    executables.append(cw)
                    force_external = True
                    wi += 1
                    while wi < len(cmd_words) and cmd_words[wi][0].startswith("-") and len(cmd_words[wi][0]) > 1:
                        n_opt, n_flag = cmd_words[wi]
                        if is_dynamic(n_flag):
                            problems.append("nice: dynamic option cannot be statically fingerprinted")
                            wi = len(cmd_words)
                            break
                        if n_opt == "--":
                            wi += 1
                            break
                        if n_opt in ("-n", "--adjustment"):
                            if wi + 1 >= len(cmd_words) or is_dynamic(cmd_words[wi + 1][1]):
                                problems.append(
                                    f"nice {n_opt}: missing or dynamic adjustment operand cannot be statically fingerprinted"
                                )
                                wi = len(cmd_words)
                                break
                            wi += 2
                        elif n_opt.startswith(("-n", "--adjustment=")) or re.match(r"^--?\d+$", n_opt):
                            wi += 1
                        else:
                            problems.append(f"nice: unsupported option {n_opt!r} cannot be statically fingerprinted")
                            wi = len(cmd_words)
                            break
                    continue
                if cw_base == "timeout":
                    executables.append(cw)
                    force_external = True
                    wi += 1
                    timeout_bad = False
                    while wi < len(cmd_words) and cmd_words[wi][0].startswith("-") and len(cmd_words[wi][0]) > 1:
                        t_opt, t_flag = cmd_words[wi]
                        if is_dynamic(t_flag):
                            problems.append("timeout: dynamic option cannot be statically fingerprinted")
                            timeout_bad = True
                            wi = len(cmd_words)
                            break
                        if t_opt == "--":
                            wi += 1
                            break
                        if t_opt in ("-k", "--kill-after", "-s", "--signal") or (
                            not t_opt.startswith("--")
                            and t_opt[1:].endswith(("k", "s"))
                            and all(c == "v" for c in t_opt[1:-1])
                        ):
                            if wi + 1 >= len(cmd_words) or is_dynamic(cmd_words[wi + 1][1]):
                                problems.append(
                                    f"timeout {t_opt}: missing or dynamic option operand cannot be statically fingerprinted"
                                )
                                timeout_bad = True
                                wi = len(cmd_words)
                                break
                            wi += 2
                        elif t_opt in ("-v", "--verbose", "--foreground", "--preserve-status") or t_opt.startswith(
                            ("-k", "--kill-after=", "-s", "--signal=")
                        ):
                            wi += 1
                        else:
                            problems.append(f"timeout: unsupported option {t_opt!r} cannot be statically fingerprinted")
                            timeout_bad = True
                            wi = len(cmd_words)
                            break
                    if not timeout_bad:
                        if wi >= len(cmd_words) or is_dynamic(cmd_words[wi][1]):
                            problems.append(
                                "timeout: missing or dynamic duration operand cannot be statically fingerprinted"
                            )
                            wi = len(cmd_words)
                        else:
                            wi += 1  # static single-word duration
                            if wi >= len(cmd_words):
                                problems.append(
                                    "timeout: missing inner command operand cannot be statically fingerprinted"
                                )
                    continue
                if cw_base == "nohup":
                    executables.append(cw)
                    force_external = True
                    wi += 1
                    while wi < len(cmd_words) and cmd_words[wi][0].startswith("-") and len(cmd_words[wi][0]) > 1:
                        nh_opt, nh_flag = cmd_words[wi]
                        if is_dynamic(nh_flag):
                            problems.append("nohup: dynamic option cannot be statically fingerprinted")
                        if nh_opt == "--":
                            wi += 1
                            break
                        problems.append(f"nohup: unsupported option {nh_opt!r} cannot be statically fingerprinted")
                        wi += 1
                    continue
                if cw_base in ("command", "builtin") and ("/" in cw or force_external):
                    problems.append(f"external {cw!r} utility cannot be statically fingerprinted")
                    wi = len(cmd_words)
                    break
                if not force_external and cw in ("command", "builtin"):
                    if cw == "builtin":
                        executables.append("__opt_builtin__:builtin")
                    skip_funcs = True
                    wi += 1
                    query_only = False
                    while wi < len(cmd_words) and cmd_words[wi][0].startswith("-") and len(cmd_words[wi][0]) > 1:
                        opt, opt_flag = cmd_words[wi]
                        wi += 1
                        if opt == "--":
                            break
                        if is_dynamic(opt_flag):
                            problems.append(f"{cw}: dynamic option {opt!r} cannot be statically fingerprinted")
                            continue
                        if cw == "builtin":
                            problems.append(f"builtin: unsupported option {opt!r} cannot be statically fingerprinted")
                            continue
                        if "p" in opt[1:]:
                            problems.append(
                                "command -p alters PATH lookup context and cannot be statically fingerprinted"
                            )
                        if any(c not in ("p", "v", "V") for c in opt[1:]):
                            problems.append(f"command: unsupported option {opt!r} cannot be statically fingerprinted")
                        if "v" in opt[1:] or "V" in opt[1:]:
                            query_only = True
                    if query_only:
                        wi = len(cmd_words)
                        break
                    continue
                if not force_external and cw == "exec":
                    wi += 1
                    while wi < len(cmd_words) and cmd_words[wi][0].startswith("-") and len(cmd_words[wi][0]) > 1:
                        opt, opt_flag = cmd_words[wi]
                        if opt == "--":
                            wi += 1
                            break
                        if is_dynamic(opt_flag):
                            problems.append("exec: dynamic option cannot be statically fingerprinted")
                            wi = len(cmd_words)
                            break
                        if "c" in opt[1:]:
                            problems.append("exec -c clears environment and alters PATH lookup context")
                        if opt == "-a":
                            if wi + 1 >= len(cmd_words) or is_dynamic(cmd_words[wi + 1][1]):
                                problems.append(
                                    "exec -a: missing or dynamic name operand cannot be statically fingerprinted"
                                )
                                wi = len(cmd_words)
                                break
                            wi += 2
                        elif opt == "-l":
                            wi += 1
                        else:
                            problems.append(f"exec: unsupported option {opt!r} cannot be statically fingerprinted")
                            wi = len(cmd_words)
                            break
                    if wi < len(cmd_words):
                        force_external = True
                    continue
                break

            if wi >= len(cmd_words):
                continue
            final_word, final_flag = cmd_words[wi]
            if is_dynamic(final_flag):
                problems.append(f"dynamic command word {final_word!r} cannot be statically fingerprinted")
                continue
            if not force_external:
                if final_word == "eval":
                    problems.append("shell 'eval' builtin cannot be statically fingerprinted")
                    continue
                if final_word in ("cd", "pushd", "popd"):
                    problems.append(f"shell {final_word!r} builtin alters working-directory lookup context")
                    continue
                if final_word in (
                    "alias", "unalias", "hash", "enable", "shopt",
                    "mapfile", "readarray", "compgen", "complete", "compopt",
                    "bind", "fc", "history", "jobs",
                ):
                    problems.append(f"shell {final_word!r} builtin alters command lookup or executes callbacks")
                    continue
                if final_word == "set":
                    allowed_set_short = set("abefhmnuvxBCEHPTo")
                    si = wi + 1
                    while si < len(cmd_words):
                        sw, sf = cmd_words[si]
                        if sw in ("--", "-"):
                            break
                        if not sw.startswith(("-", "+")) or sw == "+":
                            break
                        if is_dynamic(sf):
                            problems.append("shell 'set' dynamic option cannot be statically fingerprinted")
                            break
                        s_short = sw[1:]
                        if any(ch_s not in allowed_set_short for ch_s in s_short):
                            problems.append(
                                f"shell 'set {sw}' unsupported or lookup-altering option cannot be statically fingerprinted"
                            )
                            break
                        if "o" in s_short:
                            if not (s_short.endswith("o") and s_short.count("o") == 1):
                                problems.append(
                                    f"shell 'set {sw}' ambiguous -o option cluster cannot be statically fingerprinted"
                                )
                                break
                            if si + 1 < len(cmd_words) and cmd_words[si + 1][0] != "--":
                                oname, oflag = cmd_words[si + 1]
                                if is_dynamic(oflag) or oname not in cls._SAFE_SHELL_O_OPTIONS:
                                    problems.append(
                                        f"shell 'set {sw} {oname}' unsupported or lookup-altering option cannot be statically fingerprinted"
                                    )
                                    break
                                si += 2
                                continue
                        si += 1
                    continue
                if final_word == "wait":
                    for ww, wf in cmd_words[wi + 1:]:
                        if ww == "--":
                            break
                        if ww.startswith("-") and len(ww) > 1 and (is_dynamic(wf) or "p" in ww[1:]):
                            problems.append("shell 'wait -p' or dynamic option cannot be statically fingerprinted")
                            break
                    continue
                if final_word in ("export", "unset", "readonly", "typeset", "declare", "local"):
                    if final_word in ("typeset", "declare"):
                        executables.append(f"__opt_builtin__:{final_word}")
                    saw_dd = False
                    for arg_w, arg_f in cmd_words[wi + 1:]:
                        if not saw_dd and arg_w == "--":
                            saw_dd = True
                            continue
                        if not saw_dd and arg_w.startswith(("-", "+")) and len(arg_w) > 1:
                            if is_dynamic(arg_f):
                                problems.append(f"{final_word}: dynamic option cannot be statically fingerprinted")
                                break
                            if final_word in ("declare", "typeset", "local") and any(
                                ch_d in arg_w[1:] for ch_d in ("n", "i", "a", "A")
                            ):
                                problems.append(
                                    f"{final_word} {arg_w} nameref/integer/array attribute cannot be statically fingerprinted"
                                )
                                break
                            if final_word == "unset" and "f" in arg_w[1:]:
                                problems.append("unset -f alters function/executable dispatch")
                                break
                            continue
                        vname = arg_w.split("=", 1)[0].rstrip("+")
                        dyn_vname = is_dynamic(arg_f) and (
                            any(ch_v in vname for ch_v in "$*?[`") or "__MQ_CMDSUB__" in vname
                        )
                        if dyn_vname or cls._touches_lookup_var(vname):
                            problems.append(
                                f"shell {final_word!r} builtin touching lookup variable cannot be statically fingerprinted"
                            )
                            break
                    continue
                if final_word == "read":
                    saw_read_dd = False
                    for rw, rf in cmd_words[wi + 1:]:
                        if not saw_read_dd and rw == "--":
                            saw_read_dd = True
                            continue
                        if not saw_read_dd and rw.startswith("-") and len(rw) > 1:
                            if is_dynamic(rf) or any(ch_r in rw[1:] for ch_r in ("a", "e")):
                                problems.append("shell 'read' array/readline/dynamic option cannot be statically fingerprinted")
                                break
                            continue
                        if is_dynamic(rf) or cls._touches_lookup_var(rw.split("=", 1)[0]):
                            problems.append("shell 'read' builtin touching lookup variable cannot be statically fingerprinted")
                            break
                    continue
                if final_word == "printf":
                    pi = wi + 1
                    printf_bad = False
                    while pi < len(cmd_words):
                        pw, pf = cmd_words[pi]
                        if pw == "--":
                            pi += 1
                            break
                        if not pw.startswith("-") or pw == "-":
                            break
                        if is_dynamic(pf):
                            problems.append("shell 'printf' dynamic option cannot be statically fingerprinted")
                            printf_bad = True
                            break
                        if pw == "-v":
                            if pi + 1 >= len(cmd_words) or is_dynamic(cmd_words[pi + 1][1]) or (
                                cls._touches_lookup_var(cmd_words[pi + 1][0])
                            ):
                                problems.append(
                                    "shell 'printf -v' touching lookup variable cannot be statically fingerprinted"
                                )
                                printf_bad = True
                                break
                            pi += 2
                            continue
                        if pw.startswith("-v") and len(pw) > 2:
                            if cls._touches_lookup_var(pw[2:]):
                                problems.append(
                                    "shell 'printf -v' touching lookup variable cannot be statically fingerprinted"
                                )
                                printf_bad = True
                                break
                            pi += 1
                            continue
                        problems.append(f"shell 'printf' unsupported option {pw!r} cannot be statically fingerprinted")
                        printf_bad = True
                        break
                    if not printf_bad and pi < len(cmd_words):
                        fmt_w, fmt_f = cmd_words[pi]
                        if is_dynamic(fmt_f):
                            problems.append("shell 'printf' dynamic format string cannot be statically fingerprinted")
                        elif any(
                            not re.match(r"^(?:[0-9$*+# '.-]*[hlLqjzt]*)?[diouxXfFeEgGaAcsbq]", part)
                            for part in fmt_w.replace("%%", "").split("%")[1:]
                        ):
                            problems.append(
                                "shell 'printf' non-printable or '%n' format directive cannot be statically fingerprinted"
                            )
                    continue
                if final_word == "getopts":
                    if wi + 2 >= len(cmd_words) or is_dynamic(cmd_words[wi + 2][1]) or (
                        cls._touches_lookup_var(cmd_words[wi + 2][0])
                    ):
                        problems.append("shell 'getopts' touching lookup variable cannot be statically fingerprinted")
                    continue
                if final_word == "let":
                    problems.append("shell 'let' arithmetic builtin cannot be statically fingerprinted")
                    continue
                if final_word == "trap":
                    t_args = cmd_words[wi + 1:]
                    if not t_args:
                        continue
                    ti = 0
                    if t_args[0][0] == "--":
                        ti = 1
                    elif t_args[0][0].startswith("-"):
                        problems.append("trap: option flags cannot be statically fingerprinted")
                        continue
                    if ti >= len(t_args):
                        continue
                    t_act, t_flag = t_args[ti]
                    if is_dynamic(t_flag):
                        problems.append("trap: dynamic action string cannot be statically fingerprinted")
                    elif t_act and t_act != "-" and not t_act.isdigit():
                        e2, s2, p2 = cls._analyze_gate_command(t_act, _depth + 1)
                        executables.extend(e2)
                        sourced.extend(s2)
                        problems.extend(p2)
                    continue
                if final_word in ("test", "["):
                    t_args = cmd_words[wi + 1:]
                    if final_word == "[" and t_args and t_args[-1][0] == "]":
                        t_args = t_args[:-1]
                    bin_ops = {
                        "=", "==", "!=", "<", ">",
                        "-eq", "-ne", "-lt", "-le", "-gt", "-ge",
                        "-nt", "-ot", "-ef", "-a", "-o", ")",
                    }
                    for ti, (tw, tf) in enumerate(t_args):
                        if tw in ("-v", "-R"):
                            problems.append(
                                f"{final_word} {tw} variable-reference operator evaluates array subscripts and cannot be statically fingerprinted"
                            )
                            break
                        prev_is_prefix = ti == 0 or is_dynamic(t_args[ti - 1][1]) or (
                            t_args[ti - 1][0] in ("!", "(", "-a", "-o")
                        )
                        if prev_is_prefix and is_dynamic(tf) and ti + 1 < len(t_args):
                            nw, nf = t_args[ti + 1]
                            if is_dynamic(nf) or nw not in bin_ops:
                                problems.append(
                                    f"{final_word}: dynamic unary operator cannot be statically fingerprinted"
                                )
                                break
                if final_word in (".", "source"):
                    if final_word == "source":
                        executables.append("__opt_builtin__:source")
                    if wi + 1 >= len(cmd_words) or is_dynamic(cmd_words[wi + 1][1]):
                        problems.append(f"{final_word}: dynamic or missing script target cannot be fingerprinted")
                    else:
                        src_target = cmd_words[wi + 1][0]
                        if "/" not in src_target and not os.path.isabs(src_target):
                            problems.append(
                                f"{final_word}: script target {src_target!r} without '/' searches PATH and cannot be statically fingerprinted"
                            )
                        else:
                            sourced.append(src_target)
                    continue
            if force_external:
                if final_word:
                    executables.append(final_word)
            elif final_word in defined_funcs and not skip_funcs:
                executables.append(f"__func__:{final_word}")
            elif final_word and not (
                final_word in cls._SHELL_BUILTINS
                or (is_unquoted(final_flag) and final_word in cls._SHELL_KEYWORDS)
            ):
                executables.append(final_word)
            final_base = Path(final_word).name
            if final_base == "find" and any(
                fa in ("-exec", "-execdir", "-ok", "-okdir") or is_dynamic(ff)
                for fa, ff in cmd_words[wi + 1:]
            ):
                problems.append("find -exec/-ok or dynamic predicate dispatches commands that cannot be statically fingerprinted")
            elif final_base in cls._SHELL_NAMES:
                s_src, s_exe, s_prob = cls._analyze_shell_invocation(final_word, cmd_words[wi + 1:], _depth)
                executables.extend(s_exe)
                sourced.extend(s_src)
                problems.extend(s_prob)
            else:
                i_exe, i_prob = cls._analyze_interpreter_invocation(final_word, cmd_words[wi + 1:])
                executables.extend(i_exe)
                problems.extend(i_prob)
        if paren_depth != 0:
            problems.append("unbalanced parentheses in gate command")
        if case_depth != 0:
            problems.append("unclosed case statement in gate command")
        if in_double_bracket:
            problems.append("unclosed [[ conditional in gate command")
        return executables, sourced, problems

    @classmethod
    def _analyze_shell_invocation(
        cls, shell_word: str, args: list[tuple[str, Any]], _depth: int
    ) -> tuple[list[str], list[str], list[str]]:
        """Analyze `sh`/`bash`/etc. invocations (`-c <cmd>` or `<script>` operand), failing closed on
        stdin/interactive/login modes or ambiguous flags."""
        sourced: list[str] = []
        executables: list[str] = []
        problems: list[str] = []
        if Path(shell_word).name in ("csh", "tcsh"):
            return [], [], [f"{shell_word}: non-POSIX shell cannot be statically fingerprinted"]

        def is_dynamic(flag: Any) -> bool:
            return bool(isinstance(flag, dict) and flag.get("dynamic"))

        allowed_dash = set("abefhmnuvxBCHPco")
        allowed_plus = set("abefhmnuvxBCHPo")
        j = 0
        used_dash_c = False
        while j < len(args):
            a, a_flag = args[j]
            if a in ("--", "-"):
                j += 1
                break
            if not a.startswith(("-", "+")) or a == "+":
                break
            if is_dynamic(a_flag):
                problems.append(f"{shell_word}: dynamic option {a!r} cannot be statically fingerprinted")
                return sourced, executables, problems
            if a.startswith("--"):
                if a in ("--posix", "--norc", "--noprofile"):
                    j += 1
                    continue
                problems.append(f"{shell_word}: option {a!r} cannot be statically fingerprinted")
                return sourced, executables, problems
            if a in ("-O", "+O"):
                problems.append(f"{shell_word} {a}: shopt option alters shell lookup or parsing and cannot be fingerprinted")
                return sourced, executables, problems
            if a in ("-o", "+o"):
                if j + 1 >= len(args) or is_dynamic(args[j + 1][1]) or args[j + 1][0] not in cls._SAFE_SHELL_O_OPTIONS:
                    problems.append(
                        f"{shell_word} {a}: missing, dynamic, or lookup-altering option cannot be statically fingerprinted"
                    )
                    return sourced, executables, problems
                j += 2
                continue
            short = a[1:]
            allowed = allowed_dash if a.startswith("-") else allowed_plus
            if a.startswith("-") and any(ch_s in short for ch_s in ("l", "i", "s", "r")):
                problems.append(f"{shell_word} {a}: interactive/login/stdin mode cannot be statically fingerprinted")
                return sourced, executables, problems
            if any(ch_s not in allowed for ch_s in short):
                problems.append(f"{shell_word} {a}: unsupported option cannot be statically fingerprinted")
                return sourced, executables, problems
            if "o" in short:
                if not (short.endswith("o") and short.count("o") == 1 and "c" not in short):
                    problems.append(f"{shell_word} {a}: ambiguous -o option cluster cannot be statically fingerprinted")
                    return sourced, executables, problems
                if j + 1 >= len(args) or is_dynamic(args[j + 1][1]) or args[j + 1][0] not in cls._SAFE_SHELL_O_OPTIONS:
                    problems.append(
                        f"{shell_word} {a}: missing, dynamic, or lookup-altering option cannot be statically fingerprinted"
                    )
                    return sourced, executables, problems
                j += 2
                continue
            if a.startswith("-") and "c" in short:
                used_dash_c = True
                if j + 1 >= len(args):
                    problems.append(f"{shell_word} -c: missing command string cannot be statically fingerprinted")
                else:
                    sub_script, sub_flag = args[j + 1]
                    if is_dynamic(sub_flag):
                        problems.append(f"{shell_word} -c: dynamic script cannot be fingerprinted")
                    else:
                        e2, s2, p2 = cls._analyze_gate_command(sub_script, _depth + 1)
                        executables.extend(e2)
                        sourced.extend(s2)
                        problems.extend(p2)
                break
            j += 1

        if not used_dash_c:
            if j >= len(args):
                problems.append(
                    f"{shell_word}: shell invoked without -c or script operand cannot be statically fingerprinted"
                )
            else:
                script_arg, script_flag = args[j]
                if is_dynamic(script_flag):
                    problems.append(f"{shell_word}: dynamic script operand {script_arg!r} cannot be fingerprinted")
                elif "/" not in script_arg and not os.path.isabs(script_arg):
                    problems.append(
                        f"{shell_word}: script operand {script_arg!r} without '/' has shell-dependent lookup; use ./{script_arg} or an explicit path"
                    )
                else:
                    sourced.append(script_arg)
        return sourced, executables, problems

    @classmethod
    def _analyze_interpreter_invocation(
        cls, exe_word: str, args: list[tuple[str, Any]]
    ) -> tuple[list[str], list[str]]:
        """Extract direct script file operands for non-shell interpreters (`python*`, `perl`, `ruby`, `node`, etc.)
        so replacing an external script after `plan` invalidates the saved fingerprint."""
        base = Path(exe_word).name

        def is_dynamic(flag: Any) -> bool:
            return bool(isinstance(flag, dict) and flag.get("dynamic"))

        def norm_script(p: str) -> str:
            return p if ("/" in p or os.path.isabs(p)) else f"./{p}"

        if re.match(r"^(?:python|pypy)(?:\d+(?:\.\d+)*)?$", base):
            j = 0
            saw_isolated = False
            while j < len(args):
                a, a_flag = args[j]
                if a == "--":
                    j += 1
                    break
                if not a.startswith("-") or a == "-":
                    break
                if is_dynamic(a_flag):
                    return [], [f"{exe_word}: dynamic option {a!r} cannot be statically fingerprinted"]
                if a in ("-V", "--version", "-h", "--help") and j + 1 == len(args):
                    return [], []
                if a in ("-W", "-X", "--check-hash-based-pycs"):
                    if j + 1 >= len(args) or is_dynamic(args[j + 1][1]):
                        return [], [f"{exe_word} {a}: missing or dynamic option value cannot be fingerprinted"]
                    opt_val = args[j + 1][0]
                    if a == "-W" and len(opt_val.split(":")) >= 3 and "." in opt_val.split(":")[2]:
                        return [], [f"{exe_word} -W {opt_val!r}: dotted warning category imports external module"]
                    if a == "-X":
                        x_name = opt_val.split("=", 1)[0]
                        if x_name == "pycache_prefix":
                            return [], [f"{exe_word} -X pycache_prefix: external bytecode cache cannot be fingerprinted"]
                        if x_name == "safe_path":
                            saw_isolated = True
                    j += 2
                    continue
                if a.startswith(("-W", "-X", "--check-hash-based-pycs=")):
                    if a.startswith("-W") and len(a[2:].split(":")) >= 3 and "." in a[2:].split(":")[2]:
                        return [], [f"{exe_word} {a}: dotted warning category imports external module"]
                    if a.startswith("-X"):
                        x_name = a[2:].split("=", 1)[0]
                        if x_name == "pycache_prefix":
                            return [], [f"{exe_word} {a}: external bytecode cache cannot be fingerprinted"]
                        if x_name == "safe_path":
                            saw_isolated = True
                    j += 1
                    continue
                if a.startswith("--"):
                    return [], [f"{exe_word}: option {a!r} cannot be statically fingerprinted"]
                short = a[1:]
                if "i" in short:
                    return [], [f"{exe_word} {a}: interactive mode cannot be statically fingerprinted"]
                if "I" in short or "P" in short:
                    saw_isolated = True
                if short.endswith("c") and all(c in "bBdEIOqsSuvxP" for c in short[:-1]):
                    return [], [
                        f"{exe_word} {a}: inline '-c' code execution cannot statically fingerprint external targets"
                    ]
                if short.endswith("m") and all(c in "bBdEIOqsSuvxP" for c in short[:-1]):
                    if saw_isolated:
                        return [], [
                            f"{exe_word} {a}: '-I'/'-P'/'-X safe_path' omits checkout directory for '-m' module resolution"
                        ]
                    if j + 1 >= len(args) or is_dynamic(args[j + 1][1]):
                        return [], [f"{exe_word} {a}: missing or dynamic '-m' target cannot be statically fingerprinted"]
                    mod_name = args[j + 1][0]
                    if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", mod_name):
                        return [], [f"{exe_word} -m {mod_name!r}: invalid module name cannot be fingerprinted"]
                    mod_root = mod_name.split(".", 1)[0]
                    forbid_mods = (
                        set(getattr(sys, "stdlib_module_names", ()))
                        | set(sys.builtin_module_names)
                        | {"pip", "setuptools", "wheel", "virtualenv", "nox", "tox", "coverage", "pytest", "ipython", "IPython"}
                    )
                    if mod_root in forbid_mods:
                        return [], [
                            f"{exe_word} -m {mod_name}: stdlib/external module runner cannot statically fingerprint targets"
                        ]
                    mod_files = [f"__py_mod__:{mod_name}"]
                    for ma, mf in args[j + 2:]:
                        if ma == "--":
                            continue
                        if is_dynamic(mf) or ma.startswith("-"):
                            return [], [
                                f"{exe_word} -m {mod_name}: dynamic or option argument {ma!r} cannot be statically fingerprinted"
                            ]
                        mod_files.append(norm_script(ma))
                    return mod_files, []
                if all(c in "bBdEIOqsSuvxP" for c in short):
                    j += 1
                    continue
                return [], [f"{exe_word} {a}: unsupported option cannot be statically fingerprinted"]
            if j >= len(args):
                return [], [f"{exe_word}: interpreter invoked without script or repo '-m' module cannot be fingerprinted"]
            script_arg, script_flag = args[j]
            if script_arg == "-" or is_dynamic(script_flag):
                return [], [f"{exe_word}: stdin or dynamic script operand cannot be statically fingerprinted"]
            return [norm_script(script_arg)], []

        if base in ("perl", "ruby", "node", "nodejs", "php", "lua", "Rscript"):
            if not args:
                return [], [f"{exe_word}: interpreter invoked without script operand cannot be fingerprinted"]
            a0, f0 = args[0]
            if len(args) == 1 and not is_dynamic(f0) and a0 in ("-v", "-V", "--version", "-h", "--help"):
                return [], []
            if a0 == "--":
                if len(args) < 2 or args[1][0] == "-" or is_dynamic(args[1][1]):
                    return [], [f"{exe_word}: missing or dynamic script operand cannot be fingerprinted"]
                return [norm_script(args[1][0])], []
            if a0.startswith("-"):
                return [], [f"{exe_word}: inline code or option {a0!r} cannot statically fingerprint external targets"]
            if base in ("node", "nodejs") and a0 in ("inspect", "debug"):
                return [], [f"{exe_word} {a0}: subcommand cannot statically fingerprint external targets"]
            if is_dynamic(f0):
                return [], [f"{exe_word}: dynamic script operand {a0!r} cannot be fingerprinted"]
            return [norm_script(a0)], []

        if base in ("deno", "bun"):
            if not args:
                return [], [f"{exe_word}: interpreter invoked without script operand cannot be fingerprinted"]
            a0, f0 = args[0]
            if len(args) == 1 and not is_dynamic(f0) and a0 in ("-v", "-V", "--version", "-h", "--help"):
                return [], []
            if a0 == "run" and len(args) >= 2 and not args[1][0].startswith("-") and not is_dynamic(args[1][1]):
                s_target = args[1][0]
                if base == "deno" or s_target.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")):
                    return [norm_script(s_target)], []
            if (
                base == "bun"
                and not a0.startswith("-")
                and not is_dynamic(f0)
                and a0.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"))
            ):
                return [norm_script(a0)], []
            return [], [f"{exe_word}: subcommand, task, or option {a0!r} cannot statically fingerprint external targets"]

        if base == "sed":
            files: list[str] = []
            j = 0
            while j < len(args):
                a, a_flag = args[j]
                if a == "--":
                    j += 1
                    break
                if not a.startswith("-") or a == "-":
                    break
                if is_dynamic(a_flag):
                    return [], [f"{exe_word}: dynamic option {a!r} cannot be statically fingerprinted"]
                if a in ("-V", "--version", "-h", "--help") and j + 1 == len(args):
                    return [], []
                if a in ("--quiet", "--silent", "--regexp-extended", "--separate", "--unbuffered", "--null-data", "--posix"):
                    j += 1
                    continue
                if a in ("-e", "--expression"):
                    if j + 1 >= len(args) or is_dynamic(args[j + 1][1]):
                        return [], [f"{exe_word} {a}: missing or dynamic expression cannot be fingerprinted"]
                    if args[j + 1][0] != "":
                        return [], [
                            f"{exe_word} {a}: non-empty inline sed expression cannot statically fingerprint external command/file targets; use -f <script>"
                        ]
                    j += 2
                    continue
                if a.startswith("--expression="):
                    if a.split("=", 1)[1] != "":
                        return [], [
                            f"{exe_word} {a}: non-empty inline sed expression cannot statically fingerprint external command/file targets; use -f <script>"
                        ]
                    j += 1
                    continue
                if a in ("-f", "--file"):
                    if j + 1 >= len(args) or is_dynamic(args[j + 1][1]) or not args[j + 1][0]:
                        return [], [f"{exe_word} {a}: missing or dynamic script file cannot be fingerprinted"]
                    files.append(norm_script(args[j + 1][0]))
                    j += 2
                    continue
                if a.startswith("--file="):
                    f_val = a.split("=", 1)[1]
                    if not f_val:
                        return [], [f"{exe_word} {a}: missing script file cannot be fingerprinted"]
                    files.append(norm_script(f_val))
                    j += 1
                    continue
                if a.startswith("--"):
                    return [], [f"{exe_word}: option {a!r} cannot be statically fingerprinted"]
                short = a[1:]
                # Attached `-e<expr>` or `-f<file>` (possibly preceded by zero-arg flags like `-ne<expr>`)
                k = 0
                while k < len(short) and short[k] in "nErsuz":
                    k += 1
                if k == len(short):
                    j += 1
                    continue
                rem = short[k:]
                if rem == "e":
                    if j + 1 >= len(args) or is_dynamic(args[j + 1][1]):
                        return [], [f"{exe_word} {a}: missing or dynamic expression cannot be fingerprinted"]
                    if args[j + 1][0] != "":
                        return [], [
                            f"{exe_word} {a}: non-empty inline sed expression cannot statically fingerprint external command/file targets; use -f <script>"
                        ]
                    j += 2
                    continue
                if rem.startswith("e"):
                    return [], [
                        f"{exe_word} {a}: non-empty inline sed expression cannot statically fingerprint external command/file targets; use -f <script>"
                    ]
                if rem == "f":
                    if j + 1 >= len(args) or is_dynamic(args[j + 1][1]) or not args[j + 1][0]:
                        return [], [f"{exe_word} {a}: missing or dynamic script file cannot be fingerprinted"]
                    files.append(norm_script(args[j + 1][0]))
                    j += 2
                    continue
                if rem.startswith("f"):
                    files.append(norm_script(rem[1:]))
                    j += 1
                    continue
                return [], [f"{exe_word} {a}: unsupported option cannot be statically fingerprinted"]
            if not files:
                return [], [
                    f"{exe_word}: inline sed script without -f cannot statically fingerprint external command/file targets"
                ]
            return files, []

        if base in ("awk", "gawk", "mawk", "nawk"):
            awk_files: list[str] = []
            j = 0
            while j < len(args):
                a, a_flag = args[j]
                if a == "--":
                    j += 1
                    break
                if not a.startswith("-") or a == "-":
                    break
                if is_dynamic(a_flag):
                    return [], [f"{exe_word}: dynamic option {a!r} cannot be statically fingerprinted"]
                if a in ("-V", "--version", "-h", "--help") and j + 1 == len(args):
                    return [], []
                if a in ("--posix", "--traditional", "--characters-as-bytes", "--sandbox", "--optimize"):
                    j += 1
                    continue
                if a in ("-F", "--field-separator", "-v", "--assign"):
                    if j + 1 >= len(args) or is_dynamic(args[j + 1][1]):
                        return [], [f"{exe_word} {a}: missing or dynamic option value cannot be fingerprinted"]
                    j += 2
                    continue
                if a.startswith(("-F", "-v", "--field-separator=", "--assign=")):
                    j += 1
                    continue
                if a in ("-e", "--source") or a.startswith(("-e", "--source=")):
                    return [], [
                        f"{exe_word} {a}: inline awk program cannot statically fingerprint external command/file targets; use -f <script>"
                    ]
                if a in ("-f", "--file"):
                    if j + 1 >= len(args) or is_dynamic(args[j + 1][1]) or not args[j + 1][0]:
                        return [], [f"{exe_word} {a}: missing or dynamic script file cannot be fingerprinted"]
                    awk_files.append(norm_script(args[j + 1][0]))
                    j += 2
                    continue
                if a.startswith("-f") and len(a) > 2:
                    awk_files.append(norm_script(a[2:]))
                    j += 1
                    continue
                if a.startswith("--file="):
                    f_val = a.split("=", 1)[1]
                    if not f_val:
                        return [], [f"{exe_word} {a}: missing script file cannot be fingerprinted"]
                    awk_files.append(norm_script(f_val))
                    j += 1
                    continue
                if not a.startswith("--") and all(c in "bcCdDgNnoOPrSt" for c in a[1:]):
                    j += 1
                    continue
                return [], [f"{exe_word} {a}: unsupported option cannot be statically fingerprinted"]
            if not awk_files:
                return [], [
                    f"{exe_word}: inline awk program without -f cannot statically fingerprint external command/file targets"
                ]
            return awk_files, []

        return [], []

    @classmethod
    def _extract_gate_executables(cls, gate_cmd: str, _depth: int = 0) -> list[str]:
        exes, sourced, _ = cls._analyze_gate_command(gate_cmd, _depth=_depth)
        return [
            *[x for x in exes if not x.startswith(("__func__:", "__opt_builtin__:", "__py_mod__:"))],
            *sourced,
        ]

    def _hash_rel_gate_file(self, rel_tok: str, cwd: Path | None, commit: str | None) -> tuple[str | None, str | None]:
        """Return `(sha256_hex, err)` for a repo-relative file in `cwd` (plan) or `commit` (plan_passed)."""
        norm_tok = Path(os.path.normpath(rel_tok)).as_posix()
        if os.path.isabs(rel_tok) or norm_tok in ("", ".") or ".." in Path(norm_tok).parts:
            return None, f"{rel_tok}: escapes gate checkout"
        if cwd is not None:
            cand = (cwd / norm_tok).resolve()
            cwd_real = cwd.resolve()
            if cand != cwd_real and cwd_real not in cand.parents:
                return None, f"{rel_tok}: escapes gate checkout"
            if not cand.is_file():
                return None, f"{rel_tok}: relative executable or script not found in gate checkout"
            try:
                return hashlib.sha256(cand.read_bytes()).hexdigest(), None
            except OSError as exc:
                return None, f"{rel_tok}: {exc}"
        if commit:
            try:
                proc = subprocess.run(
                    [self.git.bin, *self.git.HARDENED_CONFIG, "-C", self.git.repo_dir,
                     "cat-file", "blob", f"{commit}:{norm_tok}"],
                    capture_output=True, env=self.git.env, timeout=30,
                )
                if proc.returncode == 0:
                    return hashlib.sha256(proc.stdout).hexdigest(), None
            except (OSError, subprocess.SubprocessError) as exc:
                return None, f"{rel_tok}@{commit}: {exc}"
            return None, f"{rel_tok}: relative executable or script not found in commit {commit}"
        return None, f"{rel_tok}: relative executable or script requires gate checkout or commit context"

    def _read_sourced_gate_script(self, tok: str, cwd: Path | None, commit: str | None) -> str | None:
        if os.path.isabs(tok):
            p = Path(tok)
            if p.is_file():
                try:
                    return p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    return None
            return None
        if cwd is not None:
            cand = (cwd / tok).resolve()
            cwd_real = cwd.resolve()
            if (cand == cwd_real or cwd_real in cand.parents) and cand.is_file():
                try:
                    return cand.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    return None
            return None
        norm_tok = Path(os.path.normpath(tok)).as_posix()
        if commit and norm_tok not in ("", ".") and ".." not in Path(norm_tok).parts:
            try:
                proc = subprocess.run(
                    [self.git.bin, *self.git.HARDENED_CONFIG, "-C", self.git.repo_dir,
                     "cat-file", "blob", f"{commit}:{norm_tok}"],
                    capture_output=True, env=self.git.env, timeout=30,
                )
                if proc.returncode == 0:
                    return proc.stdout.decode("utf-8", errors="replace")
            except (OSError, subprocess.SubprocessError):
                return None
        return None

    def _gate_fingerprint(self, gate_cmd: str, cwd: Path | None = None,
                          commit: str | None = None, _depth: int = 0) -> tuple[str, list[str]]:
        if _depth > 4:
            return "", ["sourced script recursion depth exceeded"]
        clean_path = self._clean_gate_path()
        items: list[dict[str, Any]] = []
        exes, sourced, problems = self._analyze_gate_command(gate_cmd)
        for src in sourced:
            src_text = self._read_sourced_gate_script(src, cwd, commit)
            if src_text is None:
                problems.append(f"source {src}: script cannot be read for static executable analysis")
            else:
                sub_fp, sub_probs = self._gate_fingerprint(src_text, cwd=cwd, commit=commit, _depth=_depth + 1)
                problems.extend(sub_probs)
                items.append({"tok": f"source:{src}", "sub_fp": sub_fp})
        candidates = ["/bin/sh", *exes, *sourced]
        seen: set[str] = set()
        for tok in candidates:
            if tok in seen:
                continue
            seen.add(tok)
            if tok.startswith(("__func__:", "__opt_builtin__:")):
                fn_name = tok.split(":", 1)[1]
                shadow = shutil.which(fn_name, path=clean_path) if "/" not in fn_name else None
                if not shadow:
                    items.append({"tok": tok, "shadowed": None})
                    continue
                try:
                    s_real = os.path.realpath(shadow)
                    s_st = os.stat(s_real)
                    s_digest = hashlib.sha256(Path(s_real).read_bytes()).hexdigest()
                    items.append({
                        "tok": tok, "real": s_real, "dev": s_st.st_dev, "ino": s_st.st_ino, "sha256": s_digest,
                    })
                except OSError as exc:
                    problems.append(f"{fn_name}: {exc}")
                continue
            if tok.startswith("__py_mod__:"):
                mod_name = tok.split(":", 1)[1]
                mod_parts = mod_name.split(".")
                mod_rel = "/".join(mod_parts)
                py_digest, _ = self._hash_rel_gate_file(f"{mod_rel}.py", cwd, commit)
                main_digest, _ = self._hash_rel_gate_file(f"{mod_rel}/__main__.py", cwd, commit)
                self_init_digest, _ = self._hash_rel_gate_file(f"{mod_rel}/__init__.py", cwd, commit)
                if py_digest is None and main_digest is None:
                    problems.append(f"-m {mod_name}: module is not a regular file in gate checkout/commit")
                    items.append({"tok": tok, "resolved": None})
                    continue
                if main_digest is None and self_init_digest is not None:
                    problems.append(f"-m {mod_name}: package {mod_rel}/__init__.py shadows {mod_rel}.py without __main__.py")
                    items.append({"tok": tok, "resolved": None})
                    continue
                pkg_depth = len(mod_parts) if main_digest is not None else len(mod_parts) - 1
                mod_digests: dict[str, str] = {}
                if py_digest is not None:
                    mod_digests[f"{mod_rel}.py"] = py_digest
                if main_digest is not None:
                    mod_digests[f"{mod_rel}/__main__.py"] = main_digest
                pkg_missing = False
                for pk in range(1, pkg_depth + 1):
                    init_rel = f"{'/'.join(mod_parts[:pk])}/__init__.py"
                    init_digest, _ = self._hash_rel_gate_file(init_rel, cwd, commit)
                    if init_digest is None:
                        problems.append(f"-m {mod_name}: missing package {init_rel} in gate checkout/commit")
                        pkg_missing = True
                        break
                    mod_digests[init_rel] = init_digest
                if not pkg_missing:
                    items.append({"tok": tok, "kind": "py_mod", "files": mod_digests})
                continue
            resolved: str | None
            if "/" in tok and not os.path.isabs(tok):
                norm_tok = Path(os.path.normpath(tok)).as_posix()
                rel_digest, rel_err = self._hash_rel_gate_file(tok, cwd, commit)
                if rel_err:
                    problems.append(rel_err)
                items.append({"tok": norm_tok, "kind": "relative", "sha256": rel_digest})
                continue
            resolved = tok if os.path.isabs(tok) else shutil.which(tok, path=clean_path)
            if not resolved:
                problems.append(f"{tok}: executable could not be resolved on gate PATH")
                items.append({"tok": tok, "resolved": None})
                continue
            try:
                real = os.path.realpath(resolved)
                st = os.stat(real)
                digest = hashlib.sha256(Path(real).read_bytes()).hexdigest()
                items.append({
                    "tok": tok,
                    "real": real,
                    "dev": st.st_dev,
                    "ino": st.st_ino,
                    "sha256": digest,
                })
            except OSError as exc:
                problems.append(f"{tok}: {exc}")
                items.append({"tok": tok, "error": str(exc)})
        if problems:
            return "", problems
        payload = json.dumps({"path": clean_path, "items": items}, sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload).hexdigest(), problems

    @staticmethod
    @functools.lru_cache(maxsize=1)
    def _bwrap_mode() -> tuple[str, tuple[str, ...]] | None:
        bw = shutil.which("bwrap")
        if not bw:
            return None
        for flags in (
            ("--unshare-all",),
            ("--unshare-pid", "--unshare-ipc", "--unshare-uts"),
        ):
            try:
                r = subprocess.run(
                    [bw, *flags, "--ro-bind", "/", "/", "--proc", "/proc", "/bin/true"],
                    capture_output=True, timeout=5, stdin=subprocess.DEVNULL,
                )
                if r.returncode == 0:
                    return bw, flags
            except (OSError, subprocess.SubprocessError):
                continue
        return None

    @classmethod
    def _bwrap_bin(cls) -> str | None:
        mode = cls._bwrap_mode()
        return mode[0] if mode is not None else None

    @staticmethod
    @functools.lru_cache(maxsize=1)
    def _unshare_mount_proc_argv() -> tuple[str, ...] | None:
        un = shutil.which("unshare")
        if not un:
            return None
        for map_flag in ("--map-current-user", "--map-root-user"):
            argv = (un, "--user", map_flag, "--pid", "--mount", "--fork", "--mount-proc")
            try:
                r = subprocess.run(
                    [*argv, "/bin/true"],
                    capture_output=True, timeout=5, stdin=subprocess.DEVNULL,
                )
                if r.returncode == 0:
                    return argv
            except (OSError, subprocess.SubprocessError):
                continue
        return None

    @staticmethod
    @functools.lru_cache(maxsize=1)
    def _unshare_hidepid_argv() -> tuple[str, ...] | None:
        """Unprivileged user+PID namespace where kernel `hidepid=2`/`invisible` hides all outside PIDs."""
        un = shutil.which("unshare")
        if not un:
            return None
        argv = (un, "--user", "--pid", "--fork")
        probe = (
            "import os,sys; "
            "outside=any(os.path.exists(f'/proc/{p}') for p in sys.argv[1:] if int(p) > 1); "
            "sys.exit(0 if (os.getpid() == 1 and not outside) else 1)"
        )
        try:
            r = subprocess.run(
                [*argv, sys.executable, "-I", "-c", probe, str(os.getpid()), str(os.getppid())],
                capture_output=True, timeout=5, stdin=subprocess.DEVNULL,
            )
            return argv if r.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            return None

    @classmethod
    def _has_native_gate_isolation(cls, *, require_full_sandbox: bool = False) -> bool:
        if cls._bwrap_mode() is not None or cls._unshare_mount_proc_argv() is not None:
            return True
        if not require_full_sandbox and cls._unshare_hidepid_argv() is not None:
            return True
        return False

    @staticmethod
    @contextlib.contextmanager
    def _non_dumpable_conductor():
        """Mark the conductor non-dumpable (`PR_SET_DUMPABLE=0`) on Linux while gate code executes."""
        prev: int | None = None
        libc: Any = None
        if sys.platform.startswith("linux"):
            with contextlib.suppress(Exception):
                import ctypes
                libc = ctypes.CDLL(None)
                got = libc.prctl(3, 0, 0, 0, 0)  # PR_GET_DUMPABLE
                if got >= 0:
                    prev = int(got)
                    libc.prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE = 0
        try:
            yield
        finally:
            if libc is not None and prev is not None and prev != 0:
                with contextlib.suppress(Exception):
                    libc.prctl(4, prev, 0, 0, 0)

    def _conductor_state_digest(self) -> str:
        """Digest conductor SQLite state + git refs so same-UID gate tampering fails closed."""
        db_rows = {
            t: self.store.read(f"SELECT * FROM {t}")
            for t in ("mq_queues", "mq_leases", "mq_tokens", "mq_entries", "mq_receipts")
        }
        refs = self.git.out("for-each-ref", "--format=%(refname) %(objectname)")
        return _digest(db_rows, refs)

    _BWRAP_SYS_DIRS: tuple[str, ...] = ("/usr", "/bin", "/lib", "/lib64", "/sbin", "/etc", "/opt")

    def _gate_exec_argv(self, gate_cmd: str, checkout: Path, gate_home: Path,
                        gate_tmp: Path) -> list[str]:
        req_sbx = (
            self.env.get("MQ_REQUIRE_GATE_SANDBOX")
            or self.env.get("OPEN_FLEET_REQUIRE_GATE_SANDBOX")
            or ""
        ).strip().lower() in ("1", "true", "yes")
        custom_sbx = (
            self.env.get("MQ_GATE_SANDBOX_CMD")
            or self.env.get("OPEN_FLEET_GATE_SANDBOX_CMD")
            or ""
        ).strip()
        if custom_sbx:
            return [*shlex.split(custom_sbx), "/bin/sh", "-c", gate_cmd]
        bw_mode = self._bwrap_mode()
        if bw_mode is not None:
            bw, ns_flags = bw_mode
            cmd = [bw, *ns_flags, "--die-with-parent", "--proc", "/proc", "--dev", "/dev"]
            sys_dirs = self._BWRAP_SYS_DIRS
            bound_ro: set[str] = set()
            raw_forbidden = {
                "/", "/root", "/home", "/Users", "/tmp", "/var", "/var/tmp", "/proc", "/sys", "/dev", "/run",
            }
            forbidden_roots: set[str] = set()
            for r in raw_forbidden:
                forbidden_roots.add(os.path.normpath(r))
                if os.path.exists(r):
                    forbidden_roots.add(os.path.realpath(r))
            strict_subtrees = tuple(
                os.path.realpath(r) if os.path.exists(r) else r
                for r in ("/root", "/proc", "/sys", "/dev", "/run")
            )
            sensitive_ancestors: set[str] = set()
            forbidden_subtrees: list[str] = list(strict_subtrees)

            def _mark_sensitive(raw_p: str, *, forbid_subtree: bool) -> None:
                norm_p = os.path.normpath(raw_p)
                if not norm_p or norm_p in (".", "/"):
                    return
                real_p = os.path.realpath(norm_p)
                for cand_p in (norm_p, real_p):
                    forbidden_roots.add(cand_p)
                    sensitive_ancestors.add(cand_p)
                    if forbid_subtree:
                        forbidden_subtrees.append(cand_p)

            orig_home = os.path.normpath(self.env.get("HOME") or "")
            if orig_home and orig_home != ".":
                _mark_sensitive(orig_home, forbid_subtree=False)
                orig_home_real = os.path.realpath(orig_home)
                for cred_sub in (
                    ".ssh", ".gnupg", ".aws", ".config", ".kube", ".docker",
                    ".codex", ".claude", ".gemini", ".netrc", ".git-credentials",
                    ".npmrc", ".pypirc", ".pgpass",
                ):
                    _mark_sensitive(os.path.join(orig_home_real, cred_sub), forbid_subtree=True)
            for env_cred_dir in ("XDG_CONFIG_HOME", "GH_CONFIG_DIR", "DOCKER_CONFIG", "GNUPGHOME"):
                val_d = (self.env.get(env_cred_dir) or "").strip()
                if val_d and os.path.isabs(val_d):
                    _mark_sensitive(val_d, forbid_subtree=True)
            for env_cred_file in ("AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "NETRC", "NPM_CONFIG_USERCONFIG"):
                val_f = (self.env.get(env_cred_file) or "").strip()
                if val_f and os.path.isabs(val_f):
                    _mark_sensitive(val_f, forbid_subtree=True)
            for kc_part in (self.env.get("KUBECONFIG") or "").split(os.pathsep):
                kc_part = kc_part.strip()
                if kc_part and os.path.isabs(kc_part):
                    _mark_sensitive(kc_part, forbid_subtree=True)
            _mark_sensitive(str(Path(self.git.repo_dir).resolve()), forbid_subtree=True)
            store_path = getattr(self.store, "path", None)
            if store_path:
                _mark_sensitive(str(Path(store_path).resolve().parent), forbid_subtree=True)

            def _directly_forbidden(norm_s: str, real_s: str) -> bool:
                if not real_s or norm_s in forbidden_roots or real_s in forbidden_roots:
                    return True
                for p in (norm_s, real_s):
                    if any(p == sa for sa in sensitive_ancestors):
                        return True
                    if any(p == sub or p.startswith(sub.rstrip("/") + "/") for sub in forbidden_subtrees):
                        return True
                return False

            def _forbidden_bind_source(src: str) -> bool:
                norm_s = os.path.normpath(src)
                try:
                    real_s = os.path.realpath(norm_s)
                except OSError:
                    return True
                if _directly_forbidden(norm_s, real_s):
                    return True
                norm_slash = norm_s.rstrip("/") + "/"
                real_slash = real_s.rstrip("/") + "/"
                if any(sa.startswith(norm_slash) or sa.startswith(real_slash) for sa in sensitive_ancestors):
                    return True
                return False

            def _collect_safe_sys_binds(src: str, depth: int = 0) -> list[str]:
                norm_s = os.path.normpath(src)
                if not os.path.exists(norm_s):
                    return []
                try:
                    real_s = os.path.realpath(norm_s)
                except OSError:
                    return []
                if _directly_forbidden(norm_s, real_s):
                    return []
                if not _forbidden_bind_source(norm_s):
                    return [norm_s]
                if depth >= 6 or os.path.islink(norm_s) or not os.path.isdir(norm_s):
                    return []
                try:
                    entries = sorted(os.listdir(norm_s))
                except OSError:
                    return []
                if len(entries) > 4096:
                    return []
                out_binds: list[str] = []
                for entry in entries:
                    out_binds.extend(_collect_safe_sys_binds(os.path.join(norm_s, entry), depth + 1))
                return out_binds

            for sys_dir in sys_dirs:
                for safe_b in _collect_safe_sys_binds(sys_dir):
                    if safe_b not in bound_ro:
                        bound_ro.add(safe_b)
                        cmd += ["--ro-bind", safe_b, safe_b]

            for extra_dir in self._clean_gate_path().split(os.pathsep):
                norm_extra = os.path.normpath(extra_dir)
                if not norm_extra or not os.path.isabs(norm_extra) or not os.path.exists(norm_extra):
                    continue
                if any(norm_extra == d or norm_extra.startswith(d.rstrip("/") + "/") for d in bound_ro):
                    continue
                if _forbidden_bind_source(norm_extra):
                    continue
                to_bind = [norm_extra]
                if norm_extra.endswith("/bin"):
                    prefix = os.path.dirname(norm_extra)
                    if prefix and not _forbidden_bind_source(prefix):
                        real_prefix_slash = os.path.realpath(prefix).rstrip("/") + "/"
                        for sub in ("lib", "lib64", "libexec", "share"):
                            cand_sub = os.path.join(prefix, sub)
                            if (
                                os.path.exists(cand_sub)
                                and not _forbidden_bind_source(cand_sub)
                                and os.path.realpath(cand_sub).startswith(real_prefix_slash)
                            ):
                                to_bind.append(cand_sub)
                for bpath in to_bind:
                    if bpath not in bound_ro and not _forbidden_bind_source(bpath):
                        bound_ro.add(bpath)
                        cmd += ["--ro-bind", bpath, bpath]
            cmd += [
                "--bind", str(checkout), str(checkout),
                "--bind", str(gate_home), str(gate_home),
                "--bind", str(gate_tmp), str(gate_tmp),
                "--chdir", str(checkout),
                "/bin/sh", "-c", gate_cmd,
            ]
            return cmd
        un_mp = self._unshare_mount_proc_argv()
        if un_mp is not None and not req_sbx:
            return [*un_mp, "/bin/sh", "-c", gate_cmd]
        if not req_sbx:
            un_hp = self._unshare_hidepid_argv()
            if un_hp is not None:
                return [*un_hp, "/bin/sh", "-c", gate_cmd]
        raise QueueError(
            "sandbox_unavailable",
            "gate execution requires bubblewrap (bwrap), unshare with isolated /proc, or MQ_GATE_SANDBOX_CMD; "
            "refusing to execute gate with conductor /proc exposed",
        )

    def _run_gate(self, gate_cmd: str, commit: str, e: dict[str, Any], timeout: float) -> dict[str, Any]:
        tmp = tempfile.mkdtemp(prefix="mq-gate-")
        os.chmod(tmp, 0o700)
        checkout = Path(tmp) / "prefix"
        gate_home = Path(tmp) / "home"
        gate_tmp = Path(tmp) / "tmp"
        gate_home.mkdir(mode=0o700)
        gate_tmp.mkdir(mode=0o700)
        try:
            # Isolated object copy (`git init` + direct `fetch` of `commit`), never `--shared` or a
            # worktree of the conductor's clone, with `.git/FETCH_HEAD` removed so the gate checkout
            # carries neither `.git/objects/info/alternates` nor `remote.origin.url` nor `FETCH_HEAD`
            # pointing at the conductor's repo (C21).
            self.git.run("init", "--quiet", str(checkout))
            self.git.run("fetch", "--quiet", "--no-tags", self.git.repo_dir, commit, cwd=str(checkout))
            self.git.run("checkout", "--quiet", "--detach", commit, cwd=str(checkout))
            (checkout / ".git" / "FETCH_HEAD").unlink(missing_ok=True)
            env = self._gate_env(e, commit, gate_home=gate_home, gate_tmp=gate_tmp)
            pre_fp, pre_problems = self._gate_fingerprint(gate_cmd, cwd=checkout)
            plan_fp, plan_problems = self._gate_fingerprint(gate_cmd, commit=commit)
            pre_state = self._conductor_state_digest()
            exec_argv = self._gate_exec_argv(gate_cmd, checkout, gate_home, gate_tmp)
            if pre_problems or plan_problems:
                why = "; ".join(pre_problems or plan_problems)
                return {
                    "cmd": gate_cmd,
                    "exit": 1,
                    "tail": f"[C19: {why}]"[-500:],
                    "commit": commit,
                    "fingerprint": "",
                }
            # Its own session, so a timeout kills everything the gate started: a grandchild left
            # holding the output pipe would otherwise stretch the timeout to its own lifetime.
            with self._non_dumpable_conductor():
                proc = subprocess.Popen(exec_argv, cwd=checkout, env=env, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                        close_fds=True, start_new_session=True)
                try:
                    out, _ = proc.communicate(timeout=timeout)
                    code, tail = proc.returncode, (out or "")[-500:]
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(proc.pid, signal.SIGKILL)
                    proc.communicate()
                    code, tail = 124, f"gate timed out after {timeout}s"
            post_fp, post_problems = self._gate_fingerprint(gate_cmd, cwd=checkout)
            post_plan_fp, post_plan_problems = self._gate_fingerprint(gate_cmd, commit=commit)
            post_state = self._conductor_state_digest()
            if (pre_problems or post_problems or plan_problems or post_plan_problems
                    or pre_fp != post_fp or plan_fp != post_plan_fp):
                code = 1 if code == 0 else code
                tail = (tail + "\n[C19: gate executable changed during gate execution]")[-500:]
            if pre_state != post_state:
                code = 1 if code == 0 else code
                tail = (tail + "\n[C21: conductor state modified during gate execution]")[-500:]
            return {"cmd": gate_cmd, "exit": code, "tail": tail, "commit": commit, "fingerprint": post_plan_fp}
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def plan_passed(self, e: dict[str, Any], gate_cmd: str | None) -> bool:
        """Whether the entry's saved plan covers this request: a tested merge tree and, when a gate
        is asked for, THAT gate passed on THAT prefix commit with the same resolved executable
        fingerprint (PR #647, C19)."""
        if not e.get("tested_tree"):
            return False
        if gate_cmd is None:
            return True
        try:
            gate = json.loads(e.get("gate_json") or "null")
        except ValueError:
            return False
        if not (isinstance(gate, dict) and gate.get("cmd") == gate_cmd and gate.get("exit") == 0
                and bool(e.get("prefix_commit")) and gate.get("commit") == e.get("prefix_commit")):
            return False
        saved_fp = gate.get("fingerprint")
        if not isinstance(saved_fp, str) or not saved_fp:
            return False
        current_fp, problems = self._gate_fingerprint(gate_cmd, commit=e.get("prefix_commit"))
        if problems or saved_fp != current_fp:
            return False
        return True

    def merge(self, token: str, *, entry_id: str | None = None, delete_branch: bool = True,
              require_gate: str | None = None) -> dict[str, Any]:
        """Merge the head of the train, once, behind every guard (merge-serialization.md steps 2-4).

        `require_gate` refuses a head whose saved plan did not pass exactly that gate command.
        """
        self.settle_in_flight(token)
        cfg, lease = self._owner(token)
        repo, base = cfg["repo"], cfg["base"]
        head = self._guard_head(self._line(repo, base), entry_id)
        if head is None:
            return {"ok": True, "result": "empty"}
        if not head["tested_tree"]:
            raise QueueError("untested", f"{head['entry_id']} has no tested merge tree: run plan first",
                             {"entry": head["entry_id"]})
        if not self.plan_passed(head, require_gate):
            raise QueueError("gate_not_run", f"{head['entry_id']}'s saved plan did not pass the required gate "
                             f"{require_gate!r}: run plan --gate-cmd with it first",
                             {"entry": head["entry_id"], "required": require_gate,
                              "saved": json.loads(head["gate_json"] or "null")})
        info = {"entry": head["entry_id"], "unit": head["unit"], "pr": head["pr"], "epoch": lease["epoch"],
                "pid": os.getpid()}
        self._boundary("lease_checked", info)
        lock = self._lock(repo, base)
        try:
            if not lock.acquire(30.0):
                raise QueueError("merge_in_flight", "another process holds the merge boundary")
            return self._merge_locked(token, cfg, head, lock, info, delete_branch)
        finally:
            lock.release()

    def _merge_locked(self, token: str, cfg: dict[str, Any], e: dict[str, Any], lock: EffectLock,
                      info: dict[str, Any], delete_branch: bool) -> dict[str, Any]:
        repo, base = cfg["repo"], cfg["base"]
        # Revalidate against authoritative state (#599): the tested prefix and both expected heads.
        try:
            base_head = self._base_head(cfg)
            st = self._unit_state(cfg, e)
        except Offline as exc:
            self._record(token, cfg, e, "offline", {"step": "revalidate", "message": exc.message})
            raise
        if self.git.tree(base_head) != e["tested_base_tree"]:
            return self._retest(token, cfg, e, "base_moved", {"baseHead": base_head})
        if st["state"] == "MERGED":
            return self._fail(token, cfg, e, "merged_outside_queue", {"mergeCommit": st["mergeCommit"]})
        why = self._bounce_reason(cfg, e, st)
        accepted, how = (None, why) if why else self._fresh_head(e, st["head"])
        if accepted is None:
            return self._bounce(token, cfg, e, how, {"head": st["reported"], "reviewedSha": e["reviewed_sha"]})
        pred = self._predict(e, base_head, accepted)
        if not pred["clean"] or pred["tree_oid"] != e["tested_tree"]:
            return self._retest(token, cfg, e, "merge_tree_changed",
                                {"baseHead": base_head, "acceptedHead": accepted, "tree": pred["tree_oid"]})
        local_merge = None
        if cfg["mode"] == "git":
            # Built before the intent is recorded: a failure here leaves nothing in flight. Its
            # tree is the TESTED tree by construction, so the git lane merges exactly what was tested.
            local_merge = self.git.commit_tree(
                e["tested_tree"], [base_head, accepted],
                f"Merge {e['branch']} into {base} (merge queue {e['entry_id']}, unit {e['unit']})")
            self.git.keep(f"entry/{e['entry_id']}/merge", local_merge)
        # The fenced compare-and-set: the merge intent is recorded under THIS conductor's token,
        # inside the effect lock. A conductor taken over since its lease check stops here.
        now = self.clock()
        teardown = ("delete" if delete_branch else "keep") if cfg["mode"] == "gh" else None
        with self.store.tx() as conn:
            lease = self._fence(conn, token)
            # The compare-and-set binds the plan validated above: the tested tree and the gate record
            # (a concurrent re-plan by this owner changes one of them, and the write is refused).
            cur = conn.execute("UPDATE mq_entries SET state = ?, accepted_head = ?, expected_base = ?, merging_epoch = ?, "
                               "merging_pid = ?, teardown = ?, updated_at = ? WHERE entry_id = ? AND state = ? "
                               "AND tested_tree = ? AND COALESCE(gate_json, '') = ?",
                               (MERGING, accepted, base_head, lease["epoch"], os.getpid(), teardown, now, e["entry_id"],
                                QUEUED, e["tested_tree"], e["gate_json"] or ""))
            if cur.rowcount != 1:
                raise QueueError("queue_changed", f"{e['entry_id']} is no longer queued as it was validated")
            self._receipt(conn, repo, base, "merge_intent", {"acceptedHead": accepted, "how": how, "expectedBase": base_head,
                                                             "testedTree": e["tested_tree"], "mode": cfg["mode"],
                                                             "localMerge": local_merge, "repository": cfg["repo"]},
                          e["entry_id"], lease)
        e = {**e, "state": MERGING, "accepted_head": accepted, "expected_base": base_head, "teardown": teardown}
        try:
            receipt_id = self._egress(cfg, e, token)
        except egress.EgressError as exc:
            with self.store.tx() as conn:
                lease = self._fence(conn, token)
                conn.execute("UPDATE mq_entries SET state = ?, updated_at = ? WHERE entry_id = ? AND state = ?",
                             (QUEUED, self.clock(), e["entry_id"], MERGING))
                self._receipt(conn, repo, base, "egress_refused", {"message": str(exc)}, e["entry_id"], lease)
            raise QueueError("egress_failed", f"the egress receipt could not be written, so nothing was sent: {exc}") from exc
        self._boundary("intent_recorded", info)
        sent, detail = self._send(cfg, e, lock, delete_branch, local_merge)
        if sent:
            self._boundary("remote_merged", info)
        decision = self._reconcile_decision(cfg, e)
        if decision["resolution"] == "requeued":
            # The remote refused or never applied it. Re-read why before deciding the train's fate.
            try:
                decision = self._refusal(cfg, e, detail)
            except Offline as exc:
                decision = {**decision, "resolution": "unknown", "reason": exc.message}
        with self.store.tx() as conn:
            lease = self._fence(conn, token)
            self._apply_reconcile(conn, cfg, {**decision, "send": detail}, lease)
            if decision["resolution"] in ("requeued", "failed"):
                self._clear_tested(conn, repo, base, 0 if decision["resolution"] == "requeued" else e["seq"])
        if decision["resolution"] == "merged":
            self._boundary("merged_recorded", info)
            branch = self._teardown_branch(token, cfg, e, lock)
            return {"ok": True, "result": "merged", "entry": e["entry_id"], "unit": e["unit"], **decision,
                    "noGh": cfg["mode"] == "git", "branch": branch, "egressReceipt": receipt_id}
        if decision["resolution"] == "unknown":
            raise QueueError("merge_outcome_unknown", "the merge was sent but its outcome cannot be read yet; it is "
                             "reconciled before anything else merges", decision)
        raise QueueError("merge_refused" if decision["resolution"] == "failed" else "retest_required",
                         f"{e['entry_id']} did not merge: {decision.get('reason')}", decision)

    def _teardown_decide(self, cfg: dict[str, Any], e: dict[str, Any]) -> dict[str, Any]:
        """Whether the merged unit's head branch may be deleted, from GitHub's own report. Writes nothing.

        Only when GitHub reports THIS PR merged into BASE (a PR retargeted elsewhere stays open,
        and deleting its head would close it), only when its head branch lives in the queue's own
        repository (a fork's branch is never touched, and a same-named branch in the queue's
        repository is not the PR's: PR #647), and only that branch. A PR GitHub has not yet
        marked merged is `final: False`: the teardown stays owed and is retried.
        """
        st = self._unit_state(cfg, e)
        out = {"branch": e["branch"], "headRepository": st.get("headRepository"), "delete": False, "final": True}
        if st["state"] == "OPEN" and st["baseRefName"] == cfg["base"]:
            return {**out, "final": False, "outcome": "pending: GitHub has not marked the PR merged yet"}
        if st["state"] != "MERGED" or st["baseRefName"] != cfg["base"]:
            return {**out, "outcome": f"retained: PR is {st['state'].lower()} on {st['baseRefName']}"}
        head_repo = st.get("headRepository")
        if head_repo is None:
            return {**out, "outcome": "retained: GitHub reported no head repository"}
        if st.get("crossRepository") or self.normalize(head_repo) != cfg["repo"]:
            return {**out, "outcome": "retained: head branch in a fork"}
        if st.get("headRefName") != e["branch"]:
            return {**out, "outcome": "retained: the PR's head branch is not the entry's branch"}
        return {**out, "delete": True, "outcome": "delete"}

    def _teardown_branch(self, token: str, cfg: dict[str, Any], e: dict[str, Any], lock: EffectLock) -> str:
        """Carry out the entry's persisted teardown request, once. Never fails the merge.

        `keep` (the merge's --keep-branch) records that the branch was kept. `delete` deletes the
        head branch when `_teardown_decide` allows it. The deletion is an off-repo write like the
        merge: fenced first (a conductor taken over never deletes), egress-receipted before it is
        sent, aimed at the bound remote, and a compare-and-swap on the merged head, so a branch
        moved since is kept for re-review. A final outcome is written once, with a
        `branch_teardown` receipt. A transient one (GitHub not caught up, offline) leaves the
        request owed for `retry_teardowns`.
        """
        request = e.get("teardown")
        if request not in ("delete", "keep", "deleting"):
            return request or "retained: no teardown requested"
        d: dict[str, Any] = {"branch": e["branch"], "headRepository": None, "final": True,
                             "outcome": "kept: --keep-branch"}
        if request == "deleting":
            # Claimed by a command that never recorded the outcome (it died: the lock it shared with
            # its push is free, so that push has ended). Whether it was sent is unknown, and a
            # branch at the same commit may be a recreated one: it is never sent again.
            try:
                now = self.git.fetch(self._bound_remote(cfg), f"refs/heads/{e['branch']}", f"teardown/{e['branch']}")
                d["outcome"] = ("gone: deleted elsewhere" if now is None
                                else "retained: an earlier deletion's outcome is unknown and the branch exists")
            except QueueError as exc:
                d.update(final=False, outcome=f"pending: {exc.code}")
        elif request == "delete":
            try:
                d = self._teardown_decide(cfg, e)
                if d["delete"]:
                    d["outcome"], d["final"], claimed = self._delete_branch(token, cfg, e, lock)
                    request = claimed or request
            except egress.EgressError as exc:
                d.update(final=False, outcome=f"pending: no egress receipt ({exc})")
            except QueueError as exc:
                if exc.exit_code == EXIT_FENCED:
                    raise
                d.update(final=False, outcome=f"pending: {exc.code}")
        if not d.pop("final"):
            return d["outcome"]
        d.pop("delete", None)
        with self.store.tx() as conn:
            lease = self._fence(conn, token)
            cur = conn.execute("UPDATE mq_entries SET teardown = ?, updated_at = ? WHERE entry_id = ? AND teardown = ?",
                               (d["outcome"], self.clock(), e["entry_id"], request))
            if cur.rowcount == 1:
                self._receipt(conn, cfg["repo"], cfg["base"], "branch_teardown", d, e["entry_id"], lease)
        return d["outcome"]

    def _claim_deletion(self, token: str, e: dict[str, Any], frm: str, to: str) -> bool:
        """Move the entry's teardown from `frm` to `to` in ONE fenced transaction that re-reads it.

        `delete` -> `deleting` is the claim before a send: only one command can win it, and only
        while the entry is still merged or landed and the deletion still owed (PR #647).
        """
        with self.store.tx() as conn:
            self._fence(conn, token)
            cur = conn.execute("UPDATE mq_entries SET teardown = ?, updated_at = ? WHERE entry_id = ? AND teardown = ? "
                               "AND state IN (?, ?)", (to, self.clock(), e["entry_id"], frm, MERGED, LANDED))
        return cur.rowcount == 1

    def _delete_branch(self, token: str, cfg: dict[str, Any], e: dict[str, Any],
                       lock: EffectLock) -> tuple[str, bool, str | None]:
        """(outcome, final, the teardown state to record it from) of the merged head's deletion.

        Called only with the effect lock held, and the push inherits it (`pass_fds`), as the
        merge's send does: a conductor killed mid-deletion holds the boundary until its push
        ends, so no handoff completes under a deletion still in flight. The deletion is claimed
        (`delete` -> `deleting`, fenced) immediately before the receipt and the send; a command
        that loses the claim sends nothing (PR #647).
        """
        remote = self._bound_remote(cfg)
        if lock.fd is None:
            raise QueueError("merge_in_flight", "a branch deletion needs the held merge boundary")
        if not self._claim_deletion(token, e, "delete", "deleting"):
            return "skipped: another command already owns or finished this deletion", False, None
        body = json.dumps({"repo": cfg["repo"], "branch": e["branch"], "head": e["accepted_head"]},
                          sort_keys=True).encode()
        try:
            self._egress_receipt(token, cfg, e, "branch-delete", body)
        except egress.EgressError:
            self._claim_deletion(token, e, "deleting", "delete")  # nothing was sent: still owed
            raise
        proc = self.git.run("push", "--porcelain", f"--force-with-lease=refs/heads/{e['branch']}:{e['accepted_head']}",
                            remote, f":refs/heads/{e['branch']}", check=False, pass_fds=(lock.fd,))
        if proc.returncode == 0:
            return "deleted", True, "deleting"
        now = self.git.fetch(remote, f"refs/heads/{e['branch']}", f"teardown/{e['branch']}")
        if now is None:
            return "gone: deleted elsewhere", True, "deleting"
        if now != e["accepted_head"]:
            return f"retained: branch moved to {now}", True, "deleting"
        self._claim_deletion(token, e, "deleting", "delete")  # refused and still there: owed again
        return f"pending: deletion refused ({proc.stderr.strip()[-120:]})", False, None

    def _refusal(self, cfg: dict[str, Any], e: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
        """A send that did not land: a moved head or BASE returns to plan; anything else freezes."""
        base_head = self._base_head(cfg)
        moved_base = base_head != e["expected_base"]
        moved_head = False
        if cfg["mode"] == "gh":
            moved_head = self._unit_state(cfg, e)["reported"] != e["accepted_head"]
        out = {"entry": e["entry_id"], "unit": e["unit"], "acceptedHead": e["accepted_head"], "expectedBase": e["expected_base"]}
        if moved_base or moved_head:
            return {**out, "resolution": "requeued", "reason": "base_moved" if moved_base else "head_moved"}
        return {**out, "resolution": "failed", "reason": "merge_refused", "stderr": detail.get("stderr", "")[-300:]}

    def _send(self, cfg: dict[str, Any], e: dict[str, Any], lock: EffectLock, delete_branch: bool,
              local_merge: str | None) -> tuple[bool, dict[str, Any]]:
        """The remote merge, with the effect lock inherited by the child that performs it."""
        fds = (lock.fd,) if lock.fd is not None else ()
        remote = self._bound_remote(cfg)  # re-proved at the send: the push URL is read here
        if cfg["mode"] == "gh":
            try:
                proc = self.gh.merge_into(
                    cfg["repo"], cfg["base"], e["accepted_head"],
                    f"Merge PR #{e['pr']} ({e['branch']}) into {cfg['base']} "
                    f"(merge queue {e['entry_id']}, unit {e['unit']})", fds)
            except Offline as exc:  # never sent, or sent with no answer: reconcile decides which
                return False, {"exit": None, "stderr": exc.message}
        else:
            proc = self.git.run("push", "--porcelain", f"--force-with-lease=refs/heads/{cfg['base']}:{e['expected_base']}",
                                remote, f"{local_merge}:refs/heads/{cfg['base']}", check=False, pass_fds=fds)
        return proc.returncode == 0, {"exit": proc.returncode, "stderr": (proc.stderr or "")[-300:]}

    def _egress(self, cfg: dict[str, Any], e: dict[str, Any], token: str) -> str:
        """egress.py's fail-closed receipt, appended BEFORE the send (#368); returns its id."""
        body = json.dumps({"repo": cfg["repo"], "base": cfg["base"], "entry": e["entry_id"], "pr": e["pr"],
                           "head": e["accepted_head"], "expectedBase": e["expected_base"]}, sort_keys=True).encode()
        return self._egress_receipt(token, cfg, e, "pr-merge" if cfg["mode"] == "gh" else "base-push", body)

    def _egress_receipt(self, token: str, cfg: dict[str, Any], e: dict[str, Any], payload_class: str,
                        body: bytes) -> str:
        """Write one egress receipt, then keep its id OFF the ledger: in this queue's own store (an
        `egress_receipt` receipt, which `receipts` lists) and on stderr. An id that never leaves the
        ledger binds nothing: a receipt rewritten after the last close, id recomputed, verified
        clean against every anchor a close held (2026-10-27 re-attack, W5-05). A ledger routed by
        $OPEN_FLEET_EGRESS_LEDGER / $ORCA_EGRESS_LEDGER is said too, never silent (W5-03)."""
        explicit = self.env.get(egress.PRIMARY_LEDGER_ENV) or self.env.get(egress.LEDGER_ENV)
        # The ledger egress.py's own default picks from here (the repository root's, refusing under
        # a nested `.git`), never `<--repo-dir>/.orca`: --repo-dir defaults to the working directory,
        # and a queue run from a subdirectory receipted where no close looks (W5-03).
        default, _source = egress.default_ledger(self.repo_dir)
        path = Path(os.path.abspath(explicit)) if explicit else default
        record = egress.write_receipt(path, "merge-queue", cfg["host"], payload_class, cfg["consent"],
                                      nbytes=len(body), payload_sha256=hashlib.sha256(body).hexdigest())
        if explicit:
            print(f"merge_queue: egress receipt written to {path} (from the environment), not the repository "
                  f"ledger {default}", file=sys.stderr)
        print(f"merge_queue: egress receipt {record['id']} ({payload_class}, {e['entry_id']}) in {path}",
              file=sys.stderr)
        with self.store.tx() as conn:
            lease = self._fence(conn, token)
            self._receipt(conn, cfg["repo"], cfg["base"], "egress_receipt",
                          {"id": record["id"], "payloadClass": payload_class, "ledger": str(path),
                           "routed": bool(explicit)}, e["entry_id"], lease)
        return record["id"]

    def _record(self, token: str, cfg: dict[str, Any], e: dict[str, Any], kind: str, body: dict[str, Any]) -> None:
        with self.store.tx() as conn:
            lease = self._fence(conn, token)
            self._receipt(conn, cfg["repo"], cfg["base"], kind, body, e["entry_id"], lease)

    def _retest(self, token: str, cfg: dict[str, Any], e: dict[str, Any], reason: str, body: dict[str, Any]) -> dict[str, Any]:
        with self.store.tx() as conn:
            lease = self._fence(conn, token)
            self._clear_tested(conn, cfg["repo"], cfg["base"])
            self._receipt(conn, cfg["repo"], cfg["base"], "retest_required", {"reason": reason, **body}, e["entry_id"], lease)
        raise QueueError("retest_required", f"{e['entry_id']}: {reason}; the tested prefix is stale, plan again",
                         {"entry": e["entry_id"], "reason": reason, **body})

    def _bounce(self, token: str, cfg: dict[str, Any], e: dict[str, Any], reason: str, body: dict[str, Any]) -> dict[str, Any]:
        with self.store.tx() as conn:
            lease = self._fence(conn, token)
            conn.execute("UPDATE mq_entries SET state = ?, reason = ?, updated_at = ? WHERE entry_id = ? AND state = ?",
                         (BOUNCED, reason, self.clock(), e["entry_id"], QUEUED))
            self._clear_tested(conn, cfg["repo"], cfg["base"])
            self._receipt(conn, cfg["repo"], cfg["base"], "returned_to_review", {"reason": reason, **body}, e["entry_id"], lease)
        return {"ok": False, "result": "returned_to_review", "entry": e["entry_id"], "unit": e["unit"], "reason": reason, **body}

    def _fail(self, token: str, cfg: dict[str, Any], e: dict[str, Any], reason: str, body: dict[str, Any]) -> dict[str, Any]:
        with self.store.tx() as conn:
            lease = self._fence(conn, token)
            conn.execute("UPDATE mq_entries SET state = ?, reason = ?, updated_at = ? WHERE entry_id = ? AND state = ?",
                         (FAILED, reason, self.clock(), e["entry_id"], QUEUED))
            self._clear_tested(conn, cfg["repo"], cfg["base"], e["seq"])
            self._receipt(conn, cfg["repo"], cfg["base"], "failed", {"reason": reason, "frozen": True, **body},
                          e["entry_id"], lease)
        raise QueueError("merge_refused", f"{e['entry_id']}: {reason}; the train is frozen behind it",
                         {"entry": e["entry_id"], "reason": reason, **body})

    def ack(self, token: str, entry_id: str, *, note: str | None = None, accept_untested_tree: bool = False) -> dict[str, Any]:
        """Acknowledge a verified merge (the conductor has ledgered it): merged -> landed."""
        cfg, _lease = self._owner(token)
        rows = self.store.read("SELECT * FROM mq_entries WHERE entry_id = ? AND repo = ? AND base = ?",
                               (entry_id, cfg["repo"], cfg["base"]))
        if not rows:
            raise QueueError("entry_not_found", f"no entry {entry_id!r} in this queue", exit_code=EXIT_USAGE)
        e = rows[0]
        if e["state"] == LANDED:
            return {"ok": True, "duplicate": True, "entry": entry_id, "mergeSha": e["merge_sha"]}
        if e["state"] != MERGED:
            raise QueueError("not_merged", f"{entry_id} is {e['state']!r}, not merged", exit_code=EXIT_USAGE)
        if not e["tree_matches_tested"] and not accept_untested_tree:
            raise QueueError("untested_tree_merged", f"{entry_id} merged a tree other than the tested one (BASE moved "
                             "under the remote merge); ack with --accept-untested-tree once that content is checked",
                             {"entry": entry_id, "mergeSha": e["merge_sha"], "mergedTree": e["merged_tree"],
                              "testedTree": e["tested_tree"]})
        base_head = self._base_head(cfg)
        if not self.git.is_ancestor(e["merge_sha"], base_head):
            raise QueueError("merge_not_on_base", f"{e['merge_sha']} is not an ancestor of {cfg['base']} "
                             f"({base_head}); BASE was rewritten", {"entry": entry_id})
        teardown = self.retry_teardowns(token, cfg, entry_id)
        with self.store.tx() as conn:
            lease = self._fence(conn, token)
            cur = conn.execute("UPDATE mq_entries SET state = ?, updated_at = ? WHERE entry_id = ? AND state = ?",
                               (LANDED, self.clock(), entry_id, MERGED))
            if cur.rowcount != 1:
                raise QueueError("queue_changed", f"{entry_id} changed state while acknowledging")
            body = {"mergeSha": e["merge_sha"], "baseHead": base_head, "note": note,
                    "acceptedUntestedTree": bool(accept_untested_tree and not e["tree_matches_tested"]),
                    "promotion": f"{cfg['base']}->{cfg['default_branch']} is a human gate, not performed here"}
            if cfg["mode"] == "git":
                body["ledger"] = "no-gh: local-merge"
            self._receipt(conn, cfg["repo"], cfg["base"], "acknowledged", body, entry_id, lease)
        return {"ok": True, "entry": entry_id, "landed": True, "teardown": teardown, **body}

    def resolve(self, token: str, entry_id: str, *, action: str, reason: str) -> dict[str, Any]:
        """The conductor's recorded decision on the failed entry the train is frozen behind."""
        if action not in RESOLVE_ACTIONS:
            raise QueueError("usage", f"--action must be one of {sorted(RESOLVE_ACTIONS)}", exit_code=EXIT_USAGE)
        if not reason or not reason.strip():
            raise QueueError("usage", "--reason is recorded with the decision", exit_code=EXIT_USAGE)
        with self.store.tx() as conn:
            lease = self._fence(conn, token)
            row = conn.execute("SELECT * FROM mq_entries WHERE entry_id = ? AND repo = ? AND base = ?",
                               (entry_id, lease["repo"], lease["base"])).fetchone()
            if row is None or row["state"] != FAILED:
                raise QueueError("not_failed", f"{entry_id} is not a failed entry", exit_code=EXIT_USAGE)
            conn.execute("UPDATE mq_entries SET state = ?, reason = ?, updated_at = ? WHERE entry_id = ?",
                         (RESOLVE_ACTIONS[action], f"{row['reason']} -> {action}: {reason}", self.clock(), entry_id))
            self._clear_tested(conn, lease["repo"], lease["base"])
            if action == "requeue":
                conn.execute("UPDATE mq_entries SET tested_base_tree = NULL, tested_tree = NULL, prefix_commit = NULL "
                             "WHERE entry_id = ?", (entry_id,))
            self._receipt(conn, lease["repo"], lease["base"], "resolved",
                          {"action": action, "reason": reason, "was": row["reason"]}, entry_id, lease)
        return {"ok": True, "entry": entry_id, "state": RESOLVE_ACTIONS[action]}

    # --- read-only views ---------------------------------------------------------------------
    @staticmethod
    def _entry_view(e: dict[str, Any]) -> dict[str, Any]:
        keys = ("entry_id", "seq", "state", "run_id", "unit", "pr", "branch", "reviewed_sha", "reviewed_tree",
                "accepted_head", "expected_base", "tested_base_tree", "tested_tree", "prefix_commit", "merge_sha",
                "merged_tree", "tree_matches_tested", "reason", "teardown")
        return {k: e.get(k) for k in keys}

    def status(self, repo: str, base: str) -> dict[str, Any]:
        repo = self.normalize(repo)
        with self.store.connect() as conn:
            cfg = self._config(conn, repo, base)
            lease = conn.execute("SELECT holder, epoch, expires_at, released_at FROM mq_leases WHERE repo = ? AND base = ?",
                                 (repo, base)).fetchone()
        line = self._line(repo, base)
        frozen = next((e for e in line if e["state"] == FAILED), None)
        now = self.clock()
        return {
            "ok": True, "repo": repo, "base": base, "mode": cfg["mode"],
            "lease": ({**dict(lease), "live": lease["released_at"] is None and lease["expires_at"] > now} if lease else None),
            "line": [self._entry_view(e) for e in line],
            "frozen": {"entry": frozen["entry_id"], "reason": frozen["reason"]} if frozen else None,
            "ackOwed": [e["entry_id"] for e in line if e["state"] == MERGED],
            "inFlight": [e["entry_id"] for e in line if e["state"] == MERGING],
            "promotion": {"from": base, "to": cfg["default_branch"], "by": "human", "automated": False},
            "all": [self._entry_view(e) for e in self.store.read(
                "SELECT * FROM mq_entries WHERE repo = ? AND base = ? ORDER BY seq ASC", (repo, base))],
        }

    def receipts(self, repo: str, base: str, entry_id: str | None = None) -> dict[str, Any]:
        repo = self.normalize(repo)
        q, params = "SELECT * FROM mq_receipts WHERE repo = ? AND base = ?", [repo, base]
        if entry_id:
            q += " AND entry_id = ?"
            params.append(entry_id)
        rows = self.store.read(q + " ORDER BY id ASC", tuple(params))
        return {"ok": True, "receipts": [{**{k: r[k] for k in ("id", "entry_id", "kind", "epoch", "holder", "created_at")},
                                          "body": json.loads(r["body_json"])} for r in rows]}

    def drain(self, *, repo: str, base: str, holder: str, ttl: float = DEFAULT_TTL, takeover: bool = False,
              wait: float = 10.0, gate_cmd: str | None = None, ack: bool = False, max_steps: int = 100,
              delete_branch: bool = True, gate_timeout: float = 1800.0) -> dict[str, Any]:
        """acquire -> (plan -> merge -> ack)* -> release: one conductor turn over the whole train."""
        repo = self.normalize(repo)
        acq = self.acquire(repo=repo, base=base, holder=holder, ttl=ttl, takeover=takeover, wait=wait)
        token, steps = acq["token"], []
        stop: QueueError | None = None
        try:
            self.settle_in_flight(token)  # owed teardowns too, even when the train is already empty
            for _ in range(max_steps):
                line = self._line(repo, base)
                if not line:
                    break
                head = line[0]
                try:
                    if head["state"] == MERGED and ack:
                        steps.append({"ack": self.ack(token, head["entry_id"], note=f"drain by {holder}")})
                    elif head["state"] == QUEUED and not self.plan_passed(head, gate_cmd):
                        # Re-plan unless the saved plan passed THIS gate on this prefix (PR #647).
                        steps.append({"plan": self.plan(token, gate_cmd=gate_cmd, gate_timeout=gate_timeout)})
                    else:
                        steps.append({"merge": self.merge(token, entry_id=head["entry_id"], delete_branch=delete_branch,
                                                          require_gate=gate_cmd)})
                except QueueError as exc:
                    if exc.code == "retest_required":
                        steps.append({"retest": exc.as_json()})
                        continue
                    raise
            else:
                stop = QueueError("max_steps", f"stopped after {max_steps} steps with the train not empty")
        except QueueError as exc:
            stop = exc
        if stop is None or stop.exit_code != EXIT_FENCED:
            with contextlib.suppress(QueueError):
                self.release(token)
        result = {"ok": stop is None, "epoch": acq["epoch"], "reconciled": acq["reconciled"], "steps": steps,
                  "promotion": {"from": base, "by": "human", "automated": False}}
        if stop is not None:
            raise QueueError(stop.code, stop.message, {**stop.data, "drain": result}, exit_code=stop.exit_code)
        return result


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="merge_queue.py",
        description="The persisted, fenced single-conductor merge queue (#599; merge-serialization.md).",
        epilog="exit 0 ok / 1 blocked / 2 usage or refused input / 3 not the owner (fenced, lease held)",
    )
    p.add_argument("--db", default=None, help="queue store (default $OPEN_FLEET_MERGE_QUEUE_DB, "
                   "$OPEN_FLEET_STATE_DIR/merge-queue.db, or ~/.open-fleet/state/merge-queue.db)")
    p.add_argument("--repo-dir", default=".", help="the conductor's clone (default: cwd)")
    p.add_argument("--repo", default=None, help="repository identity (default: the origin URL as host/owner/name)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="open the queue for one BASE (idempotent)")
    s.add_argument("--base", required=True)
    s.add_argument("--default", required=True, help="the default branch: never a merge target here")
    s.add_argument("--consent", required=True, help="the standing grant each merge's egress receipt cites")
    s.add_argument("--mode", choices=MODES, default="gh", help="gh (default) or git, the no-gh lane")
    s.add_argument("--remote", default="origin")
    s.add_argument("--host", default=None, help="egress host (default github.com, or the remote's host)")

    for name, helptext in (("acquire", "become the conductor: reconcile in-flight merges, then take the lease"),
                           ("drain", "acquire, then plan/merge/ack the whole train, then release")):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("--base", required=True)
        s.add_argument("--holder", required=True, help="the conductor's handle")
        s.add_argument("--ttl", type=float, default=DEFAULT_TTL, help="lease seconds, renewed by every write")
        s.add_argument("--takeover", action="store_true", help="fence a live holder")
        s.add_argument("--wait", type=float, default=0.0 if name == "acquire" else 10.0,
                       help="seconds to wait for the merge boundary")
        if name == "drain":
            s.add_argument("--gate-cmd", default=None, help="shell command run in each prefix checkout; a saved "
                           "plan is reused only when it passed exactly this command")
            s.add_argument("--gate-timeout", type=float, default=1800.0)
            s.add_argument("--ack", action="store_true", help="acknowledge each verified merge")
            s.add_argument("--max-steps", type=int, default=100)
            s.add_argument("--keep-branch", action="store_true",
                           help="gh lane: keep the head branch (it is deleted only when GitHub merged the PR into BASE)")

    s = sub.add_parser("release", help="give the lease up")
    s.add_argument("--token", required=True)
    s = sub.add_parser("enqueue", help="board one merge_ready payload (duplicates are no-ops)")
    s.add_argument("--token", required=True)
    s.add_argument("--payload", required=True, help="the merge_ready payload JSON")
    s.add_argument("--run", default=None)
    s.add_argument("--delivery", default=None, help="the delivery or message id, recorded")
    s = sub.add_parser("plan", help="test the prefix: BASE + each queued entry in arrival order")
    s.add_argument("--token", required=True)
    s.add_argument("--gate-cmd", default=None)
    s.add_argument("--gate-timeout", type=float, default=1800.0)
    s = sub.add_parser("merge", help="merge the head of the train behind every guard")
    s.add_argument("--token", required=True)
    s.add_argument("--entry", default=None)
    s.add_argument("--keep-branch", action="store_true")
    s.add_argument("--require-gate", default=None, help="refuse unless the saved plan passed exactly this gate")
    s = sub.add_parser("ack", help="acknowledge a verified merge (merged -> landed)")
    s.add_argument("--token", required=True)
    s.add_argument("--entry", required=True)
    s.add_argument("--note", default=None)
    s.add_argument("--accept-untested-tree", action="store_true")
    s = sub.add_parser("resolve", help="decide the failed entry the train is frozen behind")
    s.add_argument("--token", required=True)
    s.add_argument("--entry", required=True)
    s.add_argument("--action", required=True, choices=sorted(RESOLVE_ACTIONS))
    s.add_argument("--reason", required=True)
    s = sub.add_parser("reconcile", help="settle an in-flight merge an earlier attempt left behind")
    s.add_argument("--token", required=True)
    for name in ("status", "receipts"):
        s = sub.add_parser(name, help="read-only")
        s.add_argument("--base", required=True)
        if name == "receipts":
            s.add_argument("--entry", default=None)
    return p


def run(args: argparse.Namespace, mq: MergeQueue) -> dict[str, Any]:
    cmd = args.command
    if cmd in ("init", "acquire", "drain", "status", "receipts"):
        repo = mq.normalize(args.repo) if args.repo else mq.default_repo(getattr(args, "remote", "origin"))
    if cmd == "init":
        return mq.init(repo=repo, base=args.base, default=args.default, consent=args.consent, mode=args.mode,
                       remote=args.remote, host=args.host)
    if cmd == "acquire":
        return mq.acquire(repo=repo, base=args.base, holder=args.holder, ttl=args.ttl, takeover=args.takeover,
                          wait=args.wait)
    if cmd == "drain":
        return mq.drain(repo=repo, base=args.base, holder=args.holder, ttl=args.ttl, takeover=args.takeover,
                        wait=args.wait, gate_cmd=args.gate_cmd, ack=args.ack, max_steps=args.max_steps,
                        delete_branch=not args.keep_branch, gate_timeout=args.gate_timeout)
    if cmd == "status":
        return mq.status(repo, args.base)
    if cmd == "receipts":
        return mq.receipts(repo, args.base, args.entry)
    if cmd == "release":
        return mq.release(args.token)
    if cmd == "enqueue":
        return mq.enqueue(args.token, args.payload, run=args.run, delivery=args.delivery)
    if cmd == "plan":
        return mq.plan(args.token, gate_cmd=args.gate_cmd, gate_timeout=args.gate_timeout)
    if cmd == "merge":
        return mq.merge(args.token, entry_id=args.entry, delete_branch=not args.keep_branch,
                        require_gate=args.require_gate)
    if cmd == "ack":
        return mq.ack(args.token, args.entry, note=args.note, accept_untested_tree=args.accept_untested_tree)
    if cmd == "resolve":
        return mq.resolve(args.token, args.entry, action=args.action, reason=args.reason)
    return {"ok": True, "reconciled": mq.settle_in_flight(args.token)}


def main(argv: list[str] | None = None, mq: MergeQueue | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        mq = mq or MergeQueue(args.db, args.repo_dir)
        out = run(args, mq)
    except QueueError as exc:
        print(json.dumps(exc.as_json(), indent=2, sort_keys=True, default=str))
        return exc.exit_code
    print(json.dumps(out, indent=2, sort_keys=True, default=str))
    return EXIT_OK if out.get("ok", True) else EXIT_BLOCKED


if __name__ == "__main__":
    sys.exit(main())
