#!/usr/bin/env python3
"""wip_curve.py — the pre-registered WIP throughput-curve experiment (#604): plan, run, report, verify.

runtime/attention-budget.md kept the fleet's WIP caps ASSERTED until at least three
protocol-compliant runs at differing WIP settings measured verified-CLOSED throughput. This script
is that experiment; its 12 live runs (docs/runs/2026-10-25-wip-curve-604-live.md) measured the
mutation-wave caps and kept them. A live run spends model budget only under the owner's
authorisation (docs/experiments/wip-curve-prereg.md):

  check-prereg  the pre-registration and its task set are well formed and bound to each other: the
                task set hashes to the registered digest, the seed rebuilds to the registered
                commit, every oracle fails on the seed and passes on its task's reference edit, and
                the six references compose in the forward and the reverse order
  plan          the schedule derived from the pre-registration alone: each run's condition,
                repetition, position in the counterbalanced order, and task order
  run           execute scheduled runs on the posix provider through the public wrappers
                (task_ops.py, spawn_worker.sh, worker_ops.py, orca_cli.py), with build-blind
                reviewers, a coordinator-run oracle at each worker's head in a clean checkout, and
                merges through merge_queue.py's git lane; every observation goes into the run's
                append-only events.py record (#603), and every source it rests on is retained
  report        derive the experiment report from the retained sources ONLY: each run's metrics
                come from events.py's derivation of its record, conflicts from the merge queue's
                receipts, and every terminal outcome is re-checked against git and review authority
  verify        recompute the report from the sources and name every cell a published report.json
                or report.md gets wrong, then run `events.py check` on each run's WIP-curve rows
  gate          (internal) the merge queue's gate: the visible tests, plus the oracle of every task
                whose reviewed head the prefix commit under test contains

Two kinds of worker, ONE code path (first_run.py's pattern, #596):

  --worker inert   a stand-in answers to the harness name from a private bin directory first on
      PATH, behind tripwires for every other harness name, with a private HOME. It applies each
      task's reference edit (or a scripted miss) and answers reviews; it calls no model and spends
      nothing. Its runs are labelled fixture-tested and are never protocol-compliant.
  --worker live    only inside the container-based live harness (PR #668; scripts/live_container.py):
      anywhere else refused, before anything is read or reserved (runtime/scripts/containment.py).
      The operator's real harness, refused without an explicit --cost-cap-usd above zero and a
      --model pin, its runs labelled live-unreviewed until a maintainer binds them.

Exit: 0 ok · 1 incomplete, mismatch or refused check · 2 usage or refused start · 3 fail-closed (a
bound source is missing, altered or unreadable).
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import functools
import hashlib
import importlib.util
import io
import json
import os
import platform
import re
import secrets
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation, localcontext
from fractions import Fraction
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "runtime" / "scripts"
PREREG_DEFAULT = ROOT / "docs" / "experiments" / "wip-curve-prereg.json"
PREREG_SCHEMA = "open-fleet.wip-curve-prereg/1"
TASKSET_SCHEMA = "open-fleet.wip-curve-taskset/1"
RUN_SCHEMA = "open-fleet.wip-curve-run/1"
ORACLE_SCHEMA = "open-fleet.wip-curve-oracle/1"
REPORT_SCHEMA = "open-fleet.wip-curve-report/1"
PENDING = "PENDING OWNER AUTHORISATION"
AUTHORISED = "AUTHORISED"  # cost.reservation_status once the owner's authorisation is recorded
AUTHORISATION = ("authorised_by", "authorised_on", "authorised_via")
EXIT_OK, EXIT_INCOMPLETE, EXIT_USAGE, EXIT_FAIL_CLOSED = 0, 1, 2, 3
HOLDER = "wip-runner"
# A reviewer may dress its verdict line in markdown (`code` or **bold**); nonce and head must match.
REVIEW_LINE = re.compile(r"^[`*\s]*WIP-REVIEW (WIP-NONCE:[0-9a-f]{16}) ([0-9a-f]{40}) (approve|changes)[`*\s]*$", re.M)
# Inert workers answer in Claude's stream-json shape, the one events.py ingest-usage reads.
INERT_AGENTS = ("claude",)
# Two-sided 95% Student-t critical values by degrees of freedom (the usual table, 3 places).
T95 = {1: "12.706", 2: "4.303", 3: "3.182", 4: "2.776", 5: "2.571", 6: "2.447", 7: "2.365",
       8: "2.306", 9: "2.262", 10: "2.228", 11: "2.201", 12: "2.179", 13: "2.160", 14: "2.145",
       15: "2.131", 16: "2.120", 17: "2.110", 18: "2.101", 19: "2.093", 20: "2.086"}
Z95 = Decimal("1.959963984540054")
# No harness in the posix launch table (runtime/providers/base.py) is given a per-call budget
# flag, so a running dispatch can overrun its reservation; the guard refuses every NEXT dispatch.
# The posix launch table passes no model to any harness; claude reads its model from its own
# environment, which the setsid launch hands the worker. A harness with no such channel cannot be
# held to a pin, so a live run on it is refused before any dispatch (PR #653 review).
MODEL_ENV = {"claude": "ANTHROPIC_MODEL"}
PER_CALL_LIMIT = "none passed: the posix launch table has no per-call budget flag for any harness"
# The merge queue's own `failed` receipt reasons (runtime/scripts/merge_queue.py plan()).
MQ_CONFLICT, MQ_GATE_FAILED = "conflict", "gate_failed"
# A run that ended this way may be re-run once (-a2): an infrastructure failure, not a result.
RETRYABLE = ("failed", "interrupted", "lost")
# A call the API refused for its credential (an expired token: #604's 2026-10-25 run, every call
# HTTP 401) is an infrastructure failure: the run halts and ends `failed`, never a measurement.
CREDENTIAL_REJECTED = "credential-rejected"
_AUTH_FAILURE_RE = re.compile(r"not logged in|/login|invalid api key|authentication|oauth token has expired|\b401\b",
                              re.IGNORECASE)
AGREED_UNAVAILABLE = "the record cannot derive it, yet the report claims 'unavailable'"


def _load(name: str, path: Path):
    """A module loaded by path, never writing bytecode beside it (PR #668 CI: a load wrote into the source tree)."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    prior, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = prior
    return mod


# The event record, the first-run sandbox and its stand-in pattern, and the hardened git executor
# (#629/#649) are reused, never copied.
events = _load("wip_curve_events", SCRIPTS / "events.py")
gitexec = _load("wip_curve_gitexec", SCRIPTS / "gitexec.py")
first_run = _load("wip_curve_first_run", SCRIPTS / "first_run.py")
# #606's call containment (scripts/_ablation_run.py: the watchdog, the OF_CALL_ID marker that follows
# a process across sessions, and the sweep that kills by it), loaded by path as hint_replay.py does:
# one helper, shared, never copied (Codex review of PR #668).
contain = _load("wip_curve_contain", ROOT / "scripts" / "_ablation_run.py")


class Refused(Exception):
    """A usage error or a refused start (exit 2)."""


class SourceError(Exception):
    """A bound source is missing, altered or unreadable (exit 3)."""


class DeadlineReached(Exception):
    """A bounded step ran into the run's deadline."""


class RunFailed(Exception):
    """An infrastructure failure inside a run: the run is retained as failed."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def money(text) -> Decimal:
    try:
        value = Decimal(str(text))
    except (InvalidOperation, ValueError):
        raise Refused(f"{text!r} is not a decimal amount") from None
    if not value.is_finite() or value < 0:
        raise Refused(f"{text!r} is not a non-negative amount")
    return value


def fmt(frac, places=2) -> str:
    return events._decimal(Fraction(frac), places)


# ---------------------------------------------------------------------------- child processes
# Every child the runner starts leads its own process group, so it and anything it starts die
# together: on a timeout, after it exits (a straggler it left behind), and when the run is
# interrupted (#652's fix, mirrored for PR #653's review). Workers live in the posix provider's
# setsid sessions and are stopped through worker_ops.py, which kills their group.
LIVE_GROUPS: set[int] = set()
TRAPPED_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)


def group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    return True


def kill_group(pgid: int, wait_s: float = 10.0) -> bool:
    """SIGKILL every process in the group and wait until none is left: True once it is empty."""
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    deadline = time.monotonic() + wait_s
    while group_alive(pgid):
        if time.monotonic() > deadline:
            return False
        time.sleep(0.02)
    LIVE_GROUPS.discard(pgid)
    return True


def stop_all_groups() -> None:
    for pgid in sorted(LIVE_GROUPS):
        kill_group(pgid)


DRAIN_S = 2  # seconds a killed call's output is drained for, at most


def run_group(argv, *, cwd=None, env=None, timeout: float = 600, data: bytes = b"") -> subprocess.CompletedProcess:
    """argv as the leader of a new session; bytes out. A timeout kills the whole group (rc 124);
    anything the leader leaves behind is killed after it exits; an exception mid-call (an
    interrupt) kills it on the way out. stdin is `data` (empty by default), never ours."""
    proc = subprocess.Popen(argv, cwd=None if cwd is None else str(cwd), env=env, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    LIVE_GROUPS.add(proc.pid)
    try:
        try:
            out, err = proc.communicate(data, timeout=timeout)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            kill_group(proc.pid, wait_s=0)
            try:
                out, err = proc.communicate(timeout=DRAIN_S)
            except subprocess.TimeoutExpired:
                # A descendant that left the group (a new session) holds the pipes open: draining
                # them waits for nobody (Codex review of PR #668), and what they held is lost.
                proc.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=DRAIN_S)
                for stream in (proc.stdout, proc.stderr):
                    with contextlib.suppress(OSError):
                        stream.close()
                out, err = b"", b"its output was held open by a process outside its group"
            rc, err = 124, (err or b"") + f"\ntimed out after {timeout}s; its process group was killed".encode()
    finally:
        if proc.poll() is None:
            kill_group(proc.pid, wait_s=0)
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=DRAIN_S)
        kill_group(proc.pid)
    return subprocess.CompletedProcess(argv, rc, out or b"", err or b"")


def run_text(argv, *, cwd=None, env=None, timeout: float = 600) -> subprocess.CompletedProcess:
    """run_group with stdout and stderr decoded for display and checks (first_run.text_of)."""
    proc = run_group(argv, cwd=cwd, env=env, timeout=timeout)
    return subprocess.CompletedProcess(argv, proc.returncode, first_run.text_of(proc.stdout),
                                       first_run.text_of(proc.stderr))


def _terminated(signum, _frame):
    """SIGTERM, SIGHUP and Ctrl-C unwind the run like an exception, so its cleanup kills every live
    group, stops every worker and settles every launched call before exiting 128+N. The first
    signal wins: the run is ending either way, so no second one may cut that cleanup short."""
    for sig in TRAPPED_SIGNALS:
        signal.signal(sig, signal.SIG_IGN)
    raise SystemExit(128 + signum)


def git_env(base: dict | None = None, repo: Path | None = None) -> dict:
    """gitexec.py's hardened environment (#629): no system or user config (which would also make
    the seed commit differ between hosts), no prompt, no replace objects, and every repository-
    config command channel closed at command-line precedence: core.fsmonitor, core.hooksPath,
    diff.external, the ext:: transport. With `repo`, every filter, diff and merge driver that
    repository's config declares is blanked too. A builder writes the config its worktree shares
    with the target clone, so without this a planted command ran on the coordinator, outside the
    worker's guarded session (PR #653 review). The driver query fails closed."""
    blanks = ()
    if repo is not None:
        try:
            blanks = gitexec.driver_blanks(repo)
        except gitexec.DriverQueryFailed as err:
            raise RunFailed(f"the git config of {repo} cannot be read, so its drivers cannot be "
                            f"neutralised: {err}") from err
    return gitexec.env(dict(base if base is not None else os.environ), blanks)


def git(cwd: Path, *args: str, env: dict | None = None, check=True, data: bytes | None = None):
    """git through gitexec: the absolute git resolved once, the hardened environment with the
    repository's drivers blanked (except for `init`/`clone`, which create it), --no-ext-diff and
    --no-textconv on every diff, and no inherited stdin (a planted command must not read ours)."""
    if args and args[0] == "diff":
        args = ("diff", "--no-ext-diff", "--no-textconv", *args[1:])
    repo = None if args and args[0] in ("init", "clone") else Path(cwd)
    try:
        proc = run_group(gitexec.argv("-C", str(cwd), *args), env=git_env(env, repo),
                         data=data if data is not None else b"")
    except OSError as err:
        raise RunFailed(f"git {' '.join(args[:2])} could not run in {cwd}: {err}") from err
    if check and proc.returncode != 0:
        raise RunFailed(f"git {' '.join(args)} failed in {cwd}: "
                        f"{proc.stderr.decode('utf-8', 'replace').strip()[:400]}")
    return proc


def git_out(cwd: Path, *args: str, env: dict | None = None) -> str:
    return git(cwd, *args, env=env).stdout.decode("utf-8", "replace").strip()


# ---------------------------------------------------------------------------- prereg + taskset

def load_json(path: Path) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        raise Refused(f"{path} is not readable JSON: {err}") from err


def load_prereg(path: Path | None = None):
    """(prereg, taskset, prereg path, prereg sha256)."""
    path = Path(path or PREREG_DEFAULT)
    prereg = load_json(path)
    rel = (prereg.get("taskset") or {}).get("path")
    if not isinstance(rel, str):
        raise Refused(f"{path}: taskset.path is missing")
    taskset_path = (ROOT / rel) if not Path(rel).is_absolute() else Path(rel)
    taskset = load_json(taskset_path)
    return prereg, taskset, path, sha256_file(path), taskset_path


# What no runner write (or later delete) may touch: the repository's sources and the registered
# pre-registration and task set (which holds the seed). PR #652's class, found here too (#604).
SOURCE_DIRS = ("skills", "playbooks", "runtime", "scripts", "docs", "tests", "bench", "evals", ".git")


def sandbox_path(workdir, run_id: str, results: Path, registered=()) -> Path:
    """The run's sandbox, `<workdir>/<run id>`, resolved and guarded like every other write: never
    a link (a complete run deletes its sandbox, and rmtree never follows one), never in the checkout
    or around the results, and new or empty (PR #653 review: the final path skipped the guard)."""
    sandbox = Path(workdir).expanduser().resolve() / run_id
    if sandbox.is_symlink():
        raise Refused(f"the sandbox {sandbox} is a symbolic link: it must be a directory the runner creates")
    target = check_writable(sandbox, "the sandbox", registered)
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise Refused(f"the sandbox {sandbox} already holds something: a complete run deletes its sandbox, "
                      "so it must be a directory the runner creates")
    if results.is_relative_to(target) or target.is_relative_to(results):
        raise Refused(f"--results {results} and the sandbox {sandbox} overlap: deleting one would delete the other")
    return target


def check_writable(path, what: str, registered=()) -> Path:
    """`path` resolved (symlinks followed), or Refused when it is, lies inside or contains the
    checkout or a registered file: a results, output or sandbox path there would overwrite, or
    later delete, what the experiment is measured against. The whole checkout, not a list of its
    directories (Codex review, C5: .github/ and assets/ were outside the list)."""
    target = Path(path).expanduser().resolve()
    protected = [ROOT.resolve()] + [(ROOT / d).resolve() for d in SOURCE_DIRS]
    protected += [Path(r).resolve() for r in (PREREG_DEFAULT, *registered)]
    for q in protected:
        if target == q or target.is_relative_to(q) or q.is_relative_to(target):
            how = "is" if target == q else "lies inside" if target.is_relative_to(q) else "contains"
            raise Refused(f"{what} {path} resolves to {target}, which {how} {q}: the runner never writes there")
    return target


# The worker contracts are registered text, not code (#604): what a builder and a reviewer are told
# is pinned by the pre-registration's digest. Each names the fields it may use; the markers are
# what the inert stand-in and the review parser read.
PLACEHOLDER = re.compile(r"\{(task|nonce|title|statement|base|head|task_file|diff_file|verdict)\}")
CONTRACT_FIELDS = {"builder": {"task", "nonce", "title", "statement"},
                   "reviewer": {"task", "nonce", "base", "head", "task_file", "diff_file"}}
CONTRACT_MARKERS = {"builder": "WIP-BUILD {nonce} task={task}",
                    "reviewer": "WIP-REVIEW-REQUEST {nonce} task={task} head={head} diff={diff_file}"}


def render(lines, **fields) -> str:
    """A registered contract with its fields filled; any other brace is left as written."""
    return "\n".join(PLACEHOLDER.sub(lambda m: str(fields[m.group(1)]), line) for line in lines)


def contract_errors(contracts) -> list[str]:
    errors = []
    if not isinstance(contracts, dict):
        return ["contracts are not registered: the builder and reviewer text must be pinned"]
    for role, allowed in CONTRACT_FIELDS.items():
        lines = contracts.get(role)
        if not isinstance(lines, list) or not all(isinstance(x, str) for x in lines) or not lines:
            errors.append(f"contracts.{role} is not a list of lines")
            continue
        text = "\n".join(lines)
        used = set(PLACEHOLDER.findall(text))
        if used - allowed:
            errors.append(f"contracts.{role} uses {sorted(used - allowed)}, which a {role} is not given")
        if CONTRACT_MARKERS[role] not in text:
            errors.append(f"contracts.{role} must carry {CONTRACT_MARKERS[role]} (the line the worker is read by)")
        missing = sorted(f"{{{f}}}" for f in allowed - used)
        if missing:
            errors.append(f"contracts.{role} never uses {missing}")
    verdicts = contracts.get("verdicts")
    if verdicts != ["approve", "changes"]:
        errors.append(f"contracts.verdicts is {verdicts!r}; the record knows ['approve', 'changes']")
    line = contracts.get("verdict_line")
    for verdict in ("approve", "changes"):
        sample = render([line], nonce="WIP-NONCE:" + "0" * 16, head="a" * 40, verdict=verdict) \
            if isinstance(line, str) else ""
        m = REVIEW_LINE.search(sample)
        if not m or m.group(3) != verdict or m.group(2) != "a" * 40:
            errors.append(f"contracts.verdict_line {line!r} is not a line the review parser reads")
            break
    return errors


# Everything the experiment's measurement depends on: the runner, the shared call helper whose
# watchdog, timeouts and sweep every oracle call runs under (scripts/_ablation_run.py, PR #668
# review), the registration and task set, and the runtime it drives. A live run refuses while any
# is uncommitted, and every run records their digest, so runs made on different inputs are never
# pooled.
EXPERIMENT_INPUTS = ("scripts/wip_curve.py", "scripts/_ablation_run.py", "docs/experiments", "runtime")


def dirty_inputs(root: Path = ROOT) -> list[str]:
    """The experiment inputs with uncommitted changes in `root`, as paths relative to it."""
    proc = git(root, "status", "--porcelain", "--untracked-files=no", "--", *EXPERIMENT_INPUTS, check=False)
    if proc.returncode != 0:
        return [f"(git status failed: {proc.stderr.decode('utf-8', 'replace').strip()[:200]})"]
    return sorted(line[3:] for line in proc.stdout.decode("utf-8", "replace").splitlines() if line.strip())


def experiment_inputs(registered=()) -> dict:
    """{sha256, files}: the bytes of every tracked experiment input (and the registration in use)."""
    proc = git(ROOT, "ls-files", "-z", "--", *EXPERIMENT_INPUTS, check=False)
    if proc.returncode == 0:
        rels = [r for r in proc.stdout.decode("utf-8", "replace").split("\0") if r]
    else:  # no git metadata (an exported tree): every file but bytecode
        rels = []
        for d in EXPERIMENT_INPUTS:
            base = ROOT / d
            found = [base] if base.is_file() else sorted(base.rglob("*"))
            rels += [str(f.relative_to(ROOT)) for f in found if f.is_file() and "__pycache__" not in f.parts]
    files = {rel: sha256_file(ROOT / rel) for rel in sorted(set(rels)) if (ROOT / rel).is_file()}
    for path in registered:
        path = Path(path).resolve()
        key = str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)
        files[key] = sha256_file(path)
    return {"sha256": sha256_bytes(json.dumps(files, sort_keys=True).encode()), "files": dict(sorted(files.items()))}


def write_output(path: Path, text: str, registered=()) -> None:
    """Write a report file without ever following a link: an existing symlink there is refused,
    the final path is held to check_writable, and the open itself refuses a link planted in
    between (O_NOFOLLOW), so a report can never overwrite a source or a registered file."""
    path = Path(path)
    if path.is_symlink():
        raise Refused(f"{path} is a symbolic link; the runner never writes through one")
    check_writable(path, "a report file", registered)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    except OSError as err:
        raise Refused(f"{path} cannot be written without following a link: {err}") from err
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


LOCK_NAME = ".wip-curve.lock"
LIVE_CALL = ("held", "launching", "launched")  # a call that may still spend: its hold counts


def _committed(calls: dict) -> Decimal:
    return sum((Decimal(c["usd"]) for c in calls.values() if c.get("state") in LIVE_CALL + ("charged",)),
               Decimal(0))


class Budget:
    """The experiment's one budget (PR #653 review): every paid call in a results directory, by a
    stable identity (`<run>/<task>/a<attempt>/<role>`), in ONE append-only ledger, budget.jsonl,
    read and appended under an exclusive flock. A call's LAST record is its state:

        held -> launching -> launched -> charged      released: a hold that never launched

    so settling a call again, or recovering it after a crash, reconciles it and never adds a
    second charge. Committed spend is each call's charge, or its hold while it may still spend:
    every admission, by any run and any concurrent dispatch, is checked against that one total,
    read and updated atomically. A run's own cost is read back from its calls, never kept apart
    (a separately kept per-run figure counted earlier runs' spend twice)."""

    NAME = "budget.jsonl"

    def __init__(self, results: Path):
        self.path = Path(results) / self.NAME

    def _update(self, fn):
        """fn(calls) -> (records to append, result), all under one exclusive lock."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "r+", encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                fh.seek(0)
                records, result = fn(self._parse(fh.read()))
                for rec in records:
                    fh.write(json.dumps({**rec, "at": now()}, sort_keys=True) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
                return result
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def _parse(self, text: str) -> dict:
        calls = {}
        for lineno, line in enumerate(text.splitlines(), 1):
            try:
                rec = json.loads(line)
                calls[rec["call"]] = {**calls.get(rec["call"], {}), **rec}
            except (ValueError, KeyError, TypeError) as err:
                raise SourceError(f"{self.path}:{lineno} is not a ledger record ({err}): the budget "
                                  "cannot be read, so nothing may spend against it") from err
        return calls

    def calls(self) -> dict:
        """Every call's state, read under a shared lock and never written: a directory without a
        ledger has none, and a read never creates one (a report reads a published copy too)."""
        if not self.path.is_file():
            return {}
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, encoding="utf-8") as fh:
            fcntl.flock(fh.fileno(), fcntl.LOCK_SH)
            try:
                return self._parse(fh.read())
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

    def total(self) -> Decimal:
        return _committed(self.calls())

    def start_run(self, run: str, sandbox: Path, worker: str, call_tag: str | None = None) -> None:
        """The run's start: its sandbox, its worker, and the OF_CALL_ID every process of it carries."""
        self._update(lambda calls: ([{"call": f"{run}/run", "run": run, "state": "run", "usd": "0",
                                      "sandbox": str(sandbox), "worker": worker, "call_tag": call_tag}], None))

    def hold(self, entries, amount: Decimal, cap: Decimal) -> bool:
        """Hold `amount` for each (call, fields) at once, or none: False when the cap cannot cover
        them on top of everything committed."""
        def fn(calls):
            reused = [c for c, _f in entries if c in calls]
            if reused:
                raise RunFailed(f"call identity reused: {reused}")
            if _committed(calls) + amount * len(entries) > cap:
                return [], False
            return [{"call": c, "state": "held", "usd": str(amount), "hold_usd": str(amount), **f}
                    for c, f in entries], True
        return self._update(fn)

    def admit(self, call: str, cap: Decimal) -> bool:
        """A held call may start only while everything committed, its own hold included, is within
        the cap; otherwise its hold is released unspent."""
        def fn(calls):
            c = calls.get(call)
            if not c or c.get("state") != "held":
                return [], False
            if _committed(calls) > cap:
                return [{"call": call, "state": "released", "usd": "0"}], False
            return [{"call": call, "state": "launching"}], True
        return self._update(fn)

    def note(self, call: str, **fields) -> None:
        """Record a call's progress; a settled call (charged or released) never moves again."""
        def fn(calls):
            settled = (calls.get(call) or {}).get("state") in ("charged", "released")
            return ([] if settled and "state" in fields else [{"call": call, **fields}]), None
        self._update(fn)

    def charge(self, call: str, usd: Decimal, measured: bool, run: str | None = None) -> bool:
        """Charge a call once: a call already charged or released is reconciled, not charged again."""
        def fn(calls):
            c = calls.get(call)
            if c and c.get("state") in ("charged", "released"):
                return [], False
            rec = {"call": call, "state": "charged", "usd": str(usd), "measured": measured}
            if not c:
                rec["run"] = run
            return [rec], True
        return self._update(fn)

    def top_up(self, call: str, usd: Decimal) -> bool:
        """Raise a charged call to `usd` (its full hold) when a process of its run may still be
        spending (Codex review of PR #668): the charge never falls, and it is never added twice."""
        def fn(calls):
            c = calls.get(call)
            if not c or c.get("state") != "charged" or Decimal(c["usd"]) >= usd:
                return [], False
            return [{"call": call, "state": "charged", "usd": str(usd), "measured": False, "topped_up": True}], True
        return self._update(fn)

    def release(self, call: str, launched_too: bool = False) -> bool:
        """Release a hold that never launched (`launched_too`: a launching call the store never
        registered, which therefore never ran)."""
        def fn(calls):
            c = calls.get(call)
            states = ("held", "launching") if launched_too else ("held",)
            if not c or c.get("state") not in states:
                return [], False
            return [{"call": call, "state": "released", "usd": "0"}], True
        return self._update(fn)

    @staticmethod
    def of_run(calls: dict, run: str) -> dict:
        return {c: v for c, v in calls.items() if v.get("run") == run and v.get("state") != "run"}


@contextlib.contextmanager
def results_lock(results: Path, shared: bool = False):
    """The results directory's lock: exclusive for a runner, held from its first check through its
    cleanup; shared for a report or a verification, which never read a run in progress. Never
    waited for: a held lock is refused, so two commands cannot both spend one budget."""
    results = Path(results)
    if shared:  # a read never writes into --results, not even its lock (PR #653 review sweep)
        try:
            fd = os.open(results / LOCK_NAME, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:  # no runner ever held this directory
            yield
            return
    else:
        results.mkdir(parents=True, exist_ok=True)
        fd = os.open(results / LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o644)
    try:
        try:
            fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused(f"another runner holds {results} (its lock {LOCK_NAME}); one runner per results "
                          "directory, and a report waits until it ends") from None
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def task_by_id(taskset: dict) -> dict:
    return {t["id"]: t for t in taskset["tasks"]}


def apply_edits(tree: Path, edits: list) -> list[str]:
    """Apply a task's reference edits to a working tree; the paths changed. An anchor must match
    exactly one whole line, so an edit never lands somewhere its author did not mean (#604)."""
    changed = []
    for edit in edits:
        path = Path(tree) / edit["file"]
        text = path.read_text(encoding="utf-8")
        lines = text.split("\n")
        if "replace" in edit:
            hits = [i for i, line in enumerate(lines) if line == edit["replace"]]
            if len(hits) != 1:
                raise ValueError(f"{edit['file']}: anchor {edit['replace']!r} matches {len(hits)} lines")
            lines[hits[0]:hits[0] + 1] = list(edit["with"])
            text = "\n".join(lines)
        elif "append" in edit:
            if not text.endswith("\n"):
                text += "\n"
            text += "\n".join(edit["append"]) + "\n"
        else:
            raise ValueError(f"{edit['file']}: an edit is replace/with or append")
        path.write_text(text, encoding="utf-8")
        if edit["file"] not in changed:
            changed.append(edit["file"])
    return changed


def write_seed(taskset: dict, dest: Path) -> None:
    for rel, content in sorted(taskset["seed"]["files"].items()):
        path = dest / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o644)


def seed_env(taskset: dict, base: dict | None = None) -> dict:
    seed = taskset["seed"]
    env = git_env(base)
    env.update(GIT_AUTHOR_NAME=seed["author_name"], GIT_AUTHOR_EMAIL=seed["author_email"],
               GIT_AUTHOR_DATE=seed["date"], GIT_COMMITTER_NAME=seed["author_name"],
               GIT_COMMITTER_EMAIL=seed["author_email"], GIT_COMMITTER_DATE=seed["date"])
    return env


def configure_repo(repo: Path, env: dict | None = None) -> None:
    for key, val in (("user.email", "wip-curve@open-fleet.invalid"), ("user.name", "open-fleet wip-curve"),
                     ("commit.gpgsign", "false"), ("tag.gpgsign", "false"), ("core.hooksPath", os.devnull),
                     ("core.autocrlf", "false")):
        git(repo, "config", key, val, env=env)


def build_seed(taskset: dict, dest: Path, env: dict | None = None) -> str:
    """The seed repository at `dest` (branch main), committed with the task set's fixed identity
    and date: the same task set gives the same commit on any host, which is the reset proof."""
    dest.mkdir(parents=True, exist_ok=True)
    git(dest, "init", "-q", "-b", "main", env=env)
    configure_repo(dest, env)
    write_seed(taskset, dest)
    git(dest, "add", "-f", "--", *sorted(taskset["seed"]["files"]), env=env)
    git(dest, "commit", "-q", "--no-verify", "-m", taskset["seed"]["message"], env=seed_env(taskset, env))
    return git_out(dest, "rev-parse", "HEAD", env=env)


def python_argv(*args: str) -> list[str]:
    return [sys.executable, "-s", *args]


ORACLE_TIMEOUT = 300  # seconds for one verification, every step together


def run_oracle(checkout: Path, tasks: list[dict], taskset: dict, workdir: Path, timeout: float = ORACLE_TIMEOUT,
               contained: bool = True, on_tag=None) -> dict:
    """The visible tests plus each task's oracle, at `checkout`, with the oracles OUTSIDE it (a
    worker never receives them). {"exit": 0 pass | 2 fail | 1 could not run, ...}."""
    oracle_dir = workdir / f"oracle-{secrets.token_hex(4)}"
    oracle_dir.mkdir(parents=True)
    for task in tasks:
        (oracle_dir / f"test_oracle_{task['id'].lower()}.py").write_text(task["oracle"], encoding="utf-8")
    # Worker-written code runs here, on the coordinator: it gets a minimal environment and its
    # own HOME and TMPDIR, never the coordinator's (where a harness API key lives) (adversarial
    # pass: every subprocess). PATH is this Python's directory and the system directories.
    home = oracle_dir / "home"
    (home / "tmp").mkdir(parents=True)
    env = {"PATH": os.pathsep.join([os.path.dirname(sys.executable), "/usr/bin", "/bin"]), "HOME": str(home),
           "TMPDIR": str(home / "tmp"), "LANG": "C.UTF-8", "PYTHONPATH": str(checkout),
           "PYTHONDONTWRITEBYTECODE": "1"}
    steps, tail, exit_code = [], [], 0
    end = time.monotonic() + timeout  # the whole oracle, every step together
    commands = [("visible", python_argv(*taskset["visible_tests"]))]
    if tasks:
        commands.append(("oracle", python_argv("-m", "unittest", "discover", "-s", str(oracle_dir),
                                               "-t", str(oracle_dir))))
    vouched, tags = True, []
    for name, argv in commands:
        if not vouched:  # the first step that could not be contained ends it: nothing more launches
            break
        if contained:
            # Worker-written code runs here, under #606's watchdog: its streams go to files (nothing it
            # leaves behind can hold a pipe of ours open), and every process it starts, in its group or
            # in a session of its own, carries the call's OF_CALL_ID and is swept (Codex review of #668).
            out_path = oracle_dir / f"{name}.out"
            tag = secrets.token_hex(16)
            if on_tag:  # recorded BEFORE the step starts: a later sweep can always find what it left
                on_tag(tag)
            tags.append(tag)
            rc, killed, emptied = contain.contained_run(argv, timeout=max(end - time.monotonic(), 0.1),
                                                        cwd=checkout, env=env, stdout_path=out_path, tag=tag)
            out = out_path.read_text(encoding="utf-8", errors="replace") if out_path.is_file() else ""
            if killed:
                rc, out = None, f"timed out after {timeout}s"
            if not emptied:  # a process of it survived SIGKILL, or none could be seen: nothing is vouched for
                vouched, rc = False, None
                out += "\na process it started survived, or the process table could not be read"
        else:  # the registered code alone (check-prereg's seed and reference edits): its own group, bounded
            proc = run_group(argv, cwd=checkout, env=env, timeout=max(end - time.monotonic(), 0.1))
            rc = None if proc.returncode == 124 and b"its process group was killed" in proc.stderr else proc.returncode
            out = f"timed out after {timeout}s" if rc is None else (proc.stdout + proc.stderr).decode("utf-8", "replace")
        steps.append({"name": name, "rc": rc})
        tail += [f"[{name}] {ln}" for ln in out.strip().splitlines()[-8:]]
        if rc is None:
            exit_code = 1
        elif rc != 0 and exit_code == 0:
            exit_code = 2
    if vouched:
        shutil.rmtree(oracle_dir, ignore_errors=True)  # an uncontained one is kept, to investigate
    return {"exit": exit_code, "steps": steps, "tail": tail, "tasks": [t["id"] for t in tasks], "contained": vouched,
            "call_tags": tags, "kept": None if vouched else str(oracle_dir)}


# A report's binding re-run of an oracle runs worker-written code on the reader's host. It writes
# nothing into --results (a read never does), so its markers are journaled in a directory of its
# own under KEPT_ROOT (None: the host's temp directory), which every run check reads (Codex P1 (c)
# at 9db89fbe3c). Temporary storage is durable enough: it lasts as long as a process it names can.
KEPT_ROOT = None
RERUN_PREFIX = "wip-curve-rerun-"
RERUN_JOURNAL = "markers.txt"
SWEPT = "SWEPT "  # the journal's last word once a sweep vouched for every marker in it


def rerun_oracle(repo: Path, head: str, task: dict, taskset: dict, what: str) -> dict:
    """The report's binding re-run of one task's oracle at `head`, from the retained bundle `repo`.

    Each step's marker is appended to the journal and synced before the step starts, under an
    exclusive lock held for the whole re-run (a run check leaves a re-run in progress to its own
    sweeps). Contained: the directory is removed. Not contained: every marker is swept once more,
    `SWEPT` is journaled only if that vouched, the directory is KEPT with the checkout and the
    oracle's files, and SourceError names it. A journal no sweep vouched for blocks every run."""
    keep = Path(tempfile.mkdtemp(prefix=RERUN_PREFIX, dir=KEPT_ROOT))
    fd = os.open(keep / RERUN_JOURNAL, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as journal:
        fcntl.flock(journal.fileno(), fcntl.LOCK_EX)

        def record(line):
            journal.write(line + "\n")
            journal.flush()
            os.fsync(journal.fileno())
        work = keep / f"rerun-{task['id']}-{head[:8]}"
        extract_tree(repo, head, work)
        result = run_oracle(work, [task], taskset, keep, on_tag=record)
        if result["contained"]:
            shutil.rmtree(keep, ignore_errors=True)
            return result
        vouched = sweep_tags(result["call_tags"])
        if vouched:
            record(SWEPT + now())
    raise SourceError(f"{what}: the oracle's re-run at that head could not be contained; its files and its "
                      f"marker journal are kept at {keep}: inspect them before reading this run"
                      + ("" if vouched else f"; no sweep vouched for its {contain.CALL_MARKER} markers since, so "
                         "no run starts until one does"))


def unswept_reruns() -> list[tuple[Path, list[str]]]:
    """[(directory, markers)] of every report re-run under KEPT_ROOT, this user's own, whose journal
    no sweep vouched for: what a run check must sweep before anything starts. A re-run in progress
    (its journal locked) is its own process's to sweep and is left alone."""
    found = []
    for d in sorted(Path(KEPT_ROOT or tempfile.gettempdir()).glob(RERUN_PREFIX + "*")):
        try:
            if d.is_symlink() or not d.is_dir() or d.lstat().st_uid != os.getuid():
                continue  # a link, a file, or another user's: never this user's re-run
            fd = os.open(d / RERUN_JOURNAL, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            continue  # gone, or a re-run that never journaled a step
        except OSError as err:
            raise Refused(f"ORPHAN_ALIVE: a report re-run's journal in {d} cannot be read ({err}): nothing "
                          "starts until it is inspected") from err
        with os.fdopen(fd, encoding="utf-8") as journal:
            try:
                fcntl.flock(journal.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                continue  # a report is re-running it now
            lines = journal.read().splitlines()
        if lines and not lines[-1].startswith(SWEPT):
            found.append((d, [ln for ln in lines if ln and not ln.startswith(SWEPT)]))
    return found


def extract_tree(git_dir: Path, rev: str, dest: Path, env: dict | None = None) -> None:
    """`rev`'s tree, as files, at `dest`: a clean checkout no worker touched."""
    data = git(git_dir, "archive", "--format=tar", rev, env=env).stdout
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        tar.extractall(dest, filter="data")


def check_prereg(prereg: dict, taskset: dict, taskset_path: Path, *, oracles=True) -> list[str]:
    """Every problem with the pre-registration, [] when it holds."""
    errors = []
    if prereg.get("schema") != PREREG_SCHEMA:
        errors.append(f"schema is {prereg.get('schema')!r}, not {PREREG_SCHEMA}")
    if taskset.get("schema") != TASKSET_SCHEMA:
        errors.append(f"task set schema is {taskset.get('schema')!r}, not {TASKSET_SCHEMA}")
    if errors:
        return errors
    conds = prereg.get("conditions") or []
    ids = [c.get("id") for c in conds]
    if len(set(ids)) != len(ids) or not all(isinstance(i, str) and i for i in ids):
        errors.append(f"condition ids must be unique, non-empty strings: {ids}")
    for c in conds:
        for key in ("builders", "reviewers"):
            if not isinstance(c.get(key), int) or isinstance(c.get(key), bool) or c[key] < 1:
                errors.append(f"condition {c.get('id')}: {key} must be a positive integer")
    if not any(c.get("builders") == 1 for c in conds):
        errors.append("no condition runs builders=1; the curve needs the serial point (#604)")
    if len({(c.get("builders"), c.get("reviewers")) for c in conds}) < 3:
        errors.append("fewer than three differing WIP settings; the protocol needs three (attention-budget.md)")
    reps = prereg.get("repetitions")
    if not isinstance(reps, int) or isinstance(reps, bool) or reps < 3:
        errors.append(f"repetitions is {reps!r}; pre-register at least 3")
    order = prereg.get("order") or {}
    rows = order.get("rows") or []
    if not isinstance(order.get("seed"), str) or not order.get("seed"):
        errors.append("order.seed is missing: the task order must be recomputable")
    if isinstance(reps, int) and len(rows) < reps:
        errors.append(f"order.rows has {len(rows)} rows for {reps} repetitions")
    for i, row in enumerate(rows, 1):
        if sorted(row) != sorted(ids):
            errors.append(f"order row {i} is not a permutation of the conditions: {row}")
    for key in ("cache_warmup", "task_difficulty", "model_changes", "reviewer_effort"):
        if not (prereg.get("confounds") or {}).get(key):
            errors.append(f"confounds.{key} is not stated")
    stop = prereg.get("stopping_rule") or {}
    for key in ("run_complete", "attempts", "cost", "experiment", "run_wall_clock_minutes",
                "dispatch_timeout_minutes", "max_attempts_per_task"):
        if key not in stop:
            errors.append(f"stopping_rule.{key} is not stated")
    cost = prereg.get("cost") or {}
    if cost.get("cap_usd") != PENDING:
        try:
            money(cost.get("cap_usd"))
        except Refused:
            errors.append(f"cost.cap_usd is {cost.get('cap_usd')!r}: an amount, or {PENDING!r}")
        missing = [k for k in AUTHORISATION if not cost.get(k)]
        if missing:  # an amount is the owner's to set, and the record says who set it, when and how
            errors.append(f"cost.cap_usd is an amount, but the authorisation is not recorded: {missing}")
    if cost.get("reservation_status") not in (PENDING, AUTHORISED):
        errors.append(f"cost.reservation_status is {cost.get('reservation_status')!r}: {PENDING!r} or {AUTHORISED!r}")
    for key in ("proposed_cap_usd", "reservation_per_dispatch_usd"):
        try:
            money(cost.get(key))
        except Refused:
            errors.append(f"cost.{key} is {cost.get(key)!r}, not an amount")
    for key in ("provider", "machine", "harness", "model"):
        if not (prereg.get("runtime") or {}).get(key):
            errors.append(f"runtime.{key} is not stated")
    if not (prereg.get("isolation") or {}).get("per_run"):
        errors.append("isolation.per_run is not stated")
    if not prereg.get("reviewer_availability"):
        errors.append("reviewer_availability is not stated")
    errors += contract_errors(prereg.get("contracts"))
    fields = (prereg.get("metrics") or {}).get("report_fields") or {}
    for scope, known in (("run", REPORTED_RUN), ("condition", REPORTED_CONDITION)):
        listed = fields.get(scope)
        if not isinstance(listed, list) or not listed:
            errors.append(f"metrics.report_fields.{scope} is not registered")
            continue
        unknown = sorted(set(listed) - set(known))
        if unknown:
            errors.append(f"metrics.report_fields.{scope} registers {unknown}, which the report cannot emit")
    if not prereg.get("generalization_limits"):
        errors.append("generalization_limits are not stated")
    reg = prereg.get("taskset") or {}
    digest = sha256_file(taskset_path)
    if reg.get("sha256") != digest:
        errors.append(f"taskset.sha256 is {reg.get('sha256')!r}; the task set hashes to {digest}")
    tasks = taskset.get("tasks") or []
    if len({t.get("id") for t in tasks}) != len(tasks) or len(tasks) < 2:
        errors.append("the task set needs at least two tasks with unique ids")
    if not oracles or errors:
        return errors
    with tempfile.TemporaryDirectory(prefix="wip-curve-check-") as tmp:
        tmp = Path(tmp)
        seed = build_seed(taskset, tmp / "seed")
        if reg.get("seed_commit") != seed:
            errors.append(f"taskset.seed_commit is {reg.get('seed_commit')!r}; the seed builds {seed}")
        for task in tasks:
            base = run_oracle(tmp / "seed", [task], taskset, tmp, contained=False)  # registered code only
            if base["steps"][0]["rc"] != 0:
                errors.append(f"{task['id']}: the visible tests fail on the seed: {base['tail']}")
            if base["exit"] == 0:
                errors.append(f"{task['id']}: the oracle passes on the seed, so it measures nothing")
            work = tmp / f"ref-{task['id']}"
            shutil.copytree(tmp / "seed", work, ignore=shutil.ignore_patterns(".git"))
            try:
                apply_edits(work, task["reference"])
            except (ValueError, KeyError, OSError) as err:
                errors.append(f"{task['id']}: the reference edit does not apply: {err}")
                continue
            ref = run_oracle(work, [task], taskset, tmp, contained=False)
            if ref["exit"] != 0:
                errors.append(f"{task['id']}: the oracle fails on the reference edit: {ref['tail']}")
        for label, ordered in (("forward", tasks), ("reverse", list(reversed(tasks)))):
            work = tmp / f"all-{label}"
            shutil.copytree(tmp / "seed", work, ignore=shutil.ignore_patterns(".git"))
            try:
                for task in ordered:
                    apply_edits(work, task["reference"])
            except (ValueError, KeyError, OSError) as err:
                errors.append(f"the references do not compose in the {label} order: {err}")
                continue
            both = run_oracle(work, tasks, taskset, tmp, contained=False)
            if both["exit"] != 0:
                errors.append(f"the composed references fail an oracle ({label}): {both['tail']}")
    return errors


# ---------------------------------------------------------------------------- schedule

def run_id_for(prereg: dict, cond: str, rep: int, attempt: int = 1) -> str:
    rid = f"wip{prereg['version']}-{cond}-rep{rep}"
    return rid if attempt == 1 else f"{rid}-a{attempt}"


def task_order(prereg: dict, taskset: dict, rid: str) -> list[str]:
    """The run's task order: ids sorted by sha256('<seed>:<run id>:<task id>'), so anyone can
    recompute it from the pre-registration (#604: randomised, recorded, not chosen)."""
    seed = prereg["order"]["seed"]
    base_id = re.sub(r"-a\d+$", "", rid)  # a re-run keeps its run's order
    return sorted((t["id"] for t in taskset["tasks"]),
                  key=lambda tid: hashlib.sha256(f"{seed}:{base_id}:{tid}".encode()).hexdigest())


def schedule(prereg: dict, taskset: dict) -> list[dict]:
    conds = {c["id"]: c for c in prereg["conditions"]}
    out, position = [], 0
    for rep in range(1, prereg["repetitions"] + 1):
        for cid in prereg["order"]["rows"][rep - 1]:
            position += 1
            rid = run_id_for(prereg, cid, rep)
            out.append({"position": position, "repetition": rep, "condition": dict(conds[cid]),
                        "run_id": rid, "task_order": task_order(prereg, taskset, rid)})
    return out


# ---------------------------------------------------------------------------- the inert stand-in

INERT_WORKER = r'''
"""Inert stand-in for a coding-agent harness (wip_curve.py, #604; first_run.py's pattern). It
calls no model and spends nothing: a builder applies its task's reference edit (or a scripted
miss), a reviewer reads the diff it was given and answers."""
import importlib.util, json, os, re, subprocess, sys, time
from pathlib import Path

harness, argv = sys.argv[1], sys.argv[2:]
here = Path(sys.argv[0]).resolve().parent
if argv[:1] == ["--version"]:
    print("inert-stand-in 0.0 (calls no model)")
    sys.exit(0)
cfg = json.loads((here / "wip-config.json").read_text(encoding="utf-8"))
dispatch = os.environ.get("OPEN_FLEET_DISPATCH_ID", "")
spec = next((a for a in argv if "WIP-NONCE:" in a), "")
build = re.search(r"WIP-BUILD (WIP-NONCE:[0-9a-f]{16}) task=(\S+)", spec)
review = re.search(r"WIP-REVIEW-REQUEST (WIP-NONCE:[0-9a-f]{16}) task=(\S+) head=([0-9a-f]{40}) diff=(\S+)", spec)
role = "builder" if build else "reviewer" if review else None
task = (build or review).group(2) if role else None
log = here / "runs.log"
prior = [json.loads(ln) for ln in log.read_text(encoding="utf-8").splitlines()] if log.is_file() else []
attempt = 1 + sum(1 for r in prior if r.get("role") == role and r.get("task") == task)
with open(log, "a", encoding="utf-8") as fh:
    fh.write(json.dumps({"harness": harness, "dispatch": dispatch, "role": role, "task": task,
                         "attempt": attempt}) + "\n")
if role is None:
    print("no WIP-curve spec in argv", file=sys.stderr)
    sys.exit(3)
plan = cfg["script"].get(task, {}).get(role, [])
action = plan[attempt - 1] if attempt <= len(plan) else ("solve" if role == "builder" else "approve")
(here / f"{dispatch or 'unknown'}.pid").write_text(str(os.getpid()), encoding="utf-8")
pause = cfg["script"].get("_sleep", {}).get(role, 0)  # a call still running (tests); per task below
time.sleep(float(cfg["script"].get("_sleep_task", {}).get(task, {}).get(role, pause)))
cost = cfg["script"].get("_cost", {}).get(role, cfg["cost_usd"])  # a fake harness that reports costs


def answer(text):
    """Claude's stream-json: the init line names the stand-in, the result line reports its usage
    (zero tokens; the configured synthetic cost, 0 unless a test asks for one)."""
    model = None if cfg["script"].get("_ignore_model_env") else os.environ.get("ANTHROPIC_MODEL")
    print(json.dumps({"type": "system", "subtype": "init", "model": model or "inert-stand-in"}))
    usage = {k: 0 for k in ("input_tokens", "output_tokens", "cache_read_input_tokens",
                            "cache_creation_input_tokens")}
    print(json.dumps({"type": "result", "subtype": "success", "is_error": False, "result": text,
                      "usage": usage, "total_cost_usd": float(cost)}))


def sh(*args):
    return subprocess.run(list(args), capture_output=True, text=True, check=True).stdout.strip()


if role == "builder":
    nonce = build.group(1)
    if action == "die":
        answer("stand-in scripted to exit without reporting")
        sys.exit(1)
    if action in ("solve", "miss", "regress", "plant", "link_review", "orphan", "solve_crash", "detach"):
        spec_r = importlib.util.spec_from_file_location("wip_curve_runner", cfg["runner"])
        runner = importlib.util.module_from_spec(spec_r)
        spec_r.loader.exec_module(runner)
        tdef = runner.task_by_id(json.loads(Path(cfg["taskset"]).read_text(encoding="utf-8")))[task]
        if action == "miss":  # a commit that does not do the task, so the oracle fails it
            target = Path(tdef["files"][0])
            target.write_text(target.read_text(encoding="utf-8") + "# stand-in: scripted miss\n",
                              encoding="utf-8")
            changed = [tdef["files"][0]]
        else:
            changed = runner.apply_edits(Path.cwd(), tdef["reference"])
        if action == "regress":  # passes its own oracle, breaks a landed task's: the merge gate fails
            changed += [f for f in runner.apply_edits(Path.cwd(), cfg["script"]["_regress"][task])
                        if f not in changed]
        if action == "detach":  # a builder whose child leaves for a session of its own, streams redirected
            child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"], start_new_session=True,
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            Path(cfg["script"]["_detached_pid"]).write_text(str(child.pid), encoding="utf-8")
        if action == "orphan":  # a builder that leaves a background child in its process group, its
            # markers cleared: only the group reap (the backstop) can find it. A marked child is the
            # dispatch sweep's, and on Linux that ends it first (PR #668 CI).
            child = subprocess.Popen(["sleep", "300"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL,
                                     env={k: v for k, v in os.environ.items() if not k.startswith("OF_")})
            Path(cfg["script"]["_orphan_pid"]).write_text(str(child.pid), encoding="utf-8")
        if action == "link_review":  # a hostile builder: the review inputs' directory as a link
            os.symlink(cfg["script"]["_review_link"], ".wip-review")
            changed.append(".wip-review")
        if action == "plant":  # a hostile builder: every config command channel git offers
            Path(".gitattributes").write_text("* filter=wipevil diff=wipevil\n", encoding="utf-8")
            changed.append(".gitattributes")
        sh("git", "add", "--", *changed)
        sh("git", "commit", "-q", "-m", f"{task}: {tdef['title']}")
        if action == "plant":  # planted AFTER its own commit, so only someone else's git can run it
            marker = cfg["script"]["_plant"]
            hook = Path(marker + ".sh")
            hook.write_text(f'#!/bin/sh\necho "cmd worker=${{OPEN_FLEET_DISPATCH_ID:-none}} $*" >> {marker}\ncat\n',
                            encoding="utf-8")
            hook.chmod(0o755)
            hooks = Path(marker + ".hooks")
            hooks.mkdir(exist_ok=True)
            for name in ("pre-push", "post-checkout", "reference-transaction"):
                (hooks / name).write_text(f'#!/bin/sh\necho "hook {name} worker=${{OPEN_FLEET_DISPATCH_ID:-none}}" >> {marker}\n',
                                          encoding="utf-8")
                (hooks / name).chmod(0o755)
            for key, value in (("diff.external", str(hook)), ("diff.wipevil.textconv", str(hook)),
                               ("filter.wipevil.smudge", str(hook)), ("core.hooksPath", str(hooks)),
                               ("core.fsmonitor", str(hook))):
                sh("git", "config", key, value)
    head = sh("git", "rev-parse", "HEAD")
    outcome = "failed" if action == "fail" else "succeeded"
    rc = subprocess.run([sys.executable, "-I", os.path.join(os.environ["OPEN_FLEET_ROOT"], "runtime",
                         "scripts", "send_msg.py"), "--type", "worker_done", "--outcome", outcome,
                         "--run", os.environ.get("OPEN_FLEET_RUN_ID", "default"),
                         "--subject", f"worker_done:{dispatch}",
                         "--payload", json.dumps({"head": head})]).returncode
    answer(f"WIP-BUILD-DONE {nonce} {head} {outcome}")
    sys.exit(3 if action == "solve_crash" else rc)  # solve_crash: reports success, then exits nonzero

nonce, head = review.group(1), review.group(3)
diff = Path(review.group(4)).read_text(encoding="utf-8", errors="replace")
verdict = "changes" if action == "changes" or "diff --git" not in diff else "approve"
text = f"Read {len(diff.splitlines())} diff lines.\nWIP-REVIEW {nonce} {head} {verdict}\n"
done = re.search(r"OPEN_FLEET_WORKER_DONE (disp_[0-9a-f]+) <outcome>", spec)
if done:
    text += f"OPEN_FLEET_WORKER_DONE {done.group(1)} succeeded\n"
answer(text)
if action == "approve_crash":  # a valid approval printed, then a nonzero exit
    sys.exit(3)
'''

# The dry run's default script: one scripted miss (an oracle bounce) and one review that asks
# for changes, so the inert pipeline exercises rework as well as conflicts and closes.
DRY_RUN_SCRIPT = {"T3": {"builder": ["miss"]}, "T1": {"reviewer": ["changes"]}}


class Sandbox(first_run.Sandbox):
    """first_run.py's sandbox (#596): private state store, scrubbed environment, setsid only,
    SHELL=/bin/sh; in inert mode a stand-in first on PATH behind a tripwire for every other
    harness name, and a private HOME."""

    def __init__(self, workdir: Path, worker: str, agent: str, inert_config: dict | None = None):
        self.inert_config = inert_config or {}
        super().__init__(workdir, worker, agent)  # it gives the run its OF_CALL_ID (call_tag)

    def _install_inert(self) -> None:
        super()._install_inert()
        (self.inert / "worker.py").write_text(INERT_WORKER, encoding="utf-8")
        (self.inert / "wip-config.json").write_text(json.dumps(self.inert_config), encoding="utf-8")


# ---------------------------------------------------------------------------- one run

def first_line(argv, env=None) -> str | None:
    """The first output line of a short probe (a --version), in its own process group."""
    try:
        proc = run_text(argv, env=env, timeout=30)
    except OSError as err:
        return f"unreadable: {err}"
    text = (proc.stdout or proc.stderr).strip()
    return text.splitlines()[0][:200] if text else None


def host_label() -> str:
    """The 12-hex label that names this run's machine: the host name's hash, or inside the container
    live harness the host's, which the launcher records in its attestation. The container's own
    name changes with every launch, so every run read as another machine and none pooled (#604)."""
    try:
        doc = json.loads(Path(contain.containment.ATTESTATION).read_text(encoding="utf-8"))
        host = doc.get("host_sha256") if isinstance(doc, dict) else None
        if isinstance(host, str) and re.fullmatch(r"[0-9a-f]{64}", host):
            return host[:12]
    except (OSError, ValueError):
        pass
    return sha256_bytes((platform.node() or "host").encode())[:12]


def host_facts() -> dict:
    """The machine a run ran on. The catalog clone is read through the hardened git like every
    other repository (adversarial pass: a command planted in its config never runs)."""
    head = git(ROOT, "rev-parse", "HEAD", check=False)
    dirty = git(ROOT, "status", "--porcelain", "--untracked-files=no", check=False)
    return {"platform": platform.platform(), "python": platform.python_version(),
            "git": first_line(gitexec.argv("--version"), env=git_env()),
            "bash": first_line(["bash", "--version"]), "machine": platform.machine(), "cpu_count": os.cpu_count(),
            "catalog_commit": head.stdout.decode().strip() if head.returncode == 0 else None,
            "catalog_dirty": bool(dirty.stdout.strip()) if dirty.returncode == 0 else None}


class Run:
    """One scheduled run: a fresh sandbox, waves of `builders` units, reviews by at most
    `reviewers` at a time, the oracle, the merge queue, and an append-only event record."""

    def __init__(self, args, prereg, taskset, paths, entry, results: Path):
        self.args, self.prereg, self.taskset, self.entry = args, prereg, taskset, entry
        self.prereg_path, self.prereg_sha, self.taskset_path = paths
        self.tasks = task_by_id(taskset)
        self.rid = entry["run_id"]
        self.cond = entry["condition"]
        self.dir = results / "runs" / self.rid
        self.log = self.dir / "events.jsonl"
        # One clock per host (events.py intervals need one); the label hashes the host name, so a
        # published record names the machine without carrying its name (host_label).
        self.clock = "wip-runner@host-" + host_label()
        self.cap = args.cost_cap
        self.budget = Budget(results)  # the experiment's one budget, shared with every other run
        self.calls: dict[str, str] = {}  # "<task>:<role>" -> the call identity it holds
        # What one dispatch may spend: the reservation the owner authorised (--reservation-usd; for
        # the inert stand-in it defaults to the synthetic cost the stand-in reports).
        self.reservation = args.reservation
        self.model_pin = args.model if args.worker == "live" else None
        self.held: dict[str, Decimal] = {}  # "<task>:<role>" -> the reservation it holds
        self.launched: dict[str, tuple[str, str]] = {}  # dispatch -> (store task, hold key)
        self.launches: dict[str, dict] = {}  # dispatch -> its effective launch (agent, flags, digest)
        # Once set (cost-cap, model-mismatch, time-limit), nothing more starts; orphan-alive, a failed
        # containment, overrides any of them, since it alone also stops the next oracle and gate.
        self.halt: str | None = None
        self.deadline = float("inf")  # the run's absolute wall-clock deadline (monotonic), set at start
        self.launched_models: dict[str, str | None] = {}
        self.usage_seen: set[str] = set()
        self.dispatch_tags: dict[str, str] = {}  # dispatch -> its own OF_DISPATCH_TAG (C-b)
        self.oracle_tags: list[str] = []  # every oracle call's OF_CALL_ID (C-d)
        self.full_hold: dict[str, bool] = {}  # calls charged their full hold whatever they report
        stop = prereg["stopping_rule"]
        self.max_attempts = stop["max_attempts_per_task"]
        scale = args.timeout_scale
        self.timeout_builder = int(stop["dispatch_timeout_minutes"]["builder"] * 60 * scale)
        self.timeout_reviewer = int(stop["dispatch_timeout_minutes"]["reviewer"] * 60 * scale)
        self.wall_limit = stop["run_wall_clock_minutes"] * 60
        self.units: dict[str, dict] = {}
        self.merges: list[dict] = []
        self.sources: dict[str, str] = {}
        self.integration = prereg["taskset"]["integration_branch"]
        self.default_branch = prereg["taskset"]["default_branch"]
        self.record = {"schema": RUN_SCHEMA, "run_id": self.rid, "position": entry["position"],
                       "repetition": entry["repetition"], "condition": self.cond,
                       "task_order": entry["task_order"], "status": "failed", "stop_reason": None}

    # --- plumbing ---------------------------------------------------------------------------
    def wrapper(self, argv, env=None, cwd=None, timeout=600):
        proc = run_text(argv, cwd=cwd or self.sb.target, env={**self.sb.env, **(env or {})}, timeout=timeout)
        self.commands.append({"argv": [str(a)[:120] for a in argv], "rc": proc.returncode})
        return proc

    def emit(self, kind, *, source_ref, task=None, dispatch=None, data=None, basis="observed",
             at=None, source_file=None, event_id=None):
        argv = [sys.executable, str(SCRIPTS / "events.py"), "--log", "events.jsonl", "emit",
                "--kind", kind, "--run", self.rid, "--epoch", "1", "--clock", self.clock,
                "--producer", "wip_curve.py", "--basis", basis, "--observed-at", at or now(),
                "--source-ref", source_ref]
        for flag, value in (("--task", task), ("--dispatch", dispatch), ("--source-file", source_file),
                            ("--event-id", event_id)):
            if value:
                argv += [flag, value]
        if data is not None:
            argv += ["--data", json.dumps(data, sort_keys=True)]
        proc = run_text(argv, cwd=self.dir)
        if proc.returncode != 0:
            raise RunFailed(f"events.py emit {kind}: rc={proc.returncode} {(proc.stderr or proc.stdout).strip()[:300]}")

    def ingest_state(self):
        proc = run_text([sys.executable, str(SCRIPTS / "events.py"), "--log", "events.jsonl",
                                   "ingest-state", "--db", str(self.sb.state_db), "--run", self.rid,
                                   "--epoch", "1", "--clock", self.clock], cwd=str(self.dir))
        if proc.returncode not in (0, 1):
            raise RunFailed(f"events.py ingest-state rc={proc.returncode}: {proc.stderr.strip()[:300]}")

    def ingest_usage(self, dispatch, store_task, key=None, call=None):
        """Retain the dispatch's stream, record its usage, and settle its hold: the cost charged.
        Re-entrant (Codex review, C1): a signal can land anywhere in here, so the dispatch counts as
        seen only once its charge is in the ledger, and its usage record carries the observation
        time the ledger kept, so a retry appends the same event, never a second or a conflicting one."""
        if dispatch in self.usage_seen:
            return Decimal(0)
        call = call or self.calls.get(key) or f"{self.rid}/dispatch/{dispatch}"
        row = self.dispatch_row(dispatch)
        lane = Path(row["lane_dir"]) if row and row["lane_dir"] else None
        stream = lane / "events.jsonl" if lane else None
        cost = None
        if stream and stream.is_file():
            rel = f"streams/{dispatch}.jsonl"
            (self.dir / "streams").mkdir(exist_ok=True)
            shutil.copyfile(stream, self.dir / rel)
            model = launched_model(self.dir / rel)
            self.launched_models[dispatch] = model
            if self.model_pin and model != self.model_pin and self.halt is None:
                self.halt = "model-mismatch"  # the harness did not run the pin: no further call starts
            if credential_rejected(self.dir / rel) and self.halt != "orphan-alive":
                self.halt = CREDENTIAL_REJECTED  # an infrastructure failure: no further call starts
            at = (self.budget.calls().get(call) or {}).get("usage_at")
            if at is None:  # kept before the record, so a retry records the same observation
                at = now()
                self.budget.note(call, run=self.rid, usage_at=at)
            proc = run_text([sys.executable, str(SCRIPTS / "events.py"), "--log", "events.jsonl",
                                       "ingest-usage", "--stream", rel, "--run", self.rid, "--epoch", "1",
                                       "--clock", self.clock, "--task", store_task, "--dispatch", dispatch,
                                       "--observed-at", at],
                                      cwd=str(self.dir))
            if proc.returncode == 0:
                cost = self.stream_cost(self.dir / rel)
        self.settle(key, cost, dispatch=dispatch, call=call)
        self.usage_seen.add(dispatch)  # only now: the charge is in the ledger
        return self.reservation if cost is None else cost

    @staticmethod
    def stream_cost(path: Path):
        total, seen = Decimal(0), False
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict) and obj.get("type") == "result":
                value = obj.get("total_cost_usd")
                if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                    return None
                total += Decimal(str(value))
                seen = True
        return total if seen else None

    # --- the spend guard (#604; PR #652's class: spend is reserved BEFORE a dispatch starts) ---
    def committed(self) -> Decimal:
        """Everything committed in the results directory: every run's charges and live holds."""
        return self.budget.total()

    def hold_unit(self, tid) -> bool:
        """Before a unit's builder starts, hold the worst case of every call the unit makes: its
        builder and its reviewer (no grader calls a model), in the shared ledger, atomically.
        False when the cap cannot cover it."""
        n = len(self.units[tid]["attempts"]) + 1 if tid in self.units else 1
        entries = [(f"{self.rid}/{tid}/a{n}/{role}", {"run": self.rid, "task": tid, "role": role})
                   for role in ("builder", "reviewer")]
        if not self.budget.hold(entries, self.reservation, self.cap):
            return False
        for (call, fields) in entries:
            key = f"{tid}:{fields['role']}"
            self.calls[key], self.held[key] = call, self.reservation
        return True

    def release_hold(self, key, launched_too: bool = False) -> None:
        """A held call that will not start: its hold goes back to the budget, unspent
        (`launched_too`: admitted, but refused before its launch)."""
        self.held.pop(key, None)
        call = self.calls.pop(key, None)
        if call:
            self.budget.release(call, launched_too=launched_too)

    def remaining(self) -> float:
        """Seconds left before the run's deadline; 0 once it passed, which halts the run."""
        left = self.deadline - time.monotonic()
        if left <= 0 and self.halt is None:
            self.halt = "time-limit"
        return max(left, 0.0)

    def admit(self, key) -> bool:
        """A dispatch starts only on a hold, only while nothing has halted the run (a launched
        model other than the pin, the deadline), and only while everything committed, its own
        hold included, is within the cap: a dispatch that overspent its hold refuses the next one.
        A refusal sets `halt` and releases the hold unspent."""
        if self.remaining() > 0 and self.halt is None and key in self.held \
                and self.budget.admit(self.calls[key], self.cap):
            return True
        self.halt = self.halt or "cost-cap"
        self.release_hold(key)
        return False

    def settle(self, key, cost, dispatch=None, call=None) -> None:
        """Charge a call what it spent (unobserved: its reservation, never free), exactly once in the
        shared ledger. The call is its hold's identity; a dispatch the runner never held a call for
        is charged under its own identity, `<run>/dispatch/<id>`, so it too is charged once."""
        if key is not None:
            self.held.pop(key, None)
            call = call or self.calls.pop(key, None)
        call = call or f"{self.rid}/dispatch/{dispatch}"
        self.budget.charge(call, cost if cost is not None else self.reservation, cost is not None, run=self.rid)
        if self.full_hold.get(call):  # what it left may have spent: the full hold, never less (C-b)
            rec = self.budget.calls().get(call) or {}
            self.budget.top_up(call, Decimal(rec.get("hold_usd") or self.reservation))

    def run_cost(self) -> dict:
        """This run's cost, read back from its calls in the shared ledger."""
        mine = Budget.of_run(self.budget.calls(), self.rid)
        charged = [v for v in mine.values() if v.get("state") == "charged"]
        return {"observed_usd": str(sum((Decimal(v["usd"]) for v in charged if v.get("measured")), Decimal(0))),
                "reserved_unobserved_usd": str(sum((Decimal(v["usd"]) for v in charged if not v.get("measured")),
                                                   Decimal(0))),
                "calls": len(mine)}

    def dispatch_row(self, dispatch):
        conn = sqlite3.connect(f"file:{self.sb.state_db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute("SELECT * FROM dispatches WHERE dispatch_id = ?", (dispatch,)).fetchone()
        finally:
            conn.close()

    def exit_of(self, dispatch):
        """The dispatch's exit status from the provider's own exit record (the lane's exit.json),
        retained as exits/<dispatch>.json so a saved run binds it too; None when there is none. A
        call's printed answer is trusted only when this is 0 (PR #668 review)."""
        row = self.dispatch_row(dispatch)
        src = Path(row["lane_dir"]) / "exit.json" if row is not None and row["lane_dir"] else None
        try:
            doc = json.loads(src.read_text(encoding="utf-8")) if src else None
        except (OSError, ValueError):
            doc = None
        if not isinstance(doc, dict):
            return None
        (self.dir / "exits").mkdir(exist_ok=True)
        (self.dir / "exits" / f"{dispatch}.json").write_text(json.dumps(doc, sort_keys=True) + "\n", encoding="utf-8")
        rc = doc.get("rc")
        return rc if isinstance(rc, int) and not isinstance(rc, bool) else None

    def worker_done(self, dispatch):
        """(outcome, store time) of the dispatch's worker_done, read from the store read-only, or
        (None, None) when it sent none."""
        row = self.dispatch_row(dispatch)
        if row is None:
            return None, None
        conn = sqlite3.connect(f"file:{self.sb.state_db}?mode=ro", uri=True)
        try:
            hit = conn.execute("SELECT outcome, created_at FROM messages WHERE msg_type = 'worker_done' "
                               "AND sender = ? AND run_id = ? ORDER BY created_at DESC LIMIT 1",
                               (row["terminal_handle"], self.rid)).fetchone()
        finally:
            conn.close()
        return (hit[0], hit[1]) if hit else (None, None)

    def create_task(self, spec, title):
        proc = self.wrapper(first_run.py("task_ops.py", "create", "--spec", spec, "--run", self.rid,
                                         "--task-title", title))
        task = first_run.field(proc.stdout, "CREATED")
        if proc.returncode != 0 or not task:
            raise RunFailed(f"task_ops.py create: rc={proc.returncode} {(proc.stderr or proc.stdout).strip()[:300]}")
        return task

    def spawn(self, store_task, worktree: Path, title, profile, key=None, nonce=None):
        env = {"PROFILE": profile}
        if profile == "rw":
            env["ORCA_COORD_ALLOW_AUTONOMOUS_WRITE"] = "1"
        dtag = secrets.token_hex(16)  # this dispatch's own marker, alongside the run's (C-b)
        env[contain.DISPATCH_MARKER] = dtag
        if key and (self.remaining() <= 0 or self.halt is not None):
            # Codex review (C2): the deadline, or a halt, reached between admission and here (the
            # review's preparation, the rest of a wave's launches): no call launches after it.
            self.halt = self.halt or "time-limit"
            self.release_hold(key, launched_too=True)
            return None
        call = self.calls.get(key) if key else None
        if call:  # before the provider can register it: a recovery finds the call by its store task
            self.budget.note(call, store_task=store_task)
        proc = self.wrapper(["bash", str(SCRIPTS / "spawn_worker.sh"), "--run", self.rid, store_task,
                             f"path:{worktree}", title, self.args.agent], env=env)
        disp = first_run.field(proc.stdout, "DISPATCH")
        if proc.returncode != 0 or not disp:
            raise RunFailed(f"spawn_worker.sh rc={proc.returncode}: {(proc.stderr or proc.stdout).strip()[-400:]}")
        self.launched[disp] = (store_task, key)  # from here on its call is spent until settled
        self.dispatch_tags[disp] = dtag
        if call:
            self.budget.note(call, state="launched", dispatch=disp)
        try:
            self.guard(worktree)
            self.launches[disp] = self.delivered(proc.stdout, nonce)
        except RunFailed:
            self.wrapper(first_run.py("worker_ops.py", "stop", "--dispatch", disp))
            raise
        return disp

    @staticmethod
    def delivered(spawn_out: str, nonce) -> dict:
        """The launch the provider recorded (LAUNCH_EFFECTIVE) must carry the unit's assignment,
        by its nonce: an assignment that never reached the harness argv is a run failure, never
        a silent measurement of something else (first_run.py's delivery step, #596). What is
        kept is the agent, its flags and the command's digest; the prompt is the contract."""
        line = next((ln.split("=", 1)[1] for ln in spawn_out.splitlines() if ln.startswith("LAUNCH_EFFECTIVE=")), None)
        try:
            launch = json.loads(line) if line else None
        except ValueError:
            launch = None
        if not isinstance(launch, dict) or not isinstance(launch.get("command"), str):
            raise RunFailed("the provider recorded no readable launch for this dispatch (LAUNCH_EFFECTIVE)")
        if nonce and nonce not in launch["command"]:
            raise RunFailed(f"the launch the provider recorded does not carry the assignment ({nonce})")
        return {"agent": launch.get("agent"), "args": launch.get("args"),
                "command_sha256": sha256_bytes(launch["command"].encode("utf-8"))}

    def guard(self, worktree: Path) -> None:
        """The deny hook the provider installed in the worker's tree must be armed (first_run.py's
        guard step, #596): a worker whose guard does not deny is stopped and the run fails."""
        settings = Path(worktree) / ".claude" / "settings.local.json"
        proc = run_text(["sh", str(SCRIPTS / "deny-hook.sh"), "--verify-settings", str(settings)])
        if proc.returncode != 0:
            raise RunFailed(f"the guard installed in {worktree} is not armed: {proc.stderr.strip()[:300]}")

    def state_of(self, dispatch):
        out = self.wrapper(first_run.py("worker_ops.py", "show", "--dispatch", dispatch)).stdout
        return first_run.field(out, "STATE")

    def transcript_answer(self, dispatch):
        proc = self.wrapper(first_run.py("orca_cli.py", "orchestration", "worker-read", "--dispatch", dispatch,
                                         "--limit", "100000", "--json"))
        try:
            messages = json.loads(proc.stdout)["result"]["transcript"]["messages"]
        except (ValueError, KeyError, TypeError):
            return ""
        lines = [str(block.get("text") or "") for msg in messages for block in (msg.get("blocks") or [])]
        return first_run.TRANSCRIPT.final_answer(self.args.agent, lines)

    def mq(self, *args, check=True, bounded=False):
        """merge_queue.py; `bounded`: a step that may block (a drain runs the gate) gets only the run's
        remaining time, and DeadlineReached when the deadline cut it (Codex review, C2)."""
        timeout = min(600, max(self.remaining(), 0.1)) if bounded else 600
        proc = self.wrapper([sys.executable, str(SCRIPTS / "merge_queue.py"), "--db", str(self.sb.dir / "merge-queue.db"),
                             "--repo-dir", str(self.sb.target), *args],
                            env=git_env({**self.sb.env, "OPEN_FLEET_STATE_DIR": str(self.sb.dir / "mq-state")},
                                        repo=self.sb.target), timeout=timeout)
        if bounded and proc.returncode == 124 and self.remaining() <= 0:
            raise DeadlineReached(f"merge_queue.py {args[0]} ran into the run's deadline")
        try:
            out = json.loads(proc.stdout)
        except ValueError:
            raise RunFailed(f"merge_queue.py {args[0]}: unreadable output rc={proc.returncode}: "
                            f"{(proc.stderr or proc.stdout).strip()[:300]}") from None
        if check and proc.returncode not in (0, 1):
            raise RunFailed(f"merge_queue.py {args[0]} rc={proc.returncode}: {json.dumps(out)[:400]}")
        return proc.returncode, out

    # --- setup ------------------------------------------------------------------------------
    def setup(self):
        sb, env = self.sb, self.sb.env
        origin = sb.dir / "origin.git"
        seed = build_seed(self.taskset, sb.dir / "seed", env)
        if seed != self.prereg["taskset"]["seed_commit"]:
            raise RunFailed(f"the seed built {seed}, not the registered {self.prereg['taskset']['seed_commit']}")
        git(sb.dir, "init", "-q", "--bare", str(origin), env=env)
        git(sb.dir / "seed", "push", "-q", str(origin), f"main:refs/heads/{self.default_branch}",
            f"main:refs/heads/{self.integration}", env=env)
        git(sb.dir, "clone", "-q", "--no-hardlinks", str(origin), str(sb.target), env=env)
        configure_repo(sb.target, env)
        git(sb.target, "branch", "-q", "--track", self.integration, f"origin/{self.integration}", env=env)
        self.record["seed_commit"] = seed
        rc, out = self.mq("init", "--base", self.integration, "--default", self.default_branch,
                          "--consent", f"wip-curve run {self.rid} (#604): merges only to {self.integration}",
                          "--mode", "git")
        if rc != 0:
            raise RunFailed(f"merge_queue.py init refused: {json.dumps(out)[:300]}")
        (sb.dir / "wt").mkdir()
        (sb.dir / "rv").mkdir()
        (sb.dir / "ck").mkdir()

    def integration_head(self):
        git(self.sb.target, "fetch", "-q", "origin", env=self.sb.env)
        head = git_out(self.sb.target, "rev-parse", f"origin/{self.integration}", env=self.sb.env)
        git(self.sb.target, "update-ref", f"refs/heads/{self.integration}", head, env=self.sb.env)
        return head

    # --- specs ------------------------------------------------------------------------------
    def builder_spec(self, tid, nonce):
        """The registered builder contract for one unit (the prereg pins the text, #604)."""
        t = self.tasks[tid]
        return render(self.prereg["contracts"]["builder"], task=tid, nonce=nonce, title=t["title"],
                      statement=t["statement"])

    def review_spec(self, tid, nonce, base, head, task_rel, diff_rel):
        """The registered reviewer contract for one review."""
        return render(self.prereg["contracts"]["reviewer"], task=tid, nonce=nonce, base=base, head=head,
                      task_file=task_rel, diff_file=diff_rel)

    # --- one wave ---------------------------------------------------------------------------
    def wave(self, k, planned):
        """Build, review, verify and merge the planned tasks; returns the tasks to carry. Builders
        and reviewers run together (PR #653 review): a unit joins the review queue as its builder
        settles, and a free reviewer slot takes the earliest worker_done (reviewer_availability)."""
        base = self.integration_head()
        if not all(self.hold_unit(tid) for tid in planned):  # over_budget() covered all of them
            raise RunFailed("a planned unit's worst case no longer fits the cap at wave open")
        store_ids = [self.units[t]["store_task"] for t in planned]
        self.emit("wave.open", source_ref=f"wip_curve.py:wave/{k}",
                  data={"wave": k, "builders": self.cond["builders"], "reviewers": self.cond["reviewers"],
                        "tasks": store_ids})
        attempts = {}
        for tid in planned:
            unit = self.units[tid]
            n = len(unit["attempts"]) + 1
            if n > 1:  # a re-dispatch: the coordinator returns the task to `ready` (rework)
                proc = self.wrapper(first_run.py("task_ops.py", "update", "--id", unit["store_task"], "--status",
                                                 "ready", "--run", self.rid))
                if proc.returncode != 0:
                    raise RunFailed(f"task_ops.py update {tid}: rc={proc.returncode} {proc.stderr.strip()[:300]}")
            branch = f"wip/{self.rid}/{tid.lower()}-a{n}"
            wt = self.sb.dir / "wt" / f"{tid.lower()}-a{n}"
            git(self.sb.target, "worktree", "add", "-q", "-b", branch, str(wt), base, env=self.sb.env)
            # Each builder's deadline runs from its own launch (PR #653 review: a deadline shared from
            # the wave's last launch gave the first builders that much more time).
            t0, w0 = time.monotonic(), time.time()
            disp = self.spawn(unit["store_task"], wt, f"wip-{tid.lower()}-a{n}", "rw", f"{tid}:builder",
                              unit["nonce"]) if self.admit(f"{tid}:builder") else None
            attempt = {"wave": k, "n": n, "dispatch": disp, "branch": branch, "base": base, "head": None,
                       "outcome": None, "deadline": t0 + self.timeout_builder,
                       "deadline_at": w0 + self.timeout_builder}
            if disp is None:  # the deadline or a halt came first: this unit stops, the run goes on to its end
                self.release_hold(f"{tid}:reviewer")
                attempt["outcome"] = f"stopped-{self.halt}"
            unit["attempts"].append(attempt)
            attempts[tid] = attempt
        building = {a["dispatch"]: tid for tid, a in attempts.items() if a["dispatch"]}
        queue, live, done = [], {}, []
        while building or queue or live:
            moved = self.poll_builders(building, attempts, base, queue, done)
            if self.review_step(queue, live) or moved:
                continue
            time.sleep(0.3)
        self.remaining()  # a wave cut short by the deadline halts the run
        # Done units board the merge queue in worker_done order.
        done.sort(key=lambda tid: (attempts[tid]["done_at"] or "", tid))
        # Once a process of the run could not be contained, no further oracle starts (Codex P1 (a)
        # at 9db89fbe3c: the next unit's oracle ran beside the first one's survivor).
        passed = [tid for tid in done if attempts[tid]["outcome"] is None and self.remaining() > 0
                  and self.halt != "orphan-alive" and self.oracle(tid, attempts[tid])]
        if self.remaining() > 0:
            self.merge(passed, attempts)
        for tid in planned:  # a halt leaves what it interrupted parked with its reason, never pending
            if self.halt and attempts[tid]["outcome"] in (None, "builder-timeout", "review-failed"):
                if attempts[tid]["outcome"] is None or self.halt == "time-limit":
                    attempts[tid]["outcome"] = f"stopped-{self.halt}"
        for tid in planned:  # every bounce counts as rework in its own wave (PR #653 review)
            a = attempts[tid]
            bounced = a["outcome"] != "landed" and not (a["outcome"] or "").startswith("stopped-")
            if bounced and a.get("oracle") != 2:  # a failing oracle verdict is its own record
                self.emit("unit.suspect", task=self.units[tid]["store_task"],
                          source_ref=f"wip_curve.py:bounce/{tid}-a{a['n']}/{a['outcome'] or 'unsettled'}")
        self.ingest_state()
        if self.held:
            raise RunFailed(f"holds outlived their wave: {sorted(self.held)}")
        carry = []
        for tid in planned:
            a = attempts[tid]
            if a["outcome"] == "landed":
                continue
            if (a["outcome"] or "").startswith("stopped-"):
                self.park(tid, a["outcome"], a.get("head"))
                continue
            if len(self.units[tid]["attempts"]) >= self.max_attempts:
                self.park(tid, "attempts-exhausted", a.get("head"))
            else:
                carry.append(tid)
        return carry

    def poll_builders(self, building, attempts, base, queue, done) -> bool:
        """Settle every builder that finished, timed out, or reached the run's deadline: measure it
        (before any reviewer is admitted against its spend), then queue it for review in
        worker_done order, or release its reviewer's hold. True when any builder settled."""
        settled = {}
        for disp, tid in sorted(building.items()):
            state = self.state_of(disp)
            if state and state not in first_run.LIVE_STATES:
                settled[disp] = self.on_time(disp, state, attempts[tid]["deadline_at"])
            elif self.remaining() <= 0 or time.monotonic() >= attempts[tid]["deadline"] \
                    or self.halt == "orphan-alive":  # an orphan may be spending: nothing runs on
                self.wrapper(first_run.py("worker_ops.py", "stop", "--dispatch", disp))
                settled[disp] = "timeout"  # its own timeout, the run's deadline, or an orphan
        if not settled:
            return False
        ended = {}
        for disp in sorted(settled):
            tid = building[disp]
            # Contained first (PR #668 review): what this dispatch left is ended and verified by its
            # own marker BEFORE its call is settled or its result accepted.
            ended[disp] = self.end_dispatch(disp, f"{tid}:builder")
            self.ingest_usage(disp, self.units[tid]["store_task"], f"{tid}:builder")
        self.ingest_state()
        for disp, state in sorted(settled.items()):
            tid = building.pop(disp)
            vouched, left = ended[disp]
            if left:
                attempts[tid]["left_behind"] = left
            if not vouched:  # it may still be spending: its result is never accepted, the run stops
                attempts[tid]["outcome"] = "stopped-orphan-alive"
                self.release_hold(f"{tid}:reviewer")
            elif left:  # it left processes behind (ended now): its result is not accepted
                attempts[tid]["outcome"] = "builder-failed"
                self.release_hold(f"{tid}:reviewer")
            elif self.classify(tid, attempts[tid], state, base):
                done.append(tid)
                queue.append(tid)
            else:
                self.release_hold(f"{tid}:reviewer")  # no review: its hold goes back unspent
        queue.sort(key=lambda tid: (attempts[tid]["done_at"] or "", tid))  # arrival (worker_done) order
        return True

    def record_oracle_tag(self, tag):
        """An oracle call's marker, in the run and the ledger before the call starts: finish() and
        the check before the next run sweep it (PR #668 review, C-d)."""
        self.oracle_tags.append(tag)
        self.budget.note(f"{self.rid}/run", oracle_tags=list(self.oracle_tags))

    def gate_tags(self):
        """The merge gate's oracle markers: the gate runs in the merge queue's process and appends
        each before its call starts."""
        try:
            tags, uncontained = gate_journal(self.sb.dir)
        except Refused:  # unreadable: nothing it names is vouched for
            tags, uncontained = [], ["UNCONTAINED (the gate journal cannot be read)"]
        if tags:
            self.budget.note(f"{self.rid}/run", gate_tags=tags)
        if uncontained:  # a gate's oracle could not be contained: this halt overrides any other
            self.halt = "orphan-alive"
        return tags

    def end_dispatch(self, disp, key):
        """End what one dispatch left behind and verify it, by the dispatch's own marker, before its
        call is settled or its result accepted (PR #668 review, C-b). The provider's monitor (the
        dispatch's group leader) is finishing its own bookkeeping and is waited for, briefly; any
        other process carrying the marker was left by the worker. (vouched, the pids it left). A
        dispatch that left something has its call charged its full hold, since what it left may
        have spent; one that cannot be vouched for halts the run orphan-alive."""
        tag, call = self.dispatch_tags.get(disp), self.calls.get(key)
        row = self.dispatch_row(disp)
        leaders = {int(row[c]) for c in ("pid", "monitor_pid") if row is not None and c in row.keys() and row[c]}
        marked = functools.partial(contain.call_processes, tag=tag, marker=contain.DISPATCH_MARKER)
        left, vouched = [], False
        if tag:
            try:
                stop_by = time.monotonic() + 5
                while (leaders & marked(contain.process_table())) and time.monotonic() < stop_by:
                    time.sleep(0.05)
                left = sorted(marked(contain.process_table()) - leaders)
                vouched = contain.sweep(tag=tag, marker=contain.DISPATCH_MARKER)
            except OSError:
                vouched = False  # the process table cannot be read: nothing is vouched for
        if call and (left or not vouched):
            self.full_hold[call] = True
        if not vouched:  # overrides any earlier halt: every guard after a failed containment asks for it
            self.halt = "orphan-alive"
        return vouched, left

    def on_time(self, disp, state, deadline_at) -> str:
        """A dispatch that ended after its deadline timed out, whenever the runner looked: its end
        is the store's, not the poll's (PR #653 review: a slow poll let a late builder succeed)."""
        row = self.dispatch_row(disp)
        ended = row["updated_at"] if row is not None else None
        return "timeout" if isinstance(ended, (int, float)) and ended > deadline_at else state

    def classify(self, tid, a, state, base) -> bool:
        """A settled builder's outcome; True when its unit is done and goes to review."""
        head = git_out(self.sb.target, "rev-parse", a["branch"], env=self.sb.env)
        row = self.dispatch_row(a["dispatch"])
        outcome, a["done_at"] = self.worker_done(a["dispatch"])
        a["state"] = state
        if state == "timeout" and self.halt == "time-limit":
            a["outcome"] = "stopped-time-limit"  # stopped at the run's deadline, not a builder failure
        elif state != "completed" or outcome != "succeeded" or head == base \
                or self.exit_of(a["dispatch"]) != 0:  # reported success, then a nonzero exit: failed
            a["outcome"] = "builder-failed" if state != "timeout" else "builder-timeout"
        elif row is not None and row["head_sha"] and row["head_sha"] != head:
            a["outcome"] = "builder-claim-mismatch"  # the store's head is not what git holds
        else:
            a["head"] = head
            a["tree"] = git_out(self.sb.target, "rev-parse", f"{head}^{{tree}}", env=self.sb.env)
            return True
        return False

    def review_step(self, queue, live) -> bool:
        """Start reviews while fewer than `reviewers` are in flight, earliest worker_done first,
        then settle the reviews that finished. True when anything started or settled."""
        started = False
        while queue and len(live) < self.cond["reviewers"]:
            started = True
            tid = queue.pop(0)
            a = self.units[tid]["attempts"][-1]
            nonce = f"WIP-NONCE:{secrets.token_hex(8)}"
            n = len(self.units[tid]["reviews"]) + 1
            wt = self.sb.dir / "rv" / f"{tid.lower()}-a{a['n']}-r{n}"
            git(self.sb.target, "worktree", "add", "-q", "--detach", str(wt), a["head"], env=self.sb.env)
            if os.path.lexists(wt / ".wip-review"):  # the builder committed it: a link would carry the
                self.release_hold(f"{tid}:reviewer")  # runner's writes out of the worktree (sweep)
                a["outcome"], a["review_blocked"] = "review-failed", "the head carries .wip-review itself"
                continue
            if not self.admit(f"{tid}:reviewer"):
                a["outcome"] = f"stopped-{self.halt}"  # refused before it starts, never detected after
                continue
            review_dir = wt / ".wip-review" / tid
            review_dir.mkdir(parents=True)
            diff = git(self.sb.target, "diff", a["base"], a["head"], env=self.sb.env).stdout
            (review_dir / "change.diff").write_bytes(diff)
            t = self.tasks[tid]
            (review_dir / "task.md").write_text(f"# {tid}: {t['title']}\n\n{t['statement']}\n", encoding="utf-8")
            task_rel, diff_rel = f".wip-review/{tid}/task.md", f".wip-review/{tid}/change.diff"
            spec = self.review_spec(tid, nonce, a["base"], a["head"], task_rel, diff_rel)
            rtask = self.create_task(spec, f"wip-review-{tid.lower()}-a{a['n']}")
            t0, w0 = time.monotonic(), time.time()  # its deadline runs from its launch, not after it
            disp = self.spawn(rtask, wt, f"wip-review-{tid.lower()}-a{a['n']}", "ro", f"{tid}:reviewer", nonce)
            if disp is None:  # the deadline or a halt came while the review was prepared
                a["outcome"] = f"stopped-{self.halt}"
                continue
            self.emit("review.started", source_ref=f"wip_curve.py:review/{disp}", task=self.units[tid]["store_task"],
                      dispatch=disp, data={"head_sha": a["head"]})
            review = {"dispatch": disp, "store_task": rtask, "nonce": nonce, "head": a["head"],
                      "attempt": a["n"], "verdict": None, "deadline_at": w0 + self.timeout_reviewer}
            self.units[tid]["reviews"].append(review)
            live[disp] = (tid, review, t0)
        settled = {}
        for disp, (_tid, review, since) in sorted(live.items()):
            state = self.state_of(disp)
            if state and state not in first_run.LIVE_STATES:
                settled[disp] = self.on_time(disp, state, review["deadline_at"])
            elif time.monotonic() - since > self.timeout_reviewer or self.remaining() <= 0 \
                    or self.halt == "orphan-alive":
                self.wrapper(first_run.py("worker_ops.py", "stop", "--dispatch", disp))
                settled[disp] = "timeout"  # its own timeout, the run's deadline, or an orphan
        for disp, state in sorted(settled.items()):
            tid, review, _since = live.pop(disp)
            vouched, left = self.end_dispatch(disp, f"{tid}:reviewer")  # contained before its verdict is read
            if left:
                review["left_behind"] = left
            if vouched and not left:
                self.finish_review(tid, review, state)
                continue
            review["state"], review["verdict"] = state, None
            self.units[tid]["attempts"][-1]["outcome"] = "review-failed" if vouched else "stopped-orphan-alive"
            self.ingest_usage(review["dispatch"], review["store_task"], f"{tid}:reviewer")
        return started or bool(settled)

    def finish_review(self, tid, review, state):
        a = self.units[tid]["attempts"][-1]
        answer = self.transcript_answer(review["dispatch"]) if state != "timeout" else ""
        rel = f"reviews/{review['dispatch']}.txt"
        (self.dir / "reviews").mkdir(exist_ok=True)
        (self.dir / rel).write_text(answer, encoding="utf-8")
        hits = [m for m in REVIEW_LINE.finditer(answer) if m.group(1) == review["nonce"]]
        review["state"] = state
        review["exit"] = self.exit_of(review["dispatch"]) if state != "timeout" else None
        if state != "completed" or review["exit"] != 0:
            # A call that did not finish successfully (died, killed, timed out, a nonzero exit) gives
            # no verdict, whatever it printed (PR #668 review): it never reaches review.verdict.
            a["outcome"] = "review-failed"
            review["verdict"] = None
        elif not hits or hits[-1].group(2) != review["head"]:
            a["outcome"] = "review-failed"
            review["verdict"] = None
        else:
            review["verdict"] = hits[-1].group(3)
            self.emit("review.verdict", source_ref=rel, source_file=rel, task=self.units[tid]["store_task"],
                      dispatch=review["dispatch"],
                      data={"verdict": review["verdict"], "reviewed_sha": review["head"],
                            "reviewed_wtree": a["tree"]})
            if review["verdict"] == "changes":
                a["outcome"] = "changes-requested"
        self.ingest_usage(review["dispatch"], review["store_task"], f"{tid}:reviewer")

    def oracle(self, tid, a) -> bool:
        """The coordinator's verification: the visible tests and the task's oracle at the worker's
        head, in a clean checkout cut from git (never the worker's tree)."""
        ck = self.sb.dir / "ck" / f"{tid.lower()}-a{a['n']}"
        extract_tree(self.sb.target, a["head"], ck, env=self.sb.env)
        started = now()
        result = run_oracle(ck, [self.tasks[tid]], self.taskset, self.sb.dir,
                            timeout=min(ORACLE_TIMEOUT, max(self.remaining(), 0.1)), on_tag=self.record_oracle_tag)
        if not result["contained"]:  # a process the worker's code started may still run: nothing more starts
            self.halt = "orphan-alive"  # over any earlier halt (Codex at 47e0616eac)
            a["outcome"] = "stopped-orphan-alive"
            a["kept"] = [str(ck), result["kept"]]  # the checkout and the oracle's files, to investigate
            return False
        if result["exit"] != 0 and self.remaining() <= 0:  # the run's deadline cut it: no verdict
            shutil.rmtree(ck, ignore_errors=True)
            a["outcome"] = "stopped-time-limit"
            return False
        doc = {"schema": ORACLE_SCHEMA, "run": self.rid, "task": tid, "head_sha": a["head"], "tree": a["tree"],
               "visible_tests": self.taskset["visible_tests"], "started_at": started, "finished_at": now(),
               **result}
        rel = f"oracle/{tid.lower()}-a{a['n']}.json"
        (self.dir / "oracle").mkdir(exist_ok=True)
        (self.dir / rel).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        shutil.rmtree(ck, ignore_errors=True)
        self.emit("verify.verdict", source_ref=rel, source_file=rel, task=self.units[tid]["store_task"],
                  basis="occurred", at=doc["finished_at"], data={"exit": result["exit"], "head_sha": a["head"]})
        a["oracle"] = result["exit"]
        if result["exit"] != 0:
            a["outcome"] = "oracle-failed"
        return result["exit"] == 0

    def merge(self, passed, attempts):
        """Board each verified, approved unit on the merge queue (git lane) and drain it behind the
        gate. A conflict or a failed gate is resolved `bounce`: the unit goes back to a builder.
        A gate whose oracle could not be contained is no ordinary failure: the gate journal is read
        right after every drain, and the run stops there, before any bounce or retry could start
        another oracle beside the survivor (Codex P1 (a) at 9db89fbe3c)."""
        if not passed or self.halt == "orphan-alive":  # after failed containment no gate starts
            return
        landing = {}
        for t, unit in self.units.items():
            heads = [a["head"] for a in unit["attempts"] if a.get("outcome") == "landed"]
            if t in passed:
                heads.append(attempts[t]["head"])
            if heads:
                landing[t] = heads
        landing_path = self.sb.dir / "landing.json"
        landing_path.write_text(json.dumps(landing, sort_keys=True), encoding="utf-8")
        gate = shlex.join([sys.executable, "-s", str(Path(__file__).resolve()), "gate", "--taskset",
                           str(self.taskset_path), "--landing", str(landing_path),
                           "--tags-file", str(self.sb.dir / "gate-tags.txt")])
        rc, out = self.mq("acquire", "--base", self.integration, "--holder", HOLDER, "--takeover")
        token = out.get("token")
        if rc != 0 or not token:
            raise RunFailed(f"merge_queue.py acquire: {json.dumps(out)[:300]}")
        by_unit = {}
        for tid in passed:
            a = attempts[tid]
            git(self.sb.target, "push", "-q", "origin", f"{a['branch']}:refs/heads/{a['branch']}", env=self.sb.env)
            payload = {"unit": self.units[tid]["store_task"], "branch": a["branch"], "base": self.integration,
                       "reviewed_sha": a["head"], "reviewed_wtree": a["tree"], "pr": None, "run": self.rid}
            rc, out = self.mq("enqueue", "--token", token, "--payload", json.dumps(payload), "--run", self.rid)
            if rc != 0:
                raise RunFailed(f"merge_queue.py enqueue {tid}: {json.dumps(out)[:300]}")
            by_unit[self.units[tid]["store_task"]] = tid
        self.mq("release", "--token", token)
        for _ in range(4 * len(passed) + 4):
            try:
                rc, out = self.mq("drain", "--base", self.integration, "--holder", HOLDER, "--gate-cmd", gate,
                                  "--ack", "--takeover", bounded=True)
            except DeadlineReached:
                break  # what landed is read below; the rest stays unlanded, stopped by the deadline
            steps = (out.get("steps") if rc == 0 else (out.get("data") or {}).get("drain", {}).get("steps")) or []
            for step in steps:
                if "ack" in step and step["ack"].get("landed"):
                    entry = step["ack"]["entry"]
                    self.merges.append({"entry": entry, "result": "landed", "merge_sha": step["ack"]["mergeSha"]})
            self.gate_tags()  # right after the drain: an uncontained gate oracle halts the run here
            if self.halt == "orphan-alive":
                if rc != 0 and out.get("code") == "queue_frozen":
                    tid = by_unit.get((out.get("data") or {}).get("unit"))
                    self.merges.append({"entry": out["data"].get("entry"), "result": "gate-uncontained", "task": tid,
                                        "head": attempts[tid]["head"] if tid else None})
                break  # no bounce, no retry: nothing more starts beside what survived
            if rc == 0:
                break
            if out.get("code") != "queue_frozen":
                raise RunFailed(f"the merge queue is blocked: {out.get('code')} {out.get('message', '')[:200]}")
            data = out["data"]
            plans = [s["plan"] for s in steps if "plan" in s]
            against = None
            for plan in plans:
                prior = plan.get("baseHead")
                for item in plan.get("planned", []):
                    if item.get("entry") == data["entry"]:
                        against = prior
                    elif item.get("prefixCommit"):
                        prior = item["prefixCommit"]
            ref = None
            if against:
                ref = f"refs/wip/prefix/{data['entry']}"
                git(self.sb.target, "update-ref", ref, against, env=self.sb.env)
            tid = by_unit.get(data.get("unit"))
            self.merges.append({"entry": data["entry"], "result": data.get("reason"), "task": tid,
                                "head": attempts[tid]["head"] if tid else None, "against": against,
                                "against_ref": ref})
            rc2, out2 = self.mq("acquire", "--base", self.integration, "--holder", HOLDER, "--takeover")
            self.mq("resolve", "--token", out2["token"], "--entry", data["entry"], "--action", "bounce",
                    "--reason", f"{data.get('reason')}: back to a builder (wip-curve)")
            self.mq("release", "--token", out2["token"])
        else:
            raise RunFailed("the merge queue did not drain")
        _, status = self.mq("status", "--base", self.integration)
        self.gate_tags()  # a drain the deadline cut short is read too (C-d)
        landed_head = self.integration_head()
        for entry in status.get("all", []):
            tid = by_unit.get(entry.get("unit"))
            if tid is None or entry.get("run_id") != self.rid or entry.get("reviewed_sha") != attempts[tid]["head"]:
                continue
            a = attempts[tid]
            if entry["state"] == "landed":
                ancestor = git(self.sb.target, "merge-base", "--is-ancestor", a["head"], landed_head,
                               env=self.sb.env, check=False).returncode == 0
                if not ancestor:
                    raise RunFailed(f"{tid}: the queue says landed, git does not hold {a['head']} on {self.integration}")
                a["outcome"] = "landed"
                a["merge_sha"] = entry["merge_sha"]
                self.emit("unit.closed", source_ref=f"merge-queue:{entry['entry_id']}",
                          task=self.units[tid]["store_task"],
                          data={"head_sha": a["head"], "head_wtree": a["tree"]})
            elif self.halt == "orphan-alive" and entry["state"] != "bounced":  # a bounce was an ordinary failure
                a["outcome"] = "stopped-orphan-alive"  # its gate, or one before it, could not be contained
            elif not entry.get("reason") and self.remaining() <= 0:
                a["outcome"] = "stopped-time-limit"  # never drained: the deadline came first, not a failure
            else:
                reason = (entry.get("reason") or "").split(" ", 1)[0] or entry["state"]
                a["outcome"] = {MQ_CONFLICT: "merge-conflict", MQ_GATE_FAILED: "gate-failed"}.get(reason, f"merge-{reason}")

    def park(self, tid, park_class, head=None):
        unit = self.units[tid]
        unit["final"] = "parked"
        unit["park_class"] = park_class
        data = {"park_class": park_class}
        if head:
            data["head_sha"] = head
        self.emit("unit.parked", source_ref=f"wip_curve.py:park/{tid}", task=unit["store_task"], data=data)

    # --- the run ----------------------------------------------------------------------------
    def execute(self, sb: Sandbox):
        self.sb = sb
        self.commands = []
        self.budget.start_run(self.rid, sb.dir, self.args.worker, sb.call_tag)  # first: every run directory has its start
        self.dir.mkdir(parents=True)
        self.record.update(started_at=now(), sandbox=str(sb.dir))
        started = time.monotonic()
        self.deadline = started + self.wall_limit
        try:
            self.setup()
            self.emit("run.start", source_ref=f"wip_curve.py:run/{self.rid}", data={"coordinator": HOLDER})
            for tid in self.entry["task_order"]:
                nonce = f"WIP-NONCE:{secrets.token_hex(8)}"
                store = self.create_task(self.builder_spec(tid, nonce), f"wip-{tid.lower()}")
                self.units[tid] = {"store_task": store, "nonce": nonce, "attempts": [], "reviews": [],
                                   "final": "not-run", "park_class": None}
            builders = self.cond["builders"]
            queue = list(self.entry["task_order"])
            nxt, k = queue[:builders], 0
            if self.over_budget(nxt):
                self.stop("cost-cap", [])  # not even the first wave fits the cap
                nxt = []
            while nxt:
                k += 1
                queue = [t for t in queue if t not in nxt]
                carry = self.wave(k, nxt)
                for tid in nxt:
                    if self.units[tid]["attempts"][-1]["outcome"] == "landed":
                        self.units[tid]["final"] = "closed"
                nxt = (carry + queue)[:builders]  # a wave holds at most `builders`, carried first
                # The stopping rule is applied BEFORE this wave closes: a unit it parks belongs to
                # this wave, so the record still derives every cell (#604).
                self.remaining()
                reason = self.halt if self.halt else "cost-cap" if (nxt and self.over_budget(nxt)) else None
                if reason:
                    self.stop(reason, carry)
                    nxt = []
                self.emit("wave.close", source_ref=f"wip_curve.py:wave/{k}", data={"wave": k})
            if self.record["stop_reason"] is None and self.remaining() <= 0:
                self.record.update(status="stopped", stop_reason="time-limit")  # finished past the deadline
            if self.record["stop_reason"] is None:
                self.record["status"] = "complete"
        except RunFailed as err:
            self.record.update(status="failed", error=str(err)[:1000])
        except (KeyboardInterrupt, SystemExit) as err:  # a signal: settle, then exit 128+N
            code = err.code if isinstance(err, SystemExit) else 128 + signal.SIGINT
            self.record.update(status="interrupted", stop_reason=f"signal (exit {code})")
            raise
        except Exception as err:  # a runner defect still ends in a retained, settled record
            self.record.update(status="failed", error=f"unexpected {type(err).__name__}: {err}"[:1000])
        finally:
            self.record["finished_at"] = now()
            self.finish()
        return self.record

    def over_budget(self, planned) -> bool:
        """Observed spend plus the next wave's worst case (a builder and a reviewer per unit, each
        at the reservation) would pass the cap."""
        return self.committed() + self.reservation * 2 * len(planned) > self.cap

    def stop(self, reason, carry):
        """The stopping rule: park every unit still in flight, so the record stays derivable. A
        refused credential ends the run `failed`, an infrastructure failure it may be re-run for."""
        self.record.update(status="failed" if reason == CREDENTIAL_REJECTED else "stopped", stop_reason=reason)
        for tid in carry:
            head = self.units[tid]["attempts"][-1].get("head") if self.units[tid]["attempts"] else None
            self.park(tid, f"stopped-{reason}", head)

    def settle_launched(self, charge_holds: bool = False) -> list[str]:
        """Reconcile every call of this run, after its workers were stopped. A launched call whose
        usage was never read is read now (no reported cost: its full reservation, PR #653 review).
        `charge_holds`: a process of the run may still be spending, so every call is charged its
        full hold, whatever its stream reported (Codex review of PR #668).
        A call the signal interrupted mid-spawn is found in the STORE by its task (#652's class)
        and charged the same way. A call that never launched is released. Each call is charged
        exactly once: the ledger reconciles a call already charged."""
        settled = []
        try:
            conn = sqlite3.connect(f"file:{self.sb.state_db}?mode=ro", uri=True)
            try:
                rows = conn.execute("SELECT dispatch_id, task_id FROM dispatches WHERE run_id = ?",
                                    (self.rid,)).fetchall()
            finally:
                conn.close()
            store_read = True
        except (sqlite3.Error, AttributeError):
            rows, store_read = [], False  # unreadable: a call mid-spawn may have run, so it is charged
        mine = Budget.of_run(self.budget.calls(), self.rid)
        by_dispatch = {v["dispatch"]: c for c, v in mine.items() if v.get("dispatch")}
        launching = {v.get("store_task"): c for c, v in mine.items()
                     if v.get("state") == "launching" and v.get("store_task")}
        for disp, store_task in rows:
            if disp not in by_dispatch and store_task in launching:
                call = launching.pop(store_task)
                self.budget.note(call, state="launched", dispatch=disp)
                by_dispatch[disp] = call
            self.launched.setdefault(disp, (store_task, None))
        for disp, (store_task, key) in sorted(self.launched.items()):
            call = by_dispatch.get(disp) or f"{self.rid}/dispatch/{disp}"
            if (self.budget.calls().get(call) or {}).get("state") in ("charged", "released"):
                continue  # the ledger says it is settled, whatever this process remembers (Codex, C1)
            self.usage_seen.discard(disp)
            try:
                if charge_holds:
                    raise RunFailed("not vouched for: its full hold")
                self.ingest_usage(disp, store_task, key, call=call)
            except (RunFailed, OSError, sqlite3.Error):
                self.settle(key, None, dispatch=disp, call=call)
                self.usage_seen.add(disp)
            settled.append(disp)
        for call, v in Budget.of_run(self.budget.calls(), self.rid).items():
            if v.get("state") == "held" or (v.get("state") == "launching" and store_read):
                self.budget.release(call, launched_too=True)  # never launched, or never registered: never ran
            elif v.get("state") in ("launching", "launched"):  # a call no dispatch above settled: its hold
                self.budget.charge(call, Decimal(v["usd"]), False)
        if charge_holds:
            for call, v in Budget.of_run(self.budget.calls(), self.rid).items():
                if v.get("state") == "charged":
                    self.budget.top_up(call, Decimal(v.get("hold_usd") or self.reservation))
        self.held.clear()
        self.calls.clear()
        return settled

    def finish(self):
        """Kill every child group, stop every worker, settle every launched call, retain the
        sources, write the run report and run.json last."""
        stop_all_groups()
        # Every process of the run torn down, finished dispatches and detached descendants included,
        # BEFORE the run settles and releases anything (Codex review, C3; of #668, B1): its worker
        # groups are reaped, then everything carrying the run's marker is swept until a fresh scan
        # finds none. A survivor, a teardown error, or a table that cannot be read vouches for
        # nothing: the run stops orphan-alive, every call is charged its full hold, and the sandbox
        # is kept.
        tags = [getattr(self.sb, "call_tag", None)] + self.oracle_tags + self.gate_tags()
        teardown = first_run.stop_workers(self.sb, sweep=(lambda: sweep_tags(tags)) if tags[0] else None)
        self.record["teardown"] = teardown
        contained = first_run.teardown_verified(teardown)
        if not contained:
            self.record.update(status="stopped", stop_reason="orphan-alive",
                               error=f"a process of the run may still be running: {teardown}"[:1000])
        self.record["settled_after_stop"] = self.settle_launched(charge_holds=not contained)
        sb = self.sb
        rec = self.record
        rec["units"] = {t: {k: v for k, v in u.items()} for t, u in self.units.items()}
        rec["not_run"] = [t for t, u in self.units.items() if not u["attempts"]] + \
            [t for t in self.entry["task_order"] if t not in self.units]
        rec["merges"] = self.merges
        rec["launched_models"] = self.launched_models
        rec["launches"] = self.launches
        rec["dispatch_tags"] = self.dispatch_tags
        rec["oracle_tags"], rec["gate_tags"] = self.oracle_tags, self.gate_tags()
        rec["commands"] = self.commands
        mine = Budget.of_run(self.budget.calls(), self.rid)  # this run's calls, bound with its sources
        (self.dir / "calls.json").write_text(json.dumps(mine, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        rec["cost"] = {"cap_usd": str(self.cap), **self.run_cost(), "ledger": Budget.NAME,
                       "experiment_committed_usd": str(self.budget.total()),
                       "reservation_per_dispatch_usd": str(self.reservation), "per_call_limit": PER_CALL_LIMIT}
        try:
            if sb.target.is_dir():
                head = git(sb.target, "rev-parse", f"refs/heads/{self.integration}", env=sb.env, check=False)
                rec["integration"] = {"branch": self.integration,
                                      "head": head.stdout.decode().strip() if head.returncode == 0 else None}
                git(sb.target, "fetch", "-q", "origin", "+refs/heads/*:refs/remotes/origin/*", env=sb.env, check=False)
                git(sb.target, "bundle", "create", "-q", str(self.dir / "target.bundle"), "--all", env=sb.env)
            if sb.state_db.is_file():
                src = sqlite3.connect(f"file:{sb.state_db}?mode=ro", uri=True)
                dst = sqlite3.connect(str(self.dir / "state.db"))
                try:
                    src.backup(dst)
                finally:
                    src.close()
                    dst.close()
            if (sb.dir / "merge-queue.db").is_file():
                _, receipts = self.mq("receipts", "--base", self.integration, check=False)
                (self.dir / "merge-receipts.json").write_text(json.dumps(receipts, indent=2, sort_keys=True) + "\n",
                                                              encoding="utf-8")
        except (RunFailed, sqlite3.Error, OSError) as err:
            rec.setdefault("error", f"retaining sources: {err}"[:1000])
            rec["status"] = "failed"
        if self.log.is_file():
            proc = run_text([sys.executable, str(SCRIPTS / "events.py"), "--log", "events.jsonl",
                                       "report", "--run", self.rid], cwd=str(self.dir))
            header = (f"# WIP-curve run {self.rid}\n\nRUN: wip-curve run={self.rid} "
                      f"condition={self.cond['id']} tier={rec.get('tier')}\n\n"
                      "## WIP-curve protocol row (derived by events.py report)\n\n")
            (self.dir / "run-report.md").write_text(header + proc.stdout, encoding="utf-8")
            _events, _sha, head = events.read_log(self.log)
            rec["events_head"] = head
        rec["sources"] = {str(p.relative_to(self.dir)): sha256_file(p) for p in sorted(self.dir.rglob("*"))
                          if p.is_file() and p.name != "run.json"}
        (self.dir / "run.json").write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------- report

def runs_in(results: Path) -> list[Path]:
    root = Path(results) / "runs"
    return sorted(p for p in root.iterdir() if (p / "run.json").is_file()) if root.is_dir() else []


def lost_in(results: Path) -> list[Path]:
    """Run directories with no run.json: a runner killed outright (SIGKILL, power loss) before it
    could settle. Their calls in the shared ledger still count, and they are reported as lost."""
    root = Path(results) / "runs"
    return sorted(p for p in root.iterdir() if p.is_dir() and not (p / "run.json").is_file()) if root.is_dir() else []


def spent_in(results: Path) -> Decimal:
    """Everything committed in a results directory: the shared ledger's total, every call counted
    once (its charge, or its hold while it may still spend). A lost run's live calls count at
    their holds until a recovery reconciles them; nothing is counted twice."""
    if not (Path(results) / Budget.NAME).is_file():
        return Decimal(0)
    return Budget(results).total()


def last_activity(calls: dict, run: str):
    """The last time the ledger heard from a run (a lost run's end, for the cooldown)."""
    times = [v.get("at") for v in calls.values() if v.get("run") == run and v.get("at")]
    return max(times) if times else None


def base_run(run_id: str) -> str:
    return re.sub(r"-a\d+$", "", run_id)


def live_positions(results: Path, positions: dict) -> set:
    """The registered positions live runs in `results` already took: each live run.json, and each
    lost run unless the ledger shows it ran the inert stand-in."""
    starts = Budget(results).calls()
    taken = set()
    for d in runs_in(results):
        if json.loads((d / "run.json").read_text(encoding="utf-8")).get("worker") == "live":
            taken.add(positions.get(base_run(d.name)))
    for d in lost_in(results):
        if (starts.get(f"{d.name}/run") or {}).get("worker", "live") == "live":
            taken.add(positions.get(base_run(d.name)))
    return taken - {None}


def check_order(results: Path, sched: dict, wanted: list) -> None:
    """Live runs take the registered order (order.conditions: repetition r runs the conditions in
    Latin-square row r; PR #653 review). A run starts only at the next position: every earlier
    position has run, and no later one. Its one re-run (-a2) comes before the next position."""
    positions = {rid: e["position"] for rid, e in sched.items()}
    taken = live_positions(results, positions)
    for base, attempt in wanted:
        p = positions[base]
        later = sorted(q for q in taken if q > p)
        missing = [q for q in range(1, p) if q not in taken] if attempt == 1 else []
        if later or missing:
            raise Refused(f"{base} is at registered position {p}: live runs take the registered order, and "
                          + (f"position(s) {later} already ran" if later else f"position(s) {missing} must run first")
                          + " (see `plan`)")
        taken.add(p)


def run_tags(start: dict) -> list[str]:
    """Every marker a run's ledger start record names: the run's own, and its oracle and gate calls'."""
    return [t for t in [start.get("call_tag"), *(start.get("oracle_tags") or []), *(start.get("gate_tags") or [])] if t]


def gate_journal(sandbox: Path):
    """(markers, UNCONTAINED lines) of the merge gate's journal in a run's sandbox, gate-tags.txt:
    the gate appends and syncs each oracle marker before its step starts. ([], []) when there is
    none; Refused when it cannot be read, since then nothing it names can be vouched for."""
    path = Path(sandbox) / "gate-tags.txt"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return [], []
    except (OSError, UnicodeDecodeError) as err:
        raise Refused(f"ORPHAN_ALIVE: the merge gate's journal {path} cannot be read ({err}): what its "
                      "oracles left cannot be vouched for, so nothing starts until it is inspected") from err
    return ([ln for ln in lines if ln and not ln.startswith("UNCONTAINED")],
            [ln for ln in lines if ln.startswith("UNCONTAINED")])


def journal_tags(start: dict) -> list[str]:
    """run_tags(start) and every marker in its sandbox's gate journal, read on its own: a runner
    killed between a gate and gate_tags() never copied the gate's markers into the ledger (Codex
    P1 (b) at 9db89fbe3c), so recovery and the check before a run must not rely on the ledger."""
    tags = run_tags(start)
    sandbox = start.get("sandbox")
    if sandbox and Path(sandbox).is_dir():  # a sandbox removed after a verified teardown has none
        tags += [t for t in gate_journal(Path(sandbox))[0] if t not in tags]
    return tags


def sweep_tags(tags) -> bool:
    """Sweep every marker (each one, even after one fails): True only when every sweep vouched."""
    return all([contain.sweep(tag=t) for t in tags])


def recover(results: Path, registered=()) -> list[str]:
    """Reconcile every call a LOST run (killed outright: no run.json) left live, under the results
    lock, so the ledger says what was spent instead of holding it forever (PR #653 review). Its
    workers are stopped first. A launched call is charged what its stream reports, or its full
    hold; a launching call is charged its hold if its sandbox's store registered it (it may have
    run) and released if not; a held call is released. Each is reconciled once."""
    budget = Budget(results)
    lost = {d.name for d in lost_in(results)}
    calls = budget.calls()
    claimed = {v["dispatch"] for v in calls.values() if v.get("dispatch")}  # a dispatch is one call's
    sandboxes = {v["run"]: Path(v["sandbox"]) for v in calls.values() if v.get("state") == "run" and v.get("sandbox")}
    settled = []
    for run in sorted(lost):
        live = {c: v for c, v in Budget.of_run(calls, run).items() if v.get("state") in LIVE_CALL}
        if not live:
            continue
        sandbox = sandboxes.get(run)
        db = sandbox / "state" / "runtime.db" if sandbox else None
        tags = journal_tags(calls.get(f"{run}/run") or {})
        if sandbox and (sandbox / "target").is_dir():  # its own store and scrubbed env, setsid, SHELL=/bin/sh
            if sandbox.is_symlink():  # the runner never made one; Sandbox() would create through it
                raise Refused(f"the ledger names {sandbox} as lost run {run}'s sandbox, and it is a symbolic "
                              "link: inspect it before any run starts")
            check_writable(sandbox, f"lost run {run}'s sandbox (from the ledger)", registered)
            teardown = first_run.stop_workers(first_run.Sandbox(sandbox, "live", "claude"),
                                              sweep=functools.partial(sweep_tags, tags) if tags else None)
            verified = first_run.teardown_verified(teardown)
        else:  # no sandbox to stop: its markers are still swept
            verified = bool(tags) and sweep_tags(tags)
        rows, store_read = {}, False
        try:
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            try:
                for row in conn.execute("SELECT * FROM dispatches WHERE run_id = ?", (run,)):
                    rows[row["dispatch_id"]] = row
            finally:
                conn.close()
            store_read = True
        except (sqlite3.Error, TypeError):
            pass  # unreadable or gone: a call mid-spawn may have run, so it is charged its hold
        for call, v in sorted(live.items()):
            disp = v.get("dispatch")
            if not disp and v.get("state") == "launching":  # killed mid-spawn: did the store register it?
                disp = next((d for d, r in rows.items() if r["task_id"] == v.get("store_task") and d not in claimed),
                            None)
                if disp:
                    claimed.add(disp)
                    budget.note(call, state="launched", dispatch=disp)
            if v.get("state") == "held" or (v.get("state") == "launching" and not disp and store_read):
                budget.release(call, launched_too=True)
                continue
            row = rows.get(disp)
            stream = Path(row["lane_dir"]) / "events.jsonl" if row is not None and row["lane_dir"] else None
            # Settled at what its stream reports only once its teardown is verified (PR #668 review):
            # a process of it may still be spending, so an unverified one is charged its full hold.
            cost = Run.stream_cost(stream) if verified and stream and stream.is_file() else None
            budget.charge(call, cost if cost is not None else Decimal(v["usd"]), cost is not None)
            settled.append(call)
        if not verified:  # a call it already settled is raised to its full hold too
            for call, v in Budget.of_run(budget.calls(), run).items():
                if v.get("state") == "charged" and v.get("hold_usd"):
                    budget.top_up(call, Decimal(v["hold_usd"]))
    return settled


def describe(values: list[Fraction], places=2) -> dict:
    """n, every value, mean, sample sd and a two-sided 95% Student-t interval (#604: uncertainty
    is reported, never narrowed). Exact arithmetic; the square root in 50-digit decimals."""
    n = len(values)
    out = {"n": n, "values": [fmt(v, places) for v in values]}
    if not n:
        return {**out, "mean": None, "sd": None, "ci95": None, "min": None, "max": None}
    mean = sum(values, Fraction(0)) / n
    out.update(mean=fmt(mean, places), min=fmt(min(values), places), max=fmt(max(values), places))
    if n < 2:
        return {**out, "sd": None, "ci95": None, "note": "one run: no spread to estimate"}
    var = sum(((v - mean) ** 2 for v in values), Fraction(0)) / (n - 1)
    with localcontext() as ctx:
        ctx.prec = 50
        sd = (Decimal(var.numerator) / Decimal(var.denominator)).sqrt()
        t = Decimal(T95.get(n - 1, "1.960"))
        half = t * sd / Decimal(n).sqrt()
        m = Decimal(mean.numerator) / Decimal(mean.denominator)
        q = Decimal(1).scaleb(-places)
        out.update(sd=str(sd.quantize(q, rounding=ROUND_HALF_EVEN)),
                   ci95=[str((m - half).quantize(q, rounding=ROUND_HALF_EVEN)),
                         str((m + half).quantize(q, rounding=ROUND_HALF_EVEN))])
    return out


def wilson(k: int, n: int) -> dict:
    """A pooled proportion with its 95% Wilson score interval."""
    if n == 0:
        return {"k": k, "n": n, "p": None, "ci95": None}
    with localcontext() as ctx:
        ctx.prec = 50
        p, z2, dn = Decimal(k) / Decimal(n), Z95 * Z95, Decimal(n)
        denom = 1 + z2 / dn
        center = (p + z2 / (2 * dn)) / denom
        half = Z95 * (p * (1 - p) / dn + z2 / (4 * dn * dn)).sqrt() / denom
        q = Decimal("0.001")
        return {"k": k, "n": n, "p": str(p.quantize(q, rounding=ROUND_HALF_EVEN)),
                "ci95": [str(max(center - half, Decimal(0)).quantize(q, rounding=ROUND_HALF_EVEN)),
                         str(min(center + half, Decimal(1)).quantize(q, rounding=ROUND_HALF_EVEN))]}


class Bound:
    """One run's retained sources, each re-hashed against the digest run.json binds."""

    def __init__(self, run_dir: Path):
        run_dir = self.dir = Path(run_dir).resolve()
        try:
            self.record = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as err:
            raise SourceError(f"{run_dir}/run.json is unreadable: {err}") from err
        self.problems = []
        sources = self.record.get("sources") or {}
        for rel, digest in sorted(sources.items()):
            path = run_dir / rel
            if not path.is_file():
                raise SourceError(f"{self.record.get('run_id')}: bound source {rel} is missing")
            if sha256_file(path) != digest:
                raise SourceError(f"{self.record.get('run_id')}: bound source {rel} does not hash to the "
                                  f"digest run.json binds ({digest[:16]}…) — altered after the run")
        extra = sorted(str(p.relative_to(run_dir)) for p in run_dir.rglob("*")
                       if p.is_file() and p.name != "run.json" and str(p.relative_to(run_dir)) not in sources)
        if extra:
            raise SourceError(f"{self.record.get('run_id')}: unbound file(s) in the run directory: {extra}")

    def path(self, rel):
        return self.dir / rel


def call_failure(bound: Bound, dispatch: str):
    """Why a retained run's dispatch did not finish successfully, from its bound store and exit
    record, or None: completed in the store, and exit status 0 (PR #668 review)."""
    db = bound.path("state.db")
    if not db.is_file():
        return "no retained store"
    conn = sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True)  # a bound source: nothing written beside it
    try:
        row = conn.execute("SELECT state FROM dispatches WHERE dispatch_id = ?", (dispatch,)).fetchone()
    finally:
        conn.close()
    if row is None or row[0] != "completed":
        return f"the store says {row[0] if row else 'nothing'}"
    try:
        rc = json.loads(bound.path(f"exits/{dispatch}.json").read_text(encoding="utf-8")).get("rc")
    except (OSError, ValueError, AttributeError):
        return "no retained exit status"
    return None if rc == 0 else f"exit status {rc}"


def bind_outcomes(bound: Bound, derived: dict, raw_events: list, prereg: dict, taskset: dict) -> list[str]:
    """Every terminal outcome re-checked against git and review authority, from the retained
    bundle and artifacts alone (#604 Verification): [] when all bind."""
    rec, problems = bound.record, []
    integration = prereg["taskset"]["integration_branch"]
    if rec.get("seed_commit") != prereg["taskset"]["seed_commit"]:
        problems.append(f"the run started at {rec.get('seed_commit')}, not the registered seed commit")
    if not bound.path("target.bundle").is_file():
        return problems + ["no retained git bundle: no terminal outcome can be checked"]
    by_store = {u["store_task"]: t for t, u in (rec.get("units") or {}).items()}
    tasks = task_by_id(taskset)
    with tempfile.TemporaryDirectory(prefix="wip-curve-bind-") as tmp:
        repo = Path(tmp) / "repo.git"
        git(Path(tmp), "init", "-q", "--bare", str(repo))
        if git(repo, "fetch", "-q", str(bound.path("target.bundle")), "+refs/*:refs/*", check=False).returncode:
            return problems + ["the retained bundle does not unpack"]
        ref = f"refs/heads/{integration}"
        roots = git(repo, "rev-list", "--max-parents=0", ref, check=False).stdout.decode().split()
        if roots != [prereg["taskset"]["seed_commit"]]:
            problems.append(f"{integration}'s root is {roots}, not the registered seed commit")
        reviews = [e for e in raw_events if e["kind"] == "review.verdict"]
        verdicts = [e for e in raw_events if e["kind"] == "verify.verdict"]
        for wave in derived["waves"]:
            for unit in wave["units"]:
                if unit["outcome"] == "closed-unverified":
                    problems.append(f"{unit['task']}: CLOSED at a head no passing verdict names")
                if unit["outcome"] != "verified-closed":
                    continue
                head = unit["revisions"]["closed_at"]
                tid = by_store.get(unit["task"], unit["task"])
                what = f"{tid} ({unit['task']}) at {head[:12]}"
                if git(repo, "merge-base", "--is-ancestor", head, ref, check=False).returncode != 0:
                    problems.append(f"{what}: not on {integration} in the retained bundle")
                    continue
                tree = git(repo, "rev-parse", f"{head}^{{tree}}", check=False).stdout.decode().strip()
                if unit["revisions"]["closed_tree"] and tree != unit["revisions"]["closed_tree"]:
                    problems.append(f"{what}: git's tree {tree} is not the recorded {unit['revisions']['closed_tree']}")
                builders = set(unit["dispatches"])
                approving = [e for e in reviews if e["task"] == unit["task"] and e["data"]["verdict"] == "approve"
                             and e["data"]["reviewed_sha"] == head and e["dispatch"] not in builders]
                if not approving:
                    problems.append(f"{what}: no approving review of that head by another dispatch")
                for disp in sorted({e["dispatch"] for e in approving} | builders):
                    why = call_failure(bound, disp)
                    if why:  # a stored answer from a call that did not finish successfully never binds
                        problems.append(f"{what}: {disp} did not finish successfully ({why})")
                for e in approving:
                    rel = e["source"]["ref"]
                    path = bound.path(rel)
                    if not path.is_file() or sha256_file(path) != e["source"]["sha256"]:
                        problems.append(f"{what}: the review artifact {rel} is missing or is not the bytes recorded")
                        continue
                    lines = [m for m in REVIEW_LINE.finditer(path.read_text(encoding="utf-8"))]
                    if not lines or lines[-1].group(2) != head or lines[-1].group(3) != "approve":
                        problems.append(f"{what}: {rel} does not end in an approving WIP-REVIEW line for that head")
                passing = [e for e in verdicts if e["task"] == unit["task"] and e["data"]["exit"] == 0
                           and e["data"]["head_sha"] == head]
                for e in passing:
                    rel = e["source"]["ref"]
                    path = bound.path(rel)
                    if not path.is_file() or sha256_file(path) != e["source"]["sha256"]:
                        problems.append(f"{what}: the oracle transcript {rel} is missing or altered")
                        continue
                    doc = json.loads(path.read_text(encoding="utf-8"))
                    if doc.get("head_sha") != head or doc.get("exit") != 0 or doc.get("task") != tid:
                        problems.append(f"{what}: {rel} does not record a pass of {tid} at that head")
                if not passing:
                    problems.append(f"{what}: no passing oracle verdict at that head")
                if tid in tasks:  # worker code a reader re-runs: an uncontained re-run raises, never a result
                    rerun = rerun_oracle(repo, head, tasks[tid], taskset, what)
                    if rerun["exit"] != 0:
                        problems.append(f"{what}: the oracle does not pass again at that head")
        for e in raw_events:
            if e["kind"] != "unit.parked" or not e["data"]["head_sha"]:
                continue
            head = e["data"]["head_sha"]
            what = f"{by_store.get(e['task'], e['task'])} parked at {head[:12]}"
            if git(repo, "cat-file", "-e", f"{head}^{{commit}}", check=False).returncode != 0:
                problems.append(f"{what}: the retained bundle does not hold that head")
            elif git(repo, "merge-base", "--is-ancestor", head, ref, check=False).returncode == 0:
                problems.append(f"{what}: parked, yet that head is on {integration}")
        for merge in rec.get("merges") or []:
            if merge.get("result") != "conflict":
                continue
            against = merge.get("against_ref")
            if not against or not merge.get("head"):
                problems.append(f"conflict {merge.get('entry')}: no retained prefix to re-derive it from")
                continue
            proc = git(repo, "merge-tree", "--write-tree", "--no-messages", against, merge["head"], check=False)
            if proc.returncode != 1:
                problems.append(f"conflict {merge['entry']}: git merges {merge['head'][:12]} onto its prefix "
                                f"cleanly (rc={proc.returncode}); the recorded conflict does not re-derive")
    return problems


def merge_counts(bound: Bound) -> dict:
    """Conflicts and gate failures from the merge queue's own receipts, cross-checked against the
    runner's merge log; None when the receipts were not retained."""
    path = bound.path("merge-receipts.json")
    if not path.is_file():
        return {"conflicts": None, "gate_failures": None, "landed": None}
    receipts = json.loads(path.read_text(encoding="utf-8")).get("receipts") or []
    reasons = [(r.get("body") or {}).get("reason") for r in receipts if r.get("kind") == "failed"]
    out = {"conflicts": reasons.count("conflict"),
           # The queue writes `gate_failed` (a failed gate, or one that timed out: exit 124).
           "gate_failures": reasons.count(MQ_GATE_FAILED),
           "gate_timeouts": sum((r.get("body") or {}).get("reason") == MQ_GATE_FAILED
                                and ((r.get("body") or {}).get("gate") or {}).get("exit") == 124
                                for r in receipts if r.get("kind") == "failed"),
           "landed": sum(r.get("kind") == "acknowledged" for r in receipts)}
    unclassified = sorted({str(r) for r in reasons if r not in (MQ_CONFLICT, MQ_GATE_FAILED)})
    if unclassified:  # a failure this cannot classify is not "no conflict" and "no failed gate"
        out.update(conflicts=None, gate_failures=None, gate_timeouts=None, unclassified=unclassified)
    return out


def summarize_run(run_dir: Path, prereg: dict, prereg_sha: str, taskset: dict, taskset_sha: str) -> dict:
    bound = Bound(run_dir)
    rec = bound.record
    rid = rec.get("run_id")
    out = {"run_id": rid, "condition": rec["condition"]["id"], "builders": rec["condition"]["builders"],
           "reviewers": rec["condition"]["reviewers"], "repetition": rec.get("repetition"),
           "position": rec.get("position"), "tier": rec.get("tier"), "status": rec.get("status"),
           "stop_reason": rec.get("stop_reason"), "error": rec.get("error"),
           "started_at": rec.get("started_at"), "finished_at": rec.get("finished_at"),
           "inputs_sha256": (rec.get("inputs") or {}).get("sha256"),
           "model_pin": rec.get("model_pin"), "harness_version": (rec.get("harness") or {}).get("version"),
           "task_order": rec.get("task_order"), "agent": rec.get("agent"),
           "machine": {"clock": rec.get("clock"), **{k: (rec.get("host") or {}).get(k)
                                                     for k in ("platform", "machine", "cpu_count")}},
           "attempt": rec.get("attempt", 1), "timeout_scale": rec.get("timeout_scale"),
           "run_json_sha256": sha256_file(run_dir / "run.json"),
           "infrastructure": infrastructure_failure(run_dir, rec.get("status"))}
    reasons = []
    if not bound.path("events.jsonl").is_file():
        out.update(metrics=None, compliant=False, noncompliance=["no event record was retained"])
        out["registered"] = registered_run(out)
        return out
    try:
        raw, file_sha, head = events.read_log(bound.path("events.jsonl"))
        if events.check_anchor(raw, head, expect_head=rec.get("events_head")):
            reasons.append("the event record does not end at the head run.json anchors")
        derived = events.derive(raw, rid, file_sha, head)
    except (events.EventsError, events.UsageError) as err:
        raise SourceError(f"{rid}: {err}") from err
    by_store = {u["store_task"]: t for t, u in (rec.get("units") or {}).items()}
    na = events.UNAVAILABLE
    waves, closed, wall, lat = [], 0, Fraction(0), []
    why = {"throughput": [], "latency": [], "rework": [], "freshness": [], "retries": []}
    bounced = units = fresh = retries = 0
    for w in derived["waves"]:
        m = w["metrics"]
        waves.append({"wave": w["wave"], "row": w["row"], "outcomes": w["outcomes"]})
        if m["throughput"]["value"] is None:
            why["throughput"] += m["throughput"][na]
        else:
            closed += m["throughput"]["verified_closed"]
            wall += Fraction(m["throughput"]["wall_clock_s"])
        # Latency is pooled from the units that reached verified-or-parked. A wave none of whose
        # units did (a builders=1 wave whose one unit was bounced) has no observation to pool;
        # events.py prints its cell `unavailable`, and it neither adds to nor voids the run's
        # latency. A wave whose units ARE measurable but unavailable (a contested or cross-clock
        # interval) voids it, with events.py's reasons.
        measured = [Fraction(u["latency"]["seconds"]) for u in w["units"] if u["latency"].get("seconds")]
        unmeasurable = [u for u in w["units"] if u["latency"].get("value") is None
                        and not u["latency"].get("excluded")]
        if m["latency_median"]["value"] is None and (measured or unmeasurable):
            why["latency"] += m["latency_median"][na]
        lat += measured
        for key in ("rework", "freshness", "retries"):
            if m[key]["value"] is None:
                why[key] += m[key][na]
        if m["rework"]["value"] is not None:
            bounced += m["rework"]["bounced"]
            units += m["rework"]["units"]
        fresh += int(m["freshness"]["value"] or 0)
        retries += int(m["retries"]["value"] or 0)
    if not derived["waves"]:
        for key in why:
            why[key].append("the record holds no wave")
    if not lat:
        why["latency"].append("no unit reached verified-or-parked after an observed worker_done")

    def cell(key, value):
        return {"value": None, na: sorted(set(why[key]))} if why[key] else value

    tput = Fraction(closed * 3600) / wall if wall else None
    if tput is None:
        why["throughput"].append("no wave wall-clock")
    metrics = {
        "throughput": cell("throughput", {"value": f"{fmt(tput)}/h" if tput is not None else None,
                                          "exact": str(tput), "verified_closed": closed, "wall_clock_s": str(wall)}),
        "latency": cell("latency", {"median_min": fmt(events._median(lat) / 60) if lat else None,
                                    "max_min": fmt(max(lat) / 60) if lat else None, "units": len(lat),
                                    "median_exact_s": str(events._median(lat)) if lat else None,
                                    "max_exact_s": str(max(lat)) if lat else None}),
        "rework": cell("rework", {"bounced": bounced, "units": units}),
        "freshness": None if why["freshness"] else fresh,
        "retries": retries if not why["retries"] else None,
        "derivable": not any(why[k] for k in ("throughput", "latency", "rework", "freshness")),
        "events_report_complete": derived["complete"],
        "rows": [w["row"] for w in waves],
    }
    metrics.update(merge_counts(bound))
    usage = derived["usage"]
    metrics["usage"] = {f: usage["run_total"][f].get("value") for f in events.USAGE_FIELDS}
    metrics["usage_unavailable"] = sorted({r for f in events.USAGE_FIELDS
                                           for r in usage["run_total"][f].get(events.UNAVAILABLE, [])})
    metrics["models"] = sorted(usage["models"])
    # Reviewer effort (a pre-registered confound): the usage of the review dispatches alone.
    reviewers = {r["dispatch"] for u in (rec.get("units") or {}).values() for r in u.get("reviews", [])}
    seen = {}
    for e in raw:
        if e["kind"] == "model.usage" and e["dispatch"] in reviewers:
            seen.setdefault(e["event_id"], e)
    covered = {e["dispatch"] for e in seen.values()}
    review_usage = {"reviews": len(reviewers), "observed": len(covered)}
    for field in ("input_tokens", "output_tokens"):
        values = [e["data"][field] for e in seen.values()]
        review_usage[field] = (sum(values) if covered == reviewers and reviewers and None not in values
                               else None)
    metrics["review_usage"] = review_usage
    metrics["review_queue"] = review_queue(raw, rid)
    closed_total = sum(w["outcomes"]["verified-closed"] for w in derived["waves"])
    cost = metrics["usage"]["cost_usd"]
    metrics["cost_per_verified_closed_usd"] = (
        str((Decimal(cost) / closed_total).quantize(Decimal("0.0001"), rounding=ROUND_HALF_EVEN))
        if cost is not None and closed_total else None)
    metrics["parked"] = {by_store.get(u["task"], u["task"]): ",".join(u["park_classes"])
                         for w in derived["waves"] for u in w["units"] if u["outcome"] == "parked"}
    tasks_out = {}
    for w in derived["waves"]:
        for u in w["units"]:
            tid = by_store.get(u["task"], u["task"])
            entry = tasks_out.setdefault(tid, {"waves": [], "outcome": None, "latency_min": []})
            entry["waves"].append(w["wave"])
            entry["outcome"] = u["outcome"]
            if u["latency"].get("seconds") is not None:
                entry["latency_min"].append(fmt(Fraction(u["latency"]["seconds"]) / 60))
    metrics["tasks"] = dict(sorted(tasks_out.items()))
    out["metrics"] = metrics
    out["registered"] = registered_run(out)
    out["record"] = {"log_sha256": file_sha, "head": head, "events": len(raw)}
    out["binding_problems"] = bind_outcomes(bound, derived, raw, prereg, taskset)
    # Protocol compliance (prereg "compliance"), each failure named.
    if rec.get("tier") != "live-unreviewed" or rec.get("worker") != "live":
        reasons.append("not a live run (the inert stand-in is a fixture)")
    if rec.get("prereg", {}).get("sha256") != prereg_sha or rec.get("taskset", {}).get("sha256") != taskset_sha:
        reasons.append("ran under another pre-registration or task set than this one")
    if not rec.get("model_pin") or not (rec.get("harness") or {}).get("version"):
        reasons.append("the model pin or harness version was not recorded")
    elif metrics["models"] != [rec["model_pin"]]:
        reasons.append(f"observed model(s) {metrics['models']} are not the pin {rec['model_pin']!r}")
    for w in derived["waves"]:  # the WIP the record shows each wave ran, not the label
        if (w["builders"], w["reviewers"]) != (rec["condition"]["builders"], rec["condition"]["reviewers"]):
            reasons.append(f"wave {w['wave']} ran builders={w['builders']} reviewers={w['reviewers']}, not the "
                           f"condition's builders={rec['condition']['builders']} reviewers={rec['condition']['reviewers']}")
    if not metrics["derivable"]:
        reasons.append("events.py cannot derive the throughput, latency, rework and freshness the experiment uses")
    if out["binding_problems"]:
        reasons.append(f"{len(out['binding_problems'])} terminal outcome(s) do not bind")
    if rec.get("status") != "complete":
        reasons.append(f"the run ended {rec.get('status')}" + (f" ({rec['stop_reason']})" if rec.get("stop_reason") else ""))
    if out["infrastructure"] and rec.get("status") not in RETRYABLE:
        reasons.append(f"an infrastructure failure: {out['infrastructure']}")
    out["compliant"] = not reasons
    out["noncompliance"] = reasons
    return out


# What the report emits for the registration's metrics.report_fields: check-prereg refuses a
# registered field not listed here, and the tests diff the two (PR #652's class: a registered
# metric the report silently omitted — review queue, cost per CLOSED unit, latency max by
# condition, the condition's role and parked units were, #604).
REPORTED_RUN = ("status", "throughput_per_h", "latency_median_min", "latency_max_min", "rework", "freshness",
                "conflicts", "gate_failures", "retries", "review_queue_median_min", "review_queue_max_min",
                "input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens",
                "cost_usd", "cost_per_verified_closed_usd", "review_tokens_per_review", "parked")
REPORTED_CONDITION = ("role", "throughput_per_h", "latency_median_min", "latency_max_min", "rework", "freshness",
                      "conflicts", "gate_failures", "retries", "review_queue_median_min", "review_queue_max_min",
                      "input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens",
                      "cost_usd", "cost_per_verified_closed_usd", "review_tokens_per_review", "tasks")


def review_queue(raw: list, rid: str) -> dict:
    """worker_done at a head -> a review of that head starting, per review (a reviewer dispatch
    and head), on the record events.py admits; unavailable with events.py's reasons otherwise."""
    kept = events.screen([e for e in raw if e["run"] == rid])[0]
    dones, starts = {}, {}
    for e in kept:
        if e["kind"] == "task.done" and e["data"]["head_sha"]:
            dones.setdefault((e["task"], e["data"]["head_sha"]), []).append(e)
        elif e["kind"] == "review.started":
            key = (e["task"], e["dispatch"] or e["event_id"], e["data"]["head_sha"])
            starts.setdefault(key, []).append(e)
    values, why = [], []
    for (task, _review, head), started in sorted(starts.items()):
        at = dones.get((task, head))
        if not at:
            why.append(f"unit {task}: review started at {head[:12]} with no worker_done at that head")
            continue
        (start, w1), (end, w2) = events.first(at, f"unit {task} worker_done"), events.first(started, "review.started")
        secs, w3 = (None, w1 or w2) if (w1 or w2) else events.interval(start, end, f"unit {task} review queue")
        if secs is None:
            why.append(w3)
        else:
            values.append(secs)
    if why or not values:
        return {"value": None, events.UNAVAILABLE: sorted(set(why)) or ["no review started"]}
    return {"median_min": fmt(events._median(values) / 60), "max_min": fmt(max(values) / 60),
            "reviews": len(values), "median_exact_s": str(events._median(values)), "max_exact_s": str(max(values))}


def launched_model(stream: Path):
    """The model a dispatch's harness reported launching (Claude's stream-json `system/init`
    line), or None when its stream names none."""
    for line in Path(stream).read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict) and obj.get("type") == "system" and obj.get("subtype") == "init":
            return obj.get("model") if isinstance(obj.get("model"), str) else None
    return None


_TOKEN_FIELDS = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")


# A refusal line's own non-zero numbers, at its top level only: its wall time, its one turn, its
# HTTP status and its place in the stream. Every other number it carries counts work, so is zero.
_REFUSAL_NUMBERS = frozenset({"duration_ms", "num_turns", "api_error_status", "result_index"})


def _no_work(value) -> bool:
    """True when no number in `value`, at any depth, is non-zero (Codex at 616217810a: a nested
    count, server_tool_use or iterations or modelUsage, is work too)."""
    if value is None or isinstance(value, (bool, str)):
        return True
    if isinstance(value, (int, float)):
        return value == 0
    if isinstance(value, dict):
        return all(_no_work(v) for v in value.values())
    return isinstance(value, list) and all(_no_work(v) for v in value)


def _zero_usage(line: dict, usage) -> bool:
    """True only for a line whose usage reports zero in every token count (a count it does not
    carry is unknown, never zero) and that carries no other non-zero number anywhere."""
    return isinstance(usage, dict) and all(type(usage.get(k)) is int and usage[k] == 0 for k in _TOKEN_FIELDS) \
        and all(_no_work(v) for k, v in line.items() if k not in _REFUSAL_NUMBERS)


def credential_rejected(stream: Path) -> bool:
    """True when a dispatch's stream is the harness's refusal of its credential and nothing else,
    wip1-b3r1-rep1's shape: the monitor's turn_started, the harness's init and notices, assistant
    turns of text alone, and results that are each an error with a reported zero cost, the last
    carrying an authentication message ("Not logged in", a 401); every line reports zero tokens
    and carries no other non-zero number but its timing, turn count and HTTP status. Any other line
    (a tool result, a thinking count, a tool call), a count a line does not report, a nested count
    (server tools, iterations, per-model usage), or one answered or paid result, and it is not
    (Codex at a61f3e660a, a8068b5cd5 and 616217810a)."""
    results = []
    for line in Path(stream).read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            return False
        kind = obj.get("type") if isinstance(obj, dict) else None
        if kind == "turn_started" or (kind == "system" and obj.get("subtype") in ("init", "informational")):
            continue
        if kind == "assistant":
            message = obj.get("message")
            content = message.get("content") if isinstance(message, dict) else None
            if not isinstance(content, list) or not _zero_usage(obj, message.get("usage")) \
                    or not all(isinstance(block, dict) and block.get("type") == "text" for block in content):
                return False
            continue
        cost = obj.get("total_cost_usd") if kind == "result" else None
        if kind != "result" or obj.get("is_error") is not True or not _zero_usage(obj, obj.get("usage")) \
                or type(cost) not in (int, float) or cost != 0:
            return False
        results.append(obj)
    return bool(results) and bool(_AUTH_FAILURE_RE.search(str(results[-1].get("result") or "")))


def recorded_dispatches(rec: dict) -> set:
    """Every dispatch a run record names: its builders' and reviewers' attempts, and every
    dispatch whose launched model it recorded."""
    found = set(rec.get("launched_models") or {})
    for unit in (rec.get("units") or {}).values():
        if isinstance(unit, dict):
            for entry in list(unit.get("attempts") or []) + list(unit.get("reviews") or []):
                if isinstance(entry, dict) and isinstance(entry.get("dispatch"), str):
                    found.add(entry["dispatch"])
    return found


def infrastructure_failure(run_dir: Path, status=None):
    """Why a recorded run failed for an infrastructure reason, or None: it ended failed,
    interrupted or lost, or the API refused every model call it made for the credential. A run of
    the second kind may still read `complete`, every unit parked, as #604's wip1-b3r1-rep1 did, so
    that claim is read from the run's bound evidence alone: every retained source unaltered and
    nothing unbound (Bound), at least one recorded dispatch, and exactly one bound stream per
    recorded dispatch, each a refused credential. A removed, altered or unbound stream never
    authorises a paid re-run (Codex at a61f3e660a)."""
    if status in RETRYABLE:
        return f"it ended {status}"
    try:
        bound = Bound(run_dir)
    except SourceError:
        return None
    dispatches = recorded_dispatches(bound.record)
    streams = {rel[len("streams/"):-len(".jsonl")] for rel in bound.record.get("sources") or {}
               if rel.startswith("streams/") and rel.endswith(".jsonl")}
    if not dispatches or streams != dispatches:
        return None
    if all(credential_rejected(bound.path(f"streams/{d}.jsonl")) for d in sorted(dispatches)):
        return f"the API refused all {len(dispatches)} of its model calls for the credential"
    return None


def tokens_per_review(review_usage: dict):
    """(input + output tokens) per review, or None when either count is unobserved (a partial
    sum is not the reviewers' usage, and never a TypeError, PR #653 review)."""
    tin, tout, n = (review_usage.get(k) for k in ("input_tokens", "output_tokens", "reviews"))
    if tin is None or tout is None or not n:
        return None
    return Fraction(tin + tout, n)


def registered_run(run: dict) -> dict:
    """The registered per-run metrics, flat; None where the record cannot say (never 0)."""
    m = run.get("metrics")
    if not m:
        return {f: (run.get("status") if f == "status" else None) for f in REPORTED_RUN}
    usage = m["usage"]
    per_review = tokens_per_review(m["review_usage"])
    reviews_tokens = fmt(per_review) if per_review is not None else None
    return {
        "status": run.get("status"), "throughput_per_h": m["throughput"].get("value"),
        "latency_median_min": m["latency"].get("median_min"), "latency_max_min": m["latency"].get("max_min"),
        "rework": f"{m['rework']['bounced']}/{m['rework']['units']}" if "bounced" in m["rework"] else None,
        "freshness": m["freshness"], "conflicts": m["conflicts"], "gate_failures": m["gate_failures"],
        "retries": m["retries"], "review_queue_median_min": m["review_queue"].get("median_min"),
        "review_queue_max_min": m["review_queue"].get("max_min"),
        **{f: usage[f] for f in ("input_tokens", "output_tokens", "cache_read_input_tokens",
                                 "cache_creation_input_tokens", "cost_usd")},
        "cost_per_verified_closed_usd": m["cost_per_verified_closed_usd"],
        "review_tokens_per_review": reviews_tokens, "parked": m["parked"],
    }


def condition_block(cond: dict, runs: list[dict]) -> dict:
    tp = [Fraction(r["metrics"]["throughput"]["exact"]) for r in runs
          if r.get("metrics") and r["metrics"]["throughput"].get("exact")]
    med = [Fraction(r["metrics"]["latency"]["median_exact_s"]) / 60 for r in runs
           if r.get("metrics") and r["metrics"]["latency"].get("median_exact_s")]
    reworks = [r["metrics"]["rework"] for r in runs if r.get("metrics")]
    if all("bounced" in rw for rw in reworks):
        rework = wilson(sum(rw["bounced"] for rw in reworks), sum(rw["units"] for rw in reworks))
    else:  # a run whose rework is unavailable is never pooled as if it had none
        rework = {"k": None, "n": None, "p": None, "ci95": None,
                  "unavailable": "a run's rework could not be derived"}
    block = {"condition": cond["id"], "builders": cond["builders"], "reviewers": cond["reviewers"],
             "runs": [r["run_id"] for r in runs], "throughput_per_h": describe(tp),
             "latency_median_min": describe(med), "rework": rework}
    for key in ("freshness", "conflicts", "gate_failures", "retries"):
        values = [r["metrics"][key] for r in runs if r.get("metrics")]
        block[key] = ({"values": values, "total": sum(values)} if values and None not in values
                      else {"values": values, "total": None})
    usable = [r for r in runs if r.get("metrics")]
    per_review = [tokens_per_review(r["metrics"]["review_usage"]) for r in usable]
    per_review = [] if None in per_review else per_review  # one unobserved run voids the mean
    block["review_tokens_per_review"] = (describe(per_review) if usable and len(per_review) == len(usable)
                                         else {"n": len(usable), "unavailable": "a run's review usage was not "
                                               "fully observed; never 0"})
    tasks = {}
    for r in usable:  # within-task reading of the difficulty confound
        for tid, info in r["metrics"]["tasks"].items():
            entry = tasks.setdefault(tid, {"runs": 0, "verified_closed": 0, "latency_min": []})
            entry["runs"] += 1
            entry["verified_closed"] += info["outcome"] == "verified-closed"
            entry["latency_min"] += info["latency_min"]
    block["tasks"] = dict(sorted(tasks.items()))
    for field in ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens",
                  "cost_usd", "cost_per_verified_closed_usd"):
        vals = [r["metrics"]["usage"][field] if field in r["metrics"]["usage"] else r["metrics"][field]
                for r in usable]
        block[field] = (describe([Fraction(str(v)) for v in vals], 4 if "cost" in field else 2)
                        if vals and None not in vals else {"n": len(vals), "unavailable":
                                                           "a run's value was not fully observed; never 0"})

    def per_run(get):
        vals = [get(r["metrics"]) for r in usable]
        return describe([Fraction(v) / 60 for v in vals]) if vals and None not in vals else \
            {"n": len(vals), "unavailable": "a run's value could not be derived"}

    block["latency_max_min"] = per_run(lambda m: m["latency"].get("max_exact_s"))
    block["review_queue_median_min"] = per_run(lambda m: m["review_queue"].get("median_exact_s"))
    block["review_queue_max_min"] = per_run(lambda m: m["review_queue"].get("max_exact_s"))
    block["role"] = cond.get("role")
    block["registered"] = {f: block[f] for f in REPORTED_CONDITION}
    return block


def recommend(prereg: dict, blocks: dict, compliant: list[dict]) -> dict:
    """The pre-registered decision rule, applied mechanically; a recommendation, never a change."""
    rule = prereg["analysis"]["decision_rule"]
    settings = {(r["builders"], r["reviewers"]) for r in compliant}
    base = {"rule": rule, "authority": rule["authority"]}
    if len(compliant) < 3 or len(settings) < 3:
        return {**base, "status": "not-issued",
                "why": f"{len(compliant)} protocol-compliant run(s) at {len(settings)} differing WIP setting(s); "
                       "the protocol needs at least three runs at three settings"}

    def ci(cid):
        b = blocks.get(cid, {}).get("throughput_per_h") or {}
        return [Decimal(x) for x in b["ci95"]] if b.get("ci95") else None

    ref = ci("b3r1")
    if ref is None:
        return {**base, "status": "keep", "why": "b3r1 (the current cap) has no interval; nothing beats it"}
    for cid in ("b6r1", "b6r2"):
        other = ci(cid)
        if other is None or other[0] <= ref[1]:
            continue
        rw, rw_ref = blocks[cid]["rework"], blocks["b3r1"]["rework"]
        fr, fr_ref = blocks[cid]["freshness"], blocks["b3r1"]["freshness"]
        if None in (rw["p"], rw_ref["p"], fr["total"], fr_ref["total"]):
            continue
        if Decimal(rw["p"]) - Decimal(rw_ref["p"]) <= Decimal("0.10") and \
                Fraction(fr["total"], max(len(fr["values"]), 1)) - Fraction(fr_ref["total"], max(len(fr_ref["values"]), 1)) <= 1:
            return {**base, "status": "raise", "why": f"{cid}'s throughput interval lies above b3r1's"}
    low = ci("b1r1")
    if low is not None and low[0] > ref[1]:
        return {**base, "status": "lower", "why": "b1r1's throughput interval lies above b3r1's"}
    return {**base, "status": "keep", "why": "no pre-registered criterion for a change is met (a null or negative result)"}


def build_report(results: Path, prereg_path: Path | None = None, basis: str = "compliant") -> dict:
    prereg, taskset, path, prereg_sha, taskset_path = load_prereg(prereg_path)
    taskset_sha = sha256_file(taskset_path)
    sched = schedule(prereg, taskset)
    runs = [summarize_run(d, prereg, prereg_sha, taskset, taskset_sha) for d in runs_in(results)]
    ledger = Budget(results).calls() if (Path(results) / Budget.NAME).is_file() else {}
    for d in lost_in(results):  # reported, never dropped, never pooled
        entry = next((e for e in sched if e["run_id"] == re.sub(r"-a\d+$", "", d.name)), None)
        lost = {"run_id": d.name, "condition": entry["condition"]["id"] if entry else None,
                "builders": entry["condition"]["builders"] if entry else None,
                "reviewers": entry["condition"]["reviewers"] if entry else None, "tier": None,
                "status": "lost", "stop_reason": None, "error": None, "metrics": None, "compliant": False,
                "spend_committed_usd": str(_committed(Budget.of_run(Budget(results).calls(), d.name)))
                if (Path(results) / Budget.NAME).is_file() else None,
                "noncompliance": ["the runner was killed before it wrote run.json; its calls in the shared "
                                  "ledger count against the cap until a recovery reconciles them"],
                "lost_start": (ledger.get(f"{d.name}/run") or {}).get("at"),
                "lost_worker": (ledger.get(f"{d.name}/run") or {}).get("worker")}
        lost["registered"] = registered_run(lost)
        runs.append(lost)
    order = {e["run_id"]: e["position"] for e in sched}
    runs.sort(key=lambda r: (order.get(re.sub(r"-a\d+$", "", r["run_id"]), 10**6), r["run_id"]))
    present = {re.sub(r"-a\d+$", "", r["run_id"]) for r in runs}
    cooldown = prereg["isolation"]["cooldown_minutes"] * 60
    live = sorted((r for r in runs if r.get("tier") == "live-unreviewed" and r.get("started_at")),
                  key=lambda r: r["started_at"])
    # One experiment, one configuration: every live run is held to the FIRST live run's inputs,
    # model pin and harness version, so a change in any of them is never read as a WIP effect
    # (PR #653 review). A run that differs is reported, never pooled.
    first = live[0] if live else {}
    for run in live[1:]:
        for key, what in (("inputs_sha256", "experiment inputs (sha256)"), ("model_pin", "model pin"),
                          ("agent", "harness"), ("harness_version", "harness version"),
                          ("machine", "machine (host, platform, CPU count)")):
            if run.get(key) != first.get(key):
                run["compliant"] = False
                run.setdefault("noncompliance", []).append(
                    f"ran on another {what} ({str(run.get(key))[:40]}) than the first live run "
                    f"{first.get('run_id')} ({str(first.get(key))[:40]}): re-register before pooling them")
    # The registered order (order.conditions; PR #653 review): repetition r runs the conditions in
    # Latin-square row r, the protection against warm-up and time effects. A live run that started
    # after a later-scheduled run, or before an earlier-scheduled one, is reported, never pooled. A
    # lost run is placed by the start the ledger recorded, unless the ledger says it was inert.
    placed = sorted([(r["started_at"], order[base_run(r["run_id"])], r) for r in live
                     if base_run(r["run_id"]) in order]
                    + [(r["lost_start"], order[base_run(r["run_id"])], r) for r in runs
                       if r["status"] == "lost" and r.get("lost_start") and r.get("lost_worker") == "live"
                       and base_run(r["run_id"]) in order], key=lambda x: (x[0], x[1]))
    ran = {q for _a, q, _r in placed}  # a position some live run (or a lost live run) took
    for i, (_at, pos, run) in enumerate(placed):
        after = sorted({q for _a, q, _r in placed[:i] if q > pos})
        before = sorted({q for _a, q, _r in placed[i + 1:] if q < pos})
        if after or before:
            run["compliant"] = False
            run.setdefault("noncompliance", []).append(
                f"ran out of the registered order: position {pos} started "
                + (f"after position(s) {after}" if after else f"before position(s) {before}"))
        missing = [q for q in range(1, pos) if q not in ran]
        if missing:  # an inversion needs both runs present; a missing predecessor is no evidence (Codex, C4)
            run["compliant"] = False
            run.setdefault("noncompliance", []).append(
                f"no evidence that position(s) {missing}, registered before it, ran")
    cooldown_runs = [(datetime.fromisoformat(r["started_at"]), datetime.fromisoformat(r["finished_at"]), r)
                     for r in live]
    for run in runs:
        if run["status"] == "lost" and run.get("lost_worker") == "live" and run.get("lost_start"):
            ended = last_activity(ledger, run["run_id"])
            if ended:
                cooldown_runs.append((datetime.fromisoformat(run["lost_start"]), datetime.fromisoformat(ended), run))
    cooldown_runs.sort(key=lambda item: item[0])
    for (_, before_end, before), (run_start, _, run) in zip(cooldown_runs, cooldown_runs[1:], strict=False):
        gap = (run_start - before_end).total_seconds()
        if gap < cooldown:
            run["compliant"] = False
            run.setdefault("noncompliance", []).append(
                f"started {int(gap)}s after {before['run_id']} ended; the cooldown is {cooldown}s")
    # One re-run, and only of a run that failed for an infrastructure reason (the registration's
    # stopping rule): any other attempt is reported, never pooled (PR #653 review).
    attempts = {}
    for run in runs:
        m = re.fullmatch(r"(.+?)(?:-a(\d+))?", run["run_id"])
        attempts.setdefault(m.group(1), {})[int(m.group(2) or 1)] = run
    scheduled = {e["run_id"]: e for e in sched}
    for run in runs:  # a scheduled run, under its scheduled condition, repetition and task order
        entry = scheduled.get(re.sub(r"-a\d+$", "", run["run_id"]))
        if entry is None:
            why = "not a scheduled run of this registration"
        elif (run.get("condition"), run.get("repetition"), run.get("task_order")) != (
                entry["condition"]["id"], entry["repetition"], entry["task_order"]):
            why = (f"not the scheduled run: {entry['run_id']} is scheduled as {entry['condition']['id']} repetition "
                   f"{entry['repetition']} with its own task order")
        else:
            continue
        run["compliant"] = False
        run.setdefault("noncompliance", []).append(why)
    for run in runs:  # the registered dispatch deadlines, or the run is not this experiment's
        if run.get("timeout_scale") != 1.0:
            run["compliant"] = False
            run.setdefault("noncompliance", []).append(
                f"dispatch deadlines scaled by {run.get('timeout_scale')} from the registered ones")
    for _base, by_n in attempts.items():
        for n, run in by_n.items():
            why = None
            if n > 2:
                why = f"attempt {n}: the registration allows one re-run (-a2), no more"
            elif n == 2 and (by_n.get(1) or {}).get("status") not in RETRYABLE \
                    and not (by_n.get(1) or {}).get("infrastructure"):
                why = (f"attempt 2 re-runs a run that did not fail for an infrastructure reason (attempt 1 "
                       f"{'ended ' + str(by_n[1].get('status')) if 1 in by_n else 'is absent'})")
            if why:
                run["compliant"] = False
                run.setdefault("noncompliance", []).append(why)
    compliant = [r for r in runs if r["compliant"]]
    pool = compliant if basis == "compliant" else [r for r in runs if r.get("metrics")]
    blocks = {c["id"]: condition_block(c, [r for r in pool if r["condition"] == c["id"]])
              for c in prereg["conditions"]}
    tiers = sorted({r["tier"] for r in runs if r.get("tier")})
    try:
        rel = str(path.resolve().relative_to(ROOT))
    except ValueError:
        rel = str(path)
    return {
        "schema": REPORT_SCHEMA, "basis": basis,
        "prereg": {"path": rel, "sha256": prereg_sha, "version": prereg["version"]},
        "taskset": {"path": prereg["taskset"]["path"], "sha256": taskset_sha},
        "tiers": tiers,
        "evidence": ("live" if tiers == ["live-unreviewed"] else
                     "none (fixture runs only: they exercise the pipeline and are not evidence)" if tiers == ["fixture-tested"]
                     else "mixed" if tiers else "none"),
        "scheduled": len(sched), "present": len(present & {e["run_id"] for e in sched}),
        "missing": [e["run_id"] for e in sched if e["run_id"] not in present],
        "runs": runs, "conditions": [blocks[c["id"]] for c in prereg["conditions"]],
        "compliant_runs": [r["run_id"] for r in compliant],
        # The rows show `basis`; the decision is the compliant runs' alone, whatever is shown, so
        # an excluded run can never sway it (PR #653 review).
        "recommendation": recommend(prereg, {c["id"]: condition_block(c, [r for r in compliant if r["condition"] == c["id"]])
                                             for c in prereg["conditions"]}, compliant),
        "generalization_limits": prereg["generalization_limits"],
    }


def _cell(value):
    if value is None:
        return "unavailable"
    if isinstance(value, dict):
        if value.get("mean") is None:
            return "no run" if value.get("n") == 0 else "unavailable"
        ci = f" [{value['ci95'][0]}, {value['ci95'][1]}]" if value.get("ci95") else ""
        return f"{value['mean']}{ci} (n={value['n']})"
    return str(value)


def _registered_cell(value) -> str:
    """One registered metric as a table cell: `unavailable` where the record cannot say."""
    if value is None:
        return "unavailable"
    if isinstance(value, dict) and "k" in value and "ci95" in value:  # a Wilson proportion
        return f"{value['k']}/{value['n']} = {value['p']} [{value['ci95'][0]}, {value['ci95'][1]}]" \
            if value["p"] else ("unavailable" if value.get("unavailable") else "no unit")
    if isinstance(value, dict) and "total" in value:  # summed counts
        return _cell(value["total"])
    if isinstance(value, dict) and ("mean" in value or "unavailable" in value):
        return _cell(value) if "mean" in value else "unavailable"
    if isinstance(value, dict):  # parked units, or per-task rows
        if not value:
            return "none"
        return "; ".join(f"{k}: {v if not isinstance(v, dict) else str(v.get('verified_closed')) + '/' + str(v.get('runs'))}"
                         for k, v in sorted(value.items()))
    return str(value).replace("|", "/")


def render_markdown(report: dict) -> str:
    lines = ["# WIP-curve experiment report", "",
             f"Pre-registration `{report['prereg']['path']}` v{report['prereg']['version']} "
             f"(sha256 `{report['prereg']['sha256']}`); task set sha256 `{report['taskset']['sha256']}`.",
             f"Evidence: {report['evidence']}. Basis of the condition rows: {report['basis']} runs. "
             f"Runs present: {report['present']} of {report['scheduled']} scheduled; protocol-compliant: "
             f"{len(report['compliant_runs'])}.", "",
             "## Conditions", "",
             "| Condition | WIP | Runs | Throughput /h, mean [95% CI] | Latency median min, mean [95% CI] | "
             "Rework (pooled, 95% Wilson) | Freshness | Conflicts | Gate failures | Cost USD |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for c in report["conditions"]:
        rw = c["rework"]
        rework = (f"{rw['k']}/{rw['n']} = {rw['p']} [{rw['ci95'][0]}, {rw['ci95'][1]}]" if rw["p"]
                  else "unavailable" if rw.get("unavailable") else "no unit")
        cost = _cell(c["cost_usd"]) if "mean" in c["cost_usd"] else "unavailable"
        lines.append(f"| `{c['condition']}` | `builders={c['builders']} reviewers={c['reviewers']}` | "
                     f"{len(c['runs'])} | {_cell(c['throughput_per_h'])} | {_cell(c['latency_median_min'])} | "
                     f"{rework} | {_cell(c['freshness']['total'])} | {_cell(c['conflicts']['total'])} | "
                     f"{_cell(c['gate_failures']['total'])} | {cost} |")
    lines += ["", "## Confounds read within the data", "",
              "Reviewer effort: tokens (input + output) per review, mean [95% CI] — "
              + "; ".join(f"`{c['condition']}` {_cell(c['review_tokens_per_review'])}"
                          if "mean" in c["review_tokens_per_review"] else f"`{c['condition']}` unavailable"
                          for c in report["conditions"]) + ".", "",
              "Task difficulty: verified-CLOSED/runs and median unit latency in minutes, per task and condition.", "",
              "| Task | " + " | ".join(f"`{c['condition']}`" for c in report["conditions"]) + " |",
              "|---|" + "---|" * len(report["conditions"])]
    for tid in sorted({t for c in report["conditions"] for t in c["tasks"]}):
        cells = []
        for c in report["conditions"]:
            entry = c["tasks"].get(tid)
            if not entry:
                cells.append("no run")
                continue
            lat = [Fraction(x) for x in entry["latency_min"]]
            cells.append(f"{entry['verified_closed']}/{entry['runs']}, "
                         + (fmt(events._median(lat)) if lat else "no latency"))
        lines.append(f"| {tid} | " + " | ".join(cells) + " |")
    lines += ["", "## Registered metrics by condition", "",
              "Every field `metrics.report_fields.condition` registers, in order.", "",
              "| Metric | " + " | ".join(f"`{c['condition']}`" for c in report["conditions"]) + " |",
              "|---|" + "---|" * len(report["conditions"])]
    for field in (report["conditions"][0]["registered"] if report["conditions"] else []):
        lines.append(f"| `{field}` | " + " | ".join(_registered_cell(c["registered"][field])
                                                   for c in report["conditions"]) + " |")
    lines += ["", "## Registered metrics by run", "",
              "Every field `metrics.report_fields.run` registers, in order, for every run.", ""]
    if report["runs"]:
        lines += ["| Metric | " + " | ".join(f"`{r['run_id']}`" for r in report["runs"]) + " |",
                  "|---|" + "---|" * len(report["runs"])]
        for field in report["runs"][0]["registered"]:
            lines.append(f"| `{field}` | " + " | ".join(_registered_cell(r["registered"][field])
                                                       for r in report["runs"]) + " |")
    lines += ["", "## Runs (every run, failed, stopped and parked included)", "",
              "| Run | Condition | Tier | Status | Throughput | Latency median/max min | Rework | Freshness | "
              "Conflicts | Retries | Cost USD | Compliant |", "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in report["runs"]:
        m = r.get("metrics")
        if not m:
            lines.append(f"| `{r['run_id']}` | `{r['condition']}` | {r['tier']} | {r['status']} | unavailable | "
                         "unavailable | unavailable | unavailable | unavailable | unavailable | unavailable | no |")
            continue
        lat = (f"{m['latency']['median_min']}/{m['latency']['max_min']}" if m["latency"].get("median_min")
               else "unavailable")
        status = r["status"] + (f" ({r['stop_reason']})" if r.get("stop_reason") else "")
        rework = (f"{m['rework']['bounced']}/{m['rework']['units']}" if "bounced" in m["rework"]
                  else "unavailable")
        lines.append(f"| `{r['run_id']}` | `{r['condition']}` | {r['tier']} | {status} | "
                     f"{m['throughput'].get('value') or 'unavailable'} | {lat} | "
                     f"{rework} | {_cell(m['freshness'])} | {_cell(m['conflicts'])} | "
                     f"{_cell(m['retries'])} | {_cell(m['usage']['cost_usd'])} | {'yes' if r['compliant'] else 'no'} |")
    lines += ["", "## Per-wave WIP-curve rows (derived by events.py from each run's record)", ""]
    for r in report["runs"]:
        if r.get("metrics"):
            lines += [f"### `{r['run_id']}`", "", "| Wave | WIP setting | Builder throughput | Verification latency | "
                      "Rework rate | Freshness violations |", "|---|---|---|---|---|---|", *r["metrics"]["rows"], ""]
    lines += ["## Non-compliance and binding", ""]
    for r in report["runs"]:
        for why in r.get("noncompliance", []):
            lines.append(f"- `{r['run_id']}`: {why}")
        for why in r.get("binding_problems", []) or []:
            lines.append(f"- `{r['run_id']}` binding: {why}")
        if r.get("error"):
            lines.append(f"- `{r['run_id']}` error: {r['error']}")
    rec = report["recommendation"]
    lines += ["", "## Recommendation", "", f"Status: **{rec['status']}** — {rec['why']}.", "",
              f"Computed from the {len(report['compliant_runs'])} protocol-compliant run(s) alone, whatever the "
              "basis of the rows above.", "",
              f"Authority: {rec['authority']}.", "", "## Limits on generalizing", ""]
    lines += [f"- {x}" for x in report["generalization_limits"]]
    return "\n".join(lines) + "\n"


def diff_json(want, got, path="$"):
    if type(want) is not type(got):
        return [f"{path}: the report says {json.dumps(got)[:120]}, the sources derive {json.dumps(want)[:120]}"]
    if isinstance(want, dict):
        out = []
        for key in sorted(set(want) | set(got)):
            if key not in got:
                out.append(f"{path}.{key}: missing from the report")
            elif key not in want:
                out.append(f"{path}.{key}: the sources derive no such field")
            else:
                out += diff_json(want[key], got[key], f"{path}.{key}")
        return out
    if isinstance(want, list):
        if len(want) != len(got):
            return [f"{path}: {len(got)} item(s) in the report, {len(want)} derived"]
        return [line for i, (w, g) in enumerate(zip(want, got, strict=True)) for line in diff_json(w, g, f"{path}[{i}]")]
    return [] if want == got else [f"{path}: the report says {json.dumps(got)}, the sources derive {json.dumps(want)}"]


# ---------------------------------------------------------------------------- commands

def cmd_check_prereg(args) -> int:
    prereg, taskset, path, digest, taskset_path = load_prereg(args.prereg)
    errors = check_prereg(prereg, taskset, taskset_path, oracles=not args.no_oracles)
    for line in errors:
        print(f"wip-curve: PREREG {line}", file=sys.stderr)
    if errors:
        return EXIT_INCOMPLETE
    cap = prereg["cost"]["cap_usd"]
    print(f"wip-curve: pre-registration OK — {path.name} sha256 {digest}; task set {len(taskset['tasks'])} "
          f"tasks, seed {prereg['taskset']['seed_commit'][:12]}; {len(schedule(prereg, taskset))} runs; cost cap: {cap}")
    return EXIT_OK


def cmd_plan(args) -> int:
    prereg, taskset, path, digest, _ = load_prereg(args.prereg)
    sched = schedule(prereg, taskset)
    if args.json:
        print(json.dumps({"prereg": {"path": str(path), "sha256": digest}, "runs": sched}, indent=2))
        return EXIT_OK
    for e in sched:
        c = e["condition"]
        print(f"{e['position']:>2}  {e['run_id']:<20} builders={c['builders']} reviewers={c['reviewers']}  "
              f"tasks={','.join(e['task_order'])}")
    print(f"cost cap: {prereg['cost']['cap_usd']} (proposed {prereg['cost']['proposed_cap_usd']} USD)")
    return EXIT_OK


def cmd_run(args) -> int:
    prereg, taskset, path, prereg_sha, taskset_path = load_prereg(args.prereg)
    if args.cost_cap_usd is None:
        raise Refused(f"--cost-cap-usd is required: the pre-registered cap is {prereg['cost']['cap_usd']!r}, "
                      "and the runner never picks the spend")
    args.cost_cap = money(args.cost_cap_usd)
    # The whole check, seed and oracles included, before anything starts: a registered input that
    # moved blocks the run here, never as a failed run record later (#604).
    errors = check_prereg(prereg, taskset, taskset_path)
    if errors:
        raise Refused("the pre-registration does not check: " + "; ".join(errors))
    if args.worker == "live":
        if args.cost_cap <= 0:
            raise Refused("a live run needs a cost cap above zero: a zero cap cannot dispatch a worker")
        if not args.model:
            raise Refused("a live run needs --model: the pin every observed model must equal")
        if args.reservation_usd is None:
            raise Refused("a live run needs --reservation-usd: the runner never picks the per-dispatch reservation "
                          f"(registered {prereg['cost']['reservation_per_dispatch_usd']} USD, "
                          f"{prereg['cost']['reservation_status']})")
        if args.timeout_scale != 1.0:
            raise Refused(f"--timeout-scale {args.timeout_scale}: a live run keeps the registered dispatch "
                          "deadlines (a dry run may shorten them)")
        if args.agent not in MODEL_ENV:
            raise Refused(f"cannot enforce the model pin on {args.agent}: the posix launch table passes no model "
                          f"and only {sorted(MODEL_ENV)} read one from their environment")
    elif args.agent not in INERT_AGENTS:
        raise Refused(f"the inert stand-in answers as {INERT_AGENTS}; --agent {args.agent} needs --worker live")
    args.reservation = money(args.reservation_usd if args.reservation_usd is not None else args.inert_cost_usd)
    if args.worker == "live" and args.reservation <= 0:
        raise Refused("a live run needs a reservation above zero")
    if args.agent not in first_run.posix_harnesses():
        raise Refused(f"--agent {args.agent!r} is not a posix harness")
    registered = (path, taskset_path)
    results = check_writable(args.results, "--results", registered)
    # One runner per results directory, from its first check through its cleanup: two commands
    # would otherwise both spend against the remaining budget, and each would read the other's
    # run in progress as lost (PR #653 review).
    if args.workdir:  # checked before the lock, which creates the directory: a refusal writes nothing
        for entry in schedule(prereg, taskset):
            for attempt in (1, 2):
                sandbox = (Path(args.workdir) / run_id_for(prereg, entry["condition"]["id"], entry["repetition"],
                                                           attempt)).resolve()
                if results.is_relative_to(sandbox) or sandbox.is_relative_to(results):
                    raise Refused(f"--results {results} and the sandbox {sandbox} overlap: deleting one would "
                                  "delete the other")
    with results_lock(results):
        return _run_locked(args, prereg, taskset, path, prereg_sha, taskset_path, results, registered)


def _run_locked(args, prereg, taskset, path, prereg_sha, taskset_path, results, registered) -> int:
    recovered = recover(results, registered)  # the lock is ours: a run directory without run.json is lost
    if recovered:
        print(f"wip-curve: reconciled {len(recovered)} call(s) a lost run left live", file=sys.stderr)
    # No run starts while an earlier one cannot vouch for its processes: every recorded marker is
    # swept again first (Codex review of PR #668, B1; #606's ORPHAN_ALIVE).
    for start in sorted((v for v in Budget(results).calls().values()
                         if v.get("state") == "run" and v.get("call_tag")), key=lambda v: v["run"]):
        if not sweep_tags(journal_tags(start)):
            raise Refused(f"ORPHAN_ALIVE: a process of {start['run']} survives, or the process table cannot be "
                          "read: nothing starts until it is gone (inspect its sandbox and the ledger)")
    for kept, tags in unswept_reruns():  # a report's re-run of worker code no sweep vouched for (c)
        if not sweep_tags(tags):
            raise Refused(f"ORPHAN_ALIVE: a report's re-run of worker code at {kept} could not be contained, and "
                          f"a process carrying one of the markers in its {RERUN_JOURNAL} survives, or the process "
                          "table cannot be read: nothing starts until it is gone (inspect that directory)")
    if args.workdir:
        check_writable(args.workdir, "--workdir", registered)
    sched = {e["run_id"]: e for e in schedule(prereg, taskset)}
    done = {d.name for d in runs_in(results) + lost_in(results)}
    taskset_sha = sha256_file(taskset_path)
    for d in runs_in(results):  # one experiment, one registration
        rec = json.loads((d / "run.json").read_text(encoding="utf-8"))
        if (rec.get("prereg") or {}).get("sha256") != prereg_sha or (rec.get("taskset") or {}).get("sha256") != taskset_sha:
            raise Refused(f"{results} holds {d.name}, run under another registration (prereg "
                          f"{str((rec.get('prereg') or {}).get('sha256'))[:12]}…): re-register (bump the version, "
                          "which gives new run ids) or use another results directory")
    if args.runs:
        wanted = []
        for rid in args.runs.split(","):
            m = re.fullmatch(r"(.+?)(?:-a(\d+))?", rid.strip())
            if not m or m.group(1) not in sched:
                raise Refused(f"{rid} is not a scheduled run (see `plan`)")
            attempt = int(m.group(2) or 1)
            if attempt > 2 or attempt < 1:
                raise Refused(f"{rid}: the registration allows one re-run (-a2) of a scheduled run, never -a{attempt}")
            if attempt == 2:  # only after an infrastructure failure of attempt 1 (PR #653 review)
                first = results / "runs" / m.group(1) / "run.json"
                status = (json.loads(first.read_text(encoding="utf-8")).get("status") if first.is_file()
                          else "lost" if first.parent.is_dir() else None)
                if status is None or not infrastructure_failure(first.parent, status):
                    raise Refused(f"{rid}: a re-run is allowed only after an infrastructure failure of "
                                  f"{m.group(1)}, which {'ended ' + str(status) if status else 'never ran'}")
            wanted.append((m.group(1), attempt))
    else:
        wanted = [(rid, 1) for rid in sched if rid not in done][: (len(sched) if args.all else args.next)]
    if not wanted:
        print("wip-curve: every scheduled run is already present", file=sys.stderr)
        return EXIT_OK
    if args.worker == "live":  # an inert dry run is fixture-tier and never pooled: any order
        check_order(results, sched, wanted)
    inputs = experiment_inputs((path, taskset_path))
    if args.worker == "live":
        dirty = dirty_inputs()
        if dirty:
            raise Refused(f"a live run needs committed experiment inputs; uncommitted: {dirty}")
        why = contain.containment_problem()  # the strong host check, before anything is reserved
        if why:
            raise Refused(f"process discovery cannot contain a call on this host ({why}): a live run's escaped "
                          "processes could never be found or stopped, so it does not start")
    for base, attempt in wanted:  # every sandbox and run directory is checked before the first run starts
        rid = run_id_for(prereg, sched[base]["condition"]["id"], sched[base]["repetition"], attempt)
        check_writable(results / "runs" / rid, "the run directory", registered)  # a planted runs/ link too
        if not args.workdir:
            continue
        sandbox_path(args.workdir, rid, results, registered)
    script = json.loads(args.inert_script) if args.inert_script else DRY_RUN_SCRIPT
    rc = EXIT_OK
    for base, attempt in wanted:
        entry = dict(sched[base])
        entry["run_id"] = run_id_for(prereg, entry["condition"]["id"], entry["repetition"], attempt)
        if entry["run_id"] in done or (results / "runs" / entry["run_id"]).exists():
            raise Refused(f"{entry['run_id']} already exists in {results}: runs are append-only; a re-run "
                          "takes the next attempt id (e.g. <run>-a2)")
        spent = spent_in(results)
        first_wave = min(entry["condition"]["builders"], len(entry["task_order"]))
        worst = args.reservation * 2 * first_wave
        if spent + worst > args.cost_cap:
            # The experiment-level stopping rule: once the cap cannot cover a first wave, no run starts.
            print(f"wip-curve: {entry['run_id']} not started: {spent} USD spent in {results} plus its first "
                  f"wave's worst case {worst} exceeds the cap {args.cost_cap}", file=sys.stderr)
            return EXIT_INCOMPLETE
        if args.worker == "live":
            calls = Budget(results).calls() if (results / Budget.NAME).is_file() else {}
            ends = [json.loads((d / "run.json").read_text(encoding="utf-8")).get("finished_at")
                    for d in runs_in(results)] + [last_activity(calls, d.name) for d in lost_in(results)]
            ends = [datetime.fromisoformat(e) for e in ends if e]
            if ends:
                since = (datetime.now(timezone.utc) - max(ends)).total_seconds()
                wait = prereg["isolation"]["cooldown_minutes"] * 60 - since
                if wait > 0:  # the cache/warmup confound: no live run starts inside the cooldown
                    print(f"wip-curve: cooldown {int(wait)}s before {entry['run_id']}", flush=True)
                    time.sleep(wait)
        # checked again at its creation: the cooldown above may have slept for minutes
        workdir = sandbox_path(args.workdir, entry["run_id"], results, registered) if args.workdir else \
            Path(tempfile.mkdtemp(prefix=f"wip-curve-{entry['run_id']}-"))
        workdir.mkdir(parents=True, exist_ok=True)
        config = {"taskset": str(taskset_path), "runner": str(Path(__file__).resolve()), "script": script,
                  "cost_usd": str(args.inert_cost_usd)}
        sb = Sandbox(workdir, args.worker, args.agent, config)
        for var in MODEL_ENV.values():  # only the pin, and only for a live run, chooses the model
            sb.env.pop(var, None)
        if args.worker == "live":
            sb.env[MODEL_ENV[args.agent]] = args.model
        run = Run(args, prereg, taskset, (path, prereg_sha, taskset_path), entry, results)
        binary = first_run.HARNESS_BINARIES.get(args.agent, args.agent)
        found = shutil.which(binary, path=sb.env["PATH"])
        if args.worker == "live" and (not found or Path(found).resolve().is_relative_to(workdir.resolve())):
            raise Refused(f"live mode needs the real `{binary}` on PATH")
        run.record.update(
            tier="fixture-tested" if args.worker == "inert" else "live-unreviewed", worker=args.worker,
            agent=args.agent, model_pin=args.model, timeout_scale=args.timeout_scale,
            harness={"path": found, "version": "inert stand-in (no model)" if args.worker == "inert"
                     else first_line([found, "--version"], env=sb.env)},
            host=host_facts(), clock=run.clock, epoch=1, attempt=attempt,
            prereg={"path": str(path), "sha256": prereg_sha}, inputs=inputs,
            taskset={"path": prereg["taskset"]["path"], "sha256": sha256_file(taskset_path)},
            inert_script=script if args.worker == "inert" else None)
        previous = {sig: signal.signal(sig, _terminated) for sig in TRAPPED_SIGNALS}
        try:
            record = run.execute(sb)
        finally:
            for sig in previous:
                signal.signal(sig, signal.SIG_IGN)
            try:
                stop_all_groups()
                first_run.stop_workers(sb)
            finally:
                first_run.restore_signals(previous)
        hits = sb.tripwire_hits() if args.worker == "inert" else ""
        if hits:
            print(f"wip-curve: TRIPWIRE a harness resolved past the stand-in: {hits[:200]!r}", file=sys.stderr)
            rc = EXIT_INCOMPLETE
        if record["status"] == "complete" and not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)
        print(f"WIP_RUN={record['run_id']} STATUS={record['status']}"
              + (f" STOP={record['stop_reason']}" if record.get("stop_reason") else "")
              + f" TIER={record['tier']} SPENT_USD="
              f"{Decimal(record['cost']['observed_usd']) + Decimal(record['cost']['reserved_unobserved_usd'])}"
              + (f" ERROR={record['error'][:200]}" if record.get("error") else ""))
        if record["status"] == "failed":
            rc = EXIT_INCOMPLETE
        if record["status"] == "stopped" and record["stop_reason"] == "orphan-alive":
            print(f"wip-curve: ORPHAN_ALIVE in {record['run_id']}: its sandbox is kept, every call is charged "
                  "its full hold, and no further run starts", file=sys.stderr)
            return EXIT_INCOMPLETE
        if record["status"] == "stopped" and record["stop_reason"] == "cost-cap":
            print("wip-curve: the cost cap is reached; no further run starts", file=sys.stderr)
            return EXIT_INCOMPLETE
    return rc


def cmd_report(args) -> int:
    results = Path(args.results)
    _prereg, _taskset, path, _sha, taskset_path = load_prereg(args.prereg)
    out = check_writable(args.out or args.results, "--out" if args.out else "--results", (path, taskset_path))
    with results_lock(results, shared=True):  # never a run in progress, read half-written
        report = build_report(results, args.prereg, args.basis)
    out.mkdir(parents=True, exist_ok=True)
    registered = (path, taskset_path)
    write_output(out / "report.json", json.dumps(report, indent=2, sort_keys=True) + "\n", registered)
    write_output(out / "report.md", render_markdown(report), registered)
    print(f"wip-curve: report for {len(report['runs'])} run(s) ({len(report['compliant_runs'])} compliant) "
          f"-> {out / 'report.json'}, {out / 'report.md'}; recommendation {report['recommendation']['status']}")
    return EXIT_OK


def cmd_verify(args) -> int:
    results = Path(args.results)
    try:
        claimed = json.loads(Path(args.report).read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        raise Refused(f"--report {args.report} is not readable JSON: {err}") from err
    with results_lock(results, shared=True):
        report = build_report(results, args.prereg, claimed.get("basis", "compliant"))
    mismatches = diff_json(report, claimed)
    if args.report_md:
        want = render_markdown(report).splitlines()
        got = Path(args.report_md).read_text(encoding="utf-8").splitlines()
        for i in range(max(len(want), len(got))):
            w = want[i] if i < len(want) else None
            g = got[i] if i < len(got) else None
            if w != g:
                mismatches.append(f"{args.report_md}:{i + 1}: the report says {g!r}, the sources derive {w!r}")
    claimed_heads = {r.get("run_id"): (r.get("record") or {}).get("head") for r in claimed.get("runs") or []}
    for r in report["runs"]:
        d = results / "runs" / r["run_id"]
        if not (d / "run-report.md").is_file() or not r.get("record"):
            continue
        # The head the PUBLISHED report names is the anchor kept off the writer (#312's rule).
        proc = run_text([sys.executable, str(SCRIPTS / "events.py"), "--log", str(d / "events.jsonl"),
                                   "check", "--run-report", str(d / "run-report.md"), "--run", r["run_id"],
                                   "--expect-head", claimed_heads.get(r["run_id"]) or ""])
        # A cell the record cannot derive and the row prints `unavailable` agrees: events.py check
        # still names it, since such a row can never bind under run_report.py.
        lines = [ln for ln in proc.stderr.strip().splitlines() if not ln.endswith(AGREED_UNAVAILABLE)]
        if proc.returncode not in (0, 1) or lines:
            mismatches += [f"{r['run_id']}/run-report.md: {ln}" for ln in lines or [f"events.py check rc={proc.returncode}"]]
    for line in mismatches:
        print(f"wip-curve: MISMATCH {line}", file=sys.stderr)
    if mismatches:
        return EXIT_INCOMPLETE
    print(f"wip-curve: the report recomputes from {len(report['runs'])} run(s)' bound sources; every terminal "
          f"outcome was re-checked against git ({sum(len(r.get('binding_problems') or []) for r in report['runs'])} "
          "binding problem(s), each named in the report)")
    return EXIT_OK


def cmd_gate(args) -> int:
    """The merge queue's gate, run in the prefix checkout: the visible tests, plus the oracle of
    every task whose reviewed head the prefix contains (a regression of an earlier unit fails)."""
    taskset = load_json(Path(args.taskset))
    landing = load_json(Path(args.landing))
    tasks = task_by_id(taskset)
    cwd = Path.cwd()
    included = [tasks[t] for t, heads in sorted(landing.items()) if t in tasks and any(
        git(cwd, "merge-base", "--is-ancestor", h, "HEAD", check=False).returncode == 0 for h in heads)]
    def record(tag):  # appended and synced before the step starts: the runner sweeps it (C-d), and
        if args.tags_file:  # so does every later run check, read from here (Codex P1 (b) at 9db89fbe3c)
            with open(args.tags_file, "a", encoding="utf-8") as fh:
                fh.write(tag + "\n")
                fh.flush()
                os.fsync(fh.fileno())
    tmp = Path(tempfile.mkdtemp(prefix="wip-curve-gate-"))
    result = run_oracle(cwd, included, taskset, tmp, on_tag=record)
    if result["contained"]:
        shutil.rmtree(tmp, ignore_errors=True)
    else:  # kept, to investigate; the runner halts the run orphan-alive when it reads this line
        record(f"UNCONTAINED {tmp}")
    print(f"wip-curve gate: {result['exit']} for {[t['id'] for t in included]}")
    for line in result["tail"]:
        print(line)
    return EXIT_OK if result["exit"] == 0 else EXIT_INCOMPLETE


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wip_curve.py", description="The pre-registered WIP-curve experiment (#604).",
                                epilog="exit 0 ok / 1 incomplete or mismatch / 2 usage or refused / 3 fail-closed")
    p.add_argument("--prereg", default=None, help=f"the pre-registration (default {PREREG_DEFAULT.relative_to(ROOT)})")
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("check-prereg", help="check the pre-registration and its task set")
    c.add_argument("--no-oracles", action="store_true", help="skip building the seed and running the oracles")
    s = sub.add_parser("plan", help="print the schedule")
    s.add_argument("--json", action="store_true")
    r = sub.add_parser("run", help="execute scheduled runs")
    r.add_argument("--results", required=True, help="the results directory (append-only; one dir per run)")
    r.add_argument("--cost-cap-usd", default=None, dest="cost_cap_usd",
                   help="REQUIRED: the spend cap the owner authorised, across every run in --results")
    r.add_argument("--worker", choices=("inert", "live"), default="inert",
                   help="live runs only inside the container-based live harness (PR #668)")
    r.add_argument("--agent", default="claude")
    r.add_argument("--model", default=None, help="the model pin (required for --worker live)")
    pick = r.add_mutually_exclusive_group()
    pick.add_argument("--runs", default=None, help="comma-separated run ids (see plan); <run>-a2 re-runs one")
    pick.add_argument("--next", type=int, default=1, help="the next N scheduled runs not yet present (default 1)")
    pick.add_argument("--all", action="store_true", help="every scheduled run not yet present")
    r.add_argument("--workdir", default=None, help="where sandboxes go (default: a new temp dir per run)")
    r.add_argument("--keep", action="store_true", help="keep a complete run's sandbox")
    r.add_argument("--timeout-scale", type=float, default=1.0, dest="timeout_scale",
                   help="scale the pre-registered dispatch timeouts (a dry run may shorten them)")
    r.add_argument("--reservation-usd", default=None, dest="reservation_usd",
                   help="the per-dispatch reservation the owner authorised (required for --worker live; "
                        "inert default: --inert-cost-usd)")
    r.add_argument("--inert-script", default=None, dest="inert_script",
                   help="dry run only: the stand-in's per-task script as JSON (default: one miss, one changes)")
    r.add_argument("--inert-cost-usd", default="0", dest="inert_cost_usd",
                   help="dry run only: a synthetic cost the stand-in reports per dispatch (not a spend)")
    rp = sub.add_parser("report", help="derive the experiment report from the retained sources")
    rp.add_argument("--results", required=True)
    rp.add_argument("--out", default=None, help="where report.json and report.md go (default --results)")
    rp.add_argument("--basis", choices=("compliant", "all"), default="compliant",
                    help="which runs feed the condition rows (all: a dry run's fixture runs too)")
    v = sub.add_parser("verify", help="recompute the report and name every cell it gets wrong")
    v.add_argument("--results", required=True)
    v.add_argument("--report", required=True, help="the published report.json")
    v.add_argument("--report-md", default=None, dest="report_md", help="the published report.md")
    g = sub.add_parser("gate", help="(internal) the merge queue's gate command")
    g.add_argument("--taskset", required=True)
    g.add_argument("--landing", required=True)
    g.add_argument("--tags-file", default=None, dest="tags_file",
                   help="(internal) where each oracle call's marker is appended before it starts")
    return p


PATH_ARGS = ("prereg", "results", "workdir", "out", "report", "report_md", "taskset", "landing", "tags_file")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    why = contain.live_disabled() if args.command == "run" and args.worker == "live" else None
    if why:  # first, before anything is read or reserved (PR #668: the live tier is off)
        print(f"wip-curve: refused: {why}", file=sys.stderr)
        return EXIT_USAGE
    # Every path argument is absolute before anything runs: the runner, git and events.py later
    # work from other directories (a temporary repository, the run directory), where a relative
    # path names something else or nothing (PR #652's class; a relative bundle path did, #604).
    for name in PATH_ARGS:
        if getattr(args, name, None):
            setattr(args, name, str(Path(getattr(args, name)).expanduser().resolve()))
    handlers = {"check-prereg": cmd_check_prereg, "plan": cmd_plan, "run": cmd_run, "report": cmd_report,
                "verify": cmd_verify, "gate": cmd_gate}
    try:
        if args.command == "run" and args.inert_script and args.worker == "live":
            raise Refused("--inert-script is for the inert stand-in only")
        if args.command == "run":
            money(args.inert_cost_usd)
        return handlers[args.command](args)
    except Refused as err:
        print(f"wip-curve: refused: {err}", file=sys.stderr)
        return EXIT_USAGE
    except SourceError as err:
        print(f"wip-curve: FAIL-CLOSED: {err}", file=sys.stderr)
        return EXIT_FAIL_CLOSED


if __name__ == "__main__":
    sys.exit(main())
