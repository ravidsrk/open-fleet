#!/usr/bin/env python3
"""first_run.py — a reproducible first run of the POSIX route, inert or live (#596).

One review unit is driven through the PUBLIC wrappers an operator types, never the provider
classes underneath them:

  preflight  preflight.py --mission review-it --runtime posix --mode readonly
  create     task_ops.py create --spec <frozen spec>
  dispatch   spawn_worker.sh <task> new-child <title> <agent>   (OPEN_FLEET_RUNTIME=posix, setsid)
  guard      deny-hook.sh --verify-settings on the registration the provider installed
  delivery   the launch the provider recorded carries the spec nonce, and the worker echoes it
  result     worker_ops.py show/read + check_reply.py: the worker's exit and its report
  verify     verify.py --unit-class report-only on a SHA-bound manifest, run in a checkout the
             coordinator cuts from git at the evidence head (never the worker's own tree)
  release    worker_ops.py retain, then release; the evidence commit survives both

and the run ends in a SHA-bound verdict line, `FIRST_RUN=GO` or `FIRST_RUN=NO-GO step=<s>`.

ONE code path, two kinds of worker:

  --worker inert (default)  an inert stand-in answers to the harness name from a private bin
      directory first on PATH, behind tripwires for every other harness name. It reads the
      spec and the change file it names, and answers in the harness's own result shape. No model
      is called and nothing is spent. A GO here is a FIXTURE result: it proves the fleet's
      route, never the harness.
  --worker live             only inside the container-based live harness (PR #668;
      scripts/live_container.py): anywhere else refused, before anything is read or created
      (containment.py). The operator's real harness on PATH does the review, and the receipt is labelled
      `live-unreviewed`: it becomes certification evidence only once a maintainer binds it into
      docs/runs/ (runtime/providers/certification.json says which cells hold).

Profiles: `ro` (default; the review-it shape — the worker prints its report and has no tool to
send mail. posix relays the completion line its assignment names as its `worker_done` and records a
clean exit without that line as `worker_died (exit=0)`; either settles the unit, and the
coordinator commits the report it read from the transcript, #596) and `rw` (the worker commits the
report itself, sends `worker_done`, then prints the same report as its final answer; both copies must
meet the contract, and its HEAD is re-read from git, never taken from the claim). The inert stand-in
is LITERAL: it prints its report only when the assignment asks, as a live worker does (#596).

The reviewed target is a two-commit repository the run synthesizes, or `--target <repo>`
(cloned into the sandbox, never modified) with `--base/--head`. Every artifact lives in one
sandbox directory: the state store, the clone, the worker worktree, the verifier checkout and
`receipt.json` (per-step argv, exit, elapsed seconds, failure and recovery hint). The sandbox
is removed after a GO unless `--keep`; it is always kept after a NO-GO.

`probes` runs the negative probes instead: unsupported profile, privilege escalation, unarmed
deny hook, malformed runtime response and missing capability, each through the same wrapper,
each required to refuse BEFORE a launch (the stand-in never runs, no dispatch is recorded).

Usage:
  first_run.py [run] [--profile ro|rw] [--agent <harness>] [--worker inert|live]
               [--target <repo> [--base <rev>] [--head <rev>]] [--workdir <dir>] [--keep]
               [--timeout <s>] [--json]
  first_run.py probes [--workdir <dir>] [--keep] [--json]

Exit: 0 GO · 1 NO-GO (receipt names the step) · 2 usage · 143/129 SIGTERM/SIGHUP (workers stopped).
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import importlib.util
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
import tempfile
import threading
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "runtime" / "scripts"
CAPABILITIES = ROOT / "runtime" / "providers" / "capabilities.json"
SCHEMA = "open-fleet-first-run/v1"
# The launch names a harness by its binary; every one gets a tripwire in inert mode.
HARNESS_BINARIES = {"antigravity": "agy"}
LIVE_STATES = ("ready", "running", "retained")
REPORT_HEAD = "FIRST-RUN-REPORT "
READ_HEAD = "FIRST-RUN-READ "
def load_module(name: str, path: Path):
    """A sibling runtime module, loaded by path, never writing bytecode beside it (PR #668 CI: a load wrote into the source tree)."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    prior, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = prior
    return mod


# The per-harness final-answer reader is shared with the posix monitor's ro completion line, so the
# two never disagree about what a worker answered (runtime/providers/transcript.py, #596 review).
TRANSCRIPT = load_module("of_first_run_transcript", ROOT / "runtime" / "providers" / "transcript.py")
REPORT_FORMATS = TRANSCRIPT.FINAL_ANSWER_FORMATS
# These carry every turn's text, not only the last answer: the report starts at its own header.
ANCHORED_FORMATS = TRANSCRIPT.ALL_TURN_FORMATS
MONITOR_EVENTS = TRANSCRIPT.MONITOR_EVENTS
# Process containment (runtime/scripts/containment.py, one helper shared with #606's runner and the
# WIP-curve runner): the marker every process of a run carries, its sweep, and the host probe.
containment = load_module("of_first_run_containment", SCRIPTS / "containment.py")


class StepFailed(Exception):
    """A lifecycle step did not hold; `recovery` is the operator's next move."""

    def __init__(self, message: str, recovery: str = ""):
        super().__init__(message)
        self.recovery = recovery


def text_of(data: bytes | str | None) -> str:
    """Captured output as text for display and checks only (#596 review): a reviewed file in an
    older encoding must never raise. Bytes that are evidence (the diff) stay bytes."""
    if isinstance(data, str):
        return data
    return (data or b"").decode("utf-8", "replace")


def run_text(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    """subprocess.run capturing BYTES, with stdout/stderr decoded by text_of; `.raw` keeps stdout."""
    proc = subprocess.run(argv, capture_output=True, **kwargs)
    out = subprocess.CompletedProcess(argv, proc.returncode, text_of(proc.stdout), text_of(proc.stderr))
    out.raw = proc.stdout or b""
    return out


def posix_harnesses() -> list[str]:
    caps = json.loads(CAPABILITIES.read_text(encoding="utf-8"))
    return list(caps["providers"]["posix"]["supported_harnesses"])


def harness_report(agent: str, lines: list[str]) -> str:
    """The worker's final answer, read from its transcript lines in its harness's own format."""
    fmt = REPORT_FORMATS[agent]
    answer = TRANSCRIPT.final_answer(agent, lines)
    if fmt in ANCHORED_FORMATS:
        heads = [i for i, ln in enumerate(answer.splitlines()) if ln.startswith(REPORT_HEAD)]
        if heads:
            answer = "\n".join(answer.splitlines()[heads[-1]:]) + "\n"
    return answer


def harness_usage(lines: list[str]) -> dict:
    """What the harness itself reported about its run, where its output carries it (#596): Claude
    Code's stream-json `init` event names the model, its `result` event the turns, duration and
    cost. Other output formats report nothing here; nothing is estimated."""
    usage: dict = {}
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        if event.get("type") == "system" and event.get("subtype") == "init" and isinstance(event.get("model"), str):
            usage["model"] = event["model"]
        if event.get("type") == "result":
            for key in ("num_turns", "total_cost_usd", "duration_ms"):
                value = event.get(key)
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    usage[key] = value
    return usage


def harness_shadow(binary: str, run_path: str, own_path: str) -> str:
    """'' when the run's PATH resolves `binary` to the file the operator's own PATH names (#596).

    The sandbox puts the interpreter's directory first on PATH, so every wrapper runs this Python.
    A harness that directory also holds would then run in place of the operator's (an isolation
    wrapper, a pinned build): a live run refuses that rather than spend on the wrong binary.
    """
    run, own = shutil.which(binary, path=run_path), shutil.which(binary, path=own_path)
    if not own:
        return f"`{binary}` is not on your PATH; the run would launch {run}"
    if not run or os.path.realpath(run) != os.path.realpath(own):
        return f"the run's PATH resolves `{binary}` to {run}, but your PATH resolves it to {own}"
    return ""


def witness_line(receipt: dict) -> str:
    """The run's route, harness version, catalog commit and verdict on ONE line (#596).

    certification.json certifies a live cell by quoting whole lines of a bound run's artifacts,
    which together must name the provider, `PROFILE=<p>` beside the harness, the harness version
    and the upstream version: this line carries all of them, so the receipt itself is quotable.
    It also says `worker=` and `tier=`, and certification.py refuses a quote of an inert run.
    """
    route, host = receipt.get("route") or {}, receipt.get("host") or {}
    harness = (receipt.get("facts") or {}).get("harness") or {}
    return (f"{route.get('provider')}/{route.get('backend')} PROFILE={route.get('profile')} "
            f"harness={route.get('harness')} version={harness.get('version') or 'unknown'} "
            f"worker={route.get('worker')} tier={receipt.get('tier')} catalog={host.get('catalog_commit')} "
            f"dirty={host.get('catalog_dirty')} verdict={receipt.get('verdict')}")


def all_harness_binaries() -> list[str]:
    """Every harness name and binary base.py knows: each gets a tripwire in inert mode."""
    mod = load_module("of_first_run_base", ROOT / "runtime" / "providers" / "base.py")
    names = {HARNESS_BINARIES.get(h, h) for h in mod.SUPPORTED_HARNESSES}
    return sorted(names | set(mod.SUPPORTED_HARNESSES))


INERT_WORKER = r'''
"""Inert stand-in for a coding-agent harness (first_run.py, #596). Calls no model."""
import json, os, re, subprocess, sys
from pathlib import Path

harness, argv = sys.argv[1], sys.argv[2:]
log_dir = Path(sys.argv[0]).resolve().parent
dispatch = os.environ.get("OPEN_FLEET_DISPATCH_ID", "")
with open(log_dir / "runs.log", "a", encoding="utf-8") as fh:
    fh.write(json.dumps({"harness": harness, "dispatch": dispatch}) + "\n")
(log_dir / f"{dispatch or 'unknown'}.argv.json").write_text(json.dumps(argv), encoding="utf-8")
spec = next((a for a in argv if "FR-NONCE:" in a), "")
m = re.search(r"FIRST-RUN-REPORT (FR-NONCE:[0-9a-f]{16}) ([0-9a-f]{40})", spec)
inp = re.search(r"diff is written to (\S+) in your working tree", spec)
if not m or not inp:
    print("no first-run spec in argv", file=sys.stderr)
    sys.exit(3)


def answer(text):
    """Print the final answer the way this harness's launch prints it (first_run.REPORT_FORMATS)."""
    note = "Reading the diff.\n"  # formats that keep every turn's text carry the earlier ones too
    msg = {"role": "assistant", "content": [{"type": "text", "text": text}]}
    head, _, rest = text.partition("\n")
    events = {
        "claude": [{"type": "system", "subtype": "init"},
                   {"type": "result", "subtype": "success", "is_error": False, "result": text}],
        "codex": [{"type": "thread.started", "thread_id": "inert"}, {"type": "turn.started"},
                  {"type": "item.completed", "item": {"id": "item_0", "type": "agent_message", "text": text}},
                  {"type": "turn.completed", "usage": {"input_tokens": 0, "cached_input_tokens": 0,
                                                       "output_tokens": 0}}],
        "opencode": [{"type": "step_start", "part": {"id": "prt_0", "type": "step-start"}},
                     {"type": "text", "part": {"id": "prt_1", "type": "text", "text": text}},
                     {"type": "step_finish", "part": {"id": "prt_2", "type": "step-finish", "reason": "stop"}}],
        "pi": [{"type": "agent_start"}, {"type": "message_end", "message": msg},
               {"type": "agent_end", "messages": [msg]}],
        "goose": [{"type": "message", "message": {"id": "msg_0", "role": "assistant",
                                                  "content": [{"type": "text", "text": chunk}]}}
                  for chunk in (head + "\n", rest)] + [{"type": "complete", "total_tokens": 0}],
        "jcode": [{"type": "start"}, {"type": "text_delta", "text": note}, {"type": "text_delta", "text": text},
                  {"type": "done", "text": note + text}],
    }
    events["omp"] = events["pi"]
    if harness in events:
        for event in events[harness]:
            print(json.dumps(event))
    else:  # hermes, crush, gemini print plain text
        print(note + text, end="")
# Like an ro harness with no shell, it learns the change only by reading the file it was given:
# the bytes git wrote, any encoding; it reads them as text the way a model would (#596 review).
raw = Path(inp.group(1)).read_bytes()
change = raw.decode("utf-8", "replace")
lines = change.splitlines()
stat = subprocess.run(["git", "apply", "--stat", "-"], input=raw, capture_output=True).stdout.decode("utf-8", "replace").strip()
stat = re.sub(r" [|] +", " | ", stat)
paths = [d.group(1) for d in map(re.compile(r"^diff --git a/.* b/(.*)$").match, lines) if d]
read = [ln for ln in lines if ln.startswith("FIRST-RUN-READ ")][-1:]
report = f"FIRST-RUN-REPORT {m.group(1)} {m.group(2)}\n" + (stat or "(empty diff)") + "\n" + "".join(
    f"changed: {p}\n" for p in paths) + "".join(f"{ln}\n" for ln in read)
rc = 0
if os.environ.get("OPEN_FLEET_SANDBOX_PROFILE") == "rw":
    rel = re.search(r"write the report to (\S+)", spec).group(1)
    Path(rel).parent.mkdir(parents=True, exist_ok=True)
    Path(rel).write_text(report, encoding="utf-8")
    subprocess.run(["git", "add", "-f", "--", rel], check=True)  # the target may ignore it
    subprocess.run(["git", "commit", "-q", "-m", "first-run report", "--", rel], check=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True).stdout.decode("ascii", "replace").strip()
    rc = subprocess.run([sys.executable, "-I", os.path.join(os.environ["OPEN_FLEET_ROOT"], "runtime",
                         "scripts", "send_msg.py"), "--type", "worker_done", "--outcome", "succeeded",
                         "--subject", f"worker_done:{dispatch}",
                         "--payload", json.dumps({"head": head, "report": rel})]).returncode
# A ro launch cannot send mail; its assignment ends with the provider's completion footer, and
# a compliant worker ends its answer with the line it names (posix relays it as worker_done, #596).
done = re.search(r"OPEN_FLEET_WORKER_DONE (disp_[0-9a-f]+) <outcome>", spec)
if done:
    report += f"OPEN_FLEET_WORKER_DONE {done.group(1)} succeeded\n"
# Literal mode (#596 live rw run): a real worker does what its assignment says and no more. Its
# final answer is the report only when the spec asks for exactly that; otherwise it is a one-line
# summary, as Claude Code's was when the rw assignment never asked. first_run installs the stand-in
# in this mode (literal_stand_in); a bare stand-in run outside any assignment keeps printing.
LITERAL = False
if LITERAL and not re.search(r"(?i)\bprint\b[^\n]*\breport\b[^\n]*\bas your final answer\b", spec):
    if os.environ.get("OPEN_FLEET_SANDBOX_PROFILE") == "rw":
        report = "I reviewed the change, committed the report, and sent the completion message.\n"
    else:
        report = "I reviewed the change.\n"
answer(report)
sys.exit(rc)
'''


def literal_stand_in(source: str) -> str:
    """The stand-in in literal mode: it prints its report only when its assignment asks (#596)."""
    return source.replace("\nLITERAL = False\n", "\nLITERAL = True\n")


# What an on-host run takes from the operator's environment (W5-20): an ALLOWLIST, never
# `**os.environ`. The container lane already holds no credential (scripts/live_container.py drops
# TOKEN_ENV; its arm gets the image's environment and PATH alone); now the host lane cannot hand
# the worker, or the code it writes and runs, ANTHROPIC_API_KEY, CLAUDE_CODE_OAUTH_TOKEN, GH_TOKEN,
# AWS_*, a proxy URL with a password in it, or anything else not named here. An inherited CLI
# override or Orca session (ORCA_CLI_COMMAND, *_SANDBOX_PROFILE, ORCA_TERMINAL_HANDLE, ...) is
# excluded by the same rule. `--worker live` needs no credential from here: its `claude` is the
# live harness's wrapper (scripts/live_container_bin/claude), which sends every call to the broker
# that holds the token. It needs HOME, the arm's config home (inert runs get a private one), and
# the image's DISABLE_AUTOUPDATER pin.
# The locale names are listed, never matched as an `LC_` prefix: a prefix let `LC_GH_TOKEN` through.
SANDBOX_ENV_ALLOW = frozenset({"HOME", "USER", "LOGNAME", "LANG", "LANGUAGE", "TZ", "TERM", "TMPDIR",
                               "DISABLE_AUTOUPDATER", "PYTHONDONTWRITEBYTECODE",
                               "LC_ALL", "LC_CTYPE", "LC_COLLATE", "LC_MESSAGES", "LC_MONETARY",
                               "LC_NUMERIC", "LC_TIME", "LC_ADDRESS", "LC_IDENTIFICATION",
                               "LC_MEASUREMENT", "LC_NAME", "LC_PAPER", "LC_TELEPHONE"})


def sandbox_base_env(environ) -> dict:
    """The allowlisted part of `environ` an on-host run starts from (W5-20): exact names only."""
    return {k: v for k, v in environ.items() if k in SANDBOX_ENV_ALLOW}


class Sandbox:
    """Every path one run touches, plus the environment its wrappers run under."""

    def __init__(self, workdir: Path, worker: str, agent: str):
        self.dir = workdir
        self.worker = worker
        self.agent = agent
        self.inert = workdir / "inert"
        self.tripwire = workdir / "tripwire"
        self.state_db = workdir / "state" / "runtime.db"
        self.target = workdir / "target"
        self.scratch = workdir / "sp"
        self.home = workdir / "home"
        for d in (self.scratch, self.home, self.state_db.parent):
            d.mkdir(parents=True, exist_ok=True)
        path = [os.path.dirname(sys.executable), os.environ.get("PATH", os.defpath)]
        if worker == "inert":
            self._install_inert()
            path = [str(self.inert), str(self.tripwire)] + path
        self.env = {
            **sandbox_base_env(os.environ),
            "PATH": os.pathsep.join(path),
            # setsid only: tmux would start a server whose login shell can reorder PATH; and no
            # rc file of a login shell (zsh reads ~/.zshenv even for `-c`) may run at all.
            "SHELL": "/bin/sh",
            "OPEN_FLEET_RUNTIME": "posix",
            "OPEN_FLEET_POSIX_BACKEND": "setsid",
            "OPEN_FLEET_STATE_DB": str(self.state_db),
            "OPEN_FLEET_CLI_CWD": str(self.target),
            "SP": str(self.scratch),
            "PYTHON": sys.executable,
        }
        if worker == "inert":
            # The stand-in needs no credentials; a private HOME keeps every user config out.
            self.env["HOME"] = str(self.home)
        # Every process of the run carries the run's own OF_CALL_ID, wherever it goes: the provider
        # passes this environment to each monitor and worker, and a descendant that leaves its
        # group for a session of its own keeps it, so teardown finds it (PR #668 review). A
        # dedicated marker, not OPEN_FLEET_DISPATCH_ID: nothing in the fleet rewrites it (a nested
        # dispatch rewrites the dispatch id), it exists before any launch is registered, and the
        # containment helper's probe and sweep speak it.
        self.call_tag = secrets.token_hex(16)
        self.env[containment.CALL_MARKER] = self.call_tag

    def _install_inert(self) -> None:
        self.inert.mkdir(parents=True, exist_ok=True)
        self.tripwire.mkdir(parents=True, exist_ok=True)
        # Literal: an assignment that never asks for the report as the final answer must fail
        # here as it failed live, not pass because the stand-in printed it anyway (#596).
        (self.inert / "worker.py").write_text(literal_stand_in(INERT_WORKER), encoding="utf-8")
        for name in all_harness_binaries():
            trip = self.tripwire / name
            trip.write_text(f'#!/bin/sh\necho "{name} $*" >> {shlex.quote(str(self.tripwire / "hits.log"))}\nexit 97\n',
                            encoding="utf-8")
            trip.chmod(0o755)
        stand_in = self.inert / HARNESS_BINARIES.get(self.agent, self.agent)
        stand_in.write_text(
            "#!/bin/sh\n# first_run.py inert stand-in: no model is called.\n"
            f"exec {shlex.quote(sys.executable)} -I {shlex.quote(str(self.inert / 'worker.py'))} "
            f"{shlex.quote(self.agent)} \"$@\"\n",
            encoding="utf-8",
        )
        stand_in.chmod(0o755)

    def inert_runs(self) -> list[dict]:
        log = self.inert / "runs.log"
        if not log.is_file():
            return []
        return [json.loads(ln) for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]

    def tripwire_hits(self) -> str:
        log = self.tripwire / "hits.log"
        return log.read_text(encoding="utf-8", errors="replace") if log.is_file() else ""


class Recorder:
    """Runs each command, times it, and keeps the receipt's step list."""

    def __init__(self, sandbox: Sandbox):
        self.sb = sandbox
        self.steps: list[dict] = []
        self.commands: list[dict] = []

    def run(self, argv: list[str], *, cwd: Path | None = None, env: dict | None = None,
            timeout: int = 300, record: bool = True) -> subprocess.CompletedProcess:
        start = time.monotonic()
        full_env = {**self.sb.env, **(env or {})}
        try:
            proc = run_text(argv, cwd=str(cwd or self.sb.target), env=full_env, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            proc = subprocess.CompletedProcess(argv, 124, text_of(exc.stdout), f"timed out after {timeout}s")
            proc.raw = exc.stdout if isinstance(exc.stdout, bytes) else b""
        if record:  # polling reads are not receipts
            self.commands.append({"argv": [str(a) for a in argv], "env": sorted((env or {}).keys()),
                                  "rc": proc.returncode, "elapsed_s": round(time.monotonic() - start, 3)})
        return proc

    def step(self, name: str, fn, *args, **kwargs):
        start = time.monotonic()
        record: dict = {"step": name}
        try:
            detail = fn(*args, **kwargs)
            record.update(ok=True, detail=detail)
            return detail
        except StepFailed as exc:
            record.update(ok=False, detail=str(exc), recovery=exc.recovery)
            raise
        except Exception as exc:
            # A defect here must still end in a receipt, not a traceback with none (#596 review).
            # KeyboardInterrupt and the signal exits are BaseException and still unwind.
            where = traceback.extract_tb(exc.__traceback__)[-1]
            detail = f"unexpected {type(exc).__name__}: {exc}"[:1000]
            recovery = (f"a first_run.py defect at {Path(where.filename).name}:{where.lineno}; the sandbox is "
                        "kept: report it with receipt.json")
            record.update(ok=False, detail=detail, recovery=recovery)
            raise StepFailed(detail, recovery) from exc
        finally:
            record["elapsed_s"] = round(time.monotonic() - start, 3)
            self.steps.append(record)


def py(script: str, *args: str) -> list[str]:
    return [sys.executable, str(SCRIPTS / script), *args]


def field(out: str, key: str) -> str:
    m = re.search(rf"(?m)(?:^|\s){re.escape(key)}=(\S+)", out)
    return m.group(1) if m else ""


def git(rec: Recorder, *args: str, cwd: Path | None = None) -> str:
    proc = rec.run(["git", *args], cwd=cwd)
    if proc.returncode != 0:
        raise StepFailed(f"git {' '.join(args)} failed: {(proc.stderr or proc.stdout).strip()[:300]}")
    return proc.stdout.strip()


def harness_version(binary: str, env: dict) -> str:
    try:
        proc = run_text([binary, "--version"], timeout=30, env=env)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"unreadable: {exc}"
    return (proc.stdout or proc.stderr).strip().splitlines()[0][:200] if (proc.stdout or proc.stderr).strip() else ""


def host_facts() -> dict:
    def version(argv):
        try:
            out = run_text(argv, timeout=30)
            return (out.stdout or out.stderr).strip().splitlines()[0]
        except (OSError, subprocess.SubprocessError, IndexError):
            return None

    catalog = run_text(["git", "-C", str(ROOT), "rev-parse", "HEAD"], timeout=60)
    dirty = run_text(["git", "-C", str(ROOT), "status", "--porcelain"], timeout=60)
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "git": version(["git", "--version"]),
        "bash": version(["bash", "--version"]),
        "catalog_commit": catalog.stdout.strip() if catalog.returncode == 0 else None,
        "catalog_dirty": bool(dirty.stdout.strip()) if dirty.returncode == 0 else None,
    }


# --- lifecycle ------------------------------------------------------------------------------

class FirstRun:
    def __init__(self, args: argparse.Namespace, sandbox: Sandbox):
        self.args = args
        self.sb = sandbox
        self.rec = Recorder(sandbox)
        self.run_id = f"fr-{secrets.token_hex(3)}"
        self.nonce = f"FR-NONCE:{secrets.token_hex(8)}"
        self.unit_dir = f".first-run/{self.run_id}"
        self.change_rel = f"{self.unit_dir}/change.diff"
        # Only the change file carries this: quoting it shows the worker read that file (FR-4).
        self.read_receipt = f"{READ_HEAD}{secrets.token_hex(8)}"
        self.facts: dict = {"run_id": self.run_id, "nonce": self.nonce}
        self.started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Each method is one step; it returns its detail string or raises StepFailed.
    def prereqs(self) -> str:
        if sys.version_info < (3, 11):
            raise StepFailed(f"python {platform.python_version()} < 3.11", "run with Python 3.11-3.13")
        missing = [t for t in ("git", "bash", "sh") if not shutil.which(t, path=self.sb.env["PATH"])]
        if missing:
            raise StepFailed(f"not on PATH: {', '.join(missing)}", "install the missing tools")
        binary = HARNESS_BINARIES.get(self.args.agent, self.args.agent)
        found = shutil.which(binary, path=self.sb.env["PATH"])
        if not found:
            raise StepFailed(f"`{binary}` is not on PATH", f"install {self.args.agent} and sign it in, or use --worker inert")
        if self.args.worker == "live" and Path(found).resolve().is_relative_to(self.sb.dir.resolve()):
            raise StepFailed("live mode resolved the harness inside the sandbox", "remove the stand-in from PATH")
        shadow = "" if self.args.worker == "inert" else harness_shadow(binary, self.sb.env["PATH"],
                                                                         os.environ.get("PATH", os.defpath))
        if shadow:
            raise StepFailed(shadow, "run first_run.py with an interpreter whose directory holds no harness, "
                                     "or put the harness you mean first on your own PATH")
        self.facts["harness"] = {
            "name": self.args.agent,
            "path": found,
            "version": "inert stand-in (no model)" if self.args.worker == "inert" else harness_version(found, self.sb.env),
        }
        return f"{binary} -> {found}"

    def target(self) -> str:
        t = self.sb.target
        if self.args.target:
            src = Path(self.args.target).resolve()
            proc = self.rec.run(["git", "clone", "-q", "--no-hardlinks", str(src), str(t)], cwd=self.sb.dir)
            if proc.returncode != 0:
                raise StepFailed(f"cannot clone {src}: {proc.stderr.strip()[:300]}", "--target must be a git repository")
        else:
            t.mkdir(parents=True)
            git(self.rec, "init", "-q", "-b", "main", cwd=t)
        for key, val in (("user.email", "first-run@open-fleet.invalid"), ("user.name", "open-fleet first run"),
                         ("commit.gpgsign", "false"), ("tag.gpgsign", "false"), ("core.hooksPath", "/dev/null")):
            git(self.rec, "config", key, val, cwd=t)
        if not self.args.target:
            (t / "README.md").write_text("# first-run target\n", encoding="utf-8")
            git(self.rec, "add", "-f", "--", "README.md", cwd=t)
            git(self.rec, "commit", "-q", "-m", "seed", cwd=t)
            (t / "app.py").write_text("def greet(name):\n    return f'hello {name}'\n", encoding="utf-8")
            git(self.rec, "add", "-f", "--", "app.py", cwd=t)
            git(self.rec, "commit", "-q", "-m", "add greet()", cwd=t)
        for flag, rev in (("--base", self.args.base), ("--head", self.args.head)):
            if not rev or rev.startswith("-"):  # git reads both in option position (W2-04)
                raise StepFailed(f"{flag} {rev!r} must name a revision, not an option", f"pass {flag}=<commit>")
        base = git(self.rec, "rev-parse", "--verify", f"{self.args.base}^{{commit}}", cwd=t)
        head = git(self.rec, "rev-parse", "--verify", f"{self.args.head}^{{commit}}", cwd=t)
        if base == head:
            raise StepFailed("--base and --head name the same commit", "review a range with at least one commit")
        self.facts["reviewed"] = {"base_sha": base, "head_sha": head}
        # The coordinator's evidence branch starts at the reviewed head; its first commit is the
        # frozen contract, so the contract exists in git BEFORE any worker is dispatched.
        git(self.rec, "checkout", "-q", "-b", f"first-run/{self.run_id}", head, cwd=t)
        # The change reaches the worker as a FILE in its tree: most ro launches have no shell to
        # run `git diff` (omp, pi, opencode, jcode, goose, hermes, crush, gemini; claude in plan
        # mode), and the spec alone let a worker that never saw the change copy the header to a
        # GO (#596 review). It is frozen with the contract, so it is the evidence range's BASE and
        # never part of the result; its last line is the read receipt no other channel carries.
        diff = self.rec.run(["git", "-c", "core.quotePath=false", "diff", base, head, "--"], cwd=t)
        names = self.rec.run(["git", "-c", "core.quotePath=false", "diff", "--name-only", base, head, "--"], cwd=t)
        if diff.returncode != 0 or names.returncode != 0:
            raise StepFailed(f"git diff {base} {head} failed: {(diff.stderr or names.stderr).strip()[:300]}")
        # Byte-exact: a reviewed file in an older encoding reaches the worker as git wrote it.
        body = diff.raw if not diff.raw or diff.raw.endswith(b"\n") else diff.raw + b"\n"
        change = (f"# first-run {self.run_id}: the change under review, `git diff {base} {head}`.\n"
                  "# Written before dispatch. Read it to the end: its last line is the read receipt.\n").encode()
        change += body + f"{self.read_receipt}\n".encode()
        (t / self.unit_dir).mkdir(parents=True)
        (t / self.change_rel).write_bytes(change)
        self.facts["change"] = {"input": self.change_rel, "paths": names.stdout.splitlines()}
        contract = (
            f"# First-run contract {self.run_id}\n\n"
            f"Frozen by first_run.py before dispatch. Reviewed change: `{base}..{head}`.\n\n"
            f"- FR-1: the worker receives this unit's frozen spec ({self.nonce}) through the posix route.\n"
            f"- FR-2: the worker's report opens with `FIRST-RUN-REPORT {self.nonce} {head}`.\n"
            "- FR-3: the report is bound to a commit the coordinator reads from git and verify.py re-derives.\n"
            f"- FR-4: the report quotes the read receipt that ends `{self.change_rel}` and names every changed path.\n"
        )
        path = t / self.unit_dir / "contract.md"
        path.write_text(contract, encoding="utf-8")
        # Force-add exactly the files this run owns: a target's ignore rules (`*.diff`,
        # `.first-run/`) must not block them, and no glob may sweep in anything else (#596 review).
        git(self.rec, "add", "-f", "--", f"{self.unit_dir}/contract.md", self.change_rel, cwd=t)
        git(self.rec, "commit", "-q", "-m", f"first-run {self.run_id}: freeze contract", cwd=t)
        self.facts["contract"] = {
            "source": f"{self.unit_dir}/contract.md@{git(self.rec, 'rev-parse', 'HEAD', cwd=t)}",
            "digest": "sha256:" + hashlib.sha256(contract.encode("utf-8")).hexdigest(),
            "criterion_ids": ["FR-1", "FR-2", "FR-3", "FR-4"],
            "text": contract,
        }
        return f"reviewed {base[:12]}..{head[:12]}; contract frozen"

    def preflight(self) -> str:
        proc = self.rec.run(py("preflight.py", "--mission", "review-it", "--runtime", "posix", "--mode", "readonly"))
        if proc.returncode != 0:
            raise StepFailed(f"preflight refused: {(proc.stderr or proc.stdout).strip()[:300]}",
                             "read the preflight line; docs/troubleshooting.md")
        return proc.stdout.strip().splitlines()[-1]

    def spec(self) -> str:
        r = self.facts["reviewed"]
        lines = [
            f"open-fleet first-run review unit {self.run_id} ({self.nonce}).",
            f"Review the change {r['base_sha']}..{r['head_sha']}. Its diff is written to {self.change_rel} in your "
            "working tree: read that file to its end. You need no shell for this, and must not change it.",
            "Report what the change does and any problem you see, one line each, naming every changed path.",
            f"Your report MUST start with this exact line: FIRST-RUN-REPORT {self.nonce} {r['head_sha']}",
            "The file's last line is a read receipt: copy that line, verbatim, into your report.",
        ]
        if self.args.profile == "rw":
            lines += [
                f"Modify nothing except: write the report to {self.unit_dir}/report.md and commit only that file, "
                f"adding it with `git add -f -- {self.unit_dir}/report.md` (the repository may ignore it).",
                "Then report completion with:",
                '  python3 "$OPEN_FLEET_ROOT/runtime/scripts/send_msg.py" --type worker_done --outcome succeeded'
                ' --subject "worker_done:$OPEN_FLEET_DISPATCH_ID" --payload \'{"head": "<the report commit sha>"}\'',
                # The run reads the report from the final answer AND from the commit, and both must
                # meet the contract; without this line a live worker answered with a summary (#596).
                "Last, print the same report you committed, exactly as committed, as your final answer.",
            ]
        else:
            lines.append("Modify nothing. Print the report as your final answer.")
        lines.append(f"Frozen contract: {self.facts['contract']['source']} ({self.facts['contract']['digest']}).")
        return "\n".join(lines)

    def create(self) -> str:
        proc = self.rec.run(py("task_ops.py", "create", "--spec", self.spec()))
        task = field(proc.stdout, "CREATED")
        if proc.returncode != 0 or not task:
            raise StepFailed(f"task_ops.py create: rc={proc.returncode} {(proc.stderr or proc.stdout).strip()[:300]}",
                             "run task_ops.py create in the sandbox target to see the refusal")
        self.facts["task"] = task
        return task

    def dispatch(self) -> str:
        # Off Orca (OPEN_FLEET_RUNTIME=posix) the provider installs and verifies the deny hook
        # inside worker-start, before the agent starts, so spawn_worker's pre-launch gate defers
        # for a new-child spawn with no opt-out (W4-06); the `guard` step below re-checks it.
        env = {"PROFILE": self.args.profile}
        if self.args.profile == "rw":
            env["ORCA_COORD_ALLOW_AUTONOMOUS_WRITE"] = "1"
        proc = self.rec.run(["bash", str(SCRIPTS / "spawn_worker.sh"), self.facts["task"], "new-child",
                             self.run_id, self.args.agent], env=env)
        disp, handle = field(proc.stdout, "DISPATCH"), field(proc.stdout, "HANDLE")
        launch = next((ln.split("=", 1)[1] for ln in proc.stdout.splitlines() if ln.startswith("LAUNCH_EFFECTIVE=")), "")
        if proc.returncode != 0 or not disp:
            raise StepFailed(f"spawn_worker.sh rc={proc.returncode}: {(proc.stderr or proc.stdout).strip()[-400:]}",
                             "read the SPAWN= line; docs/troubleshooting.md")
        self.facts.update(dispatch=disp, handle=handle)
        try:
            self.facts["launch_effective"] = json.loads(launch)
        except json.JSONDecodeError:
            raise StepFailed(f"spawn_worker.sh printed no readable LAUNCH_EFFECTIVE: {launch[:200]!r}") from None
        return f"{disp} on {handle}"

    def worker_show(self) -> dict:
        proc = self.rec.run(py("orca_cli.py", "orchestration", "worker-show", "--dispatch", self.facts["dispatch"], "--json"))
        try:
            return json.loads(proc.stdout)["result"]["worker"]
        except (ValueError, KeyError, TypeError):
            raise StepFailed(f"worker-show unreadable: {proc.stdout[:200]!r}") from None

    def guard(self) -> str:
        wt = Path(self.worker_show()["worktree"])
        self.facts["worktree"] = str(wt)
        settings = wt / ".claude" / "settings.local.json"
        proc = self.rec.run(["sh", str(SCRIPTS / "deny-hook.sh"), "--verify-settings", str(settings)])
        if proc.returncode != 0:
            raise StepFailed(f"the installed guard is not armed: {proc.stderr.strip()[:300]}",
                             f"deny-hook.sh --verify-settings {settings}")
        return proc.stdout.strip()

    def delivery(self) -> str:
        command = str((self.facts.get("launch_effective") or {}).get("command", ""))
        if self.nonce not in command:
            raise StepFailed("the launch the provider recorded does not carry the task spec",
                             "the worker would start without its assignment; compare LAUNCH_EFFECTIVE to the task")
        if self.sb.worker == "inert":
            if not self.wait_for(lambda: (self.sb.inert / f"{self.facts['dispatch']}.argv.json").is_file()):
                raise StepFailed("the stand-in never ran for this dispatch", "worker_ops.py read --dispatch <d>")
            argv = json.loads((self.sb.inert / f"{self.facts['dispatch']}.argv.json").read_text(encoding="utf-8"))
            if not any(self.nonce in a for a in argv):
                raise StepFailed("the stand-in ran without the task spec in its argv")
            return "spec in the recorded launch and in the worker's argv"
        return "spec in the recorded launch (the live worker's echo is checked at result)"

    def wait_for(self, pred, timeout: float | None = None) -> bool:
        deadline = time.monotonic() + (timeout or self.args.timeout)
        while time.monotonic() < deadline:
            if pred():
                return True
            time.sleep(0.25)
        return False

    def result(self) -> str:
        disp = self.facts["dispatch"]
        state = {"v": ""}

        def settled():
            out = self.rec.run(py("worker_ops.py", "show", "--dispatch", disp), record=False).stdout
            state["v"] = field(out, "STATE")
            return state["v"] not in ("",) + LIVE_STATES

        if not self.wait_for(settled):
            raise StepFailed(f"worker still {state['v'] or 'unknown'} after {self.args.timeout}s",
                             f"worker_ops.py read --dispatch {disp} --source transcript; raise --timeout")
        mail = self.rec.run(py("check_reply.py", "check", "--terminal", "coordinator"))
        msgs = parse_mail(mail.stdout)
        mine = [m for m in msgs if disp in m["subject"]]
        # rw reports with send_msg.py. A ro worker has no tool to send mail: posix relays the
        # completion line its assignment names as its worker_done (#596), and records a clean exit
        # without that line as worker_died (exit=0). Either is the ro worker's settled report.
        expected = ("completed",) if self.args.profile == "rw" else ("completed", "died")
        if state["v"] not in expected:
            raise StepFailed(f"dispatch settled {state['v']!r}, expected {' or '.join(map(repr, expected))}: {mine}",
                             f"worker_ops.py read --dispatch {disp} --source transcript")
        if state["v"] == "completed":
            done = [m for m in mine if m["type"] == "worker_done"]
            if not done:
                raise StepFailed("no worker_done from this dispatch", "the worker never reported; read its transcript")
            if self.args.profile == "rw":
                self.facts["worker_claim"] = done[0]["payload"]
            elif (outcome := (done[0]["payload"] or {}).get("outcome")) != "succeeded":
                raise StepFailed(f"the ro worker reported {outcome or 'no outcome'}, not succeeded: {done[0]}",
                                 f"worker_ops.py read --dispatch {disp} --source transcript")
            self.facts["settled"] = {"state": "completed", "signal": "worker_done"}
        else:
            died = [m for m in mine if m["type"] == "escalation" and m["subject"].startswith("worker_died:")]
            if not died or (died[0]["payload"] or {}).get("exitCode") != 0:
                raise StepFailed(f"ro worker did not exit cleanly: {died}", f"worker_ops.py read --dispatch {disp}")
            self.facts["settled"] = {"state": "died", "signal": "worker_died"}
        read = self.rec.run(py("worker_ops.py", "read", "--dispatch", disp, "--source", "transcript"))
        if read.returncode != 0 or "SOURCE=transcript" not in read.stdout:
            raise StepFailed(f"transcript read not certified: {(read.stderr or read.stdout).strip()[:200]}")
        report = self.transcript_report()
        first = report.splitlines()[0] if report else ""
        want = self.report_header()
        if first.strip() != want:
            raise StepFailed(f"report does not open with {want!r}: {first[:200]!r}",
                             "the worker did not follow the spec; read its transcript")
        self.check_read(report, "report")
        self.facts["report"] = report
        return f"settled {state['v']}; report names the reviewed head"

    def report_header(self) -> str:
        """FR-2: the exact line every report opens with, printed and committed alike."""
        return f"{REPORT_HEAD}{self.nonce} {self.facts['reviewed']['head_sha']}"

    def check_read(self, report: str, what: str) -> None:
        """FR-4: the report shows its worker read the change file, not only the spec (#596 review).

        The receipt is the file's LAST line and appears nowhere else the worker sees, and the
        changed paths come from the diff itself: a worker that copied the header, read no file,
        or read only one end of it cannot meet both.
        """
        missing = [] if self.read_receipt in report else ["the read receipt"]
        missing += [p for p in self.facts["change"]["paths"]
                    if not re.search(rf"(?<![\w.-]){re.escape(p)}(?![\w/-])", report)]  # `b/<path>` counts
        if missing:
            raise StepFailed(f"the {what} does not show the worker read {self.change_rel}: missing {missing}",
                             f"the worker must read {self.change_rel} to its end; read its transcript")

    def transcript_report(self) -> str:
        proc = self.rec.run(py("orca_cli.py", "orchestration", "worker-read", "--dispatch", self.facts["dispatch"],
                               "--limit", "100000", "--json"))
        try:
            messages = json.loads(proc.stdout)["result"]["transcript"]["messages"]
        except (ValueError, KeyError, TypeError):
            raise StepFailed(f"worker-read unreadable: {proc.stdout[:200]!r}") from None
        lines = [str(block.get("text") or "") for msg in messages for block in (msg.get("blocks") or [])]
        usage = harness_usage(lines)
        if usage:  # the spend and the model a live run's record names (#596)
            self.facts["harness_usage"] = usage
        return harness_report(self.args.agent, lines)

    def evidence(self) -> str:
        t, rel = self.sb.target, f"{self.unit_dir}/report.md"
        if self.args.profile == "rw":
            head = git(self.rec, "rev-parse", "HEAD", cwd=Path(self.facts["worktree"]))
            claim = (self.facts.get("worker_claim") or {}).get("head")
            if claim != head:
                raise StepFailed(f"worker_done claims head {claim!r}; git says {head}", "the claim is not evidence")
        else:
            path = t / rel
            path.write_text(self.facts["report"], encoding="utf-8", errors="replace")
            git(self.rec, "add", "-f", "--", rel, cwd=t)
            git(self.rec, "commit", "-q", "-m", f"first-run {self.run_id}: report from the worker transcript", cwd=t)
            head = git(self.rec, "rev-parse", "HEAD", cwd=t)
        contract_sha = self.facts["contract"]["source"].rsplit("@", 1)[1]
        changed = git(self.rec, "diff", "--name-only", contract_sha, head, cwd=t).splitlines()
        if changed != [rel]:
            raise StepFailed(f"the evidence range changes more than the report: {changed}",
                             "a review unit may not change code")
        # verify.py binds the COMMITTED bytes, so they are what must meet FR-2: an rw worker could
        # print the right report and commit another (#596 review). Read from git, never the tree.
        committed = self.rec.run(["git", "show", f"{head}:{rel}"], cwd=t)
        first, want = (committed.stdout.splitlines() or [""])[0], self.report_header()
        if committed.returncode != 0 or first.strip() != want:
            raise StepFailed(f"the committed report does not open with {want!r}: {first[:200]!r}",
                             f"git show {head}:{rel}; the report the worker printed is not the one it committed")
        self.check_read(committed.stdout, "committed report")
        self.facts["evidence"] = {"base_sha": contract_sha, "head_sha": head}
        return f"{contract_sha[:12]}..{head[:12]} carries only {rel}"

    def verify(self) -> str:
        ev, contract = self.facts["evidence"], self.facts["contract"]
        checkout = self.sb.dir / "verify"
        git(self.rec, "worktree", "add", "-q", "--detach", str(checkout), ev["head_sha"], cwd=self.sb.target)
        rel = f"{self.unit_dir}/report.md"
        report = (checkout / rel).read_bytes()
        manifest = {
            "unit": f"first-run-{self.run_id}",
            "claim": f"first-run review of {self.facts['reviewed']['head_sha']} on the posix route "
                     f"({self.args.worker} {self.args.agent}, PROFILE={self.args.profile})",
            "base_sha": ev["base_sha"],
            "head_sha": ev["head_sha"],
            "base_branch": f"first-run/{self.run_id}",
            "contract": {k: contract[k] for k in ("source", "digest", "criterion_ids")},
            "criteria": [{"id": cid, "text": cid, "addressed": True} for cid in contract["criterion_ids"]],
            "artifacts": [{"path": rel, "sha256": hashlib.sha256(report).hexdigest()}],
        }
        mpath = checkout / self.unit_dir / "manifest.json"
        write_manifest(mpath, manifest)
        argv = py("verify.py", "--manifest", f"{self.unit_dir}/manifest.json", "--contract-source", contract["source"],
                  "--contract-digest", contract["digest"], "--unit-class", "report-only")
        proc = self.rec.run(argv, cwd=checkout)
        self.facts["verify"] = {"argv": argv[1:], "cwd": str(checkout), "rc": proc.returncode,
                                "out": (proc.stdout + proc.stderr).strip().splitlines()[-6:]}
        if proc.returncode != 0 or "verify: OK" not in proc.stdout:
            fails = [ln for ln in (proc.stdout + proc.stderr).splitlines() if ln.startswith("FAIL")]
            why = "; ".join(fails)[:1500] or (proc.stderr or proc.stdout).strip()[-400:]
            raise StepFailed(f"verify.py rc={proc.returncode}: {why}",
                             f"re-run in {checkout}: {' '.join(shlex.quote(a) for a in argv)}")
        return "verify: OK (report-only, SHA-bound)"

    def release(self) -> str:
        disp, head = self.facts["dispatch"], self.facts["evidence"]["head_sha"]
        for verb, want in (("retain", "retained"), ("release", "released")):
            proc = self.rec.run(py("worker_ops.py", verb, "--dispatch", disp))
            got = field(self.rec.run(py("worker_ops.py", "show", "--dispatch", disp)).stdout, "STATE")
            if proc.returncode != 0 or got != want:
                raise StepFailed(f"worker_ops.py {verb}: rc={proc.returncode} state={got!r}",
                                 f"worker_ops.py show --dispatch {disp}")
            if self.rec.run(["git", "cat-file", "-e", f"{head}^{{commit}}"]).returncode != 0:
                raise StepFailed(f"the evidence commit {head} is gone after {verb}")
        return "retained, then released; the evidence commit survives"

    def execute(self) -> dict:
        order = ["prereqs", "target", "preflight", "create", "dispatch", "guard", "delivery", "result",
                 "evidence", "verify", "release"]
        failed = None
        start = time.monotonic()
        try:
            for name in order:
                self.rec.step(name, getattr(self, name))
            if self.sb.worker == "inert":
                self.rec.step("isolation", self.isolation)
        except StepFailed:
            failed = self.rec.steps[-1]
        return self.receipt(failed, round(time.monotonic() - start, 3))

    def isolation(self) -> str:
        hits = self.sb.tripwire_hits()
        if hits:
            raise StepFailed(f"a harness resolved past the stand-in to a tripwire: {hits[:200]!r}")
        runs = [r["dispatch"] for r in self.sb.inert_runs()]
        if runs != [self.facts["dispatch"]]:
            raise StepFailed(f"the stand-in ran for {runs}, expected exactly this dispatch")
        return "only the stand-in ran, once, for this dispatch"

    def receipt(self, failed: dict | None, elapsed: float) -> dict:
        facts = {k: v for k, v in self.facts.items() if k not in ("report", "contract")}
        if "contract" in self.facts:
            facts["contract"] = {k: self.facts["contract"][k] for k in ("source", "digest", "criterion_ids")}
        out = {
            "schema": SCHEMA,
            "started_at": self.started_at,
            "verdict": "NO-GO" if failed else "GO",
            "tier": "fixture-tested" if self.sb.worker == "inert" else "live-unreviewed",
            "witness": "",
            "route": {"provider": "posix", "backend": "setsid", "profile": self.args.profile,
                      "harness": self.args.agent, "worker": self.sb.worker},
            "host": host_facts(),
            "facts": facts,
            "steps": self.rec.steps,
            "commands": self.rec.commands,
            "failure": failed,
            "elapsed_s": elapsed,
            "sandbox": str(self.sb.dir),
        }
        out["witness"] = witness_line(out)
        return out


def write_manifest(path: Path, manifest: dict) -> None:
    """The coordinator's manifest; a separate function so a test can mutate what gets bound."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


MAIL_HEAD = re.compile(r"^--- (\S+) \((\S+)\) from (\S+)$")


def parse_mail(text: str) -> list[dict]:
    """check_reply.py's printed messages: header, SUBJ line, then the payload line."""
    out: list[dict] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = MAIL_HEAD.match(line)
        if not m:
            continue
        subj = lines[i + 1][len("SUBJ: "):] if i + 1 < len(lines) and lines[i + 1].startswith("SUBJ: ") else ""
        payload = None
        if i + 2 < len(lines):
            try:
                payload = json.loads(lines[i + 2])
            except ValueError:
                payload = None
        out.append({"id": m.group(1), "type": m.group(2), "from": m.group(3), "subject": subj, "payload": payload})
    return out


# --- negative probes ------------------------------------------------------------------------

def probe_table(sb: Sandbox, unarmed: Path, garbage: Path) -> list[tuple]:
    """(name, why, argv, env, expected exit, refusal text) — `{task}` is a fresh ready task."""
    rw = {"PROFILE": "rw", "ORCA_COORD_ALLOW_AUTONOMOUS_WRITE": "1"}
    spawn = ["bash", str(SCRIPTS / "spawn_worker.sh")]
    return [
        ("unsupported-profile", "PROFILE=ro for a harness with no verified read-only launch (cursor)",
         spawn + ["{task}", "new-child", "probe", "cursor"], {"PROFILE": "ro"}, 2,
         "no verified PROFILE=ro launch flag"),
        ("privilege-escalation", "a ro parent asks for an rw child",
         spawn + ["{task}", "new-child", "probe", "claude"], {**rw, "OPEN_FLEET_PARENT_PROFILE": "ro"}, 2,
         "monotonic privilege narrowing violation"),
        ("unarmed-deny-hook", "the named hook registration never denies",
         spawn + ["{task}", "new-child", "probe", "claude"], {**rw, "OPEN_FLEET_DENY_HOOK_SETTINGS": str(unarmed)}, 2,
         "deny-hook not armed"),
        ("malformed-upstream-response", "the runtime CLI answers with non-JSON",
         spawn + ["{task}", "new-child", "probe", "claude"], {"PROFILE": "ro", "ORCA_CLI_COMMAND": str(garbage)}, 1,
         "SPAWN=FAILED"),
        ("missing-capability", "pin-it needs cap:orca-self-audit, which posix lacks",
         py("preflight.py", "--mission", "pin-it", "--runtime", "posix", "--mode", "readonly"), {}, 2,
         "missing_capability: cap:orca-self-audit"),
    ]


def probes(sb: Sandbox) -> dict:
    """Each probe must REFUSE before a launch: the stand-in never runs, no dispatch is recorded."""
    rec = Recorder(sb)
    sb.target.mkdir(parents=True, exist_ok=True)
    git(rec, "init", "-q", "-b", "main", cwd=sb.target)
    for key, val in (("user.email", "probe@open-fleet.invalid"), ("user.name", "probe"), ("commit.gpgsign", "false")):
        git(rec, "config", key, val, cwd=sb.target)
    git(rec, "commit", "-q", "--allow-empty", "-m", "seed", cwd=sb.target)

    unarmed = sb.dir / "unarmed-settings.json"
    block = run_text(["sh", str(SCRIPTS / "deny-hook.sh"), "--settings", str(sb.target)], check=True, timeout=60).stdout
    doc = json.loads(block)
    for entry in doc["hooks"]["PreToolUse"]:
        for hook in entry["hooks"]:
            hook["command"] = "true # deny-hook.sh registered but never denies"
    unarmed.write_text(json.dumps(doc), encoding="utf-8")
    garbage = sb.dir / "garbage-cli"
    garbage_log = sb.dir / "garbage-cli.log"
    garbage.write_text(f'#!/bin/sh\necho "$*" >> {shlex.quote(str(garbage_log))}\necho "<html>502 Bad Gateway</html>"\n',
                       encoding="utf-8")
    garbage.chmod(0o755)

    results = []
    for name, why, argv, env, want_rc, want_text in probe_table(sb, unarmed, garbage):
        created = rec.run(py("task_ops.py", "create", "--spec", f"probe {name}"))
        task = field(created.stdout, "CREATED")
        before = len(sb.inert_runs())
        proc = rec.run([a.replace("{task}", task) for a in argv], env=env)
        text = proc.stdout + proc.stderr
        workers = rec.run(py("orca_cli.py", "orchestration", "worker-list", "--json")).stdout
        try:
            dispatched = [w for w in json.loads(workers)["result"]["workers"] if w.get("taskId") == task]
        except (ValueError, KeyError, TypeError):
            dispatched = [{"unreadable": workers[:200]}]
        if dispatched:
            # A probe that did NOT refuse launched asynchronously: give the worker time to show.
            deadline = time.monotonic() + 15
            while len(sb.inert_runs()) == before and time.monotonic() < deadline:
                time.sleep(0.2)
        problems = []
        if proc.returncode != want_rc:
            problems.append(f"exit {proc.returncode}, expected {want_rc}")
        if want_text not in text:
            problems.append(f"no {want_text!r} in the output")
        if len(sb.inert_runs()) != before or sb.tripwire_hits():
            problems.append("a worker launched")
        if dispatched:
            problems.append(f"a dispatch was recorded: {dispatched}")
        if name == "malformed-upstream-response" and garbage_log.is_file() and "worker-start" in garbage_log.read_text(errors="replace"):
            problems.append("worker-start was called after an unreadable response")
        results.append({"probe": name, "why": why, "rc": proc.returncode, "refused": not problems,
                        "problems": problems, "evidence": [ln for ln in text.splitlines() if want_text in ln][:2]})
    return {"schema": SCHEMA, "verdict": "GO" if all(r["refused"] for r in results) else "NO-GO",
            "probes": results, "host": host_facts(), "sandbox": str(sb.dir)}


# --- entry point ----------------------------------------------------------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="first_run.py", description="Reproducible first run of the posix route (#596).")
    ap.add_argument("mode", nargs="?", default="run", choices=("run", "probes"))
    ap.add_argument("--profile", default="ro", choices=("ro", "rw"))
    ap.add_argument("--agent", default="claude")
    ap.add_argument("--worker", default="inert", choices=("inert", "live"),
                    help="live runs only inside the container-based live harness (PR #668)")
    ap.add_argument("--target", default=None, help="git repository to review (cloned; never modified)")
    ap.add_argument("--base", default="HEAD~1")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--workdir", default=None, help="sandbox directory (created; default a new temp dir)")
    ap.add_argument("--keep", action="store_true", help="keep the sandbox after a GO")
    ap.add_argument("--timeout", type=int, default=None, help="seconds to wait for the worker (inert 60, live 1800)")
    ap.add_argument("--json", action="store_true", help="print the receipt JSON instead of lines")
    ns = ap.parse_args(argv)
    if ns.agent not in posix_harnesses():
        ap.error(f"--agent {ns.agent!r} is not a posix harness (want {'|'.join(posix_harnesses())})")
    if ns.timeout is None:
        ns.timeout = 60 if ns.worker == "inert" else 1800
    if ns.timeout < 1:
        ap.error("--timeout must be positive")
    return ns


def make_workdir(arg: str | None) -> Path:
    if arg:
        path = Path(arg).resolve()
        if path.exists() and any(path.iterdir()):
            raise SystemExit(f"first_run.py: --workdir {path} is not empty")
        path.mkdir(parents=True, exist_ok=True)
        return path
    return Path(tempfile.mkdtemp(prefix="open-fleet-first-run-")).resolve()


def emit(receipt: dict, path: Path, as_json: bool) -> None:
    path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    if as_json:
        print(json.dumps(receipt, indent=2))
        return
    if "probes" in receipt:
        for p in receipt["probes"]:
            state = "REFUSED" if p["refused"] else "NOT-REFUSED"
            print(f"PROBE={p['probe']} {state} rc={p['rc']}" + (f" problems={p['problems']}" if p["problems"] else ""))
        print(f"PROBES={receipt['verdict']}")
    else:
        f = receipt["facts"]
        route = receipt["route"]
        failed = receipt["failure"]
        print(f"FIRST_RUN={receipt['verdict']}" + (f" step={failed['step']}" if failed else ""))
        print(f"ROUTE=posix/setsid PROFILE={route['profile']} HARNESS={route['harness']} "
              f"WORKER={route['worker']} TIER={receipt['tier']}")
        if "reviewed" in f:
            print(f"REVIEWED={f['reviewed']['base_sha']}..{f['reviewed']['head_sha']}")
        if "evidence" in f:
            verdict = "OK" if not failed or failed["step"] not in ("verify",) else "FAILED"
            print(f"EVIDENCE={f['evidence']['base_sha']}..{f['evidence']['head_sha']} VERIFY={verdict}")
        if "dispatch" in f:
            print(f"DISPATCH={f['dispatch']} TASK={f.get('task', '')}")
        if failed:
            print(f"FAILURE={failed['detail']}")
            if failed.get("recovery"):
                print(f"RECOVERY={failed['recovery']}")
        print(f"ELAPSED_S={receipt['elapsed_s']}")
    print(f"RECEIPT={path}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    why = containment.live_disabled() if args.worker == "live" else None
    if why:  # first, before anything is read, created or launched (PR #668: the live tier is off)
        print(f"first_run.py: refused: {why}", file=sys.stderr)
        return 2
    if args.worker == "live" and args.mode != "probes":
        # A live worker spends: it starts only where containment is proven, a detached system
        # binary included, before anything is created (PR #668 review: the strong probe).
        why = containment.containment_problem()
        if why:
            print(f"first_run.py: refused: process discovery cannot contain a call on this host ({why}): a "
                  "live worker's escaped processes could never be found or stopped, so a live run does not "
                  "start (run it in a disposable Linux container)", file=sys.stderr)
            return 2
    workdir = make_workdir(args.workdir)
    agent = "claude" if args.mode == "probes" else args.agent
    sb = Sandbox(workdir, "inert" if args.mode == "probes" else args.worker, agent)
    previous = trap_termination()
    try:
        receipt = probes(sb) if args.mode == "probes" else FirstRun(args, sb).execute()
    finally:
        # Ctrl-C, `kill`, a closed terminal or any error mid-run too: setsid puts the worker in
        # its own session, out of reach of the signal that ended the run, so it would keep
        # running and spending (#596 review). A second signal is held off until it is stopped:
        # the run is ending either way.
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        try:
            teardown = stop_workers(sb, sweep=functools.partial(containment.sweep, tag=sb.call_tag))
        finally:
            restore_signals(previous)
    receipt["teardown"] = teardown
    if not teardown_verified(teardown) and receipt["verdict"] == "GO":
        # GO stands only on a verified teardown (PR #668 review): a process of the run may still be
        # running and spending, so this run is NO-GO and its sandbox is kept for inspection. The
        # failure is a step record like any other, and the witness is rebuilt from the final verdict.
        receipt["verdict"] = "NO-GO"
        receipt["failure"] = {"step": "teardown", "ok": False, "elapsed_s": 0.0,
                              "detail": f"teardown not verified: {teardown}"[:2000],
                              "recovery": f"a process of this run may still be running: the sandbox {sb.dir} is "
                                          f"kept; find what carries {containment.CALL_MARKER}={sb.call_tag} and "
                                          "end it before another run"}
        if isinstance(receipt.get("steps"), list):
            receipt["steps"].append(receipt["failure"])
        if "witness" in receipt:
            receipt["witness"] = witness_line(receipt)
    if receipt["verdict"] == "GO" and not args.keep:
        # Everything but the receipt goes: state store, clone, worktrees, verifier checkout.
        for child in workdir.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink()
        receipt["sandbox_pruned"] = True
    emit(receipt, workdir / "receipt.json", args.json)
    return 0 if receipt["verdict"] == "GO" else 1


TRAPPED_SIGNALS = (signal.SIGTERM, signal.SIGHUP)


def _terminated(signum, _frame):
    """SIGTERM/SIGHUP unwind like Ctrl-C does, so main()'s `finally` stops the workers."""
    raise SystemExit(128 + signum)


def trap_termination() -> dict:
    """Install _terminated for TRAPPED_SIGNALS; return the handlers it replaced, to restore."""
    if threading.current_thread() is not threading.main_thread():
        return {}  # signal.signal works only on the main thread; nothing to restore
    return {sig: signal.signal(sig, _terminated) for sig in TRAPPED_SIGNALS}


def restore_signals(previous: dict) -> None:
    for sig, handler in previous.items():
        signal.signal(sig, signal.SIG_DFL if handler is None else handler)


STOP_TIMEOUT_S = 120  # one worker listing or stop, at most: teardown never waits on a hung call


def stop_workers(sb: Sandbox, sweep=None) -> dict:
    """Fence anything still live in this sandbox's store before its directory goes away, then end
    whatever any of its workers left behind (reap_groups); the teardown it verified. Every call is
    bounded (Codex review of PR #668): one that times out is a teardown error, never a hang.

    A process group is only what stayed in it: a descendant that called setsid() leaves its worker's
    group, and only a marker it carries can find it. `sweep`, when given, is the caller's marker
    sweep (scripts/_ablation_run.py's, bound to the run's OF_CALL_ID): True once nothing carrying the
    marker is left, False when one survives or the process table cannot be read. Its answer is
    `contained`; without one, `contained` is None: the groups were reaped, nothing more is vouched."""
    errors = []
    try:
        proc = run_text(py("orca_cli.py", "orchestration", "worker-list", "--json"),
                        cwd=str(sb.target) if sb.target.is_dir() else str(sb.dir), env=sb.env, timeout=STOP_TIMEOUT_S)
        workers = json.loads(proc.stdout)["result"]["workers"]
    except subprocess.TimeoutExpired:
        workers, errors = [], errors + [f"worker-list timed out after {STOP_TIMEOUT_S}s"]
    except (ValueError, KeyError, TypeError):
        workers = []
    for w in workers:
        if w.get("state") in LIVE_STATES:
            try:
                run_text(py("worker_ops.py", "stop", "--dispatch", w["dispatchId"]), env=sb.env, cwd=str(sb.dir),
                         timeout=STOP_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                errors.append(f"worker_ops.py stop {w['dispatchId']} timed out after {STOP_TIMEOUT_S}s")
    reaped = reap_groups(sb)
    contained = None
    if sweep is not None:
        try:
            contained = bool(sweep())
        except Exception as err:  # a sweep that breaks vouches for nothing
            contained, errors = False, errors + [f"the marker sweep failed: {err}"]
    return {**reaped, "errors": reaped.get("errors", []) + errors, "contained": contained}


def teardown_verified(teardown: dict) -> bool:
    """Nothing of the run is left: the marker sweep vouched, no group member survived SIGKILL, and
    every teardown call answered."""
    return teardown.get("contained") is True and not teardown.get("survivors") and not teardown.get("errors")


def process_groups() -> dict[int, set[int]]:
    """{process group id: its living members}, from the shared process table (containment.py:
    /proc on Linux, `ps` elsewhere; a zombie is already dead and is not a member). OSError when the
    table cannot be read: a reap that cannot see vouches for nothing (PR #668 CI: reading `ps`
    alone, a Linux host without procps saw no groups and reported nothing)."""
    groups: dict[int, set[int]] = {}
    for pid, (_ppid, pgid, _env) in containment.process_table().items():
        groups.setdefault(pgid, set()).add(pid)
    return groups


def reap_groups(sb: Sandbox, wait_s: float = 5.0, grace_s: float = 3.0) -> dict:
    """End every process group a worker of this sandbox's store leaves behind, finished dispatches
    included (Codex review of PR #653: a dispatch is `completed` once its foreground process
    exits, and the provider never kills a finished dispatch's group because its pid may be reused,
    so a background child the worker started outlived every cleanup). A group whose leader is gone
    but whose members remain is a worker's leftover; a reused number always has its own living
    leader, so a group with a living leader is never touched (it is waited for, then reported).
    Returns {"ended", "survivors", "leaders_alive"}: survivors are members still alive after
    SIGKILL, which the caller must not settle as torn down."""
    try:
        conn = sqlite3.connect(f"file:{sb.state_db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute("SELECT * FROM dispatches").fetchall()
        finally:
            conn.close()
    except (sqlite3.Error, AttributeError):
        rows = []
    pending: dict[int, str] = {}
    for row in rows:
        for col in ("pid", "monitor_pid"):
            if col in row.keys() and row[col] and int(row[col]) > 1:
                pending[int(row[col])] = row["dispatch_id"]
    ended: list[dict] = []
    try:
        return _reap(pending, ended, wait_s, grace_s)
    except OSError as err:  # the table could not be read: nothing it has not ended is vouched for
        return {"ended": ended, "survivors": [], "leaders_alive": [{"dispatch": d, "pgid": g} for g, d in sorted(pending.items())],
                "errors": [f"the process table cannot be read: {err}"]}


def _reap(pending: dict, ended: list, wait_s: float, grace_s: float) -> dict:
    end = time.monotonic() + wait_s
    while pending:
        groups = process_groups()
        for pgid in sorted(pending):
            members = groups.get(pgid, set())
            if not members:
                pending.pop(pgid)  # nothing of it is left
            elif pgid not in members:  # leader gone, members left: the worker's leftovers
                ended.append({"dispatch": pending.pop(pgid), "pgid": pgid, "members": sorted(members)})
                for sig in (signal.SIGTERM, signal.SIGKILL):
                    try:
                        os.killpg(pgid, sig)
                    except OSError:
                        break
                    stop_by = time.monotonic() + grace_s
                    while time.monotonic() < stop_by and process_groups().get(pgid):
                        time.sleep(0.05)
                    if not process_groups().get(pgid):
                        break
        if not pending or time.monotonic() >= end:
            break
        time.sleep(0.2)
    groups = process_groups()
    return {"ended": ended,
            "survivors": [{"pgid": e["pgid"], "members": sorted(groups[e["pgid"]])} for e in ended if groups.get(e["pgid"])],
            "leaders_alive": [{"dispatch": d, "pgid": g} for g, d in sorted(pending.items())]}


if __name__ == "__main__":
    sys.exit(main())
