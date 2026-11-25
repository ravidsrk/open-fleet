#!/usr/bin/env python3
"""release_check.py — the 1.0 release checklist as a runnable gate (#414).

docs/release-1.0-checklist.md DEFINES the release: every gate is a command a
second person can run, with its expected output. This script RUNS those
commands from the repo root, one line per check, and exits with a code a
release branch can be gated on. The document stays the definition, this file
is its executable form, and the two must agree: the checklist opens with the
command that runs this file, and tests/test_release_check.py runs it against
this repository and holds the doc's commands to the script's checks.

Usage:
  python3 scripts/release_check.py                 # every gate, full suite (about an hour serially)
  python3 scripts/release_check.py --fast          # skip the unittest suite: SKIP(--fast)
  python3 scripts/release_check.py --skip-github   # skip the gh-backed checks: SKIP(--skip-github)
  python3 scripts/release_check.py --json          # one JSON object on stdout instead of lines
  python3 scripts/release_check.py --repo PATH     # gate another checkout (tests point it at a fixture)

Output, text mode: a header per gate, then one line per check —
  PASS  <gate>/<check>: <detail>
  FAIL  <gate>/<check>: <detail>
  SKIP(<reason>)  <gate>/<check>
  INFO  <gate>/<check>: <detail>        a fact the release does not gate on (#235)
— and a final `summary:` line with the counts and the exit code.

Exit contract (fail-closed):
  0  every check PASS (INFO lines are allowed; the summary counts them)
  1  any check FAIL
  2  could not run: --repo is not a directory, or a gate raised
  3  incomplete: no FAIL, but at least one SKIP — the run proved less than the
     release needs (--fast, --skip-github, or a machine without gh, network,
     git or sh). A 3 is not a release verdict; only a 0 is (PR #509 review).

SKIP rules: a check that needs something this MACHINE does not have — `gh` not
on PATH (SKIP(no gh)), `gh auth status` failing (SKIP(gh unauthenticated)), no
route to GitHub (SKIP(no network)), git or sh absent — prints SKIP with the
reason and never PASS. A SKIP is not a FAIL, but it is counted, printed, and
turns exit 0 into exit 3, so a run carrying one cannot be mistaken for a full
run by a script reading only the exit code: re-run it where the tool exists. The gh-backed checks carry `gh-` in their name. Something the
CHECKOUT lacks (no scripts/validate.py, no gate-batch store, a missing report)
is a FAIL, not a SKIP: that is the release's state, not the machine's.

Stdlib only. Subprocesses take argv lists, never shell text; the checkout's
Python tools run under this interpreter (sys.executable), so an empty PATH
cannot swap it for another.
"""
import sys

# W3-01: `python3 <dir>/<script>.py` puts <dir> at sys.path[0], AHEAD of the stdlib, so a committed
# sibling named like a stdlib module (json.py, hashlib.py) would BE that module here, and no
# toolchain hash binds it. Drop that entry before any other import (`from __future__` imports too,
# which is why this file has none); `os` is read from sys.modules, loaded at start-up, never
# imported. `python3 -I` does the same from outside; this holds when a caller forgets it.
if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import argparse
import datetime
import json
import os
import re
import shlex
import shutil
import subprocess
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_REPO = HERE.parent

PASS, FAIL, SKIP, INFO = "PASS", "FAIL", "SKIP", "INFO"
STATUSES = (PASS, FAIL, SKIP, INFO)

# Gate 1 reads this run's gate batch: #408 settled it, #419 typed it (gate-batch.json).
GATE_BATCH_RUN = "2026-09-14-clean-sweep-tracker"
# Gate 2: the flagships, and the bar as #407 re-scoped it (#409 took harden-it
# from external-run to self-run). A BOUND tier is the bar; the tier is not.
FLAGSHIPS = ("harden-it", "prove-it", "clean-sweep")
PROOF_BAR = ("self-run", "external-run")
# Gate 4: the one install command, in both places it is documented.
INSTALL_CMD = "sh scripts/install.sh"
# Gate 5: the pin must be a fresh live witness, not the 2026-09-13 one #416 replaced,
# and the chaining report must be named by a doc a reader navigates.
PIN_MIN_WITNESSED = "2026-09-16"
CHAINING_NEEDLE = "docs/reports/chaining-"
CHAINING_INDEXES = ("runtime/mission-chaining.md", "docs/runs/README.md")
# Gate 6: each mechanized tool with the contract test module that holds it.
MECHANIZED = (("runtime/scripts/watchdog.py", "tests/test_watchdog.py"),
              ("runtime/scripts/gate-batch.py", "tests/test_gate_batch.py"))

TIMEOUT_TOOL = 600      # validate, proof_status, run_report, the vf-bench gate, the demo
TIMEOUT_SUITE = 7200    # the full unittest suite: over 3600 s serially on a laptop at 1.0.0
TIMEOUT_GH = 120

OWED_LINE = re.compile(r"^(G\d+) \[owed\]")
LIST_LINE = re.compile(r"^(G\d+) \[(\w+)\]")

# gh's own wording when the machine, not GitHub, is the problem.
_OFFLINE_MARKERS = ("could not resolve", "no such host", "dial tcp", "connection refused",
                    "connection reset", "network is unreachable", "i/o timeout", "timed out",
                    "tls handshake", "error connecting to", "failed to connect",
                    "temporary failure in name resolution", "proxyconnect")
_UNAUTHENTICATED_MARKERS = ("not logged in", "gh auth login", "authentication", "http 401",
                            "bad credentials", "no oauth token", "gh_token")


class Result:
    """What a subprocess left behind, including the two ways it never ran."""
    __slots__ = ("returncode", "stdout", "stderr", "missing", "timeout")

    def __init__(self, returncode, stdout="", stderr="", missing=False, timeout=False):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.missing = missing
        self.timeout = timeout

    @property
    def ok(self):
        return self.returncode == 0


_UNPROBED = object()


class Context:
    """The checkout under test, the flags, a memo of commands already run
    (run_report.py is a Gate 0 and a Gate 2 check; it runs once) and the
    one-time gh probe. `on_check` streams each check as it lands."""

    def __init__(self, repo=DEFAULT_REPO, fast=False, skip_github=False, on_check=None):
        self.repo = Path(repo).resolve()
        self.fast = fast
        self.skip_github = skip_github
        self.on_check = on_check
        self._memo = {}
        self._gh = _UNPROBED

    def run(self, argv, timeout=TIMEOUT_TOOL, memo=True):
        """Run argv from the repo root, capturing text. Never raises for the
        executable being absent or slow: callers branch on the Result."""
        argv = [str(a) for a in argv]
        key = tuple(argv)
        if memo and key in self._memo:
            return self._memo[key]
        try:
            proc = subprocess.run(argv, cwd=str(self.repo), capture_output=True,
                                  encoding="utf-8", errors="replace", timeout=timeout)
            result = Result(proc.returncode, proc.stdout, proc.stderr)
        except FileNotFoundError:
            result = Result(None, "", f"{argv[0]}: not found on PATH", missing=True)
        except subprocess.TimeoutExpired:
            result = Result(None, "", f"timed out after {timeout}s", timeout=True)
        except OSError as e:
            result = Result(None, "", f"{argv[0]}: {e}", missing=True)
        if memo:
            self._memo[key] = result
        return result

    def py(self, tool, *args, timeout=TIMEOUT_TOOL):
        """Run one of the checkout's Python tools under this interpreter."""
        script = self.repo / tool
        if not script.is_file():
            return Result(None, "", f"{tool}: not in this checkout", missing=True)
        return self.run([sys.executable, "-I", str(script), *args], timeout=timeout)

    def read(self, rel):
        """Text of a checkout file, or None when it is not there."""
        try:
            return (self.repo / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def rel(self, path):
        try:
            return str(Path(path).resolve().relative_to(self.repo))
        except ValueError:
            return str(path)

    def record(self, checks, check):
        checks.append(check)
        if self.on_check is not None:
            self.on_check(check)
        return check


def tail(text, lines=2, width=240):
    """The last non-empty lines of a stream, on one line, for a detail field."""
    kept = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    out = " | ".join(kept[-lines:]) if kept else "(no output)"
    return out if len(out) <= width else out[:width - 1] + "…"


def git_head(ctx):
    r = ctx.run(["git", "rev-parse", "HEAD"])
    return r.stdout.strip() if r.ok else None


# ---------------------------------------------------------------------------
# gh: the machine's fault is a SKIP, GitHub's answer is a verdict.
# ---------------------------------------------------------------------------

def _offline(text):
    low = text.lower()
    return any(marker in low for marker in _OFFLINE_MARKERS)


def _unauthenticated(text):
    low = text.lower()
    return any(marker in low for marker in _UNAUTHENTICATED_MARKERS)


def gh_unavailable(ctx):
    """None when gh can answer; otherwise the SKIP reason. Probed once per run."""
    if ctx.skip_github:
        return "--skip-github"
    if ctx._gh is not _UNPROBED:
        return ctx._gh
    if shutil.which("gh") is None:
        ctx._gh = "no gh"
        return ctx._gh
    r = ctx.run(["gh", "auth", "status"], timeout=TIMEOUT_GH, memo=False)
    text = r.stderr + r.stdout
    if r.missing:
        ctx._gh = "no gh"
    elif r.timeout:
        ctx._gh = "no network: gh auth status " + r.stderr
    elif r.ok:
        ctx._gh = None
    elif _offline(text):
        ctx._gh = "no network: " + tail(text, 1, 120)
    else:
        ctx._gh = "gh unauthenticated"
    return ctx._gh


def gh_json(ctx, argv):
    """(data, None) from a gh command that prints JSON, else (None, (status, detail)):
    SKIP when the machine is at fault, FAIL when GitHub answered and it was no."""
    reason = gh_unavailable(ctx)
    if reason:
        return None, (SKIP, reason)
    r = ctx.run(["gh", *argv], timeout=TIMEOUT_GH)
    if r.missing:
        return None, (SKIP, "no gh")
    if r.timeout:
        return None, (SKIP, "no network: gh " + r.stderr)
    label = "gh " + " ".join(argv)
    if not r.ok:
        text = r.stderr + r.stdout
        if _offline(text):
            return None, (SKIP, "no network: " + tail(text, 1, 120))
        if _unauthenticated(text):
            return None, (SKIP, "gh unauthenticated")
        return None, (FAIL, f"{label}: exit {r.returncode}: {tail(text)}")
    try:
        return json.loads(r.stdout), None
    except ValueError:
        return None, (FAIL, f"{label} printed no JSON: {tail(r.stdout)}")


def check_issue_closed(ctx, gate, number, why):
    name = f"{gate}/gh-issue-{number}-closed"
    data, err = gh_json(ctx, ["issue", "view", str(number), "--json", "state"])
    if err:
        return (name, err[0], err[1])
    state = str((data or {}).get("state", "")).upper()
    if state == "CLOSED":
        return (name, PASS, f"#{number} CLOSED ({why})")
    return (name, FAIL, f"#{number} is {state or 'in an unknown state'}; the gate needs CLOSED ({why})")


def check_pr_merged(ctx, gate, number, why):
    name = f"{gate}/gh-pr-{number}-merged"
    data, err = gh_json(ctx, ["pr", "view", str(number), "--json", "state"])
    if err:
        return (name, err[0], err[1])
    state = str((data or {}).get("state", "")).upper()
    if state == "MERGED":
        return (name, PASS, f"PR #{number} MERGED ({why})")
    return (name, FAIL, f"PR #{number} is {state or 'in an unknown state'}; the gate needs MERGED ({why})")


def check_workflow_green_at_head(ctx, gate, workflow):
    """The newest `<workflow>` run at exactly this HEAD must be a success — a stale green from
    another SHA does not count.

    docs/ops.md cuts on a release branch, whose HEAD never has a run on main, so asking main
    could only FAIL at a cut (2026-10-27 security audit, W6-12); asking by branch NAME let a
    fork's pull request from a same-named branch take the one run read (PR #718 re-attack). gh's
    run list names no head repository, so the read is bound to the commit instead: the runs at
    HEAD, on any branch. A fork can only show a run of this very commit."""
    name = f"{gate}/gh-{workflow}-run-green-at-head"
    reason = gh_unavailable(ctx)
    if reason:
        return (name, SKIP, reason)
    head_probe = ctx.run(["git", "rev-parse", "HEAD"])
    if head_probe.missing:
        return (name, SKIP, "no git")
    if not head_probe.ok:
        return (name, FAIL, f"git rev-parse HEAD: {tail(head_probe.stderr, 1)}")
    head = head_probe.stdout.strip()
    data, err = gh_json(ctx, ["run", "list", "--workflow", workflow, "--commit", head,
                              "--limit", "20", "--json", "conclusion,headSha,headBranch,event"])
    if err:
        return (name, err[0], err[1])
    if not isinstance(data, list) or not data:
        return (name, FAIL, f"no `{workflow}` workflow run recorded at HEAD {head}")
    at_head = [run for run in data if isinstance(run, dict) and run.get("headSha") == head]
    if not at_head:
        other = data[0].get("headSha") if isinstance(data[0], dict) else None
        return (name, FAIL, f"no `{workflow}` run at HEAD {head} (the newest listed is at {other}) "
                            "— a stale green from another SHA does not count")
    run = at_head[0]  # gh lists the newest first
    conclusion = run.get("conclusion")
    if conclusion == "success":
        return (name, PASS, f"`{workflow}` bound GREEN at {head} "
                            f"({run.get('event') or '?'} run on {run.get('headBranch') or '?'})")
    return (name, FAIL, f"the newest `{workflow}` run at HEAD {head} is "
                        f"{conclusion or 'unfinished'}")


# ---------------------------------------------------------------------------
# Gate 0 — tree and catalog gates green
# ---------------------------------------------------------------------------

def check_tree_clean(ctx):
    name = "gate0/tree-clean"
    r = ctx.run(["git", "status", "--porcelain"])
    if r.missing:
        return (name, SKIP, "no git")
    if not r.ok:
        return (name, FAIL, f"git status --porcelain: exit {r.returncode}: {tail(r.stderr)}")
    dirty = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    if dirty:
        shown = ", ".join(dirty[:5]) + (" …" if len(dirty) > 5 else "")
        return (name, FAIL, f"{len(dirty)} uncommitted path(s): {shown}")
    return (name, PASS, f"working tree clean at {git_head(ctx) or 'HEAD'}")


def check_tool_exit0(ctx, name, tool, *args, timeout=TIMEOUT_TOOL):
    """PASS iff `python3 <tool> <args>` exits 0. A tool the checkout lacks FAILs."""
    label = " ".join((tool, *args))
    r = ctx.py(tool, *args, timeout=timeout)
    if r.missing:
        return (name, FAIL, r.stderr)
    if r.timeout:
        return (name, FAIL, f"{label}: {r.stderr}")
    if r.ok:
        return (name, PASS, f"{label}: exit 0 — {tail(r.stdout or r.stderr, 1)}")
    return (name, FAIL, f"{label}: exit {r.returncode}: {tail(r.stderr or r.stdout)}")


def check_suite(ctx):
    name = "gate0/unittest"
    label = "python3 -m unittest discover -s tests"
    if not (ctx.repo / "tests").is_dir():
        return (name, FAIL, "no tests/ directory in this checkout")
    r = ctx.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                timeout=TIMEOUT_SUITE)
    if r.timeout:
        return (name, FAIL, f"{label}: {r.stderr}")
    if r.ok:
        return (name, PASS, f"{label}: {tail(r.stderr, 2)}")
    return (name, FAIL, f"{label}: exit {r.returncode}: {tail(r.stderr, 3)}")


# The bookkeeping PRs file as one file per change and the cut folds in (CI speed and bookkeeping
# change): changelog.d/ fragments, the tests badge's count, docs/runs/index/ rows. Between releases
# PRs only add files, so the check is their shape; on a cut every one must be folded and current.
BOOKKEEPING_BETWEEN = (("scripts/changelog.py", "check"),
                       ("scripts/run_index.py", "check"))
BOOKKEEPING_AT_CUT = (("scripts/changelog.py", "check", "--released"),
                      ("scripts/run_index.py", "check", "--current"),
                      ("scripts/gen-badges.py", "--check", "--release"))


def check_release_bookkeeping(ctx):
    """PASS when the tree's bookkeeping matches its release state.

    docs/releases.json's `preparing` says which state that is: null between releases (fragments
    and run rows well formed, still waiting for a cut), a version on a cut (every fragment folded
    into the dated section, the tests badge at today's count, the run index re-rendered)."""
    name = "gate0/release-bookkeeping"
    raw = ctx.read("docs/releases.json")
    try:
        preparing = json.loads(raw).get("preparing") if raw is not None else None
    except (json.JSONDecodeError, AttributeError):
        return (name, FAIL, "docs/releases.json is not a JSON object")
    if raw is None:
        return (name, FAIL, "docs/releases.json: not in this checkout")
    commands = BOOKKEEPING_AT_CUT if preparing else BOOKKEEPING_BETWEEN
    done = []
    for tool, *args in commands:
        label = " ".join((tool, *args))
        r = ctx.py(tool, *args)
        if r.missing:
            return (name, FAIL, r.stderr)
        if r.timeout:
            return (name, FAIL, f"{label}: {r.stderr}")
        if not r.ok:
            return (name, FAIL, f"{label}: exit {r.returncode}: {tail(r.stdout or r.stderr)}")
        done.append(tail(r.stdout or r.stderr, 1))
    state = (f"cut of {preparing.get('version')}" if isinstance(preparing, dict)
             else "between releases")
    return (name, PASS, f"{state}: " + "; ".join(done))


def gate0(ctx):
    """Gate 0 — tree and catalog gates green."""
    checks = []

    def add(check):
        return ctx.record(checks, check)

    add(check_tree_clean(ctx))
    add(check_tool_exit0(ctx, "gate0/validate", "scripts/validate.py"))
    add(check_release_bookkeeping(ctx))
    if ctx.fast:
        add(("gate0/unittest", SKIP, "--fast"))
    else:
        add(check_suite(ctx))
    add(check_tool_exit0(ctx, "gate0/proof-status", "runtime/scripts/proof_status.py", "--check"))
    add(check_tool_exit0(ctx, "gate0/run-report", "runtime/scripts/run_report.py"))
    add(check_workflow_green_at_head(ctx, "gate0", "validate"))
    return checks


# ---------------------------------------------------------------------------
# Gate 1 — Phase 0 at zero (epic DoD 1)
# ---------------------------------------------------------------------------

def check_gate_batch_owed(ctx):
    """The store is gate-batch.json (#419), read through its own CLI — never a
    grep over the rendered .md, which is a view of the store, not the store.

    W3-06 / PR #719 review: whether an answer is a human's is decided by the human
    grant key, and the key is read at refs/remotes/origin/main — resolved once,
    through any symbolic chain, to a commit — never from the tree being released,
    where a deleted pin turned typed answers back on. That ref is what this clone's
    fetch of the reviewed default branch wrote, and a key lands there only by a
    reviewed one-way grant; the release HEAD is the thing being judged. No such
    commit here is a FAIL: a missing key cannot be told from a deleted one.

    PR #719 review round 3: the SET of gates is read at that same commit. gate-batch.py
    --pin-ref lists every gate the anchored batch carries that the release tree's lacks or
    altered as owed, so `"gates": []` and a re-rendered view no longer pass; a store the anchor
    does not carry has no trusted set to hold the release to, and a view the anchor carries
    must still be here and agree (render --check). Each is a FAIL."""
    name = "gate1/gate-batch-owed"
    tool = "runtime/scripts/gate-batch.py"
    store = f"docs/runs/{GATE_BATCH_RUN}/gate-batch.json"
    view_md = f"docs/runs/{GATE_BATCH_RUN}/gate-batch.md"
    anchor = "refs/remotes/origin/main"

    def git(*args):
        code, out, _err = _hardened_git(ctx, *args)
        return code, out

    # W3-07 class: the one exact-name rule (gitexec.remote_tracking_commit). With the anchor
    # ABSENT, `rev-parse refs/remotes/origin/main` expanded it to a local branch
    # refs/heads/refs/remotes/origin/main — one the release tree's author can write, carrying the
    # key and the gate set it chose.
    pin, _target, why = _gitexec().remote_tracking_commit(git, anchor)
    if pin is None:
        return (name, FAIL, f"the human grant key is read at {anchor}, which names no "
                            f"remote-tracking commit in this checkout (fetch origin) — {anchor} "
                            f"{why}: a key read from the tree being released could be one it "
                            "deleted (W3-06, W3-07)")
    label = f"gate-batch.py --run {GATE_BATCH_RUN} --pin-ref {pin[:12]} list --status owed"
    r = ctx.py(tool, "--run", GATE_BATCH_RUN, "--pin-ref", pin, "list", "--status", "owed")
    if r.missing:
        return (name, FAIL, r.stderr)
    if r.timeout:
        return (name, FAIL, f"{label}: {r.stderr}")
    if not r.ok:
        return (name, FAIL, f"{label}: exit {r.returncode}: {tail(r.stderr)}")
    code, listing, err = _hardened_git(ctx, "ls-tree", "-z", "--name-only", "--full-tree", pin,
                                       "--", store, view_md)
    if code != 0:
        return (name, FAIL, f"cannot list {store} at {anchor} ({pin[:12]}): {tail(err)}")
    carried = set(p for p in listing.split("\0") if p)
    if store not in carried:
        return (name, FAIL, f"{anchor} ({pin[:12]}) carries no {store}: the set of owed gates "
                            "is read there, and a store only the release tree carries could "
                            "owe nothing (PR #719 review)")
    if view_md in carried and ctx.read(view_md) is None:
        return (name, FAIL, f"{view_md} is at {anchor} ({pin[:12]}) but not in the release tree: "
                            "the store re-renders it on every mutation, so it is deleted, not "
                            "stale (PR #719 review)")
    # W3-06: the human-readable view must say what the store says — a .md edited to disagree
    # used to be caught by tests only. (No .md here or at the anchor: no view to disagree.)
    if ctx.read(view_md) is not None:
        view = ctx.py(tool, "--run", GATE_BATCH_RUN, "render", "--check")
        if not view.ok:
            return (name, FAIL, f"gate-batch.py --run {GATE_BATCH_RUN} render --check: the .md "
                                f"view disagrees with the store: {tail(view.stderr)}")
    owed = [m.group(1) for m in (OWED_LINE.match(ln) for ln in r.stdout.splitlines()) if m]
    if owed:
        return (name, FAIL, f"{len(owed)} owed gate(s) in {GATE_BATCH_RUN}: {', '.join(owed)}")
    listing = ctx.py(tool, "--run", GATE_BATCH_RUN, "--pin-ref", pin, "list")
    states = [f"{m.group(1)} {m.group(2)}"
              for m in (LIST_LINE.match(ln) for ln in listing.stdout.splitlines()) if m]
    detail = f"no owed gates in {GATE_BATCH_RUN}"
    if states:
        detail += ": " + ", ".join(states)
    return (name, PASS, detail)


def info_issue_235(ctx):
    """#235 (marketplace submissions) is needs-human and its own body says it
    does not gate launch: recorded for the reader, never graded."""
    name = "gate1/issue-235-marketplace"
    base = "#235 marketplace submissions: needs-human, does not gate"
    reason = gh_unavailable(ctx)
    if reason:
        return (name, INFO, f"{base} (state not queried: {reason})")
    data, err = gh_json(ctx, ["issue", "view", "235", "--json", "state"])
    if err:
        return (name, INFO, f"{base} (state not queried: {err[1]})")
    state = (data or {}).get("state", "unknown")
    return (name, INFO, f"{base} (state {state}; stays tracked)")


def gate1(ctx):
    """Gate 1 — Phase 0 at zero (epic DoD 1)."""
    checks = []

    def add(check):
        return ctx.record(checks, check)

    add(check_gate_batch_owed(ctx))
    add(check_issue_closed(ctx, "gate1", 408, "runway settled"))
    add(check_issue_closed(ctx, "gate1", 386, "signing decision recorded and implemented"))
    add(check_pr_merged(ctx, "gate1", 406, "docs re-check"))
    add(info_issue_235(ctx))
    return checks


# ---------------------------------------------------------------------------
# Gate 2 — flagships proven (epic DoD 2)
# ---------------------------------------------------------------------------

def _hardened_git(ctx, *args):
    """(exit, stdout, stderr) for one git call in the checkout under gitexec.py's absolute git and
    hardened environment — replacement objects and grafts off, repository command config closed —
    so gate 1 resolves its anchor and lists what the anchor carries the way gate-batch.py reads
    it (independent re-attack: `git replace <anchor> <other>` changed what the ambient git listed
    at the anchor). stdout is not stripped and decodes losslessly. Never raises."""
    gitexec = _gitexec()
    try:
        proc = subprocess.run(gitexec.argv("-C", str(ctx.repo), *args), capture_output=True,
                              timeout=TIMEOUT_TOOL, env=gitexec.env(), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as err:
        return None, "", f"git {args[0]}: {err}"
    return (proc.returncode, proc.stdout.decode("utf-8", "surrogateescape"),
            proc.stderr.decode("utf-8", "replace"))


def _gitexec():
    """runtime/scripts/gitexec.py, by path: the one exact-name rule a trust anchor answers to."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "gitexec_for_release_check", Path(__file__).resolve().parent.parent / "runtime"
        / "scripts" / "gitexec.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _catalog_grammar():
    """The catalog's one frontmatter reader (runtime/scripts/_catalog_grammar.py), by path."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_catalog_grammar", Path(__file__).resolve().parent.parent / "runtime" / "scripts"
        / "_catalog_grammar.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def frontmatter_proof(text):
    """`metadata.proof` from a SKILL.md, read by the shared frontmatter reader validate.py
    uses. This used its own regex over any indented `proof:` line, one of five readers that
    disagreed (2026-10-23 review, §5) — a `proof:` under some other key read as the tier."""
    data, _err = _catalog_grammar().parse_frontmatter(text)
    meta = (data or {}).get("metadata")
    proof = meta.get("proof") if isinstance(meta, dict) else None
    return proof if isinstance(proof, str) and proof else None


def gate2(ctx):
    """Gate 2 — flagships proven (epic DoD 2)."""
    checks = []

    def add(check):
        return ctx.record(checks, check)

    bar = " or ".join(PROOF_BAR)
    for mission in FLAGSHIPS:
        name = f"gate2/proof-{mission}"
        path = f"skills/{mission}/SKILL.md"
        text = ctx.read(path)
        if text is None:
            add((name, FAIL, f"{path} missing"))
            continue
        proof = frontmatter_proof(text)
        if proof is None:
            add((name, FAIL, f"{path}: no metadata.proof in the frontmatter"))
        elif proof in PROOF_BAR:
            add((name, PASS, f"{path}: proof: {proof} (bar: {bar})"))
        else:
            add((name, FAIL, f"{path}: proof: {proof}; the bar is {bar}"))
    add(check_tool_exit0(ctx, "gate2/run-report", "runtime/scripts/run_report.py"))
    return checks


# ---------------------------------------------------------------------------
# Gate 3 — verifier moat held by CI (epic DoD 3)
# ---------------------------------------------------------------------------

def check_negative_control_demo(ctx):
    name = "gate3/negative-control-demo"
    script = "evals/demo/negative-control/run.sh"
    if not (ctx.repo / script).is_file():
        return (name, FAIL, f"{script} missing")
    sh = shutil.which("sh") or ("/bin/sh" if os.path.exists("/bin/sh") else None)
    if sh is None:
        return (name, SKIP, "no sh")
    r = ctx.run([sh, str(ctx.repo / script)], timeout=TIMEOUT_TOOL)
    if r.missing:
        return (name, SKIP, "no sh")
    if r.timeout:
        return (name, FAIL, f"sh {script}: {r.stderr}")
    if r.ok:
        verdict = next((ln.strip() for ln in r.stdout.splitlines() if ln.startswith("PASS:")),
                       None) or tail(r.stdout, 1)
        return (name, PASS, f"sh {script}: exit 0 — {verdict}")
    return (name, FAIL, f"sh {script}: exit {r.returncode}: {tail(r.stdout + r.stderr, 2)}")


_BLOCK_SCALAR_RE = re.compile(r"^[|>](?:[1-9]?[+-]?|[+-]?[1-9]?)$")
_JOB_KEY_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$")
_STEP_KEY_RE = re.compile(r"^(\s*)(?:-\s+)?([A-Za-z_-]+):\s*(.*?)\s*$")
# A step or job carrying one of these may not run its line, may not fail the build, or may run
# it some other way than the line says (`shell: bash -n {0}`; `working-directory` or `defaults`
# deciding which file the path names; `needs:` on a job whose prerequisite is skipped, which
# GitHub then skips too; a `strategy:` matrix that can expand to no job at all; `uses:`, a
# reusable workflow's jobs in place of the job's own steps; a `container:` image choosing what
# `python3` or `sh` is). None of the real gate-3 steps or jobs carries one, so none is
# allowlisted: a condition's truth is GitHub's to decide at run time, not this check's.
_STEP_DISQUALIFIERS = frozenset({"if", "continue-on-error", "shell", "working-directory"})
_JOB_DISQUALIFIERS = frozenset({"if", "continue-on-error", "defaults", "needs", "strategy", "uses",
                                "container"})
_GATE3_INTERPRETERS = frozenset({"python3", "bash", "sh"})
# Anything that could make the line more than one command, redirect it or expand into one.
_SHELL_METACHARACTERS = re.compile(r"[;&|<>`\n\r]|\$\(")

# The block-style YAML that a line-by-line read of a workflow sees exactly as GitHub's parser
# does: gate 3 here, and every workflow scan in tests/test_repo_hygiene.py. It is an allowlist.
# Refusing the spellings that hide a key (a flow mapping, `uses :`, an anchor, then an explicit
# `? uses` key, PR #718 reviews) missed one more each round, and a key hidden from a line scan is
# a `needs:` or `if:` gate 3 never sees, or a `uses: …@v4` the pin test never sees.
_YAML_KEY = r"[A-Za-z0-9_][A-Za-z0-9_.-]*"
_YAML_QUOTED = r"\"(?:[^\"\\]|\\.)*\"|'(?:[^']|'')*'"
# A plain scalar on one line: it opens with no YAML indicator (a tag `!`, an anchor `&`, an alias
# `*`, an explicit key `?`, a flow collection, a quote...), holds no `: ` (a mapping) and stops
# before a ` #` comment.
_YAML_PLAIN = r"(?:[^-?:,\[\]{}#&*!|>'\"%@` ]|-(?=[^ ]))(?:[^ :]|:(?=[^ ])| +(?=[^ #]))*"
_YAML_FLOW_ITEM = (_YAML_QUOTED + r"|(?:[^-?:,\[\]{}#&*!|>'\"%@` ]|-(?=[^ ,\[\]{}]))"
                   r"(?:[^ :,\[\]{}]|:(?=[^ ,\[\]{}])| +(?=[^ #,\[\]{}]))*")
# A value: a quoted or plain scalar, an empty `{}`, or a one-line `[...]` of scalars (never a
# flow mapping, whose keys no line scan reads).
_YAML_VALUE = (rf"(?:{_YAML_QUOTED}|\{{\}}"
               rf"|\[ *(?:(?:{_YAML_FLOW_ITEM}) *(?:, *(?:{_YAML_FLOW_ITEM}) *)*)?\]|{_YAML_PLAIN})")
# One line: spaces, at most one `- ` and then a plain `key:` (with a scalar, a block scalar
# header or nothing after it), or `- ` and a scalar; a comment may follow.
_YAML_LINE_RE = re.compile(
    rf"(?P<indent> *)(?P<dash>- )?"
    rf"(?:(?P<key>{_YAML_KEY}):(?:(?P<block> +[|>](?:[1-9][+-]?|[+-][1-9]?)?)"
    rf"|(?P<value> +{_YAML_VALUE})?)|(?<=- ){_YAML_VALUE})(?: +#.*)? *")
# A control character, or a character Python's str.splitlines() breaks a line at and YAML 1.2
# does not (so a line scan and the parser would disagree on where a key starts).
_YAML_FORBIDDEN_CHAR_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\ufeff]")


def block_yaml_offenders(text):
    """[(line number, line)] for every line of `text` outside the block YAML subset a line scan
    reads as GitHub does; [] when the whole file is inside it.

    Inside it: each line, outside a block scalar's body, is blank, a comment, or matches
    _YAML_LINE_RE (a plain key, at most one `- `, scalars only), and nests by exactly two spaces:
    a key with nothing after it opens a block two columns right of the key, every other line
    sits at a column some open block of its own kind (mapping or sequence) holds, so neither a
    sequence at its parent key's column, a four-space job nor `-   uses:` passes. A block scalar's
    body is every line indented past its key. No control character, and no Unicode line or
    paragraph separator, anywhere. Not a YAML parser (none is installed in CI, and the suite is
    stdlib-only): a file this accepts is one each line scan reads key by key as written.
    """
    lines = text.split("\n")
    bad = [(n, line) for n, line in enumerate(lines, start=1)
           if _YAML_FORBIDDEN_CHAR_RE.search(line)]
    levels, opened, body = [("map", 0)], None, None
    for n, line in enumerate(lines, start=1):
        if body is not None:
            if not line.strip(" ") or _indent(line) > body:
                continue
            body = None
        if not line.strip(" ") or line.lstrip(" ").startswith("#"):
            continue
        m = _YAML_LINE_RE.fullmatch(line)
        col, kind = (len(m["indent"]), "seq" if m["dash"] else "map") if m else (None, None)
        if m and opened is not None and col == opened:
            levels.append((kind, col))
        elif m and (kind, col) in levels:
            del levels[levels.index((kind, col)) + 1:]
        else:
            bad.append((n, line))
            opened = None
            continue
        key_col, opened = col + 2 if m["dash"] else col, None
        if m["dash"] and m["key"] is not None:
            levels.append(("map", key_col))
        if m["block"]:
            body = key_col
        elif m["key"] is not None and m["value"] is None:
            opened = key_col + 2
    return sorted(set(bad))


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def workflow_steps(text):
    """[(job, [step lines])] for every step of every job under the top-level `jobs:` key. A job
    carrying a disqualifying key is left out, and so is every job of a workflow with top-level
    `defaults:`. Stdlib only: no YAML parser in CI."""
    if re.search(r"(?m)^defaults:", text):
        return []
    jobs, current, in_jobs = {}, None, False
    for line in text.splitlines():
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if in_jobs and line and not line[0].isspace() and not line.startswith("#"):
            in_jobs = False
        if not in_jobs:
            continue
        if m := _JOB_KEY_RE.match(line):
            current = jobs.setdefault(m.group(1), [])
        elif current is not None:
            current.append(line)
    out = []
    for job, lines in jobs.items():
        if any((m := _STEP_KEY_RE.match(ln)) and _indent(ln) == 4
               and m.group(2) in _JOB_DISQUALIFIERS for ln in lines):
            continue
        step, in_steps = None, False
        for line in lines:
            if re.match(r"^    steps:\s*$", line):
                in_steps = True
                continue
            if in_steps and re.match(r"^    \S", line):
                in_steps = False
            if not in_steps:
                continue
            if re.match(r"^      - ", line):
                step = [line]
                out.append((job, step))
            elif step is not None:
                step.append(line)
    return out


def _step_run(step):
    """The step's whole `run:` value, as the shell receives it (a folded scalar joined with
    spaces), or None when the step has no `run:` or carries a disqualifying key. Keys are read at
    the step's own key indent, so a nested map cannot pose as one."""
    key_indent = len(step[0]) - len(step[0].lstrip(" -"))
    value = None
    for i, line in enumerate(step):
        m = _STEP_KEY_RE.match(line)
        if not m or (i and _indent(line) != key_indent):
            continue
        key, inline = m.group(2), m.group(3)
        if key in _STEP_DISQUALIFIERS:
            return None
        if key == "run":
            if not _BLOCK_SCALAR_RE.match(inline):
                value = inline
                continue
            body = []
            for nxt in step[i + 1:]:
                if nxt.strip() and _indent(nxt) <= key_indent:
                    break
                body.append(nxt.strip())
            value = (" " if inline.startswith(">") else "\n").join(body)
    return value


def runs_on_every_pull_request(text):
    """Whether the workflow's `on:` map holds a bare `pull_request:`: every pull request runs it,
    with no `branches`, `paths` or `types` filter under the key. Both real gate-3 workflows
    trigger that way (and on pushes to main); a dispatch- or schedule-only workflow proves
    nothing about what gates a merge."""
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines) if re.match(r"^on:\s*(?:#.*)?$", ln)), None)
    if start is None:
        return False
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            return False
        if re.match(r"^  pull_request:\s*(?:#.*)?$", line):
            rest = (ln for ln in lines[i + 1:] if ln.strip() and not ln.lstrip().startswith("#"))
            return _indent(next(rest, "")) <= 2
    return False


def invoked_script(run_value):
    """The script path when `run_value`, stripped, is exactly one invocation, else None.

    One invocation: one line that is exactly `<interpreter> <script>`, the interpreter python3,
    bash or sh, or exactly `./<script>`, with no shell metacharacter anywhere (`;`, `&`, `|`, `<`,
    `>`, a backtick, `$(`, a line break). Shell reachability is undecidable, so nothing more
    permissive is read: no setup line, no prefix, no second command, no option that could stop
    the interpreter before the script (`-h`, `-c`, `-n`), and no argument after it, which the
    script reads (`--help` printed help and ran nothing, PR #718 re-attack). The real gate-3
    steps take none.
    """
    text = (run_value or "").strip()
    if not text or _SHELL_METACHARACTERS.search(text):
        return None
    try:
        words = shlex.split(text)
    except ValueError:
        return None
    if len(words) == 2 and words[0] in _GATE3_INTERPRETERS and not words[1].startswith("-"):
        return words[1][2:] if words[1].startswith("./") else words[1]
    if len(words) == 1 and words[0].startswith("./") and len(words[0]) > 2:
        return words[0][2:]
    return None


def check_workflows_mention(ctx, name, patterns, landed):
    """PASS iff some workflow job step's whole `run:` is one invocation of a script matching one
    of `patterns`.

    "CI runs X" was satisfied by X anywhere in a workflow file (2026-10-23 review, §5), then by X
    anywhere in a `run:` line (`echo X`, 2026-10-27 security audit, W6-10), then by lines a shell
    never reaches (`true || X`, `exit 0` or `if false; then` before X) and by options that stop
    the interpreter (`bash -n X`), PR #718 reviews. Shell reachability is undecidable, so the rule
    is a decidable one: a step under a top-level job counts only when its whole `run:` value,
    stripped, is one invocation (invoked_script says exactly what that is), neither the step nor
    its job carries `if:` or `continue-on-error:`, the job has no `needs:` (a skipped prerequisite
    skips it, PR #718 review round 3), `strategy:`, `uses:` or `container:`, the step sets no
    `shell:` or `working-directory:`, neither its job nor the workflow sets `defaults:`, the
    workflow runs on every pull request (runs_on_every_pull_request; a dispatch-only workflow
    counted, PR #718 re-attack), and every line of the workflow is in the block YAML subset
    (block_yaml_offenders; a quoted `"needs":`, `needs :` or an explicit `? needs` key hid the
    key from this read, PR #718 review round 3). Not read: the environment (`env:`, or
    `$GITHUB_ENV` written by an earlier step), an earlier step, or the runner.
    """
    wf_dir = ctx.repo / ".github" / "workflows"
    files = sorted(
        p for p in wf_dir.iterdir()
        if p.is_file() and p.suffix in (".yml", ".yaml")
    ) if wf_dir.is_dir() else []
    hits, unread = [], []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        if not runs_on_every_pull_request(text):
            continue
        if offenders := block_yaml_offenders(text):
            unread.append(f"{path.name}:{offenders[0][0]}")
            continue
        invoked = [script for _job, step in workflow_steps(text)
                   if (script := invoked_script(_step_run(step)))]
        if any(re.search(pat, script) for script in invoked for pat in patterns):
            hits.append(path.name)
    what = " or ".join(patterns)
    if hits:
        return (name, PASS, f".github/workflows/{{{', '.join(hits)}}} run {what} as the whole of "
                            f"an unconditional job step ({landed} landed)")
    skipped = (f"; not read, outside the block YAML subset: {', '.join(unread)}"
               if unread else "")
    return (name, FAIL, f"no unconditional job step under .github/workflows/ is exactly one "
                        f"invocation of {what} ({landed} has not landed){skipped}")


def gate3(ctx):
    """Gate 3 — verifier moat held by CI (epic DoD 3)."""
    checks = []

    def add(check):
        return ctx.record(checks, check)

    add(check_tool_exit0(ctx, "gate3/vf-bench-gate", "bench/vf-bench/gate.py"))
    add(check_negative_control_demo(ctx))
    add(check_workflows_mention(ctx, "gate3/ci-runs-vf-bench",
                                (r"^bench/vf-bench/(gate|vfbench)\.py$",), "#412"))
    add(check_workflows_mention(ctx, "gate3/ci-runs-negative-control",
                                (r"^evals/demo/negative-control/run\.sh$",), "#413"))
    return checks


# ---------------------------------------------------------------------------
# Gate 4 — install is one command (epic DoD 4)
# ---------------------------------------------------------------------------

def check_file_exists(ctx, name, rel):
    if (ctx.repo / rel).is_file():
        return (name, PASS, f"{rel} exists")
    return (name, FAIL, f"{rel} missing")


def gate4(ctx):
    """Gate 4 — install is one command (epic DoD 4)."""
    checks = []

    def add(check):
        return ctx.record(checks, check)

    for doc in ("README.md", "docs/distribution.md"):
        name = f"gate4/install-command-in-{Path(doc).stem.lower()}"
        text = ctx.read(doc)
        if text is None:
            add((name, FAIL, f"{doc} missing"))
            continue
        count = text.count(INSTALL_CMD)
        if count:
            add((name, PASS, f"{doc}: {count} mention(s) of `{INSTALL_CMD}`"))
        else:
            add((name, FAIL, f"{doc}: `{INSTALL_CMD}` not mentioned"))
    add(check_file_exists(ctx, "gate4/checklist-exists", "docs/release-1.0-checklist.md"))
    add(check_workflow_green_at_head(ctx, "gate4", "install"))
    return checks


# ---------------------------------------------------------------------------
# Gate 5 — runtime re-pinned, chaining exercised (epic DoD 5)
# ---------------------------------------------------------------------------

_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_NON_REPORT_RUN_NAMES = frozenset({"README.MD", "TEMPLATE.MD"})


def _parse_iso_date(value):
    """Strict YYYY-MM-DD calendar date via datetime.date.fromisoformat (#788)."""
    if not isinstance(value, str) or not _ISO_DATE_RE.fullmatch(value):
        return None
    try:
        return datetime.date.fromisoformat(value)
    except ValueError:
        return None


def _is_valid_live_receipt_run(ctx, run):
    """Require a real markdown run report under docs/runs/ (not README/TEMPLATE/dotfiles) (#788)."""
    if not isinstance(run, str) or not run.startswith("docs/runs/"):
        return False
    parts = run.split("/")
    if any(not part or part in (".", "..") or part.startswith(".") for part in parts):
        return False
    filename = parts[-1]
    if filename.upper() in _NON_REPORT_RUN_NAMES or not filename.endswith(".md"):
        return False
    target = ctx.repo / run
    try:
        target.resolve().relative_to((ctx.repo / "docs" / "runs").resolve())
    except (OSError, ValueError):
        return False
    return target.is_file() and ctx.read(run) is not None


def check_orca_pin(ctx):
    name = "gate5/orca-pin-live"
    text = ctx.read("runtime/pins.json")
    if text is None:
        return (name, FAIL, "runtime/pins.json missing")
    try:
        orca = json.loads(text)["orca"]
        witness = orca.get("witness")
        witnessed_raw = orca.get("witnessed")
        witnessed = str(witnessed_raw if witnessed_raw is not None else "")
        version = orca.get("version")
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        return (name, FAIL, f"runtime/pins.json: no readable orca entry ({type(e).__name__}: {e})")
    min_date = _parse_iso_date(PIN_MIN_WITNESSED)
    witnessed_date = _parse_iso_date(witnessed_raw)
    if witness == "live" and witnessed_date is not None and witnessed_date >= min_date:
        return (name, PASS, f"orca {version} witnessed {witnessed} live (fresh: >= {PIN_MIN_WITNESSED})")
    # A source-delta re-pin stands on the last LIVE replay it carries: `live_receipts` names that
    # witness's version, date and run record, which must exist under docs/runs/ and clear the same
    # floor. A pure source pin, or one leaning on a stale or unrecorded live witness, still fails.
    # pins.json once labelled the v1.4.229 source re-pin "live" and this gate passed on the label
    # (2026-10-23 review, P2-41); the carried receipts are now a field the gate reads, not a word.
    carried = orca.get("live_receipts") if isinstance(orca, dict) else None
    if witness == "source" and isinstance(carried, dict) and witnessed_date is not None:
        live_on_raw = carried.get("witnessed")
        live_on_date = _parse_iso_date(live_on_raw)
        run = carried.get("run")
        recorded = _is_valid_live_receipt_run(ctx, run)
        if (live_on_date is not None and live_on_date >= min_date
                and live_on_date <= witnessed_date and recorded):
            return (name, PASS, f"orca {version} source re-pin {witnessed} carrying live receipts "
                                f"from {carried.get('version')} witnessed {live_on_raw} ({run})")
    return (name, FAIL, f"orca {version}: witness={witness!r} witnessed={witnessed!r}; the gate "
                        f"needs witness 'live' and witnessed >= {PIN_MIN_WITNESSED}, or a source "
                        f"re-pin whose live_receipts were witnessed >= {PIN_MIN_WITNESSED} and "
                        "recorded under docs/runs/")


def check_chaining_report_published(ctx):
    name = "gate5/chaining-report-published"
    reports_dir = ctx.repo / "docs" / "reports"
    reports = sorted(p for p in reports_dir.glob("chaining-*") if p.is_dir()) \
        if reports_dir.is_dir() else []
    if reports:
        return (name, PASS, ", ".join(ctx.rel(p) + "/" for p in reports))
    return (name, FAIL, "no docs/reports/chaining-*/ directory — the chaining exercise's report "
                        "is not published")


def check_chaining_report_indexed(ctx):
    """A report nobody links is not published: the protocol under test
    (runtime/mission-chaining.md) or the run-archive index must name it."""
    name = "gate5/chaining-report-indexed"
    naming = [doc for doc in CHAINING_INDEXES if CHAINING_NEEDLE in (ctx.read(doc) or "")]
    if naming:
        return (name, PASS, f"{', '.join(naming)} name(s) {CHAINING_NEEDLE}*")
    return (name, FAIL, f"neither {' nor '.join(CHAINING_INDEXES)} names {CHAINING_NEEDLE}*")


def gate5(ctx):
    """Gate 5 — runtime re-pinned, chaining exercised (epic DoD 5)."""
    checks = []

    def add(check):
        return ctx.record(checks, check)

    add(check_orca_pin(ctx))
    add(check_chaining_report_published(ctx))
    add(check_chaining_report_indexed(ctx))
    add(check_issue_closed(ctx, "gate5", 416, "re-pin run"))
    add(check_issue_closed(ctx, "gate5", 417, "chaining exercise"))
    return checks


# ---------------------------------------------------------------------------
# Gate 6 — mechanization merged and used (epic DoD 6)
# ---------------------------------------------------------------------------

def check_tool_merged(ctx, tool, test):
    name = f"gate6/{Path(tool).stem}-merged"
    if not (ctx.repo / tool).is_file():
        return (name, FAIL, f"{tool} missing")
    if (ctx.repo / test).is_file():
        return (name, PASS, f"{tool} in tree, contract-tested by {test}")
    return (name, FAIL, f"{tool} in tree but {test} missing — merged without its contract test")


def check_gate_batch_used(ctx):
    name = "gate6/gate-batch-used"
    runs = ctx.repo / "docs" / "runs"
    stores = sorted(runs.glob("*/gate-batch.json")) if runs.is_dir() else []
    if stores:
        shown = ", ".join(ctx.rel(p) for p in stores[:3]) + (" …" if len(stores) > 3 else "")
        return (name, PASS, f"{len(stores)} run(s) carry a gate-batch.json store: {shown}")
    return (name, FAIL, "no docs/runs/*/gate-batch.json — no run has consumed gate-batch.py")


def check_watchdog_used(ctx):
    name = "gate6/watchdog-used"
    runs = ctx.repo / "docs" / "runs"
    needle = b"watchdog.py"
    hits = []
    if runs.is_dir():
        for path in sorted(runs.rglob("*")):
            if not path.is_file():
                continue
            try:
                if needle in path.read_bytes():
                    hits.append(ctx.rel(path))
            except OSError:
                continue
    if hits:
        shown = ", ".join(hits[:3]) + (f" … ({len(hits)} files)" if len(hits) > 3 else "")
        return (name, PASS, f"run artifacts name watchdog.py: {shown}")
    return (name, FAIL, "no file under docs/runs/ names watchdog.py — no run has consumed the watchdog")


def gate6(ctx):
    """Gate 6 — mechanization merged and used (epic DoD 6)."""
    checks = []

    def add(check):
        return ctx.record(checks, check)

    for tool, test in MECHANIZED:
        add(check_tool_merged(ctx, tool, test))
    add(check_gate_batch_used(ctx))
    add(check_watchdog_used(ctx))
    add(check_issue_closed(ctx, "gate6", 418, "liveness watchdog"))
    add(check_issue_closed(ctx, "gate6", 419, "gate-batch tooling"))
    return checks


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------

GATES = (
    ("gate0", "Gate 0 — tree and catalog gates green", gate0),
    ("gate1", "Gate 1 — Phase 0 at zero (epic DoD 1)", gate1),
    ("gate2", "Gate 2 — flagships proven (epic DoD 2)", gate2),
    ("gate3", "Gate 3 — verifier moat held by CI (epic DoD 3)", gate3),
    ("gate4", "Gate 4 — install is one command (epic DoD 4)", gate4),
    ("gate5", "Gate 5 — runtime re-pinned, chaining exercised (epic DoD 5)", gate5),
    ("gate6", "Gate 6 — mechanization merged and used (epic DoD 6)", gate6),
)


def format_check(check):
    name, status, detail = check
    if status == SKIP:
        return f"SKIP({detail})  {name}"
    return f"{status}  {name}: {detail}"


def run_gates(ctx):
    """Every gate in checklist order -> [(gate_id, title, checks)]."""
    return [(gid, title, fn(ctx)) for gid, title, fn in GATES]


def summarize(results):
    counts = {status.lower(): 0 for status in STATUSES}
    for _, _, checks in results:
        for _, status, _ in checks:
            counts[status.lower()] += 1
    return counts


EXIT_INCOMPLETE = 3


def exit_code(counts):
    """1 on any FAIL; else 3 when a SKIP stands (the run proved less than the release
    needs, so a gate reading only the code cannot cut on it); else 0."""
    if counts["fail"]:
        return 1
    if counts["skip"]:
        return EXIT_INCOMPLETE
    return 0


def to_json(ctx, results, counts):
    return {
        "repo": str(ctx.repo),
        "head": git_head(ctx),
        "fast": ctx.fast,
        "skip_github": ctx.skip_github,
        "gates": [{"gate": gid, "title": title,
                   "checks": [{"name": n, "status": s, "detail": d} for n, s, d in checks]}
                  for gid, title, checks in results],
        "summary": counts,
        "exit": exit_code(counts),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="release_check.py",
        description="Run docs/release-1.0-checklist.md as commands: one PASS / FAIL / "
                    "SKIP(<reason>) line per check, then a summary.",
        epilog="exit 0: every check PASS · 1: any FAIL · 2: could not run · "
               "3: incomplete (at least one SKIP). A SKIP never counts as a PASS; "
               "the summary counts it.")
    parser.add_argument("--repo", default=str(DEFAULT_REPO),
                        help="the checkout to gate (default: the repo this script lives in)")
    parser.add_argument("--fast", action="store_true",
                        help="skip the full unittest suite (about an hour); it reports SKIP(--fast)")
    parser.add_argument("--skip-github", action="store_true",
                        help="skip the gh-backed checks; they report SKIP(--skip-github)")
    parser.add_argument("--json", action="store_true",
                        help="print one JSON object instead of lines")
    args = parser.parse_args(argv)

    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"release_check.py: --repo {args.repo}: not a directory", file=sys.stderr)
        return 2
    text_mode = not args.json
    if text_mode and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    def stream(check):
        if text_mode:
            print("  " + format_check(check), flush=True)

    ctx = Context(repo, fast=args.fast, skip_github=args.skip_github, on_check=stream)
    results = []
    try:
        if text_mode:
            print(f"release check: {ctx.repo} @ {git_head(ctx) or 'HEAD unknown'}", flush=True)
        for gid, title, fn in GATES:
            if text_mode:
                print(f"\n{title}", flush=True)
            results.append((gid, title, fn(ctx)))
    except Exception:  # a gate raised: not a verdict, a broken run
        traceback.print_exc()
        print("release_check.py: could not run (a gate raised; see the traceback)",
              file=sys.stderr)
        return 2
    counts = summarize(results)
    code = exit_code(counts)
    if args.json:
        print(json.dumps(to_json(ctx, results, counts), indent=2))
    else:
        print(f"\nsummary: {counts['pass']} PASS, {counts['fail']} FAIL, {counts['skip']} SKIP, "
              f"{counts['info']} INFO -> exit {code}")
        skipped = [n for _, _, checks in results for n, s, _ in checks if s == SKIP]
        if skipped:
            print("skipped, so not a full run: " + ", ".join(skipped))
    return code


if __name__ == "__main__":
    sys.exit(main())
