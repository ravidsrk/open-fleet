#!/usr/bin/env python3
"""hint_replay.py — replay a FIXED corpus to measure episodic hints before memory grows (#605).

Each corpus scenario is a synthetic multi-commit git repository (renames, deletions, branches,
uncommitted edits), a git-committed run archive of manifests pointing at those commits (some
tampered after commit), a query, optional current evidence, and the expected verdict for every
hint. The replay builds each scenario in a temp dir and runs three arms:

    off        no hint at all                         (the baseline a hint must beat)
    unchecked  hints on, provenance checks off         (--hint-mode historical, no --repo)
    checked    hints on, provenance checks on          (current mode against the live repo)

and reports, per arm: correct retrieval (useful/unknown/benign notes reach the reader with their
text), stale suppression (STALE/SUPERSEDED notes kept out), stale leakage, poisoned-note
propagation, and -- for the checked arm -- label accuracy. ``--check`` fails unless the checked
arm is perfect on the corpus AND the unchecked arm leaks (a corpus the unchecked arm passes
cannot tell the checks from their absence).

The effect on REPEATED TASK FAILURES needs a worker: ``--live`` runs every scenario that carries
a ``live_task`` through an agent command per arm and attempt, then the scenario's oracle, and
counts attempts that fail with the recorded pitfall. It never runs unless asked, refuses more runs
than ``--max-runs``, and labels its report with the tier the operator declared -- a stub agent is
tier ``stub``, never ``live``.

A ``live`` tier runs only inside the container-based live harness (PR #668;
scripts/live_container.py): anywhere else ``--live --tier live`` is refused, before the corpus is
read or anything reserved (runtime/scripts/containment.py). What follows is that tier.

A ``live`` tier spends model budget, under the spend guard #606's runner uses
(scripts/_ablation_run.py, whose ledger it shares). It is refused without a declared model, an
explicit finite cap (``--budget-usd``), a per-call reservation (``--per-call-usd``, the worst case
one call is held to), the flag that hands each call its own limit at a fraction of that
reservation (``--agent-limit-flag``, Claude's ``--max-budget-usd``), and ``--out``. The guard is
PRE-EMPTIVE: a call starts only if the spend so far plus its reservation fits in the cap. Each
call's whole output is saved beside the results and its ``total_cost_usd`` (Claude
``--output-format json`` or ``stream-json``) charged; an unmeasured call is charged its full
reservation (a killed one at least that), and a finished call that reports no cost, or a measured
call above its reservation, stops the run.
Every call is entered in an fsynced ledger beside ``--out`` at its full reservation before it
starts and settled after, so a call the runner never settled (a SIGKILL) stays charged, and a
later run into the same ``--out`` counts it against its own cap. No call outlives the runner: each
leads its own process group, killed whole on timeout, after its leader exits, on SIGTERM/SIGHUP/
Ctrl-C, and -- through a watchdog leader -- when the runner itself is SIGKILLed. Every process of a
call carries a unique OF_CALL_ID marker in its environment, so one that leaves the group (setsid)
is swept too, and a call is never settled while anything of it survives. A process that
re-executes itself with an emptied environment after leaving the call's tree is not found: run
the worker in a disposable sandbox.

    python3 scripts/hint_replay.py --check                  # fixture tier, deterministic, free
    # refused while the live tier is disabled (PR #668):
    python3 scripts/hint_replay.py --live --tier live --model sonnet \\
        --agent-cmd 'claude -p --model sonnet --output-format json --permission-mode acceptEdits' \\
        --budget-usd 40 --per-call-usd 2 --agent-limit-flag=--max-budget-usd \\
        --max-runs 18 --attempts 3 --out hint-replay-605-live/results.json

Exit: 0 ok · 1 --check failed / live run failed or stopped · 2 usage, refusal or corpus error ·
128+N interrupted by signal N (results and ledger written first).
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
import contextlib
import copy
import hashlib
import importlib.util
import json
import math
import os
import re
import secrets
import shlex
import signal
import subprocess
import tempfile
import threading
import time
from decimal import ROUND_FLOOR, Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Loaded by path, registered under its name as an import would: runtime/scripts never goes on
# sys.path, where a file there named like a stdlib module — or like one the stdlib only probes
# for, as `subprocess` probes `msvcrt` — would answer the import (W3-01).
_ss_spec = importlib.util.spec_from_file_location("search_sessions",
                                                  ROOT / "runtime" / "scripts" / "search_sessions.py")
search_sessions = importlib.util.module_from_spec(_ss_spec)
sys.modules["search_sessions"] = search_sessions
_ss_spec.loader.exec_module(search_sessions)


def _load_spend_guard():
    """#606's runner, loaded by path as ablation.py loads it: its SpendLedger, process-group
    killer and durable writer are the repo's spend conventions, so they are shared, not copied."""
    spec = importlib.util.spec_from_file_location("of_hint_replay_spend", ROOT / "scripts" / "_ablation_run.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


spend = _load_spend_guard()
hp = search_sessions.hp  # the provenance module the hint itself uses (mutation tests patch it)
DEFAULT_CORPUS = ROOT / "tests" / "fixtures" / "hint-replay.json"
ARMS = ("off", "unchecked", "checked")
CLASSES = ("useful", "unknown", "stale", "poison", "benign")
# A scenario id names each live call's artifact directory, so it is one safe filename (#657 review K5).
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
EXIT_OK, EXIT_FAILED, EXIT_USAGE = 0, 1, 2
FIXED_EPOCH = 1767225600  # 2026-01-01T00:00:00Z: commit dates are part of the fixture
LIVE_SCHEMA = "hint-replay-live/v2"  # v2: spend guard, per-call cost, ledger, stop reason (#605)
# A call is handed its own limit at this fraction of its reservation: Claude's --max-budget-usd
# stops a run once its estimated spend reaches the amount and can pass it, so the limit sits below
# the reservation (#606's registered harness_limit_fraction).
LIMIT_FRACTION = 0.8
DEFAULT_LIMIT_FLAG = "--max-budget-usd"
ORACLE_TIMEOUT_S = 300
LIVE_EVIDENCE = "live-unreviewed: becomes evidence only once bound into a run report under docs/runs/"
STUB_EVIDENCE = "NOT EVIDENCE: a stub worker exercises the pipeline only; no model ran"


class CorpusError(Exception):
    """The corpus or a scenario is malformed: exit 2, nothing measured."""


def fixture_env():
    """A git environment that ignores the operator's config (no signing, no hooks, no identity)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
                "GIT_TERMINAL_PROMPT": "0"})
    return env


def _git(cwd, *args, when=None):
    env = fixture_env()
    if when is not None:
        stamp = f"@{FIXED_EPOCH + when * 3600} +0000"
        env.update({"GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp})
    proc = subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
                          cwd=cwd, env=env, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise CorpusError(f"git {' '.join(args)} failed in {cwd}: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _safe_relpath(rel, what, root=None, *, single=False):
    """Validate a corpus relative path against absolute paths, traversal (`..`), `.git`
    components, and escaping `root`."""
    if not isinstance(rel, str) or not rel or "\0" in rel:
        raise CorpusError(f"{what}: path {rel!r} must be a non-empty relative path")
    if os.path.isabs(rel) or rel.startswith(("/", "\\")) or "\\" in rel:
        raise CorpusError(f"{what}: path {rel!r} must be relative (no absolute or backslash paths)")
    parts = Path(rel).parts
    if not parts or any(part in ("", ".", "..") or part.lower() == ".git" for part in parts):
        raise CorpusError(f"{what}: path {rel!r} escapes or targets .git internals")
    if single and (len(parts) != 1 or "/" in rel):
        raise CorpusError(f"{what}: {rel!r} must be a single safe directory name")
    if root is None:
        return Path(rel)
    base = Path(root).resolve()
    target = (base / rel).resolve()
    if not target.is_relative_to(base) or target == base:
        raise CorpusError(f"{what}: path {rel!r} resolves outside {base}")
    if any(part.lower() == ".git" for part in target.relative_to(base).parts):
        raise CorpusError(f"{what}: path {rel!r} resolves into .git internals")
    return target


def _write(root, files):
    if not isinstance(files, dict):
        raise CorpusError("files map must be an object")
    for rel, content in files.items():
        target = _safe_relpath(rel, "files", root=root)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def _resolve_refs(value, shas):
    """Replace "@<commit name>" strings with that commit's sha, recursively."""
    if isinstance(value, str) and value.startswith("@") and value[1:] in shas:
        return shas[value[1:]]
    if isinstance(value, list):
        return [_resolve_refs(v, shas) for v in value]
    if isinstance(value, dict):
        return {k: _resolve_refs(v, shas) for k, v in value.items()}
    return value


def build_repo(scenario, repo):
    """The live source: commits in order (each on its branch), then the live checkout, then any
    uncommitted working-tree edits. Returns {commit name: sha}."""
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    shas, known, current = {}, {"main"}, "main"

    def ref(name, what):
        # `checkout` takes these in option position (W2-04): `live: "--detach"` detached HEAD where
        # the scenario named a ref. An option is never a ref name.
        if not isinstance(name, str) or not name or name.startswith("-"):
            raise CorpusError(f"{scenario['id']}: {what} {name!r} must name a git ref, not an option")
        return name
    for i, commit in enumerate(scenario["commits"]):
        branch = ref(commit.get("branch", "main"), "branch")
        if branch not in known:
            start = scenario.get("branches", {}).get(branch)
            if start not in shas:
                raise CorpusError(f"{scenario['id']}: branch {branch} starts at unknown commit {start}")
            _git(repo, "checkout", "-q", "-b", branch, shas[start])
            known.add(branch)
        elif branch != current:
            _git(repo, "checkout", "-q", branch)
        current = branch
        _write(repo, commit.get("files", {}))
        renames = commit.get("rename", {})
        if not isinstance(renames, dict):
            raise CorpusError(f"{scenario['id']}: rename must be an object")
        for old, new in renames.items():
            _safe_relpath(old, f"{scenario['id']}: rename", root=repo)
            new_target = _safe_relpath(new, f"{scenario['id']}: rename", root=repo)
            new_target.parent.mkdir(parents=True, exist_ok=True)
            _git(repo, "mv", "--", old, new)
        deletes = commit.get("delete", [])
        if not isinstance(deletes, list):
            raise CorpusError(f"{scenario['id']}: delete must be a list")
        for gone in deletes:
            _safe_relpath(gone, f"{scenario['id']}: delete", root=repo)
            _git(repo, "rm", "-q", "--", gone)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "--allow-empty", "-m", commit["name"], when=i)
        shas[commit["name"]] = _git(repo, "rev-parse", "HEAD")
    live = ref(scenario.get("live", "main"), "live")
    _git(repo, "checkout", "-q", shas.get(live, live))
    _write(repo, scenario.get("worktree_edits", {}))
    return shas


def build_archive(scenario, archive, shas):
    """The run archive (archive/docs/runs/<run>/...), committed to its own git repo, then any
    post-commit tampering: an evidence file rewritten, or the manifest itself edited."""
    runs_dir = archive / "docs" / "runs"
    runs_dir.mkdir(parents=True)
    _git(archive, "init", "-q", "-b", "main")
    tamper = []
    for run in scenario["runs"]:
        run_dir = _safe_relpath(run.get("run"), f"{scenario['id']}: run", root=runs_dir, single=True)
        run_dir.mkdir(parents=True, exist_ok=True)
        manifest = _resolve_refs(copy.deepcopy(run["manifest"]), shas)
        recorded = []
        artifacts = run.get("artifacts", {})
        if not isinstance(artifacts, dict):
            raise CorpusError(f"{scenario['id']}: artifacts must be an object")
        for name, content in artifacts.items():
            art = _safe_relpath(name, f"{scenario['id']}: artifacts", root=run_dir)
            art.parent.mkdir(parents=True, exist_ok=True)
            art.write_text(content, encoding="utf-8")
            recorded.append({"path": f"docs/runs/{run['run']}/{name}",
                             "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()})
        if recorded:
            manifest["artifacts"] = recorded
        path = _safe_relpath(run.get("file", "manifest.json"), f"{scenario['id']}: file", root=run_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        tamper.append((run, run_dir, path, manifest))
    _git(archive, "add", "-A")
    _git(archive, "commit", "-q", "-m", "archive", when=0)
    for run, run_dir, path, manifest in tamper:
        tamper_arts = run.get("tamper_artifacts", {})
        if not isinstance(tamper_arts, dict):
            raise CorpusError(f"{scenario['id']}: tamper_artifacts must be an object")
        for name, content in tamper_arts.items():
            tart = _safe_relpath(name, f"{scenario['id']}: tamper_artifacts", root=run_dir)
            tart.parent.mkdir(parents=True, exist_ok=True)
            tart.write_text(content, encoding="utf-8")
        if run.get("tamper_manifest"):
            manifest.update(run["tamper_manifest"])
            path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return runs_dir


def _arm_selection(arm, scenario, runs_dir, repo):
    if arm == "off":
        return {"lines": [], "entries": []}
    if arm == "unchecked":
        return search_sessions.build_episodic_selection(scenario["query"], runs_dir=str(runs_dir),
                                                        mode="historical")
    return search_sessions.build_episodic_selection(
        scenario["query"], runs_dir=str(runs_dir), live=str(repo), mode="current",
        current_evidence=scenario.get("current_evidence"))


def _observe(selection, key, expect):
    run, unit = key.split("/", 1)
    entry = next((e for e in selection["entries"] if e["run"] == run and e["unit"] == unit), None)
    text = "\n".join(selection["lines"])
    line = next((ln for ln in selection["lines"] if f"[run {run} / {unit} (" in ln), "")
    return {"found": entry is not None, "shown": bool(entry and entry["shown"]),
            "text_shown": expect["marker"] in text, "currency": entry and entry["currency"],
            "reasons": entry["reasons"] if entry else [], "line": line}


def evaluate(scenario, observed):
    """Problems (strings) for one scenario's checked/unchecked observations against its expect."""
    problems = []
    for key, expect in scenario["expect"].items():
        got = observed["checked"][key]
        cls = expect["class"]
        where = f"{scenario['id']}:{key}"
        if got["currency"] != expect["currency"]:
            problems.append(f"{where}: currency {got['currency']} != expected {expect['currency']}")
        prefix = expect.get("reason")
        if prefix and not any(r.startswith(prefix) for r in got["reasons"]):
            problems.append(f"{where}: no reason starting {prefix!r} in {got['reasons']}")
        if prefix is None and got["reasons"]:
            problems.append(f"{where}: expected no reason, got {got['reasons']}")
        if cls in ("useful", "unknown", "benign") and not got["text_shown"]:
            problems.append(f"{where}: {cls} note not retrieved with its text")
        if cls == "stale" and got["shown"]:
            problems.append(f"{where}: stale note shown in the checked arm")
        if cls == "poison" and got["text_shown"]:
            problems.append(f"{where}: poisoned note text propagated")
        forbid = expect.get("forbid_in_line")
        if forbid and re.search(forbid, got["line"]):
            problems.append(f"{where}: entry line matches forbidden {forbid!r}")
    return problems


def _metrics(rows, arm):
    def ratio(hit, total):
        return round(hit / total, 4) if total else None
    want = [r for r in rows if r["class"] in ("useful", "unknown", "benign")]
    stale = [r for r in rows if r["class"] == "stale"]
    poison = [r for r in rows if r["class"] == "poison"]
    out = {
        "retrieval": ratio(sum(r[arm]["text_shown"] for r in want), len(want)),
        "stale_suppression": ratio(sum(not r[arm]["shown"] for r in stale), len(stale)),
        "stale_leakage": sum(r[arm]["shown"] for r in stale),
        "poison_propagated": sum(r[arm]["text_shown"] for r in poison),
    }
    if arm == "checked":
        out["label_accuracy"] = ratio(sum(r["label_ok"] for r in rows), len(rows))
    return out


def load_corpus(path):
    try:
        raw = Path(path).read_bytes()
        corpus = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CorpusError(f"cannot read corpus {path}: {exc}") from exc
    scenarios = corpus.get("scenarios") if isinstance(corpus, dict) else None
    if not isinstance(scenarios, list) or not scenarios:
        raise CorpusError("corpus needs a non-empty scenarios list")
    ids = set()
    for scn in scenarios:
        if isinstance(scn, dict) and scn.get("id") and not (isinstance(scn["id"], str) and SAFE_ID.fullmatch(scn["id"])):
            raise CorpusError(f"scenario id {scn['id']!r:.80} is not one safe filename (letters, digits, '.', '_' "
                              "and '-', a letter or digit first): it names each live call's artifact directory")
        if not isinstance(scn, dict) or not scn.get("id") or scn["id"] in ids:
            raise CorpusError(f"scenario without a unique id: {scn!r:.80}")
        ids.add(scn["id"])
        for key in ("commits", "runs", "query", "expect"):
            if not scn.get(key):
                raise CorpusError(f"{scn['id']}: missing {key}")
        for key, expect in scn["expect"].items():
            if "/" not in key or expect.get("class") not in CLASSES or not expect.get("marker"):
                raise CorpusError(f"{scn['id']}: expect {key} needs run/unit, a class and a marker")
        sid = scn["id"]
        if not isinstance(scn["commits"], list):
            raise CorpusError(f"{sid}: commits must be a list")
        for i, commit in enumerate(scn["commits"]):
            if not isinstance(commit, dict):
                raise CorpusError(f"{sid}: commits[{i}] must be an object")
            files = commit.get("files", {})
            if not isinstance(files, dict):
                raise CorpusError(f"{sid}: commits[{i}].files must be an object")
            for rel in files:
                _safe_relpath(rel, f"{sid}: commits[{i}].files")
            renames = commit.get("rename", {})
            if not isinstance(renames, dict):
                raise CorpusError(f"{sid}: commits[{i}].rename must be an object")
            for old, new in renames.items():
                _safe_relpath(old, f"{sid}: commits[{i}].rename")
                _safe_relpath(new, f"{sid}: commits[{i}].rename")
            deletes = commit.get("delete", [])
            if not isinstance(deletes, list):
                raise CorpusError(f"{sid}: commits[{i}].delete must be a list")
            for gone in deletes:
                _safe_relpath(gone, f"{sid}: commits[{i}].delete")
        edits = scn.get("worktree_edits", {})
        if not isinstance(edits, dict):
            raise CorpusError(f"{sid}: worktree_edits must be an object")
        for rel in edits:
            _safe_relpath(rel, f"{sid}: worktree_edits")
        if not isinstance(scn["runs"], list):
            raise CorpusError(f"{sid}: runs must be a list")
        for i, run in enumerate(scn["runs"]):
            if not isinstance(run, dict):
                raise CorpusError(f"{sid}: runs[{i}] must be an object")
            _safe_relpath(run.get("run"), f"{sid}: runs[{i}].run", single=True)
            _safe_relpath(run.get("file", "manifest.json"), f"{sid}: runs[{i}].file")
            for field in ("artifacts", "tamper_artifacts"):
                mapping = run.get(field, {})
                if not isinstance(mapping, dict):
                    raise CorpusError(f"{sid}: runs[{i}].{field} must be an object")
                for rel in mapping:
                    _safe_relpath(rel, f"{sid}: runs[{i}].{field}")
    return corpus, hashlib.sha256(raw).hexdigest()


def replay(corpus_path=DEFAULT_CORPUS, only=None, arms=ARMS):
    """Run the deterministic arms over the corpus. Returns the fixture-tier report. ``arms`` must
    include "checked" (the expectations are about it); a mutation control needs nothing else."""
    if "checked" not in arms:
        raise CorpusError("the checked arm is the one the corpus expectations describe")
    corpus, digest = load_corpus(corpus_path)
    rows, problems, per_scenario = [], [], []
    for scenario in corpus["scenarios"]:
        if only and scenario["id"] not in only:
            continue
        with tempfile.TemporaryDirectory(prefix="hint-replay-") as tmp:
            shas = build_repo(scenario, Path(tmp) / "repo")
            runs_dir = build_archive(scenario, Path(tmp) / "archive", shas)
            observed = {arm: {} for arm in arms}
            for arm in arms:
                selection = _arm_selection(arm, scenario, runs_dir, Path(tmp) / "repo")
                for key, expect in scenario["expect"].items():
                    observed[arm][key] = _observe(selection, key, expect)
        found = evaluate(scenario, observed)
        problems.extend(found)
        for key, expect in scenario["expect"].items():
            label_ok = not any(p.startswith(f"{scenario['id']}:{key}: currency")
                               or p.startswith(f"{scenario['id']}:{key}: no reason")
                               or p.startswith(f"{scenario['id']}:{key}: expected no reason") for p in found)
            rows.append({"key": f"{scenario['id']}:{key}", "class": expect["class"], "label_ok": label_ok,
                         **{arm: observed[arm][key] for arm in arms}})
        per_scenario.append({"id": scenario["id"], "problems": found,
                             "checked": {k: {"currency": v["currency"], "reasons": v["reasons"],
                                             "shown": v["shown"], "text_shown": v["text_shown"]}
                                         for k, v in observed["checked"].items()}})
    return {"schema": "hint-replay/v1", "tier": "fixture",
            "corpus": {"path": str(corpus_path), "sha256": digest},
            "scenarios": len(per_scenario), "hints": len(rows),
            "arms": {arm: _metrics(rows, arm) for arm in arms},
            "per_scenario": per_scenario, "problems": problems}


def check(report):
    """The --check gate: the checked arm is perfect and the unchecked arm is not (the corpus binds)."""
    failures = list(report["problems"])
    checked, unchecked = report["arms"]["checked"], report["arms"]["unchecked"]
    if checked["label_accuracy"] != 1.0:
        failures.append(f"checked label accuracy {checked['label_accuracy']} < 1.0")
    if checked["retrieval"] != 1.0 or checked["stale_suppression"] != 1.0:
        failures.append(f"checked retrieval {checked['retrieval']} / suppression {checked['stale_suppression']} < 1.0")
    if checked["stale_leakage"] or checked["poison_propagated"]:
        failures.append("checked arm leaked a stale or poisoned note")
    if not unchecked["stale_leakage"] or not unchecked["poison_propagated"]:
        failures.append("the unchecked arm leaks nothing: the corpus cannot tell the checks from their absence")
    return failures


# --- live arm: repeated task failures with hints on/off (needs a worker; REMAINING by default) ----

def _usd(value):
    """A cost a result can report: a finite, non-negative number (never a bool)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        return None
    return float(value)


def reported_cost(text):
    """(USD or None, models) from what a Claude worker printed. `--output-format json` prints one
    result object (a list of messages under --verbose); stream-json prints one object per line,
    ending in a result line. Every result must carry a valid total_cost_usd, and several are
    summed (over-counting is safe, under-counting is not). No result, or one without a cost, is
    UNMEASURED (None): the caller charges it its full reservation."""
    try:
        whole = json.loads(text)
    except ValueError:
        whole = None
    if isinstance(whole, (dict, list)):
        objs = whole if isinstance(whole, list) else [whole]
    else:
        objs = []
        for line in text.splitlines():
            with contextlib.suppress(ValueError):
                objs.append(json.loads(line))
    objs = [o for o in objs if isinstance(o, dict)]
    models = set()
    for obj in objs:
        if obj.get("type") == "system" and obj.get("subtype") == "init" and isinstance(obj.get("model"), str):
            models.add(obj["model"])
        if obj.get("type") == "result" and isinstance(obj.get("modelUsage"), dict):
            models.update(k for k in obj["modelUsage"] if isinstance(k, str))
    costs = [_usd(obj.get("total_cost_usd")) for obj in objs if obj.get("type") == "result"]
    cost = round(sum(costs), 6) if costs and None not in costs else None
    return cost, sorted(models)


def call_limit(reserve):
    """The limit handed to a call: LIMIT_FRACTION of its reservation, floored to the cent, so it is
    never above the reservation (rounding could lift it there below USD 0.025) (#657 review K1)."""
    return float((Decimal(str(reserve)) * Decimal(str(LIMIT_FRACTION))).quantize(
        Decimal("0.01"), rounding=ROUND_FLOOR))


def limit_error(per_call):
    """Why a `per_call` reservation cannot hand its call a usable limit, or None. A limit of USD 0.00
    used to drop the flag, so the worker ran with no limit at all (#657 review K1)."""
    limit = call_limit(per_call)
    if 0 < limit <= per_call:
        return None
    return (f"--per-call-usd {per_call:g} leaves a per-call limit of USD {limit:.2f}: every call needs "
            f"a positive limit within its reservation, so reserve at least USD {0.01 / LIMIT_FRACTION:g}")


def call_charge(cost, killed, reserve, tier):
    """_ablation_run.agent_charge: measured where there is a measure; a killed or unmeasured live
    call is charged its whole reservation (a killed one at least that, whatever it reported)."""
    if tier != "live":
        return cost or 0.0
    if killed:
        return max(reserve, cost or 0.0)
    return cost if cost is not None else reserve


def stop_reason(row, reserve, tier, spent):
    """Why no further call may start after `row`, or None. A killed call is charged its whole
    reservation and the run goes on: its spend is held by the same per-call limit as any call's."""
    call, cost = row["call"], row["cost_usd"]
    if row["orphans"]:
        return (f"ORPHAN_ALIVE at {call}: a process of the call survived SIGKILL, or the process table "
                "could not be read; it stays open at its full reservation and no further call may start")
    if tier == "live" and cost is not None and cost > reserve:
        return (f"LIMIT_BREACHED at {call}: it cost USD {cost} against its USD {reserve:.2f} "
                "reservation, so the per-call limit did not hold and the cap can no longer be guaranteed")
    if tier == "live" and cost is None and not row["agent_killed"]:
        return (f"USAGE_UNAVAILABLE at {call}: charged its full USD {reserve:.2f} reservation; the "
                f"worker printed no total_cost_usd ({row['output']['stdout']})")
    if tier != "live" and spent > 0:
        # Not a spend guard: a stub reporting cost broke its tier's contract.
        return f"SPEND_IN_NON_LIVE_TIER at {call}: USD {spent:.2f} reported"
    return None


def _terminated(signum, _frame):
    """SIGTERM/SIGHUP/SIGINT unwind the run loop, so its `finally` kills every live group."""
    raise SystemExit(128 + signum)


def _call_dir(calls_dir, call):
    """`calls_dir / call`, refused unless it resolves to a directory directly under `calls_dir`: a
    scenario id must never steer a packet or a worker's output elsewhere (#657 review K5)."""
    target = calls_dir / call
    if target.resolve().parent != calls_dir.resolve():
        raise CorpusError(f"live call {call!r} would write outside {calls_dir}")
    return target


def _live_call(ctx, scenario, arm, attempt, call):
    """One agent call under the guard, then the oracle. Its packet, output and the oracle's are
    kept under the run's calls directory, beside the results."""
    task, ledger, reserve = scenario["live_task"], ctx["ledger"], ctx["reserve"]
    call_dir = _call_dir(ctx["calls_dir"], call)
    call_dir.mkdir(parents=True)
    paths = {"packet": call_dir / "packet.md", "stdout": call_dir / "agent.stdout",
             "stderr": call_dir / "agent.stderr", "oracle": call_dir / "oracle.txt"}
    with tempfile.TemporaryDirectory(prefix="hint-replay-live-") as tmp:
        repo = Path(tmp) / "repo"
        shas = build_repo(scenario, repo)
        runs_dir = build_archive(scenario, Path(tmp) / "archive", shas)
        hint = _arm_selection(arm, scenario, runs_dir, repo)["lines"]
        packet = task["prompt"] + ("\n\n" + "\n".join(hint) if hint else "") + "\n"
        packet_path = Path(tmp) / "PACKET.md"
        packet_path.write_text(packet, encoding="utf-8")
        paths["packet"].write_text(packet, encoding="utf-8")
        env = dict(ctx["env"], HINT_REPLAY_PACKET=str(packet_path))
        ledger.start(call, "agent", reserve)  # on disk at its full reservation BEFORE the call starts
        code, killed, emptied = spend.contained_run(ctx["argv"], cwd=repo, env=env, timeout=ctx["timeout"],
                                                    stdin_path=packet_path, stdout_path=paths["stdout"],
                                                    stderr_path=paths["stderr"])
        cost, models = reported_cost(paths["stdout"].read_text(encoding="utf-8", errors="replace"))
        if emptied:
            ledger.settle(call, "agent", call_charge(cost, killed, reserve, ctx["tier"]), cost, killed)
            oracle_home = Path(tmp) / "oracle-home"
            (oracle_home / "tmp").mkdir(parents=True)
            oracle_env = {
                "PATH": os.pathsep.join([os.path.dirname(sys.executable), "/usr/bin", "/bin"]),
                "HOME": str(oracle_home),
                "TMPDIR": str(oracle_home / "tmp"),
                "LANG": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            oracle_code, oracle_killed, oracle_emptied = spend.contained_run(
                task["oracle"], cwd=repo, env=oracle_env, timeout=ORACLE_TIMEOUT_S, stdout_path=paths["oracle"])
            output = paths["oracle"].read_text(encoding="utf-8", errors="replace")
        else:  # something of the call survived: it stays open at its full reservation, and stops here (K4)
            oracle_code, oracle_killed, oracle_emptied, output = None, False, True, ""
    oracle_exit = "timeout" if oracle_killed else oracle_code
    return {"scenario": scenario["id"], "arm": arm, "attempt": attempt, "call": call,
            "agent_exit": "timeout" if killed else code, "agent_killed": killed,
            "oracle_exit": oracle_exit,
            "repeated_failure": oracle_exit != 0 and bool(re.search(task["pitfall"], output)),
            "reserve_usd": reserve, "cost_usd": cost, "measured": cost is not None,
            "charged_usd": ledger.total(ledger.run, call), "settled": emptied, "models": models,
            "orphans": not (emptied and oracle_emptied),
            "output": {k: os.path.relpath(v, ctx["out"].parent) for k, v in paths.items()}}


def _interrupted_row(active, ledger, code):
    """The call a signal cut short, kept in the results with what the ledger charged it."""
    scenario_id, arm, attempt, call = active
    calls = {key[2]: value for key, value in ledger.calls(ledger.run, call).items()}
    settle = next((r for r in reversed(ledger.records) if r["run"] == ledger.run and r["cell"] == call
                   and r["event"] == "settle"), None)
    cost = settle.get("measured_usd") if settle else None
    return {"scenario": scenario_id, "arm": arm, "attempt": attempt, "call": call, "interrupted": True,
            "agent_exit": None, "oracle_exit": None, "repeated_failure": False,
            "cost_usd": cost, "measured": cost is not None,
            "open_calls": sorted(c for c, (_charged, settled) in calls.items() if not settled),
            "charged_usd": ledger.total(ledger.run, call),
            "errors": [f"interrupted (exit {code}) mid-call: a call it started is charged, an "
                       "unsettled one at its full reservation"]}


def live_replay(corpus_path, agent_argv, tier, attempts, max_runs, model=None, budget_usd=None,
                timeout_s=900, only=None, per_call_usd=None, limit_flag=DEFAULT_LIMIT_FLAG, out=None):
    """Per live_task scenario x arm x attempt: fresh fixture, packet (task + hint for the arm),
    agent call under the spend guard, then the oracle. A repeated failure is an oracle failure
    matching the pitfall. The results go to `out` (default: a new temp dir) durably, also when a
    signal cuts the run short, and then SystemExit(128+N) follows. Callers run preflight_live()."""
    corpus, digest = load_corpus(corpus_path)
    tasks = [s for s in corpus["scenarios"] if s.get("live_task") and (not only or s["id"] in only)]
    if not tasks:
        raise CorpusError("no scenario carries a live_task")
    planned = len(tasks) * len(ARMS) * attempts
    if planned > max_runs:
        raise CorpusError(f"{planned} agent runs planned, --max-runs allows {max_runs}")
    live = tier == "live"
    limit = call_limit(per_call_usd) if per_call_usd is not None and limit_flag else None
    why = limit_error(per_call_usd) if limit is not None else None
    if why or (live and limit is None):  # a live call never starts without a positive limit (K1)
        raise CorpusError(why or "a live run hands every call its own per-call limit: it needs "
                          "--per-call-usd and --agent-limit-flag")
    unseen = spend.containment_problem() if live else None
    if unseen:  # a paid call is never started where its escaped processes could not be found (W1)
        raise CorpusError(f"process discovery cannot contain a call on this host ({unseen}): a live "
                          "run does not start")
    # Nothing is written before this line; everything below is recorded.
    out = Path(out).resolve() if out else Path(tempfile.mkdtemp(prefix="hint-replay-live-")) / "results.json"
    # Unique per invocation (two runs in one second and one process stay apart in the ledger).
    run_id = f"{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}-{os.getpid()}-{secrets.token_hex(4)}"
    calls_dir = out.parent / f"{out.stem}.calls" / run_id
    for scenario in tasks:  # every call's directory sits under the run's, checked before any write (K5)
        for arm in ARMS:
            for attempt in range(1, attempts + 1):
                _call_dir(calls_dir, f"{scenario['id']}.{arm}.a{attempt}")
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        ledger = spend.SpendLedger(out.parent / f"{out.stem}.spend.jsonl", run_id)
    except spend.Refused as exc:  # unreadable, or held by a concurrent run on the same cap (#657 K2)
        raise CorpusError(str(exc)) from exc
    try:
        return _live_holding(ledger, out, run_id, tasks, digest, planned, corpus_path, agent_argv, tier,
                             attempts, model, budget_usd, timeout_s, per_call_usd, limit_flag, limit, calls_dir)
    finally:
        ledger.release()


def _live_holding(ledger, out, run_id, tasks, digest, planned, corpus_path, agent_argv, tier, attempts,
                  model, budget_usd, timeout_s, per_call_usd, limit_flag, limit, calls_dir):
    """The live run proper, holding the spend ledger for the whole invocation (#657 review K2)."""
    live = tier == "live"
    prior = float(ledger.total())
    reserve = float(per_call_usd) if live else 0.0  # a stub is never paid: it reserves nothing
    cap = float(budget_usd) if budget_usd is not None else 0.0
    ctx = {"ledger": ledger, "reserve": reserve, "tier": tier, "out": out, "timeout": timeout_s,
           "calls_dir": calls_dir,
           # Every path absolute (the worker's cwd is the fixture), then its own limit.
           "argv": spend.absolute_argv(list(agent_argv)) + ([limit_flag, f"{limit:.2f}"] if limit is not None else []),
           # No login-shell rc file may run (~/.zshenv can reorder PATH): the stub-claude rule.
           "env": dict(os.environ, SHELL="/bin/sh")}
    plan = [(s, arm, k) for s in tasks for arm in ARMS for k in range(1, attempts + 1)]
    results, stopped, interrupted, active = [], None, None, None
    # A signal unwinds the loop like Ctrl-C (first_run.py's pattern, #640): the `finally` kills and
    # reaps every child group still alive before the results are written and the runner exits.
    previous = ({sig: signal.signal(sig, _terminated) for sig in spend.TRAPPED_SIGNALS}
                if threading.current_thread() is threading.main_thread() else {})
    try:
        for scenario, arm, attempt in plan:
            call = f"{scenario['id']}.{arm}.a{attempt}"
            # PRE-EMPTIVE: a call starts only if what the cap has left covers its whole
            # reservation, counting every earlier run into this --out. Nothing after it is the guard.
            counted = ledger.total()
            if counted + reserve > cap:
                stopped = (f"CAP_REACHED: USD {cap - counted:.2f} of the USD {cap:.2f} cap remains, "
                           f"less than the USD {reserve:.2f} reservation of {call}")
                break
            active = (scenario["id"], arm, attempt, call)
            try:
                row = _live_call(ctx, scenario, arm, attempt, call)
            except CorpusError as exc:
                stopped = f"CORPUS_ERROR at {call}: {exc}"
                break
            results.append(row)
            active = None
            stopped = stop_reason(row, reserve, tier, ledger.total(run_id))
            if stopped:
                break
    except SystemExit as stop:
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)  # nothing may cut the record of what was spent short
        interrupted = stop.code if isinstance(stop.code, int) else 1
        if active:
            results.append(_interrupted_row(active, ledger, interrupted))
        stopped = (f"INTERRUPTED (exit {interrupted}): every live child process group was killed "
                   "and reaped before the runner exited")
    finally:
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)  # the run is ending either way: no second unwind
        try:
            spend.stop_all_groups()
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, signal.SIG_DFL if handler is None else handler)
    done = [r for r in results if not r.get("interrupted")]
    arms = {}
    for arm in ARMS:
        mine = [r for r in done if r["arm"] == arm]
        arms[arm] = {"runs": len(mine), "passed": sum(r["oracle_exit"] == 0 for r in mine),
                     "repeated_failures": sum(r["repeated_failure"] for r in mine)}
    report = {"schema": LIVE_SCHEMA, "tier": tier, "evidence": LIVE_EVIDENCE if live else STUB_EVIDENCE,
              "model": model, "budget_usd": budget_usd, "agent": os.path.basename(agent_argv[0]),
              "agent_cmd": ctx["argv"], "planned_runs": planned, "attempts": attempts, "run_id": run_id,
              "corpus": {"path": str(corpus_path), "sha256": digest}, "arms": arms,
              "cost": {"cap_usd": cap, "reserve_per_call_usd": reserve, "limit_flag": limit_flag or None,
                       "limit_usd": limit, "limit_fraction": LIMIT_FRACTION,
                       "worst_case_usd": round(planned * reserve, 6),
                       "spent_usd": float(ledger.total(run_id)), "prior_spent_usd": prior,
                       "counted_against_cap_usd": float(ledger.total()), "ledger": str(ledger.path),
                       "measured_calls": [r["call"] for r in results if r["measured"]],
                       "unmeasured_calls": [r["call"] for r in results if not r["measured"]]},
              "results_path": str(out), "calls_dir": str(ctx["calls_dir"]), "stopped": stopped,
              "complete": stopped is None and len(done) == planned, "results": results}
    spend.write_durably(out, json.dumps(report, indent=2) + "\n")
    if interrupted is not None:
        raise SystemExit(interrupted)
    return report


def preflight_live(args):
    """Every --live refusal, before anything is written or run: a live tier spends real money."""
    if args.tier is None or not args.agent_cmd or args.max_runs is None or args.attempts < 1:
        raise CorpusError("--live needs --tier, --agent-cmd, --max-runs and --attempts >= 1")
    if args.timeout_s <= 0:
        raise CorpusError("--timeout-s must be positive")
    try:
        agent_argv = shlex.split(args.agent_cmd)
    except ValueError as err:
        raise CorpusError(f"the agent command cannot be parsed: {err}") from err
    if not agent_argv:
        raise CorpusError("--agent-cmd must not be empty")
    budget, per_call = args.budget_usd, args.per_call_usd
    if args.tier == "live":
        if not args.model or budget is None or not math.isfinite(budget) or budget <= 0:
            raise CorpusError("a live tier needs a declared --model and a positive --budget-usd: an "
                              "explicit, finite cap")
        problem = spend.terminator_problem(agent_argv)
        if problem:
            raise CorpusError(f"the agent command {problem}")
        wrong = sorted({named for named in spend.model_flags(agent_argv) if named != args.model})
        if wrong:
            raise CorpusError(f"--model {args.model} disagrees with the agent command's --model "
                              f"{', '.join(wrong)}: the results would name a model the call was not asked for")
        fallback = sorted({named for named in spend.model_flags(agent_argv, "--fallback-model")
                           if named != args.model})
        if fallback:
            raise CorpusError(f"the agent command names --fallback-model {', '.join(fallback)}: the call "
                              f"could switch off {args.model} mid-run, and the results name one model")
        if per_call is None or not math.isfinite(per_call) or per_call <= 0:
            raise CorpusError("a live run needs a per-call reservation (--per-call-usd > 0, the worst "
                              "case one call is held to): without one no cap can be enforced before the spend")
        if per_call > budget:
            raise CorpusError(f"--per-call-usd {per_call:g} exceeds the --budget-usd {budget:g} cap: "
                              "no call could ever start")
        if not args.agent_limit_flag:
            raise CorpusError("a live run hands every call its own per-call limit (--agent-limit-flag, "
                              "Claude's --max-budget-usd): without one a call's worst case is unbounded")
        if limit_error(per_call):
            raise CorpusError(limit_error(per_call))
        if not args.out:
            raise CorpusError("a live run needs --out: its spend ledger sits beside the results, so a "
                              "later run into the same --out counts what this one spent")
        return
    for flag, value in (("--budget-usd", budget), ("--per-call-usd", per_call)):
        if value is not None and (not math.isfinite(value) or value < 0):
            raise CorpusError(f"{flag} must be a finite, non-negative number")
    if per_call is not None and args.agent_limit_flag and limit_error(per_call):
        raise CorpusError(limit_error(per_call))


def build_parser():
    p = argparse.ArgumentParser(prog="hint_replay.py", description=__doc__.split("\n")[0])
    p.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    p.add_argument("--scenario", action="append", default=[], help="limit to these scenario ids")
    p.add_argument("--check", action="store_true", help="exit 1 unless the corpus gate holds")
    p.add_argument("--json", action="store_true", help="print the full report")
    p.add_argument("--out", default=None, help="also write the report here; for --live, its spend "
                   "ledger (<stem>.spend.jsonl) and every call's output (<stem>.calls/) sit beside it")
    p.add_argument("--live", action="store_true", help="run the agent arm (spends model budget)")
    p.add_argument("--tier", choices=("stub", "live"), default=None,
                   help="what --agent-cmd IS: a deterministic stub, or a real model worker")
    p.add_argument("--agent-cmd", default=None, help="worker argv (shlex-split, no shell); packet on stdin "
                   "and at $HINT_REPLAY_PACKET; runs with cwd = the fixture repo")
    p.add_argument("--model", default=None)
    p.add_argument("--budget-usd", type=float, default=None,
                   help="the spend cap; REQUIRED for a live tier (counts earlier runs into the same --out)")
    p.add_argument("--per-call-usd", type=float, default=None,
                   help="each call's reservation, its worst case; REQUIRED for a live tier")
    p.add_argument("--agent-limit-flag", default=DEFAULT_LIMIT_FLAG,
                   help=f"the worker's own per-call spend-limit flag, appended to every call at "
                   f"{LIMIT_FRACTION:g} of its reservation (default {DEFAULT_LIMIT_FLAG}; '' = none, "
                   "refused for a live tier)")
    p.add_argument("--max-runs", type=int, default=None)
    p.add_argument("--attempts", type=int, default=1)
    p.add_argument("--timeout-s", type=int, default=900)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    why = spend.live_disabled() if args.live and args.tier == "live" else None
    if why:  # first, before the corpus is read or anything reserved (PR #668: the live tier is off)
        print(f"hint_replay: {why}", file=sys.stderr)
        return EXIT_USAGE
    try:
        if args.live:
            preflight_live(args)
            report = live_replay(args.corpus, shlex.split(args.agent_cmd), args.tier, args.attempts,
                                 args.max_runs, args.model, args.budget_usd, args.timeout_s,
                                 set(args.scenario) or None, per_call_usd=args.per_call_usd,
                                 limit_flag=args.agent_limit_flag, out=args.out)
            failures = [report["stopped"]] if report["stopped"] else []
        else:
            report = replay(args.corpus, set(args.scenario) or None)
            failures = check(report) if args.check else []
    except CorpusError as exc:
        print(f"hint_replay: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.out and not args.live:  # a live run wrote its results durably itself
        Path(args.out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"tier={report['tier']} corpus_sha256={report['corpus']['sha256'][:16]}")
        for arm, metrics in report["arms"].items():
            print(f"{arm}: " + " ".join(f"{k}={v}" for k, v in metrics.items()))
        if args.live:
            cost = report["cost"]
            print(f"cost: spent_usd={cost['spent_usd']} prior_spent_usd={cost['prior_spent_usd']} "
                  f"cap_usd={cost['cap_usd']} measured={len(cost['measured_calls'])} "
                  f"unmeasured={len(cost['unmeasured_calls'])}")
            print(f"results: {report['results_path']}")
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    return EXIT_FAILED if failures else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
