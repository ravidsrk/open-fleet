#!/usr/bin/env python3
"""Contract tests for scripts/wip_curve.py, the pre-registered WIP-curve experiment (#604).

What is pinned here is what a hand-run experiment silently gets wrong: a design changed after the
data came in, a task whose oracle measures nothing, a spend nobody authorised, a run that did not
start from the same state as the others, a report that cannot be recomputed from what was kept, a
metric row edited after the fact, and a CLOSED unit that git or review authority does not back.

No test calls a model. Two tests drive whole runs through the posix provider with the runner's
INERT stand-in (first_run.py's pattern, #596): every subprocess runs with SHELL=/bin/sh and a
tripwire for every harness name first on PATH, and the tripwire log must stay empty.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import io
import importlib.util
import json
import os
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "scripts" / "wip_curve.py"
EVENTS = ROOT / "runtime" / "scripts" / "events.py"
PREREG = ROOT / "docs" / "experiments" / "wip-curve-prereg.json"
TASKSET = ROOT / "docs" / "experiments" / "wip-curve-taskset.json"
_spec = importlib.util.spec_from_file_location("wip_curve_under_test", RUNNER)
wip = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wip)

LEAKY = ("ORCA_CLI_COMMAND", "OPEN_FLEET_CLI_COMMAND", "OPEN_FLEET_RUNTIME", "ORCA_FLEET_RUNTIME",
         "OPEN_FLEET_STATE_DB", "OPEN_FLEET_STATE_DIR", "OPEN_FLEET_SANDBOX_PROFILE", "ORCA_SANDBOX_PROFILE",
         "OPEN_FLEET_PARENT_PROFILE", "ORCA_PARENT_PROFILE", "WORKER_CMD", "CLAUDE_CMD", "CODEX_CMD",
         "ORCA_TERMINAL_HANDLE", "OPEN_FLEET_TERMINAL_HANDLE", "OPEN_FLEET_DENY_HOOK_SETTINGS",
         "ORCA_DENY_HOOK_SETTINGS", "OPEN_FLEET_POSIX_BACKEND", "ORCA_POSIX_BACKEND",
         "OPEN_FLEET_MERGE_QUEUE_DB", "OPEN_FLEET_EVENTS_LOG", "ORCA_EVENTS_LOG")


def bare_run(tmp: Path, cap="10", reservation="0.25", rid="wip1-b1r1-rep1"):
    """A Run with only its spend guard: the shared ledger in `tmp`/results, nothing launched."""
    run = wip.Run.__new__(wip.Run)
    run.rid, run.cap, run.reservation = rid, Decimal(cap), Decimal(reservation)
    run.budget, run.calls, run.held, run.usage_seen, run.units = wip.Budget(tmp / "results"), {}, {}, set(), {}
    run.halt, run.deadline, run.model_pin, run.launched = None, float("inf"), None, {}
    run.dispatch_tags, run.full_hold = {}, {}
    return run


_tables_spec = importlib.util.spec_from_file_location("fixture_containment_tables",
                                                      ROOT / "tests" / "fixtures" / "containment_tables.py")
TABLES = importlib.util.module_from_spec(_tables_spec)  # a process table blind to system binaries (PR #668)
_tables_spec.loader.exec_module(TABLES)

# The live tier's refusal (PR #668: disabled outside the container-based live harness). These
# tests drive the live machinery, so setUpModule lifts it in this process, the Python-level seam the
# host probe uses; TestTheLiveTierIsDisabled puts the real one back, and runs the CLI as its own
# process too.
REAL_LIVE_GATE = wip.contain.live_disabled
DISABLED = "live runs are disabled outside the container-based live harness"
SEAMS: dict = {}


_MQ_PROBE_SPEC = importlib.util.spec_from_file_location(
    "mq_probe_for_wip_curve", ROOT / "runtime" / "scripts" / "merge_queue.py"
)
_MQ_PROBE_MOD = importlib.util.module_from_spec(_MQ_PROBE_SPEC)
_MQ_PROBE_SPEC.loader.exec_module(_MQ_PROBE_MOD)


def setUpModule():
    SEAMS["live"] = mock.patch.object(wip.contain, "live_disabled", lambda: None)
    SEAMS["live"].start()
    # A report's re-run keeps its marker journal under KEPT_ROOT (the host's temp directory), which
    # every run check reads: this module's runs and reports get a root of their own, so another
    # process's journals never reach them, nor theirs another's (Codex P1 (c) at 9db89fbe3c).
    SEAMS["kept_root"] = tempfile.mkdtemp(prefix="wip-curve-kept-")
    SEAMS["kept"] = mock.patch.object(wip, "KEPT_ROOT", SEAMS["kept_root"], create=True)
    SEAMS["kept"].start()
    SEAMS["mq_sandbox"] = mock.patch.object(
        wip.first_run, "SANDBOX_ENV_ALLOW", wip.first_run.SANDBOX_ENV_ALLOW | {"MQ_GATE_SANDBOX_CMD"}
    )
    SEAMS["mq_sandbox"].start()


def _ensure_test_mq_sandbox(env: dict, tmp: Path) -> None:
    """Configure a disposable MQ_GATE_SANDBOX_CMD wrapper only on CI hosts lacking bwrap/unshare."""
    if env.get("MQ_GATE_SANDBOX_CMD"):
        return
    if not _MQ_PROBE_MOD.MergeQueue._has_native_gate_isolation():
        sbx = tmp / "mq-test-gate-sandbox"
        sbx.parent.mkdir(parents=True, exist_ok=True)
        sbx.write_text("#!/bin/sh\nexec \"$@\"\n", encoding="utf-8")
        sbx.chmod(0o755)
        env["MQ_GATE_SANDBOX_CMD"] = str(sbx)


def tripwired_env(tmp: Path) -> tuple[dict, Path]:
    """SHELL=/bin/sh and a tripwire for every harness name first on PATH (test_certification.py)."""
    trip = tmp / "tripwire"
    trip.mkdir(parents=True, exist_ok=True)
    log = tmp / "tripwire.log"
    for name in wip.first_run.all_harness_binaries():
        path = trip / name
        path.write_text(f'#!/bin/sh\necho "{name} $*" >> "{log}"\nexit 97\n', encoding="utf-8")
        path.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k not in LEAKY}
    env["PATH"] = os.pathsep.join([str(trip), os.path.dirname(sys.executable), env.get("PATH", "")])
    env["SHELL"] = "/bin/sh"
    _ensure_test_mq_sandbox(env, tmp)
    return env, log


class _Hung(Exception):
    """An in-process run outlived its test timeout (SIGALRM)."""


def run_in_process(argv, env, cwd=None, timeout=600):
    """wip_curve.main() in this process, so coverage traces the runner itself, under `env` (a
    tripwired PATH and SHELL=/bin/sh), with its output captured. An alarm stands in for the
    subprocess timeout: it unwinds the run, which still settles and stops its workers."""
    out, err = io.StringIO(), io.StringIO()
    old_cwd = os.getcwd()

    def hung(_signum, _frame):
        raise _Hung(f"wip_curve.main{tuple(argv)[:4]} ran past {timeout}s")

    previous = signal.signal(signal.SIGALRM, hung)
    signal.alarm(int(timeout))
    try:
        with mock.patch.dict(os.environ, {k: v for k, v in (env or os.environ).items()}, clear=True), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                if cwd is not None:
                    os.chdir(cwd)
                try:
                    rc = wip.main([str(a) for a in argv])
                except SystemExit as exc:  # argparse, or a trapped signal
                    rc = exc.code
            finally:
                os.chdir(old_cwd)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    return subprocess.CompletedProcess(argv, rc, out.getvalue(), err.getvalue())


def runner(*args, env=None, timeout=600, cwd=None):
    """The runner's CLI, in-process (see run_in_process)."""
    return run_in_process(args, env, cwd=cwd, timeout=timeout)


def rebind(run_dir: Path) -> None:
    """Forge run.json's source digests after an edit: what a careful tamperer would do."""
    rec = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    rec["sources"] = {str(p.relative_to(run_dir)): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in sorted(run_dir.rglob("*")) if p.is_file() and p.name != "run.json"}
    (run_dir / "run.json").write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def synthetic_run(run_id, cond, throughput, *, compliant=True, review_in=100, review_out=20, tier="live-unreviewed",
                  model="m-1", harness="h-1", inputs="i" * 64, started="2026-10-24T10:00:00+00:00",
                  machine="host-a", agent="claude"):
    """A run summary in summarize_run()'s shape, for report logic that needs no real run."""
    builders, reviewers = {"b1r1": (1, 1), "b3r1": (3, 1), "b6r1": (6, 1), "b6r2": (6, 2)}[cond]
    tp = Fraction(str(throughput))
    metrics = {
        "throughput": {"value": f"{throughput}/h", "exact": str(tp), "verified_closed": 6, "wall_clock_s": "3600"},
        "latency": {"median_min": "1.00", "max_min": "2.00", "units": 6, "median_exact_s": "60", "max_exact_s": "120"},
        "rework": {"bounced": 1, "units": 6}, "freshness": 0, "retries": 1, "conflicts": 0, "gate_failures": 0,
        "usage": {"input_tokens": 1000, "output_tokens": 200, "cache_read_input_tokens": 0,
                  "cache_creation_input_tokens": 0, "cost_usd": "1.00"},
        "review_usage": {"reviews": 6, "observed": 6, "input_tokens": review_in, "output_tokens": review_out},
        "review_queue": {"median_min": "0.50", "max_min": "1.00", "median_exact_s": "30", "max_exact_s": "60"},
        "cost_per_verified_closed_usd": "0.1667", "parked": {}, "tasks": {}, "models": [model],
        "derivable": True,
    }
    finished = (datetime.fromisoformat(started) + timedelta(hours=1)).isoformat()
    run = {"run_id": run_id, "condition": cond, "builders": builders, "reviewers": reviewers, "tier": tier,
           "status": "complete", "started_at": started, "finished_at": finished,
           "inputs_sha256": inputs, "model_pin": model, "harness_version": harness, "attempt": 1,
           "agent": agent, "machine": {"clock": machine, "platform": "p", "machine": "m", "cpu_count": 8},
           "repetition": int(re.search(r"-rep(\d+)", run_id).group(1)) if "-rep" in run_id else None,
           "task_order": wip.task_order(*wip.load_prereg(PREREG)[:2], run_id),
           "timeout_scale": 1.0, "compliant": compliant,
           "noncompliance": [] if compliant else ["excluded by the protocol"], "binding_problems": [],
           "metrics": metrics}
    run["registered"] = wip.registered_run(run)
    return run


class Tmp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="wip-curve-test-")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)


# ---------------------------------------------------------------------------- pre-registration

class TestPreregistration(Tmp):
    def mutated(self, prereg_fn=None, taskset_fn=None, rehash=True):
        """A copy of the pre-registration and task set with one defect, digests kept consistent
        unless `rehash` is False, so each test sees only the defect it plants."""
        prereg = json.loads(PREREG.read_text(encoding="utf-8"))
        taskset = json.loads(TASKSET.read_text(encoding="utf-8"))
        if taskset_fn:
            taskset_fn(taskset)
        tpath = self.tmp / "taskset.json"
        tpath.write_text(json.dumps(taskset, indent=2), encoding="utf-8")
        prereg["taskset"]["path"] = str(tpath)
        if rehash:
            prereg["taskset"]["sha256"] = hashlib.sha256(tpath.read_bytes()).hexdigest()
        if prereg_fn:
            prereg_fn(prereg)
        ppath = self.tmp / "prereg.json"
        ppath.write_text(json.dumps(prereg, indent=2), encoding="utf-8")
        p, t, _path, _sha, tp = wip.load_prereg(ppath)
        return wip.check_prereg(p, t, tp)

    def test_the_committed_pre_registration_checks_clean(self):
        p = runner("check-prereg")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("pre-registration OK", p.stdout)
        self.assertIn("cost cap: 150.00", p.stdout)

    def test_the_spend_is_left_to_the_owner(self):
        cost = json.loads(PREREG.read_text(encoding="utf-8"))["cost"]
        # the owner authorised USD 150 on 2026-10-24; the record says who, when and how
        self.assertEqual((cost["cap_usd"], cost["reservation_status"]), ("150.00", wip.AUTHORISED))
        self.assertEqual((cost["authorised_by"], cost["authorised_on"]), ("Ravindra Kumar (@ravidsrk)", "2026-10-24"))
        self.assertIn("Authorising you on everything. Go ahead and complete it.", cost["authorised_via"])
        self.assertIn("CLAUDE_CODE_OAUTH_TOKEN", cost["billing"])
        self.assertGreater(wip.money(cost["proposed_cap_usd"]), 0)

    def test_an_amount_without_its_authorisation_does_not_check(self):
        def unrecorded(prereg):
            del prereg["cost"]["authorised_via"]
        self.assertTrue(any("authorisation is not recorded" in e for e in self.mutated(prereg_fn=unrecorded)))

    def test_the_design_records_every_registered_field(self):
        prereg = json.loads(PREREG.read_text(encoding="utf-8"))
        self.assertIn(1, [c["builders"] for c in prereg["conditions"]])
        self.assertGreaterEqual(prereg["repetitions"], 3)
        for key in ("machine", "provider", "model", "harness"):
            self.assertIn(key, prereg["runtime"])
        for key in ("cache_warmup", "task_difficulty", "model_changes", "reviewer_effort"):
            self.assertTrue(prereg["confounds"][key])
        for key in ("reviewer_availability", "isolation", "stopping_rule", "generalization_limits"):
            self.assertTrue(prereg[key])

    def test_a_design_without_the_serial_point_is_refused(self):
        errors = self.mutated(lambda p: p["conditions"].__setitem__(0, {**p["conditions"][0], "builders": 2}))
        self.assertTrue(any("builders=1" in e for e in errors), errors)

    def test_fewer_than_three_wip_settings_is_refused(self):
        def two(p):
            p["conditions"] = p["conditions"][:2]
            p["order"]["rows"] = [r for r in ([["b1r1", "b3r1"]] * 3)]
        errors = self.mutated(two)
        self.assertTrue(any("three differing WIP settings" in e for e in errors), errors)

    def test_fewer_than_three_repetitions_is_refused(self):
        errors = self.mutated(lambda p: p.__setitem__("repetitions", 2))
        self.assertTrue(any("repetitions" in e for e in errors), errors)

    def test_an_order_row_that_is_not_a_permutation_is_refused(self):
        errors = self.mutated(lambda p: p["order"]["rows"][1].__setitem__(0, "b1r1"))
        self.assertTrue(any("not a permutation" in e for e in errors), errors)

    def test_an_unstated_confound_is_refused(self):
        errors = self.mutated(lambda p: p["confounds"].pop("model_changes"))
        self.assertTrue(any("confounds.model_changes" in e for e in errors), errors)

    def test_an_unstated_stopping_rule_is_refused(self):
        errors = self.mutated(lambda p: p["stopping_rule"].pop("cost"))
        self.assertTrue(any("stopping_rule.cost" in e for e in errors), errors)

    def test_a_registered_metric_the_report_cannot_emit_is_refused(self):
        errors = self.mutated(lambda p: p["metrics"]["report_fields"]["run"].append("vibes_per_hour"))
        self.assertTrue(any("vibes_per_hour" in e for e in errors), errors)

    def test_a_cap_that_is_neither_pending_nor_an_amount_is_refused(self):
        errors = self.mutated(lambda p: p["cost"].__setitem__("cap_usd", "plenty"))
        self.assertTrue(any("cost.cap_usd" in e for e in errors), errors)

    def test_editing_the_task_set_voids_the_registration(self):
        errors = self.mutated(taskset_fn=lambda t: t["tasks"][0].__setitem__("title", "easier"), rehash=False)
        self.assertTrue(any("taskset.sha256" in e for e in errors), errors)

    def test_a_seed_that_builds_another_commit_is_refused(self):
        errors = self.mutated(taskset_fn=lambda t: t["seed"].__setitem__("date", "2026-10-25T00:00:00+00:00"))
        self.assertTrue(any("seed_commit" in e for e in errors), errors)

    def test_an_oracle_that_passes_on_the_seed_is_refused(self):
        lazy = ("import unittest\n\n\nclass Oracle(unittest.TestCase):\n"
                "    def test_nothing(self):\n        self.assertTrue(True)\n")
        errors = self.mutated(taskset_fn=lambda t: t["tasks"][2].__setitem__("oracle", lazy))
        self.assertTrue(any("T3: the oracle passes on the seed" in e for e in errors), errors)

    def test_the_worker_contracts_are_registered_not_coded(self):
        contracts = json.loads(PREREG.read_text(encoding="utf-8"))["contracts"]
        prereg, taskset, *_ = wip.load_prereg(PREREG)
        run = wip.Run.__new__(wip.Run)
        run.prereg, run.tasks = prereg, wip.task_by_id(taskset)
        builder = run.builder_spec("T1", "WIP-NONCE:" + "0" * 16)
        self.assertIn("WIP-BUILD WIP-NONCE:" + "0" * 16 + " task=T1", builder)
        self.assertIn(contracts["builder"][-1].split("{")[0], builder)
        review = run.review_spec("T1", "WIP-NONCE:" + "0" * 16, "a" * 40, "b" * 40, "t.md", "c.diff")
        self.assertIn("WIP-REVIEW-REQUEST WIP-NONCE:" + "0" * 16 + " task=T1 head=" + "b" * 40 + " diff=c.diff", review)

    def test_a_contract_that_loses_a_placeholder_is_refused(self):
        errors = self.mutated(lambda p: p["contracts"]["reviewer"].__setitem__(
            0, p["contracts"]["reviewer"][0].replace(" head={head}", "")))
        self.assertTrue(any("contracts.reviewer" in e and "{head}" in e for e in errors), errors)

    def test_a_verdict_line_the_parser_cannot_read_is_refused(self):
        errors = self.mutated(lambda p: p["contracts"].__setitem__("verdict_line", "VERDICT: {verdict} for {head}"))
        self.assertTrue(any("verdict_line" in e for e in errors), errors)

    def test_editing_a_worker_contract_changes_the_registration(self):
        before = hashlib.sha256(PREREG.read_bytes()).hexdigest()
        prereg = json.loads(PREREG.read_text(encoding="utf-8"))
        prereg["contracts"]["reviewer"][1] += " Be lenient."
        self.assertNotEqual(hashlib.sha256(json.dumps(prereg, indent=2).encode()).hexdigest(), before)

    def test_a_reference_edit_that_does_not_apply_is_refused(self):
        def drift(t):
            t["tasks"][0]["reference"][0]["replace"] = "import regex"
        errors = self.mutated(taskset_fn=drift)
        self.assertTrue(any("T1: the reference edit does not apply" in e for e in errors), errors)

    def test_an_ambiguous_anchor_is_refused_not_guessed(self):
        tree = self.tmp / "tree"
        tree.mkdir()
        (tree / "f.py").write_text("x = 1\nx = 1\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            wip.apply_edits(tree, [{"file": "f.py", "replace": "x = 1", "with": ["x = 2"]}])
        self.assertEqual((tree / "f.py").read_text(encoding="utf-8"), "x = 1\nx = 1\n")

    def test_the_seed_commit_is_the_same_on_any_host(self):
        taskset = json.loads(TASKSET.read_text(encoding="utf-8"))
        hostile = {**os.environ, "GIT_AUTHOR_NAME": "someone", "GIT_COMMITTER_DATE": "2001-01-01T00:00:00Z"}
        seed = wip.build_seed(taskset, self.tmp / "seed", hostile)
        self.assertEqual(seed, json.loads(PREREG.read_text(encoding="utf-8"))["taskset"]["seed_commit"])


PREREG_V2 = ROOT / "docs" / "experiments" / "wip-curve-prereg-v2.json"


class TestVersionTwo(unittest.TestCase):
    """Version 2 re-registers the experiment after its first two live runs: a changed stopping rule
    is a new version, with new run ids and a new results directory. Nothing else changes."""

    def test_it_checks_clean_and_schedules_new_run_ids(self):
        p = runner("--prereg", str(PREREG_V2), "check-prereg")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("pre-registration OK", p.stdout)
        ids = [e["run_id"] for e in wip.schedule(*wip.load_prereg(PREREG_V2)[:2])]
        self.assertEqual(len(ids), 12)
        self.assertTrue(all(i.startswith("wip2-") for i in ids), ids)

    def test_only_the_stopping_rule_changed(self):
        v1 = json.loads(PREREG.read_text(encoding="utf-8"))
        v2 = json.loads(PREREG_V2.read_text(encoding="utf-8"))
        self.assertEqual({k for k in v1 if v1[k] != v2[k]}, {"version", "registered", "status", "stopping_rule"})
        self.assertEqual({k for k in v1["stopping_rule"] if v1["stopping_rule"][k] != v2["stopping_rule"][k]},
                         {"experiment"})
        self.assertTrue(v2["stopping_rule"]["experiment"].startswith(v1["stopping_rule"]["experiment"]))
        self.assertEqual((v2["version"], v2["supersedes"]["version"]), (2, 1))
        self.assertEqual(set(v2["supersedes"]["version_1_runs"]), {"wip1-b1r1-rep1", "wip1-b3r1-rep1"})


class TestTheMachineIsTheHostInsideTheHarness(Tmp):
    """Version 2: inside the container live harness the container's name changes with every
    launch, so every run after the first read as another machine. The launcher's attestation names
    the host; outside the harness there is none, and the host name is used as before."""

    def label(self, doc=None, node="a-host"):
        att = self.tmp / "attestation.json"
        if doc is not None:
            att.write_text(json.dumps(doc), encoding="utf-8")
        with mock.patch.object(wip.contain.containment, "ATTESTATION", str(att)), \
                mock.patch.object(wip.platform, "node", return_value=node):
            return wip.host_label()

    def test_the_attestation_names_the_machine(self):
        host = hashlib.sha256(b"the-operators-mac").hexdigest()
        self.assertEqual(self.label({"host_sha256": host}, node="container-1"), host[:12])
        self.assertEqual(self.label({"host_sha256": host}, node="container-2"), host[:12])

    def test_without_one_the_host_name_does(self):
        self.assertEqual(self.label(), hashlib.sha256(b"a-host").hexdigest()[:12])

    def test_an_attestation_that_names_no_host_is_not_read_as_one(self):
        for doc in ({}, {"host_sha256": "not-hex"}, {"host_sha256": "A" * 64}, ["x"]):
            self.assertEqual(self.label(doc), hashlib.sha256(b"a-host").hexdigest()[:12], doc)

    def test_every_launch_of_a_run_on_one_host_keeps_one_clock(self):
        # Codex at b1c1469595: the label alone passed with Run still hashing the container's name
        prereg, taskset, path, sha, taskset_path = wip.load_prereg(PREREG_V2)
        entry = wip.schedule(prereg, taskset)[0]
        args = argparse.Namespace(cost_cap=Decimal("1"), reservation=Decimal("0.25"), model="m", worker="live",
                                  timeout_scale=1.0)
        host = hashlib.sha256(b"the-operators-mac").hexdigest()
        (self.tmp / "attestation.json").write_text(json.dumps({"host_sha256": host}), encoding="utf-8")

        def clock(node, attestation="attestation.json"):
            with mock.patch.object(wip.contain.containment, "ATTESTATION", str(self.tmp / attestation)), \
                    mock.patch.object(wip.platform, "node", return_value=node):
                return wip.Run(args, prereg, taskset, (path, sha, taskset_path), entry, self.tmp / "results").clock

        self.assertEqual({clock("of-live-1"), clock("of-live-2")}, {f"wip-runner@host-{host[:12]}"})
        self.assertNotEqual(clock("host-a", "absent.json"), clock("host-b", "absent.json"))


# ---------------------------------------------------------------------------- schedule

class TestSchedule(unittest.TestCase):
    def setUp(self):
        self.prereg, self.taskset, *_ = wip.load_prereg(PREREG)
        self.sched = wip.schedule(self.prereg, self.taskset)

    def test_every_repetition_runs_every_condition_once_in_its_row(self):
        conds = sorted(c["id"] for c in self.prereg["conditions"])
        self.assertEqual(len(self.sched), len(conds) * self.prereg["repetitions"])
        for rep in range(1, self.prereg["repetitions"] + 1):
            row = [e["condition"]["id"] for e in self.sched if e["repetition"] == rep]
            self.assertEqual(row, self.prereg["order"]["rows"][rep - 1])
            self.assertEqual(sorted(row), conds)

    def test_no_condition_holds_one_position_twice(self):
        rows = self.prereg["order"]["rows"][: self.prereg["repetitions"]]
        for col in range(len(rows[0])):
            column = [row[col] for row in rows]
            self.assertEqual(len(set(column)), len(column), f"position {col + 1}: {column}")

    def test_the_task_order_is_recomputable_from_the_registration_alone(self):
        seed = self.prereg["order"]["seed"]
        for entry in self.sched:
            want = sorted((t["id"] for t in self.taskset["tasks"]),
                          key=lambda t: hashlib.sha256(f"{seed}:{entry['run_id']}:{t}".encode()).hexdigest())
            self.assertEqual(entry["task_order"], want)
        self.assertGreater(len({tuple(e["task_order"]) for e in self.sched}), 1, "the order never varies")

    def test_a_re_run_keeps_its_runs_task_order(self):
        rid = self.sched[0]["run_id"]
        self.assertEqual(wip.task_order(self.prereg, self.taskset, f"{rid}-a2"), self.sched[0]["task_order"])


# ---------------------------------------------------------------------------- statistics + rule

class TestUncertainty(unittest.TestCase):
    def test_mean_sd_and_t_interval_match_a_hand_calculation(self):
        # 1, 2, 3: mean 2, sd 1, t(2) = 4.303, half-width 4.303 / sqrt(3) = 2.4843... -> [-0.48, 4.48]
        got = wip.describe([Fraction(1), Fraction(2), Fraction(3)])
        self.assertEqual((got["mean"], got["sd"], got["ci95"]), ("2.00", "1.00", ["-0.48", "4.48"]))
        self.assertEqual(got["values"], ["1.00", "2.00", "3.00"])

    def test_one_run_has_no_spread_and_no_run_has_no_mean(self):
        self.assertIsNone(wip.describe([Fraction(5)])["ci95"])
        self.assertIsNone(wip.describe([])["mean"], "no run is not a mean of 0")

    def test_the_wilson_interval_matches_the_formula(self):
        k, n, z = 4, 9, 1.959963984540054
        p = k / n
        center = (p + z * z / (2 * n)) / (1 + z * z / n)
        half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / (1 + z * z / n)
        got = wip.wilson(k, n)
        self.assertEqual(got["ci95"], [f"{center - half:.3f}", f"{center + half:.3f}"])
        self.assertEqual(wip.wilson(0, 0)["p"], None)


class TestPartialUsage(unittest.TestCase):
    """A usage observation may report input tokens and not output tokens (or the reverse): the
    reviewer-effort metric is then unavailable, never a TypeError and never a partial sum."""

    def test_a_run_missing_one_token_count_reports_review_tokens_unavailable(self):
        for review_in, review_out in ((100, None), (None, 20)):
            run = synthetic_run("r1", "b3r1", "1.0", review_in=review_in, review_out=review_out)
            self.assertIsNone(run["registered"]["review_tokens_per_review"])
            block = wip.condition_block({"id": "b3r1", "builders": 3, "reviewers": 1, "role": "x"}, [run])
            self.assertIn("unavailable", block["review_tokens_per_review"])

    def test_complete_counts_still_give_tokens_per_review(self):
        run = synthetic_run("r1", "b3r1", "1.0")
        self.assertEqual(run["registered"]["review_tokens_per_review"], "20.00")


class ReportOver(unittest.TestCase):
    """build_report() over synthetic run summaries: report logic without a real run."""

    def report(self, runs, basis="compliant", results=Path("/nonexistent")):
        by_name = {r["run_id"]: r for r in runs}
        with mock.patch.object(wip, "runs_in", return_value=[Path(r) for r in by_name]), \
                mock.patch.object(wip, "summarize_run", side_effect=lambda d, *a: copy.deepcopy(by_name[Path(d).name])):
            return wip.build_report(results, basis=basis)


class TestIncomparableRunsAreNeverPooled(ReportOver):
    """PR #653 review: a run under another model pin or harness version than the first live run
    is not compliant, whatever its own checks say, so it never enters the curve."""

    def test_another_harness_version_or_model_pin_is_excluded(self):
        runs = [synthetic_run("wip1-b1r1-rep1", "b1r1", "1.0", started="2026-10-24T10:00:00+00:00"),
                synthetic_run("wip1-b3r1-rep1", "b3r1", "1.0", harness="h-2", started="2026-10-24T12:00:00+00:00"),
                synthetic_run("wip1-b6r1-rep1", "b6r1", "1.0", model="m-2", started="2026-10-24T14:00:00+00:00")]
        out = {r["run_id"]: r for r in self.report(runs)["runs"]}
        self.assertTrue(out["wip1-b1r1-rep1"]["compliant"])
        self.assertTrue(any("harness version" in w for w in out["wip1-b3r1-rep1"]["noncompliance"]),
                        out["wip1-b3r1-rep1"]["noncompliance"])
        self.assertTrue(any("model pin" in w for w in out["wip1-b6r1-rep1"]["noncompliance"]),
                        out["wip1-b6r1-rep1"]["noncompliance"])
        self.assertEqual(self.report(runs)["compliant_runs"], ["wip1-b1r1-rep1"])

    def test_another_machine_or_harness_name_is_excluded(self):
        runs = [synthetic_run("wip1-b1r1-rep1", "b1r1", "1.0", started="2026-10-24T10:00:00+00:00"),
                synthetic_run("wip1-b3r1-rep1", "b3r1", "1.0", machine="host-b", started="2026-10-24T12:00:00+00:00"),
                synthetic_run("wip1-b6r1-rep1", "b6r1", "1.0", agent="codex", started="2026-10-24T14:00:00+00:00")]
        out = {r["run_id"]: r for r in self.report(runs)["runs"]}
        self.assertTrue(any("machine" in w for w in out["wip1-b3r1-rep1"]["noncompliance"]),
                        out["wip1-b3r1-rep1"]["noncompliance"])
        self.assertTrue(any("harness" in w for w in out["wip1-b6r1-rep1"]["noncompliance"]),
                        out["wip1-b6r1-rep1"]["noncompliance"])


def at_position(run_id) -> str:
    """When a run at its registered position starts: two hours a position (the cooldown kept)."""
    position = next(e["position"] for e in wip.schedule(*wip.load_prereg(PREREG)[:2]) if e["run_id"] == run_id)
    return (datetime.fromisoformat("2026-10-24T00:00:00+00:00") + timedelta(hours=2 * position)).isoformat()


def series(cond, values, **kw):
    """Synthetic runs of one condition, each started at its registered position (PR #653 review:
    a fixture never runs the conditions in another order than the schedule's)."""
    return [synthetic_run(f"wip1-{cond}-rep{i + 1}", cond, v, started=at_position(f"wip1-{cond}-rep{i + 1}"), **kw)
            for i, v in enumerate(values)]


class TestOnlyCompliantRunsDecide(ReportOver):
    """PR #653 review: whatever --basis shows, the recommendation is computed from compliant runs
    alone. Six fast b6r1 fixture runs must not turn a 'keep' into a 'raise'."""

    def runs(self):
        compliant = (series("b1r1", ["1.00", "1.02"]) + series("b3r1", ["1.00", "1.02"]) + series("b6r1", ["1.00", "1.02"])
                     + series("b6r2", ["1.00"]))  # position 3: every compliant run's predecessors ran
        excluded = [synthetic_run(f"wip1-b6r1-rep{i}", "b6r1", "3.00", compliant=False, tier="fixture-tested",
                                  started=f"2026-10-25T{10 + i:02d}:00:00+00:00") for i in range(3, 9)]
        return compliant + excluded

    def test_the_basis_never_moves_the_recommendation(self):
        shown_all = self.report(self.runs(), basis="all")
        compliant_only = self.report(self.runs(), basis="compliant")
        self.assertEqual(compliant_only["recommendation"]["status"], "keep")
        self.assertEqual(shown_all["recommendation"]["status"], "keep",
                         "excluded runs swayed the recommendation")
        b6 = next(c for c in shown_all["conditions"] if c["condition"] == "b6r1")
        self.assertEqual(b6["throughput_per_h"]["n"], 8, "--basis all still shows every run's row")


class TestOnlyOneRetryAfterAFailure(ReportOver):
    """PR #653 review: the registration allows one re-run, and only of a run that failed for an
    infrastructure reason. A repeat of a run that did not fail, or a third attempt, never counts."""

    def attempt(self, n, status="complete", hour=10, **kw):
        run = synthetic_run("wip1-b1r1-rep1" + (f"-a{n}" if n > 1 else ""), "b1r1", "1.0",
                            started=f"2026-10-24T{hour:02d}:00:00+00:00", **kw)
        run.update(attempt=n, status=status)
        if status != "complete":
            run.update(compliant=False, noncompliance=[f"the run ended {status}"])
        return run

    def test_a_repeat_of_a_run_that_did_not_fail_is_excluded(self):
        out = {r["run_id"]: r for r in self.report([self.attempt(1), self.attempt(2, hour=12)])["runs"]}
        self.assertFalse(out["wip1-b1r1-rep1-a2"]["compliant"])
        self.assertTrue(any("attempt 2" in w for w in out["wip1-b1r1-rep1-a2"]["noncompliance"]))

    def test_one_retry_after_a_failure_counts_and_a_third_attempt_never_does(self):
        out = {r["run_id"]: r for r in self.report([self.attempt(1, status="failed"), self.attempt(2, hour=12),
                                                   self.attempt(3, hour=14)])["runs"]}
        self.assertTrue(out["wip1-b1r1-rep1-a2"]["compliant"], out["wip1-b1r1-rep1-a2"]["noncompliance"])
        self.assertFalse(out["wip1-b1r1-rep1-a3"]["compliant"])

    def test_a_retry_of_a_run_every_call_of_which_was_refused_counts(self):
        # version 2: wip1-b3r1-rep1 read `complete`, yet the API refused its every call
        first = self.attempt(1)
        why = "the API refused all 18 of its model calls for the credential"
        first.update(infrastructure=why, compliant=False, noncompliance=[f"an infrastructure failure: {why}"])
        out = {r["run_id"]: r for r in self.report([first, self.attempt(2, hour=12)])["runs"]}
        self.assertFalse(out["wip1-b1r1-rep1"]["compliant"])
        self.assertTrue(out["wip1-b1r1-rep1-a2"]["compliant"], out["wip1-b1r1-rep1-a2"]["noncompliance"])


class TestTheRegisteredOrderIsKept(ReportOver):
    """PR #653 review (Bu3): repetition r runs the conditions in Latin-square row r (order.conditions),
    the protection against warm-up and time effects. Live runs that started out of that order are
    reported, never pooled, whatever each run's own checks say."""

    def test_runs_in_the_registered_order_count(self):
        runs = [synthetic_run(r, r.split("-")[1], "1.0", started=at_position(r))
                for r in ("wip1-b1r1-rep1", "wip1-b3r1-rep1", "wip1-b6r2-rep1")]
        self.assertEqual(self.report(runs)["compliant_runs"], ["wip1-b1r1-rep1", "wip1-b3r1-rep1", "wip1-b6r2-rep1"])

    def test_the_serial_conditions_first_never_count(self):
        # every b1r1 repetition first, then the wider conditions: each run's own labels are right
        order = ["wip1-b1r1-rep1", "wip1-b1r1-rep2", "wip1-b1r1-rep3", "wip1-b3r1-rep1", "wip1-b6r1-rep1"]
        base = datetime.fromisoformat("2026-10-24T00:00:00+00:00")
        runs = [synthetic_run(r, r.split("-")[1], "1.0", started=(base + timedelta(hours=2 * i)).isoformat())
                for i, r in enumerate(order)]
        out = {r["run_id"]: r for r in self.report(runs)["runs"]}
        self.assertTrue(out["wip1-b1r1-rep1"]["compliant"], out["wip1-b1r1-rep1"]["noncompliance"])
        for rid in order[1:]:
            self.assertFalse(out[rid]["compliant"], rid)
            self.assertTrue(any("registered order" in w for w in out[rid]["noncompliance"]), out[rid]["noncompliance"])

    def test_a_lost_live_run_is_placed_by_the_start_its_ledger_recorded(self):
        tmp = Path(tempfile.mkdtemp(prefix="wip-curve-order-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "runs" / "wip1-b1r1-rep1").mkdir(parents=True)  # position 1, killed: no run.json
        wip.Budget(tmp).start_run("wip1-b1r1-rep1", tmp / "gone", "live")  # its start: now
        early = synthetic_run("wip1-b3r1-rep1", "b3r1", "1.0", started="2026-01-01T00:00:00+00:00")
        out = {r["run_id"]: r for r in self.report([early], results=tmp)["runs"]}
        self.assertFalse(out["wip1-b3r1-rep1"]["compliant"])
        self.assertIn("ran out of the registered order: position 2 started before position(s) [1]",
                      out["wip1-b3r1-rep1"]["noncompliance"])

    def test_a_run_whose_predecessors_never_ran_never_counts(self):
        # Codex review (C4): position 4 alone, no evidence that positions 1-3 ran before it
        out = self.report([synthetic_run("wip1-b6r1-rep1", "b6r1", "1.0", started=at_position("wip1-b6r1-rep1"))])
        run = out["runs"][0]
        self.assertFalse(run["compliant"])
        self.assertIn("no evidence that position(s) [1, 2, 3], registered before it, ran", run["noncompliance"])

    def test_a_lost_live_predecessor_is_evidence_that_its_position_ran(self):
        tmp = Path(tempfile.mkdtemp(prefix="wip-curve-order-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "runs" / "wip1-b1r1-rep1").mkdir(parents=True)  # position 1, killed: no run.json
        wip.Budget(tmp).start_run("wip1-b1r1-rep1", tmp / "gone", "live")  # its start: now
        later = synthetic_run("wip1-b3r1-rep1", "b3r1", "1.0",
                              started=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
        out = {r["run_id"]: r for r in self.report([later], results=tmp)["runs"]}
        self.assertTrue(out["wip1-b3r1-rep1"]["compliant"], out["wip1-b3r1-rep1"]["noncompliance"])
        wip.Budget(tmp).note("wip1-b1r1-rep1/run", worker="inert")  # an inert lost run is no evidence
        out = {r["run_id"]: r for r in self.report([later], results=tmp)["runs"]}
        self.assertFalse(out["wip1-b3r1-rep1"]["compliant"])

    def test_a_lost_live_run_ends_at_its_last_ledger_activity_for_cooldown(self):
        tmp = Path(tempfile.mkdtemp(prefix="wip-curve-order-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        rid = "wip1-b1r1-rep1"
        (tmp / "runs" / rid).mkdir(parents=True)  # killed: no run.json
        budget = wip.Budget(tmp)
        with mock.patch.object(wip, "now", side_effect=("2026-10-24T10:00:00+00:00",
                                                        "2026-10-24T10:00:00+00:00")):
            budget.start_run(rid, tmp / "gone", "live")
            budget.note(f"{rid}/dispatch/activity", run=rid, state="launched", usd="0.25")
        later = synthetic_run("wip1-b3r1-rep1", "b3r1", "1.0", started="2026-10-24T10:01:00+00:00")

        run = {r["run_id"]: r for r in self.report([later], results=tmp)["runs"]}["wip1-b3r1-rep1"]

        self.assertFalse(run["compliant"])
        self.assertIn("started 60s after wip1-b1r1-rep1 ended; the cooldown is 600s", run["noncompliance"])

    def test_a_re_run_after_a_later_position_never_counts(self):
        first = synthetic_run("wip1-b1r1-rep1", "b1r1", "1.0", started=at_position("wip1-b1r1-rep1"))
        first.update(status="failed", compliant=False, noncompliance=["the run ended failed"])
        later = synthetic_run("wip1-b3r1-rep1", "b3r1", "1.0", started=at_position("wip1-b3r1-rep1"))
        rerun = synthetic_run("wip1-b1r1-rep1-a2", "b1r1", "1.0", started=at_position("wip1-b6r2-rep1"))
        rerun["attempt"] = 2
        out = {r["run_id"]: r for r in self.report([first, later, rerun])["runs"]}
        self.assertFalse(out["wip1-b1r1-rep1-a2"]["compliant"])
        self.assertTrue(any("registered order" in w for w in out["wip1-b1r1-rep1-a2"]["noncompliance"]))


class TestChangedDeadlinesNeverCount(ReportOver):
    """PR #653 review: a run whose dispatch deadlines were scaled away from the registered 30 and
    15 minutes is reported, never pooled; and every run records the scale it ran under."""

    def test_a_scaled_run_is_excluded(self):
        scaled = synthetic_run("wip1-b1r1-rep1", "b1r1", "1.0")
        scaled["timeout_scale"] = 0.5
        run = self.report([scaled])["runs"][0]
        self.assertFalse(run["compliant"])
        self.assertTrue(any("deadlines" in w for w in run["noncompliance"]), run["noncompliance"])

    def test_every_run_records_its_timeout_scale(self):
        record = json.loads((Path(dry_run(*B1_BOUNDARY)[0].name) / "results" / "runs" / B1_BOUNDARY[0]
                             / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(record["timeout_scale"], 1.0)


class TestOnlyTheScheduledRunCounts(ReportOver):
    """Adversarial pass (pooling incomparable runs; extra runs swaying the curve): a run must be a
    scheduled run, under its scheduled condition, repetition and task order."""

    def test_an_unscheduled_run_is_excluded(self):
        run = self.report([synthetic_run("wip1-b6r1-rep4", "b6r1", "9.0")])["runs"][0]
        self.assertFalse(run["compliant"])
        self.assertTrue(any("not a scheduled run" in w for w in run["noncompliance"]), run["noncompliance"])

    def test_a_run_under_another_condition_than_scheduled_is_excluded(self):
        mislabelled = synthetic_run("wip1-b3r1-rep1", "b6r1", "9.0")
        run = self.report([mislabelled])["runs"][0]
        self.assertFalse(run["compliant"])
        self.assertTrue(any("scheduled" in w and "b3r1" in w for w in run["noncompliance"]), run["noncompliance"])

    def test_a_run_whose_waves_ran_another_wip_is_excluded(self):
        src = Path(dry_run(*B1_BOUNDARY)[0].name) / "results" / "runs" / B1_BOUNDARY[0]
        results = Path(tempfile.mkdtemp(prefix="wip-curve-wip-"))
        self.addCleanup(shutil.rmtree, results, True)
        shutil.copytree(src, results / "runs" / src.name)
        rec_path = results / "runs" / src.name / "run.json"
        rec = json.loads(rec_path.read_text(encoding="utf-8"))
        rec["condition"] = {**rec["condition"], "builders": 3}  # the label says 3; the record ran 1
        rec_path.write_text(json.dumps(rec), encoding="utf-8")
        run = wip.build_report(results, basis="all")["runs"][0]
        self.assertTrue(any("builders=1" in w for w in run["noncompliance"]), run["noncompliance"])


class TestDecisionRule(unittest.TestCase):
    def setUp(self):
        self.prereg = json.loads(PREREG.read_text(encoding="utf-8"))

    def block(self, ci, rework="0.100", fresh=0):
        return {"throughput_per_h": {"ci95": ci}, "rework": {"p": rework},
                "freshness": {"values": [fresh, fresh, fresh], "total": 3 * fresh}}

    def compliant(self):
        return [{"builders": b, "reviewers": 1} for b in (1, 3, 6)]

    def test_too_few_compliant_runs_issue_nothing(self):
        got = wip.recommend(self.prereg, {}, self.compliant()[:2])
        self.assertEqual(got["status"], "not-issued")

    def test_overlapping_intervals_keep_the_caps(self):
        blocks = {"b1r1": self.block(["1.0", "2.0"]), "b3r1": self.block(["1.5", "3.0"]),
                  "b6r1": self.block(["2.5", "4.0"]), "b6r2": self.block(["2.0", "3.5"])}
        self.assertEqual(wip.recommend(self.prereg, blocks, self.compliant())["status"], "keep")

    def test_a_clear_gain_above_the_cap_is_a_raise_candidate(self):
        blocks = {"b1r1": self.block(["1.0", "2.0"]), "b3r1": self.block(["1.5", "3.0"]),
                  "b6r1": self.block(["3.5", "5.0"]), "b6r2": self.block(["2.0", "3.5"])}
        got = wip.recommend(self.prereg, blocks, self.compliant())
        self.assertEqual(got["status"], "raise")
        self.assertIn("human-reviewed policy change", got["authority"])

    def test_a_gain_bought_with_rework_is_not_a_raise(self):
        blocks = {"b1r1": self.block(["1.0", "2.0"]), "b3r1": self.block(["1.5", "3.0"]),
                  "b6r1": self.block(["3.5", "5.0"], rework="0.300"), "b6r2": self.block(["2.0", "3.5"])}
        self.assertEqual(wip.recommend(self.prereg, blocks, self.compliant())["status"], "keep")

    def test_a_serial_run_beating_the_cap_is_a_lower_candidate(self):
        blocks = {"b1r1": self.block(["3.1", "4.0"]), "b3r1": self.block(["1.5", "3.0"]),
                  "b6r1": self.block(["1.0", "2.0"]), "b6r2": self.block(["1.0", "2.0"])}
        self.assertEqual(wip.recommend(self.prereg, blocks, self.compliant())["status"], "lower")


# ---------------------------------------------------------------------------- refusals + gate

class TestTheLiveTierIsDisabled(Tmp):
    """PR #668, the owner's decision: `wip_curve.py run --worker live` is refused on every host but
    the live harness's container (scripts/live_container.py), exit 2, before the pre-registration is
    read or anything reserved. The owner's authorised cap and reservation change nothing."""

    def argv(self):
        return ["run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"),
                "--worker", "live", "--agent", "claude", "--model", "m", "--cost-cap-usd", "20",
                "--reservation-usd", "0.25", "--next", "1"]

    def test_a_live_run_is_refused_before_anything_is_read(self):
        env, trip_log = tripwired_env(self.tmp)
        with mock.patch.object(wip.contain, "live_disabled", REAL_LIVE_GATE), \
                mock.patch.object(wip, "load_prereg", side_effect=AssertionError("the registration was read")), \
                mock.patch.object(wip, "dirty_inputs", side_effect=AssertionError("the inputs were read")):
            p = run_in_process(["--prereg", str(self.tmp / "no-such-prereg.json"), *self.argv()], env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn(DISABLED, p.stderr)
        self.assertIn("PR #668", p.stderr)
        self.assertEqual(len(p.stderr.strip().splitlines()), 1, p.stderr)
        self.assertFalse((self.tmp / "results").exists(), "a refused live run created its results")
        self.assertFalse((self.tmp / "wd").exists(), "a refused live run created its sandbox")
        self.assertFalse(trip_log.exists(), "a refused live run reached a harness")

    def test_the_cli_refuses_as_its_own_process(self):
        # No seam at all: the script as an operator runs it.
        env, trip_log = tripwired_env(self.tmp)
        p = subprocess.run([sys.executable, str(RUNNER), *self.argv()], cwd=str(ROOT), env=env,
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn(DISABLED, p.stderr)
        self.assertFalse((self.tmp / "results").exists())
        self.assertFalse(trip_log.exists())

    def test_the_inert_worker_is_untouched(self):
        env, _trip_log = tripwired_env(self.tmp)
        with mock.patch.object(wip.contain, "live_disabled", REAL_LIVE_GATE):
            p = run_in_process(["run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"),
                                "--runs", "wip1-b1r1-rep1-a3", "--cost-cap-usd", "0"], env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("one re-run", p.stderr)
        self.assertNotIn(DISABLED, p.stderr)


class TestRunRefusals(Tmp):
    """Refusals happen before anything launches: no run directory, no tripwire hit."""

    def setUp(self):
        super().setUp()
        self.env, self.trip_log = tripwired_env(self.tmp)
        self.results = self.tmp / "results"

    def refused(self, *args, rc=2, text=""):
        p = runner("run", "--results", str(self.results), "--workdir", str(self.tmp / "wd"), *args, env=self.env)
        self.assertEqual(p.returncode, rc, p.stdout + p.stderr)
        self.assertIn(text, p.stderr)
        self.assertFalse((self.results / "runs").exists() and any((self.results / "runs").iterdir()),
                         "a refused run left a run directory")
        self.assertFalse(self.trip_log.exists(), "a refused run reached a harness")

    def test_no_run_starts_without_an_explicit_cost_cap(self):
        self.refused(text="--cost-cap-usd is required")

    def test_a_live_run_refuses_a_zero_cap(self):
        self.refused("--worker", "live", "--cost-cap-usd", "0", "--model", "m", text="above zero")

    def test_a_live_run_refuses_without_a_model_pin(self):
        self.refused("--worker", "live", "--cost-cap-usd", "5", text="--model")

    def test_a_live_run_on_another_harness_is_not_refused_as_the_stand_in(self):
        # The stand-in's claude-only rule is not a live run's: codex is refused for the reason that
        # applies to it, that no model pin can reach it (PR #653 review).
        self.refused("--worker", "live", "--agent", "codex", "--cost-cap-usd", "5", "--model", "m",
                     "--reservation-usd", "1", "--runs", "wip1-b9r9-rep1", text="cannot enforce the model pin")

    def test_a_live_run_refuses_changed_dispatch_deadlines(self):
        self.refused("--worker", "live", "--model", "m", "--cost-cap-usd", "5", "--reservation-usd", "1",
                     "--timeout-scale", "0.5", text="--timeout-scale")

    def test_a_retry_with_no_failed_first_attempt_is_refused(self):
        self.refused("--cost-cap-usd", "0", "--runs", "wip1-b1r1-rep1-a2", text="infrastructure failure")

    def test_a_third_attempt_is_refused(self):
        self.refused("--cost-cap-usd", "0", "--runs", "wip1-b1r1-rep1-a3", text="one re-run")

    def test_a_retry_of_a_run_that_did_not_fail_is_refused(self):
        src = Path(dry_run(*B3)[0].name) / "results" / "runs" / B3[0]
        shutil.copytree(src, self.results / "runs" / src.name)
        p = runner("run", "--results", str(self.results), "--workdir", str(self.tmp / "wd"), "--runs",
                   f"{B3[0]}-a2", "--cost-cap-usd", "0", env=self.env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("infrastructure failure", p.stderr)
        self.assertEqual([d.name for d in (self.results / "runs").iterdir()], [B3[0]])

    def test_a_live_run_refuses_without_an_authorised_reservation(self):
        # The per-dispatch reservation is PENDING OWNER AUTHORISATION too: never taken as given.
        self.refused("--worker", "live", "--cost-cap-usd", "5", "--model", "m", text="--reservation-usd")

    def test_a_cap_must_be_an_amount(self):
        self.refused("--cost-cap-usd", "lots", text="not a decimal amount")

    def test_the_stand_in_refuses_a_harness_it_cannot_imitate(self):
        self.refused("--cost-cap-usd", "0", "--agent", "codex", text="needs --worker live")

    def test_an_unscheduled_run_is_refused(self):
        self.refused("--cost-cap-usd", "0", "--runs", "wip1-b9r9-rep1", text="not a scheduled run")

    def test_a_cap_below_the_first_waves_worst_case_starts_nothing(self):
        self.refused("--cost-cap-usd", "1.00", "--inert-cost-usd", "0.25", "--runs", "wip1-b6r2-rep1",
                     rc=1, text="not started")


class TestWorkerCodeRunsWithoutTheCoordinatorsEnvironment(Tmp):
    """Adversarial pass (every subprocess): the oracle and the merge gate execute worker-written
    code on the coordinator. They hand it a minimal environment and a private HOME and TMPDIR,
    never the coordinator's own (where a harness API key lives)."""

    def test_the_oracle_sees_no_coordinator_secret_and_no_real_home(self):
        taskset = json.loads(TASKSET.read_text(encoding="utf-8"))
        checkout = self.tmp / "ck"
        wip.build_seed(taskset, checkout)
        probe = {"id": "TX", "oracle": (
            "import os, tempfile, unittest\n\n\nclass Oracle(unittest.TestCase):\n"
            "    def test_environment(self):\n"
            # booleans only: a failure must never print the environment it is guarding
            "        self.assertFalse('WIP_CURVE_TEST_SECRET' in os.environ, 'a coordinator variable reached it')\n"
            f"        self.assertFalse(os.environ.get('HOME') == {os.environ.get('HOME', '')!r}, 'the real HOME')\n"
            "        self.assertTrue(tempfile.gettempdir().startswith(os.environ['HOME']), 'a private TMPDIR')\n"
            "        self.assertFalse(len(os.environ) > 12, 'more than the minimal environment')\n")}
        with mock.patch.dict(os.environ, {"WIP_CURVE_TEST_SECRET": "s3cret"}):
            result = wip.run_oracle(checkout, [probe], taskset, self.tmp)
        self.assertEqual(result["exit"], 0, result["tail"])


class TestHostFactsUseTheHardenedGit(Tmp):
    """Adversarial pass (every git call): the host facts every run records read the catalog clone
    through gitexec too, so a command planted in its config never runs."""

    def test_a_planted_fsmonitor_in_the_catalog_never_runs(self):
        repo = self.tmp / "catalog"
        wip.build_seed(json.loads(TASKSET.read_text(encoding="utf-8")), repo)
        marker = self.tmp / "ran.log"
        hook = self.tmp / "hook.sh"
        hook.write_text(f"#!/bin/sh\necho ran >> {marker}\n", encoding="utf-8")
        hook.chmod(0o755)
        subprocess.run(["git", "-C", str(repo), "config", "core.fsmonitor", str(hook)], check=True)
        with mock.patch.object(wip, "ROOT", repo), mock.patch.object(wip.first_run, "ROOT", repo):
            facts = wip.host_facts()
        self.assertFalse(marker.exists(), "a command planted in the catalog's git config ran")
        self.assertEqual(facts["catalog_commit"], wip.git_out(repo, "rev-parse", "HEAD"))
        self.assertIs(facts["catalog_dirty"], False)


class TestGate(Tmp):
    """The merge gate runs the oracle of every task the prefix commit contains, so a later unit
    that breaks a landed one fails the gate even when its own oracle passes."""

    def test_a_regression_of_a_landed_task_fails_the_gate(self):
        taskset = json.loads(TASKSET.read_text(encoding="utf-8"))
        repo = self.tmp / "repo"
        wip.build_seed(taskset, repo)
        t3 = wip.task_by_id(taskset)["T3"]
        wip.apply_edits(repo, t3["reference"])
        wip.git(repo, "commit", "-qam", "T3")
        landed = wip.git_out(repo, "rev-parse", "HEAD")
        landing = self.tmp / "landing.json"
        landing.write_text(json.dumps({"T3": [landed]}), encoding="utf-8")
        gate = ["gate", "--taskset", str(TASKSET), "--landing", str(landing)]
        ok = runner(*gate, cwd=repo)
        self.assertEqual(ok.returncode, 0, ok.stdout)
        self.assertIn("['T3']", ok.stdout)
        units = repo / "stocklib" / "units.py"
        units.write_text(units.read_text(encoding="utf-8").replace('    "lb": 453.59237,\n', ""), encoding="utf-8")
        wip.git(repo, "commit", "-qam", "a later unit drops pounds")
        broken = runner(*gate, cwd=repo)
        self.assertEqual(broken.returncode, 1, broken.stdout)


# ---------------------------------------------------------------------------- the inert pipeline

_DRY_RUNS: dict = {}


def dry_run(run: str, args: tuple, relative: bool = False):
    """(tmp, env, tripwire log, process) of one inert run, made once per module. `relative` runs
    it from the temp directory with --results, --workdir and --prereg given as relative paths."""
    key = (run, args, relative)
    if key not in _DRY_RUNS:
        tmp = tempfile.TemporaryDirectory(prefix="wip-curve-dry-")
        root = Path(tmp.name).resolve()  # a relative path walks the real directories (/var -> /private/var)
        env, trip_log = tripwired_env(root)
        if relative:
            proc = runner("--prereg", os.path.relpath(PREREG, root), "run", "--results", "results", "--runs", run,
                          "--workdir", "wd", *args, env=env, cwd=root)
        else:
            proc = runner("run", "--results", str(root / "results"), "--runs", run, "--workdir",
                          str(root / "wd"), *args, env=env)
        _DRY_RUNS[key] = (tmp, env, trip_log, proc)
    return _DRY_RUNS[key]


B3 = ("wip1-b3r1-rep1", ("--cost-cap-usd", "0"))
B6_CAPPED = ("wip1-b6r2-rep1", ("--cost-cap-usd", "3.40", "--inert-cost-usd", "0.25"))
# b1r1-rep1 builds T5 first. A cap of exactly one unit's worst case (a builder and a reviewer at
# 0.25 each); in the second, the fake harness reports 0.40 for the builder, over its reservation.
B1_BOUNDARY = ("wip1-b1r1-rep1", ("--cost-cap-usd", "0.50", "--inert-cost-usd", "0.25"))
_PLANT_MARKER = Path(tempfile.gettempdir()) / f"wip-curve-plant-{os.getpid()}.log"
# One run serves two findings. T5 lands first, after its builder planted diff.external, a textconv
# and a smudge driver selected by a committed .gitattributes, core.fsmonitor and a hooks directory
# in the SHARED repository config: commands only someone else's git would run, while the
# coordinator diffs, checks out, pushes and merges next to them. T3's builder then also empties
# Ledger.history(): its own oracle passes, T5's fails in the merge gate, so the queue writes a
# real `gate_failed` receipt and T3 is rebuilt.
B1_GATE = ("wip1-b1r1-rep1", ("--cost-cap-usd", "0", "--inert-script", json.dumps(
    {"T5": {"builder": ["plant"]}, "_plant": str(_PLANT_MARKER), "T3": {"builder": ["regress"]}, "_regress": {"T3": [
        {"file": "stocklib/ledger.py", "replace": "        return list(self._history)", "with": ["        return []"]}]}})))
# b3r1-rep1's first wave is T5, T2, T6: T6's builder takes 20 s longer, each review 3 s.
B3_STAGGERED = ("wip1-b3r1-rep1", ("--cost-cap-usd", "0", "--inert-script", json.dumps(
    {"_sleep_task": {"T6": {"builder": 20}}, "_sleep": {"reviewer": 3}})))
# b1r1-rep1: T5's review asks for changes on all three attempts; T3's builder reports failure, and
# T4's dies without reporting. None of them has a failing oracle verdict.
B1_REJECTED = ("wip1-b1r1-rep1", ("--cost-cap-usd", "0", "--inert-script", json.dumps(
    {"T5": {"reviewer": ["changes", "changes", "changes"]}, "T3": {"builder": ["fail"]}, "T4": {"builder": ["die"]}})))
B1_OVERSPEND = ("wip1-b1r1-rep1", ("--cost-cap-usd", "0.50", "--inert-cost-usd", "0.25",
                                   "--inert-script", json.dumps({"_cost": {"builder": "0.40"}})))


def tearDownModule():
    SEAMS["mq_sandbox"].stop()
    SEAMS["live"].stop()
    SEAMS["kept"].stop()
    shutil.rmtree(SEAMS["kept_root"], ignore_errors=True)
    for tmp, *_rest in _DRY_RUNS.values():
        tmp.cleanup()
    if "tmp" in _DOCUMENTED:
        _DOCUMENTED["tmp"].cleanup()
    for _results, _proc, tmp, *_rest in _DOCUMENTED.get("under", {}).values():
        tmp.cleanup()


class DryRun(unittest.TestCase):
    """One inert run per (run, arguments), shared by every class that asks for it (a run takes
    ~20 s); each tamper test works on a copy."""

    RUN, ARGS = B3

    @classmethod
    def setUpClass(cls):
        tmp, cls.env, cls.trip_log, cls.proc = dry_run(cls.RUN, cls.ARGS)
        cls.results = Path(tmp.name) / "results"
        cls.run_dir = cls.results / "runs" / cls.RUN

    def setUp(self):
        self.assertTrue((self.run_dir / "run.json").is_file(), self.proc.stdout + self.proc.stderr)
        self.record = json.loads((self.run_dir / "run.json").read_text(encoding="utf-8"))
        self.addCleanup(self.no_tripwire_hit)

    def no_tripwire_hit(self):
        hits = self.trip_log.read_text() if self.trip_log.exists() else ""
        self.assertEqual(hits, "", f"something resolved a real harness name: {hits!r}")

    def copy(self) -> Path:
        work = Path(tempfile.mkdtemp(prefix="wip-curve-copy-"))
        self.addCleanup(shutil.rmtree, work, True)
        shutil.copytree(self.results, work / "results")
        return work / "results"

    def report(self, results: Path, basis="all"):
        p = runner("report", "--results", str(results), "--basis", basis, env=self.env)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads((results / "report.json").read_text(encoding="utf-8"))

    def verify(self, results: Path):
        return runner("verify", "--results", str(results), "--report", str(results / "report.json"),
                      "--report-md", str(results / "report.md"), env=self.env)


class TestDryRunPipeline(DryRun):
    def test_the_run_completes_through_the_public_wrappers(self):
        self.assertEqual(self.proc.returncode, 0, self.proc.stdout + self.proc.stderr)
        self.assertEqual(self.record["status"], "complete")
        self.assertEqual(self.record["tier"], "fixture-tested", "an inert run is never labelled live")
        used = {Path(c["argv"][1]).name for c in self.record["commands"] if len(c["argv"]) > 1}
        for script in ("task_ops.py", "spawn_worker.sh", "worker_ops.py", "orca_cli.py", "merge_queue.py"):
            self.assertIn(script, used, f"{script} never ran: the run bypassed the public wrapper")
        self.assertEqual(self.record["seed_commit"], json.loads(PREREG.read_text())["taskset"]["seed_commit"])

    def test_the_dry_run_exercises_rework_conflict_and_close(self):
        outcomes = {t: [a["outcome"] for a in u["attempts"]] for t, u in self.record["units"].items()}
        self.assertEqual(outcomes["T1"][0], "changes-requested")
        self.assertEqual(outcomes["T3"][0], "oracle-failed")
        self.assertIn("merge-conflict", outcomes["T2"] + outcomes["T5"])
        self.assertTrue(all(u["final"] == "closed" for u in self.record["units"].values()), outcomes)
        self.assertEqual(wip.merge_counts(wip.Bound(self.run_dir))["conflicts"], 1)

    def test_every_wave_cell_derives_and_the_rows_check(self):
        rep = subprocess.run([sys.executable, str(EVENTS), "--log", str(self.run_dir / "events.jsonl"), "report"],
                             capture_output=True, text=True)
        self.assertEqual(rep.returncode, 0, rep.stdout + rep.stderr)
        chk = subprocess.run([sys.executable, str(EVENTS), "--log", str(self.run_dir / "events.jsonl"), "check",
                              "--run-report", str(self.run_dir / "run-report.md")], capture_output=True, text=True)
        self.assertEqual(chk.returncode, 0, chk.stderr)

    def test_the_report_recomputes_and_every_outcome_binds(self):
        results = self.copy()
        report = self.report(results)
        run = report["runs"][0]
        self.assertEqual(run["binding_problems"], [])
        self.assertEqual(run["metrics"]["conflicts"], 1)
        self.assertIsNotNone(run["metrics"]["throughput"]["value"])
        reviews = sum(len(u["reviews"]) for u in self.record["units"].values())
        self.assertEqual(run["metrics"]["review_usage"]["reviews"], reviews)
        self.assertEqual(run["metrics"]["review_usage"]["observed"], reviews, "a reviewer's usage went unread")
        b3 = next(c for c in report["conditions"] if c["condition"] == "b3r1")
        self.assertEqual(sorted(b3["tasks"]), ["T1", "T2", "T3", "T4", "T5", "T6"])
        p = self.verify(results)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("recomputes", p.stdout)

    def test_the_report_emits_every_registered_metric(self):
        """The registration's metric list, diffed against what the report emits (PR #652's class)."""
        fields = json.loads(PREREG.read_text(encoding="utf-8"))["metrics"]["report_fields"]
        results = self.copy()
        report = self.report(results)
        md = (results / "report.md").read_text(encoding="utf-8")
        for run in report["runs"]:
            self.assertEqual(sorted(run["registered"]), sorted(fields["run"]), run["run_id"])
        for cond in report["conditions"]:
            self.assertEqual(sorted(cond["registered"]), sorted(fields["condition"]), cond["condition"])
        for name in fields["run"] + fields["condition"]:
            self.assertIn(f"`{name}`", md, f"report.md never shows {name}")
        run = report["runs"][0]["registered"]
        self.assertIsNotNone(run["review_queue_median_min"], "the run's reviews have a measurable queue")
        self.assertEqual(run["parked"], {})

    def test_a_fixture_run_is_never_evidence(self):
        report = self.report(self.copy())
        self.assertEqual(report["compliant_runs"], [])
        self.assertIn("not a live run", " ".join(report["runs"][0]["noncompliance"]))
        self.assertTrue(report["evidence"].startswith("none"))
        self.assertEqual(report["recommendation"]["status"], "not-issued")

    def test_an_altered_metric_row_in_the_report_is_detected(self):
        results = self.copy()
        self.report(results)
        md = results / "report.md"
        text = md.read_text(encoding="utf-8")
        row = next(ln for ln in text.splitlines() if ln.startswith(f"| `{self.RUN}`"))
        forged = re.sub(r"\| [0-9.]+/h \|", "| 9.99/h |", row, count=1)
        self.assertNotEqual(forged, row)
        md.write_text(text.replace(row, forged), encoding="utf-8")
        p = self.verify(results)
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("9.99/h", p.stderr)

    def test_an_altered_metric_in_the_report_json_is_detected(self):
        results = self.copy()
        report = self.report(results)
        forged = copy.deepcopy(report)
        forged["runs"][0]["metrics"]["conflicts"] = 0
        (results / "report.json").write_text(json.dumps(forged), encoding="utf-8")
        p = self.verify(results)
        self.assertEqual(p.returncode, 1)
        self.assertIn("$.runs[0].metrics.conflicts", p.stderr)

    def test_an_altered_wave_row_is_caught_by_events_check_even_when_rebound(self):
        results = self.copy()
        self.report(results)
        run_dir = results / "runs" / self.RUN
        rr = run_dir / "run-report.md"
        text = rr.read_text(encoding="utf-8")
        m = re.search(r"`rework=(\d+)/(\d+)`", text)  # wave 1's cell
        forged = f"`rework={0 if m.group(1) != '0' else m.group(2)}/{m.group(2)}`"
        rr.write_text(text.replace(m.group(0), forged, 1), encoding="utf-8")
        rebind(run_dir)  # run.json now binds the edited bytes: only the record can catch it
        p = self.verify(results)
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("events: MISMATCH wave 1 rework", p.stderr)

    def test_an_edited_source_fails_closed(self):
        results = self.copy()
        (results / "runs" / self.RUN / "run-report.md").write_text("edited\n", encoding="utf-8")
        p = runner("report", "--results", str(results), env=self.env)
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("altered after the run", p.stderr)

    def test_an_unbound_file_fails_closed(self):
        results = self.copy()
        (results / "runs" / self.RUN / "oracle" / "extra.json").write_text("{}", encoding="utf-8")
        p = runner("report", "--results", str(results), env=self.env)
        self.assertEqual(p.returncode, 3)
        self.assertIn("unbound file", p.stderr)

    def test_an_edited_event_record_fails_closed_even_when_rebound(self):
        results = self.copy()
        run_dir = results / "runs" / self.RUN
        log = run_dir / "events.jsonl"
        lines = log.read_text(encoding="utf-8").splitlines()
        lines[3] = lines[3].replace('"v":1', '"v": 1', 1)  # the same JSON, other bytes
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        rebind(run_dir)
        p = runner("report", "--results", str(results), env=self.env)
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("prev does not match", p.stderr)


class TestOutcomesBindToGitAndReview(DryRun):
    """Each terminal outcome is re-derived from the retained bundle and artifacts; a forged one
    stops binding, and the run stops being compliant."""

    def problems_after(self, mutate) -> list[str]:
        results = self.copy()
        run_dir = results / "runs" / self.RUN
        mutate(run_dir)
        rebind(run_dir)
        return wip.build_report(results, basis="all")["runs"][0]["binding_problems"]

    def test_a_closed_head_missing_from_the_integration_branch_does_not_bind(self):
        def rewind(run_dir):
            work = run_dir.parent.parent / "rewind"
            wip.git(run_dir.parent, "clone", "-q", "--mirror", str(run_dir / "target.bundle"), str(work))
            seed = json.loads(PREREG.read_text())["taskset"]["seed_commit"]
            wip.git(work, "update-ref", "refs/heads/wip-integration", seed)
            (run_dir / "target.bundle").unlink()
            wip.git(work, "bundle", "create", "-q", str(run_dir / "target.bundle"), "--all")
            shutil.rmtree(work)
        problems = self.problems_after(rewind)
        self.assertTrue(any("not on wip-integration" in p for p in problems), problems)

    def test_a_forged_review_artifact_does_not_bind(self):
        def forge(run_dir):
            for review in (run_dir / "reviews").iterdir():  # rewritten after the review.verdict event
                review.write_text(review.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        problems = self.problems_after(forge)
        self.assertTrue(any("review artifact" in p for p in problems), problems)

    def test_an_altered_oracle_transcript_does_not_bind(self):
        def forge(run_dir):
            path = run_dir / "oracle" / "t4-a1.json"
            doc = json.loads(path.read_text(encoding="utf-8"))
            doc["tail"] = ["edited"]
            path.write_text(json.dumps(doc), encoding="utf-8")
        problems = self.problems_after(forge)
        self.assertTrue(any("oracle transcript" in p for p in problems), problems)

    def test_a_recorded_conflict_git_does_not_reproduce_does_not_bind(self):
        def forge(run_dir):
            rec = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
            seed = json.loads(PREREG.read_text())["taskset"]["seed_commit"]
            for merge in rec["merges"]:
                if merge["result"] == "conflict":
                    merge["against_ref"] = seed  # the unit's own base: it merges cleanly there
            (run_dir / "run.json").write_text(json.dumps(rec), encoding="utf-8")
        problems = self.problems_after(forge)
        self.assertTrue(any("does not re-derive" in p for p in problems), problems)

    def test_a_reviewer_may_dress_its_verdict_line_in_markdown(self):
        nonce, head = "WIP-NONCE:" + "ab" * 8, "c" * 40
        for line in (f"WIP-REVIEW {nonce} {head} approve", f"`WIP-REVIEW {nonce} {head} approve`",
                     f"**WIP-REVIEW {nonce} {head} approve**"):
            self.assertEqual(wip.REVIEW_LINE.search(f"notes\n{line}\n").group(3), "approve", line)
        self.assertIsNone(wip.REVIEW_LINE.search(f"I would say WIP-REVIEW {nonce} {head} approve"),
                          "a verdict inside a sentence is not the verdict line")

    def test_the_untouched_run_binds(self):
        self.assertEqual(self.problems_after(lambda _d: None), [])


class TestGuardIsVerified(Tmp):
    """Every spawned worker's installed deny hook is checked armed (first_run.py's guard step)."""

    def test_an_unarmed_guard_fails_the_run(self):
        wt = self.tmp / "wt"
        (wt / ".claude").mkdir(parents=True)
        block = subprocess.run(["sh", str(ROOT / "runtime" / "scripts" / "deny-hook.sh"), "--settings", str(wt)],
                               capture_output=True, text=True, check=True).stdout
        (wt / ".claude" / "settings.local.json").write_text(block, encoding="utf-8")
        run = wip.Run.__new__(wip.Run)
        run.guard(wt)  # the hook deny-hook.sh itself writes is armed
        doc = json.loads(block)
        for entry in doc["hooks"]["PreToolUse"]:
            for hook in entry["hooks"]:
                hook["command"] = "true # registered but never denies"
        (wt / ".claude" / "settings.local.json").write_text(json.dumps(doc), encoding="utf-8")
        with self.assertRaises(wip.RunFailed):
            run.guard(wt)


class TestTheAssignmentReachesTheLaunch(Tmp):
    """Adversarial pass (inputs that never reach the launch): the unit's assignment, by its nonce,
    must be in the launch the provider recorded; a launch without it is stopped at once and the
    run fails. Every dispatch's effective launch (agent, flags, command digest) is recorded."""

    def spawned(self, launch):
        run = wip.Run.__new__(wip.Run)
        run.launched, run.launches, run.commands, run.rid = {}, {}, [], "wip1-b1r1-rep1"
        run.calls = {}  # no hold: these launches are about the assignment, not the spend
        run.deadline, run.halt = float("inf"), None
        run.dispatch_tags, run.full_hold = {}, {}
        run.args = argparse.Namespace(agent="claude")
        run.guard = lambda _wt: None
        calls = []

        def wrapper(argv, env=None, cwd=None, timeout=600):
            calls.append([str(a) for a in argv])
            out = "DISPATCH=disp_0123456789\nHANDLE=term_x\n" + (f"LAUNCH_EFFECTIVE={json.dumps(launch)}\n" if launch else "")
            return subprocess.CompletedProcess(argv, 0, out, "")
        run.wrapper = wrapper
        return run, calls

    def test_a_launch_without_the_assignment_is_stopped(self):
        run, calls = self.spawned({"agent": "claude", "args": "--dangerously-skip-permissions",
                                   "command": "claude -p --dangerously-skip-permissions 'another task'"})
        with self.assertRaises(wip.RunFailed):
            run.spawn("task_1", self.tmp, "t", "rw", "T1:builder", "WIP-NONCE:" + "a" * 16)
        self.assertTrue(any("stop" in c for c in calls), "the launched worker was not stopped")

    def test_a_launch_the_provider_did_not_record_is_refused(self):
        run, _calls = self.spawned(None)
        with self.assertRaises(wip.RunFailed):
            run.spawn("task_1", self.tmp, "t", "rw", "T1:builder", "WIP-NONCE:" + "a" * 16)

    def test_the_effective_launch_is_recorded(self):
        nonce = "WIP-NONCE:" + "a" * 16
        command = f"claude -p --dangerously-skip-permissions 'WIP-BUILD {nonce} task=T1'"
        run, _calls = self.spawned({"agent": "claude", "args": "--dangerously-skip-permissions", "command": command})
        disp = run.spawn("task_1", self.tmp, "t", "rw", "T1:builder", nonce)
        self.assertEqual(run.launches[disp], {"agent": "claude", "args": "--dangerously-skip-permissions",
                                              "command_sha256": hashlib.sha256(command.encode()).hexdigest()})


class TestCostCapStopsTheExperiment(DryRun):
    """The inert stand-in reports a synthetic 0.25 USD per dispatch (not a spend) so the cap is
    reached: six builders and six reviewers spend 3.00 of 3.40, the four bounced units' next wave
    would need 2.00 more, so the run parks them and stays derivable, and no further run starts."""

    RUN, ARGS = B6_CAPPED

    def test_the_run_stops_and_parks_every_unit_in_flight(self):
        self.assertEqual(self.record["status"], "stopped", self.proc.stdout + self.proc.stderr)
        self.assertEqual(self.record["stop_reason"], "cost-cap")
        parked = {t: u["park_class"] for t, u in self.record["units"].items() if u["final"] == "parked"}
        self.assertTrue(parked)
        self.assertEqual(set(parked.values()), {"stopped-cost-cap"})
        self.assertEqual(Decimal(self.record["cost"]["observed_usd"]), Decimal("3.00"))
        rep = subprocess.run([sys.executable, str(EVENTS), "--log", str(self.run_dir / "events.jsonl"), "report"],
                             capture_output=True, text=True)
        self.assertEqual(rep.returncode, 0, "a stopped run's record must still derive every cell\n" + rep.stdout)
        self.assertIn("reviewers=2", rep.stdout)

    def test_a_parked_head_git_does_not_hold_does_not_bind(self):
        parked = [a["head"] for u in self.record["units"].values() if u["final"] == "parked"
                  for a in u["attempts"][-1:] if a.get("head")]
        self.assertTrue(parked)
        results = self.copy()
        run_dir = results / "runs" / self.RUN
        self.assertEqual(wip.build_report(results, basis="all")["runs"][0]["binding_problems"], [])
        work = results.parent / "drop"
        wip.git(run_dir, "clone", "-q", "--mirror", str(run_dir / "target.bundle"), str(work))
        refs = wip.git_out(work, "for-each-ref", "--format=%(refname)", "--points-at", parked[0]).split()
        for ref in refs:
            wip.git(work, "update-ref", "-d", ref)
        (run_dir / "target.bundle").unlink()
        wip.git(work, "bundle", "create", "-q", str(run_dir / "target.bundle"), "--all")
        rebind(run_dir)
        problems = wip.build_report(results, basis="all")["runs"][0]["binding_problems"]
        self.assertTrue(any("does not hold that head" in p for p in problems), problems)

    def test_a_stopped_run_is_reported_not_dropped(self):
        results = self.copy()
        report = wip.build_report(results, basis="all")
        run = report["runs"][0]
        self.assertEqual(run["status"], "stopped")
        self.assertIn("the run ended stopped (cost-cap)", run["noncompliance"])

    def test_no_further_run_starts_past_the_cap(self):
        results = self.copy()
        # 3.00 spent; even the serial next run's first wave (2 x 0.25) would pass 3.40.
        p = runner("run", "--results", str(results), "--cost-cap-usd", "3.40", "--inert-cost-usd", "0.25",
                   "--next", "1", "--workdir", str(results.parent / "wd2"), env=self.env)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("not started", p.stderr)
        self.assertEqual([d.name for d in (results / "runs").iterdir()], [self.RUN])

    def test_a_stream_with_any_unreported_cost_is_unobserved(self):
        stream = Path(tempfile.mkdtemp(prefix="wip-curve-stream-")) / "s.jsonl"
        self.addCleanup(shutil.rmtree, stream.parent, True)
        stream.write_text(json.dumps({"type": "result", "result": "a", "total_cost_usd": 0.5}) + "\n"
                          + json.dumps({"type": "result", "result": "b"}) + "\n", encoding="utf-8")
        self.assertIsNone(wip.Run.stream_cost(stream), "a partial sum is not the dispatch's cost")
        stream.write_text(json.dumps({"type": "result", "result": "a", "total_cost_usd": 0.5}) + "\n",
                          encoding="utf-8")
        self.assertEqual(wip.Run.stream_cost(stream), Decimal("0.5"))

    def test_an_unobserved_dispatch_is_charged_the_reservation(self):
        tmp = Path(tempfile.mkdtemp(prefix="wip-curve-ledger-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        run = bare_run(tmp, reservation="2.00")
        run.budget.charge("earlier/T1/a1/builder", Decimal("1.00"), True, run="earlier")
        run.dispatch_row = lambda _d: {"lane_dir": None}  # no stream retained: nothing observed
        self.assertEqual(run.ingest_usage("disp_x", "task_x"), Decimal("2.00"))
        self.assertEqual(run.ingest_usage("disp_x", "task_x"), Decimal(0), "one dispatch is charged once")
        self.assertEqual(wip.spent_in(tmp / "results"), Decimal("3.00"))
        self.assertEqual(run.run_cost()["reserved_unobserved_usd"], "2.00", "its run's cost is its own calls")


class TestComplianceNeedsLiveBoundEvidence(unittest.TestCase):
    """A run counts toward the curve only when it is live, pinned, from the seed and cooled down:
    fixture runs relabelled as live show each rule catching what it is for."""

    @classmethod
    def setUpClass(cls):
        cls.env = dry_run(*B3)[1]
        cls.sources = [Path(dry_run(*key)[0].name) / "results" / "runs" / key[0] for key in (B3, B6_CAPPED)]

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="wip-curve-compliance-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        for src in self.sources:
            self.assertTrue((src / "run.json").is_file())
            shutil.copytree(src, self.tmp / "runs" / src.name)

    def edit(self, run, **fields):
        path = self.tmp / "runs" / run / "run.json"
        rec = json.loads(path.read_text(encoding="utf-8"))
        rec.update(fields)
        path.write_text(json.dumps(rec), encoding="utf-8")  # run.json binds; it is not bound itself

    def runs(self):
        return {r["run_id"]: r for r in wip.build_report(self.tmp, basis="all")["runs"]}

    def test_a_run_that_did_not_keep_the_cooldown_is_not_compliant(self):
        live = {"tier": "live-unreviewed", "worker": "live"}
        self.edit(B3[0], started_at="2026-10-24T10:00:00+00:00", finished_at="2026-10-24T11:00:00+00:00", **live)
        self.edit(B6_CAPPED[0], started_at="2026-10-24T11:01:00+00:00", finished_at="2026-10-24T12:00:00+00:00",
                  **live)
        runs = self.runs()
        self.assertTrue(any("the cooldown is 600s" in why for why in runs[B6_CAPPED[0]]["noncompliance"]),
                        runs[B6_CAPPED[0]]["noncompliance"])
        self.assertFalse(any("cooldown" in why for why in runs[B3[0]]["noncompliance"]))

    def test_an_observed_model_other_than_the_pin_is_not_compliant(self):
        self.edit(B3[0], model_pin="claude-pinned", harness={"version": "1.0"})
        why = self.runs()[B3[0]]["noncompliance"]
        self.assertIn("observed model(s) ['inert-stand-in'] are not the pin 'claude-pinned'", why)
        self.edit(B3[0], model_pin="inert-stand-in")
        self.assertFalse(any("not the pin" in w for w in self.runs()[B3[0]]["noncompliance"]))

    def test_a_run_on_other_experiment_inputs_is_not_compliant(self):
        live = {"tier": "live-unreviewed", "worker": "live"}
        self.edit(B3[0], started_at="2026-10-24T10:00:00+00:00", finished_at="2026-10-24T11:00:00+00:00", **live)
        self.edit(B6_CAPPED[0], started_at="2026-10-24T12:00:00+00:00", finished_at="2026-10-24T13:00:00+00:00",
                  inputs={"sha256": "f" * 64, "files": {}}, **live)
        why = self.runs()[B6_CAPPED[0]]["noncompliance"]
        self.assertTrue(any("experiment inputs" in w for w in why), why)

    def test_a_run_that_did_not_start_at_the_seed_does_not_bind(self):
        self.edit(B3[0], seed_commit="0" * 40)
        problems = self.runs()[B3[0]]["binding_problems"]
        self.assertTrue(any("not the registered seed commit" in p for p in problems), problems)


class TestSpendIsReservedBeforeEachDispatch(Tmp):
    """The ledger admits a dispatch only while measured spend, unobserved charges and every held
    reservation, this dispatch's included, stay within the cap: the exact boundary is admitted,
    a cent over is not."""

    def ledger(self, cap, spent_before="0"):
        run = bare_run(self.tmp / cap, cap=cap)
        if Decimal(spent_before):
            run.budget.charge("earlier/T1/a1/builder", Decimal(spent_before), True, run="earlier")
        return run

    def test_the_exact_boundary_is_admitted_and_a_cent_over_is_not(self):
        run = self.ledger("0.50")
        self.assertTrue(run.hold_unit("T1"))  # builder + reviewer, 0.50 of 0.50
        self.assertTrue(run.admit("T1:builder"))
        self.assertFalse(self.ledger("0.49").hold_unit("T1"))

    def test_a_measured_overspend_refuses_the_next_dispatch_before_it_starts(self):
        run = self.ledger("0.50")
        self.assertTrue(run.hold_unit("T1"))
        run.settle("T1:builder", Decimal("0.40"))  # the builder spent past its 0.25 reservation
        self.assertEqual(run.committed(), Decimal("0.65"))
        self.assertFalse(run.admit("T1:reviewer"), "a reviewer may not start once the cap is passed")
        self.assertEqual(run.committed(), Decimal("0.40"), "a refused dispatch releases its hold")

    def test_spend_before_this_run_counts(self):
        self.assertFalse(self.ledger("0.50", spent_before="0.01").hold_unit("T1"))


class TestOneSharedLedger(Tmp):
    """PR #653 review (Buw/Buy): one ledger per results directory. A call is charged once by its
    identity, a unit's holds are taken all or none, and holds taken at the same moment by
    separate processes never commit past the cap."""

    def test_a_call_is_charged_once_whatever_settles_it_again(self):
        budget = wip.Budget(self.tmp)
        self.assertTrue(budget.hold([("r/T1/a1/builder", {"run": "r"})], Decimal("0.25"), Decimal("1")))
        self.assertTrue(budget.charge("r/T1/a1/builder", Decimal("0.40"), True))
        self.assertFalse(budget.charge("r/T1/a1/builder", Decimal("0.25"), False), "a second charge was recorded")
        self.assertFalse(budget.release("r/T1/a1/builder"), "a charged call was released")
        budget.note("r/T1/a1/builder", state="launched", dispatch="d")  # a late note cannot reopen it
        self.assertEqual(budget.calls()["r/T1/a1/builder"]["state"], "charged")
        self.assertEqual(budget.total(), Decimal("0.40"))

    def test_a_unit_is_held_all_or_none(self):
        budget = wip.Budget(self.tmp)
        entries = [("r/T1/a1/builder", {"run": "r"}), ("r/T1/a1/reviewer", {"run": "r"})]
        self.assertFalse(budget.hold(entries, Decimal("0.25"), Decimal("0.49")))
        self.assertEqual(budget.calls(), {})
        self.assertTrue(budget.hold(entries, Decimal("0.25"), Decimal("0.50")))
        with self.assertRaises(wip.RunFailed):  # an identity is never reused, so never charged twice
            budget.hold(entries[:1], Decimal("0.25"), Decimal("10"))

    def test_a_read_never_creates_the_ledger(self):
        self.assertEqual((wip.spent_in(self.tmp / "results"), wip.Budget(self.tmp / "results").calls()),
                         (Decimal(0), {}))
        self.assertFalse((self.tmp / "results").exists())

    def test_an_unreadable_record_refuses_every_spend(self):
        budget = wip.Budget(self.tmp)
        budget.charge("r/T1/a1/builder", Decimal("0.25"), True, run="r")
        with budget.path.open("a", encoding="utf-8") as fh:
            fh.write("{torn\n")
        with self.assertRaises(wip.SourceError):
            budget.hold([("r/T2/a1/builder", {"run": "r"})], Decimal("0.25"), Decimal("10"))

    def test_concurrent_holds_never_pass_the_cap(self):
        # eight processes each hold a unit (2 x 0.25) against a 2.00 cap at the same moment:
        # exactly four fit, whatever the interleaving
        code = ("import importlib.util, os, sys, time; from decimal import Decimal\n"
                "s = importlib.util.spec_from_file_location('w', sys.argv[1]); m = importlib.util.module_from_spec(s)\n"
                "s.loader.exec_module(m); r, go = sys.argv[3], sys.argv[4]\n"
                "open(go + '.' + r, 'w').close()\n"
                "while not os.path.exists(go): time.sleep(0.0005)\n"  # every process holds at the same moment
                "print(m.Budget(sys.argv[2]).hold([(r + '/b', {'run': r}), (r + '/r', {'run': r})], "
                "Decimal('0.25'), Decimal('2.00')))")
        go = self.tmp / "go"
        procs = [subprocess.Popen([sys.executable, "-c", code, str(RUNNER), str(self.tmp / "results"), f"run{i}",
                                   str(go)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for i in range(8)]
        deadline = time.monotonic() + 120
        while len(list(self.tmp.glob("go.run*"))) < 8 and time.monotonic() < deadline:
            time.sleep(0.01)
        go.touch()
        outs = [p.communicate(timeout=120) for p in procs]
        self.assertEqual(sorted(o.strip() for o, _e in outs), ["False"] * 4 + ["True"] * 4, outs)
        self.assertEqual(wip.Budget(self.tmp / "results").total(), Decimal("2.00"))


class TestReviewsStartAsBuildersFinish(DryRun):
    """PR #653 review (Bu0): reviewers=<n> is the number of reviews in flight, and a done unit
    waits in worker_done order for a free reviewer slot (reviewer_availability), never for the
    wave's slowest builder. Two quick units also contend for the one reviewer."""

    RUN, ARGS = B3_STAGGERED

    def first_wave(self):
        events = [json.loads(line) for line in (self.run_dir / "events.jsonl").read_text().splitlines()]
        tid_of = {u["store_task"]: t for t, u in self.record["units"].items()}
        def at(event):
            return datetime.fromisoformat(event["observed_at"])

        done, started, verdicts = {}, {}, {}
        for e in events:
            tid = tid_of.get(e.get("task"))
            if e["kind"] == "task.done" and tid:
                done.setdefault(tid, at(e))
            elif e["kind"] == "review.started" and tid:
                started.setdefault(tid, (at(e), e["dispatch"]))
            elif e["kind"] == "review.verdict":
                verdicts[e["dispatch"]] = at(e)
        return done, started, verdicts

    def test_a_done_unit_is_reviewed_while_a_slower_builder_runs(self):
        done, started, _verdicts = self.first_wave()
        for tid in ("T5", "T2"):
            self.assertLess(started[tid][0], done["T6"],
                            f"{tid}'s review waited for T6's builder although the reviewer was free")

    def test_the_reviewer_cap_holds_and_arrival_order_is_kept(self):
        done, started, verdicts = self.first_wave()
        spans = sorted((s, verdicts[d]) for s, d in started.values())
        for (_s1, end), (s2, _e2) in zip(spans, spans[1:], strict=False):
            self.assertGreaterEqual(s2, end, "two reviews were in flight with reviewers=1")
        wave1 = ["T5", "T2", "T6"]
        self.assertEqual(sorted(wave1, key=lambda t: started[t][0]), sorted(wave1, key=lambda t: done[t]),
                         "reviews did not start in worker_done order")


def bounced_unit_waves(record) -> tuple[int, int]:
    """(bounced, all) unit-waves from the run record: an attempt that ended neither landed nor
    stopped by a halt is bounced, and so is every re-dispatch (attempt > 1), as events.py counts it."""
    attempts = [a for u in record["units"].values() for a in u["attempts"]]
    bounced = [a for a in attempts if (a["outcome"] != "landed" and not (a["outcome"] or "").startswith("stopped-"))
               or a["n"] > 1]
    return len(bounced), len(attempts)


class TestEveryBouncedAttemptIsRework(DryRun):
    """PR #653 review (lic): rework is the share of unit-waves bounced, and a bounce is any attempt
    that does not land: a review that asks for changes or gives no verdict, a builder failure, a
    merge conflict or a failed merge gate count in their own wave, as a failing oracle does, the
    last attempt before a park included."""

    RUN, ARGS = B1_REJECTED

    def test_a_task_rejected_on_every_attempt_counts_every_rejection(self):
        t5 = self.record["units"]["T5"]
        self.assertEqual(([a["outcome"] for a in t5["attempts"]], t5["park_class"]),
                         (["changes-requested"] * 3, "attempts-exhausted"))
        rework = self.report(self.copy())["runs"][0]["metrics"]["rework"]
        self.assertEqual((rework["bounced"], rework["units"]), bounced_unit_waves(self.record))
        self.assertEqual(bounced_unit_waves(self.record), (7, 10))  # T5 x3, T3 x2, T4 x2 of 10

    def test_every_dry_run_counts_what_its_record_bounced(self):
        # a failing oracle (B3), a merge conflict (B3), a failed merge gate (B1_GATE), a cost-cap stop
        # (B6_CAPPED) and a review queue (B3_STAGGERED)
        for fixture in (B3, B1_GATE, B6_CAPPED, B3_STAGGERED):
            with self.subTest(run=fixture[0], args=fixture[1][:2]):
                tmp = Path(dry_run(*fixture)[0].name)
                record = json.loads((tmp / "results" / "runs" / fixture[0] / "run.json").read_text(encoding="utf-8"))
                work = Path(tempfile.mkdtemp(prefix="wip-curve-rework-"))
                self.addCleanup(shutil.rmtree, work, True)
                shutil.copytree(tmp / "results", work / "results")
                rework = self.report(work / "results")["runs"][0]["metrics"]["rework"]
                self.assertEqual((rework["bounced"], rework["units"]), bounced_unit_waves(record))


class TestExactCapBoundary(DryRun):
    RUN, ARGS = B1_BOUNDARY

    def test_a_cap_that_exactly_covers_one_unit_runs_it_and_no_more(self):
        self.assertEqual(self.record["status"], "stopped", self.proc.stdout + self.proc.stderr)
        self.assertEqual(self.record["stop_reason"], "cost-cap")
        t5 = self.record["units"]["T5"]
        self.assertEqual((t5["final"], len(t5["attempts"]), len(t5["reviews"])), ("closed", 1, 1))
        self.assertEqual(Decimal(self.record["cost"]["observed_usd"]), Decimal("0.50"))
        self.assertEqual(sorted(self.record["not_run"]), ["T1", "T2", "T3", "T4", "T6"])


class TestAnOverspentBuilderGetsNoReviewer(DryRun):
    """A fake harness reports 0.40 for a builder reserved at 0.25: the reviewer that would take
    the run to 0.65 of 0.50 is refused BEFORE it starts, so the cap is never passed."""

    RUN, ARGS = B1_OVERSPEND

    def test_the_reviewer_is_refused_and_the_unit_parked(self):
        t5 = self.record["units"]["T5"]
        self.assertEqual(t5["reviews"], [], "a reviewer was dispatched past the cap")
        self.assertEqual(t5["attempts"][0]["outcome"], "stopped-cost-cap")
        self.assertEqual((t5["final"], t5["park_class"]), ("parked", "stopped-cost-cap"))
        spent = Decimal(self.record["cost"]["observed_usd"]) + Decimal(self.record["cost"]["reserved_unobserved_usd"])
        self.assertEqual(spent, Decimal("0.40"))
        self.assertLessEqual(spent, Decimal(self.record["cost"]["cap_usd"]))
        rep = subprocess.run([sys.executable, str(EVENTS), "--log", str(self.run_dir / "events.jsonl"), "report"],
                             capture_output=True, text=True)
        self.assertNotIn("unavailable", rep.stdout.split("Derived by")[0], "the stopped run must stay derivable")


class TestNoWriteTouchesTheRepository(Tmp):
    """Every path the runner writes to, or later deletes, is refused when it resolves to, inside
    or around the repository's sources or the registered task set, symlinks followed; and a
    sandbox is only ever a fresh directory, never one that already holds something."""

    def setUp(self):
        super().setUp()
        self.env, self.trip_log = tripwired_env(self.tmp)
        self.addCleanup(lambda: self.assertFalse(self.trip_log.exists(), "a refused run reached a harness"))

    def link(self, name, target):
        path = self.tmp / name
        path.symlink_to(target, target_is_directory=Path(target).is_dir())
        return path

    def test_the_overlap_check_refuses_sources_seed_and_symlinks(self):
        refused = [ROOT / "docs" / "experiments" / "out", ROOT / "scripts", ROOT, ROOT.parent, TASKSET, PREREG,
                   ROOT / "skills" / "ship-it", self.link("into-runtime", ROOT / "runtime") / "x",
                   self.link("into-tests", ROOT / "tests")]
        for path in refused:
            with self.subTest(path=str(path)), self.assertRaises(wip.Refused):
                wip.check_writable(path, "--results")
        wip.check_writable(self.tmp / "results", "--results")  # an unrelated directory is fine

    def test_a_report_into_a_symlink_to_the_docs_is_refused_and_writes_nothing(self):
        out = self.link("out", ROOT / "docs" / "experiments")
        results = Path(dry_run(*B1_BOUNDARY)[0].name) / "results"
        p = runner("report", "--results", str(results), "--out", str(out), "--basis", "all", env=self.env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertFalse((ROOT / "docs" / "experiments" / "report.json").exists())

    def test_a_report_file_that_is_a_link_into_the_sources_is_refused(self):
        out = self.tmp / "out"
        out.mkdir()
        before = TASKSET.read_bytes()
        (out / "report.json").symlink_to(TASKSET)
        results = Path(dry_run(*B1_BOUNDARY)[0].name) / "results"
        p = runner("report", "--results", str(results), "--out", str(out), "--basis", "all", env=self.env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertEqual(TASKSET.read_bytes(), before, "the report overwrote the registered task set")

    def test_any_existing_link_as_a_report_file_is_refused(self):
        out = self.tmp / "out"
        out.mkdir()
        elsewhere = self.tmp / "elsewhere.md"
        elsewhere.write_text("not a report\n", encoding="utf-8")
        (out / "report.md").symlink_to(elsewhere)
        results = Path(dry_run(*B1_BOUNDARY)[0].name) / "results"
        p = runner("report", "--results", str(results), "--out", str(out), "--basis", "all", env=self.env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertEqual(elsewhere.read_text(encoding="utf-8"), "not a report\n")

    def test_a_run_into_a_symlink_to_the_docs_is_refused_and_writes_nothing(self):
        results = self.link("results", ROOT / "docs")
        p = runner("run", "--results", str(results), "--workdir", str(self.tmp / "wd"), "--runs",
                   "wip1-b1r1-rep1", "--cost-cap-usd", "0.50", "--inert-cost-usd", "0.25", env=self.env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertFalse((ROOT / "docs" / "runs" / "wip1-b1r1-rep1").exists())

    def test_a_runs_directory_linked_into_the_sources_is_refused(self):
        results = self.tmp / "results"
        results.mkdir()
        (results / "runs").symlink_to(ROOT / "docs" / "runs")
        p = runner("run", "--results", str(results), "--workdir", str(self.tmp / "wd"), "--runs",
                   "wip1-b1r1-rep1", "--cost-cap-usd", "0.50", "--inert-cost-usd", "0.25", env=self.env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertFalse((ROOT / "docs" / "runs" / "wip1-b1r1-rep1").exists())

    def test_a_sandbox_that_already_holds_something_is_refused_and_kept(self):
        keep = self.tmp / "wd" / "wip1-b6r1-rep1" / "keep.txt"
        keep.parent.mkdir(parents=True)
        keep.write_text("not the runner's", encoding="utf-8")
        p = runner("run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"), "--runs",
                   "wip1-b6r1-rep1", "--cost-cap-usd", "0", "--inert-script", "{}", env=self.env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertTrue(keep.is_file(), "a complete run deleted a directory it did not create")

    def test_the_whole_checkout_is_protected(self):
        # Codex review (C5): .github/, assets/ and any new directory are the checkout too
        for path in (ROOT / ".github" / "x", ROOT / "assets" / "badges" / "x", ROOT / "wip-results",
                     self.link("into-github", ROOT / ".github") / "x"):
            with self.subTest(path=str(path)), self.assertRaises(wip.Refused):
                wip.check_writable(path, "--results")

    def test_a_sandbox_that_is_a_link_is_refused_and_nothing_is_written_through_it(self):
        # PR #653 review (lig): <workdir>/<run id> linked to an empty directory elsewhere
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        (self.tmp / "wd").mkdir()
        (self.tmp / "wd" / "wip1-b1r1-rep1").symlink_to(elsewhere, target_is_directory=True)
        p = runner("run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"), "--runs",
                   "wip1-b1r1-rep1", "--cost-cap-usd", "0.50", "--inert-cost-usd", "0.25", env=self.env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("symbolic link", p.stderr)
        self.assertEqual(list(elsewhere.iterdir()), [], "the run wrote through the sandbox link")

    def test_a_report_and_a_verification_never_write_into_the_results(self):
        results = self.tmp / "results"
        shutil.copytree(Path(dry_run(*B1_BOUNDARY)[0].name) / "results", results)
        (results / wip.LOCK_NAME).unlink()
        before = sorted(p.name for p in results.iterdir())
        out = self.tmp / "out"
        p = runner("report", "--results", str(results), "--out", str(out), "--basis", "all", env=self.env)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        p = runner("verify", "--results", str(results), "--report", str(out / "report.json"), env=self.env)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(sorted(p.name for p in results.iterdir()), before, "a read wrote into --results")

    def test_a_recovery_never_writes_through_a_sandbox_the_ledger_names(self):
        # the ledger's record of a lost run names a link: the recovery refuses, never creates through it
        elsewhere = self.tmp / "elsewhere"
        (elsewhere / "target").mkdir(parents=True)
        link = self.link("sandbox-link", elsewhere)
        results = self.tmp / "results"
        (results / "runs" / "wip1-b1r1-rep1").mkdir(parents=True)
        budget = wip.Budget(results)
        budget.start_run("wip1-b1r1-rep1", link, "inert")
        budget.hold([("wip1-b1r1-rep1/T5/a1/builder", {"run": "wip1-b1r1-rep1"})], Decimal("0.25"), Decimal("10"))
        p = runner("run", "--results", str(results), "--workdir", str(self.tmp / "wd"), "--runs",
                   "wip1-b3r1-rep1", "--cost-cap-usd", "0", env=self.env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertEqual(sorted(x.name for x in elsewhere.iterdir()), ["target"], "the recovery wrote through the link")

    def test_a_builder_cannot_point_the_review_inputs_outside_the_worktree(self):
        # a builder commits .wip-review as a link: the runner's review inputs never follow it
        escape = self.tmp / "escape"
        escape.mkdir()
        script = {"T5": {"builder": ["link_review"]}, "_review_link": str(escape)}
        p = runner("run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"), "--runs",
                   "wip1-b1r1-rep1", "--cost-cap-usd", "0.50", "--inert-cost-usd", "0.25",
                   "--inert-script", json.dumps(script), env=self.env)
        self.assertEqual(list(escape.iterdir()), [], "review inputs were written through the builder's link")
        record = json.loads((self.tmp / "results" / "runs" / "wip1-b1r1-rep1" / "run.json").read_text(encoding="utf-8"))
        t5 = record["units"]["T5"]
        self.assertEqual((t5["attempts"][0]["outcome"], t5["reviews"]), ("review-failed", []), p.stdout + p.stderr)

    def test_results_inside_the_sandbox_it_deletes_are_refused(self):
        wd = self.tmp / "wd"
        results = wd / "wip1-b6r1-rep1" / "results"
        p = runner("run", "--results", str(results), "--workdir", str(wd), "--runs", "wip1-b6r1-rep1",
                   "--cost-cap-usd", "0", "--inert-script", "{}", env=self.env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertFalse(results.exists())


class TestRegisteredInputsBlockARun(Tmp):
    """A change to anything the experiment depends on blocks a run until it is re-registered."""

    def setUp(self):
        super().setUp()
        self.env, self.trip_log = tripwired_env(self.tmp)

    def test_a_seed_the_task_set_does_not_build_is_refused_before_a_run_starts(self):
        prereg = json.loads(PREREG.read_text(encoding="utf-8"))
        prereg["taskset"]["path"] = str(TASKSET)
        prereg["taskset"]["seed_commit"] = "0" * 40
        path = self.tmp / "prereg.json"
        path.write_text(json.dumps(prereg), encoding="utf-8")
        p = runner("--prereg", str(path), "run", "--results", str(self.tmp / "results"), "--workdir",
                   str(self.tmp / "wd"), "--runs", "wip1-b1r1-rep1", "--cost-cap-usd", "0", env=self.env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("seed_commit", p.stderr)
        self.assertFalse((self.tmp / "results" / "runs").exists(), "a refused run left a run record")

    def test_results_under_another_registration_refuse_the_next_run(self):
        src = Path(dry_run(*B1_BOUNDARY)[0].name) / "results" / "runs" / B1_BOUNDARY[0]
        results = self.tmp / "results"
        shutil.copytree(src, results / "runs" / src.name)
        rec = json.loads((results / "runs" / src.name / "run.json").read_text(encoding="utf-8"))
        rec["prereg"]["sha256"] = "e" * 64  # a run made under an earlier registration
        (results / "runs" / src.name / "run.json").write_text(json.dumps(rec), encoding="utf-8")
        p = runner("run", "--results", str(results), "--workdir", str(self.tmp / "wd"), "--runs", "wip1-b3r1-rep1",
                   "--cost-cap-usd", "0", env=self.env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("re-register", p.stderr)
        self.assertEqual([d.name for d in (results / "runs").iterdir()], [src.name])

    def test_uncommitted_experiment_inputs_are_named(self):
        repo = self.tmp / "repo"
        for rel in ("scripts/wip_curve.py", "docs/experiments/wip-curve-prereg.json", "README.md"):
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text("v1\n", encoding="utf-8")
        wip.git(repo, "init", "-q")
        wip.git(repo, "add", "-A")
        wip.git(repo, "-c", "user.email=t@t.invalid", "-c", "user.name=t", "commit", "-qm", "seed")
        self.assertEqual(wip.dirty_inputs(repo), [])
        (repo / "scripts" / "wip_curve.py").write_text("v2\n", encoding="utf-8")
        (repo / "README.md").write_text("v2\n", encoding="utf-8")  # not an experiment input
        self.assertEqual(wip.dirty_inputs(repo), ["scripts/wip_curve.py"])

    def test_the_shared_call_helper_is_an_experiment_input(self):
        # PR #668 review (Greptile): every oracle call runs under scripts/_ablation_run.py's watchdog,
        # timeouts and sweep, so a change there changes how a run is contained and timed. It is
        # digested with the runner, and a live run refuses while it is uncommitted.
        repo = self.tmp / "repo"
        for rel in ("scripts/wip_curve.py", "scripts/_ablation_run.py", "README.md"):
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text("v1\n", encoding="utf-8")
        wip.git(repo, "init", "-q")
        wip.git(repo, "add", "-A")
        wip.git(repo, "-c", "user.email=t@t.invalid", "-c", "user.name=t", "commit", "-qm", "seed")
        (repo / "scripts" / "_ablation_run.py").write_text("v2\n", encoding="utf-8")
        self.assertEqual(wip.dirty_inputs(repo), ["scripts/_ablation_run.py"])
        files = wip.experiment_inputs()["files"]
        self.assertEqual(files.get("scripts/_ablation_run.py"),
                         hashlib.sha256((ROOT / "scripts" / "_ablation_run.py").read_bytes()).hexdigest())

    def test_a_live_run_refuses_uncommitted_inputs_before_anything_starts(self):
        # In-process with dirty_inputs faked. Were the check gone, the cost pre-check (a cap of 1.00
        # below the first wave's 2.00) would still stop the run before any harness: rc 1, not 2.
        err = io.StringIO()
        with mock.patch.object(wip, "dirty_inputs", return_value=["scripts/wip_curve.py"]), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = wip.main(["run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"),
                           "--worker", "live", "--model", "m", "--cost-cap-usd", "1.00", "--reservation-usd",
                           "1.00", "--runs", "wip1-b1r1-rep1"])
        self.assertEqual(rc, 2, err.getvalue())
        self.assertIn("uncommitted: ['scripts/wip_curve.py']", err.getvalue())
        self.assertFalse((self.tmp / "results" / "runs").exists())

    def test_every_run_records_the_digest_of_its_inputs(self):
        record = json.loads((Path(dry_run(*B1_BOUNDARY)[0].name) / "results" / "runs" / B1_BOUNDARY[0]
                             / "run.json").read_text(encoding="utf-8"))
        files = record["inputs"]["files"]
        for rel in ("scripts/wip_curve.py", "docs/experiments/wip-curve-prereg.json",
                    "docs/experiments/wip-curve-taskset.json", "runtime/scripts/events.py",
                    "runtime/providers/posix.py"):
            self.assertEqual(files[rel], hashlib.sha256((ROOT / rel).read_bytes()).hexdigest(), rel)
        self.assertEqual(record["inputs"]["sha256"], wip.experiment_inputs()["sha256"])


class TestMergeQueueFailuresAreCounted(Tmp):
    """Conflicts and gate failures come from the merge queue's own receipts, as it writes them:
    a real failed-gate receipt (reason `gate_failed`) counts once, never as zero."""

    def receipts_with_a_failed_gate(self) -> Path:
        mq = [sys.executable, str(ROOT / "runtime" / "scripts" / "merge_queue.py"), "--db", str(self.tmp / "mq.db"),
              "--repo-dir", str(self.tmp / "clone")]
        env = {**os.environ, "OPEN_FLEET_STATE_DIR": str(self.tmp / "mq-state")}
        _ensure_test_mq_sandbox(env, self.tmp)
        wip.git(self.tmp, "init", "-q", "--bare", str(self.tmp / "origin.git"))
        seed = self.tmp / "seed"
        wip.build_seed(json.loads(TASKSET.read_text(encoding="utf-8")), seed)
        wip.git(seed, "push", "-q", str(self.tmp / "origin.git"), "main:refs/heads/main", "main:refs/heads/wip-integration")
        wip.git(self.tmp, "clone", "-q", str(self.tmp / "origin.git"), str(self.tmp / "clone"))
        clone = self.tmp / "clone"
        wip.configure_repo(clone)
        wip.git(clone, "checkout", "-q", "-b", "unit", "origin/wip-integration")
        (clone / "NOTES.md").write_text("a unit\n", encoding="utf-8")
        wip.git(clone, "add", "NOTES.md")
        wip.git(clone, "commit", "-qm", "unit")
        wip.git(clone, "push", "-q", "origin", "unit")
        head = wip.git_out(clone, "rev-parse", "HEAD")

        def call(*args):
            out = subprocess.run([*mq, *args], capture_output=True, text=True, env=env)
            return json.loads(out.stdout)
        call("init", "--base", "wip-integration", "--default", "main", "--consent", "test", "--mode", "git")
        token = call("acquire", "--base", "wip-integration", "--holder", "t")["token"]
        call("enqueue", "--token", token, "--payload", json.dumps(
            {"unit": "u1", "branch": "unit", "base": "wip-integration", "reviewed_sha": head, "pr": None}))
        call("release", "--token", token)
        drained = call("drain", "--base", "wip-integration", "--holder", "t", "--gate-cmd", "exit 1", "--ack")
        self.assertEqual((drained.get("data") or {}).get("reason"), "gate_failed", drained)
        run_dir = self.tmp / "run"
        run_dir.mkdir()
        (run_dir / "merge-receipts.json").write_text(json.dumps(call("receipts", "--base", "wip-integration")),
                                                    encoding="utf-8")
        (run_dir / "run.json").write_text(json.dumps({"run_id": "r", "sources": {
            "merge-receipts.json": hashlib.sha256((run_dir / "merge-receipts.json").read_bytes()).hexdigest()}}),
            encoding="utf-8")
        return run_dir

    def test_a_real_failed_gate_receipt_counts_as_a_gate_failure(self):
        counts = wip.merge_counts(wip.Bound(self.receipts_with_a_failed_gate()))
        self.assertEqual((counts["gate_failures"], counts["conflicts"]), (1, 0), counts)

    def test_an_unclassified_failure_leaves_the_counts_unavailable_not_zero(self):
        run_dir = self.receipts_with_a_failed_gate()
        doc = json.loads((run_dir / "merge-receipts.json").read_text(encoding="utf-8"))
        for receipt in doc["receipts"]:
            if receipt["kind"] == "failed":
                receipt["body"]["reason"] = "merge_refused"
        (run_dir / "merge-receipts.json").write_text(json.dumps(doc), encoding="utf-8")
        rebind(run_dir)
        counts = wip.merge_counts(wip.Bound(run_dir))
        self.assertIsNone(counts["gate_failures"], counts)


class TestAFailedMergeGateIsReported(DryRun):
    RUN, ARGS = B1_GATE

    def test_the_failed_gate_bounces_the_unit_and_counts_once(self):
        self.assertEqual(self.record["status"], "complete", self.proc.stdout + self.proc.stderr)
        t3 = self.record["units"]["T3"]
        self.assertEqual([a["outcome"] for a in t3["attempts"]], ["gate-failed", "landed"])
        report = wip.build_report(self.copy(), basis="all")
        self.assertEqual(report["runs"][0]["registered"]["gate_failures"], 1)
        self.assertEqual(report["runs"][0]["binding_problems"], [])


class TestWorkerGitConfigNeverRunsOnTheCoordinator(DryRun):
    """PR #653 review: every coordinator git call over the target repository goes through
    gitexec's hardened environment with the repository's declared drivers blanked."""

    RUN, ARGS = B1_GATE

    def test_no_planted_command_ran_on_the_coordinator(self):
        for path in (_PLANT_MARKER, Path(f"{_PLANT_MARKER}.sh"), Path(f"{_PLANT_MARKER}.hooks")):
            self.addCleanup(shutil.rmtree if path.suffix == ".hooks" else Path.unlink, *(
                (path, True) if path.suffix == ".hooks" else (path,)))
        ran = _PLANT_MARKER.read_text(encoding="utf-8").splitlines() if _PLANT_MARKER.exists() else []
        # Later builders share the config, so their OWN git runs it (worker=<their dispatch>): that
        # stays inside a guarded worker session. Nothing may run with no worker (the coordinator).
        self.assertEqual([ln for ln in ran if "worker=none" in ln], [],
                         "a worker-planted git command ran on the coordinator")
        self.assertTrue(ran, "the plant never armed: later builders' own git should have run it")
        self.assertEqual(self.record["status"], "complete", self.proc.stdout + self.proc.stderr)
        self.assertEqual(self.record["units"]["T5"]["final"], "closed")


class TestAnInterruptedRunSettlesItsSpend(Tmp):
    """PR #653 review: SIGTERM, SIGHUP or Ctrl-C mid-dispatch. The runner kills every child
    process group and stops every worker before it exits 128+N, and charges each launched
    dispatch whose usage was never read its full reservation, so a later run cannot spend it."""

    def interrupt(self, sig):
        env, trip_log = tripwired_env(self.tmp)
        wd, results = self.tmp / "wd", self.tmp / "results"
        script = json.dumps({"_sleep": {"builder": 60}})
        proc = subprocess.Popen([sys.executable, str(RUNNER), "run", "--results", str(results), "--workdir", str(wd),
                                 "--runs", "wip1-b1r1-rep1", "--cost-cap-usd", "5", "--inert-cost-usd", "0.25",
                                 "--inert-script", script], cwd=str(ROOT), env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        runs_log = wd / "wip1-b1r1-rep1" / "inert" / "runs.log"
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline and not (runs_log.is_file() and '"builder"' in runs_log.read_text()):
            time.sleep(0.2)
        self.assertTrue(runs_log.is_file(), "the builder never started")
        time.sleep(1.0)  # the stand-in is now asleep inside its dispatch
        pids = [int(p.read_text()) for p in (wd / "wip1-b1r1-rep1" / "inert").glob("*.pid")]
        proc.send_signal(sig)
        out, err = proc.communicate(timeout=180)
        self.assertEqual(proc.returncode, 128 + sig, out + err)
        record = json.loads((results / "runs" / "wip1-b1r1-rep1" / "run.json").read_text(encoding="utf-8"))
        self.assertFalse(trip_log.exists())
        return record, pids

    def assert_settled(self, record, pids):
        self.assertEqual(record["status"], "interrupted")
        self.assertEqual(Decimal(record["cost"]["reserved_unobserved_usd"]), Decimal("0.25"),
                         "the interrupted builder's call was never charged")
        self.assertEqual(Decimal(record["cost"]["observed_usd"]), Decimal("0"))
        self.assertTrue(pids, "the stand-in recorded no pid")
        for pid in pids:
            with self.assertRaises(ProcessLookupError, msg=f"pid {pid} outlived the run"):
                os.kill(pid, 0)

    def test_sigterm_mid_dispatch(self):
        self.assert_settled(*self.interrupt(signal.SIGTERM))

    def test_ctrl_c_mid_dispatch(self):
        self.assert_settled(*self.interrupt(signal.SIGINT))


def install_fake_harness(bin_dir: Path, *, cost="0.25", script=None) -> Path:
    """A fake `claude` first on PATH for a --worker live run: the runner's own inert stand-in,
    answering as a harness that reads its model from ANTHROPIC_MODEL and reports fake costs."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    (bin_dir / "worker.py").write_text(wip.INERT_WORKER, encoding="utf-8")
    (bin_dir / "wip-config.json").write_text(json.dumps(
        {"taskset": str(TASKSET), "runner": str(RUNNER), "script": script or {}, "cost_usd": cost}), encoding="utf-8")
    launcher = bin_dir / "claude"
    launcher.write_text(f'#!/bin/sh\nexec {sys.executable} -I {bin_dir / "worker.py"} claude "$@"\n', encoding="utf-8")
    launcher.chmod(0o755)
    return launcher


class LiveWithAFakeHarness(Tmp):
    """--worker live end to end, against a fake harness (never a real one: a tripwire answers
    for every other harness name, and HOME is private)."""

    def live(self, *extra, script=None, run="wip1-b1r1-rep1", model="wip-fake-model", cost="0.25", containment=None):
        env, self.trip_log = tripwired_env(self.tmp)
        fake = self.tmp / "fake-bin"
        install_fake_harness(fake, cost=cost, script=script)
        env.update(PATH=os.pathsep.join([str(fake), env["PATH"]]), HOME=str(self.tmp / "home"))
        (self.tmp / "home").mkdir(exist_ok=True)
        self.results = self.tmp / "results"
        with mock.patch.object(wip, "dirty_inputs", return_value=[]), \
                mock.patch.object(wip.contain, "containment_problem", return_value=containment):
            p = run_in_process(["run", "--results", str(self.results), "--workdir", str(self.tmp / "wd"),
                                "--worker", "live", "--agent", "claude", "--model", model, "--cost-cap-usd", "20",
                                "--reservation-usd", cost, "--runs", run, *extra], env)
        self.assertFalse(self.trip_log.exists(), "a real harness name was reached")
        return p, self.results / "runs" / run / "run.json"


class TestLiveRunsTakeTheRegisteredOrder(LiveWithAFakeHarness):
    """PR #653 review (Bu3): a live run starts only at the next registered position: every earlier
    position has run and no later one has. Checked before anything is dispatched."""

    def refused(self, runs, text):
        p, _run_json = self.live(run=runs)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn(text, p.stderr)
        runs_dir = self.results / "runs"
        return sorted(d.name for d in runs_dir.iterdir()) if runs_dir.is_dir() else []

    def test_a_later_position_first_is_refused(self):
        self.assertEqual(self.refused("wip1-b3r1-rep1", "position 2"), [])

    def test_a_list_out_of_order_is_refused_before_its_first_run(self):
        self.assertEqual(self.refused("wip1-b3r1-rep1,wip1-b1r1-rep1", "position 2"), [])

    def test_a_lost_run_takes_its_position_unless_its_ledger_says_inert(self):
        positions = {e["run_id"]: e["position"] for e in wip.schedule(*wip.load_prereg(PREREG)[:2])}
        for rid, worker in (("wip1-b1r1-rep1", "live"), ("wip1-b3r1-rep1", "inert"), ("wip1-b6r2-rep1", None)):
            (self.tmp / "runs" / rid).mkdir(parents=True)
            if worker:
                wip.Budget(self.tmp).start_run(rid, self.tmp / "gone", worker)
        # no ledger record: unknown, so it counts as a live run that took its position
        self.assertEqual(wip.live_positions(self.tmp, positions), {1, 3})

    def test_a_skipped_position_is_refused(self):
        results, _p = documented_live_run(PREREG)  # position 1 ran live (the rule is the same in every version)
        shutil.copytree(results, self.tmp / "results")
        self.assertEqual(self.refused("wip1-b6r2-rep1", "[2]"), ["wip1-b1r1-rep1"])


class TestTheModelPinReachesTheLaunch(LiveWithAFakeHarness):
    """PR #653 review: --model must reach the harness, and the run records the model each call
    truly launched; a harness that ignores the pin is stopped before its next call."""

    def test_the_pinned_model_is_the_model_every_call_launched(self):
        results, p = documented_live_run()  # the page's own live command, against a fake claude
        record = json.loads((results / "runs" / documented_run_id(1) / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(record["status"], "complete", p.stdout + p.stderr)
        self.assertTrue(record["launched_models"])
        self.assertEqual(set(record["launched_models"].values()), {"wip-fake-model"})
        report = wip.build_report(results, _DOCUMENTED["prereg"], basis="all")
        self.assertEqual(report["runs"][0]["metrics"]["models"], ["wip-fake-model"])
        self.assertTrue(report["runs"][0]["compliant"], report["runs"][0]["noncompliance"])

    def test_a_harness_that_ignores_the_pin_gets_no_second_call(self):
        p, run_json = self.live(script={"_ignore_model_env": True})
        record = json.loads(run_json.read_text(encoding="utf-8"))
        self.assertEqual((record["status"], record["stop_reason"]), ("stopped", "model-mismatch"),
                         p.stdout + p.stderr)
        self.assertEqual(list(record["launched_models"].values()), ["inert-stand-in"])
        t5 = record["units"]["T5"]
        self.assertEqual((t5["reviews"], t5["final"], t5["park_class"]), ([], "parked", "stopped-model-mismatch"))

    def test_a_harness_with_no_enforceable_model_selection_is_refused(self):
        env, trip_log = tripwired_env(self.tmp)
        p = run_in_process(["run", "--results", str(self.tmp / "r"), "--worker", "live", "--agent", "codex",
                            "--model", "m", "--cost-cap-usd", "5", "--reservation-usd", "1", "--runs",
                            "wip1-b1r1-rep1"], env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("cannot enforce", p.stderr)
        self.assertFalse(trip_log.exists())


class TestTheRunDeadlineIsKeptInsideAWave(Tmp):
    """PR #653 review: the run's wall-clock limit is an absolute deadline carried into builder
    waits, reviewer admission and reviewer waits. A call still running at the deadline is stopped,
    its unit parked stopped-time-limit, and the run never reads complete. The registration copy
    here sets the limit to 0.1 minute (6 s); its task set is the registered one."""

    def deadline_run(self, script, minutes=0.1):
        prereg = json.loads(PREREG.read_text(encoding="utf-8"))
        prereg["taskset"]["path"] = str(TASKSET)
        prereg["stopping_rule"]["run_wall_clock_minutes"] = minutes
        path = self.tmp / "prereg.json"
        path.write_text(json.dumps(prereg), encoding="utf-8")
        env, trip_log = tripwired_env(self.tmp)
        started = time.monotonic()
        p = run_in_process(["--prereg", str(path), "run", "--results", str(self.tmp / "results"), "--workdir",
                            str(self.tmp / "wd"), "--runs", "wip1-b1r1-rep1", "--cost-cap-usd", "0",
                            "--inert-script", json.dumps(script)], env)
        elapsed = time.monotonic() - started
        self.assertFalse(trip_log.exists())
        record = json.loads((self.tmp / "results" / "runs" / "wip1-b1r1-rep1" / "run.json").read_text(encoding="utf-8"))
        return p, record, elapsed

    def test_a_builder_running_at_the_deadline_is_stopped_and_its_unit_parked(self):
        p, record, elapsed = self.deadline_run({"_sleep": {"builder": 40}})
        self.assertEqual((record["status"], record["stop_reason"]), ("stopped", "time-limit"), p.stdout + p.stderr)
        t5 = record["units"]["T5"]
        self.assertEqual((t5["final"], t5["park_class"], t5["reviews"]), ("parked", "stopped-time-limit", []))
        self.assertLess(elapsed, 35, "the builder was waited for past the run's deadline")

    def test_no_reviewer_starts_or_runs_past_the_deadline(self):
        p, record, elapsed = self.deadline_run({"_sleep": {"reviewer": 40}}, minutes=0.15)
        self.assertEqual((record["status"], record["stop_reason"]), ("stopped", "time-limit"), p.stdout + p.stderr)
        t5 = record["units"]["T5"]
        self.assertEqual((t5["final"], t5["park_class"]), ("parked", "stopped-time-limit"))
        self.assertLess(elapsed, 35, "the reviewer was waited for past the run's deadline")


_DOCUMENTED: dict = {}


def documented_live_run(prereg=None):
    """(results, process) of the protocol page's live command, placeholders filled, run once per
    module against a fake claude: a live-tier run that every check in this module can read. With
    `prereg`, the same command under that registration instead of the one the page names."""
    if prereg is not None:
        if str(prereg) not in _DOCUMENTED.setdefault("under", {}):
            _DOCUMENTED["under"][str(prereg)] = _documented_run(prereg)
        return _DOCUMENTED["under"][str(prereg)][:2]
    if "run" not in _DOCUMENTED:
        results, proc, tmp, trip_log, named = _documented_run(None)
        _DOCUMENTED.update(run=(results, proc), tmp=tmp, trip_log=trip_log, prereg=named)
    return _DOCUMENTED["run"]


def _documented_run(override):
    """One run of the page's live command: (results, process, tmp, tripwire log, registration)."""
    tmp = tempfile.TemporaryDirectory(prefix="wip-curve-documented-")
    root = Path(tmp.name).resolve()
    page = (ROOT / "docs" / "experiments" / "wip-curve-prereg.md").read_text(encoding="utf-8")
    block = next(b for b in re.findall(r"```bash\n(.*?)```", page, re.S) if "--worker live" in b)
    command = block.replace("\\\n", " ")
    fill = {"dir": str(root / "results"), "model": "wip-fake-model", "cap": "20", "reservation": "0.25"}
    for placeholder in re.findall(r"<[^>]+>", command):
        key = next((k for k in fill if k in placeholder), None)
        if key is None:
            raise AssertionError(f"an unknown placeholder {placeholder} in the documented live command")
        command = command.replace(placeholder, fill[key])
    argv = shlex.split(command)
    if argv[:2] != ["python3", "scripts/wip_curve.py"]:
        raise AssertionError(f"the documented live command is not the runner: {argv[:2]}")
    # the registration the command names (version 2 since #604's re-registration), from the checkout
    prereg = ROOT / argv[argv.index("--prereg") + 1] if "--prereg" in argv else PREREG
    if override is not None:
        argv = [a for i, a in enumerate(argv) if a != "--prereg" and (i == 0 or argv[i - 1] != "--prereg")]
        argv[2:2], prereg = ["--prereg", str(override)], override
    env, trip_log = tripwired_env(root)
    install_fake_harness(root / "fake-bin")
    env.update(PATH=os.pathsep.join([str(root / "fake-bin"), env["PATH"]]), HOME=str(root / "home"))
    (root / "home").mkdir()
    with mock.patch.object(wip, "dirty_inputs", return_value=[]), \
            mock.patch.object(wip.contain, "containment_problem", return_value=None):
        proc = run_in_process(argv[2:], env, cwd=str(ROOT))
    return root / "results", proc, tmp, trip_log, prereg


def documented_run_id(position: int) -> str:
    """The run id at `position` in the schedule of the registration the documented command names."""
    documented_live_run()
    return next(e["run_id"] for e in wip.schedule(*wip.load_prereg(_DOCUMENTED["prereg"])[:2])
                if e["position"] == position)


class TestTheDocumentedLiveCommandRuns(unittest.TestCase):
    """PR #653 review (P2): the live command the protocol page prints must parse and start a run.
    It is read from the page, its placeholders filled, and run against a fake harness."""

    def test_the_documented_live_command_starts_a_run(self):
        results, p = documented_live_run()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(_DOCUMENTED["prereg"], PREREG_V2, "the page's live command runs the current registration")
        record = json.loads((results / "runs" / documented_run_id(1) / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(record["run_id"], "wip2-b1r1-rep1")
        self.assertEqual((record["tier"], record["status"]), ("live-unreviewed", "complete"))
        self.assertFalse(_DOCUMENTED["trip_log"].exists())


class TestACallMidSpawnIsCharged(Tmp):
    """Adversarial pass (interrupted spend, #652's latest class): a signal can land while
    spawn_worker.sh is still running, after the provider registered the dispatch and before the
    runner read its id. Every dispatch the STORE holds for the run is settled on the way out, so
    that call is charged its reservation too, never lost."""

    def test_a_dispatch_the_runner_never_saw_is_charged(self):
        db = self.tmp / "runtime.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE dispatches (dispatch_id TEXT, task_id TEXT, run_id TEXT, lane_dir TEXT)")
        conn.executemany("INSERT INTO dispatches VALUES (?, ?, ?, ?)", [
            ("disp_seen", "task_a", "wip1-b1r1-rep1", None), ("disp_midspawn", "task_b", "wip1-b1r1-rep1", None),
            ("disp_other_run", "task_c", "another-run", None)])
        conn.commit()
        conn.close()
        run = self.two_units(db)
        settled = run.settle_launched()
        self.assertEqual(sorted(settled), ["disp_midspawn", "disp_seen"])
        calls = wip.Budget.of_run(run.budget.calls(), run.rid)
        self.assertEqual({c: (v["state"], v["usd"], v.get("dispatch")) for c, v in calls.items()}, {
            "wip1-b1r1-rep1/T1/a1/builder": ("charged", "0.25", "disp_seen"),
            "wip1-b1r1-rep1/T2/a1/builder": ("charged", "0.25", "disp_midspawn"),  # the call mid-spawn
            "wip1-b1r1-rep1/T1/a1/reviewer": ("released", "0", None),
            "wip1-b1r1-rep1/T2/a1/reviewer": ("released", "0", None)})
        self.assertEqual((run.held, wip.spent_in(self.tmp / "results")), ({}, Decimal("0.50")))
        self.assertEqual(run.settle_launched(), [], "a second settlement charged again")
        self.assertEqual(wip.spent_in(self.tmp / "results"), Decimal("0.50"))

    def test_an_unreadable_store_charges_a_call_mid_spawn(self):
        run = self.two_units(self.tmp / "gone.db")  # no store to ask whether it registered the call
        run.launched = {}
        run.settle_launched()
        calls = wip.Budget.of_run(run.budget.calls(), run.rid)
        self.assertEqual(calls["wip1-b1r1-rep1/T2/a1/builder"]["state"], "charged", "unavailable read as never run")

    def two_units(self, db):
        """T1's builder launched as disp_seen; T2's spawn was interrupted before DISPATCH= arrived."""
        run = bare_run(self.tmp)
        run.sb = argparse.Namespace(state_db=db)
        self.assertTrue(run.hold_unit("T1") and run.hold_unit("T2"))
        for tid, store_task in (("T1", "task_a"), ("T2", "task_b")):
            self.assertTrue(run.admit(f"{tid}:builder"))
            run.budget.note(run.calls[f"{tid}:builder"], store_task=store_task)
        run.budget.note(run.calls["T1:builder"], state="launched", dispatch="disp_seen")
        run.launched = {"disp_seen": ("task_a", "T1:builder")}
        return run


def start_runner(env, *args):
    """The runner as a real process (signals are the point here); stdout and stderr captured."""
    return subprocess.Popen([sys.executable, str(RUNNER), *map(str, args)], cwd=str(ROOT), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def wait_for_builders(test, inert_dir: Path, count: int, timeout=180):
    """Block until `count` builders of the stand-in in `inert_dir` have started; their pids."""
    runs_log = inert_dir / "runs.log"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        started = runs_log.read_text().count('"builder"') if runs_log.is_file() else 0
        if started >= count:
            time.sleep(1.0)  # each is now asleep inside its dispatch
            return [int(p.read_text()) for p in inert_dir.glob("*.pid")]
        time.sleep(0.2)
    test.fail(f"{count} builder(s) never started")


def kill_pids(pids):
    """Kill each stand-in's whole process group (the posix monitor is its session leader), so no
    monitor of a killed run outlives the test and writes into a directory being removed."""
    for pid in pids:
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    time.sleep(0.5)


class TestOneRunnerPerResultsDirectory(Tmp):
    """PR #653 review (Buy): two commands on one results directory could both spend against the
    same remaining budget. A runner holds the directory's lock from its first check through its
    cleanup; a second run, or a report that would read a run in progress, is refused."""

    def test_a_second_command_is_refused_while_a_runner_is_active(self):
        env, trip_log = tripwired_env(self.tmp)
        results, wd = self.tmp / "results", self.tmp / "wd"
        proc = start_runner(env, "run", "--results", results, "--workdir", wd, "--runs", "wip1-b1r1-rep1",
                            "--cost-cap-usd", "5", "--inert-cost-usd", "0.25",
                            "--inert-script", json.dumps({"_sleep": {"builder": 60}}))
        pids = wait_for_builders(self, wd / "wip1-b1r1-rep1" / "inert", 1)
        self.addCleanup(kill_pids, pids)
        try:
            second = runner("run", "--results", results, "--workdir", wd, "--next", "1", "--cost-cap-usd", "5",
                            "--inert-cost-usd", "0.25", env=env)
            self.assertEqual(second.returncode, 2, second.stdout + second.stderr)
            self.assertIn("another runner", second.stderr)
            self.assertEqual(sorted(d.name for d in (results / "runs").iterdir()), ["wip1-b1r1-rep1"])
            report = runner("report", "--results", results, "--basis", "all", env=env)
            self.assertEqual(report.returncode, 2, report.stdout + report.stderr)
            self.assertIn("another runner", report.stderr)
        finally:
            proc.send_signal(signal.SIGTERM)
            proc.communicate(timeout=180)
        self.assertFalse(trip_log.exists())


class TestSpendIsCountedOnce(Tmp):
    """PR #653 review (Buw): every charge is recorded once, keyed by its call, and a recovery
    reconciles the ledger instead of adding to it. Run 1 spends 0.50 and stops at its cap; run 2 is
    killed outright (SIGKILL) while its three builders run, so it writes no run.json."""

    def setUp(self):
        super().setUp()
        self.env, self.trip_log = tripwired_env(self.tmp)
        self.results, self.wd = self.tmp / "results", self.tmp / "wd"
        first = runner("run", "--results", self.results, "--workdir", self.wd, "--runs", "wip1-b1r1-rep1",
                       "--cost-cap-usd", "0.50", "--inert-cost-usd", "0.25", env=self.env)
        self.assertEqual(wip.spent_in(self.results), Decimal("0.50"), first.stdout + first.stderr)
        proc = start_runner(self.env, "run", "--results", self.results, "--workdir", self.wd, "--runs",
                            "wip1-b3r1-rep1", "--cost-cap-usd", "10", "--inert-cost-usd", "0.25",
                            "--inert-script", json.dumps({"_sleep": {"builder": 60}}))
        self.pids = wait_for_builders(self, self.wd / "wip1-b3r1-rep1" / "inert", 3)
        self.addCleanup(kill_pids, self.pids)
        proc.kill()
        proc.communicate(timeout=60)

    def test_a_killed_run_never_counts_earlier_spend_again(self):
        # run 1's 0.50, plus run 2's three units held at a builder and a reviewer each (3 x 0.50)
        self.assertEqual(wip.spent_in(self.results), Decimal("2.00"))

    def test_the_next_command_reconciles_the_killed_run_once(self):
        for _ in range(2):  # recovery twice: the second finds every call already settled
            p = runner("run", "--results", self.results, "--workdir", self.wd, "--next", "1",
                       "--cost-cap-usd", "2.00", "--inert-cost-usd", "0.25", env=self.env)
            self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
            self.assertIn("not started", p.stderr)
            # each launched builder is charged its reservation once (killed mid-call: no reported
            # cost); the reviewer holds that never launched are released
            self.assertEqual(wip.spent_in(self.results), Decimal("1.25"))
        for pid in self.pids:
            with self.assertRaises(ProcessLookupError, msg=f"the killed run's worker {pid} still runs"):
                os.kill(pid, 0)
        self.assertFalse(self.trip_log.exists())


class TestAnInterruptedIngestionIsStillCharged(Tmp):
    """Codex review (C1): a signal can land inside a dispatch's usage ingestion, after it began and
    before its charge was recorded. The run's cleanup must settle that call from the ledger, at
    what its stream reports, exactly once: never skip it as already seen and leave it at its hold."""

    def launched_call(self):
        lane = self.tmp / "lane"
        lane.mkdir()
        (lane / "events.jsonl").write_text(
            json.dumps({"type": "system", "subtype": "init", "model": "m"}) + "\n"
            + json.dumps({"type": "result", "result": "done", "total_cost_usd": 2.0,
                          "usage": {"input_tokens": 1, "output_tokens": 1}}) + "\n", encoding="utf-8")
        db = self.tmp / "runtime.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE dispatches (dispatch_id TEXT, task_id TEXT, run_id TEXT, lane_dir TEXT)")
        conn.execute("INSERT INTO dispatches VALUES (?, ?, ?, ?)", ("disp_paid", "task_a", "wip1-b1r1-rep1", str(lane)))
        conn.commit()
        conn.close()
        run = bare_run(self.tmp)
        run.sb, run.dir, run.clock = argparse.Namespace(state_db=db), self.tmp / "run", "host-clock"
        run.dir.mkdir()
        run.launched_models = {}
        self.assertTrue(run.hold_unit("T1") and run.admit("T1:builder"))
        run.budget.note(run.calls["T1:builder"], state="launched", dispatch="disp_paid")
        run.launched = {"disp_paid": ("task_a", "T1:builder")}
        return run

    def test_a_call_interrupted_mid_ingestion_is_charged_what_it_spent(self):
        run = self.launched_call()
        real = wip.run_text

        def interrupted(argv, *a, **kw):
            if "ingest-usage" in argv:
                raise SystemExit(143)  # SIGTERM, raised by _terminated inside the ingestion
            return real(argv, *a, **kw)
        with mock.patch.object(wip, "run_text", side_effect=interrupted), self.assertRaises(SystemExit):
            run.ingest_usage("disp_paid", "task_a", "T1:builder")
        run.settle_launched()
        calls = wip.Budget.of_run(run.budget.calls(), run.rid)
        self.assertEqual((calls["wip1-b1r1-rep1/T1/a1/builder"]["state"], calls["wip1-b1r1-rep1/T1/a1/builder"]["usd"]),
                         ("charged", "2.0"), "the paid call stayed at its 0.25 hold")
        self.assertEqual(wip.spent_in(self.tmp / "results"), Decimal("2.0"))  # its reviewer hold released
        run.settle_launched()  # settling again adds nothing
        self.assertEqual(wip.spent_in(self.tmp / "results"), Decimal("2.0"))
        usage = [json.loads(line) for line in (run.dir / "events.jsonl").read_text().splitlines()
                 if json.loads(line)["kind"] == "model.usage"]
        self.assertEqual(len(usage), 1, "the usage was recorded twice")

    def test_an_interruption_after_the_record_reuses_its_observation(self):
        # the record landed, the charge did not: the retry is the same event, never a conflict
        run = self.launched_call()
        real_settle = wip.Run.settle

        def interrupted(self_, *a, **kw):
            raise SystemExit(143)
        with mock.patch.object(wip.Run, "settle", interrupted), self.assertRaises(SystemExit):
            run.ingest_usage("disp_paid", "task_a", "T1:builder")
        with mock.patch.object(wip.Run, "settle", real_settle):
            run.settle_launched()
        self.assertEqual(wip.spent_in(self.tmp / "results"), Decimal("2.0"))
        check = subprocess.run([sys.executable, str(EVENTS), "--log", str(run.dir / "events.jsonl"), "report"],
                               capture_output=True, text=True)
        self.assertNotIn("contested", check.stdout + check.stderr)
        usage = [json.loads(line) for line in (run.dir / "events.jsonl").read_text().splitlines()
                 if json.loads(line)["kind"] == "model.usage"]
        self.assertEqual(len(usage), 1)


def short_wall(minutes):
    """The registration with a shorter run wall clock (its digest unchanged): a deadline a test can reach."""
    real = wip.load_prereg

    def patched(*a, **kw):
        prereg, taskset, path, sha, taskset_path = real(*a, **kw)
        prereg = copy.deepcopy(prereg)
        prereg["stopping_rule"]["run_wall_clock_minutes"] = minutes
        return prereg, taskset, path, sha, taskset_path
    return mock.patch.object(wip, "load_prereg", patched)


def slow_launches(profile, seconds, count):
    """Run.spawn, with the first `count` launches of `profile` followed by `seconds` of the runner's
    own work (the rest of a wave launching, a review being prepared)."""
    real, done = wip.Run.spawn, []

    def spawn(run, store_task, worktree, title, prof, key=None, nonce=None):
        disp = real(run, store_task, worktree, title, prof, key, nonce)
        if prof == profile and len(done) < count:
            done.append(disp)
            time.sleep(seconds)
        return disp
    return mock.patch.object(wip.Run, "spawn", spawn)


class TestEveryDeadlineStartsAtItsLaunch(Tmp):
    """PR #653 review (lia) and Codex (C2): a dispatch's registered deadline runs from its own
    launch, a call never launches after the run's deadline, and every blocking step is bounded by
    the time the run has left. --timeout-scale 0.01: builders 18 s, reviewers 9 s (inert only)."""

    def setUp(self):
        super().setUp()
        self.env, self.trip_log = tripwired_env(self.tmp)
        self.addCleanup(lambda: self.assertFalse(self.trip_log.exists(), "a harness name was reached"))

    def run_record(self, run, *args):
        p = runner("run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"), "--runs", run,
                   *args, env=self.env)
        path = self.tmp / "results" / "runs" / run / "run.json"
        self.assertTrue(path.is_file(), p.stdout + p.stderr)
        return json.loads(path.read_text(encoding="utf-8")), p

    def test_an_early_builder_is_held_to_its_own_deadline(self):
        # T5 launches first and runs 25 s; the wave's other two launches take 8 s each after it
        with slow_launches("rw", 8, 3):
            record, p = self.run_record("wip1-b3r1-rep1", "--cost-cap-usd", "1.50", "--inert-cost-usd", "0.25",
                                        "--timeout-scale", "0.01",
                                        "--inert-script", json.dumps({"_sleep_task": {"T5": {"builder": 25}}}))
        self.assertEqual(record["units"]["T5"]["attempts"][0]["outcome"], "builder-timeout", p.stdout + p.stderr)

    def test_an_early_reviewer_is_held_to_its_own_deadline(self):
        # the review runs 12 s of its 9; the runner spends 8 s after its launch before it waits
        with slow_launches("ro", 8, 1):
            record, p = self.run_record("wip1-b1r1-rep1", "--cost-cap-usd", "0.50", "--inert-cost-usd", "0.25",
                                        "--timeout-scale", "0.01", "--inert-script",
                                        json.dumps({"_sleep": {"reviewer": 12}}))
        self.assertEqual(record["units"]["T5"]["attempts"][0]["outcome"], "review-failed", p.stdout + p.stderr)

    def test_a_builder_done_after_its_deadline_is_a_timeout_whenever_it_is_noticed(self):
        # T5's builder ends at about 21 s of its 18; the runner is busy for 30 s before it looks again
        real, busy = wip.Run.review_step, []

        def slow_review_step(run, queue, live):
            if not busy:
                busy.append(1)
                time.sleep(30)
            return real(run, queue, live)
        with mock.patch.object(wip.Run, "review_step", slow_review_step):
            record, p = self.run_record("wip1-b1r1-rep1", "--cost-cap-usd", "0.50", "--inert-cost-usd", "0.25",
                                        "--timeout-scale", "0.01", "--inert-script",
                                        json.dumps({"_sleep": {"builder": 20}}))
        self.assertEqual(record["units"]["T5"]["attempts"][0]["outcome"], "builder-timeout", p.stdout + p.stderr)

    def test_a_call_admitted_before_the_deadline_never_launches_after_it(self):
        # Codex's probe: admitted at 99 of 100, launched at 103
        run = bare_run(self.tmp)
        launches = []

        def wrapper(argv, env=None, cwd=None, timeout=600):
            launches.append([str(a) for a in argv])
            return subprocess.CompletedProcess(argv, 0, "DISPATCH=disp_late\nHANDLE=term_x\n", "")
        run.wrapper, run.guard, run.delivered = wrapper, (lambda _wt: None), (lambda _out, _nonce: {})
        run.args, run.launches, run.commands = argparse.Namespace(agent="claude"), {}, []
        run.deadline = time.monotonic() + 60
        self.assertTrue(run.hold_unit("T1") and run.admit("T1:reviewer"))
        run.deadline = time.monotonic() - 3  # preparing the review ran past the deadline
        disp = run.spawn("task_r", self.tmp, "t", "ro", "T1:reviewer", "WIP-NONCE:" + "a" * 16)
        self.assertEqual([a for a in launches if any("spawn_worker.sh" in x for x in a)], [],
                         "a call launched after the run's deadline")
        self.assertEqual((disp, run.halt), (None, "time-limit"))
        self.assertEqual(wip.Budget.of_run(run.budget.calls(), run.rid)["wip1-b1r1-rep1/T1/a1/reviewer"]["state"],
                         "released")

    def test_a_deadline_during_the_launches_stops_the_run_instead_of_failing_it(self):
        # a 12 s run; each builder launch takes 8 s more: the third is admitted past the deadline
        with short_wall(0.2), slow_launches("rw", 8, 3):
            record, p = self.run_record("wip1-b3r1-rep1", "--cost-cap-usd", "0")
        self.assertEqual((record["status"], record["stop_reason"]), ("stopped", "time-limit"), p.stdout + p.stderr)
        t6 = record["units"]["T6"]
        self.assertEqual((t6["attempts"][0]["dispatch"], t6["final"], t6["park_class"]),
                         (None, "parked", "stopped-time-limit"))

    def test_the_oracle_and_the_merge_are_bounded_by_the_run_deadline(self):
        seen = {"oracle": [], "drain": []}
        real_oracle, real_wrapper = wip.run_oracle, wip.Run.wrapper

        def oracle(*a, **kw):  # the run's own verifications (a clean checkout under ck/), not the pre-run checks
            if "/ck/" in str(a[0]):
                seen["oracle"].append(kw.get("timeout", a[4] if len(a) > 4 else 300))
            return real_oracle(*a, **kw)

        def wrapper(run, argv, env=None, cwd=None, timeout=600):
            if "drain" in argv:
                seen["drain"].append(timeout)
            return real_wrapper(run, argv, env=env, cwd=cwd, timeout=timeout)
        with short_wall(1.0), mock.patch.object(wip, "run_oracle", oracle), \
                mock.patch.object(wip.Run, "wrapper", wrapper):
            record, p = self.run_record("wip1-b1r1-rep1", "--cost-cap-usd", "0.50", "--inert-cost-usd", "0.25")
        self.assertTrue(seen["oracle"] and seen["drain"], p.stdout + p.stderr)
        for kind, timeouts in seen.items():
            self.assertTrue(all(t <= 60 for t in timeouts), f"{kind} may outlive a 60 s run: {timeouts}")


class TestNoWorkerOutlivesItsRun(Tmp):
    """Codex review (C3): a builder that leaves a background child in its process group finishes
    `completed`, and nothing stopped that child. The run's cleanup ends every orphaned worker group
    before it settles, and records what it ended."""

    def test_a_finished_builders_background_child_is_ended(self):
        env, trip_log = tripwired_env(self.tmp)
        pid_file = self.tmp / "orphan.pid"
        script = {"T5": {"builder": ["orphan"]}, "_orphan_pid": str(pid_file)}
        p = runner("run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"), "--runs",
                   "wip1-b1r1-rep1", "--cost-cap-usd", "0.50", "--inert-cost-usd", "0.25",
                   "--inert-script", json.dumps(script), env=env)
        orphan = int(pid_file.read_text())
        self.addCleanup(TABLES.kill, orphan)
        end = time.monotonic() + 5
        while time.monotonic() < end:
            if not TABLES.running(orphan):  # /proc where there is one: no procps needed (PR #668 CI)
                break
            time.sleep(0.1)
        else:
            self.fail(f"the builder's background child {orphan} outlived its run: {p.stdout + p.stderr}")
        record = json.loads((self.tmp / "results" / "runs" / "wip1-b1r1-rep1" / "run.json").read_text(encoding="utf-8"))
        self.assertTrue(record["teardown"]["ended"], record.get("teardown"))
        self.assertEqual(record["teardown"]["survivors"], [])
        self.assertFalse(trip_log.exists())


def ended(pid, wait_s=5.0) -> bool:
    """The process is gone (or a zombie) within `wait_s`: /proc where there is one, so a Linux image
    with no procps can run it (PR #668 CI)."""
    end = time.monotonic() + wait_s
    while time.monotonic() < end:
        if not TABLES.running(pid):
            return True
        time.sleep(0.1)
    return False


class TestNoDrainOutlivesItsBound(Tmp):
    """Codex review of PR #668 (B2): a timed-out call's group is killed, but a descendant that left
    it (a new session) can keep the call's stdout and stderr open. Draining them must stay bounded,
    and worker-written code the oracle runs must be contained, its escaped processes included."""

    def detached(self, holds_pipes: bool, seconds: int):
        """Python that starts a new-session child sleeping `seconds`, holding the caller's output open
        or not, and writes its pid to a file. The child is a Python process: macOS hides an Apple
        platform binary's environment from `ps -E`, and the host check covers that (B1)."""
        pid_file = self.tmp / f"child-{holds_pipes}-{seconds}.pid"
        streams = "" if holds_pipes else ", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL"
        code = (f"import subprocess, sys, time\n"
                f"child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep({seconds})'], "
                f"start_new_session=True{streams})\n"
                f"open({str(pid_file)!r}, 'w').write(str(child.pid))\n")
        self.addCleanup(lambda: pid_file.is_file() and TABLES.kill(pid_file.read_text()))
        return code, pid_file

    def test_a_timed_out_call_returns_within_its_bound_though_a_detached_child_holds_its_pipes(self):
        code, _pid = self.detached(holds_pipes=True, seconds=25)
        started = time.monotonic()
        proc = wip.run_group([sys.executable, "-c", code + "time.sleep(60)\n"], timeout=0.2)
        elapsed = time.monotonic() - started
        self.assertEqual(proc.returncode, 124)
        self.assertLess(elapsed, 8, f"draining the timed-out call waited {elapsed:.1f} s for a detached child")

    def test_the_oracle_contains_what_worker_code_detaches(self):
        # the task's oracle starts a new-session child that holds the step's output open, then passes
        code, pid_file = self.detached(holds_pipes=True, seconds=25)
        oracle = ("import subprocess, sys, unittest\n\n\nclass T(unittest.TestCase):\n    def test_it(self):\n"
                  + "".join(f"        {line}\n" for line in code.splitlines() if not line.startswith("import")))
        task = {"id": "T9", "oracle": oracle}
        checkout = self.tmp / "checkout"
        checkout.mkdir()
        started = time.monotonic()
        result = wip.run_oracle(checkout, [task], {"visible_tests": ["-c", "pass"]}, self.tmp, timeout=20)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 15, f"the oracle waited {elapsed:.1f} s on a detached child: {result}")
        self.assertTrue(ended(int(pid_file.read_text())), "a process the oracle's code detached outlived it")


class TestTheOracleStopsAtItsFirstUncontainedStep(Tmp):
    """PR #668 review (Codex C-d, Greptile PRRT_kwDOTWxN9c6v3pIE): when the visible tests could not be
    contained, run_oracle still launched the hidden oracle. It stops at the first failed
    containment, launches nothing further, and keeps what is needed to investigate."""

    def test_nothing_launches_after_a_step_that_could_not_be_contained(self):
        launched = []

        def contained_run(argv, **kw):
            launched.append(argv)
            Path(kw["stdout_path"]).write_text("", encoding="utf-8")
            return 0, False, False  # a process of the visible tests survived
        checkout = self.tmp / "checkout"
        checkout.mkdir()
        task = {"id": "T9", "oracle": "import unittest\n"}
        with mock.patch.object(wip.contain, "contained_run", contained_run):
            result = wip.run_oracle(checkout, [task], {"visible_tests": ["-c", "pass"]}, self.tmp, timeout=20)
        self.assertEqual(len(launched), 1, "the hidden oracle launched after the visible tests escaped")
        self.assertEqual((result["exit"], result["contained"]), (1, False))
        self.assertTrue(result["kept"] and Path(result["kept"]).is_dir(), "the oracle's files were removed")


class TestAnUncontainedMergeGateHaltsTheRun(Tmp):
    """The merge gate runs its oracle in the merge queue's process. Its markers reach the runner
    through a file, each written before its step starts; an uncontained step is written there too,
    its files kept, and the runner halts orphan-alive when it reads it (PR #668 review, C-d)."""

    def test_the_gate_reports_it_and_the_runner_halts(self):
        tags_file, landing = self.tmp / "gate-tags.txt", self.tmp / "landing.json"
        landing.write_text("{}", encoding="utf-8")
        (self.tmp / "checkout").mkdir()

        def contained_run(argv, **kw):
            Path(kw["stdout_path"]).write_text("", encoding="utf-8")
            return 0, False, False
        cwd = os.getcwd()
        try:
            os.chdir(self.tmp / "checkout")
            with mock.patch.object(wip.contain, "contained_run", contained_run), \
                    contextlib.redirect_stdout(io.StringIO()):
                rc = wip.cmd_gate(argparse.Namespace(taskset=str(TASKSET), landing=str(landing),
                                                     tags_file=str(tags_file)))
        finally:
            os.chdir(cwd)
        self.assertNotEqual(rc, 0)
        lines = tags_file.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2, lines)
        self.assertTrue(lines[1].startswith("UNCONTAINED ") and Path(lines[1].split(" ", 1)[1]).is_dir(), lines)
        run = bare_run(self.tmp)
        run.sb = argparse.Namespace(dir=self.tmp)
        self.assertEqual(run.gate_tags(), lines[:1])
        self.assertEqual(run.halt, "orphan-alive")

    def test_a_failed_containment_overrides_any_earlier_halt(self):
        # Codex at 47e0616eac: every containment failure sets orphan-alive over whatever halted the
        # run first, since each guard that stops the next oracle or gate asks for orphan-alive.
        (self.tmp / "gate-tags.txt").write_text(f"UNCONTAINED {self.tmp}\n", encoding="utf-8")
        for earlier in ("model-mismatch", "cost-cap", "time-limit"):
            with self.subTest(earlier=earlier):
                run = bare_run(self.tmp)
                run.sb, run.halt = argparse.Namespace(dir=self.tmp), earlier
                run.gate_tags()
                self.assertEqual(run.halt, "orphan-alive")


class TestEveryOracleMarkerIsSwept(Tmp):
    """PR #668 review (Codex C-d): each oracle call, and each merge-gate oracle the merge queue runs,
    carries a marker of its own, not the run's. Every one is recorded, in the run and the ledger,
    and swept by finish() and by the check before the next run."""

    def test_the_run_and_the_next_command_sweep_every_oracle_and_gate_marker(self):
        env, _trip = tripwired_env(self.tmp)
        real, swept = wip.contain.sweep, []

        def sweep(*a, **kw):
            swept.append(kw.get("tag"))
            return real(*a, **kw)
        with mock.patch.object(wip.contain, "sweep", sweep):
            runner("run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"), "--runs",
                   "wip1-b1r1-rep1", "--cost-cap-usd", "0.50", "--inert-cost-usd", "0.25", env=env)
        record = json.loads((self.tmp / "results" / "runs" / "wip1-b1r1-rep1" / "run.json").read_text(encoding="utf-8"))
        oracle, gate = record["oracle_tags"], record["gate_tags"]
        self.assertTrue(oracle and gate, record.get("oracle_tags"))
        for tag in oracle + gate:  # once where it ran (the gate's in its own process), once more at teardown
            self.assertGreaterEqual(swept.count(tag), 1 if tag in gate else 2, tag)
        start = wip.Budget(self.tmp / "results").calls()["wip1-b1r1-rep1/run"]
        self.assertEqual((start["oracle_tags"], start["gate_tags"]), (oracle, gate))
        swept.clear()
        with mock.patch.object(wip.contain, "sweep", sweep):
            runner("run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"), "--next", "1",
                   "--cost-cap-usd", "0.50", "--inert-cost-usd", "0.25", env=env)
        self.assertTrue(set(oracle + gate) <= set(swept), "the check before the next run left an oracle marker")


class TestAnUncontainedOracleStopsTheRun(Tmp):
    """Codex review of PR #668 (B2): when a process the oracle's worker-written code started survives,
    or cannot be seen, nothing about that verification is vouched for and no further call starts."""

    def test_the_run_stops_orphan_alive(self):
        env, trip_log = tripwired_env(self.tmp)
        real = wip.contain.contained_run

        def contained_run(argv, **kw):  # the run's own verification (a checkout under ck/) survives
            if "/ck/" not in str(kw.get("cwd")):
                return real(argv, **kw)
            Path(kw["stdout_path"]).write_text("", encoding="utf-8")
            return 0, False, False
        with mock.patch.object(wip.contain, "contained_run", contained_run):
            p = runner("run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"), "--runs",
                       "wip1-b1r1-rep1", "--cost-cap-usd", "0", env=env)
        record = json.loads((self.tmp / "results" / "runs" / "wip1-b1r1-rep1" / "run.json").read_text(encoding="utf-8"))
        self.assertEqual((record["status"], record["stop_reason"]), ("stopped", "orphan-alive"), p.stdout + p.stderr)
        t5 = record["units"]["T5"]
        self.assertEqual((t5["attempts"][0]["outcome"], t5["final"]), ("stopped-orphan-alive", "parked"))
        self.assertFalse(trip_log.exists())


class TestOnlyASuccessfulCallIsTrusted(Tmp):
    """PR #668 review (Greptile PRRT_kwDOTWxN9c6v2-i3): a reviewer can print a valid approval and exit
    nonzero, and a builder can report success and exit nonzero. A call that did not finish
    successfully (a nonzero exit, died, killed, timed out) is never trusted, whatever it printed."""

    def run_record(self, script):
        env, trip_log = tripwired_env(self.tmp)
        p = runner("run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"), "--runs",
                   "wip1-b1r1-rep1", "--cost-cap-usd", "0.50", "--inert-cost-usd", "0.25",
                   "--inert-script", json.dumps(script), env=env)
        self.assertFalse(trip_log.exists())
        run_dir = self.tmp / "results" / "runs" / "wip1-b1r1-rep1"
        events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text().splitlines()]
        return json.loads((run_dir / "run.json").read_text(encoding="utf-8")), events, p

    def test_an_approval_from_a_reviewer_that_exited_nonzero_is_a_failed_review(self):
        record, events, p = self.run_record({"T5": {"reviewer": ["approve_crash"]}})
        t5 = record["units"]["T5"]
        self.assertEqual(t5["attempts"][0]["outcome"], "review-failed", p.stdout + p.stderr)
        self.assertEqual([e for e in events if e["kind"] == "review.verdict"], [], "a failed call's verdict was recorded")

    def test_a_builder_that_reported_success_and_exited_nonzero_is_a_failed_builder(self):
        record, _events, p = self.run_record({"T5": {"builder": ["solve_crash"]}})
        self.assertEqual(record["units"]["T5"]["attempts"][0]["outcome"], "builder-failed", p.stdout + p.stderr)


class TestAStoredApprovalFromAFailedCallNeverBinds(DryRun):
    """The same, read back: a saved run whose approving reviewer did not finish successfully, its
    record re-hashed by a careful tamperer, does not bind."""

    def test_an_approval_whose_reviewer_died_does_not_bind(self):
        results = self.copy()
        run_dir = results / "runs" / self.RUN
        events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text().splitlines()]
        reviewer = next(e["dispatch"] for e in events
                        if e["kind"] == "review.verdict" and e["data"]["verdict"] == "approve")
        conn = sqlite3.connect(run_dir / "state.db")
        conn.execute("UPDATE dispatches SET state = 'died' WHERE dispatch_id = ?", (reviewer,))
        conn.commit()
        conn.close()
        rebind(run_dir)
        problems = wip.build_report(results, basis="all")["runs"][0]["binding_problems"]
        self.assertTrue(any(reviewer in p and "did not finish successfully" in p for p in problems), problems)


class TestNothingDetachedOutlivesItsRun(Tmp):
    """Codex review of PR #668 (B1): a worker's child that left for a session of its own, its streams
    redirected, escaped teardown, which tracked only the worker and monitor groups. Every process of
    a run carries the run's OF_CALL_ID, and teardown sweeps by it with #606's helper. A survivor or
    a failed discovery blocks settlement and the sandbox's removal: every call of the run is
    charged its full hold, and the run stops orphan-alive."""

    def setUp(self):
        super().setUp()
        self.env, self.trip_log = tripwired_env(self.tmp)
        self.addCleanup(lambda: self.assertFalse(self.trip_log.exists(), "a harness name was reached"))

    def run_b1(self, script, *extra):
        p = runner("run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"), "--runs",
                   "wip1-b1r1-rep1", "--cost-cap-usd", "0.50", "--inert-cost-usd", "0.25",
                   "--inert-script", json.dumps(script), *extra, env=self.env)
        record = json.loads((self.tmp / "results" / "runs" / "wip1-b1r1-rep1" / "run.json").read_text(encoding="utf-8"))
        return record, p

    def test_a_detached_child_is_ended_before_the_run_settles(self):
        pid_file = self.tmp / "detached.pid"
        record, p = self.run_b1({"T5": {"builder": ["detach"]}, "_detached_pid": str(pid_file)})
        child = int(pid_file.read_text())
        self.addCleanup(TABLES.kill, child)
        self.assertTrue(ended(child), f"a detached child outlived its run: {p.stdout + p.stderr}")
        self.assertIs(record["teardown"]["contained"], True, record["teardown"])

    def test_a_failed_discovery_blocks_settlement_and_the_sandboxs_removal(self):
        real_finish, real_table, tearing = wip.Run.finish, wip.contain.process_table, []

        def finish(run):
            tearing.append(1)
            return real_finish(run)

        def table():
            if tearing:
                raise OSError("no ps")  # the process table cannot be read at teardown
            return real_table()
        with mock.patch.object(wip.Run, "finish", finish), mock.patch.object(wip.contain, "process_table", table):
            record, p = self.run_b1({"_cost": {"builder": "0.10", "reviewer": "0.10"}})
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertEqual((record["status"], record["stop_reason"]), ("stopped", "orphan-alive"))
        calls = wip.Budget.of_run(wip.Budget(self.tmp / "results").calls(), "wip1-b1r1-rep1")
        charged = {c: v["usd"] for c, v in calls.items() if v["state"] == "charged"}
        self.assertTrue(charged and all(Decimal(u) == Decimal("0.25") for u in charged.values()),
                        f"not every call was charged its full hold: {charged}")
        self.assertTrue((self.tmp / "wd" / "wip1-b1r1-rep1").is_dir(), "the sandbox was removed")

    def test_no_next_run_starts_while_a_run_cannot_vouch_for_its_processes(self):
        self.run_b1({})
        tag = wip.Budget(self.tmp / "results").calls()["wip1-b1r1-rep1/run"]["call_tag"]
        real = wip.contain.sweep

        def sweep(*a, **kw):  # the earlier run's processes cannot be vouched for; every other sweep is real
            return False if kw.get("tag") == tag else real(*a, **kw)
        with mock.patch.object(wip.contain, "sweep", sweep):
            p = runner("run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"), "--next",
                       "1", "--cost-cap-usd", "5", "--inert-cost-usd", "0.25", env=self.env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("ORPHAN_ALIVE", p.stderr)
        self.assertEqual(sorted(d.name for d in (self.tmp / "results" / "runs").iterdir()), ["wip1-b1r1-rep1"])


class TestEachDispatchIsContainedBeforeItSettles(Tmp):
    """Codex review of PR #668 (C-b): a completed builder was settled, at the cost it reported, long
    before the run's final sweep, so a child it detached could keep spending after its reservation
    had shrunk. Each dispatch carries its own marker alongside the run's, and its descendants are
    swept and verified BEFORE its call is settled or its result accepted. One it left behind is
    ended and its call charged the full hold; one that cannot be vouched for stops the run."""

    def setUp(self):
        super().setUp()
        self.env, self.trip_log = tripwired_env(self.tmp)
        self.addCleanup(lambda: self.assertFalse(self.trip_log.exists(), "a harness name was reached"))
        self.pid_file = self.tmp / "detached.pid"
        self.addCleanup(lambda: self.pid_file.is_file() and TABLES.kill(self.pid_file.read_text()))

    def run_b1(self):
        script = {"T5": {"builder": ["detach"]}, "_detached_pid": str(self.pid_file),
                  "_cost": {"builder": "0.10", "reviewer": "0.10"}}
        p = runner("run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"), "--runs",
                   "wip1-b1r1-rep1", "--cost-cap-usd", "0.50", "--inert-cost-usd", "0.25",
                   "--inert-script", json.dumps(script), env=self.env)
        record = json.loads((self.tmp / "results" / "runs" / "wip1-b1r1-rep1" / "run.json").read_text(encoding="utf-8"))
        builder = wip.Budget(self.tmp / "results").calls()["wip1-b1r1-rep1/T5/a1/builder"]
        return record, builder, p

    def test_a_builder_that_left_a_detached_child_is_charged_its_hold_and_not_accepted(self):
        record, builder, p = self.run_b1()
        self.assertTrue(ended(int(self.pid_file.read_text())), "the detached child outlived its dispatch")
        self.assertEqual((builder["state"], Decimal(builder["usd"])), ("charged", Decimal("0.25")),
                         f"it was settled at what it reported: {builder}")
        a = record["units"]["T5"]["attempts"][0]
        self.assertEqual(a["outcome"], "builder-failed", p.stdout + p.stderr)
        self.assertTrue(a["left_behind"], a)

    def test_a_dispatch_it_cannot_vouch_for_stops_the_run_at_once(self):
        real = wip.contain.sweep

        def sweep(*a, **kw):  # the dispatch's own sweep cannot vouch; the run's and the oracle's can
            return False if kw.get("marker") == wip.contain.DISPATCH_MARKER else real(*a, **kw)
        with mock.patch.object(wip.contain, "sweep", sweep):
            record, builder, p = self.run_b1()
        self.assertEqual((record["status"], record["stop_reason"]), ("stopped", "orphan-alive"), p.stdout + p.stderr)
        self.assertEqual(record["units"]["T5"]["attempts"][0]["outcome"], "stopped-orphan-alive")
        self.assertEqual(record["units"]["T5"]["reviews"], [], "a review started after an unvouched dispatch")
        self.assertEqual(Decimal(builder["usd"]), Decimal("0.25"))


class TestNothingIsSettledOrAcceptedBeforeContainment(Tmp):
    """PR #668 review, the last sweep of the class: no reservation is settled and no result accepted
    before containment is verified. A lost run's recovery whose sweep cannot vouch charges every
    call its full hold, not what its stream reported; a saved run's binding re-run of worker code
    that cannot be contained fails the report closed."""

    def lost_run(self):
        """A lost run: one launched builder whose stream reports 0.10 of its 0.25 hold."""
        results, sandbox, lane = self.tmp / "results", self.tmp / "sandbox", self.tmp / "lane"
        (results / "runs" / "wip1-b1r1-rep1").mkdir(parents=True)
        (sandbox / "target").mkdir(parents=True)
        (sandbox / "state").mkdir()
        lane.mkdir()
        (lane / "events.jsonl").write_text(json.dumps({"type": "result", "result": "done", "total_cost_usd": 0.10})
                                           + "\n", encoding="utf-8")
        conn = sqlite3.connect(sandbox / "state" / "runtime.db")
        conn.execute("CREATE TABLE dispatches (dispatch_id TEXT, task_id TEXT, run_id TEXT, lane_dir TEXT, "
                     "state TEXT, pid INTEGER)")
        conn.execute("INSERT INTO dispatches VALUES ('disp_lost', 'task_a', 'wip1-b1r1-rep1', ?, 'completed', 0)",
                     (str(lane),))
        conn.commit()
        conn.close()
        budget = wip.Budget(results)
        budget.start_run("wip1-b1r1-rep1", sandbox, "inert", "c" * 32)
        call = "wip1-b1r1-rep1/T5/a1/builder"
        budget.hold([(call, {"run": "wip1-b1r1-rep1"})], Decimal("0.25"), Decimal("10"))
        budget.note(call, state="launched", dispatch="disp_lost")
        return results, call

    def test_a_lost_run_it_cannot_vouch_for_is_charged_its_holds(self):
        env, _trip = tripwired_env(self.tmp)
        results, call = self.lost_run()
        real = wip.contain.sweep

        def sweep(*a, **kw):  # the lost run's marker cannot be vouched for; every other sweep is real
            return False if kw.get("tag") == "c" * 32 else real(*a, **kw)
        with mock.patch.object(wip.contain, "sweep", sweep):
            p = runner("run", "--results", str(results), "--workdir", str(self.tmp / "wd"), "--runs",
                       "wip1-b3r1-rep1", "--cost-cap-usd", "5", "--inert-cost-usd", "0.25", env=env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("ORPHAN_ALIVE", p.stderr)
        charged = wip.Budget(results).calls()[call]
        self.assertEqual((charged["state"], Decimal(charged["usd"])), ("charged", Decimal("0.25")),
                         f"settled at what its stream reported while a process of it may live: {charged}")


class TestABindingRerunMustBeContained(DryRun):
    RUN, ARGS = B1_BOUNDARY

    def test_a_rerun_it_cannot_contain_fails_the_report_closed(self):
        results, real = self.copy(), wip.contain.contained_run

        def contained_run(argv, **kw):  # the binding re-run of the closed head's oracle cannot be contained
            if "rerun-" not in str(kw.get("cwd")):
                return real(argv, **kw)
            Path(kw["stdout_path"]).write_text("", encoding="utf-8")
            return 0, False, False
        with mock.patch.object(wip.contain, "contained_run", contained_run), \
                self.assertRaisesRegex(wip.SourceError, "could not be contained"):
            wip.build_report(results, basis="all")


class TestALiveRunNeedsContainment(LiveWithAFakeHarness):
    """A live run spends: it does not start where process discovery cannot contain a call (the
    helper's host check), before anything is reserved."""

    def test_a_host_blind_to_system_binaries_refuses_a_live_run(self):
        # Python visible, system binaries hidden (macOS's view): the strong probe, the default (PR #668).
        env, self.trip_log = tripwired_env(self.tmp)
        fake = self.tmp / "fake-bin"
        install_fake_harness(fake)
        env.update(PATH=os.pathsep.join([str(fake), env["PATH"]]), HOME=str(self.tmp / "home"))
        (self.tmp / "home").mkdir(exist_ok=True)
        blind = TABLES.blind_to_system_binaries(wip.contain.process_table)
        with mock.patch.object(wip, "dirty_inputs", return_value=[]), \
                mock.patch.object(wip.contain, "process_table", blind):
            p = run_in_process(["run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"),
                                "--worker", "live", "--agent", "claude", "--model", "m", "--cost-cap-usd", "20",
                                "--reservation-usd", "0.25", "--runs", "wip1-b1r1-rep1"], env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("process discovery cannot contain", p.stderr)
        self.assertFalse((self.tmp / "results" / "runs").exists())

    def test_a_host_that_hides_markers_refuses_a_live_run(self):
        p, run_json = self.live(containment="the process table does not show a call's OF_CALL_ID marker")
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("process discovery cannot contain", p.stderr)
        self.assertFalse(run_json.exists())


class TestAKilledRunStillCounts(Tmp):
    """Adversarial pass (unavailable read as 0): a runner killed outright (SIGKILL, power loss)
    writes no run.json. Its calls in the shared ledger still count against the cap until the next
    run reconciles them, the run is reported as lost, and only it may be re-run once."""

    def setUp(self):
        super().setUp()
        self.env, self.trip_log = tripwired_env(self.tmp)
        self.results = self.tmp / "results"
        (self.results / "runs" / "wip1-b1r1-rep1").mkdir(parents=True)
        budget = wip.Budget(self.results)  # its sandbox is gone: no store to ask, no worker to stop
        budget.start_run("wip1-b1r1-rep1", self.tmp / "gone", "inert")
        rid = "wip1-b1r1-rep1/T5/a1"
        budget.hold([(f"{rid}/builder", {"run": "wip1-b1r1-rep1"}), (f"{rid}/reviewer", {"run": "wip1-b1r1-rep1"})],
                    Decimal("0.50"), Decimal("10"))
        budget.charge(f"{rid}/builder", Decimal("2.50"), True)

    def test_its_spend_is_counted_and_reconciled_once(self):
        self.assertEqual(wip.spent_in(self.results), Decimal("3.00"))  # 2.50 charged + the reviewer's hold
        for _ in range(2):
            p = runner("run", "--results", str(self.results), "--workdir", str(self.tmp / "wd"), "--runs",
                       "wip1-b3r1-rep1", "--cost-cap-usd", "3.40", "--inert-cost-usd", "0.25", env=self.env)
            self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
            self.assertIn("not started", p.stderr)
            # the reviewer never launched: its hold is released; the builder's charge stays, once
            self.assertEqual(wip.spent_in(self.results), Decimal("2.50"))

    def test_it_is_reported_as_lost(self):
        runs = wip.build_report(self.results, basis="all")["runs"]
        self.assertEqual([(r["run_id"], r["status"], r["compliant"]) for r in runs],
                         [("wip1-b1r1-rep1", "lost", False)])

    def test_it_may_be_re_run_once(self):
        # -a2 passes the retry rule; the bogus second id is the refusal that must be reached
        p = runner("run", "--results", str(self.results), "--workdir", str(self.tmp / "wd"), "--runs",
                   "wip1-b1r1-rep1-a2,wip1-b9r9-rep1", "--cost-cap-usd", "0", env=self.env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("not a scheduled run", p.stderr)

    def test_a_run_keeps_its_ledger_and_binds_it(self):
        run_dir = Path(dry_run(*B1_BOUNDARY)[0].name) / "results" / "runs" / B1_BOUNDARY[0]
        record = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        calls = json.loads((run_dir / "calls.json").read_text(encoding="utf-8"))
        self.assertIn("calls.json", record["sources"])
        self.assertTrue(all(v["state"] in ("charged", "released") for v in calls.values()), calls)
        charged = sum((Decimal(v["usd"]) for v in calls.values() if v["state"] == "charged"), Decimal(0))
        cost = record["cost"]
        self.assertEqual(charged, Decimal("0.50"))
        self.assertEqual(charged, Decimal(cost["observed_usd"]) + Decimal(cost["reserved_unobserved_usd"]))


# ---------------------------------------------------------------------------- a refused credential (version 2)
# #604's wip1-b3r1-rep1 began 24 hours after its subscription token was written: the API refused all 18
# of its calls (HTTP 401), every unit parked, and the run read `complete`, so the re-run the stopping
# rule allows after an infrastructure failure was refused. refused_stream() is that run's stream.

REFUSED_USAGE = {"output_tokens_details": {"thinking_tokens": 0}, "input_tokens": 0, "cache_creation_input_tokens": 0,
                 "cache_read_input_tokens": 0, "output_tokens": 0,
                 "server_tool_use": {"web_search_requests": 0, "web_fetch_requests": 0}, "service_tier": "standard",
                 "cache_creation": {"ephemeral_1h_input_tokens": 0, "ephemeral_5m_input_tokens": 0},
                 "inference_geo": "", "iterations": [], "speed": "standard", "fallback_credit": None}


def refused_stream(text="Not logged in · Please run /login", usage=None, is_error=True, model="claude-sonnet-5-5"):
    """A dispatch's stream as Claude Code wrote it for a refused credential (wip1-b3r1-rep1)."""
    lines = [{"type": "turn_started", "dispatchId": "disp_0123456789", "monitorPid": 1},
             {"type": "system", "subtype": "init", "model": model, "apiKeySource": "none"},
             {"type": "assistant", "message": {"model": "<synthetic>", "role": "assistant", "usage": REFUSED_USAGE,
                                               "content": [{"type": "text", "text": text}]},
              "error": "authentication_failed", "is_api_error_message": True, "api_error_status": 401},
             {"type": "result", "subtype": "success", "is_error": is_error, "result": text, "duration_ms": 514,
              "duration_api_ms": 0, "api_error_status": 401, "terminal_reason": "api_error", "modelUsage": {},
              "subagent_stats": {"spawned": 0, "completed": 0}, "result_index": 0,
              "usage": REFUSED_USAGE if usage is None else usage, "total_cost_usd": 0, "num_turns": 1}]
    return "".join(json.dumps(line) + "\n" for line in lines)


ANSWERED = refused_stream(text="WIP-BUILD-DONE", is_error=False,
                          usage={**REFUSED_USAGE, "input_tokens": 12, "output_tokens": 4})


def retained_run(run_dir: Path, streams: dict, *, dispatches=None, **fields) -> Path:
    """A retained run in run.json's shape: one builder attempt per recorded dispatch, every stream
    bound by its digest, as wip1-b3r1-rep1 retained them."""
    dispatches = list(streams) if dispatches is None else dispatches
    (run_dir / "streams").mkdir(parents=True, exist_ok=True)
    for dispatch, text in streams.items():
        (run_dir / "streams" / f"{dispatch}.jsonl").write_text(text, encoding="utf-8")
    rec = {"run_id": run_dir.name, "status": "complete", "stop_reason": None,
           "units": {"T1": {"attempts": [{"n": n, "dispatch": d} for n, d in enumerate(dispatches, 1)], "reviews": []}},
           "launched_models": {d: "claude-sonnet-5-5" for d in streams}, **fields}
    (run_dir / "run.json").write_text(json.dumps(rec), encoding="utf-8")
    rebind(run_dir)
    return run_dir


class TestARefusedCredentialIsAnInfrastructureFailure(Tmp):
    def stream(self, text):
        path = self.tmp / "streams" / "disp_a.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_the_harness_error_for_a_refused_credential_is_recognised(self):
        for text in ("Not logged in · Please run /login", "OAuth token has expired. Please obtain a new token",
                     'API Error: 401 {"type":"error","error":{"type":"authentication_error"}}', "Invalid API key"):
            self.assertTrue(wip.credential_rejected(self.stream(refused_stream(text=text))), text)

    def test_an_error_that_used_tokens_or_names_no_credential_is_not(self):
        self.assertFalse(wip.credential_rejected(self.stream(refused_stream(usage={**REFUSED_USAGE, "input_tokens": 12}))))
        self.assertFalse(wip.credential_rejected(self.stream(refused_stream(text="API Error: 529 overloaded"))))
        self.assertFalse(wip.credential_rejected(self.stream(refused_stream(is_error=False))))
        self.assertFalse(wip.credential_rejected(self.stream(refused_stream().splitlines()[1] + "\n")), "no result line")

    def test_an_earlier_paid_result_makes_it_a_result(self):
        # Codex at a61f3e660a: only the last result was read, so real work before a refusal was discarded
        self.assertFalse(wip.credential_rejected(self.stream(ANSWERED + refused_stream())))
        assistant = {"type": "assistant", "message": {"model": "claude-sonnet-5-5", "usage": {**REFUSED_USAGE, "output_tokens": 9}}}
        self.assertFalse(wip.credential_rejected(self.stream(json.dumps(assistant) + "\n" + refused_stream())))
        paid = json.loads(refused_stream().splitlines()[3])
        paid["total_cost_usd"] = 0.02
        self.assertFalse(wip.credential_rejected(self.stream(json.dumps(paid) + "\n")))

    def test_any_line_but_the_refusal_makes_it_a_result(self):
        # Codex at a8068b5cd5: an assistant turn with no usage was skipped, so earlier work read as a refusal
        lines = refused_stream().splitlines(keepends=True)
        turn = json.loads(lines[2])
        for usage in (None, "absent"):
            earlier = copy.deepcopy(turn)
            if usage == "absent":
                del earlier["message"]["usage"]
            else:
                earlier["message"]["usage"] = None
            self.assertFalse(wip.credential_rejected(self.stream(json.dumps(earlier) + "\n" + "".join(lines))), usage)
        tool = copy.deepcopy(turn)
        tool["message"]["content"] = [{"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "ls"}}]
        for extra in (tool, {"type": "user", "message": {"role": "user", "content": [{"type": "tool_result"}]}},
                      {"type": "system", "subtype": "thinking_tokens", "tokens": 40}, {"type": "assistant", "message": None}):
            self.assertFalse(wip.credential_rejected(self.stream(json.dumps(extra) + "\n" + "".join(lines))), extra)
        self.assertFalse(wip.credential_rejected(self.stream("not json\n" + "".join(lines))))
        result = json.loads(lines[3])
        del result["total_cost_usd"]
        self.assertFalse(wip.credential_rejected(self.stream("".join(lines[:3]) + json.dumps(result) + "\n")),
                         "a cost the result does not report")

    def test_a_nested_count_is_work(self):
        # Codex at 616217810a: only the four top-level token counts were read
        lines = refused_stream().splitlines(keepends=True)

        def result_with(**changes):
            result = json.loads(lines[3])
            for path, value in changes.items():
                *parents, leaf = path.split(".")
                node = result
                for name in parents:
                    node = node[name]
                node[leaf] = value
            return "".join(lines[:3]) + json.dumps(result) + "\n"

        for change in ({"usage.server_tool_use.web_search_requests": 1},
                       {"usage.iterations": [{"input_tokens": 12, "output_tokens": 4}]},
                       {"usage.output_tokens_details.thinking_tokens": 7},
                       {"usage.cache_creation.ephemeral_5m_input_tokens": 5160},
                       {"modelUsage": {"claude-sonnet-5-5": {"inputTokens": 12, "costUSD": 0.01}}},
                       {"subagent_stats.spawned": 1}, {"duration_api_ms": 900}):
            self.assertFalse(wip.credential_rejected(self.stream(result_with(**change))), change)
        turn = json.loads(lines[2])
        turn["message"]["usage"] = {**REFUSED_USAGE, "server_tool_use": {"web_search_requests": 0, "web_fetch_requests": 1}}
        self.assertFalse(wip.credential_rejected(self.stream(lines[0] + lines[1] + json.dumps(turn) + "\n" + lines[3])))

    def test_the_report_reads_it_from_the_same_bound_evidence(self):
        prereg, taskset, _path, prereg_sha, taskset_path = wip.load_prereg(PREREG)
        cond = {"condition": {"id": "b1r1", "builders": 1, "reviewers": 1}}
        refused = retained_run(self.tmp / "wip1-b1r1-rep1", {f"disp_{k}": refused_stream() for k in range(3)}, **cond)
        nested = json.loads(refused_stream().splitlines()[3])
        nested["usage"]["iterations"] = [{"input_tokens": 12, "output_tokens": 4}]
        worked = retained_run(self.tmp / "wip1-b3r1-rep1", {"disp_0": refused_stream(),
                                                            "disp_1": json.dumps(nested) + "\n"}, **cond)
        args = (prereg, prereg_sha, taskset, wip.sha256_file(taskset_path))
        self.assertEqual(wip.summarize_run(refused, *args)["infrastructure"],
                         "the API refused all 3 of its model calls for the credential")
        self.assertIsNone(wip.summarize_run(worked, *args)["infrastructure"])

    def test_a_usage_it_does_not_report_is_not_zero(self):
        missing = {k: v for k, v in REFUSED_USAGE.items() if k != "output_tokens"}
        self.assertFalse(wip.credential_rejected(self.stream(refused_stream(usage=missing))))
        result = json.loads(refused_stream().splitlines()[3])
        del result["usage"]
        self.assertFalse(wip.credential_rejected(self.stream(json.dumps(result) + "\n")))

    def test_a_run_whose_every_recorded_call_was_refused_failed_for_an_infrastructure_reason(self):
        run = retained_run(self.tmp / "all", {f"disp_{k}": refused_stream() for k in range(3)})
        self.assertEqual(wip.infrastructure_failure(run, "complete"),
                         "the API refused all 3 of its model calls for the credential")
        self.assertEqual(wip.infrastructure_failure(self.tmp / "absent", "failed"), "it ended failed")

    def test_an_answered_unbound_or_unrecorded_call_is_not(self):
        streams = {f"disp_{k}": refused_stream() for k in range(3)}
        self.assertIsNone(wip.infrastructure_failure(retained_run(self.tmp / "a", {**streams, "disp_9": ANSWERED}),
                                                     "complete"), "one call was answered")
        self.assertIsNone(wip.infrastructure_failure(retained_run(self.tmp / "b", streams,
                                                                  dispatches=[*streams, "disp_9"]), "complete"),
                          "a recorded dispatch has no stream")
        self.assertIsNone(wip.infrastructure_failure(retained_run(self.tmp / "c", {}), "complete"), "no call at all")
        unbound = retained_run(self.tmp / "d", streams)
        (unbound / "streams" / "disp_8.jsonl").write_text(refused_stream(), encoding="utf-8")
        self.assertIsNone(wip.infrastructure_failure(unbound, "complete"), "an unbound stream")


class TestARunEveryCallOfWhichWasRefusedMayBeReRunOnce(Tmp):
    """The -a2 rule reads the bound record: wip1-b3r1-rep1's run.json says `complete`, its streams
    say the API refused every call. Either way the decision is made before anything launches."""

    def retained(self, streams):
        self.env, self.trip_log = tripwired_env(self.tmp)
        self.results = self.tmp / "results"
        _prereg, _taskset, _path, prereg_sha, taskset_path = wip.load_prereg(PREREG)
        return retained_run(self.results / "runs" / "wip1-b1r1-rep1", streams, prereg={"sha256": prereg_sha},
                            taskset={"sha256": wip.sha256_file(taskset_path)})

    def rerun(self, expect):
        # -a2 passes the retry rule when the bogus second id is the refusal reached
        p = runner("run", "--results", str(self.results), "--workdir", str(self.tmp / "wd"), "--runs",
                   "wip1-b1r1-rep1-a2,wip1-b9r9-rep1", "--cost-cap-usd", "0", env=self.env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn(expect, p.stderr)
        self.assertFalse(self.trip_log.exists())

    def test_it_may_be_re_run_once(self):
        self.retained({f"disp_{k}": refused_stream() for k in range(3)})
        self.rerun("not a scheduled run")

    def test_one_answered_call_makes_it_a_result_that_is_never_re_run(self):
        self.retained({**{f"disp_{k}": refused_stream() for k in range(3)}, "disp_9": ANSWERED})
        self.rerun("infrastructure failure")

    def test_earlier_work_with_no_reported_usage_is_never_re_run(self):
        # Codex at a8068b5cd5: bound, complete, and read as refused because the turn's usage was absent
        turn = json.loads(refused_stream().splitlines()[2])
        del turn["message"]["usage"]
        self.retained({**{f"disp_{k}": refused_stream() for k in range(3)},
                       "disp_9": json.dumps(turn) + "\n" + refused_stream()})
        self.rerun("infrastructure failure")

    def test_a_nested_count_is_never_re_run(self):
        # Codex at 616217810a: a bound, complete run whose call reported its tokens only in iterations
        nested = json.loads(refused_stream().splitlines()[3])
        nested["usage"]["iterations"] = [{"input_tokens": 12, "output_tokens": 4}]
        self.retained({**{f"disp_{k}": refused_stream() for k in range(3)}, "disp_9": json.dumps(nested) + "\n"})
        self.rerun("infrastructure failure")

    def test_removing_or_altering_the_answered_stream_never_authorises_a_re_run(self):
        # Codex at a61f3e660a: the gate read whatever streams were present, unchecked against run.json
        run = self.retained({**{f"disp_{k}": refused_stream() for k in range(3)}, "disp_9": ANSWERED})
        (run / "streams" / "disp_9.jsonl").write_text(refused_stream(), encoding="utf-8")
        self.rerun("infrastructure failure")
        (run / "streams" / "disp_9.jsonl").unlink()
        self.rerun("infrastructure failure")


class TestARefusedCredentialHaltsTheRun(LiveWithAFakeHarness):
    """A harness that answers every call with the refused-credential error: the first answer halts
    the run, no further call starts, and the run ends `failed`, the re-runnable status."""

    def live(self, *extra, answer_lines=None, **kw):
        install = install_fake_harness
        lines = answer_lines or refused_stream(model="wip-fake-model").splitlines(keepends=True)[1:]

        def refusing(bin_dir, **fake_kw):
            launcher = install(bin_dir, **fake_kw)
            answer = bin_dir / "refused.jsonl"
            answer.write_text("".join(lines), encoding="utf-8")
            launcher.write_text(f'#!/bin/sh\n[ "$1" = --version ] && exec {sys.executable} -I {bin_dir / "worker.py"} '
                                f'claude --version\ncat {answer}\nexit 1\n', encoding="utf-8")
            return launcher
        with mock.patch.dict(globals(), install_fake_harness=refusing):
            return super().live(*extra, **kw)

    def test_the_first_refusal_ends_the_run_failed(self):
        p, run_json = self.live()
        record = json.loads(run_json.read_text(encoding="utf-8"))
        self.assertEqual((record["status"], record["stop_reason"]), ("failed", wip.CREDENTIAL_REJECTED),
                         p.stdout + p.stderr)
        self.assertEqual(len(list((run_json.parent / "streams").glob("*.jsonl"))), 1, "a second call started")
        run = wip.build_report(self.results, basis="all")["runs"][0]
        self.assertFalse(run["compliant"])
        self.assertEqual(run["infrastructure"], "it ended failed")

    def test_earlier_work_with_no_reported_usage_never_halts_it(self):
        # Codex at a8068b5cd5: the same predicate halts the run at ingestion
        lines = refused_stream(model="wip-fake-model").splitlines(keepends=True)[1:]
        turn = json.loads(lines[1])
        del turn["message"]["usage"]
        p, run_json = self.live(answer_lines=[lines[0], json.dumps(turn) + "\n", *lines[1:]])
        record = json.loads(run_json.read_text(encoding="utf-8"))
        self.assertNotEqual(record["stop_reason"], wip.CREDENTIAL_REJECTED, p.stdout + p.stderr)
        self.assertNotEqual(record["status"], "failed")
        self.assertGreater(len(list((run_json.parent / "streams").glob("*.jsonl"))), 1)


class TestRelativePaths(unittest.TestCase):
    """--results, --workdir and --prereg given relative to another working directory: the run,
    the report and the verifier resolve them once, before anything changes directory (git reads
    a bundle from a temporary repository's cwd, events.py runs in the run directory)."""

    @classmethod
    def setUpClass(cls):
        tmp, cls.env, cls.trip_log, cls.proc = dry_run(*B1_BOUNDARY, relative=True)
        cls.root = Path(tmp.name).resolve()

    def test_a_relative_results_dir_runs_reports_and_verifies(self):
        run_json = self.root / "results" / "runs" / B1_BOUNDARY[0] / "run.json"
        self.assertTrue(run_json.is_file(), self.proc.stdout + self.proc.stderr)
        record = json.loads(run_json.read_text(encoding="utf-8"))
        self.assertTrue(Path(record["sandbox"]).is_absolute())
        self.assertEqual(record["status"], "stopped")
        rel = os.path.relpath(PREREG, self.root)
        p = runner("--prereg", rel, "report", "--results", "results", "--basis", "all", env=self.env, cwd=self.root)
        self.assertEqual(p.returncode, 0, p.stderr)
        report = json.loads((self.root / "results" / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["runs"][0]["binding_problems"], [])
        v = runner("--prereg", rel, "verify", "--results", "results", "--report", "results/report.json",
                   "--report-md", "results/report.md", env=self.env, cwd=self.root)
        self.assertEqual(v.returncode, 0, v.stderr)
        self.assertFalse(self.trip_log.exists())


# ---------------------------------------------------------------------------- the container harness's entry criteria
# The Codex review of PR #668 at 9db89fbe3c named three P1s the live tier must not come back with
# (docs/runtime-scripts.md, "The container harness's entry criteria"). Each test below fails on
# 54fe725bee.

class TestAnUncontainedGateStopsTheDrain(Tmp):
    """(a) A merge gate whose oracle could not be contained writes UNCONTAINED to its journal and
    fails. The runner read that only after the drain loop, so the entry was bounced and the queue
    drained again: another unit's gate oracle started while the first one's child survived.
    Containment is checked right after every drain, and nothing is bounced or retried after it."""

    def merge(self, gate_lines, halt=None):
        run = bare_run(self.tmp)
        run.halt = halt
        run.sb = argparse.Namespace(dir=self.tmp / "sb", target=self.tmp / "target", env={})
        run.sb.dir.mkdir()
        run.integration, run.taskset_path, run.merges, run.commands = "wip-integration", TASKSET, [], []
        run.units = {t: {"store_task": f"task_{t}", "attempts": []} for t in ("T1", "T2")}
        attempts = {t: {"branch": f"wip/{t}", "head": h * 40, "tree": "e" * 40} for t, h in (("T1", "a"), ("T2", "b"))}
        calls = []

        def mq(*args, check=True, bounded=False):
            calls.append(args[0])
            if args[0] == "acquire":
                return 0, {"token": "tok"}
            if args[0] == "drain" and calls.count("drain") == 1:  # T1's gate fails; its journal says why
                (run.sb.dir / "gate-tags.txt").write_text("".join(line + "\n" for line in gate_lines), encoding="utf-8")
                return 1, {"code": "queue_frozen", "data": {"entry": "e1", "unit": "task_T1", "reason": "gate_failed",
                                                            "drain": {"steps": []}}}
            if args[0] == "status":
                return 0, {"all": [{"unit": "task_T1", "run_id": run.rid, "reviewed_sha": "a" * 40, "state": "failed",
                                    "reason": "gate_failed"},
                                   {"unit": "task_T2", "run_id": run.rid, "reviewed_sha": "b" * 40, "state": "queued",
                                    "reason": None}]}
            return 0, {"steps": []}
        run.mq = mq
        run.integration_head = lambda: "c" * 40
        with mock.patch.object(wip, "git", return_value=subprocess.CompletedProcess([], 0, b"", b"")):
            run.merge(["T1", "T2"], attempts)
        return run, calls, attempts

    def test_no_bounce_and_no_second_drain_after_an_uncontained_gate(self):
        run, calls, attempts = self.merge(["d" * 32, f"UNCONTAINED {self.tmp / 'kept'}"])
        self.assertEqual(calls.count("drain"), 1, f"the queue drained again after an uncontained gate: {calls}")
        self.assertNotIn("resolve", calls, f"the entry was bounced after an uncontained gate: {calls}")
        self.assertEqual(run.halt, "orphan-alive")
        self.assertEqual({t: a["outcome"] for t, a in attempts.items()},
                         {"T1": "stopped-orphan-alive", "T2": "stopped-orphan-alive"})

    def test_an_ordinary_failed_gate_is_still_bounced_and_retried(self):
        run, calls, attempts = self.merge(["d" * 32])
        self.assertEqual(calls.count("drain"), 2, calls)
        self.assertIn("resolve", calls)
        self.assertIsNone(run.halt)
        self.assertEqual(attempts["T1"]["outcome"], "gate-failed")

    def test_a_run_already_halted_orphan_alive_starts_no_gate(self):
        _run, calls, attempts = self.merge([], halt="orphan-alive")
        self.assertEqual(calls, [], "a gate could start after a failed containment")

    def test_an_uncontained_gate_overrides_an_earlier_halt(self):
        # Codex at 47e0616eac: `halt = halt or "orphan-alive"` kept an earlier reason, and every
        # guard asks for orphan-alive, so after a model-mismatch the drain went on beside a survivor.
        run, calls, _attempts = self.merge(["d" * 32, f"UNCONTAINED {self.tmp / 'kept'}"], halt="model-mismatch")
        self.assertEqual(run.halt, "orphan-alive")
        self.assertEqual(calls.count("drain"), 1, f"the queue drained again after an uncontained gate: {calls}")
        self.assertNotIn("resolve", calls, f"the entry was bounced after an uncontained gate: {calls}")


class TestNoOracleStartsAfterAnUncontainedOne(Tmp):
    """(a), the same class one step earlier: when one unit's oracle could not be contained, the next
    unit's oracle still started, and its passing units went on to the merge gate."""

    def test_a_second_units_oracle_never_starts(self):
        env, trip_log = tripwired_env(self.tmp)
        real, checkouts = wip.contain.contained_run, []

        def contained_run(argv, **kw):  # every one of the run's own verifications (under ck/) survives
            if "/ck/" not in str(kw.get("cwd")):
                return real(argv, **kw)
            checkouts.append(Path(kw["cwd"]).name)
            Path(kw["stdout_path"]).write_text("", encoding="utf-8")
            return 0, False, False
        with mock.patch.object(wip.contain, "contained_run", contained_run):
            p = runner("run", "--results", str(self.tmp / "results"), "--workdir", str(self.tmp / "wd"), "--runs",
                       "wip1-b3r1-rep1", "--cost-cap-usd", "0", env=env)
        record = json.loads((self.tmp / "results" / "runs" / "wip1-b3r1-rep1" / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(len(checkouts), 1, f"an oracle started after an uncontained one: {checkouts}")
        self.assertEqual((record["status"], record["stop_reason"]), ("stopped", "orphan-alive"), p.stdout + p.stderr)
        self.assertEqual(record["merges"], [], "a merge gate ran after an uncontained oracle")
        self.assertFalse(trip_log.exists())


class TestRecoveryReadsTheGateJournal(Tmp):
    """(b) Recovery and the check before a run read only the markers in the spend ledger. A runner
    that died after an uncontained gate, before gate_tags() copied the gate's markers into the
    ledger, left gate-tags.txt unread, and the next run started beside the surviving child. The
    gate journal is synced before each step starts and read on its own, whatever the ledger holds."""

    def test_a_gate_marker_the_ledger_never_got_is_swept_before_the_next_run(self):
        env, _trip = tripwired_env(self.tmp)
        results, sandbox, tag = self.tmp / "results", self.tmp / "sandbox", os.urandom(16).hex()
        (results / "runs" / "wip1-b1r1-rep1").mkdir(parents=True)  # lost: no run.json
        sandbox.mkdir()
        wip.Budget(results).start_run("wip1-b1r1-rep1", sandbox, "inert", "c" * 32)
        (sandbox / "gate-tags.txt").write_text(f"{tag}\nUNCONTAINED {sandbox / 'kept'}\n", encoding="utf-8")
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                 env={**os.environ, wip.contain.CALL_MARKER: tag}, start_new_session=True,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: child.poll() is None and (child.kill(), child.wait()))
        deadline = time.monotonic() + 3
        while child.pid not in wip.contain.call_processes(wip.contain.process_table(), tag=tag) \
                and time.monotonic() < deadline:
            time.sleep(0.02)
        p = runner("run", "--results", str(results), "--workdir", str(self.tmp / "wd"), "--runs",
                   "wip1-b1r1-rep1-a3", "--cost-cap-usd", "0", env=env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("one re-run", p.stderr)  # refused after the check, for its own reason
        self.assertIsNotNone(child.wait(timeout=10), "the gate's surviving child outlived the check")

    def test_a_marker_the_check_cannot_vouch_for_refuses_the_run(self):
        env, _trip = tripwired_env(self.tmp)
        results, sandbox, tag = self.tmp / "results", self.tmp / "sandbox", os.urandom(16).hex()
        sandbox.mkdir()
        wip.Budget(results).start_run("wip1-b1r1-rep1", sandbox, "inert", "c" * 32)
        (sandbox / "gate-tags.txt").write_text(f"{tag}\n", encoding="utf-8")
        real = wip.contain.sweep

        def sweep(*a, **kw):
            return False if kw.get("tag") == tag else real(*a, **kw)
        with mock.patch.object(wip.contain, "sweep", sweep):
            p = runner("run", "--results", str(results), "--workdir", str(self.tmp / "wd"), "--next", "1",
                       "--cost-cap-usd", "0", env=env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("ORPHAN_ALIVE", p.stderr)
        self.assertFalse((self.tmp / "wd").exists(), "a run started beside a gate marker nothing vouched for")

    def test_each_gate_marker_is_synced_before_its_step_starts(self):
        tags_file, landing = self.tmp / "gate-tags.txt", self.tmp / "landing.json"
        landing.write_text("{}", encoding="utf-8")
        (self.tmp / "checkout").mkdir()
        synced, on_disk = [], []
        real_fsync = os.fsync

        def fsync(fd):
            synced.append(fd)
            return real_fsync(fd)

        def contained_run(argv, **kw):
            on_disk.append((kw["tag"], len(synced), tags_file.read_text(encoding="utf-8")))
            Path(kw["stdout_path"]).write_text("", encoding="utf-8")
            return 0, False, True
        cwd = os.getcwd()
        try:
            os.chdir(self.tmp / "checkout")
            with mock.patch.object(wip.contain, "contained_run", contained_run), \
                    mock.patch.object(wip.os, "fsync", fsync), contextlib.redirect_stdout(io.StringIO()):
                wip.cmd_gate(argparse.Namespace(taskset=str(TASKSET), landing=str(landing), tags_file=str(tags_file)))
        finally:
            os.chdir(cwd)
        self.assertTrue(on_disk)
        for tag, syncs, text in on_disk:
            self.assertIn(tag, text.splitlines())
            self.assertGreaterEqual(syncs, 1, "a gate marker was not synced before its step started")


class TestABindingRerunKeepsItsMarkersAndItsFiles(DryRun):
    """(c) The report's binding re-run of an oracle ran worker-written code with no marker recorder,
    and under a TemporaryDirectory: failed containment raised without a final sweep or a durable
    record, the directory the error named was deleted on the way out, and no later run check could
    see what survived. Each step's marker is now journaled (and synced) before it starts, in a
    directory of the re-run's own under KEPT_ROOT; a failure sweeps every marker once more and keeps
    the directory; and every run check sweeps a journal no sweep ever vouched for."""

    RUN, ARGS = B1_BOUNDARY

    def uncontained_report(self, vouch):
        results, real, real_sweep = self.copy(), wip.contain.contained_run, wip.contain.sweep
        tags, swept, journaled = [], [], []

        def contained_run(argv, **kw):  # the binding re-run of the closed head's oracle cannot be contained
            if "rerun-" not in str(kw.get("cwd")):
                return real(argv, **kw)
            tags.append(kw["tag"])
            journaled.append(any(kw["tag"] in j.read_text(encoding="utf-8").splitlines()
                                 for j in Path(wip.KEPT_ROOT).glob("*/*") if j.is_file()))
            Path(kw["stdout_path"]).write_text("", encoding="utf-8")
            return 0, False, False

        def sweep(*a, **kw):
            swept.append(kw.get("tag"))
            return vouch if kw.get("tag") in tags else real_sweep(*a, **kw)
        with mock.patch.object(wip.contain, "contained_run", contained_run), \
                mock.patch.object(wip.contain, "sweep", sweep), \
                self.assertRaisesRegex(wip.SourceError, "could not be contained") as raised:
            wip.build_report(results, basis="all")
        kept = Path(re.search(r"kept at (\S+?):", str(raised.exception)).group(1))
        return kept, tags, swept, journaled, sweep

    def test_its_markers_are_journaled_swept_and_its_files_kept(self):
        kept, tags, swept, journaled, _sweep = self.uncontained_report(vouch=True)
        self.assertTrue(tags)
        self.assertEqual(journaled, [True] * len(tags), "a re-run step started before its marker was on disk")
        for tag in tags:
            self.assertIn(tag, swept, "no sweep followed the re-run's failed containment")
        self.assertTrue(kept.is_dir(), f"the directory the error names is gone: {kept}")
        self.assertTrue(any(p.name.startswith("oracle-") for p in kept.iterdir()), list(kept.iterdir()))

    def test_a_marker_no_sweep_vouched_for_blocks_every_later_run(self):
        kept, tags, _swept, _journaled, sweep = self.uncontained_report(vouch=False)
        work = Path(tempfile.mkdtemp(prefix="wip-curve-after-rerun-"))
        self.addCleanup(shutil.rmtree, work, True)
        with mock.patch.object(wip.contain, "sweep", sweep):
            p = runner("run", "--results", str(work / "results"), "--workdir", str(work / "wd"), "--runs",
                       "wip1-b1r1-rep1-a3", "--cost-cap-usd", "0", env=self.env)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("ORPHAN_ALIVE", p.stderr)
        self.assertIn(str(kept), p.stderr)
        # once a sweep vouches (the survivor is gone), the check lets the next run through
        p = runner("run", "--results", str(work / "results"), "--workdir", str(work / "wd"), "--runs",
                   "wip1-b1r1-rep1-a3", "--cost-cap-usd", "0", env=self.env)
        self.assertIn("one re-run", p.stderr)


if __name__ == "__main__":
    unittest.main()
