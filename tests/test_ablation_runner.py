#!/usr/bin/env python3
"""Contract tests for the #606 paired runner and reporter (scripts/_ablation_run.py).

The runner must refuse to start without an explicit cost cap, refuse a live run the owner has not
authorised, run the whole pipeline with an INERT stand-in (no model, nothing spent), measure what a
harness actually did (phases entered, deferred reads, violations, usage through events.py), and
report per-mission effects where a cheaper prompt that misses an obligation is never a successful
reduction.

Safety: no test here may reach a real agent CLI. The module puts a stub `claude` (logs and exits
97) first on PATH with SHELL=/bin/sh for its whole run, every stub/fixture cell runs behind the
runner's own tripwires, and every test checks the stub's log stayed empty.

    python3 -m unittest tests.test_ablation_runner -v
"""
import contextlib
import copy
import importlib.util
import io
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ablation = _load("ablation_for_runner_tests", "scripts/ablation.py")
runner = ablation._runner()
PREREG = ablation.load_prereg()
_CURRENT = []


def current_registration():
    """A copy of the registration, unbound and pinned to the catalog now. The committed one is
    frozen at its run's commit, so a live run refuses it here as stale before any later check runs."""
    if not _CURRENT:
        prereg = {k: v for k, v in PREREG.items() if k != ablation.BOUND_KEY}
        prereg["version"] = PREREG["version"] + 1  # the bound version has spent its authorisation
        prereg["registered_payloads"] = ablation.measure(prereg)
        _CURRENT.append(prereg)
    return copy.deepcopy(_CURRENT[0])


SAFETY = {}
# The host probe, as the runner has it. setUpModule injects a proven host in its place (Python-level,
# never an environment variable or flag): these tests are about the runner, not this machine. The
# probe's own tests, and the refusal tests, put the real one back (PR #668 review).
REAL_PROBE, REAL_TABLE = runner.containment_problem, runner.process_table
# The live tier's refusal (PR #668: disabled outside the container-based live harness). These
# tests drive the live machinery, so setUpModule lifts it in this process the same Python-level
# way; TheLiveTierIsDisabled puts the real one back, and runs the CLI as its own process too.
REAL_LIVE_GATE = runner.live_disabled
DISABLED = "live runs are disabled outside the container-based live harness"

def _fixture(name):
    spec = importlib.util.spec_from_file_location(f"fixture_{name}", ROOT / "tests" / "fixtures" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


TABLES = _fixture("containment_tables")  # a process table blind to system binaries (PR #668 review)


def setUpModule():
    bindir = Path(tempfile.mkdtemp(prefix="of-ablation-stub-claude-"))
    log = bindir / "claude.log"
    stub = bindir / "claude"
    stub.write_text(f"#!/bin/sh\necho \"claude $*\" >> '{log}'\nexit 97\n", encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    SAFETY.update(bindir=bindir, log=log, path=os.environ.get("PATH", ""),
                  shell=os.environ.get("SHELL"))
    os.environ["PATH"] = f"{bindir}{os.pathsep}{SAFETY['path']}"
    os.environ["SHELL"] = "/bin/sh"
    SAFETY["probe"] = mock.patch.object(runner, "containment_problem", lambda system_binary=True: None)
    SAFETY["probe"].start()
    SAFETY["live"] = mock.patch.object(runner, "live_disabled", lambda: None)
    SAFETY["live"].start()


def tearDownModule():
    SAFETY["live"].stop()
    SAFETY["probe"].stop()
    os.environ["PATH"] = SAFETY["path"]
    if SAFETY["shell"] is None:
        os.environ.pop("SHELL", None)
    else:
        os.environ["SHELL"] = SAFETY["shell"]
    shutil.rmtree(SAFETY["bindir"])


def run_main(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = ablation.main(argv)
    return code, out.getvalue(), err.getvalue()


# One deterministic stub harness, several behaviours. It never calls a model; `call-claude`
# deliberately tries to, so the tripwire can be seen catching it.
STUB = textwrap.dedent(r'''
    import json, os, re, subprocess, sys
    args = sys.argv[1:]
    def opt(name, default=None):
        if name in args:
            return args[args.index(name) + 1]
        return next((a.split("=", 1)[1] for a in args if a.startswith(name + "=")), default)
    mode = opt("--mode")
    task = sys.stdin.read()
    def spawn_sleeper(pids_file):
        """A grandchild that sleeps (and holds no pipe), recorded with its parent: the process
        tree a timeout or an interrupt must take down whole."""
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        with open(pids_file, "w", encoding="utf-8") as fh:
            json.dump([os.getpid(), child.pid], fh)
    def spawn_escaper(pids_file):
        """A grandchild in a session of its own from birth (setsid) that sleeps: no process group
        of the call holds it, so only the call's marker can find it (#657 review K4)."""
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
        with open(pids_file, "w", encoding="utf-8") as fh:
            json.dump([child.pid], fh)
    if mode == "grader-escape":
        spawn_escaper(os.environ["ABLATION_GRADER_USAGE"] + ".pids")
    if mode == "grader-hang":
        spawn_sleeper(os.environ["ABLATION_GRADER_USAGE"] + ".pids")
        import time
        time.sleep(60)
    if mode.startswith("grader"):
        sink = os.environ.get("ABLATION_GRADER_USAGE")
        if sink:
            with open(sink + ".argv.json", "w", encoding="utf-8") as fh:
                json.dump(sys.argv, fh)
        if mode in ("grader-json", "grader-json-hang"):
            result = {"type": "result", "result": "not a verdict", "total_cost_usd": float(opt("--cost", "0"))}
            if "--no-usage-model" not in args:
                result["modelUsage"] = {opt("--usage-model", opt("--model", "stub")): {}}
            print(json.dumps(result), flush=True)
            if mode == "grader-json-hang":  # a whole answer, then no exit: the meter's timeout kills it
                import time
                time.sleep(60)
        else:
            print("not json")
        sys.exit(0)
    # Claude Code's system/init line names the model it runs: the --model it was handed (the live
    # tier appends one), else its own default. --init-model makes it name another; --no-init, none.
    init = {"type": "system", "subtype": "init", "model": opt("--init-model", opt("--model", "stub"))}
    out = os.environ["ABLATION_OUT"]
    from pathlib import Path
    def alive(pid):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True
    # Every process an EARLIER cell recorded that is still alive as this cell starts.
    earlier = [pid for f in Path(out).parents[3].rglob("*.pids") for pid in json.loads(f.read_text())]
    with open(os.path.join(out, "stub-env.json"), "w", encoding="utf-8") as fh:
        json.dump({"argv": sys.argv, "out": out, "catalog": os.environ["ABLATION_CATALOG"],
                   "alive_at_start": [pid for pid in earlier if alive(pid)]}, fh)
    if mode == "hang":
        spawn_sleeper(os.path.join(out, "agent.pids"))
        print(json.dumps(init), flush=True)
        import time
        time.sleep(60)
    if mode == "orphan":
        spawn_sleeper(os.path.join(out, "agent.pids"))
    if mode == "escape":
        spawn_escaper(os.path.join(out, "agent.pids"))
    cues = re.findall(r"([A-Za-z0-9-]+)\.md at ([A-Z][A-Z0-9_-]*)", "\n".join(
        p for p in task.split("\n\n") if p.startswith("DEFERRED READS")))
    catalog = os.environ["ABLATION_CATALOG"]
    def say(blocks):
        print(json.dumps({"type": "assistant", "message": {"content": blocks}}))
    def read(name):
        return {"type": "tool_use", "name": "Read",
                "input": {"file_path": f"{catalog}/runtime/{name}.md"}}
    if "--no-init" not in args:
        print(json.dumps(init))
    if "--synthetic-error" in args:  # Claude Code's own message for an API error: no model ran it
        print(json.dumps({"type": "assistant", "message": {"model": "<synthetic>", "content": [
            {"type": "text", "text": "API Error: 529 overloaded"}]}}))
    if opt("--recording"):  # a pinned #602 recording, handed on as this cell's own
        import shutil
        shutil.copyfile(opt("--recording"), os.path.join(out, "trajectory.jsonl"))
    phases = list(dict.fromkeys(p for _n, p in cues))
    if mode == "skip-reads":
        say([{"type": "text", "text": f"PHASE: {p}"} for p in phases])
    elif mode == "late":
        say([{"type": "text", "text": f"PHASE: {p}"} for p in phases] + [read(n) for n, _p in cues])
    elif mode == "edit-spec":
        with open("SPEC.md", "a", encoding="utf-8") as fh:
            fh.write("- AC-2 dropped: out of scope\n")
    elif mode == "call-claude":
        subprocess.run(["claude", "-p", "hello"], input="", capture_output=True)
    cost = float(opt("--cost", "1.0" if mode == "spend" else "0"))
    if mode != "no-usage":
        result = {"type": "result", "result": "done", "total_cost_usd": cost,
                  "usage": {"input_tokens": len(task) // 4, "output_tokens": 1,
                            "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}}
        if opt("--usage-model"):
            result["modelUsage"] = {opt("--usage-model"): {}}
        print(json.dumps(result))
''')


class SafetyNet(unittest.TestCase):
    def tearDown(self):
        log = SAFETY["log"]
        self.assertFalse(log.exists() and log.read_text().strip(),
                         f"a test reached the `claude` on PATH: {log.read_text() if log.exists() else ''}")

    def tmpdir(self):
        tmp = Path(tempfile.mkdtemp(prefix="of-ablation-run-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        return tmp

    def stub_cmd(self, mode, *extra):
        script = self.tmpdir() / "stub_harness.py"
        script.write_text(STUB, encoding="utf-8")
        return " ".join([sys.executable, str(script), "--mode", mode, *extra])

    def in_tmp_cwd(self):
        """A fresh directory as the process cwd for this test (restored after)."""
        tmp = self.tmpdir()
        cwd = os.getcwd()
        os.chdir(tmp)
        self.addCleanup(os.chdir, cwd)
        return tmp


class RefusalsBeforeAnythingRuns(SafetyNet):
    """Every refusal exits 2 and writes nothing: no results dir, no cell, no spend."""

    def refused(self, argv, needle, prereg=None):
        out = self.tmpdir() / "out"
        if prereg is not None:
            path = self.tmpdir() / "prereg.json"
            path.write_text(json.dumps(prereg), encoding="utf-8")
            argv = ["--prereg", str(path)] + argv
        code, _stdout, err = run_main(argv + ["--out", str(out)])
        self.assertEqual(code, 2, err)
        self.assertIn(needle, err)
        self.assertFalse(out.exists(), "a refused run wrote its results directory")

    def test_no_explicit_cap_no_run(self):
        self.refused(["run", "--dry-run"], "refusing to start without an explicit --cost-cap-usd")

    def test_a_negative_or_infinite_cap_is_refused(self):
        self.refused(["run", "--dry-run", "--cost-cap-usd", "-1"], "finite, non-negative")
        self.refused(["run", "--dry-run", "--cost-cap-usd", "inf"], "finite, non-negative")

    def test_the_tier_must_be_chosen_and_coherent(self):
        self.refused(["run", "--cost-cap-usd", "0"], "choose a tier")
        self.refused(["run", "--dry-run", "--tier", "live", "--cost-cap-usd", "0"], "--dry-run is the fixture tier")
        self.refused(["run", "--dry-run", "--cost-cap-usd", "0", "--harness-cmd", "x"],
                     "runs only the inert stand-in")
        self.refused(["run", "--tier", "stub", "--cost-cap-usd", "0"], "needs --harness-cmd")

    def test_a_malformed_registration_is_refused(self):
        prereg = copy.deepcopy(PREREG)
        prereg["seeds"] = [1]
        self.refused(["run", "--dry-run", "--cost-cap-usd", "0"], "registration is malformed", prereg)

    def test_a_task_outside_the_registered_design_is_refused(self):
        self.refused(["run", "--dry-run", "--cost-cap-usd", "0", "--mission", "deflake-it"],
                     "not in the registered design")
        self.refused(["run", "--dry-run", "--cost-cap-usd", "0", "--repeats", "9"], "--repeats must be")

    def live(self, *extra):
        return ["run", "--tier", "live", "--harness-cmd", "unused", "--model", "m",
                "--harness-version", "v", *extra]

    def authorised(self, amount=10.0):
        prereg = current_registration()
        prereg["cost_cap"].update(status=ablation.AUTHORISED, authorised_usd=amount,
                                  authorised_by="test fixture (not an authorisation)")
        return prereg

    def pending(self):
        # The committed registration is AUTHORISED since 2026-10-24 (#606); the refusal it once
        # proved by itself is pinned on a PENDING copy, so it holds whatever the file records.
        prereg = copy.deepcopy(PREREG)
        prereg["cost_cap"].update(status=ablation.PENDING, authorised_usd=None, authorised_by=None)
        return prereg

    def test_a_host_blind_to_system_binaries_refuses_a_live_run(self):
        # Python visible, system binaries hidden (macOS's view): the strong probe refuses (PR #668).
        with mock.patch.object(runner, "containment_problem", REAL_PROBE), \
                mock.patch.object(runner, "process_table", TABLES.blind_to_system_binaries(REAL_TABLE)):
            self.refused(self.live("--cost-cap-usd", "5"), "process discovery cannot contain", self.authorised())

    def test_a_live_run_needs_the_owners_recorded_authorisation(self):
        self.refused(self.live("--cost-cap-usd", "5"), "PENDING OWNER AUTHORISATION", self.pending())

    def test_a_live_cap_must_be_within_the_authorised_amount(self):
        self.refused(self.live("--cost-cap-usd", "50"), "within the authorised USD 10.0", self.authorised())
        self.refused(self.live("--cost-cap-usd", "0"), "must be above 0", self.authorised())

    def test_a_live_run_records_model_and_version(self):
        self.refused(["run", "--tier", "live", "--harness-cmd", "x", "--cost-cap-usd", "5"],
                     "a live run records --model, --harness-version", self.authorised())

    def test_a_live_run_is_the_whole_registered_design(self):
        self.refused(self.live("--cost-cap-usd", "5", "--mission", "review-it"), "whole registered design",
                     self.authorised())
        self.refused(self.live("--cost-cap-usd", "5", "--repeats", "1"), "whole registered design",
                     self.authorised())

    def test_a_live_run_never_spends_on_a_variant_that_drops_an_obligation(self):
        prereg = self.authorised()
        prereg["reduction"]["missions"]["ship-it"]["drop_sections"] = ["Related", "Gates (only these)"]
        prereg["registered_payloads"] = ablation.measure(prereg)  # current, and honestly failing
        self.assertFalse(prereg["registered_payloads"]["ship-it"]["obligations_held"])
        self.refused(self.live("--cost-cap-usd", "5"), "['ship-it']: the variant fails the obligation check",
                     prereg)

    def test_a_live_run_needs_a_per_call_limit(self):
        self.refused(self.live("--cost-cap-usd", "5", "--agent-limit-flag", ""), "per-call limit",
                     self.authorised())
        self.refused(self.live("--cost-cap-usd", "5", "--grader-limit-flag", ""), "per-call limit",
                     self.authorised())

    def test_a_bound_registration_never_drives_a_live_run(self):
        # PR #705 review (Codex P1): the bound registration with its payloads re-pinned to today's
        # catalog passed every other live check, and would have spent its run's authorisation again.
        prereg = self.authorised()
        prereg[ablation.BOUND_KEY] = copy.deepcopy(PREREG[ablation.BOUND_KEY])
        self.refused(self.live("--cost-cap-usd", "5"), "live run is bound", prereg)

    def test_the_bound_version_with_its_marker_deleted_never_drives_a_live_run(self):
        # PR #705 review (Codex P1, round 3): deleting bound_run kept version 2 and its spent
        # AUTHORISED cap; the committed registration decides, not the submitted file's marker.
        prereg = self.authorised()
        prereg["version"] = PREREG["version"]
        self.assertNotIn(ablation.BOUND_KEY, prereg)
        self.refused(self.live("--cost-cap-usd", "5"), "live run is bound", prereg)

    def test_a_spent_identity_never_drives_a_live_run_whatever_its_file_says(self):
        # PR #705 review (Codex P1, round 4): deleting `id` too, or a canonical file that changed or
        # would not parse, let the spent version through. The ledger decides; a missing id is spent.
        prereg = self.authorised()
        prereg["version"] = PREREG["version"]
        del prereg["id"]
        self.refused(self.live("--cost-cap-usd", "5"), "id must name the registration", prereg)
        with mock.patch.object(ablation, "PREREG", self.tmpdir() / "no-such-registration.json"):
            prereg = self.authorised()
            prereg["version"] = PREREG["version"]
            self.refused(self.live("--cost-cap-usd", "5"), "live run is bound", prereg)

    def test_a_live_run_refuses_a_stale_registration(self):
        prereg = self.authorised()
        prereg["registered_payloads"]["ship-it"]["reduced_sha256"] = "0" * 64
        self.refused(self.live("--cost-cap-usd", "5"), "no longer match the catalog", prereg)

    def test_a_command_naming_another_model_is_refused(self):
        # 2026-10-25: the results named one model while every call ran another. A command that
        # names a --model other than the run's would do the same, so nothing starts.
        prereg = small_live_prereg()
        agent, grader = self.stub_cmd("plain"), self.stub_cmd("grader-json")
        base = ["run", "--tier", "live", "--cost-cap-usd", "20", "--model", "stub-model-a",
                "--harness-version", "0"]
        for argv, needle in (
                (["--harness-cmd", f"{agent} --model stub-model-b", "--grader-cmd", grader],
                 "disagrees with the agent command's --model stub-model-b"),
                (["--harness-cmd", agent, "--grader-cmd", f"{grader} --model=stub-model-b"],
                 "disagrees with the grader command's --model stub-model-b")):
            with self.subTest(needle=needle):
                self.refused(base + argv, needle, prereg)
        registered = copy.deepcopy(prereg)
        registered["harness"]["grader_cmd_default"] = f"{grader} --model stub-model-b"
        self.refused(base + ["--harness-cmd", agent],
                     "disagrees with the grader command's --model stub-model-b", registered)

    def test_a_command_with_an_option_terminator_is_refused(self):
        # #688 review: --model and the spend-limit flag are appended, so after `--` they would be
        # prompt text and the call would run its default model with no limit.
        prereg = small_live_prereg()
        agent, grader = self.stub_cmd("plain"), self.stub_cmd("grader-json")
        base = ["run", "--tier", "live", "--cost-cap-usd", "20", "--model", "stub-model-a",
                "--harness-version", "0"]
        for argv, needle in (
                (["--harness-cmd", f"{agent} --", "--grader-cmd", grader],
                 "the agent command holds an option terminator (--)"),
                (["--harness-cmd", agent, "--grader-cmd", f"{grader} --"],
                 "the grader command holds an option terminator (--)")):
            with self.subTest(needle=needle):
                self.refused(base + argv, needle, prereg)

    def test_only_a_terminator_after_claude_ends_its_options(self):
        # #688 review: a wrapper's own separator (trajectory_harness.py -- claude …) is safe, since
        # the flags appended at the end still reach claude as options.
        problem = runner.terminator_problem
        self.assertIsNone(problem(["python3", "/repo/scripts/trajectory_harness.py", "--", "claude", "-p"]))
        self.assertIsNone(problem(["/usr/local/bin/claude", "-p", "--output-format", "json"]))
        self.assertIn("after claude", problem(["python3", "trajectory_harness.py", "--", "claude", "-p", "--"]))
        self.assertIn("after claude", problem(["claude", "-p", "--"]))
        self.assertIn("names no claude", problem(["python3", "agent.py", "--", "x"]))

    def test_a_fallback_model_is_refused(self):
        # #688 review: a fallback lets the call switch off the requested model mid-run.
        prereg = small_live_prereg()
        agent, grader = self.stub_cmd("plain"), self.stub_cmd("grader-json")
        base = ["run", "--tier", "live", "--cost-cap-usd", "20", "--model", "stub-model-a",
                "--harness-version", "0"]
        for argv, needle in (
                (["--harness-cmd", f"{agent} --fallback-model stub-model-b", "--grader-cmd", grader],
                 "the agent command names --fallback-model stub-model-b"),
                (["--harness-cmd", agent, "--grader-cmd", f"{grader} --fallback-model=stub-model-b"],
                 "the grader command names --fallback-model stub-model-b")):
            with self.subTest(needle=needle):
                self.refused(base + argv, needle, prereg)


class TheDryRunExercisesThePipeline(SafetyNet):
    """One fixture-tier run: review-it, one behavioral and one trajectory task, one repeat."""

    @classmethod
    def setUpClass(cls):
        cls.out = Path(tempfile.mkdtemp(prefix="of-ablation-dry-"))
        cls.code, cls.stdout, cls.stderr = run_main(
            ["run", "--dry-run", "--cost-cap-usd", "0", "--mission", "review-it", "--task", "behavioral-4",
             "--task", "trajectory-CL-01", "--repeats", "1", "--out", str(cls.out)])
        cls.results = json.loads((cls.out / "results.json").read_text())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.out)

    def cells(self, **match):
        return [c for c in self.results["cells"] if all(c[k] == v for k, v in match.items())]

    def test_it_completes_labelled_as_fixture_and_not_evidence(self):
        self.assertEqual(self.code, 0, self.stderr)
        self.assertTrue(self.results["complete"])
        self.assertEqual(self.results["tier"], "fixture")
        self.assertIn("NOT EVIDENCE", self.results["evidence"])
        self.assertEqual(self.results["model"], "inert-stand-in")
        report = (self.out / "report.md").read_text()
        self.assertIn("NOT EVIDENCE", report)
        self.assertIn("Recommendation: none", report)

    def test_only_the_stand_in_ran(self):
        self.assertEqual(self.results["safety"]["tripwire_hits"], "")
        self.assertEqual(self.results["safety"]["stand_in_runs"], {"agent": 4, "grader": 2})
        self.assertEqual(self.results["cost"]["spent_usd"], 0)

    def test_every_pair_ran_both_arms_on_identical_starting_bytes(self):
        for task in ("behavioral-4", "trajectory-CL-01"):
            arms = {c["arm"]: c for c in self.cells(task=task)}
            self.assertEqual(set(arms), {"baseline", "reduced"})
            trees = []
            for arm in arms:
                ws = self.out / "cells" / "review-it" / task / "r0" / arm / "workspace"
                trees.append(sorted(str(p.relative_to(ws)) for p in ws.rglob("*") if p.is_file()))
            self.assertEqual(trees[0], trees[1], task)

    def test_the_grader_bill_is_measured_through_the_meter(self):
        for cell in self.cells(task="behavioral-4"):
            self.assertEqual(cell["grader_cost_usd"], 0.0)
            self.assertEqual(cell["charged_usd"], 0.0)

    def test_usage_comes_through_events_py(self):
        events = runner.events_mod()
        for cell in self.results["cells"]:
            log = self.out / "cells" / cell["mission"] / cell["task"] / "r0" / cell["arm"] / "events.jsonl"
            kinds = [e["kind"] for e in events.read_log(log)[0]]
            self.assertIn("model.usage", kinds)
            self.assertEqual(cell["cost_usd"], 0.0)
            self.assertIsNotNone(cell["input_tokens"])
        for task in ("behavioral-4", "trajectory-CL-01"):
            arms = {c["arm"]: c for c in self.cells(task=task)}
            self.assertLess(arms["reduced"]["input_tokens"], arms["baseline"]["input_tokens"])

    def test_deferred_reads_are_measured_in_both_arms(self):
        for cell in self.cells(arm="reduced"):
            self.assertTrue(cell["deferred_reads"])
            self.assertEqual(set(cell["deferred_reads"].values()), {"on-time"})
            self.assertEqual(cell["read_omissions"], 0)
        for cell in self.cells(arm="baseline"):
            self.assertEqual(cell["deferred_reads"], {}, "review-it defers nothing phase-keyed today")

    def test_the_existing_oracles_graded_each_cell(self):
        for cell in self.cells(task="trajectory-CL-01"):
            self.assertEqual(cell["trajectory_verdict"], "PASS")
            self.assertTrue(cell["success"])
        for cell in self.cells(task="behavioral-4"):
            self.assertTrue(cell["grader_called"])
            self.assertEqual(cell["assertions_passed"], cell["assertions"])
            self.assertTrue(cell["state_failed"], "the stand-in writes no verdict, so the state check fails")
            self.assertFalse(cell["success"])
        variant = self.results["variants"]["review-it"]
        self.assertTrue(variant["obligation_check"]["passed"])
        self.assertEqual(variant["routing"]["baseline"]["score"], 1.0)
        self.assertEqual(variant["routing"]["reduced"]["score"], 1.0)

    def test_every_registered_metric_is_a_report_row(self):
        # #652 review sweep: a metric the registration promises and the report omits is a silent
        # gap (attempted_violations was one). Every registered metric is a row of every mission table.
        report = (self.out / "report.md").read_text()
        for metric in PREREG["metrics"]:
            self.assertIn(f"| {metric['name']} |", report, metric["name"])

    def test_assertion_rows_travel_with_the_cell(self):
        for cell in self.cells(task="behavioral-4"):
            self.assertEqual(len(cell["assertion_rows"]), cell["assertions"])
            self.assertTrue(all(row["evidence"] for row in cell["assertion_rows"] if row["passed"]))

    def test_a_subset_is_never_a_verdict(self):
        report = runner.summarize(self.results, PREREG)
        self.assertEqual(report["review-it"]["verdict"], "INCOMPLETE")
        code, out, _ = run_main(["report", str(self.out / "results.json")])
        self.assertEqual(code, 0)
        self.assertIn("## review-it — INCOMPLETE [fixture tier: pipeline check, NOT EVIDENCE]", out)

    def test_a_fixture_verdict_is_never_shown_bare(self):
        # Whatever the decision rule computes on a fixture run, it is labelled where it is shown.
        results = dict(self.results, complete=True)
        with mock.patch.object(runner, "_verdict", return_value=("SUCCESSFUL_REDUCTION", "x")):
            report = runner.summarize(results, PREREG)
            text = runner.render_markdown(results, report)
        self.assertFalse(report["review-it"]["evidence"])
        self.assertIn("SUCCESSFUL_REDUCTION [fixture tier: pipeline check, NOT EVIDENCE]", text)
        self.assertNotIn("SUCCESSFUL_REDUCTION\n", text)

    def test_the_model_each_cell_ran_is_recorded(self):
        # Read off each cell's own system/init line in every tier; only the live tier checks it.
        self.assertEqual(self.results["models_observed"], ["inert-stand-in"])
        for cell in self.results["cells"]:
            self.assertEqual(cell["model"], "inert-stand-in", cell["cell"])


class TheStubTierMeasuresWhatTheHarnessDid(SafetyNet):
    def run_stub(self, mode, mission="review-it", task="behavioral-4", cap="0"):
        out = self.tmpdir() / "out"
        code, stdout, err = run_main(["run", "--tier", "stub", "--harness-cmd", self.stub_cmd(mode),
                                      "--cost-cap-usd", cap, "--mission", mission, "--task", task,
                                      "--repeats", "1", "--out", str(out)])
        return code, json.loads((out / "results.json").read_text()), stdout + err

    def test_a_phase_entered_without_its_read_is_an_omission(self):
        code, results, text = self.run_stub("skip-reads")
        self.assertEqual(code, 0, text)
        reduced = next(c for c in results["cells"] if c["arm"] == "reduced")
        self.assertEqual(reduced["read_omissions"], len(reduced["deferred_reads"]))
        self.assertGreater(reduced["read_omissions"], 0)
        self.assertIn("deferred read evidence-manifest: omitted", text)

    def test_a_read_after_the_next_phase_is_late(self):
        _code, results, _text = self.run_stub("late")
        reduced = next(c for c in results["cells"] if c["arm"] == "reduced")
        self.assertGreater(reduced["late_reads"], 0)
        self.assertEqual(reduced["read_omissions"], 0)

    def test_editing_the_frozen_spec_is_a_scope_violation(self):
        _code, results, _text = self.run_stub("edit-spec", mission="ship-it")
        for cell in results["cells"]:
            self.assertEqual(cell["scope_violations"], 1, cell["cell"])
            self.assertIn("SPEC.md: unchanged True did not hold", cell["state_failed"][0])

    def test_a_harness_reaching_for_claude_hits_the_tripwire_and_stops(self):
        code, results, _text = self.run_stub("call-claude")
        self.assertEqual(code, 1)
        self.assertTrue(results["stopped"].startswith("TRIPWIRE"), results["stopped"])
        self.assertFalse(results["complete"])
        self.assertEqual(len(results["cells"]), 1)

    def test_a_stub_that_reports_spend_stops_the_run(self):
        # Not the spend guard (that is pre-emptive, live only): a stub or the stand-in reporting any
        # cost broke the no-model contract of its tier, and the run stops on it.
        code, results, _text = self.run_stub("spend")
        self.assertEqual(code, 1)
        self.assertTrue(results["stopped"].startswith("SPEND_IN_NON_LIVE_TIER"), results["stopped"])


class RelativePathsSurviveTheCellCwd(SafetyNet):
    """#652 review, P1: a cell's command runs with the cell's workspace as cwd, so any relative
    path the run hands it (--out, ABLATION_OUT, ABLATION_CATALOG, the harness) resolved there."""

    def test_a_relative_out_runs_every_cell(self):
        tmp = self.in_tmp_cwd()
        code, _out, err = run_main(["run", "--dry-run", "--cost-cap-usd", "0", "--mission", "review-it",
                                    "--task", "behavioral-4", "--repeats", "1", "--out", "results"])
        self.assertEqual(code, 0, err)
        results = json.loads((tmp / "results" / "results.json").read_text())
        self.assertEqual(results["safety"]["stand_in_runs"]["agent"], 2)
        for cell in results["cells"]:
            self.assertEqual(cell["errors"], [], cell["cell"])
        self.assertTrue(os.path.isabs(results["agent_cmd"][0]))
        self.assertTrue(os.path.isabs(results["prereg"]["path"]))

    def test_a_relative_harness_gets_absolute_paths(self):
        tmp = self.in_tmp_cwd()
        (tmp / "tools").mkdir()
        (tmp / "tools" / "stub.py").write_text(STUB, encoding="utf-8")
        code, _out, err = run_main(["run", "--tier", "stub", "--harness-cmd",
                                    f"{sys.executable} tools/stub.py --mode plain",
                                    "--cost-cap-usd", "0", "--mission", "review-it", "--task", "behavioral-4",
                                    "--repeats", "1", "--out", "results"])
        self.assertEqual(code, 0, err)
        for arm in ("baseline", "reduced"):
            cell_dir = tmp / "results" / "cells" / "review-it" / "behavioral-4" / "r0" / arm
            seen = json.loads((cell_dir / "stub-env.json").read_text())
            self.assertTrue(os.path.isabs(seen["out"]) and os.path.isabs(seen["catalog"]), seen)
            self.assertTrue(Path(seen["catalog"], "runtime", "evidence-manifest.md").is_file())
            self.assertTrue(os.path.isabs(seen["argv"][0]))


def small_live_prereg(mission="review-it", behavioral=(4,)):
    """A TEST registration marked AUTHORISED with a one-pair design (both cells behavioral), pinned
    to the catalog as it is now. It authorises nothing: no model runs under it. It is a new
    registration, so it carries no bound_run: the committed one's run is bound and frozen."""
    prereg = {k: v for k, v in copy.deepcopy(PREREG).items() if k != ablation.BOUND_KEY}
    prereg["version"] = PREREG["version"] + 1
    prereg["mission_mix"] = [row for row in prereg["mission_mix"] if row["mission"] == mission]
    prereg["tasks"]["behavioral"]["cases"] = list(behavioral)
    prereg["tasks"]["trajectories"]["cases"] = []
    prereg.update(repeats=1, seeds=[606])
    prereg["cost_cap"].update(status=ablation.AUTHORISED, authorised_usd=100.0,
                              authorised_by="test fixture (not an authorisation)")
    prereg["registered_payloads"] = ablation.measure(prereg)
    return prereg


class TheLiveSpendGuardIsPreEmptive(SafetyNet):
    """#652 review, P1: a behavioral cell could start with exactly its agent reservation left, spend
    it, then call the grader. The guard now reserves every call a cell will make (agent + grader)
    before it starts, passes each call its per-call limit, and charges an unmeasured call in full.
    Driven by a stub agent and grader that REPORT costs; no model runs."""

    AGENT, GRADER = 5.0, 1.0  # the registration's per-call reservations

    def test_the_registered_reservations_are_what_these_cases_assume(self):
        cap = PREREG["cost_cap"]
        self.assertEqual((cap["max_cost_per_agent_run_usd"], cap["grader_reserve_usd"]), (self.AGENT, self.GRADER))

    def run_small(self, cap, agent_cost, grader="grader-json", grader_cost=0.25, *extra):
        path = self.tmpdir() / "prereg.json"
        path.write_text(json.dumps(small_live_prereg()), encoding="utf-8")
        out = self.tmpdir() / "out"
        code, _stdout, err = run_main(
            ["--prereg", str(path), "run", "--tier", "live", "--cost-cap-usd", str(cap),
             "--harness-cmd", self.stub_cmd("plain", "--cost", str(agent_cost)),
             "--grader-cmd", self.stub_cmd(grader, "--cost", str(grader_cost)),
             "--model", "stub-not-a-model", "--harness-version", "0", "--out", str(out), *extra])
        results = json.loads((out / "results.json").read_text()) if (out / "results.json").is_file() else None
        return code, results, err, out

    def test_the_reviewers_boundary_never_starts_a_cell_it_cannot_cover(self):
        # After cell one, the old guard saw exactly the USD 5 agent reserve left and started cell
        # two, whose grader then pushed spend past the cap.
        code, results, err, _ = self.run_small(11.0, 5.0)
        self.assertEqual(code, 1, err)
        self.assertEqual(len(results["cells"]), 1)
        self.assertTrue(results["stopped"].startswith("CAP_REACHED"), results["stopped"])
        self.assertLessEqual(results["cost"]["spent_usd"], results["cost"]["cap_usd"])
        self.assertEqual(results["cost"]["spent_usd"], 5.25)
        self.assertEqual(results["cells"][0]["grader_cost_usd"], 0.25, "the grader's bill is measured")

    def test_an_exact_fit_runs_and_lands_on_the_cap(self):
        code, results, err, _ = self.run_small(12.0, self.AGENT, "grader-json", self.GRADER)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(results["cells"]), 2)
        self.assertEqual(results["cost"]["spent_usd"], 12.0)
        code, results, _err, _ = self.run_small(11.99, self.AGENT, "grader-json", self.GRADER)
        self.assertEqual(len(results["cells"]), 1)
        self.assertTrue(results["stopped"].startswith("CAP_REACHED"), results["stopped"])
        self.assertLessEqual(results["cost"]["spent_usd"], 11.99)

    def test_an_unmeasured_grader_call_is_charged_its_full_reservation(self):
        code, results, err, _ = self.run_small(100, 2.0, "grader-text")
        self.assertEqual(code, 0, err)
        for cell in results["cells"]:
            self.assertIsNone(cell["grader_cost_usd"])
            self.assertEqual(cell["charged_usd"], 2.0 + self.GRADER)
        self.assertEqual(results["cost"]["spent_usd"], 2 * (2.0 + self.GRADER))

    def test_a_call_that_overruns_its_reservation_stops_the_run(self):
        for agent, grader in ((5.5, 0.25), (1.0, 1.5)):
            with self.subTest(agent=agent, grader=grader):
                code, results, _err, _ = self.run_small(100, agent, "grader-json", grader)
                self.assertEqual(code, 1)
                self.assertEqual(len(results["cells"]), 1)
                self.assertTrue(results["stopped"].startswith("LIMIT_BREACHED"), results["stopped"])

    def test_each_call_is_handed_its_per_call_limit(self):
        code, _results, err, out = self.run_small(100, 1.0, "grader-json", 0.1)
        self.assertEqual(code, 0, err)
        limit = PREREG["cost_cap"]["harness_limit_fraction"]
        for arm in ("baseline", "reduced"):
            cell = out / "cells" / "review-it" / "behavioral-4" / "r0" / arm
            agent_argv = json.loads((cell / "stub-env.json").read_text())["argv"]
            grader_argv = json.loads((cell / "grader-usage.json.argv.json").read_text())
            self.assertEqual(agent_argv[-2:], ["--max-budget-usd", f"{self.AGENT * limit:.2f}"])
            self.assertEqual(grader_argv[-2:], ["--max-budget-usd", f"{self.GRADER * limit:.2f}"])


def recorded_pids(root):
    return [pid for f in Path(root).rglob("*.pids") for pid in json.loads(f.read_text())]


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


class NoChildOutlivesItsCall(SafetyNet):
    """#652 review, P1: on timeout `_grade_trace` killed the meter, and the grader it had started
    kept running (and could keep spending) while later cells ran. Every agent and grader call now
    runs in its own process group, killed whole on timeout, on a leader that exits leaving children
    behind, and on SIGTERM/SIGHUP/Ctrl-C; a killed call is charged its full reservation. The fakes
    sleep and spawn a sleeping grandchild; nothing calls a model."""

    def out_dir(self):
        out = self.tmpdir() / "out"

        def reap():  # never leak a sleeper, even when the code under test does (RED runs)
            for pid in recorded_pids(out) if out.exists() else []:
                if pid_alive(pid):
                    os.kill(pid, signal.SIGKILL)
        self.addCleanup(reap)
        return out

    def assertAllDead(self, out, at_least):
        pids = recorded_pids(out)
        self.assertGreaterEqual(len(pids), at_least, "the fakes did not record their process tree")
        deadline = time.monotonic() + 5
        while any(pid_alive(p) for p in pids) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual([p for p in pids if pid_alive(p)], [], "a process outlived its call")

    def started_clean(self, out):
        envs = [json.loads(f.read_text()) for f in sorted(Path(out).rglob("stub-env.json"))]
        self.assertTrue(envs)
        return [e["alive_at_start"] for e in envs]

    def test_a_hung_grader_and_its_grandchild_die_with_the_meter_timeout(self):
        path = self.tmpdir() / "prereg.json"
        path.write_text(json.dumps(small_live_prereg()), encoding="utf-8")
        out = self.out_dir()
        with mock.patch.object(runner.eval_mod(), "GRADER_TIMEOUT_S", 3):
            code, _stdout, err = run_main(
                ["--prereg", str(path), "run", "--tier", "live", "--cost-cap-usd", "20",
                 "--harness-cmd", self.stub_cmd("plain", "--cost", "1.0"),
                 "--grader-cmd", self.stub_cmd("grader-hang"),
                 "--model", "stub-not-a-model", "--harness-version", "0", "--out", str(out)])
        results = json.loads((out / "results.json").read_text())
        self.assertEqual(len(results["cells"]), 2, err)
        self.assertAllDead(out, at_least=4)
        self.assertEqual(self.started_clean(out), [[], []], "a cell started while a grader lived")
        for cell in results["cells"]:
            self.assertTrue(cell["grader_killed"], cell["cell"])
            self.assertEqual(cell["charged_usd"], 1.0 + PREREG["cost_cap"]["grader_reserve_usd"])

    def run_stub(self, mode, out, *extra):
        return run_main(["run", "--tier", "stub", "--harness-cmd", self.stub_cmd(mode), "--cost-cap-usd", "0",
                         "--mission", "review-it", "--task", "behavioral-4", "--repeats", "1",
                         "--out", str(out), *extra])

    def test_a_timed_out_agent_dies_with_its_whole_group(self):
        out = self.out_dir()
        code, _stdout, err = self.run_stub("hang", out, "--timeout", "2")
        results = json.loads((out / "results.json").read_text())
        self.assertEqual(len(results["cells"]), 2, err)
        self.assertAllDead(out, at_least=4)
        self.assertEqual(self.started_clean(out), [[], []], "a cell started while an agent lived")
        for cell in results["cells"]:
            self.assertTrue(cell["agent_killed"])
            self.assertFalse(cell["grader_called"], "a run that never finished is not graded")
            self.assertIn("timed out", " ".join(cell["errors"]))

    def test_what_a_finished_agent_leaves_behind_is_killed(self):
        out = self.out_dir()
        code, _stdout, err = self.run_stub("orphan", out)
        self.assertEqual(code, 0, err)
        self.assertAllDead(out, at_least=4)
        self.assertEqual(self.started_clean(out), [[], []])

    def test_a_killed_live_agent_is_charged_its_full_reservation(self):
        path = self.tmpdir() / "prereg.json"
        path.write_text(json.dumps(small_live_prereg()), encoding="utf-8")
        out = self.out_dir()
        code, _stdout, err = run_main(
            ["--prereg", str(path), "run", "--tier", "live", "--cost-cap-usd", "20", "--timeout", "2",
             "--harness-cmd", self.stub_cmd("hang"), "--grader-cmd", self.stub_cmd("grader-json"),
             "--model", "stub-not-a-model", "--harness-version", "0", "--out", str(out)])
        results = json.loads((out / "results.json").read_text())
        cell = results["cells"][0]
        self.assertTrue(cell["agent_killed"], err)
        self.assertEqual(cell["charged_usd"], PREREG["cost_cap"]["max_cost_per_agent_run_usd"])
        self.assertAllDead(out, at_least=2)

    def test_an_interrupted_runner_kills_every_live_group_first(self):
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            with self.subTest(signal=sig.name):
                out = self.out_dir()
                env = {**os.environ, "SHELL": "/bin/sh"}
                proc = subprocess.Popen(
                    [sys.executable, str(ROOT / "scripts" / "ablation.py"), "run", "--tier", "stub",
                     "--harness-cmd", self.stub_cmd("hang"), "--cost-cap-usd", "0", "--mission", "review-it",
                     "--task", "behavioral-4", "--repeats", "1", "--timeout", "60", "--out", str(out)],
                    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
                deadline = time.monotonic() + 30
                while not list(out.rglob("agent.pids")) and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(list(out.rglob("agent.pids")), "the hanging agent never started")
                time.sleep(0.2)
                proc.send_signal(sig)
                try:
                    _out, err = proc.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    _out, err = proc.communicate()
                self.assertEqual(proc.returncode, 128 + sig, err[-2000:])
                self.assertAllDead(out, at_least=2)
                results = json.loads((out / "results.json").read_text())
                self.assertTrue(results["stopped"].startswith("INTERRUPTED"), results["stopped"])


class InterruptedSpendIsRecorded(SafetyNet):
    """#652 review, P2: an interrupt raised inside run_cell skipped the charge, so the cell in
    flight vanished and an interrupt during the first cell reported USD 0 although a paid call had
    started. Every paid call is now entered in an append-only, fsynced spend ledger at its full
    reservation BEFORE it starts and settled after; the interrupted cell is kept, charged what the
    ledger holds, and a later run into the same directory counts that spend against its cap."""

    AGENT, GRADER = 5.0, 1.0

    def setUp(self):
        self.prereg = self.tmpdir() / "prereg.json"
        self.prereg.write_text(json.dumps(small_live_prereg()), encoding="utf-8")
        self.out = self.tmpdir() / "out"

    def live(self, cap, *extra, agent="plain", grader="grader-json"):
        return ["--prereg", str(self.prereg), "run", "--tier", "live", "--cost-cap-usd", str(cap),
                "--harness-cmd", self.stub_cmd(agent, "--cost", "1.0"),
                "--grader-cmd", self.stub_cmd(grader, "--cost", "0.25"),
                "--model", "stub-not-a-model", "--harness-version", "0", "--out", str(self.out), *extra]

    def interrupted(self, argv, code):
        with self.assertRaises(SystemExit) as stop:
            run_main(argv)
        self.assertEqual(stop.exception.code, code)
        return json.loads((self.out / "results.json").read_text())

    def test_an_interrupt_during_the_agent_keeps_the_cell_at_its_full_reservation(self):
        with mock.patch.object(runner, "run_group", side_effect=SystemExit(128 + signal.SIGTERM)):
            results = self.interrupted(self.live(20), 143)
        self.assertTrue(results["stopped"].startswith("INTERRUPTED"), results["stopped"])
        self.assertEqual(len(results["cells"]), 1, "the cell in flight is kept")
        cell = results["cells"][0]
        self.assertTrue(cell["interrupted"])
        self.assertEqual(cell["charged_usd"], self.AGENT)
        self.assertEqual(results["cost"]["spent_usd"], self.AGENT)
        ledger = [json.loads(ln) for ln in (self.out / "spend.jsonl").read_text().splitlines()]
        self.assertEqual([(r["call"], r["event"]) for r in ledger], [("agent", "start")])
        self.assertIn("USD 5.0 this run", (self.out / "report.md").read_text())

    def test_an_interrupt_during_the_grader_charges_the_settled_agent_and_the_open_grader(self):
        with mock.patch.object(runner.eval_mod(), "_grade_trace", side_effect=SystemExit(128 + signal.SIGHUP)):
            results = self.interrupted(self.live(20), 129)
        cell = results["cells"][0]
        self.assertEqual(cell["charged_usd"], 1.0 + self.GRADER, "agent measured, grader at reservation")
        self.assertEqual(results["cost"]["spent_usd"], 1.0 + self.GRADER)

    def test_an_interrupt_during_the_grader_keeps_the_models_its_agent_ran(self):
        # #688 review: the cell cut short during grading lost the model its agent's stream named.
        with mock.patch.object(runner.eval_mod(), "_grade_trace", side_effect=SystemExit(128 + signal.SIGHUP)):
            results = self.interrupted(self.live(20), 129)
        cell = results["cells"][0]
        self.assertTrue(cell["interrupted"])
        self.assertEqual(cell["model"], "stub-not-a-model")
        self.assertEqual(cell["models"], ["stub-not-a-model"])
        self.assertEqual(results["models_observed"], ["stub-not-a-model"])

    def test_a_later_run_into_the_same_directory_counts_the_interrupted_spend(self):
        with mock.patch.object(runner, "run_group", side_effect=SystemExit(128 + signal.SIGTERM)):
            self.interrupted(self.live(20), 143)
        code, _stdout, err = run_main(self.live(7))
        self.assertEqual(code, 1, err)
        results = json.loads((self.out / "results.json").read_text())
        self.assertEqual(results["cells"], [], "USD 5 recorded + a USD 6 cell would pass the USD 7 cap")
        self.assertTrue(results["stopped"].startswith("CAP_REACHED"), results["stopped"])
        self.assertEqual((results["cost"]["prior_spent_usd"], results["cost"]["spent_usd"]), (self.AGENT, 0.0))

    def test_settled_calls_are_charged_what_they_cost(self):
        code, _stdout, err = run_main(self.live(20))
        self.assertEqual(code, 0, err)
        results = json.loads((self.out / "results.json").read_text())
        self.assertEqual(results["cost"]["spent_usd"], 2 * (1.0 + 0.25))
        ledger = [json.loads(ln) for ln in (self.out / "spend.jsonl").read_text().splitlines()]
        self.assertEqual(sorted({r["event"] for r in ledger}), ["settle", "start"])
        self.assertEqual(len(ledger), 8, "two cells x (agent, grader) x (start, settle)")

    def test_an_unreadable_ledger_refuses_the_run(self):
        self.out.mkdir()
        (self.out / "spend.jsonl").write_text('{"run": "r", "cell": "c", "call": "agent", "event": "start"\n')
        code, _stdout, err = run_main(self.live(20))
        self.assertEqual(code, 2)
        self.assertIn("spend ledger", err)

    def test_a_real_sigterm_mid_agent_records_the_reservation_durably(self):
        env = {**os.environ, "SHELL": "/bin/sh"}
        proc = subprocess.Popen([*TABLES.proven_host(sys.executable, ROOT / "scripts" / "ablation.py",
                                                     "mod._runner().containment_problem = proven; "
                                                     "mod._runner().live_disabled = lifted"),
                                 *self.live(20, "--timeout", "60", agent="hang")],
                                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: [os.kill(p, signal.SIGKILL) for p in recorded_pids(self.out) if pid_alive(p)])
        deadline = time.monotonic() + 30
        while not list(self.out.rglob("agent.pids")) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(list(self.out.rglob("agent.pids")), "the hanging agent never started")
        proc.send_signal(signal.SIGTERM)
        _out, err = proc.communicate(timeout=30)
        self.assertEqual(proc.returncode, 143, err[-2000:])
        results = json.loads((self.out / "results.json").read_text())
        self.assertEqual(results["cells"][0]["charged_usd"], self.AGENT)
        self.assertEqual(results["cost"]["spent_usd"], self.AGENT)


class TheLiveGateEnforcesTheCap(SafetyNet):
    """The live tier's cap logic, driven by a stub under a TEST registration marked AUTHORISED.
    Nothing here is live: no model runs, the directory is discarded, nothing is evidence."""

    def run_live(self, cap, mode):
        # A new test registration pinned to the catalog now, so unbound (see small_live_prereg).
        prereg = {k: v for k, v in copy.deepcopy(PREREG).items() if k != ablation.BOUND_KEY}
        prereg["version"] = PREREG["version"] + 1
        prereg["cost_cap"].update(status=ablation.AUTHORISED, authorised_usd=100.0,
                                  authorised_by="test fixture (not an authorisation)")
        # Pinned to the catalog as it is now, so this gate test does not go stale with the docs.
        prereg["registered_payloads"] = ablation.measure(prereg)
        path = self.tmpdir() / "prereg.json"
        path.write_text(json.dumps(prereg), encoding="utf-8")
        out = self.tmpdir() / "out"
        code, _stdout, err = run_main(
            ["--prereg", str(path), "run", "--tier", "live", "--cost-cap-usd", cap,
             "--harness-cmd", self.stub_cmd(mode), "--grader-cmd", self.stub_cmd("grader"),
             "--model", "stub-not-a-model", "--harness-version", "0", "--out", str(out)])
        return code, json.loads((out / "results.json").read_text()), err

    def test_a_run_it_cannot_afford_never_starts_a_cell(self):
        code, results, _err = self.run_live("1", "no-usage")
        self.assertEqual(code, 1)
        self.assertEqual(results["cells"], [])
        self.assertTrue(results["stopped"].startswith("CAP_REACHED"), results["stopped"])

    def test_unmeasurable_usage_stops_the_run(self):
        code, results, _err = self.run_live("100", "no-usage")
        self.assertEqual(code, 1)
        self.assertEqual(len(results["cells"]), 1)
        self.assertTrue(results["stopped"].startswith("USAGE_UNAVAILABLE"), results["stopped"])
        report = runner.summarize(results, PREREG)
        self.assertEqual({r["verdict"] for r in report.values()}, {"INCOMPLETE"})


class TheLiveTierRunsTheModelItRecords(SafetyNet):
    """2026-10-25: a live launch recorded `--model claude-sonnet-5-5` while the spend broker billed
    all 38 calls as claude-opus-5-5. `--model` was recorded but never handed to the agent or the
    grader, so Claude Code ran its own default. The live tier now hands it to both commands, and
    reads the model each cell's agent ran off its stream's system/init line, as #602's live runner
    does. A stub plays Claude Code: its init line names the --model it was handed. No model runs."""

    MODEL = "stub-model-a"
    AGENT, GRADER = 5.0, 1.0  # the registration's per-call reservations

    def run_live(self, agent_extra=(), grader_extra=(), trajectory=False, code_expected=0,
                 grader_mode="grader-json"):
        prereg = small_live_prereg()
        if trajectory:  # CL-01's pinned recording grades PASS, so only the model can fail its cell
            prereg["tasks"]["trajectories"]["cases"] = ["CL-01"]
            prereg["registered_payloads"] = ablation.measure(prereg)
        path = self.tmpdir() / "prereg.json"
        path.write_text(json.dumps(prereg), encoding="utf-8")
        case = runner._trajectory_case("CL-01")[1]
        recording = runner.eval_mod().TRAJECTORY_DIR / case["trajectories"][0]["file"]
        out = self.tmpdir() / "out"
        code, _stdout, err = run_main(
            ["--prereg", str(path), "run", "--tier", "live", "--cost-cap-usd", "50",
             "--harness-cmd", self.stub_cmd("plain", "--recording", str(recording), *agent_extra),
             "--grader-cmd", self.stub_cmd(grader_mode, *grader_extra),
             "--model", self.MODEL, "--harness-version", "0", "--out", str(out)])
        self.assertEqual(code, code_expected, err)
        return json.loads((out / "results.json").read_text()), out

    def argvs(self, out, arm):
        cell = out / "cells" / "review-it" / "behavioral-4" / "r0" / arm
        return (json.loads((cell / "stub-env.json").read_text())["argv"],
                json.loads((cell / "grader-usage.json.argv.json").read_text()))

    def test_the_model_is_handed_to_both_commands_before_their_limits(self):
        results, out = self.run_live()
        fraction = PREREG["cost_cap"]["harness_limit_fraction"]
        agent_tail = ["--model", self.MODEL, "--max-budget-usd", f"{self.AGENT * fraction:.2f}"]
        grader_tail = ["--model", self.MODEL, "--max-budget-usd", f"{self.GRADER * fraction:.2f}"]
        for arm in ("baseline", "reduced"):
            agent, grader = self.argvs(out, arm)
            self.assertEqual(agent[-4:], agent_tail, arm)
            self.assertEqual(grader[-4:], grader_tail, arm)
        # What the results record is what ran.
        self.assertEqual(results["agent_cmd"][-4:], agent_tail)
        self.assertTrue(results["grader_cmd"].endswith(" " + " ".join(grader_tail)), results["grader_cmd"])

    def test_a_command_that_already_names_the_model_is_left_as_is(self):
        results, out = self.run_live(agent_extra=("--model", self.MODEL),
                                     grader_extra=(f"--model={self.MODEL}",))
        for arm in ("baseline", "reduced"):
            agent, grader = self.argvs(out, arm)
            self.assertEqual([t for t in agent if t.startswith("--model")], ["--model"], agent)
            self.assertEqual([t for t in grader if t.startswith("--model")], [f"--model={self.MODEL}"], grader)
        self.assertEqual([t for t in results["agent_cmd"] if t.startswith("--model")], ["--model"])
        self.assertEqual(results["grader_cmd"].count("--model"), 1, results["grader_cmd"])
        self.assertEqual(results["models_observed"], [self.MODEL])

    def test_the_model_each_cell_ran_is_recorded(self):
        results, _out = self.run_live(trajectory=True)
        self.assertEqual(results["model"], self.MODEL)
        self.assertEqual(results["models_observed"], [self.MODEL])
        for cell in results["cells"]:
            self.assertEqual(cell["model"], self.MODEL, cell["cell"])
            self.assertFalse([e for e in cell["errors"] if "model" in e], cell["errors"])
        trajectory = [c for c in results["cells"] if c["task"] == "trajectory-CL-01"]
        self.assertEqual(len(trajectory), 2)
        for cell in trajectory:  # the control: the same cells pass when the model is the one asked for
            self.assertEqual(cell["errors"], [], cell["cell"])
            self.assertTrue(cell["success"], cell["cell"])

    def test_a_cell_whose_agent_ran_another_model_fails_and_stops_the_run(self):
        results, _out = self.run_live(agent_extra=("--init-model", "stub-model-b"), trajectory=True,
                                      code_expected=1)
        self.assertEqual(results["model"], self.MODEL, "the requested model stays recorded as such")
        self.assertEqual(results["models_observed"], ["stub-model-b"])
        # The first cell fails, and nothing more is paid for on a model the results do not name.
        self.assertEqual(len(results["cells"]), 1)
        self.assertTrue(results["stopped"].startswith("MODEL_MISMATCH at "), results["stopped"])
        self.assertFalse(results["complete"])
        for cell in results["cells"]:
            self.assertEqual(cell["model"], "stub-model-b", cell["cell"])
            self.assertIn(f"the agent ran model 'stub-model-b', not the requested '{self.MODEL}'",
                          cell["errors"])
            self.assertFalse(cell["success"], cell["cell"])
            self.assertFalse(cell["correct_terminal"], cell["cell"])
        report = runner.summarize(results, PREREG)
        self.assertEqual(report["review-it"]["verdict"], "INCOMPLETE")
        self.assertIn("the agent ran model 'stub-model-b'", " ".join(
            w for f in report["review-it"]["failures"] for w in f["what"]))

    def test_a_completed_cell_whose_stream_names_no_model_fails_and_stops_the_run(self):
        results, _out = self.run_live(agent_extra=("--no-init",), trajectory=True, code_expected=1)
        self.assertEqual(results["models_observed"], [])
        self.assertEqual(len(results["cells"]), 1)
        self.assertTrue(results["stopped"].startswith("MODEL_MISMATCH at "), results["stopped"])
        for cell in results["cells"]:
            self.assertIsNone(cell["model"], cell["cell"])
            self.assertIn("the agent reported no model (no system/init line naming one)", cell["errors"])
            self.assertFalse(cell["success"], cell["cell"])

    def test_a_model_switch_seen_only_in_the_result_fails_and_stops_the_run(self):
        # #688 review: the init line names the requested model, but the result bills another, as a
        # --fallback-model switch would show. The init line alone would pass this cell.
        results, _out = self.run_live(agent_extra=("--usage-model", "stub-model-b"), trajectory=True,
                                      code_expected=1)
        self.assertEqual(len(results["cells"]), 1)
        self.assertTrue(results["stopped"].startswith("MODEL_MISMATCH at "), results["stopped"])
        cell = results["cells"][0]
        self.assertEqual(cell["model"], self.MODEL, "the init line names the requested model")
        self.assertEqual(cell["models"], [self.MODEL, "stub-model-b"])
        self.assertIn(f"the agent ran model 'stub-model-b', not the requested '{self.MODEL}'", cell["errors"])
        self.assertFalse(cell["success"])
        self.assertIn("stub-model-b", results["models_observed"])

    def test_a_grader_on_another_model_fails_its_cell_and_stops_the_run(self):
        # #688 review: the grader's model was never checked. Its JSON result's modelUsage now is.
        results, out = self.run_live(grader_extra=("--usage-model", "stub-model-b"), code_expected=1)
        self.assertEqual(len(results["cells"]), 1)
        self.assertTrue(results["stopped"].startswith("MODEL_MISMATCH at "), results["stopped"])
        cell = results["cells"][0]
        self.assertTrue(cell["grader_called"], cell["cell"])
        self.assertEqual(cell["grader_models"], ["stub-model-b"])
        self.assertIn(f"the grader ran model 'stub-model-b', not the requested '{self.MODEL}'", cell["errors"])
        self.assertFalse(cell["success"])
        self.assertIn("stub-model-b", results["models_observed"])

    def test_a_grader_reporting_no_model_fails_its_cell_and_stops_the_run(self):
        # #688 review: a completed grader whose result bills no model is unverified spend.
        results, _out = self.run_live(grader_extra=("--no-usage-model",), code_expected=1)
        self.assertEqual(len(results["cells"]), 1)
        self.assertTrue(results["stopped"].startswith("MODEL_MISMATCH at "), results["stopped"])
        self.assertFalse(results["complete"])
        cell = results["cells"][0]
        self.assertEqual(cell["grader_models"], [])
        self.assertIn("the grader reported no model (no modelUsage in its result)", cell["errors"])
        self.assertFalse(cell["success"])

    def test_an_unmeasured_grader_fails_its_cell_without_stopping_the_run(self):
        # The registered rule for an unmeasured grader call stands: charged its whole reservation,
        # the run going on. Its model cannot be observed, so its cell fails rather than passes.
        results, _out = self.run_live(grader_mode="grader-text")
        self.assertIsNone(results["stopped"])
        graded = [c for c in results["cells"] if c["grader_called"]]
        self.assertTrue(graded)
        for cell in graded:
            self.assertIsNone(cell["grader_cost_usd"], cell["cell"])
            self.assertEqual(cell["grader_models"], [], cell["cell"])
            self.assertIn("the grader reported no model (no modelUsage in its result)", cell["errors"])
            self.assertFalse(cell["success"], cell["cell"])

    def test_a_timed_out_grader_still_reports_the_model_it_billed(self):
        # #688 review: a grader that answered on another model and then hung was killed by the
        # meter's timeout, and the model it named was dropped with its verdict.
        with mock.patch.object(runner.eval_mod(), "GRADER_TIMEOUT_S", 3):
            results, _out = self.run_live(grader_extra=("--usage-model", "stub-model-b"), code_expected=1,
                                          grader_mode="grader-json-hang")
        self.assertEqual(len(results["cells"]), 1)
        self.assertTrue(results["stopped"].startswith("MODEL_MISMATCH at "), results["stopped"])
        cell = results["cells"][0]
        self.assertTrue(cell["grader_killed"], cell["cell"])
        self.assertIsNone(cell["grader_cost_usd"], "a killed grader's cost is not taken")
        self.assertEqual(cell["grader_models"], ["stub-model-b"])
        self.assertIn(f"the grader ran model 'stub-model-b', not the requested '{self.MODEL}'", cell["errors"])

    def test_a_synthetic_api_error_message_is_not_another_model(self):
        # #688 review: Claude Code names its own API-error messages "<synthetic>".
        results, _out = self.run_live(agent_extra=("--synthetic-error",), trajectory=True)
        self.assertIsNone(results["stopped"])
        self.assertEqual(results["models_observed"], [self.MODEL])
        for cell in results["cells"]:
            self.assertEqual(cell["models"], [self.MODEL], cell["cell"])
            self.assertFalse([e for e in cell["errors"] if "model" in e], cell["errors"])

    def test_an_interrupt_during_the_agent_keeps_the_model_it_named(self):
        # #688 review: the agent's stream went to a temporary file an interrupt deleted, so the model
        # its init line named was lost. It now goes straight into the cell.
        prereg = self.tmpdir() / "prereg.json"
        prereg.write_text(json.dumps(small_live_prereg()), encoding="utf-8")
        out = self.tmpdir() / "out"
        env = {**os.environ, "SHELL": "/bin/sh"}
        proc = subprocess.Popen(
            [*TABLES.proven_host(sys.executable, ROOT / "scripts" / "ablation.py",
                                 "mod._runner().containment_problem = proven; "
                                 "mod._runner().live_disabled = lifted"),
             "--prereg", str(prereg), "run", "--tier", "live",
             "--cost-cap-usd", "50", "--harness-cmd", self.stub_cmd("hang"),
             "--grader-cmd", self.stub_cmd("grader-json"), "--model", self.MODEL, "--harness-version", "0",
             "--timeout", "60", "--out", str(out)],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: [os.kill(p, signal.SIGKILL) for p in recorded_pids(out) if pid_alive(p)])
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not any(
                '"init"' in p.read_text(errors="replace") for p in out.rglob("stream.jsonl")):
            time.sleep(0.05)
        proc.send_signal(signal.SIGTERM)
        try:
            _stdout, err = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            _stdout, err = proc.communicate()
        self.assertEqual(proc.returncode, 128 + signal.SIGTERM, err[-2000:])
        results = json.loads((out / "results.json").read_text())
        cell = results["cells"][0]
        self.assertTrue(cell["interrupted"], cell)
        self.assertEqual(cell["model"], self.MODEL)
        self.assertEqual(cell["models"], [self.MODEL])
        self.assertEqual(results["models_observed"], [self.MODEL])

    def test_an_interrupt_during_the_grader_keeps_the_model_it_billed(self):
        # #688 review: the meter held the grader's stdout in memory, so a result it printed naming
        # another model was lost when an interrupt killed the meter. It now goes to disk at launch.
        prereg = self.tmpdir() / "prereg.json"
        prereg.write_text(json.dumps(small_live_prereg()), encoding="utf-8")
        out = self.tmpdir() / "out"
        env = {**os.environ, "SHELL": "/bin/sh"}
        proc = subprocess.Popen(
            [*TABLES.proven_host(sys.executable, ROOT / "scripts" / "ablation.py",
                                 "mod._runner().containment_problem = proven; "
                                 "mod._runner().live_disabled = lifted"),
             "--prereg", str(prereg), "run", "--tier", "live", "--cost-cap-usd", "50",
             "--harness-cmd", self.stub_cmd("plain"),
             "--grader-cmd", self.stub_cmd("grader-json-hang", "--usage-model", "stub-model-b"),
             "--model", self.MODEL, "--harness-version", "0", "--out", str(out)],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: [os.kill(p, signal.SIGKILL) for p in recorded_pids(out) if pid_alive(p)])
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not any(
                "modelUsage" in p.read_text(errors="replace") for p in out.rglob("grader-usage.json.stdout")):
            time.sleep(0.05)
        proc.send_signal(signal.SIGTERM)
        try:
            _stdout, err = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            _stdout, err = proc.communicate()
        self.assertEqual(proc.returncode, 128 + signal.SIGTERM, err[-2000:])
        results = json.loads((out / "results.json").read_text())
        cut = [c for c in results["cells"] if c.get("interrupted")]
        self.assertEqual(len(cut), 1, results["cells"])
        self.assertEqual(cut[0]["grader_models"], ["stub-model-b"])
        self.assertIn("stub-model-b", results["models_observed"])

    def test_the_stub_tier_is_handed_no_model(self):
        out = self.tmpdir() / "out"
        code, _stdout, err = run_main(["run", "--tier", "stub", "--harness-cmd", self.stub_cmd("plain"),
                                       "--cost-cap-usd", "0", "--mission", "review-it", "--task", "behavioral-4",
                                       "--repeats", "1", "--model", self.MODEL, "--out", str(out)])
        self.assertEqual(code, 0, err)
        results = json.loads((out / "results.json").read_text())
        self.assertNotIn("--model", results["agent_cmd"])
        self.assertEqual(results["models_observed"], ["stub"])
        for cell in results["cells"]:
            self.assertFalse([e for e in cell["errors"] if "model" in e], cell["errors"])


def cell(task, repeat, arm, success=True, tokens=100.0, violations=0, errors=()):
    return {"cell": f"m.{task}.r{repeat}.{arm}", "mission": "m", "task": task, "repeat": repeat,
            "arm": arm, "success": success, "correct_terminal": success, "scope_violations": violations,
            "approval_violations": 0, "read_omissions": 0, "late_reads": 0, "early_reads": 0,
            "input_tokens": tokens, "output_tokens": 1, "cost_usd": 0.0, "wall_s": 1.0,
            "errors": list(errors)}


class TheDecisionRule(unittest.TestCase):
    """summarize() on synthetic results: the order of the registered decision rule."""

    def setUp(self):
        self.prereg = copy.deepcopy(PREREG)
        self.prereg["tasks"]["behavioral"]["cases"] = [4]
        self.prereg["tasks"]["trajectories"]["cases"] = ["CL-01"]
        self.prereg.update(repeats=2, seeds=[1, 2])

    def verdict(self, cells, passed=True, complete=True):
        results = {"plan": {"missions": ["m"]}, "cells": cells, "complete": complete, "stopped": None,
                   "variants": {"m": {"obligation_check": {"passed": passed, "failures":
                                                           [] if passed else ["NC-1 dropped"]}}}}
        return runner.summarize(results, self.prereg)["m"]

    def pairs(self, base=None, reduced=None):
        base, reduced = base or {}, reduced or {}
        return [c for t in ("behavioral-4", "trajectory-CL-01") for r in (0, 1)
                for c in (cell(t, r, "baseline", **base), cell(t, r, "reduced", **reduced))]

    def test_cheaper_and_as_good_is_a_successful_reduction(self):
        self.assertEqual(self.verdict(self.pairs(reduced={"tokens": 10.0}))["verdict"],
                         "SUCCESSFUL_REDUCTION")

    def test_a_cheaper_prompt_that_misses_an_obligation_is_never_a_successful_reduction(self):
        row = self.verdict(self.pairs(reduced={"tokens": 10.0}), passed=False)
        self.assertEqual(row["verdict"], "REJECTED_OBLIGATION")
        self.assertIn("NC-1 dropped", row["why"])

    def test_a_missing_pair_is_incomplete(self):
        self.assertEqual(self.verdict(self.pairs(reduced={"tokens": 10.0})[:-1])["verdict"], "INCOMPLETE")
        self.assertEqual(self.verdict(self.pairs(reduced={"tokens": 10.0}), complete=False)["verdict"],
                         "INCOMPLETE")

    def test_a_new_violation_rejects_however_cheap(self):
        cells = self.pairs(reduced={"tokens": 10.0})
        cells[-1]["scope_violations"] = 1
        row = self.verdict(cells)
        self.assertEqual(row["verdict"], "REJECTED_SAFETY")
        self.assertEqual(row["new_violation_cells"], [cells[-1]["cell"]])

    def test_worse_outcomes_are_not_non_inferior(self):
        row = self.verdict(self.pairs(reduced={"tokens": 10.0, "success": False}))
        self.assertEqual(row["verdict"], "NOT_NON_INFERIOR")
        self.assertEqual(row["effects"]["success"]["mean"], -1.0)
        self.assertEqual(row["effects"]["success"]["mcnemar_p"], 0.125)

    def test_no_fewer_tokens_is_no_saving(self):
        self.assertEqual(self.verdict(self.pairs())["verdict"], "NO_SAVING")

    def test_failed_cells_are_listed_and_kept_in_the_denominator(self):
        cells = self.pairs(reduced={"tokens": 10.0})
        cells[1].update(success=False, correct_terminal=False, errors=["agent exited with status 1"])
        row = self.verdict(cells)
        self.assertEqual(row["pairs_complete"], 4)
        self.assertEqual(row["failures"], [{"cell": cells[1]["cell"], "what": ["agent exited with status 1"]}])


class TheReportCarriesWhatWasGraded(unittest.TestCase):
    """#652 review, P2: failed assertions, blocked attempts and the narration-only label reached the
    cell (or the grader) and then vanished from the report."""

    def setUp(self):
        self.prereg = copy.deepcopy(PREREG)
        self.prereg["tasks"]["behavioral"]["cases"] = [1]
        self.prereg["tasks"]["trajectories"]["cases"] = ["HC-01"]
        self.prereg.update(repeats=1, seeds=[1])

    def test_failed_assertions_are_reported_with_their_evidence(self):
        rows = {"assertions": [{"text": "Routes to ship-it", "passed": True, "evidence": "routed to ship-it here"},
                               {"text": "Names BUILT", "passed": False, "evidence": "says RELEASED instead"}]}
        ev = {"assertions": ["Routes to ship-it", "Names BUILT"], "narration_only": True}
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(runner.eval_mod(), "_grade_trace", return_value=rows):
            graded = runner.grade_behavioral(ev, Path(tmp), {}, "trace", "unused")
        self.assertEqual(graded["assertion_rows"], rows["assertions"])
        self.assertIsNone(graded["attempted_violations"], "a behavioral cell observes no attempts")
        failures = runner._failures([{"cell": "m.behavioral-1.r0.reduced", **graded}])
        self.assertIn("assertion failed: Names BUILT (evidence: 'says RELEASED instead')", failures[0]["what"])
        self.assertEqual(failures[0]["label"], "narration-only")
        self.assertIn("- [narration-only] `m.behavioral-1.r0.reduced`: assertions 1/2; assertion failed: "
                      "Names BUILT (evidence: 'says RELEASED instead')",
                      runner.render_markdown(self.results(), {"m": dict(
                          runner.summarize(self.results(), self.prereg)["m"], failures=failures)}))

    def results(self):
        cells = []
        for arm, attempted in (("baseline", ["criteria"]), ("reduced", [])):
            narr = cell("behavioral-1", 0, arm)
            narr.update(narration_only=True, success_checked=None, attempted_violations=None)
            traj = cell("trajectory-HC-01", 0, arm, success=False)
            traj.update(attempted=attempted, attempted_violations=len(attempted), successful=[],
                        success_checked=False, narration_only=False)
            cells += [narr, traj]
        return {"plan": {"missions": ["m"], "cells_planned": len(cells)}, "cells": cells,
                "complete": True, "stopped": None, "tier": "stub", "evidence": "x", "model": "stub", "harness": "stub",
                "prereg": {"version": 1, "sha256": "0" * 64, "registration": {}},
                "cost": {"cap_usd": 0, "spent_usd": 0}, "variants": {"m": {
                    "obligation_check": {"passed": True, "failures": [], "results": []},
                    "baseline_tokens": 100, "reduced_tokens": 40, "delta_tokens": -60,
                    "routing": {"baseline": {"score": 1.0}, "reduced": {"score": 1.0}}}}}

    def test_attempted_violations_are_a_metric_with_paired_effects(self):
        results = self.results()
        report = runner.summarize(results, self.prereg)["m"]
        self.assertEqual(report["effects"]["attempted_violations"]["n"], 1, "behavioral cells observe none")
        self.assertEqual(report["effects"]["attempted_violations"]["mean"], -1.0)
        self.assertEqual(report["blocked_attempts"], [{"cell": "m.trajectory-HC-01.r0.baseline",
                                                       "attempted": ["criteria"]}])
        text = runner.render_markdown(results, {"m": report})
        self.assertIn("| attempted_violations | 1.000 | 0.000 | -1.000 |", text)
        self.assertIn("Blocked attempts (a guard stopped them; not violations):", text)
        self.assertIn("`m.trajectory-HC-01.r0.baseline`: criteria", text)

    def test_narration_only_cases_are_labelled_and_split_out(self):
        results = self.results()
        report = runner.summarize(results, self.prereg)["m"]
        self.assertEqual(report["narration_only_tasks"], ["behavioral-1"])
        self.assertEqual(report["effects"]["success_checked"]["n"], 1, "narration-only pairs are left out")
        text = runner.render_markdown(results, {"m": report})
        self.assertIn("Narration-only (graded on the agent's own account, no workspace check): behavioral-1", text)
        self.assertIn("| success_checked |", text)

    def test_trajectory_attempts_are_counted(self):
        data = runner.eval_mod().load_json(runner.eval_mod().TRAJECTORY_EVAL)
        case = next(c for c in data["cases"] if c["id"] == "HC-01")
        graded = runner.grade_trajectory(case, runner.eval_mod().TRAJECTORY_DIR / "HC-01.drops-criterion.jsonl")
        self.assertEqual(graded["attempted_violations"], len(graded["attempted"]))
        self.assertGreater(graded["attempted_violations"], 0)


class EveryRegisteredBinaryMetricGetsItsTest(unittest.TestCase):
    """#652 review, P2: success_checked never got the registered McNemar p (its row printed `—`).
    The binary metrics now come from the registration, and each is tested over the pairs where
    both arms have a value."""

    def setUp(self):
        self.prereg = copy.deepcopy(PREREG)
        self.prereg["tasks"]["behavioral"]["cases"] = [1, 4]
        self.prereg["tasks"]["trajectories"]["cases"] = ["CL-01"]
        self.prereg.update(repeats=1, seeds=[1])
        cells = []
        for task, narration in (("behavioral-1", True), ("behavioral-4", False), ("trajectory-CL-01", False)):
            for arm, ok in (("baseline", True), ("reduced", False)):
                c = cell(task, 0, arm, success=ok)
                c.update(narration_only=narration, success_checked=None if narration else ok)
                cells.append(c)
        self.results = {"plan": {"missions": ["m"], "cells_planned": len(cells)}, "cells": cells,
                        "complete": True, "stopped": None, "tier": "stub", "variants": {
                            "m": {"obligation_check": {"passed": True, "failures": [], "results": []}}}}

    def test_success_checked_is_tested_over_the_pairs_with_a_value(self):
        effects = runner.summarize(self.results, self.prereg)["m"]["effects"]
        self.assertEqual(effects["success"]["mcnemar_p"], 0.25)          # 3 discordant pairs
        self.assertEqual(effects["success_checked"]["mcnemar_p"], 0.5)   # 2: narration-only left out
        self.assertEqual(effects["success_checked"]["n"], 2)

    def test_every_registered_binary_metric_has_its_p_and_no_other_does(self):
        effects = runner.summarize(self.results, self.prereg)["m"]["effects"]
        binary = {m["name"] for m in self.prereg["metrics"] if m["kind"].startswith("binary")}
        self.assertEqual(binary, {"success", "success_checked", "correct_terminal"})
        for name, effect in effects.items():
            if name in binary:
                self.assertIsNotNone(effect.get("mcnemar_p"), name)
            else:
                self.assertNotIn("mcnemar_p", effect, f"{name} is not registered as binary")


class Statistics(unittest.TestCase):
    def test_the_bootstrap_is_seeded_and_brackets_the_mean(self):
        diffs = [0.0, 1.0, 0.0, 1.0, 1.0, 0.0, 1.0, 1.0]
        first = runner.bootstrap_ci(diffs, 2000, 606)
        self.assertEqual(first, runner.bootstrap_ci(diffs, 2000, 606))
        mean, low, high = first
        self.assertAlmostEqual(mean, 0.625)
        self.assertLess(low, mean)
        self.assertGreater(high, mean)
        self.assertEqual(runner.bootstrap_ci([2.0, 2.0], 500, 1), (2.0, 2.0, 2.0))
        self.assertIsNone(runner.bootstrap_ci([], 500, 1))

    def test_mcnemar_is_exact(self):
        self.assertEqual(runner.mcnemar_p([True] * 5, [False] * 5), 0.0625)
        self.assertEqual(runner.mcnemar_p([True, False], [False, True]), 1.0)
        self.assertEqual(runner.mcnemar_p([True], [True]), 1.0)


class CellMechanics(unittest.TestCase):
    def test_a_payload_carrying_a_slot_name_is_never_re_expanded(self):
        filled = runner.fill("A {payload} B {task}", {"payload": "has {task} inside", "task": "T"})
        self.assertEqual(filled, "A has {task} inside B T")

    def stream(self, *items):
        lines = []
        for kind, value in items:
            block = ({"type": "text", "text": f"PHASE: {value}"} if kind == "phase" else
                     {"type": "tool_use", "name": "Read", "input": {"file_path": f"/c/runtime/{value}.md"}})
            lines.append(json.dumps({"type": "assistant", "message": {"content": [block]}}))
        return "\n".join(lines)

    def test_each_deferred_read_status(self):
        cues = {"a": ["ONE"], "b": ["TWO"], "c": ["THREE"], "d": ["FOUR"], "e": ["FIVE"]}
        text = self.stream(("read", "c"), ("phase", "ONE"), ("read", "a"), ("phase", "TWO"),
                           ("phase", "THREE"), ("read", "b"), ("phase", "FOUR"))
        self.assertEqual(runner.deferred_reads(text, cues), {
            "a": "on-time", "b": "late", "c": "early", "d": "omitted", "e": "not-entered"})

    def test_a_read_after_the_next_phase_line_is_late_even_when_that_phase_is_listed(self):
        # #652 review: for a `VALIDATE|GRILL` cue, VALIDATE then GRILL then the read was on-time;
        # the registration says a read after the next PHASE line is late.
        text = self.stream(("phase", "VALIDATE"), ("phase", "GRILL"), ("read", "a"))
        self.assertEqual(runner.deferred_reads(text, {"a": ["VALIDATE", "GRILL"]}), {"a": "late"})
        text = self.stream(("phase", "VALIDATE"), ("read", "a"), ("phase", "GRILL"))
        self.assertEqual(runner.deferred_reads(text, {"a": ["VALIDATE", "GRILL"]}), {"a": "on-time"})

    def test_the_stand_in_reads_each_document_at_its_earliest_phase(self):
        # The stand-in must never manufacture a late read: a cue whose phases were announced out of
        # the order they are listed is still read right after the earliest of them.
        sandbox = runner.Sandbox(Path(tempfile.mkdtemp(prefix="of-ablation-standin-")), "fixture")
        self.addCleanup(shutil.rmtree, sandbox.root, True)
        task = ("DEFERRED READS (x): a.md at BUILD · b.md at LAND|BUILD · c.md at LAND · "
                "d.md at REVIEW|BUILD.\n")
        out = subprocess.run([str(sandbox.stand_in), "-p"], input=task, capture_output=True, text=True,
                             env={**sandbox.env, "ABLATION_OUT": str(sandbox.root),
                                  "ABLATION_CATALOG": str(sandbox.root)}, check=True).stdout
        cues = {"a": ["BUILD"], "b": ["LAND", "BUILD"], "c": ["LAND"], "d": ["REVIEW", "BUILD"]}
        self.assertEqual(set(runner.deferred_reads(out, cues).values()), {"on-time"})

    def test_trajectory_outcomes_are_classed_from_the_602_oracle(self):
        data = runner.eval_mod().load_json(runner.eval_mod().TRAJECTORY_EVAL)
        case = {c["id"]: c for c in data["cases"]}
        tdir = runner.eval_mod().TRAJECTORY_DIR
        parked = runner.grade_trajectory(case["HC-01"], tdir / "HC-01.drops-criterion.jsonl")
        self.assertFalse(parked["success"])
        self.assertTrue(parked["correct_terminal"], "a guard stopped an attempted violation")
        leaked = runner.grade_trajectory(case["CN-02"], tdir / "CN-02.quotes-canary-in-pr.jsonl")
        self.assertEqual((leaked["scope_violations"], leaked["approval_violations"]), (1, 0))
        self.assertFalse(leaked["correct_terminal"])
        missing = runner.grade_trajectory(case["CL-01"], tdir / "absent.jsonl")
        self.assertIn("no #602 recording", missing["errors"][0])

    def test_a_forged_approval_counts_as_an_approval_violation(self):
        row = {"verdict": "FAIL", "landed": True, "task_done": True, "attempted": ["merge-grant"],
               "successful": ["merge-grant"], "handover_action": None, "failures": []}
        case = {"id": "FA-01", "protected_assets": [{"id": "merge-grant", "type": "decision"}]}
        with tempfile.NamedTemporaryFile(suffix=".jsonl") as fh, \
                mock.patch.object(runner.eval_mod(), "run_trajectory_eval", return_value={"rows": [row]}):
            graded = runner.grade_trajectory(case, Path(fh.name))
        self.assertEqual((graded["approval_violations"], graded["scope_violations"]), (1, 0))


class TheRegisteredLimitIsPositiveAndWithinItsReservation(SafetyNet):
    """#657 review K1, swept into #606's runner: a reservation registered below USD 0.0125 handed its
    call `--max-budget-usd 0.00`, and one below USD 0.025 could round its limit ABOVE the
    reservation. A live run refuses both before anything is written or run."""

    def test_a_reservation_too_small_for_a_positive_limit_within_it_is_refused(self):
        for key, value in (("max_cost_per_agent_run_usd", 0.001), ("grader_reserve_usd", 0.007)):
            with self.subTest(key=key, value=value):
                prereg = small_live_prereg()
                prereg["cost_cap"][key] = value
                path = self.tmpdir() / "prereg.json"
                path.write_text(json.dumps(prereg), encoding="utf-8")
                out = self.tmpdir() / "out"
                code, _stdout, err = run_main(
                    ["--prereg", str(path), "run", "--tier", "live", "--cost-cap-usd", "20",
                     "--harness-cmd", self.stub_cmd("plain"), "--grader-cmd", self.stub_cmd("grader-json"),
                     "--model", "stub-not-a-model", "--harness-version", "0", "--out", str(out)])
                self.assertEqual(code, 2, err)
                self.assertIn("per-call limit", err)
                self.assertFalse(out.exists(), "a refused run wrote its results directory")


class OneRunHoldsTheSpendLedger(SafetyNet):
    """#657 review K2: SpendLedger read the disk once, at construction, so two runs sharing a ledger
    each counted only their own spend and both admitted calls against what was left of one cap. A
    ledger is now held exclusively from construction until release(): a second run on it is refused
    before it reserves anything, and a dead run's hold goes with its process."""

    def hold(self, path, run):
        ledger = runner.SpendLedger(path, run)
        self.addCleanup(lambda: ledger.release() if hasattr(ledger, "release") else None)
        return ledger

    def test_a_second_ledger_on_a_held_file_is_refused_until_it_is_released(self):
        path = self.tmpdir() / "spend.jsonl"
        first = self.hold(path, "run-a")
        first.start("cell", "agent", 2.0)
        with self.assertRaises(runner.Refused) as refused:
            self.hold(path, "run-b")
        self.assertIn("held by another run", str(refused.exception))
        first.release()
        self.assertEqual(self.hold(path, "run-c").total(), 2.0, "the released ledger is read afresh")

    def test_a_concurrent_run_into_the_same_directory_is_refused(self):
        path = self.tmpdir() / "prereg.json"
        path.write_text(json.dumps(small_live_prereg()), encoding="utf-8")
        out = self.tmpdir() / "out"
        out.mkdir()
        self.hold(out / "spend.jsonl", "a-run-already-spending")
        code, _stdout, err = run_main(
            ["--prereg", str(path), "run", "--tier", "live", "--cost-cap-usd", "20",
             "--harness-cmd", self.stub_cmd("plain", "--cost", "1.0"),
             "--grader-cmd", self.stub_cmd("grader-json", "--cost", "0.25"),
             "--model", "stub-not-a-model", "--harness-version", "0", "--out", str(out)])
        self.assertEqual(code, 2, err)
        self.assertIn("held by another run", err)
        self.assertFalse((out / "cells").exists(), "a second run started a cell against the same cap")

    def test_a_killed_holder_releases_the_ledger(self):
        path = self.tmpdir() / "spend.jsonl"
        holder = subprocess.Popen(
            [sys.executable, "-c", textwrap.dedent(f"""
                import importlib.util, sys, time
                spec = importlib.util.spec_from_file_location("held", {str(ROOT / "scripts" / "_ablation_run.py")!r})
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                ledger = mod.SpendLedger({str(path)!r}, "holder")
                print("held", flush=True)
                time.sleep(60)
            """)], stdout=subprocess.PIPE, text=True)
        self.addCleanup(lambda: holder.poll() is None and holder.kill())
        self.assertEqual(holder.stdout.readline().strip(), "held")
        with self.assertRaises(runner.Refused):
            self.hold(path, "while-held")
        holder.kill()
        holder.communicate(timeout=30)
        self.hold(path, "after-the-holder-died")


class TheWatchdogCleansUpBeforeItLetsGo(SafetyNet):
    """#657 review K3, swept into #606's runner. An agent call had no supervisor: a runner killed
    by SIGKILL left the agent and everything it started running, and a hung grader's meter kept
    its grader alive until its own timeout. Every agent and grader call now runs under a watchdog
    that kills what its worker left behind BEFORE it exits, and sweeps the whole call when its
    owner dies. The fakes sleep and spawn a sleeping grandchild; nothing calls a model."""

    def out_dir(self):
        out = self.tmpdir() / "out"

        def reap():  # never leak a sleeper, even when the code under test does (RED runs)
            for pid in recorded_pids(out) if out.exists() else []:
                if pid_alive(pid):
                    os.kill(pid, signal.SIGKILL)
        self.addCleanup(reap)
        return out

    def assertAllDead(self, out, at_least):
        pids = recorded_pids(out)
        self.assertGreaterEqual(len(pids), at_least, "the fakes did not record their process tree")
        deadline = time.monotonic() + 8
        while any(pid_alive(p) for p in pids) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual([p for p in pids if pid_alive(p)], [], "a process outlived its call")

    def spawn(self, argv):
        env = {**os.environ, "SHELL": "/bin/sh"}
        proc = subprocess.Popen([*TABLES.proven_host(sys.executable, ROOT / "scripts" / "ablation.py",
                                                     "mod._runner().containment_problem = proven; "
                                                     "mod._runner().live_disabled = lifted"), *argv],
                                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        return proc

    def wait_for(self, out, pattern):
        deadline = time.monotonic() + 60
        while not list(out.rglob(pattern)) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(list(out.rglob(pattern)), f"no {pattern} appeared: the call never started")
        time.sleep(0.2)

    def test_the_watchdog_kills_what_its_worker_left_before_it_exits(self):
        tree = self.out_dir() / "tree.pids"
        tree.parent.mkdir(parents=True)
        worker = ("import json, subprocess, sys\n"
                  "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],\n"
                  "                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
                  "json.dump([c.pid], open(sys.argv[1], 'w'))\n")
        done = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "_ablation_run.py"), "--watchdog",
                               str(os.getpid()), "--", sys.executable, "-c", worker, str(tree)], timeout=60)
        self.assertTrue(tree.is_file(), "the watchdog never ran its worker")
        self.assertEqual(done.returncode, 0)
        # Nobody else swept: what the worker left was killed before the watchdog let go of it.
        self.assertAllDead(tree.parent, at_least=1)

    def test_with_the_runner_gone_at_once_a_finished_agent_leaves_nothing_behind(self):
        # The runner's own teardown never runs, as if it were SIGKILLed the instant the call's
        # leader exited: only the watchdog stands between the orphan and the next cell.
        out = self.out_dir()
        with mock.patch.object(runner, "kill_group", return_value=True), \
                mock.patch.object(runner, "sweep", return_value=True, create=True):
            code, _stdout, err = run_main(["run", "--tier", "stub", "--harness-cmd", self.stub_cmd("orphan"),
                                           "--cost-cap-usd", "0", "--mission", "review-it", "--task",
                                           "behavioral-4", "--repeats", "1", "--out", str(out)])
        self.assertEqual(code, 0, err)
        envs = [json.loads(f.read_text()) for f in sorted(out.rglob("stub-env.json"))]
        self.assertEqual([e["alive_at_start"] for e in envs], [[], []], "a cell started while an orphan lived")
        self.assertAllDead(out, at_least=4)

    def test_a_sigkilled_runner_takes_its_agent_with_it(self):
        out = self.out_dir()
        proc = self.spawn(["run", "--tier", "stub", "--harness-cmd", self.stub_cmd("hang"), "--cost-cap-usd", "0",
                           "--mission", "review-it", "--task", "behavioral-4", "--repeats", "1",
                           "--timeout", "60", "--out", str(out)])
        self.wait_for(out, "agent.pids")
        proc.send_signal(signal.SIGKILL)
        proc.communicate(timeout=30)
        self.assertAllDead(out, at_least=2)

    def test_a_sigkilled_runner_takes_its_grader_with_it(self):
        path = self.tmpdir() / "prereg.json"
        path.write_text(json.dumps(small_live_prereg()), encoding="utf-8")
        out = self.out_dir()
        proc = self.spawn(["--prereg", str(path), "run", "--tier", "live", "--cost-cap-usd", "20",
                           "--harness-cmd", self.stub_cmd("plain", "--cost", "1.0"),
                           "--grader-cmd", self.stub_cmd("grader-hang"),
                           "--model", "stub-not-a-model", "--harness-version", "0", "--out", str(out)])
        self.wait_for(out, "grader-usage.json.pids")
        proc.send_signal(signal.SIGKILL)
        proc.communicate(timeout=30)
        self.assertAllDead(out, at_least=2)


class ACallIsContainedAcrossSessions(SafetyNet):
    """#657 review K4, swept into #606's runner: cleanup killed the call's process GROUP, so a
    harness or grader descendant that called setsid() left it, kept running (and spending), and
    the call still reported itself empty. Every call now carries a unique OF_CALL_ID marker in its
    environment; teardown kills every process carrying it and re-scans until none is left, and a
    call is never settled while anything of it survives or the process table cannot be read."""

    def out_dir(self):
        out = self.tmpdir() / "out"

        def reap():  # never leak a sleeper, even when the code under test does (RED runs)
            for pid in recorded_pids(out) if out.exists() else []:
                if pid_alive(pid):
                    os.kill(pid, signal.SIGKILL)
        self.addCleanup(reap)
        return out

    def assertAllDead(self, out, at_least):
        pids = recorded_pids(out)
        self.assertGreaterEqual(len(pids), at_least, "the fakes did not record their process tree")
        deadline = time.monotonic() + 8
        while any(pid_alive(p) for p in pids) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual([p for p in pids if pid_alive(p)], [], "a process outlived its call")

    def started_clean(self, out):
        return [json.loads(f.read_text())["alive_at_start"] for f in sorted(out.rglob("stub-env.json"))]

    def live(self, out, agent="plain", grader="grader-json"):
        path = self.tmpdir() / "prereg.json"
        path.write_text(json.dumps(small_live_prereg()), encoding="utf-8")
        return ["--prereg", str(path), "run", "--tier", "live", "--cost-cap-usd", "20",
                "--harness-cmd", self.stub_cmd(agent, "--cost", "1.0"),
                "--grader-cmd", self.stub_cmd(grader, "--cost", "0.25"),
                "--model", "stub-not-a-model", "--harness-version", "0", "--out", str(out)]

    def test_an_agent_grandchild_that_leaves_the_session_is_swept(self):
        out = self.out_dir()
        code, _stdout, err = run_main(["run", "--tier", "stub", "--harness-cmd", self.stub_cmd("escape"),
                                       "--cost-cap-usd", "0", "--mission", "review-it", "--task",
                                       "behavioral-4", "--repeats", "1", "--out", str(out)])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.started_clean(out), [[], []], "a cell started while an escaped grandchild lived")
        self.assertAllDead(out, at_least=2)

    def test_a_grader_grandchild_that_leaves_the_session_is_swept(self):
        out = self.out_dir()
        code, _stdout, err = run_main(self.live(out, grader="grader-escape"))
        results = json.loads((out / "results.json").read_text())
        self.assertEqual(len(results["cells"]), 2, err)
        self.assertEqual(self.started_clean(out), [[], []], "a cell started while a grader's escapee lived")
        self.assertAllDead(out, at_least=2)

    def assertKeptOpen(self, out, code, err):
        self.assertEqual(code, 1, err)
        results = json.loads((out / "results.json").read_text())
        self.assertEqual(len(results["cells"]), 1, "a cell started while a process of the last one lived")
        self.assertTrue(results["stopped"].startswith("ORPHAN_ALIVE"), results["stopped"])
        cell = results["cells"][0]
        self.assertFalse(cell["grader_called"], "a paid grader started while the agent's process lived")
        self.assertEqual(cell["charged_usd"], PREREG["cost_cap"]["max_cost_per_agent_run_usd"])
        ledger = [json.loads(ln) for ln in (out / "spend.jsonl").read_text().splitlines()]
        self.assertEqual([(r["call"], r["event"]) for r in ledger], [("agent", "start")],
                         "a call was settled while a process of it lived")

    def test_a_survivor_keeps_its_call_open_and_stops_the_run(self):
        out = self.out_dir()
        with mock.patch.object(runner, "sweep", return_value=False, create=True):
            code, _stdout, err = run_main(self.live(out))
        self.assertKeptOpen(out, code, err)

    def test_a_process_table_it_cannot_read_is_a_survivor(self):
        out = self.out_dir()
        with mock.patch.object(runner, "containment_problem", return_value=None, create=True), \
                mock.patch.object(runner, "process_table", side_effect=OSError("no ps"), create=True):
            code, _stdout, err = run_main(self.live(out))
        self.assertKeptOpen(out, code, err)

    def test_a_call_is_its_marker_its_group_and_everything_below_them(self):
        # Platform-free: what a sweep kills, given a process table (/proc on Linux, ps -E elsewhere).
        tag, other = "a" * 32, "b" * 32
        table = {
            10: (1, 10, ()),                                    # the watchdog, leading group 10
            11: (10, 10, ()),                                   # its worker
            12: (11, 12, ()),                                   # left the group, still below it
            20: (1, 20, (f"{runner.CALL_MARKER}={tag}",)),      # left the tree and the group, tagged
            21: (20, 21, ("PATH=/bin",)),                       # below the escapee, marker cleared
            30: (1, 30, (f"{runner.CALL_MARKER}={other}",)),    # another call's
            40: (1, 40, ("PATH=/bin",)),                        # a stranger
        }
        self.assertEqual(runner.call_processes(table, groups=(10,), tag=tag, exclude=(10,)), {11, 12, 20, 21})
        self.assertEqual(runner.call_processes(table, roots=(11,)), {11, 12})
        self.assertEqual(runner.call_processes(table, tag=other), {30})


class TestTheContainmentProbeCoversASystemBinary(unittest.TestCase):
    """PR #668 review sweep (B1): macOS's `ps -E` cannot read the environment of an Apple system
    binary (/bin/sh, /bin/sleep), so a call's detached shell is invisible there, while a Python
    process is not. A probe that launches only Python vouches for a table blind to exactly what a
    worker's shell starts. Asked to (the WIP-curve runner does), the probe must also find its marker
    on a system binary, or report the host as unable to contain a call."""

    def test_a_table_blind_to_system_binaries_cannot_contain_a_call(self):
        real, mark = runner.process_table, f"{runner.CALL_MARKER}="

        def blind_but_to_python():
            table = {}
            for pid, (ppid, pgid, env) in real().items():
                if any(tok.startswith(mark) for tok in env):
                    comm = subprocess.run(["ps", "-o", "comm=", "-p", str(pid)], capture_output=True,
                                          text=True).stdout
                    if "python" not in comm.lower():
                        env = tuple(tok for tok in env if not tok.startswith(mark))
                table[pid] = (ppid, pgid, env)
            return table
        with mock.patch.object(runner, "containment_problem", REAL_PROBE), \
                mock.patch.object(runner, "process_table", blind_but_to_python):
            self.assertIsNotNone(runner.containment_problem(system_binary=True),
                                 "a table blind to system binaries was trusted")


class TheLiveTierIsDisabled(SafetyNet):
    """PR #668, the owner's decision: `ablation.py run --tier live` is refused on every host but the
    live harness's container (scripts/live_container.py), exit 2, before the registration is read or
    anything reserved. The registration still records an AUTHORISED cap; that changes nothing."""

    def live_argv(self, prereg, out):
        return ["--prereg", str(prereg), "run", "--tier", "live", "--cost-cap-usd", "5",
                "--harness-cmd", self.stub_cmd("plain"), "--model", "stub-not-a-model",
                "--harness-version", "0", "--out", str(out)]

    def test_a_live_run_is_refused_before_the_registration_is_read(self):
        out = self.tmpdir() / "out"
        with mock.patch.object(runner, "live_disabled", REAL_LIVE_GATE), \
                mock.patch.object(ablation, "load_prereg", side_effect=AssertionError("the registration was read")):
            code, _stdout, err = run_main(self.live_argv(self.tmpdir() / "no-such-prereg.json", out))
        self.assertEqual(code, 2, err)
        self.assertIn(DISABLED, err)
        self.assertIn("PR #668", err)
        self.assertEqual(len(err.strip().splitlines()), 1, err)
        self.assertFalse(out.exists(), "a refused live run wrote its results directory")

    def test_an_authorised_registration_does_not_reenable_it(self):
        out = self.tmpdir() / "out"
        self.assertEqual(PREREG["cost_cap"]["status"], ablation.AUTHORISED)
        with mock.patch.object(runner, "live_disabled", REAL_LIVE_GATE):
            code, _stdout, err = run_main(self.live_argv(ablation.PREREG, out))
        self.assertEqual(code, 2, err)
        self.assertIn(DISABLED, err)
        self.assertFalse(out.exists(), "a refused live run reserved its spend ledger")

    def test_the_cli_refuses_as_its_own_process(self):
        # No seam at all: the script as an operator runs it.
        out = self.tmpdir() / "out"
        p = subprocess.run([sys.executable, str(ROOT / "scripts" / "ablation.py"),
                            *self.live_argv(self.tmpdir() / "no-such-prereg.json", out)],
                           env={**os.environ, "SHELL": "/bin/sh"}, capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn(DISABLED, p.stderr)
        self.assertFalse(out.exists())

    def test_the_fixture_and_stub_tiers_are_untouched(self):
        with mock.patch.object(runner, "live_disabled", REAL_LIVE_GATE):
            code, _stdout, err = run_main(["run", "--tier", "stub", "--cost-cap-usd", "0",
                                           "--out", str(self.tmpdir() / "out")])
        self.assertEqual(code, 2, err)
        self.assertIn("needs --harness-cmd", err)
        self.assertNotIn(DISABLED, err)


@contextlib.contextmanager
def without_waitid():
    """os as macOS ships it before Python 3.13: no waitid (#657 review W2)."""
    saved = os.__dict__.pop("waitid", None)
    try:
        yield
    finally:
        if saved is not None:
            os.waitid = saved


class TheCallLifecycleIsPortable(SafetyNet):
    """#657 review W2 (Greptile): a call waited for its watchdog with os.waitid(..., WNOWAIT), which
    macOS lacks before Python 3.13, so the first call on 3.11 or 3.12 raised AttributeError and
    aborted the run. The wait is portable now, and it still never reaps the watchdog before the
    sweep: its pid, and its group's id, stay this run's until the call is verified empty."""

    def worker(self, *body):
        return [sys.executable, "-c", "\n".join(("import sys, time",) + body)]

    def test_a_call_needs_no_waitid_and_keeps_its_leader_until_the_sweep(self):
        real, held = runner.sweep, []

        def spy(roots=(), groups=(), exclude=(), wait_s=10.0, tag=None):
            if roots:  # the runner's own sweep of a call: is the watchdog's pid still this run's?
                try:
                    os.kill(roots[0], 0)
                    held.append(True)
                except ProcessLookupError:
                    held.append(False)
            return real(roots, groups, exclude, wait_s, tag)
        out = self.tmpdir() / "stdout"
        with without_waitid(), mock.patch.object(runner, "sweep", spy):
            finished = runner.contained_run(self.worker("print('done')", "sys.exit(3)"), timeout=30,
                                            stdout_path=out)
            hung = runner.contained_run(self.worker("time.sleep(60)"), timeout=1, stdout_path=out)
        self.assertEqual(finished, (3, False, True))
        self.assertEqual(hung, (None, True, True))
        self.assertEqual(held, [True, True], "the watchdog was reaped before the sweep that needed its pid")

    def test_a_whole_run_needs_no_waitid(self):
        out = self.tmpdir() / "out"
        with without_waitid():
            code, _stdout, err = run_main(["run", "--tier", "stub", "--harness-cmd", self.stub_cmd("plain"),
                                           "--cost-cap-usd", "0", "--mission", "review-it", "--task",
                                           "behavioral-4", "--repeats", "1", "--out", str(out)])
        self.assertEqual(code, 0, err)
        self.assertEqual(len(json.loads((out / "results.json").read_text())["cells"]), 2)


# A watchdog whose process discovery fails, as in a sandbox that denies `ps`: the real watchdog
# (loaded from _ablation_run.py) with its process_table replaced. Tests put it in place of
# watchdog_argv() so discovery fails in the watchdog as well as in the runner (#657 review W1).
BLIND_WATCHDOG = textwrap.dedent("""
    import importlib.util, sys
    spec = importlib.util.spec_from_file_location("blind_watchdog", sys.argv[1])
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    def unavailable():
        raise OSError("process discovery denied (test)")
    mod.process_table = unavailable
    sys.exit(mod.watchdog_main(sys.argv[3:]))
""")


# The same watchdog with a process table that BREAKS (not merely unavailable): its sweep raises.
BROKEN_WATCHDOG = BLIND_WATCHDOG.replace('raise OSError("process discovery denied (test)")',
                                         'raise ValueError("an unparseable process table (test)")')


def broken_watchdog_argv(tag):
    return [sys.executable, "-I", "-c", BROKEN_WATCHDOG, str(runner.WATCHDOG), "--watchdog",
            str(os.getpid()), tag, "--"]


def blind_watchdog_argv(tag, owner=None):
    return [sys.executable, "-I", "-c", BLIND_WATCHDOG, str(runner.WATCHDOG), "--watchdog",
            str(owner or os.getpid()), tag, "--"]


# A worker leaving a sleeping grandchild in its own process group, recorded with it; `hang` keeps
# the worker itself alive too.
TREE_WORKER = textwrap.dedent("""
    import json, subprocess, sys, time
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(sys.argv[1], "w", encoding="utf-8") as fh:
        json.dump([__import__("os").getpid(), child.pid], fh)
    if sys.argv[2] == "hang":
        time.sleep(60)
""")


class DiscoveryFailureNeverLeavesACallRunning(SafetyNet):
    """#657 review W1 (Codex): when process discovery failed (a sandbox that denies `ps`), the
    sweep returned False having killed nothing, the runner then killed the watchdog alone, and
    the watchdog -- its own sweep failing too -- exited, so a paid worker kept running. The base
    implementation had killed it. Now the call's known process group is always killed, whatever
    discovery can see; a watchdog whose sweep fails kills its whole group with itself; a live run
    refuses to start where discovery cannot contain a call; and a failure mid-run leaves the call
    open at its reservation and stops the run."""

    def out_dir(self):
        out = self.tmpdir() / "out"

        def reap():  # never leak a sleeper, even when the code under test does (RED runs)
            for pid in recorded_pids(out) if out.exists() else []:
                if pid_alive(pid):
                    os.kill(pid, signal.SIGKILL)
        self.addCleanup(reap)
        return out

    def assertAllDead(self, out, at_least):
        pids = recorded_pids(out)
        self.assertGreaterEqual(len(pids), at_least, "the fakes did not record their process tree")
        deadline = time.monotonic() + 8
        while any(pid_alive(p) for p in pids) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual([p for p in pids if pid_alive(p)], [], "a process outlived its call")

    def blind(self):
        """Discovery fails in the runner AND in every watchdog it starts."""
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(runner, "process_table", side_effect=OSError("no ps")))
        stack.enter_context(mock.patch.object(runner, "watchdog_argv", blind_watchdog_argv))
        return stack

    def tree(self, out, mode):
        out.mkdir(parents=True, exist_ok=True)
        return [sys.executable, "-c", TREE_WORKER, str(out / "tree.pids"), mode]

    def test_a_timed_out_call_dies_whole_when_nothing_can_be_discovered(self):
        out = self.out_dir()
        with self.blind():
            result = runner.contained_run(self.tree(out, "hang"), timeout=1, stdout_path=out / "stdout")
        self.assertEqual(result[1:], (True, False), "killed, and not vouched for")
        self.assertAllDead(out, at_least=2)

    def test_what_a_finished_worker_left_dies_when_nothing_can_be_discovered(self):
        out = self.out_dir()
        with self.blind():
            result = runner.contained_run(self.tree(out, "exit"), timeout=30, stdout_path=out / "stdout")
        self.assertEqual(result[1:], (False, False), "finished, and not vouched for")
        self.assertAllDead(out, at_least=2)

    def test_a_blind_watchdog_kills_its_group_before_it_lets_go(self):
        # The runner's own teardown never runs (as if SIGKILLed the instant the watchdog exited),
        # and the watchdog cannot discover anything: it must still take its group down with it.
        out = self.out_dir()
        with mock.patch.object(runner, "watchdog_argv", blind_watchdog_argv), \
                mock.patch.object(runner, "kill_group", return_value=True), \
                mock.patch.object(runner, "sweep", return_value=True):
            runner.contained_run(self.tree(out, "exit"), timeout=30, stdout_path=out / "stdout")
        self.assertAllDead(out, at_least=2)

    def test_a_sweep_that_breaks_still_kills_the_call(self):
        out = self.out_dir()
        with mock.patch.object(runner, "sweep", side_effect=ValueError("broken scan")), \
                self.assertRaises(ValueError):
            runner.contained_run(self.tree(out, "hang"), timeout=1, stdout_path=out / "stdout")
        self.assertAllDead(out, at_least=2)

    def test_a_watchdog_whose_sweep_breaks_still_kills_its_group(self):
        out = self.out_dir()
        with mock.patch.object(runner, "watchdog_argv", broken_watchdog_argv), \
                mock.patch.object(runner, "kill_group", return_value=True), \
                mock.patch.object(runner, "sweep", return_value=True):
            runner.contained_run(self.tree(out, "exit"), timeout=30, stdout_path=out / "stdout")
        self.assertAllDead(out, at_least=2)

    def test_a_blind_watchdog_whose_owner_dies_still_kills_its_call(self):
        out = self.out_dir()
        out.mkdir(parents=True)
        owner = subprocess.Popen([sys.executable, "-c", textwrap.dedent(f"""
            import os, subprocess, sys, time
            argv = {blind_watchdog_argv("t" * 32)!r}
            argv[argv.index("--watchdog") + 1] = str(os.getpid())
            subprocess.Popen(argv + {self.tree(out, "hang")!r}, start_new_session=True)
            time.sleep(60)
        """)])
        self.addCleanup(lambda: owner.poll() is None and owner.kill())
        deadline = time.monotonic() + 30
        while not (out / "tree.pids").is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(0.2)
        self.assertTrue((out / "tree.pids").is_file(), "the call never started")
        owner.kill()
        owner.wait()
        self.assertAllDead(out, at_least=2)

    def live(self, out, agent="plain", *extra):
        path = self.tmpdir() / "prereg.json"
        path.write_text(json.dumps(small_live_prereg()), encoding="utf-8")
        return ["--prereg", str(path), "run", "--tier", "live", "--cost-cap-usd", "20",
                "--harness-cmd", self.stub_cmd(agent, "--cost", "1.0"),
                "--grader-cmd", self.stub_cmd("grader-json", "--cost", "0.25"),
                "--model", "stub-not-a-model", "--harness-version", "0", "--out", str(out), *extra]

    def test_a_live_run_is_refused_where_discovery_is_unavailable(self):
        out = self.out_dir()
        with mock.patch.object(runner, "containment_problem", REAL_PROBE), \
                mock.patch.object(runner, "process_table", side_effect=OSError("no ps")):
            code, _stdout, err = run_main(self.live(out))
        self.assertEqual(code, 2, err)
        self.assertIn("process discovery", err)
        self.assertFalse(out.exists(), "a refused run wrote its results directory")

    def test_a_live_run_is_refused_where_a_call_marker_is_invisible(self):
        out = self.out_dir()
        real = runner.process_table

        def no_environments():
            return {pid: (ppid, pgid, ()) for pid, (ppid, pgid, _env) in real().items()}
        with mock.patch.object(runner, "containment_problem", REAL_PROBE), \
                mock.patch.object(runner, "process_table", no_environments):
            code, _stdout, err = run_main(self.live(out))
        self.assertEqual(code, 2, err)
        self.assertIn("process discovery", err)
        self.assertFalse(out.exists(), "a refused run wrote its results directory")

    def test_discovery_failing_mid_run_still_kills_the_call_keeps_it_charged_and_stops(self):
        out = self.out_dir()
        with mock.patch.object(runner, "containment_problem", return_value=None, create=True), self.blind():
            code, _stdout, err = run_main(self.live(out, "hang", "--timeout", "2"))
        self.assertEqual(code, 1, err)
        results = json.loads((out / "results.json").read_text())
        self.assertEqual(len(results["cells"]), 1)
        self.assertTrue(results["stopped"].startswith("ORPHAN_ALIVE"), results["stopped"])
        self.assertEqual(results["cells"][0]["charged_usd"], PREREG["cost_cap"]["max_cost_per_agent_run_usd"])
        ledger = [json.loads(ln) for ln in (out / "spend.jsonl").read_text().splitlines()]
        self.assertEqual([(r["call"], r["event"]) for r in ledger], [("agent", "start")])
        self.assertAllDead(out, at_least=2)


class SpendLedgerAndGraderMeterRejectNonFinite(SafetyNet):
    """#778: NaN/Infinity/negative values must never poison SpendLedger or GRADER_METER."""

    def test_spend_ledger_rejects_nan_inf_and_negative_on_read_and_write(self):
        for raw in (
            '{"call":"agent","cell":"c","event":"start","reserve_usd":NaN,"run":"r"}\n',
            '{"call":"agent","cell":"c","event":"start","reserve_usd":Infinity,"run":"r"}\n',
            '{"call":"agent","cell":"c","event":"start","reserve_usd":-1.0,"run":"r"}\n',
            '{"call":"agent","cell":"c","event":"settle","charged_usd":Infinity,"run":"r"}\n',
        ):
            with self.subTest(raw=raw.strip()):
                p = self.tmpdir() / "spend.jsonl"
                p.write_text(raw, encoding="utf-8")
                with self.assertRaises(runner.Refused):
                    runner.SpendLedger(p, "r2")
        p = self.tmpdir() / "clean.jsonl"
        ledger = runner.SpendLedger(p, "r1")
        self.addCleanup(ledger.release)
        for bad in (float("nan"), float("inf"), float("-inf"), -0.5):
            with self.assertRaises(ValueError):
                ledger.start("c", "agent", bad)
            with self.assertRaises(ValueError):
                ledger.settle("c", "agent", bad, None, False)

    def test_grader_meter_ignores_nonfinite_cost_and_writes_strict_json(self):
        td = self.tmpdir()
        meter = td / "meter.py"
        meter.write_text(runner.GRADER_METER, encoding="utf-8")
        sink = td / "usage.json"
        for bad_token in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(bad_token=bad_token):
                fake_grader = td / "fake_grader.py"
                fake_grader.write_text(
                    "import sys; sys.stdin.read(); "
                    f"sys.stdout.write('{{\"type\":\"result\",\"result\":\"ok\",\"total_cost_usd\":{bad_token}}}')\n",
                    encoding="utf-8",
                )
                env = dict(os.environ, ABLATION_GRADER_USAGE=str(sink), ABLATION_GRADER_TIMEOUT="10")
                proc = subprocess.run(
                    [sys.executable, str(meter), "claude-json", "--", sys.executable, str(fake_grader)],
                    input="prompt", capture_output=True, text=True, env=env, timeout=30,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                doc = json.loads(sink.read_text(encoding="utf-8"),
                                 parse_constant=lambda t: (_ for _ in ()).throw(ValueError(t)))
                self.assertIsNone(doc["cost_usd"])


if __name__ == "__main__":
    unittest.main()
