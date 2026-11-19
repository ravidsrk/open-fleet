#!/usr/bin/env python3
"""Contract tests for scripts/release_check.py — the 1.0 checklist as a runnable gate (#414).

docs/release-1.0-checklist.md defines the release as commands; the script runs
them. These tests keep the two from drifting apart and the script from lying:

* the script runs against THIS repository once (validate, proof_status,
  run_report, the vf-bench gate and the negative-control demo all execute for
  real, ~12 s) — every check the machine can make must PASS, and the only
  SKIPs are the two the flags ask for;
* each gate that reads repository state runs against a fixture tree that
  violates it, so every check is demonstrably able to FAIL (and to PASS);
* the gh-backed checks SKIP(no gh) with no gh on PATH and never PASS;
* the checklist opens with the run command and shows the commands the script
  runs — the stale grep over the rendered gate-batch.md, the #235 gate and the
  pre-re-scope harden-it bar are gone.
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent

# Fetched branch names holding a line break (tests/fixtures/refname_breaks.py; W3-07 re-attack).
_rb_spec = importlib.util.spec_from_file_location(
    "refname_breaks", ROOT / "tests" / "fixtures" / "refname_breaks.py")
refname_breaks = importlib.util.module_from_spec(_rb_spec)
_rb_spec.loader.exec_module(refname_breaks)
SCRIPT = ROOT / "scripts" / "release_check.py"
CHECKLIST = ROOT / "docs" / "release-1.0-checklist.md"

_spec = importlib.util.spec_from_file_location("release_check", SCRIPT)
rc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rc)

_gb_spec = importlib.util.spec_from_file_location(
    "gate_batch_for_release_check", ROOT / "runtime" / "scripts" / "gate-batch.py")
gb = importlib.util.module_from_spec(_gb_spec)
_gb_spec.loader.exec_module(gb)

STATUS_LINE = re.compile(r"^\s*(PASS|FAIL|INFO)  (\S+): ")
SKIP_LINE = re.compile(r"^\s*SKIP\((.*)\)  (\S+)$")
SUMMARY_LINE = re.compile(
    r"^summary: (\d+) PASS, (\d+) FAIL, (\d+) SKIP, (\d+) INFO -> exit (\d)$", re.M)
ALL_GATES = ("gate0", "gate1", "gate2", "gate3", "gate4", "gate5", "gate6")


def parse(stdout):
    """[(status, skip_reason_or_None, check_name)] from the script's text output."""
    rows = []
    for line in stdout.splitlines():
        m = STATUS_LINE.match(line)
        if m:
            rows.append((m.group(1), None, m.group(2)))
            continue
        m = SKIP_LINE.match(line)
        if m:
            rows.append(("SKIP", m.group(1), m.group(2)))
    return rows


class Completed:
    """What subprocess.run returns, for a main() that ran in this process."""

    def __init__(self, returncode, stdout, stderr):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def run_script(*args, cwd=ROOT, env=None, timeout=900):
    """rc.main() in this process, under the cwd and environment a subprocess would have.

    In-process so the D9 coverage floor sees the script (a subprocess is invisible to the
    shard's tracer); the gates it runs still shell out exactly as before. `env` replaces
    os.environ wholesale when given, as subprocess.run(env=...) would. `timeout` is kept
    for the call sites; the checks bound their own subprocesses."""
    del timeout
    out, err = io.StringIO(), io.StringIO()
    before = os.getcwd()
    with mock.patch.dict(os.environ, env if env is not None else {}, clear=env is not None):
        try:
            os.chdir(str(cwd))
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    code = rc.main([str(a) for a in args])
                except SystemExit as exc:
                    code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 2)
        finally:
            os.chdir(before)
    return Completed(code, out.getvalue(), err.getvalue())


class RunsAsAProgram(unittest.TestCase):
    """The one subprocess call: the checklist tells a person to run the file, so it must
    run as a program, not only as an imported main()."""

    def test_help_exits_zero_from_a_subprocess(self):
        proc = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True,
                              text=True, cwd=str(ROOT), timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("usage: release_check.py", proc.stdout)


def skill_md(name, proof):
    return f"---\nname: {name}\ndescription: fixture\nmetadata:\n  proof: {proof}\n---\n\n# {name}\n"


def make_fixture(root, *, harden_proof="self-run", witness="live", witnessed="2026-09-28",
                 owed=False, batch=True):
    """The minimal tree the state-reading gates consult, and none of the tools
    the other checks run — those FAIL (a checkout without them is no release),
    which leaves the checks under test as the only thing being read."""
    root = Path(root)
    for mission in ("harden-it", "prove-it", "clean-sweep"):
        d = root / "skills" / mission
        d.mkdir(parents=True)
        proof = harden_proof if mission == "harden-it" else "self-run"
        (d / "SKILL.md").write_text(skill_md(mission, proof), encoding="utf-8")
    (root / "runtime" / "scripts").mkdir(parents=True)
    (root / "runtime" / "pins.json").write_text(json.dumps({
        "orca": {"version": "v9.9.9", "witness": witness, "witnessed": witnessed}}),
        encoding="utf-8")
    # The real CLI, at the path the gate runs it from: it resolves its store
    # relative to its own location, so the copy reads the fixture's docs/runs/.
    shutil.copy(ROOT / "runtime" / "scripts" / "gate-batch.py",
                root / "runtime" / "scripts" / "gate-batch.py")
    if batch:
        run_dir = root / "docs" / "runs" / rc.GATE_BATCH_RUN
        run_dir.mkdir(parents=True)
        path = run_dir / "gate-batch.json"
        data = gb.init_batch(path, run_id="run_fixture", run_title="fixture run")
        gb.add_gate(data, gid="G1", asked="2026-09-14", title="a parked question",
                    question="still owed?")
        if not owed:
            gb.transition(data, "G1", "answered", "answered in the fixture",
                          answered="2026-09-16", source="human:lia")
        gb.save_batch(path, data)
    anchor_fixture(root)
    return root


def anchor_fixture(root):
    """W3-06: gate 1 reads the human grant key at refs/remotes/origin/main, never from the tree
    it judges — so the fixture is a clone with that ref (an anchor commit carrying only the gate
    batch, whose set of gates gate 1 reads there too — PR #719 review round 3; nothing pinned,
    the fixture's other files left for a test to commit), and gate-batch.py has the siblings it
    reads and verifies the key with (decisions.py, ed25519.py, gitexec.py)."""
    for name in ("decisions.py", "ed25519.py", "gitexec.py"):
        shutil.copy(ROOT / "runtime" / "scripts" / name, root / "runtime" / "scripts" / name)
    subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
    if (root / "docs" / "runs").is_dir():
        subprocess.run(["git", "-C", str(root), "add", "docs/runs"], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t",
                    "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m",
                    "the fixture's key anchor"], check=True)
    subprocess.run(["git", "-C", str(root), "update-ref", "refs/remotes/origin/main", "HEAD"],
                   check=True)


def git_commit(root, message):
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t",
                    "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", message],
                   check=True)
    subprocess.run(["git", "-C", str(root), "update-ref", "refs/remotes/origin/main", "HEAD"],
                   check=True)


def ctx_for(root):
    return rc.Context(root, fast=True, skip_github=True)


def find(checks, name):
    for check in checks:
        if check[0] == name:
            return check
    raise AssertionError(f"{name} not among {[c[0] for c in checks]}")


class TheScriptAgainstThisRepository(unittest.TestCase):
    """One run of the real thing. It executes validate.py, proof_status.py,
    run_report.py, the vf-bench gate (~7 s) and the demo, so it is ONE test."""

    def test_fast_skip_github_run_passes_every_check_the_machine_can_make(self):
        proc = run_script("--fast", "--skip-github")
        transcript = proc.stdout + "\n--- stderr ---\n" + proc.stderr
        rows = parse(proc.stdout)
        self.assertGreaterEqual(len(rows), 30, transcript)
        names = [name for _, _, name in rows]
        self.assertEqual(len(names), len(set(names)), "a check name repeats")
        for gate in ALL_GATES:
            self.assertTrue(any(n.startswith(gate + "/") for n in names), f"{gate} ran no check")

        # Only the two flags may SKIP. Anything else means this machine cannot
        # make a check the release needs, and the test would pass vacuously.
        skips = {name: reason for status, reason, name in rows if status == "SKIP"}
        gh_backed = [n for n in names if "/gh-" in n]
        self.assertGreaterEqual(len(gh_backed), 8, names)
        self.assertEqual(skips.get("gate0/unittest"), "--fast")
        for name in gh_backed:
            self.assertEqual(skips.get(name), "--skip-github", name)
        self.assertEqual(set(skips), set(gh_backed) | {"gate0/unittest"},
                         f"a SKIP nobody asked for: {skips}")

        # #235 is recorded, never graded.
        infos = [name for status, _, name in rows if status == "INFO"]
        self.assertEqual(infos, ["gate1/issue-235-marketplace"])
        self.assertRegex(proc.stdout, r"INFO  gate1/issue-235-marketplace: #235 .*does not gate")

        # Every remaining line is PASS. The one tolerated FAIL is tree-clean on
        # a developer's uncommitted tree (CONTRIBUTING says run the suite BEFORE
        # committing); CI's checkout is clean, so there it must PASS with exit 0.
        failed = [name for status, _, name in rows if status == "FAIL"]
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=str(ROOT),
                               capture_output=True, text=True).stdout.strip()
        if dirty:
            self.assertEqual(failed, ["gate0/tree-clean"], transcript)
            self.assertEqual(proc.returncode, 1, transcript)
        else:
            self.assertEqual(failed, [], transcript)
            # --fast and --skip-github leave SKIPs standing, and a SKIP is not a pass:
            # the run is incomplete (3), never green (0) — PR #509 review.
            self.assertEqual(proc.returncode, 3, transcript)
        passed = [name for status, _, name in rows if status == "PASS"]
        self.assertEqual(set(names) - set(skips) - set(infos) - set(failed), set(passed))

        # The summary agrees with the lines it summarizes.
        m = SUMMARY_LINE.search(proc.stdout)
        self.assertIsNotNone(m, transcript)
        self.assertEqual([int(x) for x in m.groups()],
                         [len(passed), len(failed), len(skips), len(infos), proc.returncode])


class GatesFailOnAFixtureThatViolatesThem(unittest.TestCase):
    """Every state-reading check, shown able to fail — and to pass — on a tree
    built for it, with no network, model or full checkout in between."""

    def test_a_doctrine_only_flagship_fails_gate_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            checks = rc.gate2(ctx_for(make_fixture(tmp, harden_proof="doctrine-only")))
            _, status, detail = find(checks, "gate2/proof-harden-it")
            self.assertEqual(status, rc.FAIL, detail)
            self.assertIn("doctrine-only", detail)
            # The siblings at self-run pass: the check tells the two apart.
            self.assertEqual(find(checks, "gate2/proof-prove-it")[1], rc.PASS)
            self.assertEqual(find(checks, "gate2/proof-clean-sweep")[1], rc.PASS)

    def test_the_re_scoped_bar_is_any_bound_tier(self):
        for proof in rc.PROOF_BAR:
            with self.subTest(proof=proof), tempfile.TemporaryDirectory() as tmp:
                checks = rc.gate2(ctx_for(make_fixture(tmp, harden_proof=proof)))
                _, status, detail = find(checks, "gate2/proof-harden-it")
                self.assertEqual(status, rc.PASS, detail)
                self.assertIn(f"proof: {proof}", detail)

    def test_a_missing_skill_or_proof_key_fails_rather_than_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_fixture(tmp)
            (root / "skills" / "harden-it" / "SKILL.md").write_text(
                "---\nname: harden-it\n---\n", encoding="utf-8")
            shutil.rmtree(root / "skills" / "prove-it")
            checks = rc.gate2(ctx_for(root))
            self.assertEqual(find(checks, "gate2/proof-harden-it")[1], rc.FAIL)
            _, status, detail = find(checks, "gate2/proof-prove-it")
            self.assertEqual(status, rc.FAIL)
            self.assertIn("missing", detail)
            # And the binder a checkout lacks is a FAIL too, never a SKIP.
            self.assertEqual(find(checks, "gate2/run-report")[1], rc.FAIL)

    def test_a_source_witness_or_a_stale_live_one_fails_gate_5(self):
        cases = (("source", "2026-09-28", rc.FAIL),   # read from a clone, not witnessed
                 ("live", "2026-09-13", rc.FAIL),     # the witness #416 replaced
                 ("live", "2026-09-16", rc.PASS),     # the boundary: the re-pin day itself
                 ("live", "2026-09-28", rc.PASS))
        for witness, witnessed, want in cases:
            with self.subTest(witness=witness, witnessed=witnessed), \
                    tempfile.TemporaryDirectory() as tmp:
                root = make_fixture(tmp, witness=witness, witnessed=witnessed)
                _, status, detail = find(rc.gate5(ctx_for(root)), "gate5/orca-pin-live")
                self.assertEqual(status, want, detail)

    def test_a_source_re_pin_passes_gate_5_only_on_fresh_recorded_live_receipts(self):
        """2026-10-23 review, P2-41: pins.json labelled a source-delta re-pin "live" and gate 5
        passed on the word. The carried live witness is now a field the gate reads: it passes
        only when that witness is fresh, no later than the re-pin, and its run record exists."""
        run = "docs/runs/2026-10-12-pin-it-x.md"
        cases = (
            ({"version": "v9.9.8", "witnessed": "2026-09-20", "run": run}, True, rc.PASS),
            ({"version": "v9.9.8", "witnessed": "2026-09-20", "run": run}, False, rc.FAIL),
            ({"version": "v9.9.8", "witnessed": "2026-09-13", "run": run}, True, rc.FAIL),
            ({"version": "v9.9.8", "witnessed": "2026-10-01", "run": run}, True, rc.FAIL),
            ({"version": "v9.9.8", "witnessed": "2026-09-20", "run": "README.md"}, True, rc.FAIL),
            ({"version": "v9.9.8", "witnessed": "2026-09-20",
              "run": "docs/runs/../../README.md"}, True, rc.FAIL),
            ("2026-09-20", True, rc.FAIL),
        )
        for carried, write_run, want in cases:
            with self.subTest(carried=carried, write_run=write_run), \
                    tempfile.TemporaryDirectory() as tmp:
                root = make_fixture(tmp, witness="source", witnessed="2026-09-28")
                pins = root / "runtime" / "pins.json"
                data = json.loads(pins.read_text(encoding="utf-8"))
                data["orca"]["live_receipts"] = carried
                pins.write_text(json.dumps(data), encoding="utf-8")
                (root / "README.md").write_text("not a run record\n", encoding="utf-8")
                if write_run:
                    (root / run).parent.mkdir(parents=True, exist_ok=True)
                    (root / run).write_text("# pin-it run\n", encoding="utf-8")
                _, status, detail = find(rc.gate5(ctx_for(root)), "gate5/orca-pin-live")
                self.assertEqual(status, want, detail)

    def test_an_unreadable_pin_fails_gate_5(self):
        for text in ("{not json", '{"gstack": {}}', '{"orca": "a string"}'):
            with self.subTest(pins=text), tempfile.TemporaryDirectory() as tmp:
                root = make_fixture(tmp)
                (root / "runtime" / "pins.json").write_text(text, encoding="utf-8")
                _, status, detail = find(rc.gate5(ctx_for(root)), "gate5/orca-pin-live")
                self.assertEqual(status, rc.FAIL, detail)
        with tempfile.TemporaryDirectory() as tmp:
            root = make_fixture(tmp)
            (root / "runtime" / "pins.json").unlink()
            self.assertEqual(find(rc.gate5(ctx_for(root)), "gate5/orca-pin-live")[1], rc.FAIL)

    def test_an_owed_gate_fails_gate_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, status, detail = find(rc.gate1(ctx_for(make_fixture(tmp, owed=True))),
                                     "gate1/gate-batch-owed")
            self.assertEqual(status, rc.FAIL, detail)
            self.assertIn("G1", detail)
        with tempfile.TemporaryDirectory() as tmp:
            _, status, detail = find(rc.gate1(ctx_for(make_fixture(tmp, owed=False))),
                                     "gate1/gate-batch-owed")
            self.assertEqual(status, rc.PASS, detail)
            self.assertIn("G1 answered", detail)

    def test_a_view_that_disagrees_with_the_store_fails_gate_1(self):
        # W3-06 (2026-10-27 security audit): `render --check` ran in tests only, so the
        # human-readable gate-batch.md could silently disagree with the store it claims to show.
        with tempfile.TemporaryDirectory() as tmp:
            root = make_fixture(tmp, owed=False)
            store = root / "docs" / "runs" / rc.GATE_BATCH_RUN / "gate-batch.json"
            (store.parent / "gate-batch.md").write_text("# every gate answered, trust me\n",
                                                        encoding="utf-8")
            _, status, detail = find(rc.gate1(ctx_for(root)), "gate1/gate-batch-owed")
            self.assertEqual(status, rc.FAIL, detail)
            self.assertIn("render --check", detail)
            gb.refresh_view(store, gb.load_batch(store))
            _, status, detail = find(rc.gate1(ctx_for(root)), "gate1/gate-batch-owed")
            self.assertEqual(status, rc.PASS, detail)

    def test_a_missing_gate_batch_store_fails_not_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, status, detail = find(rc.gate1(ctx_for(make_fixture(tmp, batch=False))),
                                     "gate1/gate-batch-owed")
            self.assertEqual(status, rc.FAIL, detail)
            self.assertIn("no batch", detail)

    def test_the_chaining_index_needs_the_report_path_not_the_word(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_fixture(tmp)
            (root / "docs" / "runs" / "README.md").write_text(
                "# Run archive\n\nA chain of custody, but no report named.\n", encoding="utf-8")
            checks = rc.gate5(ctx_for(root))
            self.assertEqual(find(checks, "gate5/chaining-report-published")[1], rc.FAIL)
            self.assertEqual(find(checks, "gate5/chaining-report-indexed")[1], rc.FAIL)
            (root / "docs" / "reports" / "chaining-2026-09-16").mkdir(parents=True)
            (root / "runtime" / "mission-chaining.md").write_text(
                "see docs/reports/chaining-2026-09-16/handoff-log.md\n", encoding="utf-8")
            checks = rc.gate5(ctx_for(root))
            _, status, detail = find(checks, "gate5/chaining-report-published")
            self.assertEqual(status, rc.PASS, detail)
            self.assertIn("docs/reports/chaining-2026-09-16/", detail)
            _, status, detail = find(checks, "gate5/chaining-report-indexed")
            self.assertEqual(status, rc.PASS, detail)
            self.assertIn("runtime/mission-chaining.md", detail)

    def test_gate_6_used_reads_run_artifacts_not_the_tools_presence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_fixture(tmp)  # gate-batch.py + its store; no watchdog, no tests/
            checks = rc.gate6(ctx_for(root))
            self.assertEqual(find(checks, "gate6/watchdog-merged")[1], rc.FAIL)
            _, status, detail = find(checks, "gate6/gate-batch-merged")
            self.assertEqual(status, rc.FAIL)
            self.assertIn("tests/test_gate_batch.py missing", detail)
            _, status, detail = find(checks, "gate6/gate-batch-used")
            self.assertEqual(status, rc.PASS, detail)
            self.assertIn(f"docs/runs/{rc.GATE_BATCH_RUN}/gate-batch.json", detail)
            self.assertEqual(find(checks, "gate6/watchdog-used")[1], rc.FAIL)
            (root / "docs" / "runs" / "some-run").mkdir()
            (root / "docs" / "runs" / "some-run" / "REPORT.md").write_text(
                "ran runtime/scripts/watchdog.py --dry-run over the trace\n", encoding="utf-8")
            _, status, detail = find(rc.gate6(ctx_for(root)), "gate6/watchdog-used")
            self.assertEqual(status, rc.PASS, detail)
            self.assertIn("docs/runs/some-run/REPORT.md", detail)

    def test_gates_3_and_4_read_the_workflow_and_doc_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_fixture(tmp)
            c3, c4 = rc.gate3(ctx_for(root)), rc.gate4(ctx_for(root))
            for checks, name in ((c3, "gate3/ci-runs-vf-bench"),
                                 (c3, "gate3/ci-runs-negative-control"),
                                 (c3, "gate3/vf-bench-gate"),
                                 (c3, "gate3/negative-control-demo"),
                                 (c4, "gate4/install-command-in-readme"),
                                 (c4, "gate4/install-command-in-distribution"),
                                 (c4, "gate4/checklist-exists")):
                self.assertEqual(find(checks, name)[1], rc.FAIL, name)
            wf = root / ".github" / "workflows"
            wf.mkdir(parents=True)
            # Workflows as GitHub reads them: a job, a step, a run: line that invokes the script.
            (wf / "validate.yml").write_text(
                "on:\n  pull_request:\n\njobs:\n  vfbench:\n    steps:\n"
                "      - run: python3 bench/vf-bench/gate.py\n", encoding="utf-8")
            (wf / "negative-control.yml").write_text(
                "on:\n  pull_request:\n\njobs:\n  pinned-demo:\n    steps:\n"
                "      - run: sh evals/demo/negative-control/run.sh\n", encoding="utf-8")
            (root / "README.md").write_text("git clone … && sh scripts/install.sh\n",
                                            encoding="utf-8")
            (root / "docs" / "distribution.md").write_text("`sh scripts/install.sh`\n",
                                                           encoding="utf-8")
            (root / "docs" / "release-1.0-checklist.md").write_text("# checklist\n",
                                                                    encoding="utf-8")
            c3, c4 = rc.gate3(ctx_for(root)), rc.gate4(ctx_for(root))
            _, status, detail = find(c3, "gate3/ci-runs-vf-bench")
            self.assertEqual(status, rc.PASS, detail)
            self.assertIn("validate.yml", detail)
            self.assertEqual(find(c3, "gate3/ci-runs-negative-control")[1], rc.PASS)
            for name in ("gate4/install-command-in-readme",
                         "gate4/install-command-in-distribution", "gate4/checklist-exists"):
                self.assertEqual(find(c4, name)[1], rc.PASS, name)


FAKE_GH = """#!/bin/sh
# A canned `gh` for tests: every answer comes from the environment, so one script
# plays authenticated, logged-out, offline and wrong-answer GitHub in turn.
case "$1 $2" in
  "auth status")
    [ -n "$GH_AUTH_STDERR" ] && printf '%s\\n' "$GH_AUTH_STDERR" >&2
    exit "${GH_AUTH_EXIT:-0}" ;;
  "issue view") out="$GH_ISSUE_JSON" ;;
  "pr view") out="$GH_PR_JSON" ;;
  "run list") out="$GH_RUN_JSON" ;;
  *) echo "unexpected gh argv: $*" >&2; exit 9 ;;
esac
[ -n "$GH_CMD_STDERR" ] && printf '%s\\n' "$GH_CMD_STDERR" >&2
printf '%s\\n' "$out"
exit "${GH_CMD_EXIT:-0}"
"""


class GateOneReadsTheHumanKeyAtTheAnchor(unittest.TestCase):
    """PR #719 review (P1, W3-06): gate 1 ran `gate-batch.py … list` with no --pin-ref. With
    ORCA_PROVENANCE set, gate-batch's own rule refused it, so gate 1 failed every release; without
    it, the key came from the WORKING TREE — delete the pin, type the answers, and the original
    bypass was back. Gate 1 now reads the key at refs/remotes/origin/main, resolved once: a signed
    answer passes on both lanes, a typed one does not, and deleting the pin changes nothing.
    Driven through the real release_check → gate-batch.py → decisions.py path."""

    SEED = bytes(range(9, 41))

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.root = make_fixture(self._td.name, owed=True)
        spec = importlib.util.spec_from_file_location(
            "ed25519_for_release_check", ROOT / "runtime" / "scripts" / "ed25519.py")
        self.ed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ed)
        pin = self.root / ".orca" / "human-grant-pubkey"
        pin.parent.mkdir()
        pin.write_text(self.ed.publickey(self.SEED).hex() + "\n", encoding="utf-8")
        git_commit(self.root, "the human grant key lands on main")
        self.store = self.root / "docs" / "runs" / rc.GATE_BATCH_RUN / "gate-batch.json"

    def answer(self, signed):
        data = gb.load_batch(self.store)
        gate = gb.transition(data, "G1", "answered", "ship it", answered="2026-09-16",
                             source="human:lia")
        if signed:
            gate["grant_sig"] = self.ed.signature(gb.answer_payload(data, gate), self.SEED,
                                                  self.ed.publickey(self.SEED)).hex()
        gb.save_batch(self.store, data)

    def gate1(self, env=None):
        with mock.patch.dict(os.environ, env or {}):
            for var in ("ORCA_PROVENANCE", "OPEN_FLEET_PROVENANCE"):
                if var not in (env or {}):
                    os.environ.pop(var, None)
            return find(rc.gate1(ctx_for(self.root)), "gate1/gate-batch-owed")

    def test_a_signed_answer_passes_on_both_lanes(self):
        self.answer(signed=True)
        for env in (None, {"ORCA_PROVENANCE": "ci"}):
            with self.subTest(env=env):
                _, status, detail = self.gate1(env)
                self.assertEqual(status, rc.PASS, detail)

    def test_a_typed_answer_stays_owed(self):
        self.answer(signed=False)
        _, status, detail = self.gate1()
        self.assertEqual(status, rc.FAIL, detail)
        self.assertIn("G1", detail)

    def test_deleting_the_working_tree_pin_does_not_restore_typed_answers(self):
        (self.root / ".orca" / "human-grant-pubkey").unlink()
        self.answer(signed=False)
        _, status, detail = self.gate1()
        self.assertEqual(status, rc.FAIL, detail)
        # ...and committing the deletion moves HEAD, not the anchor the key is read at.
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=t", "-c", "user.email=t@t",
                        "commit", "-q", "-m", "drop the pin"], check=True)
        _, status, detail = self.gate1()
        self.assertEqual(status, rc.FAIL, detail)

    def test_no_anchor_fails_closed(self):
        subprocess.run(["git", "-C", str(self.root), "update-ref", "-d",
                        "refs/remotes/origin/main"], check=True)
        self.answer(signed=True)
        _, status, detail = self.gate1()
        self.assertEqual(status, rc.FAIL, detail)
        self.assertIn("refs/remotes/origin/main", detail)

    def test_a_local_bridge_inside_the_anchor_chain_is_no_anchor(self):
        # Codex review round 2 (P1): for-each-ref's %(symref) is the chain's END, so
        # refs/remotes/origin/main -> refs/heads/bridge -> refs/remotes/origin/typed (a fetched
        # branch that drops the pin and types the answer) read as remote-tracking all the way.
        (self.root / ".orca" / "human-grant-pubkey").unlink()
        self.answer(signed=False)
        git = ["git", "-C", str(self.root)]
        subprocess.run([*git, "add", "-A"], check=True)
        subprocess.run([*git, "-c", "user.name=t", "-c", "user.email=t@t", "-c",
                        "commit.gpgsign=false", "commit", "-q", "-m", "no pin, typed"], check=True)
        subprocess.run([*git, "update-ref", "refs/remotes/origin/typed", "HEAD"], check=True)
        subprocess.run([*git, "symbolic-ref", "refs/heads/bridge", "refs/remotes/origin/typed"],
                       check=True)
        for chain in ((("refs/remotes/origin/main", "refs/heads/bridge"),),
                      (("refs/remotes/origin/hop", "refs/heads/bridge"),
                       ("refs/remotes/origin/main", "refs/remotes/origin/hop"))):
            for link in chain:
                subprocess.run([*git, "symbolic-ref", *link], check=True)
            for env in (None, {"ORCA_PROVENANCE": "ci"}):
                with self.subTest(chain=chain, env=env):
                    _, status, detail = self.gate1(env)
                    self.assertEqual(status, rc.FAIL, detail)
                    self.assertIn("refs/heads/bridge", detail)

    def test_a_fetched_branch_name_holding_a_line_break_never_stands_in_for_the_anchor(self):
        # Independent re-attack (A): str.splitlines() broke the listing at U+2028/U+2029/U+0085,
        # so a fetched `x<U+2028>refs/remotes/origin/main` at a commit that drops the pin and
        # types the answer replaced the anchor and gate 1 PASSED.
        git = ["git", "-C", str(self.root)]
        honest = subprocess.run([*git, "rev-parse", "HEAD"], check=True, capture_output=True,
                                text=True).stdout.strip()
        subprocess.run([*git, "checkout", "-q", "-b", "typed"], check=True)
        (self.root / ".orca" / "human-grant-pubkey").unlink()
        self.answer(signed=False)
        subprocess.run([*git, "add", "-A"], check=True)
        subprocess.run([*git, "-c", "user.name=t", "-c", "user.email=t@t", "-c",
                        "commit.gpgsign=false", "commit", "-q", "-m", "no pin, typed"], check=True)
        typed = subprocess.run([*git, "rev-parse", "HEAD"], check=True, capture_output=True,
                               text=True).stdout.strip()
        self.assertEqual(subprocess.run([*git, "rev-parse", "refs/remotes/origin/main"],
                                        check=True, capture_output=True,
                                        text=True).stdout.strip(), honest)
        for ch in refname_breaks.LINE_BREAKS:
            with self.subTest(ch=ch):
                unplant = refname_breaks.plant(self.root, ch, typed)
                try:
                    _, status, detail = self.gate1()
                finally:
                    unplant()
                # Read at the real anchor, which pins the key the tree deleted: refused.
                self.assertEqual(status, rc.FAIL, detail)
                self.assertIn("differs", detail)

    def test_a_local_branch_spelled_as_the_absent_anchor_is_no_anchor(self):
        # W3-07 class, Codex review (P1): with refs/remotes/origin/main ABSENT, symbolic-ref
        # failed, the name kept its spelling, and rev-parse expanded it to the LOCAL branch
        # refs/heads/refs/remotes/origin/main — here a commit that drops the pin and types the
        # answer, so the key read "at the anchor" was none and the typed answer closed G1.
        (self.root / ".orca" / "human-grant-pubkey").unlink()
        self.answer(signed=False)
        git = ["git", "-C", str(self.root)]
        subprocess.run([*git, "add", "-A"], check=True)
        subprocess.run([*git, "-c", "user.name=t", "-c", "user.email=t@t", "-c",
                        "commit.gpgsign=false", "commit", "-q", "-m", "no pin, typed"], check=True)
        subprocess.run([*git, "update-ref", "-d", "refs/remotes/origin/main"], check=True)
        subprocess.run([*git, "update-ref", "refs/heads/refs/remotes/origin/main", "HEAD"],
                       check=True)
        for env in (None, {"ORCA_PROVENANCE": "ci"}):
            with self.subTest(env=env):
                _, status, detail = self.gate1(env)
                self.assertEqual(status, rc.FAIL, detail)
                self.assertIn("exactly that name", detail)


class GateOneHoldsTheReleaseToTheAnchoredGateSet(unittest.TestCase):
    """PR #719 review round 3 (P1): a signature protects each ANSWER, but nothing authenticated
    the SET of owed gates. With the key pinned at refs/remotes/origin/main, `"gates": []` plus a
    re-rendered view passed gate 1: validate_batch took the empty list and `list` owed nothing.
    The set is now read where the key is read — the batch at that same commit — and every way of
    making an anchored gate vanish from the release tree is owed (or could-not-run), each driven
    through the real release_check → gate-batch.py → decisions.py path: emptied, deleted, renamed,
    re-worded and then signed, duplicated, the store or its view deleted, a status typed without
    a signature, a batch the anchor never carried. Reordering hides nothing and blocks nothing."""

    SEED = bytes(range(11, 43))

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.root = make_fixture(self._td.name, owed=True)
        spec = importlib.util.spec_from_file_location(
            "ed25519_for_release_check_set", ROOT / "runtime" / "scripts" / "ed25519.py")
        self.ed = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ed)
        pin = self.root / ".orca" / "human-grant-pubkey"
        pin.parent.mkdir()
        pin.write_text(self.ed.publickey(self.SEED).hex() + "\n", encoding="utf-8")
        self.store = self.root / "docs" / "runs" / rc.GATE_BATCH_RUN / "gate-batch.json"
        data = gb.load_batch(self.store)
        gb.add_gate(data, gid="G2", asked="2026-09-14", title="a second question",
                    question="ship without the audit?")
        gb.save_batch(self.store, data)
        gb.refresh_view(self.store, data)
        git_commit(self.root, "the key and the owed gates land on main")

    def gate1(self, env=None):
        with mock.patch.dict(os.environ, env or {}):
            for var in ("ORCA_PROVENANCE", "OPEN_FLEET_PROVENANCE"):
                if var not in (env or {}):
                    os.environ.pop(var, None)
            return find(rc.gate1(ctx_for(self.root)), "gate1/gate-batch-owed")

    def assert_fails(self, *names):
        for env in (None, {"ORCA_PROVENANCE": "ci"}):
            with self.subTest(env=env):
                _, status, detail = self.gate1(env)
                self.assertEqual(status, rc.FAIL, detail)
                for gid in names:
                    self.assertIn(gid, detail)

    def sign(self, data, gate):
        gate["grant_sig"] = self.ed.signature(gb.answer_payload(data, gate), self.SEED,
                                              self.ed.publickey(self.SEED)).hex()

    def write(self, data, view=True):
        """Save the store exactly as a worker would, and re-render the view so render --check
        has nothing to say — the attack Codex ran."""
        self.store.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        if view:
            (self.store.parent / "gate-batch.md").write_text(gb.render_batch(data),
                                                             encoding="utf-8")

    def answer_all(self, data):
        for gid in [g["id"] for g in data["gates"]]:
            gate = gb.transition(data, gid, "answered", f"yes to {gid}", answered="2026-09-16",
                                 source="human:lia")
            self.sign(data, gate)
        return data

    def test_every_owed_gate_answered_and_signed_passes(self):
        self.write(self.answer_all(gb.load_batch(self.store)))
        for env in (None, {"ORCA_PROVENANCE": "ci"}):
            with self.subTest(env=env):
                _, status, detail = self.gate1(env)
                self.assertEqual(status, rc.PASS, detail)

    def test_an_emptied_batch_with_its_view_re_rendered_owes_every_anchored_gate(self):
        data = gb.load_batch(self.store)
        data["gates"] = []
        self.write(data)
        self.assert_fails("G1", "G2")

    def test_deleting_one_owed_gate_owes_it(self):
        data = self.answer_all(gb.load_batch(self.store))
        data["gates"] = [g for g in data["gates"] if g["id"] != "G2"]
        self.write(data)
        self.assert_fails("G2")

    def test_renaming_a_gate_owes_the_anchored_id(self):
        data = self.answer_all(gb.load_batch(self.store))
        renamed = next(g for g in data["gates"] if g["id"] == "G2")
        renamed.update(id="G9", status="owed", answer=None, answered=None)
        renamed.pop("source"), renamed.pop("grant_sig")
        gate = gb.transition(data, "G9", "answered", "yes to G9", answered="2026-09-16",
                             source="human:lia")
        self.sign(data, gate)  # a genuine signature, over a gate the anchor never asked
        self.write(data)
        self.assert_fails("G2")

    def test_a_question_re_worded_before_the_human_signed_is_owed(self):
        # The human signs what the record says. A worker that re-words the anchored question
        # into something harmless, and gets THAT signed, has not had the anchored one answered.
        data = gb.load_batch(self.store)
        next(g for g in data["gates"] if g["id"] == "G2")["question"] = "is the sky blue?"
        self.write(self.answer_all(data))
        self.assert_fails("G2")

    def test_a_re_dated_or_re_titled_gate_is_owed(self):
        for field, value in (("asked", "2026-09-15"), ("title", "a smaller question")):
            with self.subTest(field=field):
                data = gb.load_batch(self.store)
                next(g for g in data["gates"] if g["id"] == "G1")[field] = value
                self.write(self.answer_all(data))
                self.assert_fails("G1")
                subprocess.run(["git", "-C", str(self.root), "checkout", "-q", "--", "docs"],
                               check=True)

    def test_a_batch_claiming_another_run_owes_every_anchored_gate(self):
        data = gb.load_batch(self.store)
        data["run_id"] = "run_elsewhere"
        self.write(self.answer_all(data))
        self.assert_fails("G1", "G2")

    def test_a_duplicated_gate_id_fails(self):
        data = self.answer_all(gb.load_batch(self.store))
        data["gates"].append(dict(data["gates"][0]))
        self.write(data, view=False)
        self.assert_fails()

    def test_reordering_hides_nothing_and_blocks_nothing(self):
        data = gb.load_batch(self.store)
        data["gates"].reverse()
        self.write(data)
        self.assert_fails("G1", "G2")
        data = self.answer_all(gb.load_batch(self.store))
        data["gates"].reverse()
        self.write(data)
        _, status, detail = self.gate1({"ORCA_PROVENANCE": "ci"})
        self.assertEqual(status, rc.PASS, detail)

    def test_a_status_typed_without_a_signature_is_owed(self):
        for status in ("answered", "waived", "overtaken"):
            with self.subTest(status=status):
                data = gb.load_batch(self.store)
                for gid in ("G1", "G2"):
                    gb.transition(data, gid, status, "typed", answered="2026-09-16",
                                  source="human:lia")
                self.write(data)
                self.assert_fails("G1", "G2")
                subprocess.run(["git", "-C", str(self.root), "checkout", "-q", "--", "docs"],
                               check=True)

    def test_deleting_the_store_fails(self):
        self.store.unlink()
        self.assert_fails()

    def test_deleting_or_truncating_the_view_the_anchor_carries_fails(self):
        self.write(self.answer_all(gb.load_batch(self.store)))
        view = self.store.parent / "gate-batch.md"
        view.write_text("", encoding="utf-8")
        _, status, detail = self.gate1()
        self.assertEqual(status, rc.FAIL, detail)
        view.unlink()
        _, status, detail = self.gate1()
        self.assertEqual(status, rc.FAIL, detail)
        self.assertIn("gate-batch.md", detail)

    def test_a_replacement_object_cannot_hide_what_the_anchor_carries(self):
        # Independent re-attack (B): gate 1 listed what the anchor carries under the ambient env,
        # so `git replace <anchor> <a commit without the view>` hid the view the anchor holds,
        # and a release that deleted it PASSED. Resolution and listing now run under gitexec's
        # hardened env, as gate-batch.py reads the same commit.
        self.write(self.answer_all(gb.load_batch(self.store)))
        view = self.store.parent / "gate-batch.md"
        rel_view = f"docs/runs/{rc.GATE_BATCH_RUN}/gate-batch.md"
        git = ["git", "-C", str(self.root)]
        anchor = subprocess.run([*git, "rev-parse", "refs/remotes/origin/main"], check=True,
                                capture_output=True, text=True).stdout.strip()
        index = self.root.parent / "replacement-index"
        env = dict(os.environ, GIT_INDEX_FILE=str(index))
        subprocess.run([*git, "read-tree", anchor], check=True, env=env)
        subprocess.run([*git, "rm", "-q", "--cached", rel_view], check=True, env=env)
        tree = subprocess.run([*git, "write-tree"], check=True, env=env, capture_output=True,
                              text=True).stdout.strip()
        fake = subprocess.run([*git, "-c", "user.name=t", "-c", "user.email=t@t",
                               "commit-tree", tree, "-m", "the anchor, minus its view"],
                              check=True, capture_output=True, text=True).stdout.strip()
        subprocess.run([*git, "replace", anchor, fake], check=True)
        view.unlink()
        _, status, detail = self.gate1()
        self.assertEqual(status, rc.FAIL, detail)
        self.assertIn("gate-batch.md", detail)

    def test_a_batch_the_anchor_does_not_carry_fails(self):
        # Drop the store from the anchor (a reviewed main without it), keep it in the release
        # tree with every gate signed: there is no trusted set to hold the release to.
        self.write(self.answer_all(gb.load_batch(self.store)))
        rel = f"docs/runs/{rc.GATE_BATCH_RUN}"
        subprocess.run(["git", "-C", str(self.root), "rm", "-q", "-r", "--cached", rel],
                       check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=t", "-c", "user.email=t@t",
                        "-c", "commit.gpgsign=false", "commit", "-q", "-m", "no batch"],
                       check=True)
        subprocess.run(["git", "-C", str(self.root), "update-ref", "refs/remotes/origin/main",
                        "HEAD"], check=True)
        _, status, detail = self.gate1()
        self.assertEqual(status, rc.FAIL, detail)
        self.assertIn("refs/remotes/origin/main", detail)


class GitHubAnswersAreVerdicts(unittest.TestCase):
    """With gh present and answering, its answer is a verdict (PASS/FAIL), never a SKIP;
    a machine at fault (logged out, offline) is a SKIP that names why. A canned `gh` on
    PATH plays each role; the fixture is a real git repository so HEAD binds."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = make_fixture(Path(self.tmp.name) / "repo")
        for argv in (["git", "init", "-q"], ["git", "config", "user.email", "t@example.com"],
                     ["git", "config", "user.name", "t"], ["git", "add", "-A"],
                     ["git", "commit", "-q", "-m", "fixture"]):
            subprocess.run(argv, cwd=str(self.root), check=True, capture_output=True)
        self.head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(self.root),
                                   capture_output=True, text=True, check=True).stdout.strip()
        bin_dir = Path(self.tmp.name) / "bin"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(FAKE_GH, encoding="utf-8")
        gh.chmod(0o755)
        self.env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"}

    def ctx(self):
        return rc.Context(self.root, fast=True, skip_github=False)

    def with_gh(self, **answers):
        env = dict(self.env)
        env.update({k: str(v) for k, v in answers.items()})
        return mock.patch.dict(os.environ, env, clear=False)

    def test_closed_and_merged_answers_pass_open_ones_fail(self):
        with self.with_gh(GH_ISSUE_JSON='{"state": "CLOSED"}', GH_PR_JSON='{"state": "MERGED"}'):
            ctx = self.ctx()
            self.assertEqual(rc.check_issue_closed(ctx, "gate1", 408, "x")[1], rc.PASS)
            self.assertEqual(rc.check_pr_merged(ctx, "gate1", 406, "x")[1], rc.PASS)
        with self.with_gh(GH_ISSUE_JSON='{"state": "OPEN"}', GH_PR_JSON='{"state": "OPEN"}'):
            ctx = self.ctx()
            name, status, detail = rc.check_issue_closed(ctx, "gate1", 408, "x")
            self.assertEqual((name, status), ("gate1/gh-issue-408-closed", rc.FAIL))
            self.assertIn("OPEN", detail)
            _, status, detail = rc.check_pr_merged(ctx, "gate1", 406, "x")
            self.assertEqual(status, rc.FAIL)
            self.assertIn("OPEN", detail)

    def test_a_workflow_run_is_green_only_at_this_head(self):
        at_head = json.dumps([{"conclusion": "success", "headSha": self.head}])
        with self.with_gh(GH_RUN_JSON=at_head):
            name, status, detail = rc.check_workflow_green_at_head(self.ctx(), "gate0", "validate")
            self.assertEqual((name, status), ("gate0/gh-validate-run-green-at-head", rc.PASS))
            self.assertIn(self.head, detail)
        stale = json.dumps([{"conclusion": "success", "headSha": "0" * 40}])
        with self.with_gh(GH_RUN_JSON=stale):
            _, status, detail = rc.check_workflow_green_at_head(self.ctx(), "gate0", "validate")
            self.assertEqual(status, rc.FAIL)
            self.assertIn("stale green", detail)
        with self.with_gh(GH_RUN_JSON="[]"):
            _, status, detail = rc.check_workflow_green_at_head(self.ctx(), "gate0", "validate")
            self.assertEqual(status, rc.FAIL)
            self.assertIn("no `validate` workflow run", detail)

    def test_an_answer_that_is_not_json_fails_the_check(self):
        with self.with_gh(GH_ISSUE_JSON="<html>rate limited</html>"):
            _, status, detail = rc.check_issue_closed(self.ctx(), "gate1", 408, "x")
        self.assertEqual(status, rc.FAIL)
        self.assertIn("printed no JSON", detail)

    def test_a_failing_gh_command_is_a_skip_when_the_machine_is_at_fault_else_a_fail(self):
        cases = (("error: not logged in to any hosts. run gh auth login", rc.SKIP, "gh unauthenticated"),
                 ("dial tcp: lookup api.github.com: no such host", rc.SKIP, "no network"),
                 ("GraphQL: Could not find an Issue with the number of 408 (repository.issue)",
                  rc.FAIL, "exit 1"))
        for stderr, want_status, want_detail in cases:
            with self.subTest(stderr=stderr), self.with_gh(GH_CMD_EXIT=1, GH_CMD_STDERR=stderr):
                _, status, detail = rc.check_issue_closed(self.ctx(), "gate1", 408, "x")
                self.assertEqual(status, want_status, detail)
                self.assertIn(want_detail, detail)

    def test_the_auth_probe_runs_once_and_classifies_the_machine(self):
        with self.with_gh():
            ctx = self.ctx()
            self.assertIsNone(rc.gh_unavailable(ctx))
            self.assertIsNone(rc.gh_unavailable(ctx))  # memoized, not re-probed
        with self.with_gh(GH_AUTH_EXIT=1, GH_AUTH_STDERR="You are not logged in to any GitHub hosts"):
            self.assertEqual(rc.gh_unavailable(self.ctx()), "gh unauthenticated")
        with self.with_gh(GH_AUTH_EXIT=1, GH_AUTH_STDERR="error connecting: could not resolve host"):
            self.assertTrue(rc.gh_unavailable(self.ctx()).startswith("no network: "))
        with self.with_gh(GH_ISSUE_JSON='{"state": "CLOSED"}', GH_PR_JSON='{"state": "MERGED"}',
                          GH_RUN_JSON=json.dumps([{"conclusion": "success", "headSha": self.head}])):
            rows = rc.gate1(self.ctx())
            gh_rows = [r for r in rows if "/gh-" in r[0]]
            self.assertTrue(gh_rows)
            self.assertNotIn(rc.SKIP, {status for _, status, _ in gh_rows})


class TheGreenRunIsOnTheBranchBeingCut(unittest.TestCase):
    """2026-10-27 security audit, W6-12: gates 0 and 4 asked for the latest run on `main` and
    bound it to HEAD, while docs/ops.md cuts on a release branch, whose HEAD never has a run on
    main: the gate could only FAIL at a cut. Reading by branch name instead let a fork's PR from a
    same-named branch take the one run read (PR #718 re-attack). The runs at exactly HEAD are
    read, on any branch; the newest decides, and a green at another SHA still does not count."""

    LOGGING_GH = ("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$GH_ARGV_LOG\"\n"
                  "case \"$1 $2\" in\n  \"auth status\") exit 0 ;;\n"
                  "  \"run list\") printf '%s\\n' \"$GH_RUN_JSON\" ;;\n"
                  "  *) exit 9 ;;\nesac\n")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = make_fixture(Path(self.tmp.name) / "repo")
        git_env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                   "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
        self.git = lambda *a: subprocess.run(["git", *a], cwd=str(self.root), env=git_env,
                                             check=True, capture_output=True, text=True).stdout
        self.git("init", "-q", "-b", "main")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "fixture")
        self.git("switch", "-q", "-c", "release/9.9.9")
        self.git("commit", "-q", "--allow-empty", "-m", "Prepare release 9.9.9")
        self.head = self.git("rev-parse", "HEAD").strip()
        bin_dir = Path(self.tmp.name) / "bin"
        bin_dir.mkdir()
        (bin_dir / "gh").write_text(self.LOGGING_GH, encoding="utf-8")
        (bin_dir / "gh").chmod(0o755)
        self.log = Path(self.tmp.name) / "gh-argv.log"
        self.path = f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"

    def check(self, runs):
        self.log.unlink(missing_ok=True)
        env = {"PATH": self.path, "GH_ARGV_LOG": str(self.log), "GH_RUN_JSON": json.dumps(runs)}
        with mock.patch.dict(os.environ, env):
            ctx = rc.Context(self.root, fast=True, skip_github=False)
            result = rc.check_workflow_green_at_head(ctx, "gate4", "install")
        asked = [ln for ln in self.log.read_text(encoding="utf-8").splitlines()
                 if ln.startswith("run list")]
        self.assertEqual(len(asked), 1, asked)
        return result, asked[0].split()

    def run_at(self, sha, conclusion="success", branch="release/9.9.9", event="pull_request"):
        return {"conclusion": conclusion, "headSha": sha, "headBranch": branch, "event": event}

    def test_a_green_run_at_the_release_branch_head_passes(self):
        (name, status, detail), argv = self.check([self.run_at(self.head)])
        self.assertEqual(argv[argv.index("--commit") + 1], self.head)
        self.assertNotIn("--branch", argv)
        self.assertEqual((name, status), ("gate4/gh-install-run-green-at-head", rc.PASS), detail)
        self.assertIn(self.head, detail)

    def test_a_stale_green_still_fails(self):
        parent = self.git("rev-parse", "HEAD~1").strip()
        (_, status, detail), _ = self.check([self.run_at(parent)])
        self.assertEqual(status, rc.FAIL)
        self.assertIn("stale green", detail)
        (_, status, detail), _ = self.check([])
        self.assertEqual(status, rc.FAIL)
        self.assertIn("no `install` workflow run recorded at", detail)

    def test_a_fork_run_on_a_same_named_branch_cannot_take_the_slot(self):
        # PR #718 re-attack: `--branch <name> --limit 1` read whichever run was newest on that
        # branch NAME, a fork's same-named PR branch included. The runs at exactly HEAD decide.
        fork = self.run_at("f" * 40, conclusion="failure")
        (_, status, detail), _ = self.check([fork, self.run_at(self.head)])
        self.assertEqual(status, rc.PASS, detail)

    def test_the_newest_run_at_head_decides(self):
        (_, status, detail), _ = self.check([self.run_at(self.head, conclusion="failure"),
                                             self.run_at(self.head)])
        self.assertEqual(status, rc.FAIL, detail)
        self.assertIn("failure", detail)

    def test_main_and_a_detached_head_read_the_same_commit(self):
        for target in (("switch", "-q", "main"), ("switch", "-q", "--detach", "release/9.9.9")):
            self.git(*target)
            head = self.git("rev-parse", "HEAD").strip()
            with self.subTest(target=target):
                _, argv = self.check([])
                self.assertEqual(argv[argv.index("--commit") + 1], head)


class SkipsNeverPass(unittest.TestCase):
    def test_skip_github_skips_every_gh_backed_check_with_the_flag_as_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = ctx_for(make_fixture(tmp))
            self.assertEqual(rc.check_issue_closed(ctx, "gate1", 408, "x"),
                             ("gate1/gh-issue-408-closed", rc.SKIP, "--skip-github"))
            self.assertEqual(rc.check_pr_merged(ctx, "gate1", 406, "x"),
                             ("gate1/gh-pr-406-merged", rc.SKIP, "--skip-github"))
            self.assertEqual(rc.check_workflow_green_at_head(ctx, "gate0", "validate"),
                             ("gate0/gh-validate-run-green-at-head", rc.SKIP, "--skip-github"))
            _, status, detail = rc.info_issue_235(ctx)
            self.assertEqual(status, rc.INFO)
            self.assertIn("does not gate", detail)
            self.assertIn("--skip-github", detail)
            gh_checks = [c for gate in (rc.gate0, rc.gate1, rc.gate4, rc.gate5, rc.gate6)
                         for c in gate(ctx) if "/gh-" in c[0]]
            self.assertGreaterEqual(len(gh_checks), 8)
            self.assertEqual({(s, d) for _, s, d in gh_checks}, {(rc.SKIP, "--skip-github")})

    def test_no_gh_on_path_yields_skip_no_gh_never_pass(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as emptybin:
            root = make_fixture(tmp)
            env = dict(os.environ, PATH=emptybin)
            env.pop("GH_TOKEN", None)
            env.pop("GITHUB_TOKEN", None)
            proc = run_script("--fast", "--repo", str(root), cwd=root, env=env)
            self.assertIn(proc.returncode, (1, 3), proc.stderr)  # it ran; a fixture is no release
            rows = parse(proc.stdout)
            gh_rows = [r for r in rows if "/gh-" in r[2]]
            self.assertGreaterEqual(len(gh_rows), 8, proc.stdout)
            for status, reason, name in gh_rows:
                self.assertEqual((status, reason), ("SKIP", "no gh"), name)
            self.assertRegex(proc.stdout,
                             re.compile(r"^\s*SKIP\(no gh\)  gate1/gh-issue-408-closed$", re.M))
            self.assertRegex(proc.stdout, r"INFO  gate1/issue-235-marketplace: .*no gh")
            self.assertIn("SKIP(--fast)  gate0/unittest", proc.stdout)
            # git is off that PATH too: the tree check is a SKIP as well, not a PASS.
            self.assertIn("SKIP(no git)  gate0/tree-clean", proc.stdout)
            self.assertNotRegex(proc.stdout, r"PASS  gate\d/gh-")


class MachineOutputAndExitContract(unittest.TestCase):
    def test_a_standing_skip_is_incomplete_never_green(self):
        # PR #509 review: --fast / --skip-github / a machine without gh used to exit 0
        # when nothing failed, so a release script reading the code could cut 1.0 on a
        # run that never checked the suite, CI at HEAD, or the issue and PR states.
        counts = {"pass": 30, "fail": 0, "skip": 0, "info": 1}
        self.assertEqual(rc.exit_code(counts), 0)
        self.assertEqual(rc.exit_code(dict(counts, skip=1)), 3)
        self.assertEqual(rc.exit_code(dict(counts, skip=1, fail=1)), 1)
        self.assertEqual(rc.exit_code(dict(counts, fail=1)), 1)
        self.assertEqual(rc.EXIT_INCOMPLETE, 3)

    def test_the_summary_line_and_the_exit_carry_a_skip_as_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_fixture(tmp)
            (root / "scripts").mkdir(exist_ok=True)
            proc = run_script("--fast", "--skip-github", "--json", "--repo", str(root), cwd=root)
            data = json.loads(proc.stdout)
            self.assertEqual(data["exit"], proc.returncode)
            if data["summary"]["fail"] == 0:
                self.assertEqual(proc.returncode, 3)
            else:
                self.assertEqual(proc.returncode, 1)

    def test_json_is_one_object_whose_summary_and_exit_agree_with_its_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_fixture(tmp)
            proc = run_script("--fast", "--skip-github", "--json", "--repo", str(root), cwd=root)
            data = json.loads(proc.stdout)
            checks = [c for g in data["gates"] for c in g["checks"]]
            self.assertEqual([g["gate"] for g in data["gates"]], [g for g, _, _ in rc.GATES])
            statuses = [c["status"] for c in checks]
            self.assertTrue(set(statuses) <= set(rc.STATUSES), statuses)
            self.assertEqual(data["summary"],
                             {s.lower(): statuses.count(s) for s in rc.STATUSES})
            self.assertEqual(data["exit"], proc.returncode)
            self.assertEqual(proc.returncode, 1)  # no validate.py in a fixture: FAIL, exit 1
            self.assertTrue(data["fast"] and data["skip_github"])
            self.assertEqual(data["repo"], str(root.resolve()))
            skips = {c["name"]: c["detail"] for c in checks if c["status"] == "SKIP"}
            self.assertEqual(skips["gate0/unittest"], "--fast")
            self.assertEqual(skips["gate1/gh-issue-408-closed"], "--skip-github")

    def test_a_repo_that_is_not_a_directory_is_could_not_run(self):
        proc = run_script("--repo", "/nonexistent/open-fleet-checkout")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("not a directory", proc.stderr)

    def test_the_header_documents_the_contract(self):
        head = SCRIPT.read_text(encoding="utf-8")[:4000]
        for needle in ("0  every check PASS", "1  any check FAIL", "2  could not run",
                       "3  incomplete", "--fast", "--skip-github", "--repo", "--json",
                       "never PASS"):
            self.assertIn(needle, head, needle)
        self.assertTrue(os.access(SCRIPT, os.X_OK), "scripts/release_check.py is not executable")


class TheChecklistPointsAtTheScript(unittest.TestCase):
    """The doc stays the definition; the script is its executable form. Hold
    them together: the run command up top, one heading per gate the script
    runs, the commands the script runs shown verbatim, the stale ones gone."""

    @classmethod
    def setUpClass(cls):
        cls.text = CHECKLIST.read_text(encoding="utf-8")

    def test_it_opens_with_the_run_command(self):
        self.assertIn("Run it: `python3 scripts/release_check.py`", self.text[:400])

    def test_one_heading_per_gate_the_script_runs(self):
        headings = re.findall(r"^## (Gate \d)", self.text, re.M)
        self.assertEqual(headings, [title.split(" — ")[0] for _, title, _ in rc.GATES])

    def test_the_commands_shown_are_the_ones_the_script_runs(self):
        for needle in (
                "python3 runtime/scripts/gate-batch.py --run "
                f"{rc.GATE_BATCH_RUN} list --status owed",
                "python3 scripts/validate.py",
                "python3 -m unittest discover -s tests",
                "python3 runtime/scripts/proof_status.py --check",
                "python3 runtime/scripts/run_report.py",
                "python3 bench/vf-bench/gate.py",
                "sh evals/demo/negative-control/run.sh",
                'gh run list --workflow validate --commit "$RELEASE_SHA"',
                'gh run list --workflow install --commit "$RELEASE_SHA"',
                "export RELEASE_SHA=$(git rev-parse HEAD)",
                "gh pr view 406 --json state",
                f"grep -c '{rc.INSTALL_CMD}' README.md docs/distribution.md",
                "runtime/pins.json",
                f"grep -l '{rc.CHAINING_NEEDLE}' " + " ".join(rc.CHAINING_INDEXES),
                "docs/runs/*/gate-batch.json",
                "watchdog",
        ):
            self.assertIn(needle, self.text, needle)
        for number in (408, 386, 416, 417, 418, 419):
            self.assertIn(f"gh issue view {number} --json state", self.text)
        for tool, test in rc.MECHANIZED:
            self.assertIn(tool, self.text)
            self.assertIn(test, self.text)

    def test_the_stale_gates_are_gone(self):
        self.assertNotIn("Status: ANSWERED", self.text)  # the grep over the rendered view
        self.assertNotRegex(self.text, r"gh issue view 235 [^\n]*CLOSED")  # #235 no longer gates
        self.assertIn("does not gate", self.text)
        self.assertNotRegex(self.text, r'"harden-it",\s*"external-run"')  # the pre-re-scope bar
        self.assertIn("#407", self.text)
        self.assertIn("2026-09-21-harden-it-self-run.md", self.text)

    def test_the_bars_in_the_doc_are_the_scripts_bars(self):
        m = re.search(r"^BAR = \((.*?)\)$", self.text, re.M)
        self.assertIsNotNone(m, "Gate 2's python block no longer states BAR")
        self.assertEqual(tuple(re.findall(r'"([^"]+)"', m.group(1))), rc.PROOF_BAR)
        self.assertIn(f'e["witnessed"]>="{rc.PIN_MIN_WITNESSED}"', self.text)



VF_BENCH = (r"vfbench\.py", r"vf-bench/gate\.py")


class CiRunsMeansARunStep(unittest.TestCase):
    """2026-10-23 review, §5: "CI runs X" was satisfied by X anywhere in a workflow file — a
    comment, a step name, an `if:` — so gate3 could PASS on a check CI never executes."""

    def gate3(self, workflow):
        # Every pull request runs the fixture, as it runs the real ones, unless the case under
        # test names its own triggers.
        if not re.search(r"(?m)^on:", workflow):
            workflow = "on:\n  pull_request:\n\n" + workflow
        with tempfile.TemporaryDirectory() as tmp:
            root = make_fixture(tmp)
            wf = root / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "validate.yml").write_text(workflow, encoding="utf-8")
            # The check gate3 makes, without gate3's ~10 s of real tool runs around it.
            return rc.check_workflows_mention(ctx_for(root), "gate3/ci-runs-vf-bench",
                                              VF_BENCH, "#412")[1]

    def test_a_mention_outside_a_run_step_fails(self):
        for workflow in (
            "# python3 bench/vf-bench/gate.py is run nightly elsewhere\n",
            "jobs:\n  gates:\n    steps:\n      - name: bench/vf-bench/gate.py\n"
            "        run: echo skipped\n",
            "jobs:\n  gates:\n    steps:\n      - run: |\n          echo start\n"
            "          # python3 bench/vf-bench/gate.py\n",
        ):
            with self.subTest(workflow=workflow):
                self.assertEqual(self.gate3(workflow), rc.FAIL)

    def test_inline_and_block_run_steps_pass(self):
        for workflow in (
            "jobs:\n  gates:\n    steps:\n      - run: python3 bench/vf-bench/gate.py\n",
            "jobs:\n  gates:\n    steps:\n      - name: bench\n        run: |\n"
            "          python3 bench/vf-bench/gate.py\n",
        ):
            with self.subTest(workflow=workflow):
                self.assertEqual(self.gate3(workflow), rc.PASS)

    def test_a_mention_that_runs_nothing_fails(self):
        """2026-10-27 security audit, W6-10: `- run: echo negative-control` passed gate 3 with the
        real jobs deleted. A run: line counts only when a job step hands the script to an
        interpreter (or executes it), in a job and a step that are not switched off."""
        step = "jobs:\n  gates:\n    steps:\n      - run: {}\n"
        for workflow in (
            step.format("echo python3 bench/vf-bench/gate.py"),
            step.format('echo "bench/vf-bench/gate.py"'),
            step.format("printf '%s' 'python3 bench/vf-bench/gate.py'"),
            step.format("true  # python3 bench/vf-bench/gate.py"),
            step.format("cat bench/vf-bench/gate.py"),
            "run: python3 bench/vf-bench/gate.py\n",  # outside any job: GitHub never runs it
            "jobs:\n  gates:\n    if: false\n    steps:\n      - run: python3 bench/vf-bench/gate.py\n",
            "jobs:\n  gates:\n    if: ${{ false }}\n    steps:\n"
            "      - run: python3 bench/vf-bench/gate.py\n",
            "jobs:\n  gates:\n    steps:\n      - if: false\n"
            "        run: python3 bench/vf-bench/gate.py\n",
            "jobs:\n  gates:\n    steps:\n      - name: x\n        if: ${{ false }}\n"
            "        run: |\n          time python3 bench/vf-bench/gate.py\n",
        ):
            with self.subTest(workflow=workflow):
                self.assertEqual(self.gate3(workflow), rc.FAIL)

    STEP = "jobs:\n  gates:\n    steps:\n      - name: bench\n        run: |\n{}"

    def test_exactly_one_invocation_passes(self):
        for workflow in (
            "jobs:\n  gates:\n    steps:\n      - run: python3 bench/vf-bench/gate.py\n",
            "jobs:\n  gates:\n    steps:\n      - run: ./bench/vf-bench/gate.py\n",
            "jobs:\n  gates:\n    steps:\n      - run: bash bench/vf-bench/gate.py\n",
            self.STEP.format("\n          python3 bench/vf-bench/gate.py\n\n"),
        ):
            with self.subTest(workflow=workflow):
                self.assertEqual(self.gate3(workflow), rc.PASS)

    def test_anything_but_exactly_one_invocation_fails(self):
        """PR #718 re-review (P2): shell reachability is undecidable, so `exit 0` or
        `if false; then … fi` before the invocation, and an interpreter option that stops it
        (`-h`, `-c`, `-n`), still counted. A step counts only when its whole `run:`, stripped,
        is one line: python3, bash or sh and the script with no option between them (or
        ./script), and no shell metacharacter anywhere on the line."""
        for body in (
            "          exit 0\n          python3 bench/vf-bench/gate.py\n",
            "          if false; then\n            python3 bench/vf-bench/gate.py\n          fi\n",
            "          if false; then python3 bench/vf-bench/gate.py; fi\n",
            "          python3 -h bench/vf-bench/gate.py\n",
            "          python3 -c pass bench/vf-bench/gate.py\n",
            "          python3 -cpass bench/vf-bench/gate.py\n",
            "          python3 -m bench/vf-bench/gate.py\n",
            "          bash -n bench/vf-bench/gate.py\n",
            "          python3 bench/vf-bench/gate.py; echo done\n",
            "          python3 bench/vf-bench/gate.py && echo done\n",
            "          python3 bench/vf-bench/gate.py | tee out.txt\n",
            "          python3 bench/vf-bench/gate.py > out.txt\n",
            "          python3 bench/vf-bench/gate.py < /dev/null\n",
            "          python3 bench/vf-bench/gate.py $(true)\n",
            "          python3 bench/vf-bench/gate.py `true`\n",
            "          python3 bench/vf-bench/gate.py &\n",
            "          time python3 bench/vf-bench/gate.py\n",
            "          FOO=1 python3 bench/vf-bench/gate.py\n",
            "          exec python3 bench/vf-bench/gate.py\n",
            "          python bench/vf-bench/gate.py\n",
            "          set -euo pipefail\n          python3 bench/vf-bench/gate.py\n",
            "          python3 -mpy_compile bench/vf-bench/gate.py\n",
            "          python3 bench/vf-bench/gate.py --help\n",
            "          python3 bench/vf-bench/gate.py --strict x\n",
            "          ./bench/vf-bench/gate.py -h\n",
            "          cat <<EOF\n          python3 bench/vf-bench/gate.py\n          EOF\n",
        ):
            with self.subTest(body=body):
                self.assertEqual(self.gate3(self.STEP.format(body)), rc.FAIL)

    def test_a_workflow_every_pull_request_does_not_run_does_not_count(self):
        # PR #718 re-attack: a workflow only `workflow_dispatch` starts still counted. The real
        # gate-3 workflows run on every pull request (no filter) and on pushes to main.
        jobs = "\njobs:\n  gates:\n    steps:\n      - run: python3 bench/vf-bench/gate.py\n"
        for on in ("on:\n  workflow_dispatch:\n",
                   "on:\n  push:\n    branches: [main]\n",
                   "on:\n  schedule:\n    - cron: '0 0 * * *'\n",
                   "on:\n  pull_request:\n    paths:\n      - docs/**\n",
                   "on:\n  pull_request:\n    branches: [never]\n",
                   "on:\n  pull_request_target:\n"):
            with self.subTest(on=on):
                self.assertEqual(self.gate3(on + jobs), rc.FAIL)
        self.assertEqual(self.gate3("on:\n  pull_request:\n  push:\n    branches: [main]\n" + jobs),
                         rc.PASS)

    def test_a_key_that_changes_how_the_line_runs_disqualifies_it(self):
        # `shell: bash -n {0}` is `bash -n` moved out of the run: line; `working-directory` and
        # `defaults` decide which file the path names. None of the real gate-3 steps uses one.
        run = "      - name: x\n        run: python3 bench/vf-bench/gate.py\n"
        for workflow in (
            "jobs:\n  gates:\n    steps:\n" + run + "        shell: bash -n {0}\n",
            "jobs:\n  gates:\n    steps:\n" + run + "        working-directory: elsewhere\n",
            "jobs:\n  gates:\n    defaults:\n      run:\n        shell: bash -n {0}\n"
            "    steps:\n" + run,
            "defaults:\n  run:\n    shell: bash -n {0}\n\njobs:\n  gates:\n    steps:\n" + run,
        ):
            with self.subTest(workflow=workflow):
                self.assertEqual(self.gate3(workflow), rc.FAIL)

    def test_a_job_that_needs_another_does_not_count(self):
        # PR #718 review round 3 (P2): GitHub skips a job whose `needs:` prerequisite was skipped
        # (`if: false` on the prerequisite), and only the job's own keys were read. Neither real
        # gate-3 job has `needs:`, so a counted job may not have one at all.
        run = "    steps:\n      - name: x\n        run: python3 bench/vf-bench/gate.py\n"
        for workflow in (
                "jobs:\n  prereq:\n    if: false\n    steps:\n      - run: true\n"
                "  gates:\n    needs: prereq\n" + run,
                "jobs:\n  prereq:\n    steps:\n      - run: true\n"
                "  gates:\n    needs: [prereq]\n" + run,
                "jobs:\n  gates:\n    needs:\n      - prereq\n" + run):
            with self.subTest(workflow=workflow):
                self.assertEqual(self.gate3(workflow), rc.FAIL)

    def test_a_key_spelled_outside_the_block_subset_counts_nothing(self):
        # PR #718 review round 3: the job and step keys are read line by line, so a quoted
        # `"needs":`, `needs :` or an explicit `? needs` key on a job a skipped prerequisite skips
        # (or `'if': false`, or a step's `"shell": bash -n {0}`) was no key at all, and the step
        # counted. A workflow with any line outside the block subset counts for nothing.
        pre = "jobs:\n  prereq:\n    if: false\n    steps:\n      - run: true\n"
        run = "    steps:\n      - name: x\n        run: python3 bench/vf-bench/gate.py\n"
        step = "jobs:\n  gates:\n    steps:\n      - run: python3 bench/vf-bench/gate.py\n"
        for workflow in (
                pre + "  gates:\n    \"needs\": prereq\n" + run,
                pre + "  gates:\n    needs : prereq\n" + run,
                pre + "  gates:\n    ? needs\n    : prereq\n" + run,
                pre + "  gates:\n    needs: &n prereq\n" + run,
                "jobs:\n  gates:\n    'if': false\n" + run,
                "jobs:\n  gates:\n    if : false\n" + run,
                "jobs:\n  gates:\n    !!str if: false\n" + run,
                step + "        \"shell\": bash -n {0}\n",
                step + "        if : false\n",
                step + "        ? continue-on-error\n        : true\n"):
            with self.subTest(workflow=workflow):
                self.assertEqual(self.gate3(workflow), rc.FAIL)
        check = rc.check_workflows_mention(ctx_for(ROOT), "x", VF_BENCH, "x")
        self.assertEqual(check[1], rc.PASS, "the real workflows are inside the subset")

    def test_the_block_subset_is_an_allowlist(self):
        for text in ("jobs:\n  x:\n    steps:\n      -   uses: a/b@v4\n",
                     "jobs:\n  x:\n    steps:\n      - uses:\n          a/b@v4\n",
                     "jobs:\n  x:\n    steps:\n    - uses: a/b@v4\n",
                     "jobs:\n    x:\n      steps:\n        - run: echo\n",
                     "jobs:\n  x:\n    steps:\n      - - uses: a/b@v4\n",
                     "jobs:\n  x:\n    steps:\n      -\n        uses: a/b@v4\n",
                     "jobs:\n  x:\n    steps:\n      - uses: \"a/b@\n          v4\"\n",
                     "jobs:\n  x:\n    steps: [uses: a/b@v4]\n",
                     "jobs:\n  x:\n    steps: [\"uses\":a/b@v4]\n",
                     "jobs:\n  x:\n    steps:\n      - {uses: a/b@v4}\n",
                     "jobs:\n  x:\n    steps:\n      - name: a\u2028        uses: a/b@v4\n",
                     # a byte GitHub's parser refuses the whole file for, and a line break only
                     # Python's splitlines() sees: the line grammar alone accepts both
                     "jobs:\n  x:\n    steps:\n      - name: a\x00b\n",
                     "jobs:\n  x:\n    steps:\n      - name: a\x85b\n",
                     "jobs:\n  x:\n\tsteps:\n",
                     "---\njobs:\n  x:\n",
                     "jobs:\n  x:\n    steps:\n      - run: |\n          echo\n"
                     "        'uses': a/b@v4\n"):
            with self.subTest(text=text):
                self.assertTrue(rc.block_yaml_offenders(text))
        ok = ("on:\n  pull_request:\n  push:\n    branches: [main, 'release/**']\n"
              "permissions: {}\njobs:\n  x:\n    runs-on: ubuntu-latest  # c\n    steps:\n"
              "      - run: |\n          a && b {x}, y: \"$ref\" # sh\n\n          - z: 1\n"
              "      - uses: a/b@" + "c" * 40 + " # v1\n        with:\n          k: '1'\n"
              "          if: ${{ github.event_name == 'push' }}\n")
        self.assertEqual(rc.block_yaml_offenders(ok), [])

    def test_a_job_with_a_matrix_a_reusable_workflow_or_a_container_does_not_count(self):
        # PR #718 review round 3: a `strategy:` matrix can expand to no job at all (an empty
        # vector, or an exclude covering every combination), a job-level `uses:` runs another
        # workflow's jobs, and a `container:` image decides what `python3` is. No real gate-3
        # job has any of them.
        run = "    steps:\n      - name: x\n        run: python3 bench/vf-bench/gate.py\n"
        for workflow in (
                "jobs:\n  gates:\n    strategy:\n      matrix:\n        x: []\n" + run,
                "jobs:\n  gates:\n    strategy:\n      matrix:\n        x: [1]\n"
                "        exclude:\n          - x: 1\n" + run,
                "jobs:\n  gates:\n    uses: ./.github/workflows/other.yml\n" + run,
                "jobs:\n  gates:\n    container: example/python3-stub\n" + run):
            with self.subTest(workflow=workflow):
                self.assertEqual(self.gate3(workflow), rc.FAIL)

    def test_a_condition_or_a_non_failing_step_does_not_count(self):
        """PR #718 review (P2): `_NEVER_RE` knew only literal false spellings, so
        `if: ${{ 1 == 2 }}` kept a dead job counting. A counted step and its job carry no `if:`
        at all (none of the real ones does), and no `continue-on-error`."""
        run = "        run: python3 bench/vf-bench/gate.py\n"
        for workflow in (
            "jobs:\n  gates:\n    if: ${{ 1 == 2 }}\n    steps:\n      - name: x\n" + run,
            "jobs:\n  gates:\n    if: github.event_name == 'nothing'\n    steps:\n"
            "      - name: x\n" + run,
            "jobs:\n  gates:\n    steps:\n      - name: x\n        if: ${{ 1 == 2 }}\n" + run,
            "jobs:\n  gates:\n    steps:\n      - name: x\n        if: always()\n" + run,
            "jobs:\n  gates:\n    steps:\n      - name: x\n        continue-on-error: true\n" + run,
            "jobs:\n  gates:\n    continue-on-error: true\n    steps:\n      - name: x\n" + run,
        ):
            with self.subTest(workflow=workflow):
                self.assertEqual(self.gate3(workflow), rc.FAIL)

    def test_the_earlier_line_shapes_still_fail(self):
        """PR #718 review (P2): `true || python3 bench/vf-bench/gate.py` counted though the
        script never runs; so did a line inside a quoted string, a heredoc or a continuation.
        Each is more than one invocation, so each fails the one-line rule."""
        for body in (
            "          true || python3 bench/vf-bench/gate.py\n",
            "          false && python3 bench/vf-bench/gate.py\n",
            "          cd . && ./bench/vf-bench/gate.py\n",
            "          if ! python3 bench/vf-bench/gate.py; then exit 1; fi\n",
            "          echo x; python3 bench/vf-bench/gate.py\n",
            "          python3 bench/vf-bench/gate.py || true\n",
            "          echo '\n          python3 bench/vf-bench/gate.py\n          '\n",
            "          cat <<'EOF'\n          python3 bench/vf-bench/gate.py\n          EOF\n",
            "          echo \\\n          python3 bench/vf-bench/gate.py\n",
        ):
            with self.subTest(body=body):
                self.assertEqual(self.gate3(self.STEP.format(body)), rc.FAIL)
        folded = ("jobs:\n  gates:\n    steps:\n      - name: bench\n        run: >-\n"
                  "          echo\n          python3 bench/vf-bench/gate.py\n")
        self.assertEqual(self.gate3(folded), rc.FAIL, "a folded scalar is one shell line")

    def test_the_demo_check_wants_the_demo_script_itself(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = make_fixture(tmp)
            wf = root / ".github" / "workflows"
            wf.mkdir(parents=True)
            for body, want in (("echo negative-control", rc.FAIL),
                               ("sh evals/demo/negative-control/other.sh", rc.FAIL),
                               ("bash -n evals/demo/negative-control/run.sh", rc.FAIL),
                               ("sh evals/demo/negative-control/run.sh 2>&1 | tee x.txt", rc.FAIL),
                               ("sh evals/demo/negative-control/run.sh", rc.PASS)):
                with self.subTest(body=body):
                    (wf / "negative-control.yml").write_text(
                        "on:\n  pull_request:\n\njobs:\n  pinned-demo:\n    steps:\n"
                        "      - run: " + body + "\n", encoding="utf-8")
                    check = find(rc.gate3(ctx_for(root)), "gate3/ci-runs-negative-control")
                    self.assertEqual(check[1], want, check)

    def test_the_real_gate3_steps_pass_exactly_as_written(self):
        # Each real step, copied line for line from its workflow into a bare job, counts alone.
        for workflow, job, name, patterns in (
                ("validate.yml", "vfbench",
                 "VF-Bench soundness gate (verify.py false-done must be 0)", VF_BENCH),
                ("negative-control.yml", "pinned-demo",
                 "The demo runs as one command (release gate 3 reads this step)",
                 (r"^evals/demo/negative-control/run\.sh$",))):
            text = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
            steps = [step for j, step in rc.workflow_steps(text)
                     if j == job and any(ln.strip() in (f"- name: {name}", f"name: {name}")
                                         for ln in step)]
            with self.subTest(workflow=workflow):
                self.assertEqual(len(steps), 1, f"{workflow}: no step named {name!r} in {job}")
                self.assertTrue(rc.runs_on_every_pull_request(text), workflow)
                with tempfile.TemporaryDirectory() as tmp:
                    root = make_fixture(tmp)
                    wf = root / ".github" / "workflows"
                    wf.mkdir(parents=True)
                    (wf / workflow).write_text("on:\n  pull_request:\n\njobs:\n  " + job
                                               + ":\n    steps:\n" + "\n".join(steps[0]) + "\n",
                                               encoding="utf-8")
                    check = rc.check_workflows_mention(ctx_for(root), "real", patterns, "x")
                    self.assertEqual(check[1], rc.PASS, check)

    def test_the_live_workflows_run_both_checks(self):
        for patterns in (VF_BENCH, (r"negative-control",)):
            check = rc.check_workflows_mention(ctx_for(ROOT), "live", patterns, "landed")
            self.assertEqual(check[1], rc.PASS, check)


class SecurityHardening788(unittest.TestCase):
    """Regression tests for #770 + #788 hardening in release_check.py."""

    def test_ctx_py_runs_python_isolated(self):
        ctx = rc.Context(repo=ROOT)
        seen = []

        def spy(argv, timeout=rc.TIMEOUT_TOOL, memo=True):
            seen.append(list(argv))
            return rc.Result(0, "ok", "")

        ctx.run = spy
        res = ctx.py("scripts/validate.py", "--help")
        self.assertTrue(res.ok)
        self.assertEqual(seen, [[sys.executable, "-I", str(ROOT / "scripts/validate.py"), "--help"]])

    def test_workflows_mention_ignores_non_yaml_files(self):
        wf_body = ("on:\n  pull_request:\n\njobs:\n  gate:\n    steps:\n"
                   "      - run: python3 bench/vf-bench/gate.py\n")
        with tempfile.TemporaryDirectory() as tmp:
            root = make_fixture(tmp)
            wf = root / ".github" / "workflows"
            wf.mkdir(parents=True)
            for decoy in ("README.md", "notes.txt", "ci.yml.bak"):
                (wf / decoy).write_text(wf_body, encoding="utf-8")
            check = rc.check_workflows_mention(ctx_for(root), "g", VF_BENCH, "#412")
            self.assertEqual(check[1], rc.FAIL, check)
            (wf / "ci.yaml").write_text(wf_body, encoding="utf-8")
            check = rc.check_workflows_mention(ctx_for(root), "g", VF_BENCH, "#412")
            self.assertEqual(check[1], rc.PASS, check)

    def test_orca_pin_rejects_invalid_and_impossible_dates(self):
        bad_dates = ("9999-99-99", "2026-02-30", "2026-13-01", "2026-9-20", "TBD", "", 20261026)
        for bad in bad_dates:
            with self.subTest(mode="live", bad=bad), tempfile.TemporaryDirectory() as tmp:
                root = make_fixture(tmp, witness="live", witnessed="2026-09-20")
                pins = root / "runtime" / "pins.json"
                data = json.loads(pins.read_text(encoding="utf-8"))
                data["orca"]["witnessed"] = bad
                pins.write_text(json.dumps(data), encoding="utf-8")
                self.assertEqual(rc.check_orca_pin(ctx_for(root))[1], rc.FAIL)
            with self.subTest(mode="source-live-on", bad=bad), tempfile.TemporaryDirectory() as tmp:
                root = make_fixture(tmp, witness="source", witnessed="2026-09-28")
                run = "docs/runs/2026-09-20-pin-it-x.md"
                (root / run).parent.mkdir(parents=True, exist_ok=True)
                (root / run).write_text("# pin-it\n", encoding="utf-8")
                pins = root / "runtime" / "pins.json"
                data = json.loads(pins.read_text(encoding="utf-8"))
                data["orca"]["live_receipts"] = {"version": "v1.0.0", "witnessed": bad, "run": run}
                pins.write_text(json.dumps(data), encoding="utf-8")
                self.assertEqual(rc.check_orca_pin(ctx_for(root))[1], rc.FAIL)

    def test_orca_pin_rejects_non_report_live_receipt_paths(self):
        bad_runs = (
            "docs/runs/README.md",
            "docs/runs/TEMPLATE.md",
            "docs/runs/.ignore",
            "docs/runs/.hidden.md",
            "docs/runs/sub/README.md",
            "docs/runs/index/row.json",
        )
        for bad_run in bad_runs:
            with self.subTest(run=bad_run), tempfile.TemporaryDirectory() as tmp:
                root = make_fixture(tmp, witness="source", witnessed="2026-09-28")
                target = root / bad_run
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("not a run report\n", encoding="utf-8")
                pins = root / "runtime" / "pins.json"
                data = json.loads(pins.read_text(encoding="utf-8"))
                data["orca"]["live_receipts"] = {
                    "version": "v1.0.0", "witnessed": "2026-09-20", "run": bad_run,
                }
                pins.write_text(json.dumps(data), encoding="utf-8")
                self.assertEqual(rc.check_orca_pin(ctx_for(root))[1], rc.FAIL)


if __name__ == "__main__":
    unittest.main()
