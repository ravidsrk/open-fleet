#!/usr/bin/env python3
"""Provider/harness certification and the reproducible first run (#596).

The local certification subset CI runs without paid agents:

  - the record (`runtime/providers/certification.json`) validates, covers every advertised
    cell exactly once, and refuses a live-witnessed claim no bound run report backs;
  - a pin refresh voids the provider's cells (they read `stale`) until they are rechecked;
  - every `unsupported` cell is refused before a launch by the code that owns it, and every
    other cell gets past those refusals — the record cannot drift from the adapters;
  - `first_run.py` drives create -> dispatch -> delivery -> result -> independent verify ->
    retain/release through the public wrappers on the posix route, for every posix harness
    name, with an inert stand-in (setsid only; tripwires shadow every real harness);
  - the five negative probes refuse before a launch, and a probe whose guard is removed sees it.

No test here starts tmux or reaches a real agent: every subprocess runs with SHELL=/bin/sh and
a tripwire for each harness name first on PATH, and the tripwire log must stay empty.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import copy
import hashlib
import importlib
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "runtime" / "scripts"
RECORD = ROOT / "runtime" / "providers" / "certification.json"
CAPS = json.loads((ROOT / "runtime" / "providers" / "capabilities.json").read_text(encoding="utf-8"))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

base = importlib.import_module("runtime.providers.base")
LocalStateStore = importlib.import_module("runtime.providers.local_state").LocalStateStore
ProviderError = base.ProviderError


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


certification = _load("certification_under_test", SCRIPTS / "certification.py")
first_run = _load("first_run_under_test", SCRIPTS / "first_run.py")
TABLES = _load("fixture_containment_tables", ROOT / "tests" / "fixtures" / "containment_tables.py")  # PR #668
# The live tier's refusal (PR #668: disabled outside the container-based live harness). The live
# first-run tests drive the live machinery, so setUpModule lifts it in this process, the Python-level
# seam the host probe uses; TestTheLiveTierIsDisabled puts the real one back, and runs the CLI as its
# own process too.
REAL_LIVE_GATE = first_run.containment.live_disabled
DISABLED = "live runs are disabled outside the container-based live harness"
SEAMS: dict = {}


def setUpModule():
    SEAMS["live"] = mock.patch.object(first_run.containment, "live_disabled", lambda: None)
    SEAMS["live"].start()


def tearDownModule():
    SEAMS["live"].stop()


LEAKY = ("ORCA_CLI_COMMAND", "OPEN_FLEET_CLI_COMMAND", "OPEN_FLEET_RUNTIME", "ORCA_FLEET_RUNTIME",
         "OPEN_FLEET_STATE_DB", "OPEN_FLEET_STATE_DIR", "OPEN_FLEET_SANDBOX_PROFILE", "ORCA_SANDBOX_PROFILE",
         "OPEN_FLEET_PARENT_PROFILE", "ORCA_PARENT_PROFILE", "WORKER_CMD", "CLAUDE_CMD", "CODEX_CMD",
         "ORCA_TERMINAL_HANDLE", "OPEN_FLEET_TERMINAL_HANDLE", "OPEN_FLEET_DENY_HOOK_SETTINGS",
         "ORCA_DENY_HOOK_SETTINGS", "OPEN_FLEET_POSIX_BACKEND", "ORCA_POSIX_BACKEND")


def cert_main(*args):
    """certification.main() in-process: (rc, stdout, stderr) without an interpreter start."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = certification.main(list(args))
    return subprocess.CompletedProcess(args, rc, out.getvalue(), err.getvalue())


class Tripwired(unittest.TestCase):
    """A tripwire for every harness name first on PATH; no test may ever reach one."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="of-cert-")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.trip = self.tmp / "tripwire"
        self.trip.mkdir()
        self.trip_log = self.tmp / "tripwire.log"
        for name in first_run.all_harness_binaries():
            path = self.trip / name
            path.write_text(f'#!/bin/sh\necho "{name} $*" >> "{self.trip_log}"\nexit 97\n', encoding="utf-8")
            path.chmod(0o755)
        env = {k: v for k, v in os.environ.items() if k not in LEAKY}
        env["PATH"] = os.pathsep.join([str(self.trip), os.path.dirname(sys.executable), env.get("PATH", "")])
        env["SHELL"] = "/bin/sh"
        self.env = env
        self.addCleanup(self._no_tripwire_hit)

    def _no_tripwire_hit(self):
        hits = self.trip_log.read_text() if self.trip_log.exists() else ""
        self.assertEqual(hits, "", f"something resolved a real harness name: {hits!r}")

    def run_py(self, script, *args, env=None, cwd=None, timeout=300):
        return subprocess.run([sys.executable, str(SCRIPTS / script), *args], env={**self.env, **(env or {})},
                              cwd=str(cwd or ROOT), capture_output=True, text=True, timeout=timeout)


# --- the record -----------------------------------------------------------------------------

class TestRecordValidates(Tripwired):
    def check(self, *args):
        return cert_main("check", *args)

    def mutated(self, fn):
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        fn(record)
        path = self.tmp / "record.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        return ["--record", str(path)]

    def test_the_shipped_record_is_valid_and_fresh(self):
        p = self.run_py("certification.py", "check")  # the CLI itself, as CI and an operator run it
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("certification: OK", p.stdout)

    def test_every_advertised_cell_is_classified_exactly_once(self):
        errors, _stale, cells = certification.validate(ROOT)
        self.assertEqual(errors, [])
        want = {("provider", name, p, h) for name, entry in CAPS["providers"].items()
                for p in entry["supported_profiles"] for h in entry["supported_harnesses"]}
        want |= {("harness", h, p, h) for h in base.SUPPORTED_HARNESSES for p in ("ro", "rw")}
        got = [(c["kind"], c["name"], c["profile"], c["harness"]) for c in cells]
        self.assertEqual(len(got), len(set(got)), "a cell is classified twice")
        self.assertEqual(set(got), want)

    def test_only_bound_run_reports_carry_live_witnessed(self):
        _errors, _stale, cells = certification.validate(ROOT)
        live = {(c["name"], c["profile"], c["harness"]) for c in cells if c["tier"] == "live-witnessed"}
        self.assertEqual(live, {("orca", "ro", "claude"), ("orca", "rw", "claude"), ("posix", "ro", "claude"), ("posix", "rw", "claude"), ("claude", "ro", "claude"), ("claude", "rw", "claude")})
        unknown = [c for c in cells if c["kind"] == "provider" and c["name"] not in ("orca", "posix")]
        self.assertTrue(unknown and all(certification.version_label(c["upstream"]) == "unknown" for c in unknown),
                        "an external adapter's upstream version was never recorded: it must read unknown")

    def test_a_fixture_cell_relabelled_live_is_refused(self):
        def relabel(rec):
            rec["providers"]["posix"]["routes"][0]["tier"] = "live-witnessed"
        p = self.check(*self.mutated(relabel))
        self.assertEqual(p.returncode, 1)
        self.assertIn("live-witnessed needs `witnessed`", p.stderr)
        self.assertIn("without a binding run report", p.stderr)

    def test_a_live_claim_on_an_unbound_report_is_refused(self):
        def rebind(rec):
            group = rec["providers"]["orca"]["routes"][0]
            group["evidence"] = ["docs/runs/2026-10-12-pin-it-224.md"]  # receipts, not a GREEN proof report
        p = self.check(*self.mutated(rebind))
        self.assertEqual(p.returncode, 1)
        self.assertIn("without a binding run report", p.stderr)

    def test_a_dropped_doubled_or_unadvertised_cell_is_refused(self):
        cases = {
            "dropped": (lambda rec: rec["providers"]["ao"]["routes"][0]["harnesses"].remove("droid"),
                        "advertised route rw/droid is not classified"),
            "doubled": (lambda rec: rec["providers"]["ao"]["routes"].append(
                copy.deepcopy(rec["providers"]["ao"]["routes"][0])), "already classified"),
            "unadvertised": (lambda rec: rec["providers"]["ao"]["routes"][0]["profiles"].append("ro"),
                             "is not an advertised provider route"),
        }
        for name, (fn, needle) in cases.items():
            with self.subTest(case=name):
                p = self.check(*self.mutated(fn))
                self.assertEqual(p.returncode, 1)
                self.assertIn(needle, p.stderr)

    def test_dangling_evidence_and_missing_refusals_are_refused(self):
        cases = {
            "missing file": (lambda rec: rec["providers"]["ao"]["routes"][0]["evidence"].append("tests/no_such_test.py"),
                             "does not exist"),
            "missing symbol": (lambda rec: rec["providers"]["ao"]["routes"][0]["evidence"].append(
                "tests/test_certification.py::NoSuchClass"), "defines no class/def NoSuchClass"),
            "no refusal": (lambda rec: rec["providers"]["paperclip"]["routes"][0].pop("refusal"),
                           "unsupported needs the typed `refusal`"),
            "no limitation": (lambda rec: rec["providers"]["ao"]["routes"][0].update(limitations=[]),
                              "limitations must be a non-empty list"),
        }
        for name, (fn, needle) in cases.items():
            with self.subTest(case=name):
                p = self.check(*self.mutated(fn))
                self.assertEqual(p.returncode, 1)
                self.assertIn(needle, p.stderr)


def moved(version: str) -> str:
    """The release after `version` (its last number bumped), so a moved pin differs from whatever
    runtime/pins.json pins today: a literal next release turns into a no-op the day it is pinned."""
    bumped = re.sub(r"\d+$", lambda m: str(int(m[0]) + 1), version)
    return bumped if bumped != version else f"{version}.1"


class TestPinRefreshInvalidatesCells(Tripwired):
    """Refreshing a provider version voids its cells until a maintainer rechecks them."""

    def pins(self, mutate=None):
        pins = json.loads((ROOT / "runtime" / "pins.json").read_text(encoding="utf-8"))
        if mutate:
            mutate(pins["orca"])
        path = self.tmp / "pins.json"
        path.write_text(json.dumps(pins), encoding="utf-8")
        return path

    def matrix(self, *args):
        p = cert_main("matrix", "--json", *args)
        return p, {(r["name"], r["profile"], r["harness"]): r["effective"] for r in json.loads(p.stdout)
                   if r["kind"] == "provider"}

    def test_an_unchanged_pin_keeps_every_cell_fresh(self):
        p, cells = self.matrix("--pins", str(self.pins()))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(cells[("orca", "ro", "claude")], "live-witnessed")

    def test_a_new_pin_turns_every_orca_cell_stale(self):
        for name, mutate in {
            "commit": lambda e: e.update(commit="f" * 40),
            "version": lambda e: e.update(version=moved(e["version"])),
            "live receipts": lambda e: e["live_receipts"].update(version=moved(e["live_receipts"]["version"])),
        }.items():
            with self.subTest(moved=name):
                pins = self.pins(mutate)
                check = cert_main("check", "--pins", str(pins))
                self.assertEqual(check.returncode, 1)
                self.assertIn("STALE provider orca", check.stderr)
                _p, cells = self.matrix("--pins", str(pins))
                orca = {k: v for k, v in cells.items() if k[0] == "orca"}
                self.assertEqual(set(orca.values()), {"stale"}, "a cell kept its tier after the pin moved")
                self.assertEqual(cells[("posix", "ro", "claude")], "live-witnessed", "staleness is per provider")

    def test_rechecking_and_re_recording_makes_the_cells_fresh_again(self):
        pins = self.pins(lambda e: e.update(commit="e" * 40, version=moved(e["version"])))
        new = json.loads(pins.read_text(encoding="utf-8"))["orca"]
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        record["providers"]["orca"]["certified_against"].update(commit=new["commit"], version=new["version"])
        rec_path = self.tmp / "record.json"
        rec_path.write_text(json.dumps(record), encoding="utf-8")
        p = cert_main("check", "--pins", str(pins), "--record", str(rec_path))
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_the_cli_exits_nonzero_on_a_stale_pin(self):
        p = self.run_py("certification.py", "check", "--pins", str(self.pins(lambda e: e.update(version="v9.9.9"))))
        self.assertEqual(p.returncode, 1)
        self.assertIn("STALE provider orca", p.stderr)


# --- the record against the code that owns each cell ------------------------------------------

class Reached(Exception):
    """The adapter got past every pre-launch refusal to its first upstream call."""


def _reach(*args, **_kw):
    raise Reached(args)


class TestAdapterRefusalsMatchTheRecord(Tripwired):
    """An `unsupported` cell is refused with its recorded code before any upstream call; any
    other cell gets past the refusals to the upstream boundary."""

    def adapter(self, name):
        def m(mod):
            return importlib.import_module(f"runtime.providers.{mod}")

        state = LocalStateStore(db_path=self.tmp / f"{name}.db")
        wt = self.tmp / f"wt-{name}"
        wt.mkdir(exist_ok=True)
        def hooks(*_a, **_k):
            return {}

        table = {
            "overstory": (lambda: m("overstory").OverstoryProvider(state=state, runner=_reach), {}),
            "t3code": (lambda: m("t3code").T3CodeProvider(state=state, runner=_reach, project_id="p", git_runner=_reach,
                                                         install_hooks=hooks), {}),
            "ao": (lambda: m("ao").ComposioAOProvider(state=state, runner=_reach, project="p1"), {}),
            "superset": (lambda: m("superset").SupersetProvider(
                state=state, runner=_reach, install_hooks=hooks, env={"OPEN_FLEET_SUPERSET_PROJECT": "p"}), {}),
            "gastown": (lambda: m("gastown").GastownProvider(state=state, runner=_reach, rig="r", install_hooks=hooks), {}),
            "worktrunk": (lambda: m("worktrunk").WorktrunkProvider(state=state, runner=_reach, install_hooks=hooks), {}),
            "jcode-swarm": (lambda: m("jcode_swarm").JCodeSwarmProvider(
                state=state, runner=_reach, coordinator_session="coord"), {"worktree": str(wt)}),
            "emdash": (lambda: m("emdash").EmdashProvider(state=state, runner=_reach, git_runner=_reach,
                                                         env={"OPEN_FLEET_EMDASH_REPOSITORY_ID": "r"}), {"base": "main"}),
            "vibe-kanban": (lambda: m("vibe_kanban").VibeKanbanProvider(
                state=state, runner=_reach,
                env={"OPEN_FLEET_VIBE_KANBAN_REPO_ID": "r1", "OPEN_FLEET_VIBE_KANBAN_TARGET_BRANCH": "main"}), {}),
            "paperclip": (lambda: m("paperclip").PaperclipProvider(state=state, runner=_reach, company_id="co"),
                          {"worktree": str(wt)}),
            "multiclaude": (lambda: self._multiclaude(state), {"name": "mc"}),
            "openhands": (lambda: m("openhands").OpenHandsProvider(
                state=state, runner=_reach, env={"OPEN_FLEET_OPENHANDS_MODEL": "m"}), {}),
        }
        make, extra = table[name]
        return make(), extra

    def _multiclaude(self, state):
        home = self.tmp / "mch"
        (home / "repos" / "proj").mkdir(parents=True, exist_ok=True)
        mod = importlib.import_module("runtime.providers.multiclaude")
        return mod.MulticlaudeProvider(state=state, runner=_reach, home=home, repo="proj")

    def test_external_adapters_refuse_exactly_the_unsupported_cells(self):
        _errors, _stale, cells = certification.validate(ROOT)
        external = [c for c in cells if c["kind"] == "provider" and c["name"] not in ("orca", "posix")]
        self.assertGreater(len(external), 100)
        for cell in external:
            with self.subTest(provider=cell["name"], profile=cell["profile"], harness=cell["harness"]):
                prov, extra = self.adapter(cell["name"])
                if cell["name"] == "gastown" and cell["profile"] == "ro":
                    # gastown registers a ro gt alias after `bd create` and before `gt sling` (the
                    # launch): the alias builder is where a ro cell is refused.
                    if cell["tier"] == "unsupported":
                        with self.assertRaises(ProviderError) as ctx:
                            prov._ro_alias_command(cell["harness"])
                        self.assertEqual(ctx.exception.code, cell["refusal"])
                    else:
                        self.assertTrue(prov._ro_alias_command(cell["harness"]))
                    continue
                kwargs = dict(task_id="t", agent=cell["harness"], profile=cell["profile"], prompt="x", **extra)
                if cell["tier"] == "unsupported":
                    with self.assertRaises(ProviderError) as ctx:
                        prov.worker_start(**kwargs)
                    self.assertEqual(ctx.exception.code, cell["refusal"])
                else:
                    with self.assertRaises(Reached):
                        prov.worker_start(**kwargs)

    def test_posix_refuses_hermes_danger_and_frees_the_task(self):
        repo = self.tmp / "repo"
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@e", "-c", "user.name=t", "-c", "commit.gpgsign=false",
                        "commit", "-q", "--allow-empty", "-m", "i"], check=True)
        env = {**self.env, "OPEN_FLEET_STATE_DB": str(self.tmp / "s" / "r.db"), "OPEN_FLEET_POSIX_BACKEND": "dry-run",
               "OPEN_FLEET_CLI_CWD": str(repo)}
        providers = importlib.import_module("runtime.providers")
        _errors, _stale, cells = certification.validate(ROOT)
        danger = [c for c in cells if c["name"] == "posix" and c["profile"] == "danger"]
        self.assertEqual(len(danger), len(CAPS["providers"]["posix"]["supported_harnesses"]))
        for cell in danger:
            with self.subTest(harness=cell["harness"]):
                prov = providers.get_provider("posix", env=env)
                task = prov.dispatch(["orchestration", "task-create", "--spec", f"danger {cell['harness']}"])["task"]
                kwargs = dict(task_id=task["id"], worktree="new-child", agent=cell["harness"], profile="danger",
                              on_env="img", name=f"d-{cell['harness']}")
                if cell["tier"] == "unsupported":
                    with self.assertRaises(ProviderError) as ctx:
                        prov.worker_start(**kwargs)
                    self.assertEqual(ctx.exception.code, cell["refusal"])
                    self.assertEqual(prov.worker_list(task=task["id"])["workers"], [], "nothing was dispatched")
                    status = {t["id"]: t["status"] for t in prov.task_list()["tasks"]}
                    self.assertEqual(status[task["id"]], "ready", "a refused start must hand the task back")
                else:
                    res = prov.worker_start(**kwargs)  # dry-run backend: composed, never executed
                    self.assertIn("docker run", res["launch"]["effective"]["command"])


class TestOrcaRouteCellsMatchTheWrapper(Tripwired):
    """On Orca the fleet's wrapper is spawn_worker.sh: each orca cell is accepted or refused there
    exactly as the record says (SW_PRINT_LAUNCH stops before any orchestration side effect)."""

    def stub(self):
        doctor = {"ok": True, "result": {
            "recipeId": "lane-7", "backend": "docker", "ok": True, "ephemeral": True, "credential_mounts": [],
            "prelaunch_placement_bound": True, "checks": [{"id": "isolation-flags", "status": "pass"}],
            "isolation": {"capDrop": ["ALL"], "noNewPrivileges": True, "pidsLimit": 512, "privileged": False,
                          "network": "bridge"}, "mounts": [], "failures": [], "warnings": []}}
        (self.tmp / "doctor.json").write_text(json.dumps(doctor), encoding="utf-8")
        stub = self.tmp / "orca"
        stub.write_text(f"""#!/bin/sh
echo "$*" >> "{self.tmp}/orca-calls.log"
case "$*" in *"recipe doctor"*) cat "{self.tmp}/doctor.json" ;; *) echo '{{"result": {{}}}}' ;; esac
""", encoding="utf-8")
        stub.chmod(0o755)
        return stub

    def spawn(self, stub, cell):
        env = {"ORCA_CLI_COMMAND": str(stub), "SW_PRINT_LAUNCH": "1", "PROFILE": cell["profile"], "SP": str(self.tmp),
               "ORCA_COORD_ALLOW_AUTONOMOUS_WRITE": "1"}
        if cell["profile"] == "danger":
            env.update(ORCA_COORD_ALLOW_DANGER="1", ORCA_SANDBOX_RECIPE="lane-7")
        return subprocess.run(["bash", str(SCRIPTS / "spawn_worker.sh"), "task_x", "new-child", "t", cell["harness"]],
                              env={**self.env, **env}, cwd=str(self.tmp), capture_output=True, text=True, timeout=120)

    def test_every_orca_cell_is_accepted_or_refused_as_recorded(self):
        stub = self.stub()
        _errors, _stale, cells = certification.validate(ROOT)
        orca = [c for c in cells if c["name"] == "orca"]
        self.assertEqual(len(orca), 3 * len(CAPS["providers"]["orca"]["supported_harnesses"]))
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda c: (c, self.spawn(stub, c)), orca))
        for cell, p in results:
            with self.subTest(profile=cell["profile"], harness=cell["harness"]):
                if cell["tier"] == "unsupported":
                    self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                    self.assertIn(cell["refusal"], p.stderr)
                    self.assertNotIn("LAUNCH=", p.stdout)
                else:
                    self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                    self.assertIn("LAUNCH=", p.stdout)
        calls = (self.tmp / "orca-calls.log").read_text() if (self.tmp / "orca-calls.log").exists() else ""
        for verb in ("worker-start", "terminal create", "task-create", "--inject"):
            self.assertNotIn(verb, calls, "a refusal or a printed launch must precede every side effect")


class TestHarnessCellsMatchTheLaunchTable(unittest.TestCase):
    def test_each_harness_cell_builds_or_refuses_as_recorded(self):
        _errors, _stale, cells = certification.validate(ROOT)
        harness = [c for c in cells if c["kind"] == "harness"]
        with tempfile.TemporaryDirectory() as wt:
            for cell in harness:
                with self.subTest(harness=cell["harness"], profile=cell["profile"]):
                    if cell["tier"] == "unsupported":
                        with self.assertRaises(ProviderError) as ctx:
                            base.build_harness_command(cell["harness"], cell["profile"], wt, prompt="TASK-SENTINEL")
                        self.assertEqual(ctx.exception.code, cell["refusal"])
                    else:
                        launch = base.build_harness_command(cell["harness"], cell["profile"], wt, prompt="TASK-SENTINEL")
                        self.assertIn("TASK-SENTINEL", launch["argv"], "the task must ride the launch argv")


# --- the first run ----------------------------------------------------------------------------

class TestFirstRunRangeIsRevisionsNotOptions(Tripwired):
    """W2-04: `--base`/`--head` reach `rev-parse --verify <rev>^{commit}` and `git diff <base>
    <head>` in option position; `--base=--show-toplevel` is refused as an option before git."""

    def test_an_option_shaped_end_is_refused_before_git_reads_it(self):
        for base_rev, head_rev in (("--show-toplevel", "HEAD"), ("HEAD~1", "--all"), ("-h", "HEAD")):
            with self.subTest(base=base_rev, head=head_rev):
                work = Path(tempfile.mkdtemp(dir=self.tmp))
                sandbox = argparse.Namespace(target=work / "target", dir=work,
                                             env={**self.env, "GIT_CONFIG_GLOBAL": os.devnull,
                                                  "GIT_CONFIG_NOSYSTEM": "1"})
                args = argparse.Namespace(target=None, base=base_rev, head=head_rev)
                fr = first_run.FirstRun(args, sandbox)
                with self.assertRaises(first_run.StepFailed) as ctx:
                    fr.target()
                self.assertIn("not an option", str(ctx.exception))
                self.assertFalse([c for c in fr.rec.commands if "rev-parse" in c["argv"]],
                                 "the option reached git")


class TestFirstRunFixture(Tripwired):
    STEPS = ["prereqs", "target", "preflight", "create", "dispatch", "guard", "delivery", "result",
             "evidence", "verify", "release", "isolation"]

    def first_run(self, *args, workdir=None):
        wd = workdir or self.tmp / "fr"
        p = self.run_py("first_run.py", *args, "--workdir", str(wd), "--json", timeout=600)
        try:
            receipt = json.loads(p.stdout)
        except ValueError:
            self.fail(f"no receipt: rc={p.returncode}\n{p.stdout}\n{p.stderr}")
        return p, receipt

    def assert_go(self, p, receipt):
        self.assertEqual(p.returncode, 0, json.dumps(receipt.get("failure"), indent=1))
        self.assertEqual(receipt["verdict"], "GO")
        self.assertEqual([s["step"] for s in receipt["steps"]], self.STEPS)
        self.assertTrue(all(s["ok"] for s in receipt["steps"]))
        self.assertEqual(receipt["tier"], "fixture-tested", "an inert run is never labelled live")
        facts = receipt["facts"]
        self.assertRegex(facts["evidence"]["head_sha"], r"^[0-9a-f]{40}$")
        self.assertNotEqual(facts["evidence"]["head_sha"], facts["evidence"]["base_sha"])
        self.assertEqual(facts["verify"]["rc"], 0)
        self.assertIn("verify: OK", "\n".join(facts["verify"]["out"]))
        self.assertTrue(all(isinstance(s["elapsed_s"], float) for s in receipt["steps"]))

    def test_ro_review_unit_is_go_through_the_public_wrappers(self):
        p, receipt = self.first_run("--profile", "ro")
        self.assert_go(p, receipt)
        wrappers = {Path(c["argv"][1]).name for c in receipt["commands"] if len(c["argv"]) > 1}
        for script in ("task_ops.py", "spawn_worker.sh", "worker_ops.py", "check_reply.py", "verify.py",
                       "preflight.py"):
            self.assertIn(script, wrappers, f"{script} never ran: the lifecycle bypassed the public wrapper")
        self.assertIn("--permission-mode plan", receipt["facts"]["launch_effective"]["command"])
        self.assertTrue(receipt.get("sandbox_pruned"), "a GO prunes the sandbox down to its receipt")

    def test_rw_unit_commits_its_report_and_the_commit_survives_release(self):
        p, receipt = self.first_run("--profile", "rw")
        self.assert_go(p, receipt)
        facts = receipt["facts"]
        self.assertEqual(facts["worker_claim"]["head"], facts["evidence"]["head_sha"])

    def test_every_posix_harness_runs_the_whole_route(self):
        cells = [(h, p) for h in CAPS["providers"]["posix"]["supported_harnesses"] for p in ("ro", "rw")
                 if h != "claude"]

        def one(cell):
            h, prof = cell
            return cell, self.first_run("--agent", h, "--profile", prof, workdir=self.tmp / f"fr-{h}-{prof}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(one, cells))
        for (h, prof), (p, receipt) in results:
            with self.subTest(harness=h, profile=prof):
                self.assert_go(p, receipt)
                self.assertEqual(receipt["route"]["harness"], h)
                if prof == "ro":  # #596: the relay finds the completion line in every output shape
                    self.assertEqual(receipt["facts"]["settled"], {"state": "completed", "signal": "worker_done"})

    def in_process(self, *args):
        """first_run.main() in this process, so a test can mutate what it binds."""
        buf = io.StringIO()
        clean = {k: v for k, v in self.env.items()}
        with mock.patch.dict(os.environ, clean, clear=True), contextlib.redirect_stdout(buf):
            rc = first_run.main([*args, "--workdir", str(self.tmp / "inproc"), "--json"])
        return rc, json.loads(buf.getvalue())

    def test_verify_goes_red_when_the_manifest_binds_the_wrong_sha(self):
        real = first_run.write_manifest

        def bind_the_base(path, manifest):
            real(path, {**manifest, "head_sha": manifest["base_sha"]})

        with mock.patch.object(first_run, "write_manifest", bind_the_base):
            rc, receipt = self.in_process("--profile", "ro")
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["verdict"], "NO-GO")
        self.assertEqual(receipt["failure"]["step"], "verify")
        self.assertIn("base_sha == head_sha", receipt["failure"]["detail"])

    def test_a_worker_that_ignores_its_spec_is_no_go(self):
        deaf = first_run.INERT_WORKER.replace(
            'report = f"FIRST-RUN-REPORT {m.group(1)} {m.group(2)}\\n"', 'report = "I reviewed something\\n"')
        self.assertNotEqual(deaf, first_run.INERT_WORKER, "the mutant must change the stand-in")
        with mock.patch.object(first_run, "INERT_WORKER", deaf):
            rc, receipt = self.in_process("--profile", "ro")
        self.assertEqual((rc, receipt["failure"]["step"]), (1, "result"))
        self.assertIn("report does not open with", receipt["failure"]["detail"])

    def test_a_worker_claim_that_git_contradicts_is_no_go(self):
        liar = first_run.INERT_WORKER.replace('{"head": head, "report": rel}', '{"head": "f" * 40, "report": rel}')
        self.assertNotEqual(liar, first_run.INERT_WORKER, "the mutant must change the stand-in")
        with mock.patch.object(first_run, "INERT_WORKER", liar):
            rc, receipt = self.in_process("--profile", "rw")
        self.assertEqual((rc, receipt["failure"]["step"]), (1, "evidence"))
        self.assertIn("the claim is not evidence", receipt["failure"]["recovery"])

    # The stand-in reads the completion line its ro assignment names, as a compliant model would.
    FOOTER = 'done = re.search(r"OPEN_FLEET_WORKER_DONE (disp_[0-9a-f]+) <outcome>", spec)'

    def test_a_ro_worker_that_reports_completion_settles_completed_and_is_go(self):
        # #596 follow-up: posix relays a ro worker's completion line as its worker_done, so a ro
        # unit may now settle `completed`; the run must take that as the worker's own report.
        rc, receipt = self.in_process("--profile", "ro")
        self.assertEqual(rc, 0, json.dumps(receipt.get("failure"), indent=1))
        self.assertEqual(receipt["facts"]["settled"], {"state": "completed", "signal": "worker_done"})

    def test_a_ro_worker_deaf_to_the_footer_is_still_go_on_a_clean_death(self):
        self.assertIn(self.FOOTER, first_run.INERT_WORKER)
        deaf = first_run.INERT_WORKER.replace(self.FOOTER, "done = None")
        with mock.patch.object(first_run, "INERT_WORKER", deaf):
            rc, receipt = self.in_process("--profile", "ro")
        self.assertEqual(rc, 0, json.dumps(receipt.get("failure"), indent=1))
        self.assertEqual(receipt["facts"]["settled"], {"state": "died", "signal": "worker_died"})

    def test_a_ro_worker_that_reports_failure_is_no_go(self):
        failed = first_run.INERT_WORKER.replace("{done.group(1)} succeeded", "{done.group(1)} failed")
        self.assertNotEqual(failed, first_run.INERT_WORKER, "the mutant must change the stand-in")
        with mock.patch.object(first_run, "INERT_WORKER", failed):
            rc, receipt = self.in_process("--profile", "ro")
        self.assertEqual((rc, receipt["failure"]["step"]), (1, "result"))
        self.assertIn("reported failed", receipt["failure"]["detail"])

    def test_live_mode_without_the_harness_stops_at_prerequisites(self):
        bare = os.pathsep.join([os.path.dirname(sys.executable), "/usr/bin", "/bin"])
        agent = next((h for h in CAPS["providers"]["posix"]["supported_harnesses"]
                      if not shutil.which(first_run.HARNESS_BINARIES.get(h, h), path=bare)), None)
        self.assertIsNotNone(agent, "every posix harness is installed system-wide; nothing safe to probe")
        # A proven host injected at the Python level: this test is about prerequisites, not this
        # machine's process table (PR #668 review: the strong probe refuses a live run on macOS).
        boot = TABLES.proven_host(sys.executable, SCRIPTS / "first_run.py", "mod.containment.containment_problem = proven; "
                                  "mod.containment.live_disabled = lifted")
        p = subprocess.run([*boot, "--worker", "live", "--agent", agent, "--workdir", str(self.tmp / "live"), "--json"],
                           env={**self.env, "PATH": bare}, cwd=str(ROOT), capture_output=True, text=True, timeout=300)
        receipt = json.loads(p.stdout)
        self.assertEqual(p.returncode, 1)
        self.assertEqual(receipt["tier"], "live-unreviewed")
        self.assertEqual(receipt["failure"]["step"], "prereqs")
        self.assertEqual([s["step"] for s in receipt["steps"]], ["prereqs"], "nothing ran after the refusal")


class TestTheOnHostSandboxHoldsNoCredential(Tripwired):
    """W5-20 (2026-10-27 audit): the on-host Sandbox handed its wrappers and the worker
    `{**os.environ, ...}`, so a CLAUDE_CODE_OAUTH_TOKEN / ANTHROPIC_API_KEY / GH_TOKEN exported on
    the operator's host reached every command the worker ran, while the container lane
    (scripts/live_container.py) deliberately holds none. The environment is an allowlist now."""

    SECRETS = {"ANTHROPIC_API_KEY": "sk-ant-x", "CLAUDE_CODE_OAUTH_TOKEN": "oat-x", "GH_TOKEN": "ghp-x",
               "GITHUB_TOKEN": "ghs-x", "AWS_SECRET_ACCESS_KEY": "aws-x", "AWS_SESSION_TOKEN": "aws-s",
               "OPENAI_API_KEY": "sk-x", "SOME_VENDOR_PASSWORD": "pw", "HTTPS_PROXY": "http://u:p@proxy",
               # re-attack of W5-20: an LC_ PREFIX allowlisted any name
               "LC_GH_TOKEN": "ghp-lc", "LC_ANTHROPIC_API_KEY": "sk-ant-lc"}

    def sandbox(self, worker):
        env = dict(self.env, **self.SECRETS, LANG="C.UTF-8", LC_ALL="C.UTF-8", TZ="UTC",
                   DISABLE_AUTOUPDATER="1", HOME="/home/operator")
        with mock.patch.dict(os.environ, env, clear=True):
            return first_run.Sandbox(self.tmp / f"sb-{worker}", worker, "claude")

    def test_no_operator_credential_reaches_the_sandbox_environment(self):
        for worker in ("inert", "live"):
            with self.subTest(worker=worker):
                sb = self.sandbox(worker)
                self.assertEqual(sorted(set(sb.env) & set(self.SECRETS)), [])
                for kept in ("LANG", "LC_ALL", "TZ", "PATH", "SHELL", "OPEN_FLEET_RUNTIME",
                             first_run.containment.CALL_MARKER):
                    self.assertIn(kept, sb.env)

    def test_live_keeps_exactly_what_its_harness_needs(self):
        # --worker live runs the live harness's claude wrapper, which takes its credential from the
        # broker, never from this environment: it needs the container's HOME and its updater pin.
        live, inert = self.sandbox("live"), self.sandbox("inert")
        self.assertEqual(live.env["HOME"], "/home/operator")
        self.assertEqual(live.env["DISABLE_AUTOUPDATER"], "1")
        self.assertEqual(inert.env["HOME"], str(inert.home))

    def test_the_worker_process_itself_sees_no_credential(self):
        probe = first_run.INERT_WORKER.replace(
            'harness, argv = sys.argv[1], sys.argv[2:]\n',
            'harness, argv = sys.argv[1], sys.argv[2:]\n'
            '(Path(sys.argv[0]).resolve().parent / "env-keys.json").write_text(json.dumps(sorted(os.environ)))\n')
        self.assertNotEqual(probe, first_run.INERT_WORKER, "the probe must change the stand-in")
        buf = io.StringIO()
        with mock.patch.object(first_run, "INERT_WORKER", probe), \
                mock.patch.dict(os.environ, dict(self.env, **self.SECRETS), clear=True), \
                contextlib.redirect_stdout(buf):
            rc = first_run.main(["--profile", "ro", "--workdir", str(self.tmp / "run"), "--keep", "--json"])
        receipt = json.loads(buf.getvalue())
        self.assertEqual(rc, 0, json.dumps(receipt.get("failure"), indent=1))
        seen = json.loads((self.tmp / "run" / "inert" / "env-keys.json").read_text())
        self.assertIn("OPEN_FLEET_DISPATCH_ID", seen, "the probe did not run as the worker")
        self.assertEqual(sorted(set(seen) & set(self.SECRETS)), [])


class TestNegativeProbes(Tripwired):
    REQUIRED = {"unsupported-profile", "privilege-escalation", "unarmed-deny-hook",
                "malformed-upstream-response", "missing-capability"}

    def test_every_probe_refuses_before_a_launch(self):
        p = self.run_py("first_run.py", "probes", "--workdir", str(self.tmp / "probes"), "--json")
        receipt = json.loads(p.stdout)
        self.assertEqual(p.returncode, 0, json.dumps(receipt["probes"], indent=1))
        self.assertEqual({r["probe"] for r in receipt["probes"]}, self.REQUIRED)
        for r in receipt["probes"]:
            with self.subTest(probe=r["probe"]):
                self.assertTrue(r["refused"], r["problems"])
                self.assertTrue(r["evidence"], "the refusal text must be on record")

    def test_a_probe_whose_guard_trigger_is_removed_sees_the_launch(self):
        # The detectors are not vacuous: privilege-escalation WITHOUT the ro parent launches,
        # and the same checks that pass the real probes report it.
        real = first_run.probe_table

        def with_control(sb, unarmed, garbage):
            table = real(sb, unarmed, garbage)
            name, why, argv, env, rc, text = next(t for t in table if t[0] == "privilege-escalation")
            control = {k: v for k, v in env.items() if k != "OPEN_FLEET_PARENT_PROFILE"}
            return table + [("control-no-parent", why, argv, control, rc, text)]

        buf = io.StringIO()
        with mock.patch.object(first_run, "probe_table", with_control), \
                mock.patch.dict(os.environ, dict(self.env), clear=True), contextlib.redirect_stdout(buf):
            rc = first_run.main(["probes", "--workdir", str(self.tmp / "ctl"), "--json"])
        receipt = json.loads(buf.getvalue())
        self.assertEqual(rc, 1)
        control = next(r for r in receipt["probes"] if r["probe"] == "control-no-parent")
        self.assertFalse(control["refused"])
        self.assertTrue(any("a worker launched" in x for x in control["problems"]), control["problems"])
        self.assertTrue(any("a dispatch was recorded" in x for x in control["problems"]), control["problems"])
        self.assertTrue(all(r["refused"] for r in receipt["probes"] if r["probe"] != "control-no-parent"))


class TestStopWorkersEndsWhatAFinishedWorkerLeft(unittest.TestCase):
    """Codex review of PR #653 (C3): a dispatch is `completed` once its foreground process exits,
    and the provider never kills a finished dispatch's group (its pid may be reused), so a child
    the worker left in its process group outlived the cleanup. stop_workers ends every orphaned
    group of the sandbox's store, finished dispatches included, and never a group with a living
    leader (a reused number)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="first-run-reap-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def leftover(self):
        """A group leader that starts a background child and exits: (leader pid, child pid)."""
        proc = subprocess.Popen(["/bin/sh", "-c", "sleep 300 </dev/null >/dev/null 2>&1 & echo $!"], stdout=subprocess.PIPE, text=True,
                                start_new_session=True)
        child = int(proc.communicate(timeout=30)[0].strip())
        self.addCleanup(TABLES.kill, child)
        return proc.pid, child

    def store(self, rows):
        db = self.tmp / "state" / "runtime.db"
        db.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE dispatches (dispatch_id TEXT, state TEXT, pid INTEGER)")
        conn.executemany("INSERT INTO dispatches VALUES (?, ?, ?)", rows)
        conn.commit()
        conn.close()
        return argparse.Namespace(dir=self.tmp, target=self.tmp / "target", state_db=db,
                                  env={**os.environ, "SHELL": "/bin/sh"})

    def alive(self, pid, wait_s=5.0):
        end = time.monotonic() + wait_s
        while time.monotonic() < end:
            if not TABLES.running(pid):  # /proc where there is one: no procps needed (PR #668 CI)
                return False
            time.sleep(0.1)
        return True

    def test_a_process_table_it_cannot_read_is_a_teardown_error(self):
        # PR #668 CI (F1): the group reap read `ps` and, where it could not run (a Linux image with
        # no procps), saw no groups at all and reported nothing. It reads the shared process table
        # (/proc on Linux) now, and one it cannot read is a teardown error, never an empty table.
        leader, _child = self.leftover()
        with mock.patch.object(first_run.containment, "process_table", side_effect=OSError("no ps")):
            teardown = first_run.stop_workers(self.store([("disp_done", "completed", leader)]))
        self.assertTrue(teardown["errors"], teardown)
        self.assertFalse(first_run.teardown_verified(teardown))

    def test_a_completed_dispatch_leaves_no_process_behind(self):
        leader, child = self.leftover()
        first_run.stop_workers(self.store([("disp_done", "completed", leader)]))
        self.assertFalse(self.alive(child), "a finished worker's child outlived stop_workers")

    def test_a_group_with_a_living_leader_is_never_touched(self):
        leader = subprocess.Popen(["sleep", "300"], start_new_session=True)
        self.addCleanup(leader.kill)
        first_run.stop_workers(self.store([("disp_reused", "completed", leader.pid)]))
        self.assertTrue(self.alive(leader.pid, wait_s=1.0), "a group whose leader lives may not be ours")


class TestAStandaloneFirstRunVouchesForItsTeardown(Tripwired):
    """Codex review of PR #668 (C-a): a standalone first run stopped only its workers' process
    groups and ignored what that teardown found, so a detached helper (a new session, its output
    redirected) survived and the run still said GO. Every process of the run now carries the run's
    OF_CALL_ID; teardown sweeps it, and GO stands only on a verified teardown. Anything else is
    NO-GO, step `teardown`, with the sandbox kept."""

    def first_run_in_process(self, wd, execute=None):
        out = io.StringIO()
        patches = [mock.patch.dict(os.environ, self.env, clear=True), contextlib.redirect_stdout(out)]
        if execute:
            patches.append(mock.patch.object(first_run.FirstRun, "execute", execute))
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            rc = first_run.main(["--profile", "ro", "--workdir", str(wd), "--json"])
        return rc, json.loads((wd / "receipt.json").read_text(encoding="utf-8"))

    def test_a_detached_helper_is_ended_before_go(self):
        real, helpers = first_run.FirstRun.execute, []

        def execute(run):  # the worker leaves a helper in a session of its own, output redirected
            receipt = real(run)
            helpers.append(subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"], env=run.sb.env,
                                            start_new_session=True, stdin=subprocess.DEVNULL,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            return receipt
        rc, receipt = self.first_run_in_process(self.tmp / "fr", execute)
        self.addCleanup(helpers[0].kill)
        try:
            helpers[0].wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.fail("the detached helper outlived the first run")
        self.assertEqual((rc, receipt["verdict"]), (0, "GO"), receipt.get("failure"))

    def test_a_teardown_that_found_a_survivor_is_no_go_and_keeps_the_sandbox(self):
        survivors = {"ended": [], "survivors": [{"pgid": 1, "members": [1]}], "leaders_alive": []}
        with mock.patch.object(first_run, "reap_groups", return_value=survivors):
            rc, receipt = self.first_run_in_process(self.tmp / "fr")
        self.assertEqual((rc, receipt["verdict"], (receipt["failure"] or {}).get("step")), (1, "NO-GO", "teardown"))
        self.assertFalse(receipt.get("sandbox_pruned"), "a sandbox that may still be in use was pruned")
        self.assertTrue(any(p.name != "receipt.json" for p in (self.tmp / "fr").iterdir()))

    def test_a_teardown_no_go_reads_as_no_go_everywhere(self):
        # Codex review of 9db89fbe3c (P2): the witness line still said verdict=GO, and the default text
        # output raised KeyError: 'detail'. The failure uses the step schema and the witness is rebuilt.
        survivors = {"ended": [], "survivors": [{"pgid": 1, "members": [1]}], "leaders_alive": []}
        wd, out = self.tmp / "fr", io.StringIO()
        with mock.patch.object(first_run, "reap_groups", return_value=survivors), \
                mock.patch.dict(os.environ, self.env, clear=True), contextlib.redirect_stdout(out):
            rc = first_run.main(["--profile", "ro", "--workdir", str(wd)])
        receipt = json.loads((wd / "receipt.json").read_text(encoding="utf-8"))
        self.assertEqual((rc, receipt["verdict"]), (1, "NO-GO"))
        self.assertIn("verdict=NO-GO", receipt["witness"])
        self.assertEqual({"step", "ok", "detail", "recovery"} - set(receipt["failure"]), set(), receipt["failure"])
        self.assertIn("FIRST_RUN=NO-GO step=teardown", out.getvalue())
        self.assertIn("FAILURE=", out.getvalue())

    def test_a_process_table_it_cannot_read_is_no_go(self):
        with mock.patch.object(first_run.containment, "process_table", side_effect=OSError("no ps")):
            rc, receipt = self.first_run_in_process(self.tmp / "fr")
        self.assertEqual((rc, receipt["verdict"], (receipt["failure"] or {}).get("step")), (1, "NO-GO", "teardown"))


class TestALiveFirstRunNeedsProvenContainment(Tripwired):
    """PR #668 review (C-c): a live worker spends, so `--worker live` starts only where the strong
    probe proves containment: Python visible and system binaries visible. A table that hides a
    system binary's marker (macOS's view) refuses it before anything is created."""

    def test_a_host_blind_to_system_binaries_refuses_a_live_first_run(self):
        err, wd = io.StringIO(), self.tmp / "fr"
        blind = TABLES.blind_to_system_binaries(first_run.containment.process_table)
        with mock.patch.dict(os.environ, self.env, clear=True), \
                mock.patch.object(first_run.containment, "process_table", blind), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = first_run.main(["--worker", "live", "--profile", "ro", "--workdir", str(wd), "--json"])
        self.assertEqual(rc, 2, err.getvalue())
        self.assertIn("process discovery cannot contain", err.getvalue())
        self.assertFalse(wd.exists(), "a refused live run created its sandbox")


class TestTheLiveTierIsDisabled(Tripwired):
    """PR #668, the owner's decision: `first_run.py --worker live` is refused on every host but the
    live harness's container (scripts/live_container.py), exit 2, before anything is read, created
    or launched. The inert worker, which spends nothing, is untouched."""

    def test_a_live_first_run_is_refused_before_anything_is_created(self):
        err, wd = io.StringIO(), self.tmp / "fr"
        with mock.patch.object(first_run.containment, "live_disabled", REAL_LIVE_GATE), \
                mock.patch.object(first_run.containment, "containment_problem",
                                  side_effect=AssertionError("the host was probed")), \
                mock.patch.object(first_run, "make_workdir", side_effect=AssertionError("a sandbox was made")), \
                mock.patch.dict(os.environ, self.env, clear=True), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = first_run.main(["--worker", "live", "--profile", "ro", "--target", str(self.tmp / "no-such-repo"),
                                 "--workdir", str(wd), "--json"])
        self.assertEqual(rc, 2, err.getvalue())
        self.assertIn(DISABLED, err.getvalue())
        self.assertIn("PR #668", err.getvalue())
        self.assertEqual(len(err.getvalue().strip().splitlines()), 1, err.getvalue())
        self.assertFalse(wd.exists(), "a refused live run created its sandbox")

    def test_the_cli_refuses_as_its_own_process_for_either_profile(self):
        # No seam at all: the script as an operator runs it, as the certification page shows it.
        for profile in ("ro", "rw"):
            with self.subTest(profile=profile):
                wd = self.tmp / f"cli-{profile}"
                p = self.run_py("first_run.py", "--worker", "live", "--agent", "claude", "--profile", profile,
                                "--keep", "--workdir", str(wd), "--json")
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertIn(DISABLED, p.stderr)
                self.assertEqual(p.stdout, "", "a refused live run printed a receipt")
                self.assertFalse(wd.exists())

    def test_every_mode_refuses_a_live_worker(self):
        # `probes` never launches the worker it is given, but `--worker live` is refused there too:
        # the rule is unconditional.
        err = io.StringIO()
        with mock.patch.object(first_run.containment, "live_disabled", REAL_LIVE_GATE), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = first_run.main(["probes", "--worker", "live", "--workdir", str(self.tmp / "probes")])
        self.assertEqual(rc, 2, err.getvalue())
        self.assertIn(DISABLED, err.getvalue())
        self.assertFalse((self.tmp / "probes").exists())

    def test_the_inert_worker_passes_the_gate(self):
        class Reached(Exception):
            """main() got past the gate to the sandbox it makes."""

        with mock.patch.object(first_run.containment, "live_disabled", REAL_LIVE_GATE), \
                mock.patch.object(first_run, "make_workdir", side_effect=Reached):
            with self.assertRaises(Reached):
                first_run.main(["--worker", "inert", "--workdir", str(self.tmp / "inert")])


class TestDocsCarryTheGeneratedMatrix(unittest.TestCase):
    BEGIN = "<!-- BEGIN GENERATED: certification-matrix — runtime/scripts/certification.py markdown -->"
    END = "<!-- END GENERATED: certification-matrix -->"

    def test_the_certification_page_matches_the_record(self):
        text = (ROOT / "docs" / "certification.md").read_text(encoding="utf-8")
        self.assertIn(self.BEGIN, text)
        block = text.split(self.BEGIN, 1)[1].split(self.END, 1)[0].strip("\n")
        _errors, _stale, cells = certification.validate(ROOT)
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        self.assertEqual(block, certification.render_markdown(cells, record).strip("\n"),
                         "regenerate: python3 runtime/scripts/certification.py markdown")

    def test_mocked_and_live_results_are_labelled_apart(self):
        text = (ROOT / "docs" / "certification.md").read_text(encoding="utf-8")
        for heading in ("## Live-witnessed results", "## Fixture (mocked) results"):
            self.assertIn(heading, text)


# --- the live report, read in each harness's own output (#596 review) ---------------------------

FR_HEADER = "FIRST-RUN-REPORT FR-NONCE:0123456789abcdef " + "c0ffee" + "0" * 34
FR_BODY = " app.py | 2 ++"
FR_REPORT = f"{FR_HEADER}\n{FR_BODY}\n"
FR_NOTE = "I will read the diff first."
FR_PROMPT = f"Review the change. Your report MUST start with this exact line: {FR_HEADER}"


def _events(*events):
    return [json.dumps(e) for e in events]


def _goose(mid, role, *content):
    return {"type": "message", "message": {"id": mid, "role": role, "created": 1, "content": list(content)}}


# What each posix launch (runtime/providers/base.py) prints on stdout, as upstream source emits
# it: claude `-p --output-format stream-json`; codex-rs exec/src/exec_events.rs (`exec --json`);
# opencode `run --format json` events; pi/omp `--mode json` AgentSessionEvents; goose-cli
# session/mod.rs StreamEvent (`--output-format stream-json`, one message streamed as chunks that
# share its id); jcode src/cli/commands.rs `run --ndjson` (`done.text` is every text delta of the
# run); hermes `-Q`, crush `run -q` and gemini `-p` print plain text (stderr is merged in).
UPSTREAM_STDOUT = {
    "claude": _events(
        {"type": "system", "subtype": "init", "session_id": "s"},
        {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": FR_NOTE}]}},
        {"type": "result", "subtype": "success", "is_error": False, "result": FR_REPORT}),
    "codex": _events(
        {"type": "thread.started", "thread_id": "t"}, {"type": "turn.started"},
        {"type": "item.completed", "item": {"id": "item_0", "type": "reasoning", "text": FR_HEADER}},
        {"type": "item.completed", "item": {"id": "item_1", "type": "agent_message", "text": FR_NOTE}},
        {"type": "item.completed", "item": {"id": "item_2", "type": "command_execution", "command": "git diff",
                                            "aggregated_output": FR_HEADER, "exit_code": 0, "status": "completed"}},
        {"type": "item.completed", "item": {"id": "item_3", "type": "agent_message", "text": FR_REPORT}},
        {"type": "turn.completed", "usage": {"input_tokens": 1, "cached_input_tokens": 0, "output_tokens": 1}}),
    "opencode": _events(
        {"type": "step_start", "sessionID": "s", "part": {"id": "p0", "type": "step-start"}},
        {"type": "text", "sessionID": "s", "part": {"id": "p1", "type": "text", "text": FR_NOTE}},
        {"type": "tool_use", "sessionID": "s", "part": {"id": "p2", "type": "tool", "tool": "read"}},
        {"type": "step_finish", "sessionID": "s", "part": {"id": "p3", "type": "step-finish", "reason": "tool-calls"}},
        {"type": "step_start", "sessionID": "s", "part": {"id": "p4", "type": "step-start"}},
        {"type": "text", "sessionID": "s", "part": {"id": "p5", "type": "text", "text": FR_REPORT}},
        {"type": "step_finish", "sessionID": "s", "part": {"id": "p6", "type": "step-finish", "reason": "stop"}}),
    "pi": _events(
        {"type": "agent_start"},
        {"type": "message_end", "message": {"role": "user", "content": [{"type": "text", "text": FR_PROMPT}]}},
        {"type": "message_end", "message": {"role": "assistant", "content": [
            {"type": "text", "text": FR_NOTE}, {"type": "toolCall", "id": "c1", "name": "read", "arguments": {}}]}},
        {"type": "message_end", "message": {"role": "toolResult", "toolCallId": "c1",
                                            "content": [{"type": "text", "text": FR_HEADER}]}},
        {"type": "message_end", "message": {"role": "assistant", "content": [
            {"type": "thinking", "thinking": "done"}, {"type": "text", "text": FR_REPORT}]}},
        {"type": "agent_end", "messages": []}),
    "goose": _events(
        _goose("m1", "assistant", {"type": "text", "text": FR_NOTE}),
        _goose("m2", "assistant", {"type": "toolRequest", "id": "r1"}),
        _goose("m3", "user", {"type": "toolResponse", "id": "r1"}),
        _goose("m4", "assistant", {"type": "text", "text": FR_HEADER + "\n"}),
        _goose("m4", "assistant", {"type": "text", "text": FR_BODY + "\n"}),
        {"type": "complete", "total_tokens": 42}),
    "jcode": _events(
        {"type": "start"}, {"type": "text_delta", "text": FR_NOTE + "\n"},
        {"type": "tool_start", "id": "t1", "name": "read"}, {"type": "tool_done", "id": "t1"},
        {"type": "text_delta", "text": FR_REPORT},
        {"type": "done", "session_id": "s", "text": FR_NOTE + "\n" + FR_REPORT, "usage": {}}),
    "hermes": [FR_HEADER, FR_BODY],
    "crush": [FR_NOTE, FR_HEADER, FR_BODY],
    "gemini": ["Loaded cached credentials.", FR_NOTE, FR_HEADER, FR_BODY],
}
UPSTREAM_STDOUT["omp"] = UPSTREAM_STDOUT["pi"]


def read_report(agent, stdout_lines):
    """FirstRun.transcript_report() over a posix worker-read of these stdout lines."""
    fr = first_run.FirstRun(first_run.parse_args(["--agent", agent]), None)
    fr.facts["dispatch"] = "disp_fixture"
    monitor = json.dumps({"type": "turn_started", "dispatchId": "disp_fixture"})
    read = {"ok": True, "result": base.normalize_read("transcript", lines=[monitor, *stdout_lines])}
    fr.rec.run = lambda argv, **_kw: subprocess.CompletedProcess(argv, 0, json.dumps(read), "")
    return fr.transcript_report()


class TestLiveReportFormats(Tripwired):
    """A live worker's answer is read in its own harness's format, never only in Claude's."""

    def test_every_posix_harness_names_its_output_format(self):
        self.assertEqual(set(first_run.REPORT_FORMATS), set(CAPS["providers"]["posix"]["supported_harnesses"]))
        self.assertEqual(set(UPSTREAM_STDOUT), set(first_run.REPORT_FORMATS))

    def test_each_harness_report_is_read_from_its_own_output(self):
        for agent, lines in UPSTREAM_STDOUT.items():
            with self.subTest(harness=agent):
                report = read_report(agent, lines)
                self.assertEqual(report.splitlines()[:1], [FR_HEADER], f"{agent} report discarded: {report!r}")
                self.assertIn(FR_BODY, report)

    def test_a_header_only_echoed_inside_a_line_is_not_a_report(self):
        for agent in ("gemini", "jcode"):
            with self.subTest(harness=agent):
                lines = ([FR_PROMPT, FR_NOTE] if agent == "gemini"
                         else _events({"type": "done", "text": FR_PROMPT + "\n" + FR_NOTE}))
                self.assertNotEqual(read_report(agent, lines).splitlines()[:1], [FR_HEADER])

    def test_the_stand_in_answers_in_each_harness_own_format(self):
        repo = self.tmp / "repo"
        git = ["git", "-C", str(repo), "-c", "user.email=t@e", "-c", "user.name=t", "-c", "commit.gpgsign=false"]
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "a"], check=True)
        (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run([*git, "add", "app.py"], check=True)
        subprocess.run([*git, "commit", "-q", "-m", "b"], check=True)
        base_sha, head_sha = (subprocess.run([*git, "rev-parse", rev], capture_output=True, text=True,
                                             check=True).stdout.strip() for rev in ("HEAD~1", "HEAD"))
        header = f"FIRST-RUN-REPORT FR-NONCE:{'ab' * 8} {head_sha}"
        diff = subprocess.run([*git, "diff", base_sha, head_sha], capture_output=True, text=True, check=True).stdout
        (repo / "change.diff").write_text(diff + "FIRST-RUN-READ 00ff00ff00ff00ff\n", encoding="utf-8")
        spec = f"Its diff is written to change.diff in your working tree.\nYour report MUST start with: {header}"
        worker = self.tmp / "inert" / "worker.py"
        worker.parent.mkdir()
        worker.write_text(first_run.INERT_WORKER, encoding="utf-8")
        for agent in CAPS["providers"]["posix"]["supported_harnesses"]:
            with self.subTest(harness=agent):
                p = subprocess.run([sys.executable, "-I", str(worker), agent, spec], cwd=str(repo), capture_output=True,
                                   text=True, timeout=60, env={**self.env, "OPEN_FLEET_DISPATCH_ID": f"disp_{agent}"})
                self.assertEqual(p.returncode, 0, p.stderr)
                lines = p.stdout.splitlines()
                self.assertEqual(read_report(agent, lines).splitlines()[:2], [header, "app.py | 1 +"])
                if agent != "claude":
                    self.assertEqual(read_report("claude", lines), "", f"the {agent} stand-in answered as Claude")


class TestCommittedReportIsChecked(Tripwired):
    """rw: the report the worker COMMITS is what verify.py binds, so it is what must open with
    the frozen header; a correct printed report cannot carry a different committed one."""

    WRITE = 'Path(rel).write_text(report, encoding="utf-8")'

    def run_rw(self, committed: str, name: str):
        mutant = first_run.INERT_WORKER.replace(self.WRITE, f"Path(rel).write_text({committed}, encoding='utf-8')")
        self.assertNotEqual(mutant, first_run.INERT_WORKER, "the mutant must change the stand-in")
        buf = io.StringIO()
        with mock.patch.object(first_run, "INERT_WORKER", mutant), \
                mock.patch.dict(os.environ, dict(self.env), clear=True), contextlib.redirect_stdout(buf):
            rc = first_run.main(["--profile", "rw", "--workdir", str(self.tmp / name), "--json"])
        return rc, json.loads(buf.getvalue())

    def test_a_committed_report_that_differs_from_the_printed_one_is_no_go(self):
        for name, committed in {"tampered": '"I reviewed something else\\n"', "empty": '""'}.items():
            with self.subTest(committed=name):
                rc, receipt = self.run_rw(committed, name)
                self.assertEqual((rc, receipt["verdict"]), (1, "NO-GO"))
                self.assertEqual(receipt["failure"]["step"], "evidence")
                self.assertIn("the committed report does not open with", receipt["failure"]["detail"])
                self.assertNotIn("verify", [s["step"] for s in receipt["steps"]], "nothing may bind the wrong report")

    def test_the_committed_report_itself_passes(self):
        rc, receipt = self.run_rw("report", "control")
        self.assertEqual((rc, receipt["verdict"]), (0, "GO"), json.dumps(receipt.get("failure"), indent=1))


class TestRwWorkerPrintsItsReport(Tripwired):
    """#596 live rw run: Claude Code committed the right report and sent worker_done, but its final
    answer was a one-line summary, because the rw assignment never asked for the report there, and
    `result` reads the report from the final answer on both profiles. The stand-in printed it anyway,
    so no fixture caught it. first_run now installs the stand-in in LITERAL mode, which prints the
    report only when its assignment asks, and the rw assignment asks: commit, report completion,
    then print that same report as the final answer."""

    ASK = re.compile(r"(?i)\bprint\b[^\n]*\breport\b[^\n]*\bas your final answer\b")

    def spec_for(self, profile: str) -> str:
        fr = first_run.FirstRun(first_run.parse_args(["--profile", profile]), None)
        fr.facts["reviewed"] = {"base_sha": "a" * 40, "head_sha": "b" * 40}
        fr.facts["contract"] = {"source": f"{fr.unit_dir}/contract.md@{'c' * 40}", "digest": "sha256:" + "d" * 64}
        return fr.spec()

    def in_process(self, name: str, *args: str):
        buf = io.StringIO()
        with mock.patch.dict(os.environ, dict(self.env), clear=True), contextlib.redirect_stdout(buf):
            rc = first_run.main([*args, "--workdir", str(self.tmp / name), "--json"])
        return rc, json.loads(buf.getvalue())

    def test_the_rw_assignment_asks_for_the_committed_report_as_the_final_answer(self):
        lines = self.spec_for("rw").splitlines()
        asks = [i for i, ln in enumerate(lines) if self.ASK.search(ln)]
        sends = [i for i, ln in enumerate(lines) if "worker_done" in ln]
        self.assertTrue(asks, "the rw assignment never asks for the report as the final answer")
        self.assertTrue(sends and asks[-1] > sends[-1], "the final answer comes after the worker_done it reports")
        self.assertRegex(lines[asks[-1]], r"(?i)\bsame report\b", "the printed report is the committed one")
        self.assertTrue(any(self.ASK.search(ln) for ln in self.spec_for("ro").splitlines()))

    def test_first_run_installs_the_literal_stand_in(self):
        self.assertIn("\nLITERAL = False\n", first_run.INERT_WORKER)
        self.assertIn("\nLITERAL = True\n", first_run.literal_stand_in(first_run.INERT_WORKER))
        rc, receipt = self.in_process("installed", "--profile", "rw", "--keep")
        self.assertEqual((rc, receipt["verdict"]), (0, "GO"), json.dumps(receipt.get("failure"), indent=1))
        installed = (self.tmp / "installed" / "inert" / "worker.py").read_text(encoding="utf-8")
        self.assertIn("\nLITERAL = True\n", installed)

    def test_a_literal_rw_worker_is_no_go_when_its_assignment_never_asks(self):
        # The live run's semantics, kept as a mutation control: drop the ask and the literal
        # stand-in answers with a summary, exactly as Claude Code did, and `result` refuses it.
        real = first_run.FirstRun.spec

        def without_the_ask(fr):
            return "\n".join(ln for ln in real(fr).splitlines() if not self.ASK.search(ln))

        with mock.patch.object(first_run.FirstRun, "spec", without_the_ask):
            rc, receipt = self.in_process("unasked", "--profile", "rw")
        self.assertEqual((rc, receipt["verdict"]), (1, "NO-GO"))
        self.assertEqual(receipt["failure"]["step"], "result")
        self.assertIn("report does not open with", receipt["failure"]["detail"])
        self.assertIn("committed the report, and sent the completion message", receipt["failure"]["detail"])


class TestInterruptedRunStopsItsWorker(Tripwired):
    """Ctrl-C mid-run: the setsid worker is in its own session, so the terminal's SIGINT never
    reaches it; the run itself must stop it before exiting, or it keeps running and spending."""

    RECORDED = """(log_dir / f"{dispatch or 'unknown'}.argv.json").write_text(json.dumps(argv), encoding="utf-8")"""

    @staticmethod
    def alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True

    def reap(self, pid_file: Path):
        """Never leave a hung stand-in behind, even when the run under test did."""
        if pid_file.is_file() and self.alive(pid := int(pid_file.read_text())):
            pgid = os.getpgid(pid)
            if pgid != os.getpgrp():
                os.killpg(pgid, 9)

    def test_ctrl_c_while_waiting_on_the_worker_stops_it(self):
        hung = first_run.INERT_WORKER.replace(
            self.RECORDED, '(log_dir / "pid").write_text(str(os.getpid()))\n' + self.RECORDED + "\nimport time; time.sleep(120)")
        self.assertNotEqual(hung, first_run.INERT_WORKER, "the mutant must change the stand-in")
        wd = self.tmp / "interrupted"
        self.addCleanup(self.reap, wd / "inert" / "pid")
        with mock.patch.object(first_run, "INERT_WORKER", hung), \
                mock.patch.object(first_run.FirstRun, "result", side_effect=KeyboardInterrupt), \
                mock.patch.dict(os.environ, dict(self.env), clear=True), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                first_run.main(["--workdir", str(wd), "--json"])
        pid = int((wd / "inert" / "pid").read_text())
        dispatch = json.loads((wd / "inert" / "runs.log").read_text().splitlines()[0])["dispatch"]
        deadline = time.monotonic() + 15
        while self.alive(pid) and time.monotonic() < deadline:
            time.sleep(0.2)
        self.assertFalse(self.alive(pid), "the interrupted run left its worker running")
        store = LocalStateStore(db_path=wd / "state" / "runtime.db")
        self.assertEqual(store.dispatch_state(dispatch), "stopped")

    DRIVER = (
        "import importlib.util, sys\n"
        "from pathlib import Path\n"
        "spec = importlib.util.spec_from_file_location('first_run_driven', sys.argv[1])\n"
        "fr = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(fr)\n"
        "fr.INERT_WORKER = Path(sys.argv[2]).read_text(encoding='utf-8')\n"
        "sys.exit(fr.main(sys.argv[3:]))\n"
    )

    def test_sigterm_or_sighup_to_the_run_stops_its_worker(self):
        # A plain `kill`, or the terminal closing, ends the first_run.py PROCESS: its worker must
        # not outlive it any more than it outlives Ctrl-C.
        hung = first_run.INERT_WORKER.replace(
            self.RECORDED, '(log_dir / "pid").write_text(str(os.getpid()))\n' + self.RECORDED + "\nimport time; time.sleep(120)")
        self.assertNotEqual(hung, first_run.INERT_WORKER, "the mutant must change the stand-in")
        (self.tmp / "hung_worker.py").write_text(hung, encoding="utf-8")
        (self.tmp / "driver.py").write_text(self.DRIVER, encoding="utf-8")
        for sig in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=sig.name):
                wd = self.tmp / f"killed-{sig.name}"
                self.addCleanup(self.reap, wd / "inert" / "pid")
                run = subprocess.Popen([sys.executable, "-I", str(self.tmp / "driver.py"), str(SCRIPTS / "first_run.py"),
                                        str(self.tmp / "hung_worker.py"), "--workdir", str(wd), "--json"],
                                       env=self.env, cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True)
                deadline = time.monotonic() + 60
                while not (wd / "inert" / "pid").is_file() and run.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.1)
                self.assertTrue((wd / "inert" / "pid").is_file(), "the hung stand-in never started")
                run.send_signal(sig)
                _out, err = run.communicate(timeout=120)
                pid = int((wd / "inert" / "pid").read_text())
                dispatch = json.loads((wd / "inert" / "runs.log").read_text().splitlines()[0])["dispatch"]
                deadline = time.monotonic() + 15
                while self.alive(pid) and time.monotonic() < deadline:
                    time.sleep(0.2)
                self.assertFalse(self.alive(pid), f"{sig.name} to the run left its worker running")
                store = LocalStateStore(db_path=wd / "state" / "runtime.db")
                self.assertEqual(store.dispatch_state(dispatch), "stopped")
                self.assertEqual(run.returncode, 128 + sig, err[-500:])

    def test_the_run_restores_the_signal_handlers_it_replaced(self):
        trapped = (signal.SIGTERM, signal.SIGHUP)
        seen = {}

        def mine(*_a):
            return None

        def interrupted(*_a):
            seen.update({s: signal.getsignal(s) for s in trapped})
            raise KeyboardInterrupt

        before = {s: signal.signal(s, mine) for s in trapped}
        self.addCleanup(lambda: [signal.signal(s, signal.SIG_DFL if h is None else h) for s, h in before.items()])
        with mock.patch.object(first_run.FirstRun, "execute", interrupted), \
                mock.patch.dict(os.environ, dict(self.env), clear=True), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                first_run.main(["--workdir", str(self.tmp / "restored"), "--json"])
        self.assertEqual(seen, {s: first_run._terminated for s in trapped}, "the run did not trap TERM/HUP")
        self.assertEqual({s: signal.getsignal(s) for s in trapped}, {s: mine for s in trapped})


# A stand-in that echoes the spec's header and shows only what SEEN says it read. It opens a file
# only through read(): the first spec token naming a file in its working tree.
SKIMMER = r'''
import json, os, re, sys
from pathlib import Path
here = Path(sys.argv[0]).resolve().parent
dispatch = os.environ.get("OPEN_FLEET_DISPATCH_ID", "")
with open(here / "runs.log", "a", encoding="utf-8") as fh:
    fh.write(json.dumps({"harness": sys.argv[1], "dispatch": dispatch}) + "\n")
(here / f"{dispatch}.argv.json").write_text(json.dumps(sys.argv[2:]), encoding="utf-8")
spec = next((a for a in sys.argv[2:] if "FR-NONCE:" in a), "")
header = re.search(r"FIRST-RUN-REPORT FR-NONCE:[0-9a-f]{16} [0-9a-f]{40}", spec).group(0)
files = [Path(t) for t in (w.rstrip(".:,;") for w in re.split(r"[\s`'\"()]+", spec)) if t and Path(t).is_file()]
def read():
    return files[0].read_text(encoding="utf-8") if files else ""
seen = SEEN
print(json.dumps({"type": "result", "subtype": "success", "result": header + "\n" + seen + "\n"}))
'''


class TestWorkerReadsTheChange(Tripwired):
    """Most ro launches have no shell to run `git diff` (omp, pi, opencode, jcode, goose, hermes,
    crush, gemini; claude plan mode): the change reaches every worker as a file in its tree, and
    a report that copies the header without reading it is NO-GO (#596 review)."""

    def run_with(self, seen: str, name: str, *args):
        worker = SKIMMER.replace("SEEN", seen)
        buf = io.StringIO()
        with mock.patch.object(first_run, "INERT_WORKER", worker), \
                mock.patch.dict(os.environ, dict(self.env), clear=True), contextlib.redirect_stdout(buf):
            rc = first_run.main([*args, "--workdir", str(self.tmp / name), "--json"])
        return rc, json.loads(buf.getvalue())

    def test_a_worker_that_does_not_read_the_change_is_no_go(self):
        for name, seen in {
            "copies the header, opens nothing": '"I reviewed the change; it looks fine."',
            "reads only the last line": '"\\n".join(read().splitlines()[-1:])',
            "reads only the top half": '"\\n".join(read().splitlines()[: len(read().splitlines()) // 2])',
        }.items():
            with self.subTest(worker=name):
                rc, receipt = self.run_with(seen, name.split()[0] + name.split()[-1])
                self.assertEqual((rc, receipt["verdict"]), (1, "NO-GO"), name)
                self.assertEqual(receipt["failure"]["step"], "result")
                self.assertIn("does not show the worker read", receipt["failure"]["detail"])

    def test_a_worker_that_reads_the_whole_change_is_go(self):
        rc, receipt = self.run_with("read()", "reader")
        self.assertEqual((rc, receipt["verdict"]), (0, "GO"), json.dumps(receipt.get("failure"), indent=1))

    def test_every_profile_gets_the_change_as_a_file_in_the_worker_tree(self):
        for profile in ("ro", "rw"):
            with self.subTest(profile=profile):
                wd = self.tmp / f"keep-{profile}"
                buf = io.StringIO()
                with mock.patch.dict(os.environ, dict(self.env), clear=True), contextlib.redirect_stdout(buf):
                    rc = first_run.main(["--profile", profile, "--workdir", str(wd), "--keep", "--json"])
                receipt = json.loads(buf.getvalue())
                self.assertEqual(rc, 0, json.dumps(receipt.get("failure"), indent=1))
                facts = receipt["facts"]
                argv = json.loads((wd / "inert" / f"{facts['dispatch']}.argv.json").read_text(encoding="utf-8"))
                spec = next(a for a in argv if "FR-NONCE:" in a)
                wt = Path(facts["worktree"])
                named = [wt / t for t in (w.rstrip(".:,;") for w in re.split(r"[\s`'\"()]+", spec)) if t]
                inputs = [p for p in named if p.is_file()]
                self.assertTrue(inputs, f"the spec names no file in the worker's tree: {spec!r}")
                change = inputs[0].read_text(encoding="utf-8")
                rev = facts["reviewed"]
                diff = subprocess.run(["git", "-C", str(wt), "diff", rev["base_sha"], rev["head_sha"]],
                                      capture_output=True, text=True, check=True).stdout
                self.assertIn(diff, change, "the input file must carry the whole reviewed diff")
                receipt_line = change.splitlines()[-1]
                self.assertNotIn(receipt_line, spec, "the read receipt may reach the worker only through the file")
                self.assertNotIn(receipt_line, json.dumps(facts["launch_effective"]))
                ev = facts["evidence"]
                range_files = subprocess.run(["git", "-C", str(wt), "diff", "--name-only", ev["base_sha"], ev["head_sha"]],
                                             capture_output=True, text=True, check=True).stdout.split()
                self.assertNotIn(str(inputs[0].relative_to(wt)), range_files, "the input is not part of the result")


class TestLiveRouteIsIdentified(Tripwired):
    """A live-witnessed cell is live only for the route its cited, BOUND evidence names: the
    provider, profile, harness and harness version are read from the run's own inventoried
    artifacts at its pinned commit, never from the record's own fields (#596 review)."""

    def check_with(self, fn):
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        fn(record)
        path = self.tmp / "record.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        return cert_main("check", "--record", str(path))

    @staticmethod
    def live(rec, profile):
        return next(g for g in rec["providers"]["orca"]["routes"]
                    if g["tier"] == "live-witnessed" and g["profiles"] == [profile])

    @staticmethod
    def move_codex_rw_to(rec, group):
        """Reclassify orca rw/codex into `group`, keeping the cover exact."""
        routes = rec["providers"]["orca"]["routes"]
        home = next(g for g in routes if g["profiles"] == ["rw"] and "codex" in g.get("harnesses", []))
        home["harnesses"].remove("codex")
        routes.append({**group, "profiles": ["rw"], "harnesses": ["codex"]})

    def test_a_copied_claude_witness_does_not_certify_codex(self):
        # The reviewer's case: an rw/codex group copies the rw/claude witness and cites the
        # Claude ship-it report, which binds — but names no codex worker anywhere.
        p = self.check_with(lambda rec: self.move_codex_rw_to(rec, copy.deepcopy(self.live(rec, "rw"))))
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("rw/codex", p.stderr)
        self.assertIn("does not identify this route", p.stderr)

    def test_a_witness_for_another_profile_does_not_certify_this_one(self):
        def cite_the_ro_run(rec):
            rw, ro = self.live(rec, "rw"), self.live(rec, "ro")
            rw.update(witnessed=copy.deepcopy(ro["witnessed"]), evidence=list(ro["evidence"]))
        p = self.check_with(cite_the_ro_run)
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("rw/claude", p.stderr)
        self.assertIn("does not identify this route", p.stderr)

    def test_a_live_cell_whose_evidence_names_no_route_is_refused(self):
        p = self.check_with(lambda rec: self.live(rec, "ro")["witnessed"].pop("route", None))
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("witnessed.route", p.stderr)

    def test_a_route_quote_the_bound_evidence_does_not_carry_is_refused(self):
        ship = "docs/runs/2026-10-13-ship-it-mdtoc"
        cases = {
            "fabricated in a bound file": ({"path": f"{ship}/stage-build.py",
                                            "lines": ['WORKER_CMD="codex exec", PROFILE="rw", orca-ide 1.4.224, codex-cli 0.50']},
                                           "does not carry the quoted lines"),
            "real but not bound by the run": ({"path": "runtime/providers/base.py",
                                               "lines": ['"codex",']}, "is not an artifact the cited run's inventory binds"),
        }
        for name, (quote, needle) in cases.items():
            with self.subTest(quote=name):
                def forge(rec, quote=quote):
                    group = copy.deepcopy(self.live(rec, "rw"))
                    group["witnessed"].update(harness_version="codex-cli 0.50", route=[quote])
                    self.move_codex_rw_to(rec, group)
                p = self.check_with(forge)
                self.assertEqual(p.returncode, 1, p.stdout)
                self.assertIn(needle, p.stderr)

    def test_the_genuine_claude_routes_still_pass(self):
        p = cert_main("check")
        self.assertEqual(p.returncode, 0, p.stderr)
        _errors, _stale, cells = certification.validate(ROOT)
        live = {(c["name"], c["profile"], c["harness"]) for c in cells if c["effective"] == "live-witnessed"}
        self.assertEqual(live, {("orca", "ro", "claude"), ("orca", "rw", "claude"), ("posix", "ro", "claude"), ("posix", "rw", "claude"), ("claude", "ro", "claude"), ("claude", "rw", "claude")})


class TargetRepo(Tripwired):
    """A `--target` repository whose last commit is the reviewed change, run in-process."""

    def target(self, name: str, base_files: dict, change_files: dict) -> Path:
        repo = self.tmp / name
        git = ["git", "-C", str(repo), "-c", "user.email=t@e", "-c", "user.name=t", "-c", "commit.gpgsign=false"]
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
        for files, msg in ((base_files, "base"), (change_files, "change")):
            for rel, data in files.items():
                (repo / rel).parent.mkdir(parents=True, exist_ok=True)
                (repo / rel).write_bytes(data)
            subprocess.run([*git, "add", "-f", "--", *files], check=True)
            subprocess.run([*git, "commit", "-q", "-m", msg], check=True)
        return repo

    def run_target(self, repo: Path, name: str, *args):
        buf = io.StringIO()
        with mock.patch.dict(os.environ, dict(self.env), clear=True), contextlib.redirect_stdout(buf):
            rc = first_run.main(["--target", str(repo), *args, "--workdir", str(self.tmp / name), "--json"])
        return rc, json.loads(buf.getvalue())


class TestOlderTextEncodings(TargetRepo):
    """A reviewed file in an older encoding is reviewed, not a traceback (#596 review)."""

    LATIN1 = b"caf\xe9 cr\xe8me br\xfbl\xe9e\n"  # ISO-8859-1: not valid UTF-8

    def test_a_non_utf8_change_reaches_the_worker_byte_exact(self):
        repo = self.target("latin1", {"README.md": b"# r\n"}, {"legacy.txt": self.LATIN1})
        diff = subprocess.run(["git", "-C", str(repo), "diff", "HEAD~1", "HEAD"], capture_output=True, check=True).stdout
        self.assertIn(self.LATIN1.strip(), diff)
        for profile in ("ro", "rw"):
            with self.subTest(profile=profile):
                rc, receipt = self.run_target(repo, f"latin1-{profile}", "--profile", profile, "--keep")
                self.assertEqual((rc, receipt["verdict"]), (0, "GO"), json.dumps(receipt.get("failure"), indent=1))
                wt = Path(receipt["facts"]["worktree"])
                change = (wt / receipt["facts"]["change"]["input"]).read_bytes()
                self.assertIn(diff, change, "the worker must see exactly the bytes git produced")

    def test_an_unexpected_error_is_a_recorded_no_go(self):
        wd = self.tmp / "boom"
        buf = io.StringIO()
        with mock.patch.object(first_run.FirstRun, "preflight", side_effect=RuntimeError("boom")), \
                mock.patch.dict(os.environ, dict(self.env), clear=True), contextlib.redirect_stdout(buf):
            rc = first_run.main(["--workdir", str(wd), "--json"])
        receipt = json.loads(buf.getvalue())
        self.assertEqual((rc, receipt["verdict"]), (1, "NO-GO"))
        self.assertEqual(receipt["failure"]["step"], "preflight")
        self.assertIn("RuntimeError: boom", receipt["failure"]["detail"])
        self.assertTrue(receipt["failure"]["recovery"], "an unexpected failure still names the next move")
        self.assertEqual(json.loads((wd / "receipt.json").read_text(encoding="utf-8"))["verdict"], "NO-GO")


class TestTargetIgnoreRules(TargetRepo):
    """A target's ignore rules cannot block the files the run itself owns (#596 review)."""

    def test_ignored_run_files_are_force_added_by_exact_path(self):
        for ignored in ("*.diff", ".first-run/"):
            repo = self.target(f"ignores-{ignored.strip('*./')}", {".gitignore": ignored.encode() + b"\n"},
                               {"app.py": b"x = 1\n"})
            for profile in ("ro", "rw"):
                with self.subTest(ignored=ignored, profile=profile):
                    rc, receipt = self.run_target(repo, f"ign-{ignored.strip('*./')}-{profile}", "--profile", profile)
                    self.assertEqual((rc, receipt["verdict"]), (0, "GO"), json.dumps(receipt.get("failure"), indent=1))
                    adds = [c["argv"] for c in receipt["commands"] if c["argv"][:2] == ["git", "add"]]
                    self.assertTrue(adds, "the run commits its own files")
                    for argv in adds:
                        self.assertEqual(argv[2:4], ["-f", "--"], f"not a force-add of exact paths: {argv}")
                        self.assertFalse([a for a in argv[4:] if set(a) & set("*?[")], f"a glob was added: {argv}")



# --- the record takes a live first run (#596) ---------------------------------------------------

class TestReceiptCarriesTheWitness(Tripwired):
    """A first-run receipt names everything a live record needs in one quotable line, and what
    the harness itself reported (model, turns, cost); a live run never uses a harness the
    interpreter's directory shadows."""

    def in_process(self, name: str, *args: str):
        buf = io.StringIO()
        with mock.patch.dict(os.environ, dict(self.env), clear=True), contextlib.redirect_stdout(buf):
            rc = first_run.main([*args, "--workdir", str(self.tmp / name), "--json"])
        return rc, json.loads(buf.getvalue())

    def test_the_receipt_names_its_route_in_one_quotable_line(self):
        rc, receipt = self.in_process("witness", "--profile", "ro", "--keep")
        self.assertEqual(rc, 0, json.dumps(receipt.get("failure"), indent=1))
        line = receipt["witness"]
        for part in ("posix/setsid", "PROFILE=ro", "harness=claude", "worker=inert", "tier=fixture-tested",
                     f"catalog={receipt['host']['catalog_commit']}", "verdict=GO"):
            self.assertIn(part, line)
        self.assertRegex(receipt["started_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        on_disk = (self.tmp / "witness" / "receipt.json").read_text(encoding="utf-8").splitlines()
        self.assertIn(f'"witness": {json.dumps(line)},', [ln.strip() for ln in on_disk], "quotable as one line")

    def test_the_harness_own_usage_is_read_from_its_output(self):
        lines = _events({"type": "system", "subtype": "init", "model": "claude-opus-5-5", "session_id": "s"},
                        {"type": "assistant", "message": {"role": "assistant", "content": []}},
                        {"type": "result", "subtype": "success", "num_turns": 3, "total_cost_usd": 0.1999,
                         "duration_ms": 8341, "result": FR_REPORT})
        self.assertEqual(first_run.harness_usage(lines),
                         {"model": "claude-opus-5-5", "num_turns": 3, "total_cost_usd": 0.1999, "duration_ms": 8341})
        self.assertEqual(first_run.harness_usage(UPSTREAM_STDOUT["gemini"]), {}, "plain text reports nothing")

    def test_a_live_run_refuses_a_harness_the_interpreter_directory_shadows(self):
        # The sandbox puts the interpreter's directory first on PATH; a `claude` there would run
        # instead of the one the operator's PATH names (an isolation wrapper, say).
        pybin = self.tmp / "pybin"
        pybin.mkdir()
        (pybin / "python3").symlink_to(sys.executable)
        shadow = pybin / "claude"
        shadow.write_text(f'#!/bin/sh\necho "shadow $*" >> "{self.trip_log}"\nexit 97\n', encoding="utf-8")
        shadow.chmod(0o755)
        buf = io.StringIO()
        with mock.patch.object(first_run.sys, "executable", str(pybin / "python3")), \
                mock.patch.object(first_run.containment, "containment_problem", return_value=None), \
                mock.patch.dict(os.environ, dict(self.env), clear=True), contextlib.redirect_stdout(buf):
            rc = first_run.main(["--worker", "live", "--workdir", str(self.tmp / "shadowed"), "--json"])
        receipt = json.loads(buf.getvalue())
        self.assertEqual((rc, receipt["failure"]["step"]), (1, "prereqs"))
        self.assertIn(str(shadow), receipt["failure"]["detail"])
        self.assertIn(str(self.trip / "claude"), receipt["failure"]["detail"])
        self.assertEqual([s["step"] for s in receipt["steps"]], ["prereqs"])

    def test_the_shadow_check_passes_one_binary_and_names_two(self):
        one = str(self.trip)
        self.assertEqual(first_run.harness_shadow("claude", one, one), "")
        other = self.tmp / "other"
        other.mkdir()
        (other / "claude").symlink_to(self.trip / "claude")  # the same file by another name
        self.assertEqual(first_run.harness_shadow("claude", str(other), one), "")
        (self.tmp / "third").mkdir()
        (self.tmp / "third" / "claude").write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
        (self.tmp / "third" / "claude").chmod(0o755)
        self.assertIn("third", first_run.harness_shadow("claude", str(self.tmp / "third"), one))
        self.assertIn("not on your PATH", first_run.harness_shadow("claude", one, str(self.tmp / "nowhere")))


def _git_out(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=str(repo), capture_output=True, text=True, check=True).stdout.strip()


class TestLiveRecordTakesTheFirstRun(unittest.TestCase):
    """The record can take a live posix first run (#596). In a scratch repository, a first_run.py
    receipt bound in a run report certifies posix ro/claude and the claude ro harness cell; the
    fields the coordinator copies from the receipt are checked against the bound evidence."""

    RUN = "docs/runs/2026-10-24-review-it-first-run"
    REPORT = "docs/runs/2026-10-24-review-it-first-run.md"
    HV = "2.1.304 (Claude Code)"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name).resolve()
        _git_out(self.repo, "init", "-q", ".")
        for key, val in (("user.email", "t@example.com"), ("user.name", "t"), ("commit.gpgsign", "false")):
            _git_out(self.repo, "config", key, val)
        caps = {"providers": {"posix": {"supported_profiles": ["ro"], "supported_harnesses": ["claude"]}}}
        (self.repo / "runtime" / "providers").mkdir(parents=True)
        (self.repo / "runtime" / "providers" / "capabilities.json").write_text(json.dumps(caps), encoding="utf-8")
        (self.repo / "README.md").write_text("scratch catalog\n", encoding="utf-8")
        _git_out(self.repo, "add", "-A")
        _git_out(self.repo, "commit", "-qm", "catalog")
        self.catalog = _git_out(self.repo, "rev-parse", "HEAD")

    def bind(self, worker: str = "live", catalog: str | None = None) -> str:
        """Commit a receipt and a verifier-ledger manifest, write the run report; the quotable line."""
        receipt = {"schema": first_run.SCHEMA, "verdict": "GO",
                   "tier": "live-unreviewed" if worker == "live" else "fixture-tested",
                   "route": {"provider": "posix", "backend": "setsid", "profile": "ro", "harness": "claude",
                             "worker": worker},
                   "host": {"catalog_commit": catalog or self.catalog, "catalog_dirty": False},
                   "facts": {"harness": {"name": "claude", "version": self.HV}}}
        receipt["witness"] = first_run.witness_line(receipt)
        run = self.repo / self.RUN
        run.mkdir(parents=True, exist_ok=True)
        (run / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        _git_out(self.repo, "add", "-A")
        _git_out(self.repo, "commit", "-qm", "first-run receipt")
        manifest = f"{self.RUN}/manifest.json"
        cmd = f"python3 runtime/scripts/verify.py --manifest {manifest}"
        (self.repo / manifest).write_text(json.dumps({"unit": "first-run", "commands": [
            {"cmd": cmd, "cmd_sha256": hashlib.sha256(cmd.encode()).hexdigest(), "exit": 0,
             "wtree": _git_out(self.repo, "rev-parse", "HEAD^{tree}")}]}) + "\n", encoding="utf-8")
        _git_out(self.repo, "add", "-A")
        _git_out(self.repo, "commit", "-qm", "manifest")
        rev = _git_out(self.repo, "rev-parse", "HEAD")
        rows = "\n".join(f"{hashlib.sha256((self.repo / p).read_bytes()).hexdigest()}  {p}"
                         for p in (manifest, f"{self.RUN}/receipt.json"))
        (self.repo / self.REPORT).write_text(
            f"# Run report\n\nRUN: mission=review-it tier=self-run inventory_at={rev} manifest={manifest} "
            f"verifier=GREEN\n\n    {cmd}\n    exit 0\n\n## Run-close integrity inventory (sha256)\n\n```\n{rows}\n```\n",
            encoding="utf-8")
        return next(ln.strip() for ln in (run / "receipt.json").read_text(encoding="utf-8").splitlines()
                    if ln.strip().startswith('"witness": '))

    def record(self, quote: str, **over) -> dict:
        witnessed = {"upstream_version": self.catalog, "harness_version": self.HV, "host": "macOS-27.0.1-arm64",
                     "date": "2026-10-24", "route": [{"path": f"{self.RUN}/receipt.json", "lines": [quote]}]}
        witnessed.update(over.pop("witnessed", {}))
        live = {"tier": "live-witnessed", "witnessed": witnessed, "evidence": [self.REPORT],
                "limitations": ["one live first run"]}
        idle = {"tier": "unavailable", "evidence": ["README.md"], "limitations": ["scratch"]}
        harnesses = {h: {"upstream": {"version": None}, "routes": [{"profiles": ["ro", "rw"], **idle}]}
                     for h in base.SUPPORTED_HARNESSES}
        harnesses["claude"] = {"upstream": {"version": over.pop("harness_version", "2.1.304")},
                               "routes": [{"profiles": ["ro"], **copy.deepcopy(live)}, {"profiles": ["rw"], **idle}]}
        upstream = {"repo": "open-fleet", "version": "in-repo", "commit": None}
        real = json.loads(RECORD.read_text(encoding="utf-8"))
        return {"schema_version": real["schema_version"], "record_version": 1, "recorded": "2026-10-24",
                "tiers": real["tiers"], "harnesses": harnesses,
                "providers": {"posix": {"upstream": upstream, "routes": [
                    {"profiles": ["ro"], "harnesses": ["claude"], **copy.deepcopy(live)}]}}}

    def check(self, record: dict) -> tuple[list[str], list[dict]]:
        path = self.repo / "record.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        errors, _stale, cells = certification.validate(self.repo, path)
        return errors, cells

    def test_a_bound_live_receipt_certifies_the_posix_and_harness_cells(self):
        errors, cells = self.check(self.record(self.bind()))
        self.assertEqual(errors, [])
        live = {(c["kind"], c["name"], c["profile"]) for c in cells if c["effective"] == "live-witnessed"}
        self.assertEqual(live, {("provider", "posix", "ro"), ("harness", "claude", "ro")})

    def test_the_harness_version_field_must_be_the_witnessed_one(self):
        line = self.bind()
        for version, needle in (("2.1.305", "is not the witnessed harness version"),
                                (None, "upstream whose version is unknown")):
            with self.subTest(version=version):
                errors, _cells = self.check(self.record(line, harness_version=version))
                self.assertTrue(any(needle in e and "harness claude" in e for e in errors), errors)

    def test_an_in_repo_witness_names_a_commit_of_this_repository(self):
        line = self.bind(catalog="f" * 40)
        errors, _cells = self.check(self.record(line, witnessed={"upstream_version": "f" * 40}))
        self.assertTrue(any("provider posix" in e and "a commit of this repository" in e for e in errors), errors)

    def test_a_fixture_receipt_certifies_nothing_live(self):
        errors, _cells = self.check(self.record(self.bind(worker="inert")))
        self.assertTrue(any("fixture" in e and "provider posix" in e for e in errors), errors)
        self.assertTrue(any("fixture" in e and "harness claude" in e for e in errors), errors)

    def test_a_witness_date_is_a_calendar_date(self):
        errors, _cells = self.check(self.record(self.bind(), witnessed={"date": "last week"}))
        self.assertTrue(any("witnessed.date" in e for e in errors), errors)

    def test_an_orca_witness_does_not_certify_base_py_launch_line(self):
        # The Orca route runs spawn_worker.sh's own rows, never base.py's table: its witness cannot
        # make a harness cell live, even though it names the harness and the profile.
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        orca_ro = next(g for g in record["providers"]["orca"]["routes"]
                       if g["tier"] == "live-witnessed" and g["profiles"] == ["ro"])
        claude = record["harnesses"]["claude"]
        claude["upstream"]["version"] = "2.1.296"
        claude["routes"] = [{"profiles": ["ro"], "tier": "live-witnessed", "witnessed": copy.deepcopy(orca_ro["witnessed"]),
                             "evidence": list(orca_ro["evidence"]), "limitations": ["copied"]},
                            {**claude["routes"][0], "profiles": ["rw"]}]
        path = Path(tempfile.mkdtemp(prefix="of-cert-orca-")) / "record.json"
        self.addCleanup(shutil.rmtree, path.parent, True)
        path.write_text(json.dumps(record), encoding="utf-8")
        p = cert_main("check", "--record", str(path))
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("harness claude", p.stderr)
        self.assertIn("off Orca", p.stderr)



class TestTheBoundFirstRunsAreLive(unittest.TestCase):
    """Record version 5 (#596): the 2026-10-24 live first runs, bound in a run report, certify
    posix ro/rw with claude and the claude harness cells; the fields copied from their receipts
    are what check holds them to."""

    REPORT = "docs/runs/2026-10-24-review-it-first-run.md"
    LIVE = {("posix", "ro", "claude"), ("posix", "rw", "claude"), ("claude", "ro", "claude"), ("claude", "rw", "claude")}

    def check_with(self, fn):
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        fn(record)
        tmp = Path(tempfile.mkdtemp(prefix="of-cert-v5-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "record.json").write_text(json.dumps(record), encoding="utf-8")
        return cert_main("check", "--record", str(tmp / "record.json"))

    @staticmethod
    def posix_live(rec):
        return next(g for g in rec["providers"]["posix"]["routes"] if g["tier"] == "live-witnessed")

    def test_the_shipped_record_binds_the_first_runs(self):
        errors, _stale, cells = certification.validate(ROOT)
        self.assertEqual(errors, [])
        live = {(c["name"], c["profile"], c["harness"]) for c in cells if c["effective"] == "live-witnessed"}
        self.assertTrue(self.LIVE <= live, live)
        rec = json.loads(RECORD.read_text(encoding="utf-8"))
        self.assertIn(self.REPORT, self.posix_live(rec)["evidence"])
        run_report = _load("run_report_for_v5", SCRIPTS / "run_report.py")
        self.assertEqual(run_report.check_report(self.REPORT, "review-it", "external-run"), [])
        self.assertEqual(rec["harnesses"]["claude"]["upstream"]["version"], "2.1.304")

    def test_without_the_bound_report_the_cells_are_not_live(self):
        def unbind(rec):
            group = self.posix_live(rec)
            group["evidence"] = [e for e in group["evidence"] if e != self.REPORT]
        p = self.check_with(unbind)
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("without a binding run report", p.stderr)

    def test_a_harness_version_the_runs_did_not_report_is_refused(self):
        p = self.check_with(lambda rec: rec["harnesses"]["claude"]["upstream"].update(version="2.1.305"))
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("is not the witnessed harness version", p.stderr)


class TestSecurityHardening782(unittest.TestCase):
    """Regression tests for #782 hardening in certification.py."""

    REPORT = "docs/runs/2026-10-24-review-it-first-run.md"

    def _validate_with(self, mutate=None, strict_pin_witness=False):
        rec = json.loads(RECORD.read_text(encoding="utf-8"))
        if mutate is not None:
            mutate(rec)
        tmp = Path(tempfile.mkdtemp(prefix="of-cert-782-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        path = tmp / "record.json"
        path.write_text(json.dumps(rec), encoding="utf-8")
        return certification.validate(ROOT, record_path=path,
                                      strict_pin_witness=strict_pin_witness)

    def test_fixture_marker_in_unquoted_bound_artifact_is_refused(self):
        real_bound = certification._bound_artifacts
        for marker in ("worker=inert", "tier=fixture-tested",
                       '"worker": "inert"', '"tier": "fixture-tested"', "(inert "):
            with self.subTest(marker=marker):
                def poisoned(rel, root, marker=marker):
                    arts = dict(real_bound(rel, root))
                    if rel == self.REPORT:
                        arts["docs/runs/2026-10-24-review-it-first-run/extra.log"] = (
                            f"unquoted line with {marker} marker",
                        )
                    return arts
                with mock.patch.object(certification, "_bound_artifacts", side_effect=poisoned):
                    errors, _, _ = self._validate_with()
                self.assertTrue(any("fixture run" in e for e in errors), errors)

    def test_structural_first_run_receipt_validation_catches_non_live_or_no_go(self):
        real_bound = certification._bound_artifacts
        cases = (
            ("non-live worker", {"route": {"worker": "standin"}}, "route.worker="),
            ("fixture tier", {"tier": "fixture-tested"}, "fixture"),
            ("quoted NO-GO", {"verdict": "NO-GO"}, "must be 'GO'"),
        )
        for label, patch, needle in cases:
            with self.subTest(case=label):
                def tampered(rel, root, patch=patch):
                    arts = dict(real_bound(rel, root))
                    if rel == self.REPORT:
                        for k, lines in list(arts.items()):
                            if k.endswith("mac-ro/receipt.json"):
                                obj = json.loads("\n".join(lines))
                                obj.update(patch)
                                arts[k] = tuple(ln.strip() for ln in json.dumps(obj, indent=2).splitlines())
                    return arts
                with mock.patch.object(certification, "_bound_artifacts", side_effect=tampered):
                    errors, _, _ = self._validate_with()
                self.assertTrue(any(needle in e for e in errors), errors)

    def test_inert_in_harness_or_upstream_version_is_refused(self):
        def set_inert_harness(rec):
            live = next(g for g in rec["providers"]["posix"]["routes"]
                        if g["tier"] == "live-witnessed")
            live["witnessed"]["harness_version"] = "inert-claude 1.0"

        errors, _, _ = self._validate_with(set_inert_harness)
        self.assertTrue(any("inert" in e.lower() for e in errors), errors)
        errors2, _, _ = self._validate_with(
            lambda rec: rec["harnesses"]["claude"]["upstream"].update(version="inert-2.1.304")
        )
        self.assertTrue(any("inert" in e.lower() for e in errors2), errors2)

    def test_pinned_provider_upstream_version_mismatch_is_checked_and_surfaced(self):
        # Undisclosed version mismatch fails default validate()
        def undisclosed_mismatch(rec):
            orca_rw = next(
                g for g in rec["providers"]["orca"]["routes"]
                if g["tier"] == "live-witnessed" and g["profiles"] == ["rw"]
            )
            orca_rw["limitations"] = ["no mention of prior pin version"]
        errors, _, _ = self._validate_with(undisclosed_mismatch)
        self.assertTrue(any("does not match pinned upstream.version" in e for e in errors), errors)

        # Strict mode rejects even disclosed source-delta carry-forwards (orca rw/claude at 1.4.224)
        strict_errors, _, _ = self._validate_with(strict_pin_witness=True)
        self.assertTrue(
            any("orca" in e and "does not match pinned upstream.version" in e
                for e in strict_errors),
            strict_errors,
        )

        # matrix --json exposes witnessed_upstream and witness_matches_pin cleanly
        p = cert_main("matrix", "--json")
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        orca_rw_cell = next(
            c for c in data
            if c["name"] == "orca" and c["profile"] == "rw" and c["harness"] == "claude"
        )
        self.assertEqual(orca_rw_cell["witnessed_upstream"], "orca-ide 1.4.224")
        self.assertFalse(orca_rw_cell["witness_matches_pin"])


if __name__ == "__main__":
    unittest.main()
