#!/usr/bin/env python3
"""Contract tests for scripts/shard-tests.py (speed-it J1 sharding).

The failure mode this file exists to close is a shard map that silently drops
a module: CI stays green while running a subset of the suite — the "three CI
eval jobs had run zero tests and passed" shape. So the load-bearing assertion
is ID-level: the union of per-shard live discovery equals full-suite live
discovery, pairwise disjoint. Weights steer balance only and are covered by a
freshness test plus a deterministic balance bound (no wall-clock assertions —
perf budgets live in harnesses, never in tests).

    python3 -m unittest tests.test_shard_tests -v
"""
import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "shard-tests.py"
WORKFLOW = ROOT / ".github" / "workflows" / "validate.yml"


def load_sharder():
    spec = importlib.util.spec_from_file_location("_shard_tests", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def collect_ids(suite):
    out = set()

    def walk(s):
        for t in s:
            if isinstance(t, unittest.TestSuite):
                walk(t)
            else:
                out.add(t.id())

    walk(suite)
    return out


def unit_ids(loader, tests_dir, unit):
    """The test IDs one shard unit collects, named the way full discovery names them.

    A whole module goes through the same per-module discover as always. A class unit
    (`test_mod.TestCase`, a module the sharder splits by class) goes through the loader's dotted
    name, the call `python -m unittest tests.test_mod.TestCase` makes in the shard, with tests/
    importable as the top level discover uses, so its IDs compare with discovery's directly.
    """
    module, _, cls = unit.partition(".")
    if not cls:
        return collect_ids(loader.discover(tests_dir, pattern=unit + ".py"))
    if tests_dir not in sys.path:
        sys.path.insert(0, tests_dir)
    return collect_ids(loader.loadTestsFromName(unit))


def shard_union_ids(shards):
    """Every ID the shards collect, through the union test's own per-unit loader call."""
    loader = unittest.TestLoader()
    tests_dir = str(ROOT / "tests")
    union = set()
    for shard in shards:
        for mod in shard:
            union |= unit_ids(loader, tests_dir, mod)
    return union


class ShardCoverage(unittest.TestCase):
    """A module that runs nowhere is a test suite that lies about its size."""

    def test_every_test_file_lands_in_exactly_one_shard(self):
        sh = load_sharder()
        modules = sh.discover_modules()
        self.assertGreater(len(modules), 20, "the scan found almost no test files")
        shards = sh.partition(modules, sh.DEFAULT_SHARDS)
        self.assertEqual(sh.check(shards, modules), [])

    def test_no_shard_is_empty(self):
        # check() already flags empties; this names the CI shape explicitly: an
        # empty shard is a matrix job that runs zero tests and reports green.
        sh = load_sharder()
        for i, shard in enumerate(sh.partition(sh.discover_modules(), sh.DEFAULT_SHARDS),
                                  start=1):
            self.assertTrue(shard, f"shard {i} runs zero tests and would pass vacantly")

    def test_union_of_shard_ids_equals_full_discovery(self):
        """ID-level, against LIVE discovery — not a file list compared to itself.

        A file list compared to its own partition passes whether or not the
        modules import or collect anything. Loading each shard's modules and
        the full suite through the real loader fails if a shard names a module
        that collects nothing, or if discovery finds tests no shard names.
        """
        sh = load_sharder()
        loader = unittest.TestLoader()
        tests_dir = str(ROOT / "tests")
        full = collect_ids(loader.discover(tests_dir))
        self.assertGreater(len(full), 1000, "full discovery collected almost nothing")
        seen, union = {}, set()
        for i, shard in enumerate(sh.partition(sh.discover_modules(), sh.DEFAULT_SHARDS),
                                  start=1):
            for mod in shard:
                # Per-module discover, NOT loadTestsFromName("tests.<mod>"): the
                # dotted import collects the same tests under different IDs
                # ("tests."-prefixed), which would fake a mismatch. Same loader
                # call shape both sides, so IDs are directly comparable.
                found = unit_ids(loader, tests_dir, mod)
                self.assertTrue(found, f"{mod} collected zero tests in its shard")
                for tid in found:
                    self.assertNotIn(tid, seen,
                                     f"{tid} runs in shards {seen.get(tid)} and {i}")
                    seen[tid] = i
                    union.add(tid)
        self.assertEqual(union, full,
                         "shards and discovery disagree — tests run twice or never")

    def test_the_id_comparison_can_actually_see_a_drop(self):
        """Without this the union test is a tautology shaped like a check.

        A mutant comparing a set to itself passes on any tree. Dropping one ID
        from a copied union must break equality, or the assertion proves nothing.
        """
        # 2026-10-23 review, §5 Tests: this compared two literal sets and could not fail.
        # Both operands are now the live ones the union test compares: full discovery, and
        # the union of a real partition that silently lost one module.
        sh = load_sharder()
        shards = sh.partition(sh.discover_modules(), sh.DEFAULT_SHARDS)
        victim = shards[0][-1]
        sample = collect_ids(unittest.TestLoader().discover(str(ROOT / "tests")))
        dropped = shard_union_ids([[m for m in s if m != victim] for s in shards])
        self.assertNotEqual(dropped, sample, "the union comparison cannot see a drop")
        lost = sample - dropped
        self.assertTrue(lost, f"dropping {victim} lost no test ID")
        self.assertTrue(all(tid.startswith(victim + ".") for tid in lost),
                        f"dropping {victim} lost IDs outside it: {sorted(lost)[:3]}")

    def test_the_union_test_itself_fails_when_a_shard_drops_a_module(self):
        """The real check, mutated (2026-10-23 review, §5 Tests).

        Runs test_union_of_shard_ids_equals_full_discovery against a sharder whose partition
        silently drops one module and requires it to FAIL, naming the drop. A union test
        weakened to compare a set with itself passes that run, and this test catches it.
        """
        real = load_sharder()
        victim = real.partition(real.discover_modules(), real.DEFAULT_SHARDS)[0][-1]

        def partition(modules, n, *args, **kwargs):
            return [[m for m in s if m != victim]
                    for s in real.partition(modules, n, *args, **kwargs)]

        mutant = types.SimpleNamespace(discover_modules=real.discover_modules,
                                       DEFAULT_SHARDS=real.DEFAULT_SHARDS, partition=partition)
        union_test = ShardCoverage.test_union_of_shard_ids_equals_full_discovery
        result = unittest.TestResult()
        with mock.patch.dict(union_test.__globals__, {"load_sharder": lambda: mutant}):
            ShardCoverage("test_union_of_shard_ids_equals_full_discovery").run(result)
        self.assertEqual(result.errors, [], "the mutated union test errored instead of failing")
        self.assertEqual(len(result.failures), 1, f"the union test passed with {victim} dropped")
        report = result.failures[0][1]
        self.assertIn("shards and discovery disagree", report)
        self.assertIn(victim + ".", report, "the failure does not name the dropped module's tests")


class ShardDeterminismAndBalance(unittest.TestCase):
    def test_partition_is_deterministic(self):
        sh = load_sharder()
        modules = sh.discover_modules()
        self.assertEqual(sh.partition(modules, sh.DEFAULT_SHARDS),
                         sh.partition(modules, sh.DEFAULT_SHARDS))

    def test_list_output_is_byte_identical_across_runs(self):
        first = subprocess.run([sys.executable, str(SCRIPT), "--list"],
                               capture_output=True, text=True, cwd=ROOT)
        second = subprocess.run([sys.executable, str(SCRIPT), "--list"],
                                capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout,
                         "--list differs run to run — the CI partition is not stable")
        sh = load_sharder()
        for mod in sh.discover_modules():
            self.assertIn(mod, first.stdout, f"--list never names {mod}")

    def test_every_test_file_has_a_weight(self):
        """Unknown files fall back to the median weight, which silently rots
        balance as the suite grows. A new test file must name its measured
        weight deliberately — the script header says how."""
        sh = load_sharder()
        missing = sorted(set(sh.discover_modules()) - set(sh.WEIGHTS))
        self.assertEqual(missing, [],
                         f"no WEIGHTS entry in scripts/shard-tests.py for {missing} — "
                         "measure one run (`python3 -m unittest tests.<mod>` wall s "
                         "from the repo root) and add it")
        stale = sorted(set(sh.WEIGHTS) - set(sh.discover_modules()))
        self.assertEqual(stale, [], f"weights for deleted modules never run: {stale}")

    def test_predicted_shards_are_balanced(self):
        """Deterministic bound on the LPT partition — no wall clock involved.

        If the heaviest shard ever drifts past 1.5x the mean prediction, the
        weights are stale (or a module outgrew file-level sharding) and the
        matrix is fan-out theater. Today the four shards sit within 1% of
        each other, so the bound has two orders of slack against noise.
        """
        sh = load_sharder()
        walls = [sh.predicted_wall(s)
                 for s in sh.partition(sh.discover_modules(), sh.DEFAULT_SHARDS)]
        mean = sum(walls) / len(walls)
        self.assertLessEqual(max(walls), 1.5 * mean,
                             f"shard predictions {walls} are unbalanced — re-measure "
                             "WEIGHTS or reconsider the shard count")

    def test_unknown_modules_still_partition_deterministically(self):
        """The median-weight fallback path: total coverage even for modules the
        weights table has never seen (e.g. a file added between the weight
        edit and this test — the freshness test above still fails, but the
        partition itself must never drop the file)."""
        sh = load_sharder()
        modules = ["test_aaa_brand_new", "test_verify", "test_zzz_also_new"]
        first = sh.partition(modules, 2, dict(sh.WEIGHTS))
        self.assertEqual(sh.check(first, modules), [])
        self.assertEqual(first, sh.partition(modules, 2, dict(sh.WEIGHTS)))


class ShardCoverageWrap(unittest.TestCase):
    """Per-shard coverage feeds the D9 gate through a CI combine — pinned as
    command SHAPE, because the suite is stdlib-only and no test here may
    import coverage. The wrap order is the load-bearing part: `coverage run`
    must precede `-m unittest` (it traces the child interpreter), and
    `--parallel-mode` must be present (without it every shard overwrites the
    same `.coverage` file and the combine silently reports one shard)."""

    def test_default_command_runs_unittest_with_no_coverage(self):
        sh = load_sharder()
        cmd = sh.shard_command(["test_verify", "test_pins"])
        self.assertEqual(cmd[:3], [sys.executable, "-m", "unittest"])
        self.assertEqual(cmd[3:], ["tests.test_verify", "tests.test_pins"])
        self.assertNotIn("coverage", cmd)

    def test_with_coverage_wraps_unittest_in_parallel_mode(self):
        sh = load_sharder()
        cmd = sh.shard_command(["test_verify"], with_coverage=True)
        self.assertEqual(
            cmd[:6],
            [sys.executable, "-m", "coverage", "run", "--parallel-mode", "-m"])
        self.assertEqual(cmd[6:8], ["unittest", "tests.test_verify"])

    def test_cli_accepts_with_coverage(self):
        r = subprocess.run([sys.executable, str(SCRIPT), "--help"],
                           capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--with-coverage", r.stdout)


class ShardCliAndWorkflowAgreement(unittest.TestCase):
    """The workflow and the script agree on the shard count, or CI is red by
    construction somewhere nobody reads. Each half is asserted from the other
    half's source so they cannot drift apart silently."""

    def _matrix_shards(self):
        """Every job that shards the suite (the 3.13 `tests` lane and, since #514, the
        `floor` lanes) declares the same matrix; one list comes back once they agree, so a
        lane whose matrix drifts from the others fails here rather than running a shard
        under the wrong total."""
        found = re.findall(r"shard:\s*\[([0-9,\s]+)\]", WORKFLOW.read_text(encoding="utf-8"))
        self.assertTrue(found, "no job declares a shard matrix")
        matrices = [[int(x) for x in m.split(",")] for m in found]
        self.assertEqual(matrices, [matrices[0]] * len(matrices),
                         f"shard matrices disagree across jobs: {matrices}")
        return matrices[0]

    def test_shard_index_out_of_range_exits_2(self):
        for bad in ("0", "5"):
            r = subprocess.run([sys.executable, str(SCRIPT), "--shard", bad, "--of", "4"],
                               capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(r.returncode, 2, f"--shard {bad} --of 4: {r.stderr}")

    def test_workflow_matrix_is_contiguous_and_matches_of(self):
        wf = WORKFLOW.read_text(encoding="utf-8")
        matrix = self._matrix_shards()
        self.assertEqual(sorted(matrix), list(range(1, len(matrix) + 1)),
                         f"matrix shards {matrix} skip a number — that shard never runs")
        ofs = {int(x) for x in re.findall(r"--of\s+(\d+)", wf)}
        self.assertEqual(ofs, {len(matrix)},
                         f"workflow --of values {ofs} disagree with the {len(matrix)}-job "
                         "matrix — shards run under the wrong total")

    def test_gates_still_implies_suite_green(self):
        """`gates` is the branch-protection context; the suite moved to a matrix
        job, so gates must NEED it — otherwise the new job is advisory and a red
        suite still merges."""
        wf = WORKFLOW.read_text(encoding="utf-8")
        starts = [(m.start(), m.group(1))
                  for m in re.finditer(r"^  ([a-z_]+):$", wf, re.MULTILINE)]
        names = [n for _, n in starts]
        self.assertIn("tests", names, "the sharded suite job is gone from CI")
        self.assertIn("gates", names, "the gates job is gone from CI")
        gi = names.index("gates")
        end = starts[gi + 1][0] if gi + 1 < len(starts) else len(wf)
        gates = wf[starts[gi][0]:end]
        self.assertRegex(gates, r"needs:\s*\[[^\]]*tests[^\]]*\]",
                         "gates no longer needs the sharded suite — suite failures "
                         "cannot block the merge")

    def _gates(self):
        wf = WORKFLOW.read_text(encoding="utf-8")
        starts = [(m.start(), m.group(1))
                  for m in re.finditer(r"^  ([a-z_]+):$", wf, re.MULTILINE)]
        names = [n for _, n in starts]
        self.assertIn("gates", names, "the gates job is gone from CI")
        gi = names.index("gates")
        end = starts[gi + 1][0] if gi + 1 < len(starts) else len(wf)
        gates = wf[starts[gi][0]:end]
        needs = re.search(r"(?m)^    needs:\s*\[([^\]]*)\]", gates)
        self.assertIsNotNone(needs, "gates declares no needs list")
        return gates, [j.strip() for j in needs.group(1).split(",") if j.strip()], names

    def test_gates_runs_whatever_its_needs_did(self):
        """2026-10-23 review, P1-5: the test above held while gates merely NEEDED the suite,
        and that was not enough. A failed need SKIPS a plain dependent, and GitHub counts a
        skipped required check as success — runs 39386063357 and 38533245355 left `gates`
        skipped on a red shard. `if: always()` makes gates run, so its own verdict counts."""
        gates, needs, names = self._gates()
        self.assertRegex(gates, r"(?m)^    if:\s*always\(\)\s*$",
                         "gates has no job-level if: always() — a red need skips it, and a "
                         "skipped required check passes")
        self.assertIn("floor", needs, "gates no longer needs the floor interpreters")
        for job in needs:
            with self.subTest(need=job):
                self.assertIn(job, names, f"gates needs {job!r}, which no job defines")

    def test_gates_first_step_fails_unless_every_need_succeeded(self):
        """The result check is RUN here, once per need and per non-success result, so a check
        that reads the wrong field, misses a need or passes an empty map fails this test."""
        gates, needs, _ = self._gates()
        steps = re.split(r"(?m)^      - ", gates.split("\n    steps:\n", 1)[1])[1:]
        self.assertTrue(steps, "gates has no steps")
        first = steps[0]
        self.assertNotIn("actions/checkout@", first, "gates checks out before judging its needs")
        self.assertRegex(first, r"NEEDS_JSON:\s*\$\{\{\s*toJSON\(needs\)\s*\}\}",
                         "the first step does not read every need's result")
        self.assertIn("run: |\n", first)
        script = textwrap.dedent(first.split("run: |\n", 1)[1])

        def run(results):
            env = {**os.environ, "NEEDS_JSON": json.dumps(
                {job: {"result": r, "outputs": {}} for job, r in results.items()})}
            env["PATH"] = os.path.dirname(sys.executable) + os.pathsep + env.get("PATH", "")
            return subprocess.run(["bash", "-e", "-c", script], env=env,
                                  capture_output=True, text=True, timeout=60)

        green = run({job: "success" for job in needs})
        self.assertEqual(green.returncode, 0, green.stdout + green.stderr)
        for job in needs:
            for result in ("failure", "cancelled", "skipped"):
                with self.subTest(need=job, result=result):
                    r = run({**{j: "success" for j in needs}, job: result})
                    self.assertNotEqual(r.returncode, 0, f"gates passed with {job} {result}")
                    self.assertIn(f"'{job}' ended '{result}'", r.stdout)
        self.assertNotEqual(run({}).returncode, 0, "gates passed with no needs at all")

    def test_ci_shard_invocation_collects_coverage(self):
        """The --with-coverage flag unwired is the orphan-mechanism shape: CI
        would combine zero data files and the D9 gate would fail on every PR
        (or, worse, report 0% as a gate event nobody reads). The matrix
        invocation must carry the flag."""
        wf = WORKFLOW.read_text(encoding="utf-8")
        invocations = [ln.strip() for ln in wf.splitlines()
                       if "shard-tests.py" in ln and "--shard" in ln
                       and not ln.lstrip().startswith("#")]
        self.assertTrue(invocations, "no CI step invokes the sharder at all")
        for ln in invocations:
            self.assertIn("--with-coverage", ln,
                          f"shard invocation collects no coverage: {ln}")

    def test_gates_combines_shard_coverage_instead_of_rerunning(self):
        """Reconciliation, both halves: gates must `combine` the per-shard
        data files (no `coverage run` of its own — that would double-run the
        suite the matrix just ran) and still end in `coverage report`, which
        is the fail_under = 80 gate. Comments excluded: prose may name the
        old and new commands while explaining the move."""
        wf = WORKFLOW.read_text(encoding="utf-8")
        run = "\n".join(ln for ln in wf.splitlines()
                        if not ln.lstrip().startswith("#"))
        self.assertIn("coverage combine", run,
                      "gates never combines the per-shard data files")
        self.assertIn("coverage report", run,
                      "the fail_under = 80 report is gone from gates")
        self.assertNotIn("coverage run", run,
                         "gates still runs coverage itself — the suite runs twice")

    def test_no_unscoped_full_suite_run_remains_in_ci(self):
        """The matrix owns full-suite coverage now. Any surviving unscoped
        `discover -s tests` in CI double-runs the suite (~260 s) or, worse,
        becomes the 'real' gate nobody shards. The gitleaks step's scoped
        `-p test_verify.py` re-run (optional-scanner path) is the one allowed
        discover invocation."""
        unscoped = [ln.strip() for ln in WORKFLOW.read_text(encoding="utf-8").splitlines()
                    if "discover -s tests" in ln and "-p " not in ln
                    and not ln.lstrip().startswith("#")]
        self.assertEqual(unscoped, [],
                         "an unscoped full-suite run survives beside the matrix")
        self.assertIn("shard-tests.py", WORKFLOW.read_text(encoding="utf-8"),
                      "no CI step invokes the sharder — the mechanism is unwired")


class ShardWeightFiles(unittest.TestCase):
    """CI speed and bookkeeping change: WEIGHTS was one dict literal in the sharder, so every PR
    adding a test module added a line beside every other PR's and they conflicted. A module's
    weight is now its own tests/shard-weights/<module>.json, which no other change edits."""

    def test_the_sharder_holds_no_per_module_table(self):
        source = SCRIPT.read_text(encoding="utf-8")
        named = [m for m in load_sharder().discover_modules() if f'"{m}"' in source]
        self.assertEqual(named, [], "a weight lives in the shared script again: one file per "
                                    "module (tests/shard-weights/) keeps PRs off each other's lines")

    def test_every_weight_file_names_a_module_and_every_recorded_class_exists(self):
        sh = load_sharder()
        files = sorted(p.stem for p in sh.WEIGHTS_DIR.glob("*.json"))
        self.assertEqual(files, sorted(sh.WEIGHTS), "a weight file did not load")
        for mod, recorded in sorted(sh.CLASS_WEIGHTS.items()):
            live = sh.live_classes(mod)
            with self.subTest(module=mod):
                self.assertTrue(live, f"{mod} records class weights but cannot be split")
                stale = sorted(set(recorded) - set(live))
                self.assertEqual(stale, [], f"{mod} records weights for classes it no longer "
                                            f"has: {stale} — rename them in its weight file")

    def test_each_malformed_weight_file_is_refused_by_name(self):
        sh = load_sharder()
        cases = {
            "test_a.json": ("{", "unreadable"),
            "test_b.json": ("[]", "one JSON object"),
            "test_c.json": ('{"seconds": 1, "measured": "x", "secs": 2}', "unknown keys"),
            "test_d.json": ('{"measured": "x"}', "positive number"),
            "test_e.json": ('{"seconds": 0, "measured": "x"}', "positive number"),
            "test_f.json": ('{"seconds": true, "measured": "x"}', "positive number"),
            "test_g.json": ('{"seconds": 1}', "when and how"),
            "test_h.json": ('{"seconds": 1, "measured": "x", "classes": []}', "class names"),
            "test_i.json": ('{"seconds": 1, "measured": "x", "classes": {"not a name": 1}}',
                            "class names"),
            "test_j.json": ('{"seconds": 1, "measured": "x", "fixture_seconds": 1}',
                            "only a module split by class"),
            "test_k.json": ('{"seconds": 1, "measured": "x", "classes": {"A": 1}, '
                            '"fixture_seconds": -1}', "non-negative"),
            "notes.json": ('{"seconds": 1, "measured": "x"}', "named after a test module"),
        }
        for name, (text, why) in cases.items():
            with self.subTest(file=name), tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / name).write_text(text, encoding="utf-8")
                with self.assertRaises(ValueError) as caught:
                    sh.load_weights(tmp)
                self.assertIn(name, str(caught.exception))
                self.assertIn(why, str(caught.exception))

    def test_a_module_with_no_file_still_runs_on_the_median(self):
        sh = load_sharder()
        weights = {"test_a": 1.0, "test_b": 3.0, "test_c": 9.0}
        shards = sh.partition(["test_a", "test_b", "test_c", "test_new"], 2, weights)
        self.assertEqual(sh.check(shards, ["test_a", "test_b", "test_c", "test_new"]), [])
        self.assertEqual(sh.predicted_wall(["test_new"], weights), 3.0)


class ClassLevelSplitting(unittest.TestCase):
    """A module whose weight file records classes runs as one unit per live TestCase class."""

    def test_a_split_module_runs_every_live_class_once_and_never_whole(self):
        sh = load_sharder()
        self.assertTrue(sh.CLASS_WEIGHTS, "no module is split: the heaviest stays one shard")
        units = [u for shard in sh.partition(sh.discover_modules(), sh.DEFAULT_SHARDS)
                 for u in shard]
        for mod in sorted(sh.CLASS_WEIGHTS):
            with self.subTest(module=mod):
                self.assertNotIn(mod, units, f"{mod} runs whole beside its classes")
                pieces = sorted(u.split(".", 1)[1] for u in units if u.startswith(mod + "."))
                self.assertEqual(pieces, sorted(sh.live_classes(mod)))

    def test_a_class_the_record_has_not_seen_still_runs(self):
        sh = load_sharder()
        live = sh.live_classes("test_shard_tests")
        self.assertGreaterEqual(len(live), 3)
        classes = {"test_shard_tests": {live[0]: 5.0}}  # one recorded, the rest new
        modules = ["test_shard_tests", "test_pins"]
        shards = sh.partition(modules, 2, {"test_shard_tests": 9.0, "test_pins": 1.0}, classes)
        self.assertEqual(sh.check(shards, modules), [])
        units = sorted(u for s in shards for u in s)
        self.assertEqual(units, sorted(["test_pins"] + [f"test_shard_tests.{c}" for c in live]))

    def test_check_names_every_way_a_split_can_go_wrong(self):
        sh = load_sharder()
        live = sh.live_classes("test_shard_tests")
        mods = ["test_shard_tests", "test_pins"]
        every = [f"test_shard_tests.{c}" for c in live]
        cases = (
            ([every[1:], ["test_pins"]], f"test_shard_tests.{live[0]} is in no shard"),
            ([every, ["test_pins", every[0]]], f"test_shard_tests.{live[0]} is in shards 1 and 2"),
            ([every, ["test_pins", "test_shard_tests"]], "runs whole and split by class"),
            ([every + ["test_shard_tests.NoSuchCase"], ["test_pins"]],
             "test_shard_tests.NoSuchCase is sharded but test_shard_tests has no such test class"),
            ([every, ["test_pins", "test_gone.SomeCase"]], "test_gone is sharded but no longer exists"),
        )
        for shards, want in cases:
            with self.subTest(want=want):
                errors = sh.check(shards, mods)
                self.assertTrue(any(want in e for e in errors), errors)
        self.assertEqual(sh.check([every, ["test_pins"]], mods), [])

    def test_a_module_that_cannot_be_split_runs_whole(self):
        sh = load_sharder()
        self.assertIsNone(sh.live_classes("test_no_such_module_anywhere"))
        with mock.patch.object(sh, "live_classes", lambda mod: None):
            units = sh.units(["test_pins"], {"test_pins": 2.0}, {"test_pins": {"Anything": 1.0}})
        self.assertEqual(units, [("test_pins", "test_pins", 2.0)])
        errors = sh.check([["test_pins.Anything"]], ["test_pins"])
        self.assertTrue(any("no such test class" in e for e in errors), errors)

    def test_a_class_unit_runs_by_its_dotted_name(self):
        sh = load_sharder()
        cmd = sh.shard_command(["test_pins", "test_shard_tests.ShardCoverage"], with_coverage=True)
        self.assertEqual(cmd[6:], ["unittest", "tests.test_pins", "tests.test_shard_tests.ShardCoverage"])

    def test_a_split_modules_classes_run_together_and_its_fixture_is_charged_once(self):
        sh = load_sharder()
        weights = {"test_shard_tests": 30.0, "test_pins": 1.0}
        live = sh.live_classes("test_shard_tests")
        classes = {"test_shard_tests": {c: 5.0 for c in live}}
        shards = sh.partition(["test_shard_tests", "test_pins"], 1, weights, classes,
                              {"test_shard_tests": 4.0})
        self.assertEqual(shards[0], sorted(shards[0]), "a shard does not run in sorted order")
        self.assertEqual(sh.predicted_wall(shards[0], weights, classes, {"test_shard_tests": 4.0}),
                         5.0 * len(live) + 4.0 + 1.0)

    def test_at_every_shard_count_each_unit_lands_exactly_once(self):
        sh = load_sharder()
        modules = sh.discover_modules()
        for n in (1, 2, 4, 6, 9):
            with self.subTest(shards=n):
                self.assertEqual(sh.check(sh.partition(modules, n), modules), [])

    def test_the_heaviest_module_no_longer_sets_the_wall(self):
        """The defect this split closes: test_wip_curve alone was the slowest shard (640-745 s
        of CI wall) while the others idled. Split, no shard is far above the mean."""
        sh = load_sharder()
        walls = [sh.predicted_wall(s)
                 for s in sh.partition(sh.discover_modules(), sh.DEFAULT_SHARDS)]
        mean = sum(walls) / len(walls)
        self.assertLessEqual(max(walls), 1.1 * mean, f"shard predictions {walls}")
        self.assertLess(max(walls), max(sh.WEIGHTS.values()),
                        "the heaviest module still sets the critical path")

    def test_the_default_matches_the_ci_matrix(self):
        sh = load_sharder()
        wf = WORKFLOW.read_text(encoding="utf-8")
        found = re.findall(r"shard:\s*\[([0-9,\s]+)\]", wf)
        self.assertTrue(found)
        for m in found:
            self.assertEqual(len(m.split(",")), sh.DEFAULT_SHARDS,
                             "--list and --check describe a different partition than CI runs")

    def test_measure_prints_a_weight_file(self):
        r = subprocess.run([sys.executable, str(SCRIPT), "--measure", "test_pins", "--scale", "2"],
                           capture_output=True, text=True, cwd=ROOT, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr)
        record = json.loads(r.stdout)
        self.assertEqual(set(record), {"seconds", "measured", "classes", "fixture_seconds"})
        self.assertIn("x2 to the CI lane", record["measured"])
        self.assertTrue(record["classes"])
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "test_pins.json").write_text(r.stdout, encoding="utf-8")
            weights, classes, _ = load_sharder().load_weights(tmp)
        self.assertIn("test_pins", weights)
        for bad in (["--measure", "test_no_such_module"], ["--measure", "test_pins", "--scale", "0"]):
            with self.subTest(args=bad):
                r = subprocess.run([sys.executable, str(SCRIPT), *bad],
                                   capture_output=True, text=True, cwd=ROOT, timeout=60)
                self.assertEqual(r.returncode, 2, r.stderr)


class TheCommandLineInProcess(unittest.TestCase):
    """main() and run_shard() in this process, the shard's own unittest run stubbed, so the
    suite's coverage traces the code CI calls (a subprocess of the script would not be)."""

    def main(self, *args, check=None):
        sh = load_sharder()
        calls = []

        def fake_run(cmd, cwd=None):
            calls.append((cmd, cwd))
            return subprocess.CompletedProcess(cmd, 0)

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sh.subprocess, "run", fake_run), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            if check is not None:
                with mock.patch.object(sh, "check", check):
                    rc = sh.main(list(args))
            else:
                rc = sh.main(list(args))
        return rc, out.getvalue(), err.getvalue(), calls, sh

    def test_list_and_check(self):
        rc, out, _, calls, _ = self.main("--list")
        self.assertEqual(rc, 0)
        self.assertEqual(len(re.findall(r"(?m)^shard \d/6: ~", out)), 6, out)
        self.assertEqual(calls, [])
        self.assertEqual(self.main("--check")[0], 0)

    def test_a_shard_runs_its_units_once_under_coverage(self):
        rc, out, _, calls, sh = self.main("--shard", "2", "--with-coverage")
        self.assertEqual(rc, 0)
        shard = sh.partition(sh.discover_modules(), sh.DEFAULT_SHARDS)[1]
        self.assertEqual(calls, [(sh.shard_command(shard, True), sh.ROOT)])
        self.assertIn(f"shard 2/6: {len(shard)} units, predicted ~", out)

    def test_a_broken_partition_runs_nothing(self):
        rc, _, err, calls, _ = self.main("--shard", "1", check=lambda shards, modules: ["boom"])
        self.assertEqual((rc, calls), (1, []))
        self.assertIn("shard-tests: boom", err)
        rc, _, err, _, _ = self.main("--check", check=lambda shards, modules: ["boom"])
        self.assertEqual(rc, 1)
        self.assertIn("shard-tests: boom", err)

    def test_usage_errors_exit_2(self):
        for args in (["--shard", "7"], ["--of", "0"], [], ["--measure", "test_no_such_module"],
                     ["--measure", "test_pins", "--scale", "-1"]):
            with self.subTest(args=args):
                self.assertEqual(self.main(*args)[0], 2)

    def test_measure_in_process(self):
        rc, out, _, _, _ = self.main("--measure", "test_pins")
        self.assertEqual(rc, 0)
        self.assertIn("x1 to the CI lane", json.loads(out)["measured"])


def _load_check():
    spec = importlib.util.spec_from_file_location("_check", ROOT / "scripts" / "check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class LocalCheckCommand(unittest.TestCase):
    """scripts/check.py is the one local command AGENTS.md and CONTRIBUTING.md name (#760)."""

    def setUp(self):
        self.check = _load_check()

    def test_the_plan_runs_validate_ruff_partition_and_every_shard(self):
        steps = dict(self.check.plan(4, ruff="ruff"))
        self.assertEqual(steps["validate"][-1], "scripts/validate.py")
        self.assertEqual(steps["shard-partition"][-3:], ["--check", "--of", "4"])
        for i in range(1, 5):
            self.assertEqual(steps[f"suite {i}/4"][-4:], ["--shard", str(i), "--of", "4"])
        self.assertEqual(len([n for n in steps if n.startswith("suite ")]), 4)

    def test_ruff_lints_exactly_what_ci_lints(self):
        wf = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
        ci = re.search(r"run: ruff check (.+)$", wf, re.M)
        self.assertIsNotNone(ci, "the CI ruff step moved; update check.py's RUFF_PATHS with it")
        self.assertEqual(tuple(ci.group(1).split()), self.check.RUFF_PATHS)
        for rel in self.check.RUFF_PATHS:
            self.assertTrue((ROOT / rel).is_dir(), rel)

    def test_the_documented_commands_name_it_and_lint_paths_that_exist(self):
        contributing = (ROOT / ".github" / "CONTRIBUTING.md").read_text(encoding="utf-8")
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        self.assertIn("python3 scripts/check.py", contributing)
        self.assertIn("python3 scripts/check.py", agents)
        for line in re.findall(r"ruff check ([^\n`]+)", contributing):
            for rel in line.split("#")[0].split():
                with self.subTest(path=rel):
                    self.assertTrue((ROOT / rel).exists(), f"CONTRIBUTING lints a missing path: {rel}")

    def test_a_missing_tool_is_skipped_never_passed(self):
        steps = dict(self.check.plan(1, suite=False, ruff=""))
        self.assertIsNone(steps["ruff"])
        out = io.StringIO()
        results = self.check.run_steps([("ruff", None)], out=out)
        self.assertEqual(results[0][1], "SKIPPED")
        self.assertEqual(self.check.report(results, strict=False, out=out), 0)
        self.assertIn("1 skipped", out.getvalue())
        self.assertEqual(self.check.report(results, strict=True, out=io.StringIO()), 1)

    def test_one_red_step_fails_the_run_and_every_step_still_runs(self):
        ok = [sys.executable, "-c", "print('fine')"]
        bad = [sys.executable, "-c", "import sys; print('the cause'); sys.exit(3)"]
        out = io.StringIO()
        results = self.check.run_steps([("a", ok), ("b", bad), ("c", ok)], out=out)
        self.assertEqual([r[1] for r in results], ["PASS", "FAIL", "PASS"])
        self.assertEqual(self.check.report(results, strict=False, out=out), 1)
        self.assertIn("the cause", out.getvalue(), "a red step must show its own output")
        self.assertIn("check: RED", out.getvalue())

    def test_each_step_is_timed_when_it_finishes_not_when_its_turn_comes(self):
        slow = [sys.executable, "-c", "import time; time.sleep(1.5)"]
        fast = [sys.executable, "-c", "pass"]
        out = io.StringIO()
        results = dict((r[0], r) for r in self.check.run_steps([("slow", slow), ("fast", fast)],
                                                                out=out))
        self.assertLess(results["fast"][2], 1.0, "a quick step inherited the slow step's wait")
        self.assertTrue(out.getvalue().index("fast") < out.getvalue().index("slow"),
                        "steps are reported in completion order")

    def test_jobs_below_one_is_refused(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.check.main(["--jobs", "0", "--plan"])


if __name__ == "__main__":
    unittest.main()
