#!/usr/bin/env python3
"""Contract tests for runtime/scripts/run_report.py — the proof-tier artifact binding.

docs/reviews/2026-09-10-review.md §2.2 / issue #259: before this, `proof: self-run` needed only a file under
docs/runs/ whose name and body mentioned the mission, so a three-line fabricated
report advanced a tier past every gate. These tests are the bypasses, run against
the checker: each one has to be refused.

The fixtures build real git repos, because the mechanism is "re-hash the recorded
paths at the recorded commit" — a fake that never touches git would test nothing.
"""
import base64
import contextlib
import hashlib
import io
import importlib.util
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "run_report", ROOT / "runtime" / "scripts" / "run_report.py"
)
run_report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_report)

INVENTORY_HEADING = "## Run-close integrity inventory (sha256)"


def _git(repo, *args):
    return subprocess.run(
        ["git", *args], cwd=str(repo), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=True,
    ).stdout.strip()


def _report(mission, tier, rev, manifest, verifier, inventory, body=None, header_extra=""):
    rows = "\n".join(f"{digest}  {path}" for digest, path in inventory)
    shown = body if body is not None else (
        f"    python3 runtime/scripts/verify.py --manifest {manifest} --unit-class mutation --lighting lit\n"
        f"    exit {0 if verifier == 'GREEN' else 2}\n"
    )
    return (
        f"# Run report — {mission} {tier}\n\n"
        f"RUN: mission={mission} tier={tier} inventory_at={rev} "
        f"manifest={manifest} verifier={verifier}{header_extra}\n\n"
        f"## Verifier outcome (recorded exactly)\n\n{shown}\n"
        f"{INVENTORY_HEADING}\n\n```\n{rows}\n```\n"
    )


class ExecutionIdentity(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name).resolve()
        self.verifier = self.repo / "runtime/scripts/verify.py"
        self.verifier.parent.mkdir(parents=True)
        self.verifier.write_text("#!/usr/bin/env python3\nprint('REPOSITORY VERIFIER')\n")
        self.verifier.chmod(0o755)
        self.shadow = self.repo / "shadow/runtime/scripts/verify.py"
        self.shadow.parent.mkdir(parents=True)
        self.shadow.write_text("print('SHADOW')\n")
        (self.repo / "inline_module.py").write_text("print('MODULE')\n")

    def observed(self, prefix, script="runtime/scripts/verify.py"):
        argv = [*prefix, script, "--manifest", "m.json"]
        result = subprocess.run(argv, cwd=self.repo, input="", capture_output=True,
                                text=True, timeout=10)
        return shlex.join(argv), result

    def test_interpreter_options_that_skip_the_script_are_rejected(self):
        options = [["-cpass"], ["-ucpass"], ["-c", "pass"], ["-minline_module"],
                   ["-Bm", "inline_module"], ["-m", "inline_module"],
                   ["--version"], ["-V"], ["-VV"], ["-uV"], ["-h"], ["-?"],
                   ["--help"], ["--help-env"], ["--help-xoptions"], ["--help-all"],
                   ["--unknown-option"]]
        for flags in options:
            with self.subTest(flags=flags):
                cmd, result = self.observed([sys.executable, *flags])
                self.assertNotEqual(result.stdout.strip(), "REPOSITORY VERIFIER")
                self.assertFalse(run_report.executes_verifier(cmd, "m.json", self.repo), cmd)

    def test_valid_interpreter_options_still_execute_the_verifier(self):
        for flags in ([], ["-u"], ["-IB"], ["-OO"], ["-W", "ignore"], ["-Wignore"],
                      ["-X", "dev"], ["-Xdev"], ["-uW", "ignore"],
                      ["--check-hash-based-pycs", "always"], ["--"]):
            with self.subTest(flags=flags):
                cmd, result = self.observed([sys.executable, *flags])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "REPOSITORY VERIFIER")
                self.assertTrue(run_report.executes_verifier(cmd, "m.json", self.repo), cmd)

    def test_only_the_exact_repository_script_counts(self):
        for script in ("shadow/runtime/scripts/verify.py", str(self.shadow)):
            with self.subTest(script=script):
                cmd, result = self.observed([sys.executable], script)
                self.assertEqual(result.stdout.strip(), "SHADOW")
                self.assertFalse(run_report.executes_verifier(cmd, "m.json", self.repo), cmd)
        for prefix, script in (([sys.executable], str(self.verifier)),
                               ([sys.executable], "./runtime/scripts/verify.py"),
                               ([], "./runtime/scripts/verify.py")):
            with self.subTest(prefix=prefix, script=script):
                cmd, result = self.observed(prefix, script)
                self.assertEqual(result.stdout.strip(), "REPOSITORY VERIFIER")
                self.assertTrue(run_report.executes_verifier(cmd, "m.json", self.repo), cmd)

    def test_xoption_values_that_abort_initialization_are_rejected(self):
        # CPython 3.13 --help-xoptions and using/cmdline.html define these value constraints.
        options = ["int_max_str_digits", "int_max_str_digits=1", "int_max_str_digits=-1",
                   "int_max_str_digits=abc", "int_max_str_digits=2147483648",
                   "utf8=", "utf8=2", "frozen_modules=bad",
                   "tracemalloc=-1", "tracemalloc=abc", "tracemalloc=65536",
                   "tracemalloc=2147483648"]
        if sys.version_info >= (3, 13):  # cpu_count/gil were introduced in 3.13
            options += ["cpu_count", "cpu_count=0", "cpu_count=-1", "cpu_count=abc",
                        "cpu_count=2147483648", "gil", "gil=2"]
        for option in options:
            for flags in (["-X", option], ["-uX" + option]):
                with self.subTest(flags=flags):
                    cmd, result = self.observed([sys.executable, *flags])
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("REPOSITORY VERIFIER", result.stdout)
                    self.assertFalse(run_report.executes_verifier(cmd, "m.json", self.repo), cmd)

    def test_valid_xoption_values_preserve_actual_script_execution(self):
        options = ["int_max_str_digits=0", "int_max_str_digits=640", "int_max_str_digits=",
                   "int_max_str_digits=+640", "utf8", "utf8=0", "utf8=1",
                   "frozen_modules", "frozen_modules=", "frozen_modules=on", "frozen_modules=off",
                   "tracemalloc", "tracemalloc=", "tracemalloc=0", "tracemalloc=1", "dev",
                   "arbitrary=value"]
        if sys.version_info >= (3, 13):
            options += ["cpu_count=default", "cpu_count=1", "gil=1"]
        for option in options:
            for flags in (["-X", option], ["-X" + option]):
                with self.subTest(flags=flags):
                    cmd, result = self.observed([sys.executable, *flags])
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), "REPOSITORY VERIFIER")
                    self.assertTrue(run_report.executes_verifier(cmd, "m.json", self.repo), cmd)

    def test_repeated_xoptions_use_the_first_initialization_value(self):
        for values, expected in ((["utf8=1", "utf8=2"], True), (["utf8=2", "utf8=1"], False)):
            with self.subTest(values=values):
                cmd, result = self.observed([sys.executable, "-X", values[0], "-X", values[1], "--"])
                self.assertEqual(result.stdout.strip() == "REPOSITORY VERIFIER", expected)
                self.assertEqual(run_report.executes_verifier(cmd, "m.json", self.repo), expected)


class RunDirectoryBinding(unittest.TestCase):
    """#382 + PR #387 review: the mission match must be token-contiguous, never substring —
    and the first fix's anchored regex was dead code under the glob's own naming convention."""

    def _run_dir(self, dirs, mission, stem):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp) / "docs" / "runs"
            for d in dirs:
                (runs / d).mkdir(parents=True)
            report = runs / f"{stem}.md"
            report.write_text("x", encoding="utf-8")
            return run_report.run_directory(report, mission, Path(tmp))

    def test_a_prefix_colliding_directory_is_not_borrowed(self):
        got = self._run_dir(["2026-09-14-map-iteration"], "map-it", "2026-09-14-map-it-selfrun")
        self.assertEqual(got, "docs/runs/2026-09-14-map-it-selfrun",
                         "map-it matched the map-iteration directory")

    def test_the_real_directory_is_found(self):
        got = self._run_dir(["2026-09-13-pin-it-266", "2026-09-14-pin-its-neighbor"],
                            "pin-it", "2026-09-13-pin-it-266-selfrun")
        self.assertEqual(got, "docs/runs/2026-09-13-pin-it-266")

    def test_a_same_day_sibling_run_does_not_lend_its_directory(self):
        # #694 review: two same-day runs of one mission. The report named for its own directory
        # gets that directory, never the alphabetically first one the fuzzy match finds.
        days = ["2026-10-25-trajectories-602-adapters", "2026-10-25-trajectories-602-live"]
        for stem in days:
            with self.subTest(report=stem):
                self.assertEqual(self._run_dir(days, "trajectories", stem), f"docs/runs/{stem}")

    def test_each_legacy_report_keeps_its_directory(self):
        # The four reports bound before a run's directory had to be named for its report.
        for stem, mission, directory in (
                ("2026-08-28-ship-it-self-run", "ship-it", "2026-08-28-ship-it-selfrun"),
                ("2026-09-14-clean-sweep-self-run", "clean-sweep", "2026-09-14-clean-sweep-tracker"),
                ("2026-09-16-prove-it-self-run", "prove-it", "2026-09-16-prove-it-selfrun"),
                ("2026-09-21-harden-it-self-run", "harden-it", "2026-09-21-harden-it-selfrun")):
            with self.subTest(report=stem):
                self.assertEqual(self._run_dir([directory], mission, stem), f"docs/runs/{directory}")

    def test_an_ambiguous_fuzzy_match_fails_closed(self):
        # Neither candidate is named for the report: both match, so neither is borrowed.
        got = self._run_dir(["2026-10-25-trajectories-a", "2026-10-25-trajectories-b"],
                            "trajectories", "2026-10-25-trajectories-c")
        self.assertEqual(got, "docs/runs/2026-10-25-trajectories-c")


class WipCurveObligation(unittest.TestCase):
    """#365: the per-wave WIP row was mandated by attention-budget.md and machine-checked nowhere."""

    def test_mutation_missions_come_from_the_evidence_manifest(self):
        missions = run_report._mutation_missions(ROOT)
        self.assertIsNotNone(missions)
        self.assertIn("ship-it", missions)
        self.assertIn("absorb-it", missions)
        self.assertNotIn("review-it", missions)  # report-only: no dispatch waves
        self.assertNotIn("map-it", missions)     # planning
        self.assertIn("offload-it", missions)    # lands a recipe through a PR since #626
        self.assertEqual(len(missions), 18)

    def test_a_mutating_report_without_a_wip_row_does_not_bind(self):
        errs = run_report._wip_curve_errors("RUN: x\nno curve here\n", "ship-it", ROOT, "r.md")
        self.assertEqual(len(errs), 1, errs)
        self.assertIn("WIP-curve", errs[0])

    def test_a_mutating_report_with_a_wip_row_binds(self):
        # #389: this test used to bless `| 1 | builders=4 reviewers=2 | 3.1 |` — a settings row
        # with one unlabelled number, which is the bug. The row now carries the protocol's schema.
        body = (f"RUN: mission=ship-it waves=1\n\n{self.SECTION}\n\n"
                "| wave=1 | builders=4 reviewers=2 | throughput=3.1/h | latency_median=9m "
                "| latency_max=31m | rework=1/5 | freshness=0 |\n")
        self.assertEqual(run_report._wip_curve_errors(body, "ship-it", ROOT, "r.md"), [])

    # #389: the rows below are the protocol's own words (attention-budget.md §"The WIP-curve
    # protocol"), never rebuilt from the checker's pattern — a settings row is not a data point.
    def test_a_settings_only_row_is_refused(self):
        # Each case names the check that has to fire, so one leg cannot stand in for another.
        no_metrics = "carries no measured ['throughput', 'latency_median', 'latency_max', 'rework'"
        for row, expected in (("| 1 | builders=4 reviewers=2 | 3.1 |", "— none found;"),
                              ("| wave=1 | builders=4 reviewers=2 |", no_metrics),
                              ("| deviation | raised mid-run to builders=3 reviewers=1 |",
                               "— none found;")):
            with self.subTest(row=row):
                body = f"RUN: mission=ship-it waves=1\n\n{self.SECTION}\n\n{row}\n"
                errs = run_report._wip_curve_errors(body, "ship-it", ROOT, "r.md")
                self.assertTrue(any(expected in e for e in errs),
                                f"a settings-only row bound as a WIP-curve data point: {row} {errs}")

    ROW_1 = ("| wave=1 | builders=3 reviewers=1 | throughput=1.5/h | latency_median=12m "
             "| latency_max=40m | rework=0/3 | freshness=0 |")
    ROW_2 = ("| wave=2 | builders=2 reviewers=1 | throughput=0.8/h | latency_median=20m "
             "| latency_max=55m | rework=1/2 | freshness=1 |")

    def test_a_multi_wave_report_with_partial_or_missing_wave_rows_is_refused(self):
        # One complete row per recorded wave: the waves the report records are 1..n of its RUN:
        # header's waves=<n> (attention-budget.md). A row standing in for the others, a wave with
        # no row, a row whose metric is absent, and a count recorded nowhere each fail to bind.
        partial_2 = self.ROW_2.replace("| latency_max=55m ", "")
        no_row_for_2 = "RUN: waves=2 but no WIP-curve row for wave(s) [2]"
        cases = {
            "one row for three waves": ("waves=3", [self.ROW_1],
                                        "RUN: waves=3 but no WIP-curve row for wave(s) [2, 3]"),
            "wave 2 of 2 has no row": ("waves=2", [self.ROW_1], no_row_for_2),
            "wave 2 row lacks latency_max": ("waves=2", [self.ROW_1, partial_2],
                                             "carries no measured ['latency_max']"),
            "wave 1 recorded twice, wave 2 never": ("waves=2", [self.ROW_1, self.ROW_1],
                                                    no_row_for_2),
            "a row for an unrecorded wave": ("waves=1", [self.ROW_1, self.ROW_2],
                                             "wave(s) [2] outside the recorded waves 1..1"),
            "no waves= recorded at all": ("", [self.ROW_1, self.ROW_2], "RUN: waves=<missing>"),
        }
        for name, (waves, rows, expected) in cases.items():
            with self.subTest(case=name):
                body = f"RUN: mission=ship-it {waves}\n\n{self.SECTION}\n\n" + "\n".join(rows) + "\n"
                errs = run_report._wip_curve_errors(body, "ship-it", ROOT, "r.md")
                self.assertTrue(any(expected in e for e in errs),
                                f"{name}: bound with incomplete per-wave rows {errs}")

    def test_a_wave_carrying_two_rows_is_refused_with_none_missing(self):
        # Verdict r1 (PR #391): the doubled-wave check only ever ran beside a missing wave, so a
        # mutant without it stayed green. Here waves 1..2 each have a row and wave 1 has two.
        body = (f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n"
                + "\n".join([self.ROW_1, self.ROW_1, self.ROW_2]) + "\n")
        errs = run_report._wip_curve_errors(body, "ship-it", ROOT, "r.md")
        self.assertEqual(len(errs), 1, errs)
        self.assertIn("wave(s) [1] carry more than one WIP-curve row", errs[0])

    def test_a_wave_that_is_not_a_number_is_refused_without_crashing(self):
        # wave=one names a wave, so the row is a WIP-curve row, but it names no number: refused as
        # a cell, and kept out of the per-wave count rather than crashing int().
        row = self.ROW_1.replace("wave=1", "wave=one")
        body = f"RUN: mission=ship-it waves=1\n\n{self.SECTION}\n\n{row}\n"
        errs = run_report._wip_curve_errors(body, "ship-it", ROOT, "r.md")
        self.assertTrue(any("carries no measured ['wave']" in e for e in errs), errs)

    def test_a_wave_that_is_not_an_integer_is_refused(self):
        # Verdict r2: wave=1.5 is digit-led, so the metric rule would take it, and the per-wave
        # count skips it — beside a complete wave 1 row, only the integer rule refuses it.
        row = self.ROW_2.replace("wave=2", "wave=1.5")
        body = (f"RUN: mission=ship-it waves=1\n\n{self.SECTION}\n\n"
                + "\n".join([self.ROW_1, row]) + "\n")
        errs = run_report._wip_curve_errors(body, "ship-it", ROOT, "r.md")
        self.assertEqual(len(errs), 1, errs)
        self.assertIn("carries no measured ['wave']", errs[0])

    def test_a_zero_wave_count_is_refused(self):
        body = f"RUN: mission=ship-it waves=0\n\n{self.SECTION}\n\n{self.ROW_1}\n"
        errs = run_report._wip_curve_errors(body, "ship-it", ROOT, "r.md")
        self.assertTrue(any("RUN: waves=0 — a mutating run records" in e for e in errs), errs)

    def test_a_wave_count_that_is_not_a_number_is_refused_without_crashing(self):
        # Verdict r2: waves=two reaches int() only past the digit guard — without it the checker
        # raised ValueError instead of refusing the header.
        body = f"RUN: mission=ship-it waves=two\n\n{self.SECTION}\n\n{self.ROW_1}\n"
        errs = run_report._wip_curve_errors(body, "ship-it", ROOT, "r.md")
        self.assertEqual(len(errs), 1, errs)
        self.assertIn("RUN: waves=two — a mutating run records", errs[0])

    def test_a_run_header_carrying_waves_twice_is_refused(self):
        # Verdict r1: dict() kept the LAST waves=, so `waves=3 waves=1` plus one row bound on the 1
        # while the same header said three waves ran — the F3 collapse, one line up.
        body = f"RUN: mission=ship-it waves=3 waves=1\n\n{self.SECTION}\n\n{self.ROW_1}\n"
        errs = run_report._wip_curve_errors(body, "ship-it", ROOT, "r.md")
        self.assertEqual(len(errs), 1, errs)
        self.assertIn("RUN: header carries waves= more than once", errs[0])

    def test_a_row_with_placeholder_metrics_is_refused(self):
        # Verdict r1: every key present, no value measured. Only the digit-led metric rule refuses
        # it — a mutant taking any non-blank value stayed green.
        row = (self.ROW_1.replace("throughput=1.5/h", "throughput=TBD")
               .replace("latency_median=12m", "latency_median=?"))
        body = f"RUN: mission=ship-it waves=1\n\n{self.SECTION}\n\n{row}\n"
        errs = run_report._wip_curve_errors(body, "ship-it", ROOT, "r.md")
        self.assertEqual(len(errs), 1, errs)
        self.assertIn("carries no measured ['throughput', 'latency_median']", errs[0])

    def test_a_wip_setting_that_is_not_an_integer_is_refused(self):
        # The settings are counts. builders=two is no number at all; builders=2.5 and reviewers=2.5
        # are ones the digit-led metric rule would take, so only the integer rule refuses them —
        # for each setting, since dropping one key from the rule is one line (verdict r2).
        for cell, value in (("builders=3", "builders=two"), ("builders=3", "builders=2.5"),
                            ("reviewers=1", "reviewers=2.5")):
            with self.subTest(setting=value):
                row = self.ROW_1.replace(cell, value)
                body = f"RUN: mission=ship-it waves=1\n\n{self.SECTION}\n\n{row}\n"
                errs = run_report._wip_curve_errors(body, "ship-it", ROOT, "r.md")
                self.assertEqual(len(errs), 1, errs)
                self.assertIn(f"carries no measured ['{value.split('=')[0]}']", errs[0])

    def test_a_row_carrying_a_cell_twice_is_refused(self):
        # PR #391 review (P2): a copy-edited row kept only the LAST occurrence of each key, so
        # throughput=TBD throughput=1 bound on the 1 while still saying it was never measured.
        row = self.ROW_1.replace("throughput=1.5/h", "throughput=TBD throughput=1")
        body = f"RUN: mission=ship-it waves=1\n\n{self.SECTION}\n\n{row}\n"
        errs = run_report._wip_curve_errors(body, "ship-it", ROOT, "r.md")
        self.assertTrue(any("carries ['throughput'] more than once" in e for e in errs), errs)

    def test_complete_per_wave_rows_bind(self):
        # Cell order and extra cells are free; only the schema's cells are owed, once per wave.
        reordered = ("| wave=2 | note: second wave | freshness=1 | rework=1/2 | throughput=0.8/h "
                     "| builders=2 reviewers=1 | latency_max=55m | latency_median=20m |")
        for rows in ([self.ROW_1, self.ROW_2], [self.ROW_1, reordered]):
            with self.subTest(rows=rows):
                body = f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n" + "\n".join(rows) + "\n"
                self.assertEqual(run_report._wip_curve_errors(body, "ship-it", ROOT, "r.md"), [])

    # #387: the rows are the ones in the report's WIP-curve section (docs/runs/TEMPLATE.md's
    # heading, below) and nowhere else. Scanning every pipe-prefixed line bound a complete row
    # quoted in a fenced example or a deviations table as the run's evidence.
    SECTION = "## WIP-curve protocol row (mutating self-runs)"
    DEVIATIONS = ("## Deviations and lessons (recorded, not hidden)\n\n"
                  "| Deviation | Detail |\n|---|---|\n")

    def test_complete_rows_outside_the_wip_curve_section_do_not_bind(self):
        template = (ROOT / "docs" / "runs" / "TEMPLATE.md").read_text(encoding="utf-8")
        self.assertIn(f"\n{self.SECTION}\n", template, "the fixture's heading is not the template's")
        rows = f"{self.ROW_1}\n{self.ROW_2}\n"
        section = f"{self.SECTION}\n\nNot measured to protocol this run.\n\n"
        cases = {
            "a fenced example inside the section": f"{section}```\n{rows}```\n",
            "a tilde-fenced example inside the section": f"{section}~~~text\n{rows}~~~\n",
            "a deviations table": f"{section}{self.DEVIATIONS}{rows}",
            "a fenced example and a deviations table": (f"{section}```\n{self.ROW_1}\n```\n\n"
                                                        f"{self.DEVIATIONS}{self.ROW_2}\n"),
            "another section, and no WIP-curve section": f"## Pipeline evidence\n\n{rows}",
            "rows before any heading": rows,
            "the section heading quoted inside a fence": f"```markdown\n{self.SECTION}\n\n{rows}```\n",
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                report = f"RUN: mission=ship-it waves=2\n\n{body}"
                errs = run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md")
                self.assertTrue(any("— none found;" in e and "WIP-curve protocol row" in e
                                    for e in errs),
                                f"{name}: bound on rows outside the WIP-curve section {errs}")

    def test_rows_outside_the_section_do_not_count_against_the_rows_inside_it(self):
        # The false fail: the section is complete, and rows quoted elsewhere (an example of wave 1,
        # a deviation about wave 2's WIP, a third wave planned and never run) tripped the
        # duplicate, unmeasured-row and stray-wave checks. The fence comes first, so a fence that
        # never closed would swallow the real rows.
        report = (f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n"
                  f"Filled in as the protocol's example shows:\n\n```text\n{self.ROW_1}\n```\n\n"
                  "| Wave | WIP setting | Throughput | Latency | Rework | Freshness |\n"
                  f"|---|---|---|---|---|---|\n{self.ROW_1}\n{self.ROW_2}\n\n{self.DEVIATIONS}"
                  "| wave=2 | raised mid-run to builders=3 reviewers=1 |\n"
                  f"{self.ROW_2.replace('wave=2', 'wave=3')}\n")
        self.assertEqual(run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md"), [])

    def test_an_incomplete_section_row_is_refused_whatever_lies_outside(self):
        # Completeness still binds inside the section: the unmeasured row is refused naming its
        # wave, and a complete copy outside the section neither rescues it nor doubles the wave.
        partial_2 = self.ROW_2.replace("| latency_max=55m ", "")
        report = (f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n{self.ROW_1}\n{partial_2}\n\n"
                  f"{self.DEVIATIONS}{self.ROW_2}\n")
        errs = run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md")
        self.assertEqual(len(errs), 1, errs)
        self.assertIn("| wave=2 |", errs[0])
        self.assertIn("carries no measured ['latency_max']", errs[0])

    def test_the_section_heading_tolerates_its_real_spellings(self):
        # The template's heading, the 2026-08-28 ship-it report's, and loose whitespace, a deeper
        # level or a closing sequence around them.
        for heading in (self.SECTION,
                        "## WIP-curve protocol row (qualitative first observation — NOT a "
                        "protocol-compliant data point)",
                        "##   WIP-curve protocol row   ", "### WIP-curve \t protocol  row",
                        "   ## WIP-curve protocol row (mutating self-runs) ##"):
            with self.subTest(heading=heading):
                report = f"RUN: mission=ship-it waves=2\n\n{heading}\n\n{self.ROW_1}\n{self.ROW_2}\n"
                self.assertEqual(run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md"), [])

    def test_a_look_alike_heading_does_not_open_the_section(self):
        # Verdict r1 (F-1): any heading beginning 'WIP curve' opened the section, so another run's
        # quoted example bound as this run's evidence. Only the protocol's heading opens it.
        rows = f"{self.ROW_1}\n{self.ROW_2}\n"
        # Verdict r2 (N-1): the heading's case and its word boundary after 'row' are the anchor too.
        for heading in ("## WIP-curve example (from another run)",
                        "## Deviations — WIP-curve cap raised", "## WIP curve", "### WIP \t curve",
                        "## WIP-curve protocol rows", "## wip-curve protocol row"):
            with self.subTest(heading=heading):
                report = f"RUN: mission=ship-it waves=2\n\n{heading}\n\n{rows}"
                errs = run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md")
                self.assertTrue(any("— none found;" in e and "WIP-curve protocol row" in e
                                    for e in errs), f"{heading!r} opened the section {errs}")
        # Nor does a look-alike after the section reopen it: a wave planned and never run, quoted
        # under it, is not a stray row of this run.
        report = (f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n{rows}\n"
                  f"## WIP-curve example (from another run)\n\n{self.ROW_2.replace('wave=2', 'wave=3')}\n")
        self.assertEqual(run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md"), [])

    def test_a_fence_closes_only_on_a_bare_run_of_its_own_character_at_least_as_long(self):
        # Verdict r1 (R2): the CommonMark closing rule went unwitnessed — "any fence line closes"
        # kept the suite green. Each second line below is content of the example's fence, so the
        # wave=3 row after it is still the example's; the real closer then ends the fence.
        stray = self.ROW_2.replace("wave=2", "wave=3")
        for name, fenced in {"a shorter run": f"````\n```\n{stray}\n````\n",
                             "the other character": f"```\n~~~\n{stray}\n```\n",
                             "an info string": f"```\n```text\n{stray}\n```\n"}.items():
            with self.subTest(case=name):
                report = (f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n{fenced}\n"
                          f"{self.ROW_1}\n{self.ROW_2}\n")
                self.assertEqual(run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md"), [])

    def test_a_backtick_run_with_a_backtick_after_it_opens_no_fence(self):
        # PR #401 review (P2): CommonMark opens no backtick fence whose info string holds a
        # backtick, so '```text`example``' is prose with inline code, not a fence swallowing the
        # rows after it. A tilde fence's info string may hold one, and that fence still opens.
        rows = f"{self.ROW_1}\n{self.ROW_2}\n"
        report = f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n```text`example``\n\n{rows}"
        self.assertEqual(run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md"), [])
        tilde = f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n~~~text`example``\n{rows}~~~\n"
        errs = run_report._wip_curve_errors(tilde, "ship-it", ROOT, "r.md")
        self.assertTrue(any("— none found;" in e for e in errs), errs)

    def test_a_setext_heading_after_the_section_ends_it(self):
        # Verdict r1: only an ATX heading ended the section, so a 'Deviations' line underlined as a
        # setext heading left it open, and the rows under that heading bound as the run's evidence.
        rows = f"{self.ROW_1}\n{self.ROW_2}\n"
        for underline in ("---", "==="):
            with self.subTest(underline=underline):
                report = (f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n"
                          f"Not measured to protocol this run.\n\nDeviations\n{underline}\n\n{rows}")
                errs = run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md")
                self.assertTrue(any("— none found;" in e and "WIP-curve protocol row" in e
                                    for e in errs), f"bound under a setext heading {errs}")
        # After a blank line --- is a thematic break, not a heading: the section stays open.
        report = f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\nA note.\n\n---\n\n{rows}"
        self.assertEqual(run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md"), [])

    def test_a_list_item_or_block_quote_underlined_does_not_end_the_section(self):
        # PR #401 review (P1 4012744258): only a plain paragraph can be underlined. After a list
        # item or a block quote, or a lazy continuation of one, --- is a thematic break and === is
        # more of its text (CommonMark), so the section stays open and its complete rows bind.
        rows = f"{self.ROW_1}\n{self.ROW_2}\n"
        for name, lead in {"a list item, ---": "- a note\n---",
                           "an ordered list item, ---": "1. a note\n---",
                           "a block quote, ---": "> a note\n---",
                           "a list item, ===": "- a note\n===",
                           "a list item's continuation, ---": "- a note\nthat runs on\n---",
                           "a block quote's continuation, ---": "> a note\nthat runs on\n---"}.items():
            with self.subTest(case=name):
                report = f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n{lead}\n\n{rows}"
                self.assertEqual(run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md"), [])

    def test_a_row_after_a_list_item_and_a_thematic_break_is_still_read(self):
        # PR #401 review (P1 4012744258), the fail-open side: closing the section on a list item's
        # --- hid an incomplete second wave=2 row after it, and the report bound [].
        partial_2 = self.ROW_2.replace("| latency_max=55m ", "")
        report = (f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n{self.ROW_1}\n{self.ROW_2}\n\n"
                  f"- a note\n---\n\n{partial_2}\n")
        errs = run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md")
        self.assertTrue(any("| wave=2 |" in e and "carries no measured ['latency_max']" in e
                            for e in errs), f"the row after the break was not read {errs}")
        self.assertTrue(any("wave(s) [2] carry more than one WIP-curve row" in e for e in errs),
                        errs)

    def test_indented_code_is_never_underlined(self):
        # Verdict r4 (STANDARDS S-2, SPEC C-2): a line four spaces past its container's column is
        # indented code, not a paragraph, so a --- or === under it underlines nothing (CommonMark).
        # Read as a paragraph, '    note' / '---' closed the section and hid an incomplete second
        # wave=2 row after it, and the report bound [] where base refused it twice.
        # Verdict r5 (SPEC F-1, TEST T5-1): a tab runs to the next column that is a multiple of 4,
        # so a tab reaches the same four columns; counting spaces only, '\tnote' was a paragraph
        # and '  \tnote' after an empty item one at column 2, both underlined (markdown-it-py).
        partial_2 = self.ROW_2.replace("| latency_max=55m ", "")
        for name, code in {"at the margin, ---": "    note\n---",
                           "at the margin, ===": "    note\n===",
                           "a list item's first block, ---": "-     note\n  ---",
                           "a list item's block after a blank line, ---": "- a\n\n      note\n  ---",
                           "a tab at the margin, ---": "\tnote\n---",
                           "a tab after two spaces, after an empty item and a blank line, ===":
                               "*\n\n  \tnote\n===",
                           "tabs after the marker, a list item's first block, ---": "-\t\tnote\n  ---"
                           }.items():
            with self.subTest(case=name):
                report = (f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n{self.ROW_1}\n"
                          f"{self.ROW_2}\n\n{code}\n\n{partial_2}\n")
                errs = run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md")
                self.assertEqual(len(errs), 2, errs)
                self.assertTrue(any("| wave=2 |" in e and "carries no measured ['latency_max']" in e
                                    for e in errs), f"the row after the code was not read {errs}")
                self.assertTrue(any("wave(s) [2] carry more than one WIP-curve row" in e
                                    for e in errs), errs)
        # Verdict r5 (TEST T5-2): three spaces short of that is still a paragraph, and underlined
        # it is a setext heading that ends the section (markdown-it-py).
        with self.subTest(case="three spaces in, a paragraph, ---"):
            report = (f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n   Deviations\n---\n\n"
                      f"{self.ROW_1}\n{self.ROW_2}\n")
            errs = run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md")
            self.assertTrue(any("— none found;" in e for e in errs),
                            f"bound under a setext heading {errs}")

    def test_a_thematic_break_after_a_table_row_a_heading_or_a_fence_keeps_the_section_open(self):
        # Verdict r2 (TEST R-1): each paragraph-gate exclusion is witnessed on its own. Straight
        # after a table row, the section heading or a closed fence, --- underlines nothing, so the
        # wave=2 row after it is still the section's: complete it binds, incomplete it is refused.
        partial_2 = self.ROW_2.replace("| latency_max=55m ", "")
        for name, lead in {"a table row": f"\n{self.ROW_1}\n---\n",
                           "the section heading": f"---\n{self.ROW_1}\n",
                           "a closed fence": f"\n```text\nan example\n```\n---\n{self.ROW_1}\n"}.items():
            with self.subTest(case=name):
                report = f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n{lead}"
                self.assertEqual(run_report._wip_curve_errors(f"{report}{self.ROW_2}\n", "ship-it",
                                                              ROOT, "r.md"), [])
                errs = run_report._wip_curve_errors(f"{report}{partial_2}\n", "ship-it", ROOT, "r.md")
                self.assertEqual(len(errs), 1, errs)
                self.assertIn("| wave=2 |", errs[0])
                self.assertIn("carries no measured ['latency_max']", errs[0])

    def test_an_ordered_item_not_numbered_1_under_a_paragraph_line_is_its_text(self):
        # PR #401 review (P1 4013204408, verdict r3 F-2): a list item interrupts a paragraph only
        # with content, and an ordered one only from 1 (CommonMark). So 'Deviations / 2. x / ---'
        # is one paragraph underlined, a setext heading: the section ends, and the rows under it
        # are not the run's. '1. x' does interrupt, and the --- after it is a thematic break.
        rows = f"{self.ROW_1}\n{self.ROW_2}\n"
        for name, lead in {"2.": "Deviations\n2. raised mid-run\n---",
                           "10)": "Deviations\n10) raised mid-run\n---",
                           "an empty item": "Deviations\n*\n---"}.items():
            with self.subTest(case=name):
                report = (f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n"
                          f"Not measured to protocol this run.\n\n{lead}\n\n{rows}")
                errs = run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md")
                self.assertTrue(any("— none found;" in e and "WIP-curve protocol row" in e
                                    for e in errs), f"bound under a setext heading {errs}")
        report = f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\nA note:\n1. raised mid-run\n---\n\n{rows}"
        self.assertEqual(run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md"), [])

    def test_a_list_items_paragraph_after_a_blank_line_is_still_in_the_list(self):
        # PR #401 review (P1 4013204408, verdict r3 F-1): a line indented to a list item's content
        # after a blank line is that item's paragraph, not a plain one, so a --- at the margin
        # after it is a thematic break (CommonMark). Complete rows after it bind, and an incomplete
        # second wave=2 row after it is refused naming the wave, never hidden.
        partial_2 = self.ROW_2.replace("| latency_max=55m ", "")
        head = f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n"
        # Text five spaces past its marker is indented code in the item, whose content starts at
        # column 2, not 7 (CommonMark), so the line at column 2 is still the item's. Verdict r5
        # (TEST T5-3, T5-4): an empty item given content on its next line is no longer empty, so a
        # blank line after that keeps it; and a blank line after a nested empty item ends only
        # that item, not the one holding it (markdown-it-py).
        for name, item in {"a list item": "- a note\n\n  that runs on",
                           "an ordered item, content at column 4": "10. a note\n\n    that runs on",
                           "text five spaces past the marker": "-     a note\n\n  that runs on",
                           "an empty item's content on the next line": "-\n  a note\n\n  that runs on",
                           "after a nested empty item and a blank line":
                               "- a\n\n  -\n\n  that runs on"}.items():
            with self.subTest(case=name, rows="complete"):
                complete = f"{head}{item}\n---\n\n{self.ROW_1}\n{self.ROW_2}\n"
                self.assertEqual(run_report._wip_curve_errors(complete, "ship-it", ROOT, "r.md"), [])
            with self.subTest(case=name, rows="an incomplete second wave=2"):
                hidden = f"{head}{self.ROW_1}\n{self.ROW_2}\n\n{item}\n---\n\n{partial_2}\n"
                errs = run_report._wip_curve_errors(hidden, "ship-it", ROOT, "r.md")
                self.assertTrue(any("| wave=2 |" in e and "carries no measured ['latency_max']" in e
                                    for e in errs), f"the row after the break was not read {errs}")
                self.assertTrue(any("wave(s) [2] carry more than one WIP-curve row" in e
                                    for e in errs), errs)
        # Underlined at the item's own column, that paragraph is a heading; so is a line back at
        # the margin, or short of an item whose text starts three or four spaces past its marker,
        # which has left the list. Either ends the section. So does a line after an empty item and
        # a blank line: an item begins with at most one blank line, so the item ended empty
        # (CommonMark; verdict r4 SPEC S4-1).
        for name, lead in {"at column 2": "- a note\n\n  Deviations\n  ---",
                           "at column 4": "10. a note\n\n    Deviations\n    ---",
                           "back at the margin": "- a note\n\nDeviations\n---",
                           "short of the item's column 4": "-   a note\n\n  Deviations\n---",
                           "short of the item's column 5": "-    a note\n\n  Deviations\n---",
                           "after an empty item and a blank line, ---": "-\n\n  Deviations\n---",
                           "after an empty item and a blank line, ===": "*\n\n  Deviations\n===",
                           # A tab after the marker runs to column 4 (verdict r5): content at 4.
                           "a tab after the marker, at column 4": "-\tDeviations\n    ---"
                           }.items():
            with self.subTest(case=name, rows="under a setext heading"):
                report = f"{head}{lead}\n\n{self.ROW_1}\n{self.ROW_2}\n"
                errs = run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md")
                self.assertTrue(any("— none found;" in e for e in errs), errs)

    def test_a_fence_nested_in_a_list_item_hides_its_rows(self):
        # Verdict r3 (F-3): a fence may sit up to three spaces past the content column of the list
        # item holding it, so an example fenced four or more spaces deep is still code (CommonMark),
        # and its rows are not the run's: alone they are none found, and beside the real rows a
        # wave=3 example is no stray wave.
        stray = self.ROW_2.replace("wave=2", "wave=3")
        for name, nested in {"an ordered item": "1. Filled in as the example shows:\n\n"
                                                "    ```text\n    {row}\n    ```\n",
                             "a nested item": "- Example\n  - quoted from another run:\n\n"
                                              "      ~~~\n      {row}\n      ~~~\n"}.items():
            head = f"RUN: mission=ship-it waves=1\n\n{self.SECTION}\n\n"
            with self.subTest(case=name, rows="the example alone"):
                errs = run_report._wip_curve_errors(f"{head}{nested.format(row=self.ROW_1)}",
                                                    "ship-it", ROOT, "r.md")
                self.assertTrue(any("— none found;" in e for e in errs),
                                f"bound on a fenced example {errs}")
            with self.subTest(case=name, rows="a wave=3 example beside the real row"):
                report = f"{head}{nested.format(row=stray)}\n{self.ROW_1}\n"
                self.assertEqual(run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md"), [])
        # A nested fence ends at its own closer, so the item's content after it is read: a closer
        # looked for only near the margin never matched, and the fence swallowed the item's real row
        # (mutant M13g; since verdict r5 F-2 a row back at the margin ends the fence regardless).
        with self.subTest(case="the item's row after its closed fence"):
            report = (f"RUN: mission=ship-it waves=1\n\n{self.SECTION}\n\n"
                      f"1. Filled in as the example shows:\n\n    ```text\n    {stray}\n    ```\n\n"
                      f"    {self.ROW_1}\n")
            self.assertEqual(run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md"), [])
        # Verdict r5 (SPEC F-2): and only while its item lasts. A line left of the item's content
        # column ends the item, and an unclosed fence in it with it (markdown-it-py), so an
        # incomplete second wave=2 row after that line is read, never swallowed as code.
        with self.subTest(case="an unclosed fence ends with its item"):
            partial_2 = self.ROW_2.replace("| latency_max=55m ", "")
            report = (f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n{self.ROW_1}\n{self.ROW_2}\n\n"
                      f"- a note\n  ```\n  example\n\nNext paragraph.\n\n{partial_2}\n")
            errs = run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md")
            self.assertEqual(len(errs), 2, errs)
            self.assertTrue(any("| wave=2 |" in e and "carries no measured ['latency_max']" in e
                                for e in errs), f"the row after the item was not read {errs}")
            self.assertTrue(any("wave(s) [2] carry more than one WIP-curve row" in e for e in errs),
                            errs)
        # Verdict r6 (TEST R-1, N-1): a blank line is not a line left of the item's column, so it
        # ends neither the item nor its fence (markdown-it-py): a wave=2 example after one is still
        # code, in an item at the margin or one indented off it, and wave 2 stays unrecorded.
        for name, item in {"at the margin": "- ", "off the margin": "  - "}.items():
            pad = " " * len(item)
            with self.subTest(case=f"a blank line in the fence of an item {name}"):
                report = (f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n{self.ROW_1}\n\n"
                          f"{item}Filled in as the example shows:\n{pad}```text\n{pad}example\n\n"
                          f"{pad}{self.ROW_2}\n{pad}```\n")
                errs = run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md")
                self.assertEqual(len(errs), 1, errs)
                self.assertIn("no WIP-curve row for wave(s) [2]", errs[0])
        # And a line one column short of an item indented off the margin ends that item and its
        # fence, so the incomplete second wave=2 row there is read. A fence ended only by a line at
        # the margin, or by one a column further left, swallowed it (verdict r6 N-1).
        with self.subTest(case="an unclosed fence ends with an item off the margin"):
            report = (f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n{self.ROW_1}\n{self.ROW_2}\n\n"
                      f"  - a note\n    ```\n    example\n   {partial_2}\n")
            errs = run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md")
            self.assertEqual(len(errs), 2, errs)
            self.assertTrue(any("| wave=2 |" in e and "carries no measured ['latency_max']" in e
                                for e in errs), f"the row after the item was not read {errs}")
            self.assertTrue(any("wave(s) [2] carry more than one WIP-curve row" in e for e in errs),
                            errs)

    def test_a_thematic_break_is_neither_a_list_item_nor_a_paragraph(self):
        # The list items followed for PR #401 review: '* * *' is a thematic break, not three list
        # items, so the paragraph under it is a plain one; and a --- ending a list item closes it,
        # so the next line starts a plain paragraph. Underlined, each is a setext heading.
        rows = f"{self.ROW_1}\n{self.ROW_2}\n"
        for name, lead in {"* * *": "* * *\n\n  Deviations\n---",
                           "a list item, ---": "- a note\n---\nDeviations\n---"}.items():
            with self.subTest(case=name):
                report = f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n{lead}\n\n{rows}"
                errs = run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md")
                self.assertTrue(any("— none found;" in e for e in errs),
                                f"bound under a setext heading {errs}")
        # An empty list item holds no paragraph, so the --- in it is a thematic break.
        with self.subTest(case="an empty list item"):
            report = f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n-\n  ---\n\n{rows}"
            self.assertEqual(run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md"), [])

    def test_a_thematic_break_in_a_list_item_keeps_that_item_open(self):
        # Verdict r4 (TEST R-1; PR #401 P1 4013782318, a false positive): a thematic break closes
        # only the items it is not indented into. '  ***' closes '  - b' but sits in '- a', so
        # '  para' is a's paragraph and a --- at the margin under it is a thematic break: the
        # incomplete second wave=2 row after it is still read. Dropping every open item on the
        # break made '  para' a plain paragraph and the --- its underline, which hid that row.
        partial_2 = self.ROW_2.replace("| latency_max=55m ", "")
        report = (f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n{self.ROW_1}\n{self.ROW_2}\n\n"
                  f"- a\n  - b\n  ***\n  para\n---\n\n{partial_2}\n")
        errs = run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md")
        self.assertEqual(len(errs), 2, errs)
        self.assertTrue(any("| wave=2 |" in e and "carries no measured ['latency_max']" in e
                            for e in errs), f"the row after the break was not read {errs}")
        self.assertTrue(any("wave(s) [2] carry more than one WIP-curve row" in e for e in errs),
                        errs)

    def test_the_marker_heading_and_underline_edges_commonmark_draws(self):
        # Verdict r3 (TEST nits: mutants D6, D7, C8, C10, D15 survived): every marker the checker
        # reads has its own witness. '+' and '*' bullets and a ')' ordered item are list items, so
        # a --- after them is a thematic break; seven #s are text; an underline indented four
        # spaces is text: the section stays open. A bare '##' is an empty heading, and ends it.
        rows = f"{self.ROW_1}\n{self.ROW_2}\n"
        for name, lead in {"a '+' list item": "+ a note\n---", "a '*' list item": "* a note\n---",
                           "a ')' ordered item": "1) a note\n---",
                           "seven #s": "####### not a heading",
                           "an underline indented four spaces": "Deviations\n    ---"}.items():
            with self.subTest(case=name):
                report = f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n{lead}\n\n{rows}"
                self.assertEqual(run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md"), [])
        with self.subTest(case="an empty '##' heading"):
            report = f"RUN: mission=ship-it waves=2\n\n{self.SECTION}\n\n##\n\n{rows}"
            errs = run_report._wip_curve_errors(report, "ship-it", ROOT, "r.md")
            self.assertTrue(any("— none found;" in e for e in errs), errs)

    def test_the_protocol_names_the_schema_the_checker_enforces(self):
        # The text and the check drifted once (#389: the prose owed five metrics, the check read
        # two settings). The protocol section must name every row key the checker enforces — and
        # no other — plus the waves=<n> count, and a row filled in from its Row cells must bind.
        # #387: it must also name the section the rows live in, the template's heading, and the
        # check must read exactly that: the row binds under the heading and nowhere else. Verdict
        # r1 (F-2): the prose named one heading while the check opened on any 'WIP curve' heading,
        # so the named text is tried both ways — at any level and suffix, and cut to its first word.
        budget = (ROOT / "runtime" / "attention-budget.md").read_text(encoding="utf-8")
        section = budget.split("## The WIP-curve protocol", 1)[1].split("\n## ", 1)[0]
        self.assertIn("`waves=<n>`", section, "the protocol no longer defines the recorded waves")
        cells = [c for cell in re.findall(r"^\|[^|]*\| `([^`]+)` \|", section, re.M)
                 for c in cell.split()]
        self.assertEqual({c.split("=")[0] for c in cells}, set(run_report.WIP_ROW_KEYS))
        named = re.search(r"under an ATX heading whose text begins `([^`]+)`", section)
        self.assertIsNotNone(named, "the protocol no longer names the section its rows live in")
        text = named.group(1)
        template = (ROOT / "docs" / "runs" / "TEMPLATE.md").read_text(encoding="utf-8")
        self.assertRegex(template, rf"(?m)^#+ {re.escape(text)}\b",
                         "the protocol names a section heading the run template does not carry")
        row = "| " + " | ".join(re.sub(r"<\w+>", "1", c) for c in cells) + " |"
        for heading in (f"## {text}", f"#### {text} (this run)"):
            with self.subTest(heading=heading):
                self.assertEqual(run_report._wip_curve_errors(
                    f"RUN: waves=1\n\n{heading}\n\n{row}\n", "ship-it", ROOT, "r.md"), [], row)
        for other in (self.DEVIATIONS, f"## {text.split()[0]} example\n\n"):
            with self.subTest(other=other):
                errs = run_report._wip_curve_errors(f"RUN: waves=1\n\n{other}{row}\n",
                                                    "ship-it", ROOT, "r.md")
                self.assertTrue(any("— none found;" in e for e in errs), errs)

    def test_a_report_filled_in_from_the_canonical_template_binds(self):
        # PR #391 review (P1): docs/runs/TEMPLATE.md kept the pre-#389 header (no waves=) and an
        # unlabelled single WIP row, so a mutating run that followed the repo's own template
        # produced a report that could not bind. Fill every <blank> as a two-wave run would.
        template = (ROOT / "docs" / "runs" / "TEMPLATE.md").read_text(encoding="utf-8")
        filled = re.sub(r"<[^<>\n]+>", "2", template)
        self.assertEqual(run_report._wip_curve_errors(filled, "ship-it", ROOT, "TEMPLATE.md"), [])

    def test_report_only_and_planning_runs_are_exempt(self):
        for mission in ("review-it", "attest-it", "map-it", "root-cause"):
            with self.subTest(mission=mission):
                self.assertEqual(run_report._wip_curve_errors("no rows\n", mission, ROOT, "r.md"), [])

    def test_a_repo_without_the_protocol_is_unscoped_not_refused(self):
        # The obligation starts with the policy's existence: a rev (or repo) without
        # runtime/evidence-manifest.md predates the protocol and owes no row.
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(run_report._wip_curve_errors("anything", "ship-it", tmp, "r.md"), [])

    def test_the_policy_is_read_at_the_pinned_revision(self):
        # The report binds to inventory_at; the policy in force for the run is THAT commit's,
        # so a report pinned at a commit with the protocol owes the row even if the worktree
        # is mid-edit.
        rev = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                             capture_output=True, text=True).stdout.strip()
        errs = run_report._wip_curve_errors("RUN: x\nno curve here\n", "ship-it", ROOT, "r.md",
                                            rev=rev)
        self.assertEqual(len(errs), 1, errs)


class RunReportBinding(unittest.TestCase):
    """One temp repo per test: a run directory, its manifest, a committed artifact."""

    def setUp(self):
        # ignore_cleanup_errors: same teardown race as #340 — something writes into
        # .git/objects while rmtree walks it, and the rmdir fails with OSError 39
        # (Directory not empty) AFTER every assertion in the test body has passed.
        # It reddened main at a6ec0fd on a tree that had just gone green as a
        # pull_request run, and the run before that needed a second attempt to pass.
        # Unlike #340 the writer is NOT gitleaks: this suite runs in the workflow step
        # that fails the build if gitleaks is on PATH at all, so it demonstrably is not.
        # The writer here is unidentified; what is certain is that the failure is in
        # cleanup of a throwaway repo, so it is not a signal and must not gate the build.
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        # resolve(): the check under test resolves both sides of its containment comparison
        # (#349); handing it an unresolved /var/folders path on macOS would test the platform's
        # symlink spelling, not the refusal.
        self.repo = Path(self._tmp.name).resolve()
        _git(self.repo, "init", "-q", ".")
        _git(self.repo, "config", "user.email", "t@example.com")
        _git(self.repo, "config", "user.name", "t")
        self.run_dir = self.repo / "docs" / "runs" / "2026-01-01-demo-it-selfrun"
        self.run_dir.mkdir(parents=True)
        self.manifest = "docs/runs/2026-01-01-demo-it-selfrun/build-manifest.json"
        (self.run_dir / "build-manifest.json").write_text('{"unit": "u1"}\n', encoding="utf-8")
        (self.run_dir / "negctrl.txt").write_text("mutant KILLED\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "artifacts")
        # #286: a tier costs a command EXECUTION, so the graded manifest carries a commands[]
        # record of the verifier running against itself, bound to a tree that really exists here.
        # Written in a second commit because the record has to name the first commit's tree.
        tree = _git(self.repo, "rev-parse", "HEAD^{tree}")
        self.verifier_cmd = f"python3 runtime/scripts/verify.py --manifest {self.manifest}"
        (self.run_dir / "build-manifest.json").write_text(json.dumps({
            "unit": "u1",
            "commands": [{
                "label": "verify", "cmd": self.verifier_cmd,
                "cmd_sha256": hashlib.sha256(self.verifier_cmd.encode("utf-8")).hexdigest(),
                "exit": 0, "wtree": tree,
            }],
        }) + "\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "manifest with a verifier ledger record")
        self.rev = _git(self.repo, "rev-parse", "HEAD")
        self.nc = "docs/runs/2026-01-01-demo-it-selfrun/negctrl.txt"
        self.nc_sha = self._blob_sha(self.rev, self.nc)
        self.manifest_sha = self._blob_sha(self.rev, self.manifest)
        self.path = self.repo / "docs" / "runs" / "2026-01-01-demo-it-self-run.md"

    def tearDown(self):
        self._tmp.cleanup()

    def _blob_sha(self, rev, path):
        blob = subprocess.run(
            ["git", "cat-file", "blob", f"{rev}:{path}"],
            cwd=str(self.repo), stdout=subprocess.PIPE, check=True,
        ).stdout
        return hashlib.sha256(blob).hexdigest()

    def _inventory(self):
        """The default inventory: this run's own artifacts, the manifest among them."""
        return [(self.manifest_sha, self.manifest), (self.nc_sha, self.nc)]

    def _write(self, **kw):
        args = dict(
            mission="demo-it", tier="self-run", rev=self.rev, manifest=self.manifest,
            verifier="GREEN", inventory=self._inventory(),
        )
        args.update(kw)
        self.path.write_text(_report(**args), encoding="utf-8")
        return self.path

    def _check(self, mission="demo-it", tier="self-run"):
        return run_report.check_report(self.path, mission, tier, root=self.repo)

    # --- the shape that must pass ------------------------------------------
    def test_an_unrelated_report_name_cannot_borrow_a_sole_same_day_run(self):
        # #694/#695 review: a report of any name took a mission's only same-day directory and
        # bound on another run's manifest and inventory. The same bytes under an unrelated name
        # are refused; under this run's own name they bind.
        self._write()
        self.assertEqual(self._check(), [])
        self.path = self.repo / "docs" / "runs" / "2026-01-01-demo-it-impostor.md"
        self._write()
        errs = self._check()
        self.assertTrue(any("outside this run's own directory" in e for e in errs), errs)

    def _remanifest(self, payload):
        """Rewrite the graded manifest and re-pin the report to the new commit."""
        (self.run_dir / "build-manifest.json").write_text(
            json.dumps(payload) + "\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "manifest rewritten")
        self.rev = _git(self.repo, "rev-parse", "HEAD")
        self.manifest_sha = self._blob_sha(self.rev, self.manifest)
        self.nc_sha = self._blob_sha(self.rev, self.nc)
        self._write()

    def test_a_recorded_command_is_read_as_argv_not_matched(self):
        """PR #308 review. A regex over a ledger record accepts `echo verify.py --manifest <m>`:
        it hashes true, names a real tree, and invokes nothing. This module already carries the
        scar tissue for the same class — _invocation_re was tightened twice, first because any
        prose mentioning verify.py matched, then because `--manifest \\S+` matched this module's
        own docstring. A recorded command is argv, so it is read as argv."""
        m = self.manifest
        V = "runtime/scripts/verify.py"
        for cmd in (f"python3 {V} --manifest {m}",
                    f"python3 ./{V} --manifest {m}",
                    f"/usr/bin/python3 -u {V} --contract-source c --manifest {m}",
                    f"env FOO=1 python3 {V} --manifest={m}",
                    # argparse keeps the LAST --manifest, so a trailing graded one is a real run.
                    f"python3 {V} --manifest other.json --manifest {m}",
                    # Flags this function does not model must not disbelieve a real run.
                    f"python3 {V} --contract-source c --execute-nc --nc-command 'pytest -q' "
                    f"--manifest {m}"):
            self.assertTrue(run_report.executes_verifier(cmd, m), cmd)
        for cmd in (f"echo {V} --manifest {m}",
                    f"true # {V} --manifest {m}",
                    f"sh -c '{V} --manifest {m}'",
                    f"python3 -c 'print(\"{V} --manifest {m}\")'",
                    f"cat {V} --manifest {m}",
                    f"python3 {V} --manifest other.json",
                    # A script the worker wrote is not this repository's verifier.
                    f"python3 /tmp/verify.py --manifest {m}",
                    f"python3 verify.py --manifest {m}",
                    f"python3 /tmp/{V} --manifest {m}",
                    f"python3 ../../tmp/{V} --manifest {m}",
                    # ...and argparse would read the LAST one, which is not the graded manifest.
                    f"python3 {V} --manifest {m} --manifest other.json",
                    # A dangling option: argparse refuses the whole command line, so the verifier
                    # never started. A hand-rolled scan kept the earlier value instead.
                    f"python3 {V} --manifest {m} --manifest",
                    f"python3 {V} --manifest"):
            self.assertFalse(run_report.executes_verifier(cmd, m), cmd)

    def test_the_interpreter_is_read_as_argv_too(self):
        """PR #327 review, P1.

        The executable was accepted on a basename that STARTS WITH `python`, so
        `/tmp/python3 runtime/scripts/verify.py --manifest m.json` satisfied verifier_ran with
        an arbitrary binary — a symlink to /bin/true runs nothing and records a pass. The
        interpreter is part of the recorded argv and is read like the rest of it.
        """
        m = self.manifest
        V = "runtime/scripts/verify.py"
        for cmd in (
            # An executable the run put somewhere it can write is not an interpreter.
            f"/tmp/python3 {V} --manifest {m}",
            f"/var/tmp/python3 -u {V} --manifest {m}",
            f"/dev/shm/python {V} --manifest {m}",
            f"/tmp/nested/python3.11 {V} --manifest {m}",
            # Nor is one inside the tree under review, which the run certainly writes.
            f"{self.repo}/python3 {V} --manifest {m}",
            # A relative path resolves against a cwd this check cannot know.
            f"./python3 {V} --manifest {m}",
            f"tools/python3 {V} --manifest {m}",
            f"/usr/bin/../tmp/python3 {V} --manifest {m}",
            # A name that merely begins with `python` is not a Python.
            f"python-decoy {V} --manifest {m}",
            f"pythonish {V} --manifest {m}",
            f"/usr/bin/python3-wrapper {V} --manifest {m}",
            f"python3x {V} --manifest {m}",
        ):
            with self.subTest(cmd=cmd):
                self.assertFalse(run_report.executes_verifier(cmd, m, self.repo), cmd)
        for cmd in (
            # The documented form: PATH resolves a bare name.
            f"python3 {V} --manifest {m}",
            f"python {V} --manifest {m}",
            f"python3.13 {V} --manifest {m}",
            f"python3.13t {V} --manifest {m}",
            # A real system interpreter, and a virtualenv outside the graded tree.
            f"/usr/bin/python3 -u {V} --manifest {m}",
            f"/usr/local/bin/python3.11 {V} --manifest {m}",
            f"/opt/ci/venv/bin/python3 {V} --manifest {m}",
            f"env FOO=1 /usr/bin/python3 {V} --manifest={m}",
        ):
            with self.subTest(cmd=cmd):
                self.assertTrue(run_report.executes_verifier(cmd, m, self.repo), cmd)

    def test_an_interpreter_inside_the_graded_tree_is_the_runs_own(self):
        # The temp repo above lives under /tmp, where the scratch rule would mask this one.
        root = "/opt/checkouts/open-fleet"
        for token in (f"{root}/python3", f"{root}/.venv/bin/python3",
                      f"{root}/runtime/scripts/python"):
            with self.subTest(token=token):
                self.assertFalse(run_report._is_python_interpreter(token, root), token)
        for token in ("/opt/checkouts/other/python3", "/usr/bin/python3", "python3"):
            with self.subTest(token=token):
                self.assertTrue(run_report._is_python_interpreter(token, root), token)

    def test_symlink_spellings_of_the_same_file_are_refused_too(self):
        # #349: the comparison used to be lexical on the token side, so on macOS the
        # /var/folders spelling of an interpreter inside a /private/var/folders repo (and the
        # /private/tmp spelling of /tmp) escaped both refusals.
        alias = Path(tempfile.mkdtemp(prefix="run-report alias "))
        self.addCleanup(shutil.rmtree, alias, True)
        real = self.repo / "real-tree"
        real.mkdir()
        (alias / "linked").symlink_to(real, target_is_directory=True)
        self.assertFalse(run_report._is_python_interpreter(str(alias / "linked" / "python3"), real))
        tmp = Path("/tmp").resolve()
        if tmp != Path("/tmp"):  # only a symlinked /tmp (macOS) has a second spelling to test
            self.assertFalse(
                run_report._is_python_interpreter(str(tmp / "python3"), self.repo),
                f"{tmp}/python3 is the resolved spelling of /tmp/python3",
            )

    def test_a_decoy_interpreter_does_not_buy_a_tier(self):
        # End to end: the ledger record hashes true and names a real tree, and still buys nothing.
        payload = json.loads((self.repo / self.manifest).read_text())
        line = f"/tmp/python3 runtime/scripts/verify.py --manifest {self.manifest}"
        payload["commands"] = [{
            "label": "verifier", "cmd": line, "exit": 0,
            "cmd_sha256": hashlib.sha256(line.encode("utf-8")).hexdigest(),
            "wtree": _git(self.repo, "rev-parse", "HEAD^{tree}"),
        }]
        (self.repo / self.manifest).write_text(json.dumps(payload) + "\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "decoy interpreter")
        rev = _git(self.repo, "rev-parse", "HEAD")
        problems = run_report.verifier_ran(self.manifest, rev, self.repo)
        self.assertTrue(problems, "a decoy interpreter must not satisfy verifier_ran")
        self.assertIn("records no commands[] entry running", problems[0])

    def test_an_echoed_invocation_does_not_buy_a_tier(self):
        # The same thing end to end: a fabricated report whose ledger only echoes the command.
        cmd = f"echo runtime/scripts/verify.py --manifest {self.manifest}"
        self._remanifest({"unit": "u1", "commands": [{
            "label": "verify", "cmd": cmd,
            "cmd_sha256": hashlib.sha256(cmd.encode("utf-8")).hexdigest(),
            "exit": 0, "wtree": self.rev}]})
        errs = self._check()
        self.assertTrue(any("records no commands[] entry" in e for e in errs), errs)

    def test_an_actual_inline_execution_does_not_buy_a_tier(self):
        argv = [sys.executable, "-cpass", "runtime/scripts/verify.py", "--manifest", self.manifest]
        result = subprocess.run(argv, cwd=self.repo, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        cmd = shlex.join(argv)
        self._remanifest({"unit": "u1", "commands": [{
            "label": "verify", "cmd": cmd,
            "cmd_sha256": hashlib.sha256(cmd.encode()).hexdigest(),
            "exit": result.returncode, "wtree": _git(self.repo, "rev-parse", "HEAD^{tree}")}]})
        errs = self._check()
        self.assertTrue(any("records no commands[] entry" in e for e in errs), errs)

    def test_a_manifest_with_no_verifier_run_is_refused(self):
        # #286. THE case: a fabricated map-it self-run — seven files, 32 lines, one commit —
        # reported "bound" in under fifteen minutes, because every artifact a worker writes and
        # commits hashes true at the commit containing it. Writing a command line costs nothing;
        # running one costs a run.
        self._remanifest({"unit": "u1"})
        errs = self._check()
        self.assertTrue(any("records no commands[] entry" in e for e in errs), errs)

    def test_a_verifier_record_for_another_manifest_does_not_count(self):
        # The record has to show the verifier run against THIS manifest, not a neighbour's.
        other = "docs/runs/2026-01-01-demo-it-selfrun/other-manifest.json"
        cmd = f"python3 runtime/scripts/verify.py --manifest {other}"
        self._remanifest({"unit": "u1", "commands": [{
            "label": "verify", "cmd": cmd,
            "cmd_sha256": hashlib.sha256(cmd.encode("utf-8")).hexdigest(),
            "exit": 0, "wtree": self.rev}]})
        errs = self._check()
        self.assertTrue(any("records no commands[] entry" in e for e in errs), errs)

    def test_a_verifier_record_whose_digest_does_not_match_is_refused(self):
        # A decorative cmd_sha256 would let the line be edited after the run.
        cmd = f"python3 runtime/scripts/verify.py --manifest {self.manifest}"
        self._remanifest({"unit": "u1", "commands": [{
            "label": "verify", "cmd": cmd, "cmd_sha256": "0" * 64,
            "exit": 0, "wtree": self.rev}]})
        errs = self._check()
        self.assertTrue(any("binds to nothing" in e and "cmd_sha256" in e for e in errs), errs)

    def test_a_verifier_record_bound_to_no_tree_is_refused(self):
        cmd = f"python3 runtime/scripts/verify.py --manifest {self.manifest}"
        self._remanifest({"unit": "u1", "commands": [{
            "label": "verify", "cmd": cmd,
            "cmd_sha256": hashlib.sha256(cmd.encode("utf-8")).hexdigest(), "exit": 0}]})
        errs = self._check()
        self.assertTrue(any("no wtree" in e for e in errs), errs)

    def test_a_verifier_record_naming_a_tree_that_does_not_exist_is_refused(self):
        cmd = f"python3 runtime/scripts/verify.py --manifest {self.manifest}"
        self._remanifest({"unit": "u1", "commands": [{
            "label": "verify", "cmd": cmd,
            "cmd_sha256": hashlib.sha256(cmd.encode("utf-8")).hexdigest(),
            "exit": 0, "wtree": "0" * 40}]})
        errs = self._check()
        self.assertTrue(any("does not resolve to a tree object" in e for e in errs), errs)

    def test_a_verifier_record_naming_the_empty_tree_is_refused(self):
        # 2026-10-23 review, P3 (#614): git resolves its built-in empty tree in EVERY repository
        # without storing it, so a hand-written record naming it passed "resolves to a real tree"
        # while binding the run to no content at all.
        cmd = f"python3 runtime/scripts/verify.py --manifest {self.manifest}"
        empty = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        self.assertEqual(run_report.tree_of(empty, self.repo), empty)  # it does resolve here
        self._remanifest({"unit": "u1", "commands": [{
            "label": "verify", "cmd": cmd,
            "cmd_sha256": hashlib.sha256(cmd.encode("utf-8")).hexdigest(),
            "exit": 0, "wtree": empty}]})
        errs = self._check()
        self.assertTrue(any("EMPTY tree" in e for e in errs), errs)

    def test_a_recorded_red_verifier_run_still_counts_as_a_run(self):
        # A RED is a legitimate recorded outcome — the point is that the verifier RAN.
        cmd = f"python3 runtime/scripts/verify.py --manifest {self.manifest}"
        tree = _git(self.repo, "rev-parse", "HEAD^{tree}")
        self._remanifest({"unit": "u1", "commands": [{
            "label": "verify", "cmd": cmd,
            "cmd_sha256": hashlib.sha256(cmd.encode("utf-8")).hexdigest(),
            "exit": 2, "wtree": tree}]})
        self.path.write_text(_report(
            mission="demo-it", tier="self-run", rev=self.rev, manifest=self.manifest,
            verifier="RED", inventory=self._inventory()), encoding="utf-8")
        errs = self._check()
        self.assertEqual([e for e in errs if "commands[]" in e or "binds to nothing" in e], [], errs)

    def test_a_bound_report_passes(self):
        self._write()
        self.assertEqual(self._check(), [])

    def test_a_recorded_red_verifier_still_binds(self):
        # A solo run cannot manufacture an independent approver; recording that
        # RED is honest and must not cost the tier.
        self._write(verifier="RED")
        self.assertEqual(self._check(), [])

    # --- the bypasses ------------------------------------------------------
    def test_no_run_header_is_refused(self):
        self.path.write_text(
            f"# Run report — demo-it self-run\n\nIt ran. verify.py was green.\n\n"
            f"{INVENTORY_HEADING}\n\n```\n{self.nc_sha}  {self.nc}\n```\n",
            encoding="utf-8",
        )
        self.assertTrue(any("no 'RUN:' header" in e for e in self._check()), self._check())

    def test_two_run_headers_are_refused(self):
        self._write()
        self.path.write_text(
            self.path.read_text(encoding="utf-8")
            + f"\nRUN: mission=demo-it tier=self-run inventory_at={self.rev} "
              f"manifest={self.manifest} verifier=GREEN\n",
            encoding="utf-8",
        )
        self.assertTrue(any("'RUN:' headers" in e for e in self._check()), self._check())

    def test_missing_field_is_refused(self):
        self.path.write_text(
            "# Run report — demo-it self-run\n\nRUN: mission=demo-it tier=self-run\n",
            encoding="utf-8",
        )
        self.assertTrue(any("missing" in e for e in self._check()), self._check())

    def test_report_pointed_at_another_mission_is_refused(self):
        self._write()
        errs = self._check(mission="other-it")
        self.assertTrue(any("belongs to the mission that ran" in e for e in errs), errs)

    def test_tier_disagreeing_with_frontmatter_is_refused(self):
        self._write(tier="self-run")
        errs = self._check(tier="external-run")
        self.assertTrue(any("frontmatter claims external-run" in e for e in errs), errs)

    def test_unresolvable_commit_is_refused(self):
        self._write(rev="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        self.assertTrue(
            any("is not a commit in this repository" in e for e in self._check()), self._check()
        )

    def test_borrowed_manifest_from_another_run_is_refused(self):
        # The B2 bypass: fabricate a report and point it at a REAL other run's
        # artifacts. Everything hashes; nothing about it is this mission's run.
        other = self.repo / "docs" / "runs" / "2026-01-01-someone-else-selfrun"
        other.mkdir(parents=True)
        (other / "build-manifest.json").write_text('{"unit": "theirs"}\n', encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "other run")
        rev = _git(self.repo, "rev-parse", "HEAD")
        self._write(rev=rev, manifest="docs/runs/2026-01-01-someone-else-selfrun/build-manifest.json")
        errs = self._check()
        self.assertTrue(any("outside this run's own directory" in e for e in errs), errs)

    def test_inventory_of_only_borrowed_artifacts_is_refused(self):
        other = self.repo / "docs" / "runs" / "2026-01-01-someone-else-selfrun"
        other.mkdir(parents=True)
        borrowed = other / "artifact.txt"
        borrowed.write_text("theirs\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "other run")
        rev = _git(self.repo, "rev-parse", "HEAD")
        digest = hashlib.sha256(b"theirs\n").hexdigest()
        self._write(
            rev=rev,
            inventory=[(digest, "docs/runs/2026-01-01-someone-else-selfrun/artifact.txt")],
        )
        errs = self._check()
        self.assertTrue(any("own directory" in e for e in errs), errs)

    def test_a_hash_that_does_not_re_derive_is_refused(self):
        self._write(inventory=[("0" * 64, self.nc)])
        errs = self._check()
        self.assertTrue(any("recorded 000000000000" in e for e in errs), errs)

    def test_inventory_naming_only_absent_paths_verifies_nothing(self):
        import hashlib
        self._write(inventory=[(hashlib.sha256(b"x").hexdigest(), "docs/runs/gone.txt")])
        errs = self._check()
        self.assertTrue(any("verified nothing" in e for e in errs), errs)

    def test_no_inventory_block_is_refused(self):
        self.path.write_text(
            f"# Run report — demo-it self-run\n\nRUN: mission=demo-it tier=self-run "
            f"inventory_at={self.rev} manifest={self.manifest} verifier=GREEN\n\n"
            "Ran verify.py. Artifacts retained elsewhere.\n",
            encoding="utf-8",
        )
        errs = self._check()
        self.assertTrue(any("integrity inventory" in e for e in errs), errs)

    def test_verifier_outcome_described_in_prose_is_refused(self):
        # The original weakness: any body mentioning verify.py satisfied the gate.
        self.path.write_text(
            _report("demo-it", "self-run", self.rev, self.manifest, "GREEN", self._inventory(),
                    body="We ran verify.py and it went fine.\n"),
            encoding="utf-8")
        errs = self._check()
        self.assertTrue(any("no verify.py invocation against" in e for e in errs), errs)

    def test_an_invocation_naming_a_placeholder_path_is_refused(self):
        # The SECOND weakness, found by this module's own docstring satisfying it:
        # `--manifest <path>` parses as a command with an argument. The argument has
        # to be the manifest this report is actually graded on.
        self.path.write_text(
            _report("demo-it", "self-run", self.rev, self.manifest, "GREEN", self._inventory(),
                    body="    python3 runtime/scripts/verify.py --manifest <path>\n"),
            encoding="utf-8")
        errs = self._check()
        self.assertTrue(any("no verify.py invocation against" in e for e in errs), errs)

    def test_an_invocation_against_a_different_manifest_is_refused(self):
        self.path.write_text(
            _report("demo-it", "self-run", self.rev, self.manifest, "GREEN", self._inventory(),
                    body="    python3 runtime/scripts/verify.py --manifest /tmp/other.json\n"),
            encoding="utf-8")
        errs = self._check()
        self.assertTrue(any("no verify.py invocation against" in e for e in errs), errs)

    def test_the_graded_manifest_must_be_pinned_by_the_inventory(self):
        # Hashing a neighbouring artifact while the document the verdict rests on
        # floats free binds nothing that matters (PR #277 review, P1).
        self._write(inventory=[(self.nc_sha, self.nc)])
        errs = self._check()
        self.assertTrue(any("the graded manifest" in e for e in errs), errs)

    def test_this_runs_own_artifact_going_absent_is_refused(self):
        # A path elsewhere may legitimately have moved; one of THIS run's own
        # artifacts being absent means the evidence was not retained.
        self._write(inventory=self._inventory() + [
            ("0" * 64, "docs/runs/2026-01-01-demo-it-selfrun/never-committed.txt")])
        errs = self._check()
        self.assertTrue(any("are absent at" in e for e in errs), errs)

    def test_unknown_verifier_outcome_is_refused(self):
        self._write(verifier="PROBABLY")
        errs = self._check()
        self.assertTrue(any("verifier=PROBABLY" in e for e in errs), errs)

    def test_missing_report_is_refused(self):
        errs = run_report.check_report(
            "docs/runs/never-written.md", "demo-it", "self-run", root=self.repo
        )
        self.assertTrue(any("does not exist" in e for e in errs), errs)


_dsspec = importlib.util.spec_from_file_location(
    "dispatch_sign", ROOT / "runtime" / "scripts" / "dispatch-sign.py")
dispatch_sign = importlib.util.module_from_spec(_dsspec)
_dsspec.loader.exec_module(dispatch_sign)


class SignedKeyFixture(RunReportBinding):
    """The coordinator-key fixture the signed-transcript and signed-inventory legs share: a
    committed pubkey, a verdict envelope, and the ancestry shapes (the key landing after the
    pin; a fork from a pre-key commit). No tests of its own."""

    SEED = bytes(range(1, 33))
    PUBKEY = ".orca/dispatch-pubkey"
    TRANSCRIPT = "docs/runs/2026-01-01-demo-it-selfrun/verifier-transcript.json"

    def setUp(self):
        super().setUp()
        # h409 F-5: a signed transcript names the verifier TOOLCHAIN it ran as (verify.py and every
        # sibling it loads, hashed per file), and run_report binds that set to the files in the
        # checkout being graded — so the graded checkout carries the real files at the pin.
        scripts = self.repo / "runtime" / "scripts"
        scripts.mkdir(parents=True, exist_ok=True)
        for name in run_report.TOOLCHAIN_FILES:
            (scripts / name).write_bytes((ROOT / "runtime" / "scripts" / name).read_bytes())
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "the verifier toolchain at the pin")
        self.rev = _git(self.repo, "rev-parse", "HEAD")

    def _ed(self):
        return dispatch_sign._load_ed25519()

    def _toolchain_files(self, **over):
        files = {name: hashlib.sha256((ROOT / "runtime" / "scripts" / name).read_bytes()).hexdigest()
                 for name in run_report.TOOLCHAIN_FILES}
        files.update(over)
        return files

    def _verdict(self, **over):
        full_args = {k: None for k in run_report.SIGNED_ARGS}
        full_args.update({"execute_nc": False, "no_gh": False,
                          "unit_class": "mutation", "lighting": "lit"})
        if "args" in over:
            full_args.update(over.pop("args"))  # producer-shape: a full tuple with overrides
        rec = {"unit": "u1", "manifest": self.manifest, "manifest_sha256": self.manifest_sha,
               "args": full_args, "fatal": [], "notes": [],
               "exit": 0, "toolchain": {"python": "3.13", "files": self._toolchain_files()},
               "timestamp": "2026-01-01T00:00:00+00:00"}
        rec.update(over)
        return rec

    def _envelope(self, record, seed=None):
        ed = self._ed()
        seed = seed or self.SEED
        sig = ed.signature(dispatch_sign.canonical_transcript(record), seed, ed.publickey(seed))
        return {"record": record, "sig_b64": base64.b64encode(sig).decode("ascii")}

    def _sign_report(self, seed=None):
        """Sign the report's inventory in place with `seed` (the coordinator's by default) —
        inventory.py sign, which re-derives the entries from the working tree first."""
        seed = seed or self.SEED
        # The seed lives the way gen-key leaves it — 0600, outside the graded repo — because the
        # signer re-asserts that custody at use (h409 F-4); an in-repo 0644 seed is refused.
        with tempfile.TemporaryDirectory(prefix="orca-seed-") as keydir:
            key = Path(keydir) / "seed"
            key.write_text(seed.hex() + "\n", encoding="utf-8")
            key.chmod(0o600)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = run_report.inventory.main(["sign", str(self.path), "--key", str(key)])
        self.assertEqual(rc, 0, "inventory.py sign refused — the tree does not match the entries")

    def _land(self, pubkey=True, transcript=None, msg="pubkey / transcript"):
        """Commit the pubkey and/or a transcript on the CURRENT branch. The report is NOT re-pinned:
        the pin stays where the caller left it, so the key can land after it (or beside it)."""
        if pubkey:
            pin = self.repo / self.PUBKEY
            pin.parent.mkdir(exist_ok=True)
            pin.write_text(self._ed().publickey(self.SEED).hex() + "\n", encoding="utf-8")
        if transcript is not None:
            (self.repo / self.TRANSCRIPT).write_text(json.dumps(transcript) + "\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", msg)
        return _git(self.repo, "rev-parse", "HEAD")

    def _commit(self, pubkey=True, transcript=None):
        """Land the pubkey and/or a transcript, re-pin the report to the new commit."""
        if pubkey:
            pin = self.repo / self.PUBKEY
            pin.parent.mkdir(exist_ok=True)
            pin.write_text(self._ed().publickey(self.SEED).hex() + "\n", encoding="utf-8")
        if transcript is not None:
            (self.repo / self.TRANSCRIPT).write_text(json.dumps(transcript) + "\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "pubkey / transcript")
        self.rev = _git(self.repo, "rev-parse", "HEAD")
        extra = f" transcript={self.TRANSCRIPT}" if transcript is not None else ""
        self._write(header_extra=extra)

    def _on_main(self):
        """The fixture's branch, named so grading_base() resolves it whatever init.defaultBranch is."""
        _git(self.repo, "branch", "-M", "main")

    def _fork_from_pre_key(self, dangling=False):
        """The BOT-2 shape: the key lands on main; a branch forked from the PRE-key commit gets
        fresh artifacts; the report pins that fork tip (which exists, and carries no key)."""
        self._on_main()
        pre_key = self.rev
        key_commit = self._land(pubkey=True, msg="the key lands on main")
        _git(self.repo, "checkout", "-q", "-b", "sneaky", pre_key)
        (self.run_dir / "negctrl.txt").write_text("mutant KILLED (fresh work)\n", encoding="utf-8")
        fork = self._land(pubkey=False, msg="fresh artifacts on a pre-key fork")
        _git(self.repo, "checkout", "-q", "main")
        if dangling:
            _git(self.repo, "branch", "-D", "sneaky")
        self.rev = fork
        self.nc_sha = self._blob_sha(self.rev, self.nc)
        self.assertNotEqual(
            subprocess.run(["git", "merge-base", "--is-ancestor", fork, "main"], cwd=str(self.repo)).returncode,
            0, "the fork must sit OFF main's ancestry for this test to mean anything")
        return key_commit


class SignedTranscriptRequired(SignedKeyFixture):
    """#281 / #386: with the coordinator's public key COMMITTED, the verifier-ran leg needs more
    than a worker-written ledger entry — it needs verify.py's verdict as a signed transcript that
    verifies against that key and binds to this report's claims.

    WHERE the key is read is the whole switch, and it is ancestry-aware (round-1 review of PR
    #489, BOT-2): a pin on the grading base's ancestry (the default branch's current tip) reads
    the key at the pin, so a report pinned before the key landed keeps the unsigned path; a pin
    OFF that ancestry — a fork from any pre-key commit, a dangling commit — is judged against the
    key at the grading base, because fresh artifacts on such a fork prove nothing about the key.
    The fixtures below therefore must NOT re-pin every report to HEAD: the tests that matter are
    the ones where blob_at(rev) != blob_at(HEAD).
    """

    def test_without_a_committed_key_the_ledger_still_suffices(self):
        # Today's path, byte-identical: no key at the pin, no transcript named -> bound.
        self._write()
        self.assertEqual(self._check(), [])

    def test_with_a_committed_key_a_ledger_entry_alone_no_longer_suffices(self):
        self._commit(pubkey=True)
        errors = self._check()
        self.assertTrue(any("transcript" in e and self.PUBKEY in e for e in errors), errors)

    def test_a_signed_transcript_against_the_committed_key_binds(self):
        self._commit(pubkey=True, transcript=self._envelope(self._verdict()))
        self._sign_report()  # the key is one switch for both legs (#386); this test is the transcript's
        self.assertEqual(self._check(), [])

    def test_a_tampered_transcript_is_refused(self):
        env = self._envelope(self._verdict(exit=2))
        env["record"]["exit"] = 0  # the RED verdict, retyped GREEN after signing
        self._commit(pubkey=True, transcript=env)
        errors = self._check()
        self.assertTrue(any("signature" in e.lower() for e in errors), errors)

    def test_an_unsigned_transcript_is_refused_when_the_key_is_committed(self):
        self._commit(pubkey=True, transcript=self._verdict())  # the bare verdict, no envelope
        errors = self._check()
        self.assertTrue(any("unsigned" in e.lower() or "sig_b64" in e for e in errors), errors)

    def test_a_transcript_signed_by_another_key_is_refused(self):
        self._commit(pubkey=True, transcript=self._envelope(self._verdict(), seed=bytes(range(100, 132))))
        errors = self._check()
        self.assertTrue(any("signature" in e.lower() for e in errors), errors)

    def test_a_transcript_over_other_manifest_bytes_is_refused(self):
        # A valid signature over a different manifest (an earlier draft, another unit's) is a
        # verdict on something else; the transcript's manifest_sha256 must be the graded blob.
        self._commit(pubkey=True, transcript=self._envelope(self._verdict(manifest_sha256="00" * 32)))
        errors = self._check()
        self.assertTrue(any("manifest_sha256" in e for e in errors), errors)
        self._commit(pubkey=False, transcript=self._envelope(self._verdict(manifest="docs/runs/other.json")))
        errors = self._check()
        self.assertTrue(any("manifest" in e and "transcript" in e for e in errors), errors)

    def test_a_transcript_whose_exit_disagrees_with_the_header_is_refused(self):
        self._commit(pubkey=True, transcript=self._envelope(self._verdict(exit=2)))
        errors = self._check()  # header says GREEN, the signed verdict says RED
        self.assertTrue(any("exit" in e and "GREEN" in e for e in errors), errors)

    def test_a_recorded_red_binds_when_the_transcript_agrees(self):
        self._commit(pubkey=True, transcript=self._envelope(self._verdict(exit=2, fatal=["x"])))
        self._write(verifier="RED", header_extra=f" transcript={self.TRANSCRIPT}")
        self._sign_report()
        self.assertEqual(self._check(), [])

    def test_a_transcript_outside_the_run_directory_is_refused(self):
        self.TRANSCRIPT = "docs/runs/elsewhere/verifier-transcript.json"
        (self.repo / "docs/runs/elsewhere").mkdir(parents=True)
        self._commit(pubkey=True, transcript=self._envelope(self._verdict()))
        errors = self._check()
        self.assertTrue(any("own directory" in e for e in errors), errors)

    def test_a_named_transcript_is_checked_even_without_a_committed_key(self):
        # Naming a transcript is a claim; a forged one is refused whether or not the key is pinned
        # (without a key nothing can verify it, so it fails closed rather than passing quietly).
        self._commit(pubkey=False, transcript=self._envelope(self._verdict()))
        errors = self._check()
        self.assertTrue(any("transcript" in e and self.PUBKEY in e for e in errors), errors)

    def test_a_key_whose_pin_is_malformed_fails_closed(self):
        self._commit(pubkey=True, transcript=self._envelope(self._verdict()))
        (self.repo / self.PUBKEY).write_text("not-hex\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "bad pin")
        self.rev = _git(self.repo, "rev-parse", "HEAD")
        self._write(header_extra=f" transcript={self.TRANSCRIPT}")
        errors = self._check()
        self.assertTrue(any("malformed" in e for e in errors), errors)

    # --- the signed argument tuple is READ, not only signed (BOT-1 / round-1 F-2) ---------------

    def test_a_transcript_whose_signed_args_disagree_with_the_shown_invocation_is_refused(self):
        # The body shows `--unit-class mutation --lighting lit`; the coordinator signed a verdict
        # reached under report-only. Same manifest, same exit — a verdict on the wrong question.
        self._commit(pubkey=True, transcript=self._envelope(
            self._verdict(args={"unit_class": "report-only", "lighting": "lit"})))
        errors = self._check()
        self.assertTrue(any("argument" in e and "report-only" in e for e in errors), errors)

    def test_a_lane_changed_or_omitted_from_the_signed_tuple_is_refused(self):
        # Greptile on PR #544: --lane changes the verdict, so it must be in the
        # signed tuple — a signed lane the shown invocation lacks (and a tuple
        # omitting lane entirely) both refuse, like every other policy flag.
        self._commit(pubkey=True, transcript=self._envelope(
            self._verdict(args={"lane": "0"})))
        errors = self._check()
        self.assertTrue(any("argument" in e and "lane" in e for e in errors), errors)
        verdict = self._verdict()
        del verdict["args"]["lane"]
        self._commit(pubkey=True, transcript=self._envelope(verdict))
        errors = self._check()
        self.assertTrue(any("partial" in e and "lane" in e for e in errors), errors)

    def test_a_transcript_signing_no_argument_tuple_is_refused(self):
        verdict = self._verdict()
        verdict["args"] = {}
        self._commit(pubkey=True, transcript=self._envelope(verdict))
        errors = self._check()
        self.assertTrue(any("argument" in e for e in errors), errors)

    def test_a_transcript_with_a_partial_argument_tuple_is_refused(self):
        # Greptile on PR #491: the checker must not derive its key set from the fields present —
        # a tuple naming only some policy fields still signed a verdict reached under controls it
        # omits (execute_nc, nc_command, contract_digest, …). The full tuple or nothing.
        verdict = self._verdict()
        verdict["args"] = {"unit_class": "mutation", "lighting": "lit"}  # an ACTUAL subset
        self._commit(pubkey=True, transcript=self._envelope(verdict))
        errors = self._check()
        self.assertTrue(any("partial" in e and "missing keys" in e for e in errors), errors)

    def test_hostile_args_on_a_mutation_mission_are_refused_even_when_the_body_agrees(self):
        # P1 from the round-1 TESTS axis: report-only / dark on a mutation-class mission, with the
        # body's invocation retyped to match. The class list is the in-repo oracle (#310).
        policy = self.repo / "runtime" / "evidence-manifest.md"
        policy.parent.mkdir(parents=True, exist_ok=True)
        policy.write_text("- **Mutation units** (demo-it, ship-it) — need a negative control.\n",
                          encoding="utf-8")
        self._commit(pubkey=True, transcript=self._envelope(
            self._verdict(args={"unit_class": "report-only", "lighting": "lit"})))
        body = (f"    python3 runtime/scripts/verify.py --manifest {self.manifest} "
                "--unit-class report-only --lighting lit\n    exit 0\n")
        self._write(header_extra=f" transcript={self.TRANSCRIPT}", body=body)
        errors = self._check()
        self.assertTrue(any("mutation-class" in e and "report-only" in e for e in errors), errors)

    # --- WHERE the key is read: the pin on the base's ancestry, the base off it -----------------

    def test_a_report_pinned_before_the_key_landed_keeps_the_unsigned_path(self):
        # P2: the key lands AFTER the pin, on the same line; blob_at(rev) != blob_at(HEAD).
        self._on_main()
        self._write()  # pinned at self.rev, no key there
        later = self._land(pubkey=True)
        self.assertNotEqual(later, self.rev)
        self.assertEqual(self._check(), [], "a pre-key report on the base's ancestry is grandfathered")

    def test_a_pre_key_transcript_fails_closed_even_once_the_key_lands_later(self):
        # P3: a transcript named at a pin with no key is unverifiable THERE; a key committed
        # afterwards does not reach back and validate it.
        self._on_main()
        self._land(pubkey=False, transcript=self._envelope(self._verdict()))
        self.rev = _git(self.repo, "rev-parse", "HEAD")
        self._write(header_extra=f" transcript={self.TRANSCRIPT}")
        self._land(pubkey=True)
        errors = self._check()
        self.assertTrue(any("transcript" in e and self.PUBKEY in e for e in errors), errors)

    def test_a_transcript_signed_after_the_pin_does_not_retro_sign_the_pinned_verdict(self):
        # P8: at the pin the transcript is the bare verdict; a later commit replaces it with a
        # valid envelope. The report is graded at the pin, so it is still the unsigned one.
        self._on_main()
        self._commit(pubkey=True, transcript=self._verdict())
        self._land(transcript=self._envelope(self._verdict()))
        errors = self._check()
        self.assertTrue(any("unsigned" in e.lower() or "sig_b64" in e for e in errors), errors)

    def test_post_key_work_pinned_to_a_pre_key_fork_is_refused(self):
        # P4, the evasion round 1 executed: artifacts exist at the pin, the key does not, and
        # the pin is not an ancestor of the grading base -> the key at the BASE is what counts.
        self._fork_from_pre_key()
        self._write()
        errors = self._check()
        self.assertTrue(any("transcript" in e and self.PUBKEY in e for e in errors), errors)
        self.assertTrue(any("ancestor" in e for e in errors), errors)

    def test_a_dangling_pre_key_pin_is_refused_the_same_way(self):
        # P5: the fork on no branch at all still resolves (rev_exists), and is still off-ancestry.
        self._fork_from_pre_key(dangling=True)
        self._write()
        errors = self._check()
        self.assertTrue(any("transcript" in e and self.PUBKEY in e for e in errors), errors)

    def test_an_off_ancestry_report_binds_with_a_transcript_signed_by_the_base_key(self):
        # The lawful off-ancestry shape: a feature-branch run whose verdict the coordinator
        # signed with the key that IS committed on the base.
        self._fork_from_pre_key()
        _git(self.repo, "checkout", "-q", "sneaky")
        self._land(pubkey=False, transcript=self._envelope(self._verdict()))
        self.rev = _git(self.repo, "rev-parse", "HEAD")
        self._write(header_extra=f" transcript={self.TRANSCRIPT}")
        self._sign_report()  # on the fork's tree: sign re-derives from disk
        _git(self.repo, "checkout", "-q", "main")
        self.assertEqual(self._check(), [])

    def test_a_pre_key_report_still_binds_when_the_base_is_named_explicitly(self):
        # check_report(base=...) is the coordinator's override; the default resolves the tip.
        self._on_main()
        self._write()
        self._land(pubkey=True)
        self.assertEqual(run_report.check_report(self.path, "demo-it", "self-run", root=self.repo,
                                                 base="main"), [])
        self.assertEqual(run_report.grading_base(self.repo), _git(self.repo, "rev-parse", "main"))


class SignedInventoryRequired(SignedKeyFixture):
    """#386 / U-SIG-2: with the coordinator's key committed where the switch is read, the run-close
    inventory's ENTRY SET must carry the coordinator's signature (inventory.py sign) — a worker
    can type an inventory as easily as a transcript. The key is read exactly where the transcript
    rule reads it (key_rev: the pin on the grading base's ancestry, the base off it), so the two
    legs cannot disagree about whether enforcement is on. Every test here lands a VALID signed
    transcript first, so what it isolates is the inventory leg alone.
    """

    def _transcript_commit(self, pubkey=True):
        self._commit(pubkey=pubkey, transcript=self._envelope(self._verdict()))

    def test_with_a_committed_key_an_unsigned_inventory_no_longer_binds(self):
        self._transcript_commit()
        self.assertEqual([e for e in self._check() if "transcript" in e], [], "the transcript leg holds")
        errors = self._check()
        self.assertTrue(any("inventory" in e and "unsigned" in e.lower() and self.PUBKEY in e
                            for e in errors), errors)

    def test_a_signed_inventory_against_the_committed_key_binds(self):
        self._transcript_commit()
        self._sign_report()
        self.assertEqual(self._check(), [])

    def test_a_tampered_inventory_entry_is_refused(self):
        self._transcript_commit()
        self._sign_report()
        # The negative-control entry dropped AFTER signing: what remains still re-derives at the
        # pin (the manifest is a real blob there), so only the signature knows the attested set
        # was larger.
        text = self.path.read_text(encoding="utf-8")
        self.assertIn(f"{self.nc_sha}  {self.nc}\n", text)
        self.path.write_text(text.replace(f"{self.nc_sha}  {self.nc}\n", "", 1), encoding="utf-8")
        errors = self._check()
        self.assertTrue(any("inventory" in e and "signature" in e.lower() for e in errors), errors)

    def test_an_inventory_signed_by_another_key_is_refused(self):
        self._transcript_commit()
        self._sign_report(seed=bytes(range(100, 132)))
        errors = self._check()
        self.assertTrue(any("inventory" in e and "signature" in e.lower() for e in errors), errors)

    def test_a_signed_inventory_is_checked_even_without_a_committed_key(self):
        # G-4's rule, mirrored: a signature with nothing to verify it against is a claim that
        # fails closed, not one that passes quietly.
        self._write()
        self._sign_report()
        errors = self._check()
        self.assertTrue(any("inventory" in e and self.PUBKEY in e for e in errors), errors)

    def test_without_a_committed_key_an_unsigned_inventory_still_binds(self):
        self._write()
        self.assertEqual(self._check(), [])

    def test_a_pre_key_report_on_the_ancestry_keeps_the_unsigned_inventory(self):
        self._on_main()
        self._write()
        self._land(pubkey=True)
        self.assertEqual(self._check(), [])

    def test_post_key_work_pinned_to_a_pre_key_fork_needs_a_signed_inventory(self):
        # The transcript leg's BOT-2 closure applies to the inventory leg through the same key_rev.
        self._fork_from_pre_key()
        _git(self.repo, "checkout", "-q", "sneaky")
        self._land(pubkey=False, transcript=self._envelope(self._verdict()))
        self.rev = _git(self.repo, "rev-parse", "HEAD")
        self._write(header_extra=f" transcript={self.TRANSCRIPT}")
        _git(self.repo, "checkout", "-q", "main")
        errors = self._check()
        self.assertEqual([e for e in errors if "transcript" in e], [], errors)
        self.assertTrue(any("inventory" in e and self.PUBKEY in e for e in errors), errors)
        # Signed on the fork's own tree (sign re-derives from disk), graded from main.
        _git(self.repo, "checkout", "-q", "sneaky")
        self._sign_report()
        _git(self.repo, "checkout", "-q", "main")
        self.assertEqual(self._check(), [])

    # --- round-1 G-1 / G-2 mirrored at the gate ------------------------------------------------
    def _rewrite_envelope(self, edit):
        text = self.path.read_text(encoding="utf-8")
        line = next(l for l in text.splitlines() if l.startswith("<!-- inventory-signature"))
        self.path.write_text(edit(text, line), encoding="utf-8")

    def test_a_malformed_sig_b64_never_binds(self):
        # M14 at the gate: the record is derivable from the report; a sig_b64 that does not
        # decode is a keyless forgery and must refuse, never read as bound.
        self._transcript_commit()
        self._sign_report()
        self._rewrite_envelope(lambda text, line: text.replace(
            line, line.replace(json.loads(line[len("<!-- inventory-signature "):-len(" -->")])["sig_b64"],
                               "not*base64!")))
        errors = self._check()
        self.assertTrue(any("signature does not bind" in e and "malformed" in e for e in errors), errors)

    def test_a_signature_line_in_the_report_prose_is_refused(self):
        # BOT-1 at the gate: a pasted example above the inventory heading is outside every
        # find_blocks range — refused as a would-be forgery, not honoured, not "unsigned".
        self._transcript_commit()
        self._sign_report()
        self.assertEqual(self._check(), [])
        self._rewrite_envelope(lambda text, line: line + "\n" + text)
        errors = self._check()
        self.assertTrue(any("inventory" in e and "outside" in e for e in errors), errors)
        self.assertFalse(any("UNSIGNED" in e for e in errors), errors)

    def test_a_malformed_pin_refuses_the_inventory_leg_too(self):
        # G-5: the pin is parsed once, in enforcement_key(); both legs refuse the same way.
        self._transcript_commit()
        self._sign_report()
        (self.repo / self.PUBKEY).write_text("not-hex\n", encoding="utf-8")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "bad pin")
        self.rev = _git(self.repo, "rev-parse", "HEAD")
        self._write(header_extra=f" transcript={self.TRANSCRIPT}")
        self._sign_report()
        errors = self._check()
        self.assertEqual(len([e for e in errors if "malformed" in e]), 2, errors)
        pub, at, why = run_report.enforcement_key(self.rev, self.repo)
        self.assertIsNone(pub)
        self.assertIsNone(at)
        self.assertIn("malformed", why)


class LiveCatalog(unittest.TestCase):
    """The repo's own claims, checked by the same code CI runs."""

    def test_every_advanced_tier_binds(self):
        code = run_report.main([])
        self.assertEqual(code, 0, "a mission claims a tier its run report cannot re-derive")

    def test_ship_its_artifacts_still_hash_true_but_its_transcript_is_missing(self):
        """The four-of-five state, pinned so neither half drifts.

        Its inventory re-derives at `748b328` and its manifest is in its own run
        directory — that much is real and should keep working. What is absent is the
        `verify.py … --manifest` invocation the recorded RED came from, which is why
        ship-it sits at doctrine-only.

        Since #286 that absence is reported twice, at two levels, and both are the same
        gap: the report body shows no invocation, AND the graded manifest's commands[]
        ledger records no verifier run. The run really did not write the command line
        down — its own report says so — so a gate that costs a run must fail it here.

        Since #389 its WIP-curve table is refused too, and truthfully: its only row carrying
        builders=/reviewers= is a settings row (`| WIP setting | builders=1 reviewers=1 |`) whose
        throughput cell reads "not measured to protocol" — the report calls itself "NOT a
        protocol-compliant data point". The old check bound it on the settings alone.
        """
        errs = run_report.check_report(
            "docs/runs/2026-08-28-ship-it-self-run.md", "ship-it", "self-run"
        )
        missing_transcript = [e for e in errs
                              if "invocation" in e or "records no commands[] entry" in e
                              or "RUN: tier=doctrine-only" in e]
        no_wip_curve_row = [e for e in errs if "WIP-curve" in e]
        self.assertEqual(
            [e for e in errs if e not in missing_transcript + no_wip_curve_row], [],
            "only the missing verifier transcript and WIP-curve row should stop this report binding",
        )
        self.assertEqual(len(no_wip_curve_row), 1, "the WIP-curve leg (#389) stopped reporting")
        self.assertTrue(any("invocation" in e for e in errs), "the prose leg stopped reporting")
        self.assertTrue(any("records no commands[] entry" in e for e in errs),
                        "the ledger leg (#286) stopped reporting")
        # And the header itself now refuses the claim: asked whether this report supports
        # `self-run`, it answers with what it actually declares.
        self.assertTrue(any("RUN: tier=doctrine-only" in e for e in errs),
                        "the RUN: header no longer states the tier the body supports")

    def test_demoted_reports_are_kept_and_say_why(self):
        # Demoting is only honest if the record survives and explains itself.
        for name in (
            "2026-07-13-clean-sweep-self-run.md",
            "2026-07-13-review-it-external-run.md",
            "2026-07-16-oss-contribute-external-run.md",
            "2026-08-28-ship-it-self-run.md",
        ):
            text = (ROOT / "docs" / "runs" / name).read_text(encoding="utf-8")
            self.assertIn("Evidence binding", text, f"{name} was demoted without saying why")

    def test_the_readme_does_not_claim_the_tier_gate_re_derives(self):
        """#281. The gate hashes artifacts at a named commit; it does not re-run the verifier, and
        run_report.py's own docstring says so at :33-38. The README claimed a tier "re-derives",
        which a fabricated map-it self-run disproved in fifteen minutes. Guard the honest wording:
        a doc claim that outruns its mechanism is the failure this repository exists to refuse."""
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        start = readme.index("## Proof status")
        section = " ".join(readme[start:readme.index("\n## ", start + 1)].split())
        self.assertNotIn("it is a report that re-derives", section,
                         "the README is claiming the tier gate re-derives again (#281)")
        self.assertIn("hash true at a named commit", section)
        self.assertIn("it hashes, it does not re-run the verifier", section,
                      "the section must state the limit, not only the capability")

class TranscriptBindsTheVerifierToolchain(SignedKeyFixture):
    """h409 F-5 (C4): `toolchain.verify_sha256` had zero consumers and covered verify.py alone — a
    substituted _verify_sig.py / diff_scope.py / ed25519.py yielded a byte-identical signed
    envelope. The transcript now hashes verify.py AND every sibling it loads as one named set,
    and run_report verifies each against the file at the graded pin: a transcript proves WHICH
    verifier ran, nothing more."""

    def test_an_unmodified_toolchain_binds(self):
        self._commit(pubkey=True, transcript=self._envelope(self._verdict()))
        self._sign_report()
        self.assertEqual(self._check(), [])

    def test_a_substituted_sibling_does_not_bind(self):
        tampered = hashlib.sha256(b"def _failure_signature(out, err):\n    return True, None\n").hexdigest()
        files = self._toolchain_files(**{"_verify_sig.py": tampered})
        rec = self._verdict(toolchain={"python": "3.13", "files": files})
        self._commit(pubkey=True, transcript=self._envelope(rec))
        self._sign_report()
        errors = self._check()
        self.assertTrue(any("_verify_sig.py" in e and "transcript" in e for e in errors), errors)

    def test_a_transcript_naming_no_toolchain_set_does_not_bind(self):
        rec = self._verdict(toolchain={"python": "3.13", "verify_sha256": "ab" * 32})
        self._commit(pubkey=True, transcript=self._envelope(rec))
        self._sign_report()
        errors = self._check()
        self.assertTrue(any("toolchain" in e and "transcript" in e for e in errors), errors)

    def test_the_file_set_is_one_set_on_both_sides_and_is_what_the_verifier_loads(self):
        # h409 G-3: the producer (verify.py _Transcript.TOOLCHAIN) and the consumer
        # (run_report.TOOLCHAIN_FILES) are two literals mirrored by comment only. A sibling dropped
        # from the producer is hashed nowhere and every transcript is refused (noisy); dropped from
        # the consumer it is hashed and never checked — a substituted copy BINDS (silent). Both
        # are pinned here to one literal, and the literal to what the scripts actually load by
        # path (transitively), so a drop from EITHER side — or a new by-path sibling left out of
        # either — is RED, and the fixture above can no longer inherit a shrunken set.
        expected = ("verify.py", "_verify_sig.py", "diff_scope.py", "ed25519.py", "dispatch-sign.py",
                    "inventory.py", "gitexec.py")
        self.assertEqual(tuple(run_report.TOOLCHAIN_FILES), expected)
        vspec = importlib.util.spec_from_file_location("verify_for_parity", ROOT / "runtime" / "scripts" / "verify.py")
        verify = importlib.util.module_from_spec(vspec)
        vspec.loader.exec_module(verify)
        self.assertEqual(tuple(verify._Transcript.TOOLCHAIN), expected)
        by_path = re.compile(r'(?:Path\(__file__\)\.resolve\(\)\.parent|_HERE) / "([^"]+\.py)"')
        loaded, queue = {"verify.py"}, ["verify.py"]
        while queue:
            name = queue.pop()
            for sibling in by_path.findall((ROOT / "runtime" / "scripts" / name).read_text(encoding="utf-8")):
                if sibling not in loaded:
                    loaded.add(sibling)
                    queue.append(sibling)
        self.assertEqual(loaded, set(expected))

    def test_a_partial_toolchain_set_does_not_bind(self):
        files = self._toolchain_files()
        del files["ed25519.py"]
        rec = self._verdict(toolchain={"python": "3.13", "files": files})
        self._commit(pubkey=True, transcript=self._envelope(rec))
        self._sign_report()
        errors = self._check()
        self.assertTrue(any("ed25519.py" in e and "transcript" in e for e in errors), errors)


class ASelfPinnedKeyNeverChoosesItsJudge(RunReportBinding):
    """h409 O-3.3: GRADING_BASES ends in HEAD, so a checkout with no origin and no main/master
    branch read the enforcement key AT the pin — the pin choosing its own judge. key_rev now
    refuses that fallback when the pin carries a key; any named base re-opens the lane."""

    def _drop_named_bases(self):
        for branch in ("main", "master"):
            subprocess.run(["git", "branch", "-D", branch], cwd=str(self.repo),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _pin(self):
        (self.repo / ".orca").mkdir(exist_ok=True)
        (self.repo / ".orca" / "dispatch-pubkey").write_text("ab" * 32 + "\n")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "self-pinned key")
        return _git(self.repo, "rev-parse", "HEAD")

    def test_head_only_self_pin_refuses(self):
        _git(self.repo, "checkout", "-q", "-b", "trunk")
        self._drop_named_bases()
        rev = self._pin()
        at, why = run_report.key_rev(rev, self.repo)
        self.assertIsNone(at)
        self.assertIn("O-3.3", why)

    def test_a_key_introduced_off_the_base_by_the_pin_never_enforces(self):
        # Full-review forge: the claim commit introduces its own pubkey
        # while the grading base carries none. enforcement_key used to fall
        # back to that pin key, so a self-signed transcript verified against
        # a key the claimant chose. The switch must read at the base only.
        base = self.rev
        _git(self.repo, "checkout", "-q", "-b", "claim")
        rev = self._pin()
        pub, at, why = run_report.enforcement_key(rev, self.repo, base=base)
        self.assertIsNone(pub)
        self.assertEqual(at, base)
        self.assertIn("grading base", why)

    def test_a_named_base_reopens_the_lane(self):
        _git(self.repo, "checkout", "-q", "-b", "trunk")
        self._drop_named_bases()
        rev = self._pin()
        _git(self.repo, "branch", "-f", "main", rev)
        at, why = run_report.key_rev(rev, self.repo)
        self.assertEqual(at, rev)
        self.assertIn("the pin", why)


if __name__ == "__main__":
    unittest.main()
