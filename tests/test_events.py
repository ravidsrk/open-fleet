#!/usr/bin/env python3
"""Contract tests for runtime/scripts/events.py (#603).

The record's job is to let a run report's WIP-curve rows be DERIVED instead of typed. So the
properties pinned here are the ones a typed row would silently get wrong: a duplicate delivery
counted twice, a negative or cross-clock interval reported as a number, a fenced coordinator's
write treated as fact, an unknown cost written as 0, and a report that does not reproduce.

The two committed fixture streams (tests/fixtures/events/) are built by `scenario_clean()` and
`scenario_crash()` below — the expected rows beside them were calculated by hand from the
timestamps in those functions, not by running the tool.
"""
import calendar
import contextlib
import importlib
import io
import importlib.util
import json
import os
import random
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
EVENTS = ROOT / "runtime" / "scripts" / "events.py"
FIXTURES = ROOT / "tests" / "fixtures" / "events"
SPEC = importlib.util.spec_from_file_location("events", EVENTS)
events = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(events)


def sha(tag):
    """A full 40-hex commit id from a two-hex tag: sha('a1') -> 'a1a1…a1'."""
    return tag * 20


def ev(kind, hms, *, run, epoch, clock, task=None, dispatch=None, data=None, event_id=None,
       producer="coordinator", basis="observed", day="2026-10-20", ref=None, digest=None):
    return events.build_event(kind, run, epoch=epoch, producer=producer, clock=clock,
                              observed_at=f"{day}T{hms}Z", basis=basis,
                              source_ref=ref or f"fixture:{kind}", source_sha256=digest,
                              task=task, dispatch=dispatch, data=data, event_id=event_id)


def chain(evs):
    """The record's bytes for `evs` in this order, duplicates kept — what a concatenation, or a
    producer that skipped append's dedup, leaves on disk."""
    out, prev = [], None
    for event in evs:
        raw = json.dumps(dict(event, prev="" if prev is None else events.sha256_hex(prev)),
                         sort_keys=True, separators=(",", ":"))
        out.append(raw + "\n")
        prev = raw
    return "".join(out)


def scenario_clean():
    """run-a: two complete waves, appended OUT OF ORDER, with a duplicate delivery, a
    re-observation under a new id, a retry, a bounce, a voided review and a tree-equal rebase.

    Hand calculation (clock host-a throughout):
      wave 1 open 10:00, close 11:45 -> 6300 s; t1 and t2 verified-CLOSED -> 2*3600/6300 = 1.14/h
        t1: done@A1 10:20 (also re-observed 10:21) -> pass@A1 10:40 = 20 m
        t2: done@B1 10:30 -> FAIL@B1 (bounce) -> retry d3 -> done@B2 11:10 -> pass@B2 11:34 = 24 m
        latency median (20+24)/2 = 22.00m, max 24.00m; rework 1/2;
        freshness: t2's approval at B1 is voided by the close at B2 -> 1
        review queue 5 m (t1), 2 m (t2@B1), 10 m (t2@B2) -> median 5.00m, max 10.00m; retries 1
      wave 2 open 11:50, close 13:00 -> 4200 s; t4 verified-CLOSED, t3 parked -> 3600/4200 = 0.86/h
        t3: done@C1 12:10 -> parked 12:15 = 5 m
        t4: done@D1 12:20 -> pass@D1 12:40 = 20 m (the conductor's rebase D2 re-verifies a head no
            worker reported); approval at D1 survives the close at D2: same tree W1
        latency median (5+20)/2 = 12.50m, max 20.00m; rework 0/2; freshness 0
      usage: builders (claude-fixture) input 1000+1500+500+400+600 = 4000, output
        200+300+100+80+120 = 800; cost 0.50+0.25+0.10+0.15 known = 1.00 but d2 never reported
        one -> null, never 0. Reviewers r1..r4 (claude-review-fixture) input 300+200+250+150 =
        900, output 60+40+50+30 = 180, cost 0.05+0.04+0.05+0.03 = 0.17. Every dispatch the
        record names is covered, so the run total is the whole run's: input 4000+900 = 4900,
        output 800+180 = 980; cost stays null (d2)
    """
    c = {"run": "run-a", "epoch": 1, "clock": "host-a"}
    st = {"producer": "local_state", "basis": "occurred"}
    a1, b1, b2, c1, d1, d2, w1 = sha("a1"), sha("b1"), sha("b2"), sha("c1"), sha("d1"), sha("d2"), sha("e7")
    done_t1 = ev("task.done", "10:20:00", task="t1", dispatch="d1", data={"head_sha": a1},
                 event_id="local-state:message:m1", **st, **c)

    def usage(dispatch, task, inp, out, cost, line, model="claude-fixture"):
        prov = f"fixture stream {dispatch} result line {line}"
        if cost is None:
            prov += "; not reported: cost_usd"
        return ev("model.usage", "13:05:00", task=task, dispatch=dispatch,
                  data={"model": model, "input_tokens": inp, "output_tokens": out,
                        "cost_usd": cost, "provenance": prov},
                  event_id=f"usage:{dispatch}:{line}", producer="claude-stream-json", **c)
    usage_d3 = usage("d3", "t2", 500, 100, "0.25", 22)
    return [
        ev("run.start", "10:00:00", data={"coordinator": "coord-1"}, **c),
        ev("wave.open", "10:00:00", data={"wave": 1, "builders": 2, "reviewers": 1,
                                          "tasks": ["t1", "t2"]}, **c),
        ev("dispatch.launched", "10:01:00", task="t1", dispatch="d1", data={"agent": "claude"},
           event_id="local-state:dispatch:d1", **st, **c),
        ev("dispatch.launched", "10:01:30", task="t2", dispatch="d2", data={"agent": "claude"},
           event_id="local-state:dispatch:d2", **st, **c),
        # out of order: t1's verdict lands before its worker_done
        ev("verify.verdict", "10:40:00", task="t1", data={"exit": 0, "head_sha": a1},
           producer="verify.py", basis="occurred", digest=sha("f1") + "f1" * 12, **c),
        done_t1,
        ev("review.started", "10:25:00", task="t1", dispatch="r1", data={"head_sha": a1}, **c),
        ev("task.done", "10:30:00", task="t2", dispatch="d2", data={"head_sha": b1},
           event_id="local-state:message:m2", **st, **c),
        done_t1,  # the same delivery, again
        ev("review.verdict", "10:35:00", task="t1", data={"verdict": "approve", "reviewed_sha": a1}, **c),
        ev("review.started", "10:32:00", task="t2", dispatch="r2", data={"head_sha": b1}, **c),
        ev("task.done", "10:21:00", task="t1", dispatch="d1", data={"head_sha": a1},
           event_id="coordinator-saw-done-t1", **c),  # a later re-observation of the same fact
        ev("review.verdict", "10:45:00", task="t2", data={"verdict": "approve", "reviewed_sha": b1}, **c),
        ev("verify.verdict", "10:50:00", task="t2", data={"exit": 2, "head_sha": b1},
           producer="verify.py", basis="occurred", **c),
        ev("unit.closed", "10:55:00", task="t1", data={"head_sha": a1}, **c),
        ev("dispatch.launched", "10:52:00", task="t2", dispatch="d3", data={"agent": "claude"},
           event_id="local-state:dispatch:d3", **st, **c),
        ev("unit.closed", "11:40:00", task="t2", data={"head_sha": b2}, **c),
        ev("task.done", "11:10:00", task="t2", dispatch="d3", data={"head_sha": b2},
           event_id="local-state:message:m3", **st, **c),
        ev("review.started", "11:20:00", task="t2", dispatch="r3", data={"head_sha": b2}, **c),
        ev("review.verdict", "11:25:00", task="t2", data={"verdict": "approve", "reviewed_sha": b2}, **c),
        ev("verify.verdict", "11:34:00", task="t2", data={"exit": 0, "head_sha": b2},
           producer="verify.py", basis="occurred", **c),
        ev("wave.close", "11:45:00", data={"wave": 1}, **c),
        ev("wave.open", "11:50:00", data={"wave": 2, "builders": 1, "reviewers": 1,
                                          "tasks": ["t3", "t4"]}, **c),
        ev("dispatch.launched", "11:51:00", task="t3", dispatch="d4", event_id="local-state:dispatch:d4", **st, **c),
        ev("dispatch.launched", "11:52:00", task="t4", dispatch="d5", event_id="local-state:dispatch:d5", **st, **c),
        ev("unit.parked", "12:15:00", task="t3", data={"park_class": "needs-human", "head_sha": c1}, **c),
        ev("task.done", "12:10:00", task="t3", dispatch="d4", data={"head_sha": c1},
           event_id="local-state:message:m4", **st, **c),
        ev("task.done", "12:20:00", task="t4", dispatch="d5", data={"head_sha": d1},
           event_id="local-state:message:m5", **st, **c),
        ev("review.started", "12:21:00", task="t4", dispatch="r4", data={"head_sha": d1}, **c),
        ev("review.verdict", "12:30:00", task="t4", data={"verdict": "approve", "reviewed_sha": d1,
                                                          "reviewed_wtree": w1}, **c),
        ev("verify.verdict", "12:48:00", task="t4", data={"exit": 0, "head_sha": d2},
           producer="verify.py", basis="occurred", **c),
        ev("verify.verdict", "12:40:00", task="t4", data={"exit": 0, "head_sha": d1},
           producer="verify.py", basis="occurred", **c),
        ev("unit.closed", "12:50:00", task="t4", data={"head_sha": d2, "head_wtree": w1}, **c),
        ev("wave.close", "13:00:00", data={"wave": 2}, **c),
        usage("d1", "t1", 1000, 200, "0.50", 40),
        usage("d2", "t2", 1500, 300, None, 31),
        usage_d3,
        usage_d3,  # duplicate delivery: must not add 500 more input tokens
        usage("d4", "t3", 400, 80, "0.10", 18),
        usage("d5", "t4", 600, 120, "0.15", 27),
        # the reviewers are dispatches too: their spend is part of the run total
        usage("r1", "t1", 300, 60, "0.05", 9, model="claude-review-fixture"),
        usage("r2", "t2", 200, 40, "0.04", 7, model="claude-review-fixture"),
        usage("r3", "t2", 250, 50, "0.05", 8, model="claude-review-fixture"),
        usage("r4", "t4", 150, 30, "0.03", 6, model="claude-review-fixture"),
    ]


CLEAN_ROWS = [
    "| `wave=1` | `builders=2 reviewers=1` | `throughput=1.14/h` | "
    "`latency_median=22.00m latency_max=24.00m` | `rework=1/2` | `freshness=1` |",
    "| `wave=2` | `builders=1 reviewers=1` | `throughput=0.86/h` | "
    "`latency_median=12.50m latency_max=20.00m` | `rework=0/2` | `freshness=0` |",
]


def scenario_crash():
    """run-b: a coordinator crash on host-a, a resume on host-b, and the observations that a
    crash leaves incomplete — every metric below that the record cannot support is unavailable.

    Hand calculation:
      wave 1: opened on host-a, closed on host-b -> no common clock, throughput unavailable;
        u1 done on host-a, verified on host-b -> latency unavailable (two clocks);
        u2's done was RECOVERED at resume -> its time is the rebuild time -> unavailable;
        both verified-CLOSED with fresh approvals, no bounce -> rework 0/2, freshness 0
      wave 2: never closed; u3 verified at 10:25 before its done at 10:30 -> a negative interval
        (a clock that stepped back) -> unavailable, not 0; u4 launched and never heard from
        -> open, so throughput/rework/freshness are unavailable
      wave 3: complete on host-b, but the fenced epoch-1 coordinator wrote unit.suspect for u5
        after epoch 2 was declared -> excluded, and wave 3 is unavailable rather than guessed
      plus: one event of another run, an unplanned reviewer task whose launch was delivered
        twice with different bodies (a conflict), and a usage event under an undeclared epoch
    """
    a = {"run": "run-b", "epoch": 1, "clock": "host-a"}
    b = {"run": "run-b", "epoch": 2, "clock": "host-b"}
    e1, f1, g1, h1 = sha("e1"), sha("f1"), sha("f2"), sha("f3")
    return [
        ev("run.start", "09:00:00", data={"coordinator": "coord-1"}, **a),
        ev("wave.open", "09:00:00", data={"wave": 1, "builders": 2, "reviewers": 1,
                                          "tasks": ["u1", "u2"]}, **a),
        ev("dispatch.launched", "09:01:00", task="u1", dispatch="x1", **a),
        ev("dispatch.launched", "09:02:00", task="u2", dispatch="x2", **a),
        ev("task.done", "09:20:00", task="u1", dispatch="x1", data={"head_sha": e1}, **a),
        ev("run.start", "08:00:00", run="run-other", epoch=1, clock="host-z",
           data={"coordinator": "coord-z"}),
        ev("coordinator.resume", "09:40:00", data={"coordinator": "coord-2"}, **b),
        ev("task.done", "09:35:00", task="u2", dispatch="x2", data={"head_sha": f1},
           basis="recovered", **b),
        ev("review.verdict", "09:44:00", task="u1", data={"verdict": "approve", "reviewed_sha": e1}, **b),
        ev("verify.verdict", "09:45:00", task="u1", data={"exit": 0, "head_sha": e1}, **b),
        ev("unit.closed", "09:50:00", task="u1", data={"head_sha": e1}, **b),
        ev("review.verdict", "09:52:00", task="u2", data={"verdict": "approve", "reviewed_sha": f1}, **b),
        ev("verify.verdict", "09:55:00", task="u2", data={"exit": 0, "head_sha": f1}, **b),
        ev("unit.closed", "10:00:00", task="u2", data={"head_sha": f1}, **b),
        ev("wave.close", "10:05:00", data={"wave": 1}, **b),
        ev("wave.open", "10:10:00", data={"wave": 2, "builders": 1, "reviewers": 1,
                                          "tasks": ["u3", "u4"]}, **b),
        ev("dispatch.launched", "10:11:00", task="u3", dispatch="x3", **b),
        ev("dispatch.launched", "10:12:00", task="u4", dispatch="x4", **b),
        ev("verify.verdict", "10:25:00", task="u3", data={"exit": 0, "head_sha": g1}, **b),
        ev("task.done", "10:30:00", task="u3", dispatch="x3", data={"head_sha": g1}, **b),
        ev("review.verdict", "10:35:00", task="u3", data={"verdict": "approve", "reviewed_sha": g1}, **b),
        ev("unit.closed", "10:40:00", task="u3", data={"head_sha": g1}, **b),
        ev("wave.open", "11:00:00", data={"wave": 3, "builders": 1, "reviewers": 0,
                                          "tasks": ["u5"]}, **b),
        ev("dispatch.launched", "11:01:00", task="u5", dispatch="x5", **b),
        ev("unit.suspect", "11:05:00", task="u5", **a),  # the fenced coordinator, still writing
        ev("task.done", "11:10:00", task="u5", dispatch="x5", data={"head_sha": h1}, **b),
        ev("review.verdict", "11:12:00", task="u5", data={"verdict": "approve", "reviewed_sha": h1}, **b),
        ev("verify.verdict", "11:15:00", task="u5", data={"exit": 0, "head_sha": h1}, **b),
        ev("unit.closed", "11:20:00", task="u5", data={"head_sha": h1}, **b),
        ev("wave.close", "11:30:00", data={"wave": 3}, **b),
        ev("dispatch.launched", "10:20:00", task="rv1", dispatch="xr1", data={"agent": "claude"},
           event_id="rv-launch", **b),
        ev("dispatch.launched", "10:20:00", task="rv1", dispatch="xr1", data={"agent": "codex"},
           event_id="rv-launch", **b),
        ev("model.usage", "11:31:00", run="run-b", epoch=3, clock="host-b", dispatch="x1",
           data={"model": "claude-fixture", "input_tokens": 10, "provenance": "undeclared epoch"}),
        ev("model.usage", "11:31:00", task="u5", dispatch="x5",
           data={"model": None, "input_tokens": 900,
                 "provenance": "fixture stream x5 result line 12; not reported: model, output_tokens, cost_usd"},
           event_id="usage:x5:12", **b),
    ]


CRASH_ROWS = [
    "| `wave=1` | `builders=2 reviewers=1` | `throughput=unavailable` | "
    "`latency_median=unavailable latency_max=unavailable` | `rework=0/2` | `freshness=0` |",
    "| `wave=2` | `builders=1 reviewers=1` | `throughput=unavailable` | "
    "`latency_median=unavailable latency_max=unavailable` | `rework=unavailable` | "
    "`freshness=unavailable` |",
    "| `wave=3` | `builders=1 reviewers=0` | `throughput=unavailable` | "
    "`latency_median=unavailable latency_max=unavailable` | `rework=unavailable` | "
    "`freshness=unavailable` |",
]

SCENARIOS = {"clean-two-waves": (scenario_clean, "run-a"), "crash-resume": (scenario_crash, "run-b")}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="events-"))
        self.log = self.tmp / "state" / "events.jsonl"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, evs, path=None):
        path = path or self.log
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(chain(evs), encoding="utf-8")
        return path

    def derive(self, evs, run=None):
        self.write(evs)
        recorded, file_sha, head = events.read_log(self.log)
        return events.derive(recorded, run, file_sha, head)

    def cli(self, *args, log=None, env=None):
        return subprocess.run([sys.executable, str(EVENTS), "--log", str(log or self.log), *args],
                              capture_output=True, text=True, env=env, cwd=str(self.tmp))

    def rows(self, report):
        return [w["row"] for w in report["waves"]]

    def metric(self, report, wave, name):
        return report["waves"][wave - 1]["metrics"][name]


class TestHandCalculatedRows(Base):
    """The derived rows equal the rows calculated by hand from the scenario timestamps."""

    def test_clean_stream_derives_the_hand_calculated_rows(self):
        report = self.derive(scenario_clean())
        self.assertEqual(self.rows(report), CLEAN_ROWS)
        self.assertTrue(report["complete"])

    def test_clean_stream_extra_metrics_and_outcomes(self):
        report = self.derive(scenario_clean())
        self.assertEqual(self.metric(report, 1, "review_queue_median")["value"], "5.00m")
        self.assertEqual(self.metric(report, 1, "review_queue_max")["value"], "10.00m")
        self.assertEqual(self.metric(report, 1, "retries")["value"], "1")
        self.assertEqual(self.metric(report, 2, "retries")["value"], "0")
        self.assertEqual(self.metric(report, 1, "throughput")["wall_clock_s"], "6300")
        # task completion, verified-CLOSED and parked are distinct counts
        self.assertEqual(report["waves"][0]["outcomes"]["verified-closed"], 2)
        self.assertEqual(report["waves"][1]["outcomes"]["verified-closed"], 1)
        self.assertEqual(report["waves"][1]["outcomes"]["parked"], 1)
        self.assertEqual(report["waves"][1]["outcomes"]["task_completed"], 2)
        units = {u["task"]: u for w in report["waves"] for u in w["units"]}
        self.assertEqual(units["t2"]["voided_reviews"], [sha("b1")])
        self.assertEqual(units["t4"]["voided_reviews"], [], "a tree-equal rebase keeps the review")
        self.assertTrue(units["t2"]["bounced"])
        self.assertEqual(units["t2"]["dispatches"], ["d2", "d3"])
        self.assertEqual(units["t3"]["park_classes"], ["needs-human"])

    def test_crash_stream_derives_the_hand_calculated_rows(self):
        report = self.derive(scenario_crash(), run="run-b")
        self.assertEqual(self.rows(report), CRASH_ROWS)
        self.assertFalse(report["complete"])
        self.assertEqual(report["record"]["other_run_events"], 1)
        self.assertEqual(report["record"]["conflicts"], 1)
        self.assertEqual(report["record"]["fenced"], 2)
        self.assertEqual([e["epoch"] for e in report["epochs"]], [1, 2])
        self.assertEqual(report["unplanned"], [{"task": "rv1", "events": 1}])

    def test_crash_stream_names_why_each_metric_is_unavailable(self):
        report = self.derive(scenario_crash(), run="run-b")

        def reasons(wave, name):
            return " ".join(self.metric(report, wave, name)["unavailable"])
        self.assertIn("different clocks", reasons(1, "throughput"))
        self.assertIn("different clocks", reasons(1, "latency_median"))
        self.assertIn("recovered after a coordinator resume", reasons(1, "latency_median"))
        self.assertIn("negative", reasons(2, "latency_max"))
        self.assertIn("never clamped to 0", reasons(2, "latency_max"))
        self.assertIn("wave.close not observed", reasons(2, "throughput"))
        self.assertIn("['u4']", reasons(2, "rework"))
        self.assertIn("fenced coordinator", reasons(3, "throughput"))
        self.assertIn("fenced coordinator", reasons(3, "freshness"))


class TestFixturesReproduce(Base):
    """Committed fixture streams, and the reports over them, reproduce byte-for-byte."""

    def test_committed_streams_are_the_documented_scenarios(self):
        for name, (build, _run) in SCENARIOS.items():
            with self.subTest(name):
                self.assertEqual((FIXTURES / f"{name}.jsonl").read_text(encoding="utf-8"),
                                 chain(build()))

    def test_report_is_byte_for_byte_the_golden_report(self):
        for name, (_build, run) in SCENARIOS.items():
            for fmt, ext in ((["--json"], "json"), ([], "md")):
                with self.subTest(name=name, fmt=ext):
                    proc = self.cli("report", "--run", run, *fmt, log=FIXTURES / f"{name}.jsonl")
                    self.assertIn(proc.returncode, (0, 1), proc.stderr)
                    self.assertEqual(proc.stdout,
                                     (FIXTURES / f"{name}.report.{ext}").read_text(encoding="utf-8"))

    def test_report_does_not_depend_on_hash_seed_timezone_or_cwd(self):
        golden = (FIXTURES / "clean-two-waves.report.json").read_text(encoding="utf-8")
        for seed, tz in (("0", "UTC"), ("12345", "Asia/Kolkata"), ("random", "America/Los_Angeles")):
            env = dict(os.environ, PYTHONHASHSEED=seed, TZ=tz)
            proc = self.cli("report", "--json", log=FIXTURES / "clean-two-waves.jsonl", env=env)
            self.assertEqual(proc.stdout, golden, f"seed={seed} tz={tz}")

    def test_the_report_names_raw_event_digests_and_exact_revisions(self):
        path = FIXTURES / "clean-two-waves.jsonl"
        raw_lines = [ln for ln in path.read_text(encoding="utf-8").split("\n") if ln]
        report = json.loads((FIXTURES / "clean-two-waves.report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["record"]["log_sha256"], events.sha256_hex(path.read_bytes()))
        self.assertEqual(report["record"]["head"], events.sha256_hex(raw_lines[-1]))
        digests = {events.sha256_hex(ln) for ln in raw_lines}
        cited = {e["digest"] for w in report["waves"] for u in w["units"] for e in u["events"]}
        self.assertTrue(cited and cited <= digests)
        t4 = next(u for w in report["waves"] for u in w["units"] if u["task"] == "t4")
        self.assertEqual(t4["revisions"]["closed_at"], sha("d2"))
        self.assertEqual(t4["revisions"]["verified_at"], [sha("d1"), sha("d2")])


class TestOrderAndDuplicates(Base):
    def _metrics(self, report):
        return [(w["row"], json.dumps(w["metrics"], sort_keys=True)) for w in report["waves"]]

    def test_any_append_order_derives_the_same_rows(self):
        baseline = self._metrics(self.derive(scenario_clean()))
        for seed in range(6):
            evs = scenario_clean()
            head, rest = evs[:1], evs[1:]  # run.start must declare epoch 1 before it is used
            random.Random(seed).shuffle(rest)
            with self.subTest(seed=seed):
                self.assertEqual(self._metrics(self.derive(head + rest)), baseline)

    def test_a_duplicate_delivery_does_not_double_count(self):
        report = self.derive(scenario_clean())
        self.assertEqual(report["record"]["duplicates"], 2)
        model = report["usage"]["models"]["claude-fixture"]
        self.assertEqual(model["observations"], 5)
        self.assertEqual(model["input_tokens"], {"value": 4000})
        self.assertEqual(report["usage"]["run_total"]["output_tokens"], {"value": 980})

    def test_a_re_observation_never_moves_an_interval_endpoint(self):
        # t1's done is seen twice (10:20 at the store, 10:21 by the coordinator); latency is 20m.
        report = self.derive(scenario_clean())
        t1 = next(u for u in report["waves"][0]["units"] if u["task"] == "t1")
        self.assertEqual(t1["latency"]["value"], "20.00m")

    def test_append_skips_an_event_the_record_already_holds(self):
        evs = scenario_clean()[:3]
        first = events.append_events(self.log, evs)
        again = events.append_events(self.log, evs)
        self.assertEqual([s for _i, s in first], ["appended"] * 3)
        self.assertEqual([s for _i, s in again], ["duplicate"] * 3)
        self.assertEqual(len(self.log.read_text(encoding="utf-8").splitlines()), 3)

    def test_a_reused_id_with_a_different_body_contests_the_unit(self):
        evs = scenario_clean()
        evs.append(ev("unit.closed", "10:56:00", task="t1", data={"head_sha": sha("a9")},
                      event_id=evs[14]["event_id"], run="run-a", epoch=1, clock="host-a"))
        report = self.derive(evs)
        self.assertEqual(report["record"]["conflicts"], 1)
        reasons = self.metric(report, 1, "throughput")["unavailable"]
        self.assertTrue(any("different bodies" in r for r in reasons), reasons)
        self.assertEqual(self.metric(report, 2, "throughput")["value"], "0.86/h",
                         "a conflict contests its own wave, not every wave")


ONE = {"run": "r", "epoch": 1, "clock": "host-a"}


def unit_stream(done_at="10:10:00", verdict_at="10:20:00", done_kw=None, verdict_kw=None):
    """One unit, one wave, one clock: done 10:10 -> verified 10:20 (latency 10 m)."""
    c = ONE
    return [
        ev("run.start", "10:00:00", data={"coordinator": "c1"}, **c),
        ev("wave.open", "10:00:00", data={"wave": 1, "builders": 1, "reviewers": 1, "tasks": ["t"]}, **c),
        ev("dispatch.launched", "10:01:00", task="t", dispatch="d", **c),
        ev("task.done", done_at, task="t", dispatch="d", data={"head_sha": sha("aa")},
           **{**c, **(done_kw or {})}),
        ev("review.verdict", "10:15:00", task="t", data={"verdict": "approve", "reviewed_sha": sha("aa")}, **c),
        ev("verify.verdict", verdict_at, task="t", data={"exit": 0, "head_sha": sha("aa")},
           **{**c, **(verdict_kw or {})}),
        ev("unit.closed", "10:30:00", task="t", data={"head_sha": sha("aa")}, **c),
        ev("wave.close", "10:40:00", data={"wave": 1}, **c),
    ]


class TestClocksAndResume(Base):
    def test_control_the_same_stream_on_one_clock_is_measured(self):
        report = self.derive(unit_stream())
        self.assertEqual(self.metric(report, 1, "latency_max")["value"], "10.00m")

    def test_a_negative_interval_is_unavailable_never_zero(self):
        report = self.derive(unit_stream(done_at="10:25:00"))
        latency = self.metric(report, 1, "latency_max")
        self.assertIsNone(latency["value"])
        self.assertTrue(any("negative" in r for r in latency["unavailable"]))

    def test_two_clocks_give_no_interval(self):
        report = self.derive(unit_stream(verdict_kw={"clock": "host-b"}))
        self.assertIsNone(self.metric(report, 1, "latency_median")["value"])

    def test_a_recovered_endpoint_gives_no_interval(self):
        report = self.derive(unit_stream(done_kw={"basis": "recovered"}))
        self.assertIsNone(self.metric(report, 1, "latency_median")["value"])
        self.assertEqual(self.metric(report, 1, "rework")["value"], "0/1",
                         "recovery hides a time, not an outcome")

    def test_a_fenced_coordinators_write_is_excluded_and_contests_its_wave(self):
        evs = unit_stream()
        evs.insert(4, ev("coordinator.resume", "10:12:00", data={"coordinator": "c2"},
                         run="r", epoch=2, clock="host-a"))
        for event in evs[5:]:
            event["epoch"] = 2
        evs.append(ev("unit.suspect", "10:41:00", task="t", **ONE))  # epoch 1, after the resume
        report = self.derive(evs)
        self.assertEqual(report["record"]["fenced"], 1)
        self.assertIsNone(self.metric(report, 1, "rework")["value"],
                          "the stale SUSPECT is neither counted nor silently dropped")
        self.assertTrue(any("fenced coordinator" in r
                            for r in self.metric(report, 1, "rework")["unavailable"]))

    def test_resume_on_the_same_clock_keeps_intervals_that_span_it(self):
        evs = unit_stream()
        evs.insert(4, ev("coordinator.resume", "10:12:00", data={"coordinator": "c2"},
                         run="r", epoch=2, clock="host-a"))
        for event in evs[5:]:
            event["epoch"] = 2
        report = self.derive(evs)
        self.assertEqual(self.metric(report, 1, "latency_max")["value"], "10.00m")

    def test_missing_run_history_is_unavailable_not_complete(self):
        # PR #638 review (P2): a record that opens on a resume, a run.start past epoch 1, or a
        # resume that skips an epoch is missing coordinator history; it must not read complete.
        def at_epoch(evs, epoch, start=0):
            for event in evs[start:]:
                event["epoch"] = epoch
            return evs

        opens_on_resume = unit_stream()
        opens_on_resume[0] = ev("coordinator.resume", "10:00:00", data={"coordinator": "c2"}, **ONE)
        skipped = unit_stream()
        skipped.insert(4, ev("coordinator.resume", "10:12:00", data={"coordinator": "c3"},
                             run="r", epoch=3, clock="host-a"))
        cases = {"opens on a resume": opens_on_resume,
                 "run.start at epoch 2": at_epoch(unit_stream(), 2),
                 "resume skips epoch 2": at_epoch(skipped, 3, 5)}
        for name, evs in cases.items():
            with self.subTest(name):
                report = self.derive(evs)
                self.assertFalse(report["complete"])
                reasons = self.metric(report, 1, "throughput")["unavailable"]
                self.assertTrue(any("missing" in r for r in reasons), reasons)

    def test_an_undeclared_epoch_is_excluded(self):
        evs = unit_stream()
        evs[5]["epoch"] = 2  # a verdict under an epoch no resume declared
        report = self.derive(evs)
        self.assertEqual(report["record"]["fenced"], 1)
        self.assertIsNone(self.metric(report, 1, "throughput")["value"])

    def test_without_run_start_nothing_is_measured(self):
        report = self.derive(unit_stream()[1:])
        self.assertFalse(report["complete"])
        self.assertEqual(report["record"]["fenced"], 7, "every event's epoch is undeclared")
        self.assertEqual(report["waves"], [])

    def test_a_missing_wave_close_leaves_throughput_unavailable(self):
        report = self.derive(unit_stream()[:-1])
        self.assertIsNone(self.metric(report, 1, "throughput")["value"])
        self.assertEqual(self.metric(report, 1, "latency_max")["value"], "10.00m")

    def test_a_unit_with_no_close_leaves_throughput_unavailable(self):
        evs = [e for e in unit_stream() if e["kind"] != "unit.closed"]
        report = self.derive(evs)
        self.assertIsNone(self.metric(report, 1, "throughput")["value"])
        self.assertEqual(report["waves"][0]["units"][0]["outcome"], "verified")

    def test_a_close_with_no_passing_verdict_is_completion_not_verified_closed(self):
        evs = [e for e in unit_stream() if e["kind"] != "verify.verdict"]
        report = self.derive(evs)
        self.assertEqual(report["waves"][0]["units"][0]["outcome"], "closed-unverified")
        self.assertEqual(self.metric(report, 1, "throughput")["verified_closed"], 0)


def carried_stream(late_clock="host-a"):
    """Task t parked in wave 1, re-planned, retried and closed in wave 2 (one clock).

    Hand calculation: wave 1 10:00-10:20 (1200 s): parked, 0 closed -> 0.00/h; done 10:10 ->
    parked 10:15 = 5 m. Wave 2 10:30-11:00 (1800 s): 1 closed -> 2.00/h; done 10:40 -> pass
    10:45 = 5 m."""
    c = ONE
    late = dict(c, clock=late_clock)
    return [
        ev("run.start", "10:00:00", data={"coordinator": "c1"}, **c),
        ev("wave.open", "10:00:00", data={"wave": 1, "builders": 1, "reviewers": 1, "tasks": ["t"]}, **c),
        ev("dispatch.launched", "10:01:00", task="t", dispatch="d1", **c),
        ev("task.done", "10:10:00", task="t", dispatch="d1", data={"head_sha": sha("a1")}, **c),
        ev("unit.parked", "10:15:00", task="t", data={"park_class": "needs-human", "head_sha": sha("a1")}, **c),
        ev("wave.close", "10:20:00", data={"wave": 1}, **c),
        ev("wave.open", "10:30:00", data={"wave": 2, "builders": 1, "reviewers": 1, "tasks": ["t"]}, **c),
        ev("dispatch.launched", "10:31:00", task="t", dispatch="d2", **c),
        ev("task.done", "10:40:00", task="t", dispatch="d2", data={"head_sha": sha("b1")}, **late),
        ev("review.verdict", "10:42:00", task="t", data={"verdict": "approve", "reviewed_sha": sha("b1")}, **c),
        ev("verify.verdict", "10:45:00", task="t", data={"exit": 0, "head_sha": sha("b1")}, **c),
        ev("unit.closed", "10:50:00", task="t", data={"head_sha": sha("b1")}, **c),
        ev("wave.close", "11:00:00", data={"wave": 2}, **c),
    ]


class TestCarriedUnits(Base):
    """PR #638 review (P1): a later close must not rewrite an earlier wave's outcome."""

    def test_each_wave_measures_its_own_window_of_a_carried_unit(self):
        report = self.derive(carried_stream())
        self.assertEqual(report["waves"][0]["row"],
                         "| `wave=1` | `builders=1 reviewers=1` | `throughput=0.00/h` | "
                         "`latency_median=5.00m latency_max=5.00m` | `rework=0/1` | `freshness=0` |")
        self.assertEqual([u["outcome"] for u in report["waves"][0]["units"]], ["parked"])
        self.assertEqual([u["outcome"] for u in report["waves"][1]["units"]], ["verified-closed"])
        self.assertEqual(self.metric(report, 2, "throughput")["value"], "2.00/h")
        self.assertEqual(self.metric(report, 2, "latency_max")["value"], "5.00m")
        self.assertEqual(report["carried"], [{"task": "t", "waves": [1, 2]}])

    def test_an_event_no_window_can_hold_leaves_both_waves_unavailable(self):
        report = self.derive(carried_stream(late_clock="host-b"))
        for wave in (1, 2):
            reasons = self.metric(report, wave, "throughput")["unavailable"]
            with self.subTest(wave=wave):
                self.assertTrue(any("cannot be placed" in r for r in reasons), reasons)

    def test_a_recovered_wave_opening_is_no_boundary_for_earlier_work(self):
        # PR #638 review (P1): place() refused an event whose own time was recovered, but used
        # a recovered wave.open as a known boundary. Its time is when it was rebuilt, later than
        # the opening, so wave-2 work done before the rebuild landed in wave 1: the replacement
        # d2 and its retry counted there (rework 1/1) and wave 2 lost them (rework 0/1).
        evs = carried_stream()
        evs[6] = ev("wave.open", "10:47:00", data={"wave": 2, "builders": 1, "reviewers": 1,
                                                   "tasks": ["t"]}, basis="recovered", **ONE)
        report = self.derive(evs)
        for wave in (1, 2):
            reasons = self.metric(report, wave, "rework")["unavailable"]
            with self.subTest(wave=wave):
                self.assertTrue(any("cannot be placed" in r and "recovered" in r for r in reasons),
                                reasons)

    def test_work_after_a_recovered_opening_is_still_placed(self):
        # Control: a rebuilt opening time is no earlier than the real one, so an event at or
        # after it is in that wave (or a later one) for certain. t was planned in wave 1 but
        # did nothing there; all of its work follows wave 2's rebuilt opening. Only wave 2's
        # wall-clock, an interval with a recovered end, is unavailable.
        stream = carried_stream()  # drop wave 1's launch, done and park of t (indexes 2-4)
        evs = stream[:2] + [stream[5], ev("wave.open", "10:30:00", basis="recovered", **ONE, data={
            "wave": 2, "builders": 1, "reviewers": 1, "tasks": ["t"]})] + stream[7:]
        report = self.derive(evs)
        self.assertEqual([e["kind"] for e in evs][:5],
                         ["run.start", "wave.open", "wave.close", "wave.open", "dispatch.launched"])
        self.assertEqual(self.metric(report, 2, "latency_max")["value"], "5.00m")
        self.assertEqual(self.metric(report, 2, "rework")["value"], "0/1")
        self.assertTrue(any("recovered" in r for r in self.metric(report, 2, "throughput")["unavailable"]))

    def test_an_opening_rebuilt_after_a_later_wave_opened_does_not_refuse_that_wave(self):
        # Guard: wave 2's opening was rebuilt at 11:20, after wave 3 opened at 11:00. Work at
        # 11:06-11:15 follows wave 3's real opening, so it is wave 3's whatever wave 2's was.
        c, a = ONE, sha("a1")
        evs = [ev("run.start", "10:00:00", data={"coordinator": "c1"}, **c)] + [
            ev("wave.open", at, data={"wave": k, "builders": 1, "reviewers": 1, "tasks": ["t"]},
               basis=basis, **c)
            for k, at, basis in ((1, "10:00:00", "observed"), (2, "11:20:00", "recovered"),
                                 (3, "11:00:00", "observed"))] + [
            ev("dispatch.launched", "11:06:00", task="t", dispatch="d1", **c),
            ev("task.done", "11:10:00", task="t", dispatch="d1", data={"head_sha": a}, **c),
            ev("verify.verdict", "11:15:00", task="t", data={"exit": 0, "head_sha": a}, **c)]
        units = self.derive(evs)["waves"][2]["units"]
        self.assertEqual((units[0]["outcome"], units[0]["latency"]["value"]), ("verified", "5.00m"))

    def test_a_worker_carried_into_the_next_wave_is_not_a_replacement(self):
        # PR #638 review (P1): d1 launched in wave 1 and finished in wave 2. Wave 2 saw d1 and
        # the task's earlier dispatch d1, so it marked the unit bounced, and with d1's launch in
        # wave 1's window its retries were "reported without an observed launch".
        report = self.derive(inflight_stream())
        self.assertEqual([self.metric(report, 2, m)["value"] for m in ("rework", "retries")],
                         ["0/1", "0"])
        self.assertEqual(report["waves"][1]["row"],
                         "| `wave=2` | `builders=1 reviewers=1` | `throughput=2.00/h` | "
                         "`latency_median=5.00m latency_max=5.00m` | `rework=0/1` | `freshness=0` |")

    def test_a_unit_carried_out_in_flight_leaves_its_earlier_wave_measured(self):
        # Sweep (cross-wave carry-over): t was still in flight when wave 1 closed and wave 2
        # re-planned it, so every later event of t is placed in wave 2 — wave 1's view of it is
        # final. "Not observed CLOSED or parked — a pending close would change the count" left
        # wave 1 unavailable for good; t closed nothing there and has no latency there.
        report = self.derive(inflight_stream())
        self.assertEqual(report["waves"][0]["row"],
                         "| `wave=1` | `builders=2 reviewers=1` | `throughput=3.00/h` | "
                         "`latency_median=5.00m latency_max=5.00m` | `rework=0/2` | `freshness=0` |")
        self.assertEqual(self.metric(report, 1, "retries")["value"], "0")

    def test_a_done_in_one_wave_and_its_pass_in_the_next_measure_latency_there(self):
        # Sweep: the worker_done is a fact at a head whichever wave saw it; the interval it
        # starts belongs to the wave its end (the pass) is placed in. Wave 2 read "verified
        # without an observed worker_done" and its retries "no dispatch observed".
        # Hand calculation: done@A 10:10 (wave 1) -> pass@A 10:40 (wave 2) = 30 m; wave 2
        # 10:30-11:00 (1800 s), one close -> 2.00/h.
        a = sha("a1")
        report = self.derive(two_wave_stream(
            wave1=[("task.done", "10:10:00", {"dispatch": "d1", "data": {"head_sha": a}})],
            wave2=[("review.verdict", "10:35:00", {"data": {"verdict": "approve", "reviewed_sha": a}}),
                   ("verify.verdict", "10:40:00", {"data": {"exit": 0, "head_sha": a}}),
                   ("unit.closed", "10:50:00", {"data": {"head_sha": a}})]))
        self.assertEqual(report["waves"][1]["row"],
                         "| `wave=2` | `builders=1 reviewers=1` | `throughput=2.00/h` | "
                         "`latency_median=30.00m latency_max=30.00m` | `rework=0/1` | "
                         "`freshness=0` |")
        self.assertEqual(self.metric(report, 2, "retries")["value"], "0")
        self.assertEqual(report["waves"][0]["units"][0]["latency"]["value"], None)
        self.assertIn("excluded", report["waves"][0]["units"][0]["latency"])

    def test_a_unit_verified_in_one_wave_and_closed_in_the_next_is_verified_closed_there(self):
        # Sweep: wave 2 judged the close only by its own verdicts, so a head verified in wave 1
        # and closed in wave 2 read closed-unverified and throughput counted 0 — a wrong number.
        # Its latency ended in wave 1, which measures it; wave 2 never measures it again, not
        # even when it re-verifies the same head.
        a = sha("a1")
        wave1 = [("task.done", "10:10:00", {"dispatch": "d1", "data": {"head_sha": a}}),
                 ("review.verdict", "10:12:00", {"data": {"verdict": "approve", "reviewed_sha": a}}),
                 ("verify.verdict", "10:15:00", {"data": {"exit": 0, "head_sha": a}})]
        for again in ([], [("verify.verdict", "10:35:00", {"data": {"exit": 0, "head_sha": a}})]):
            with self.subTest(reverified=bool(again)):
                report = self.derive(two_wave_stream(
                    wave1=wave1, wave2=again + [("unit.closed", "10:40:00", {"data": {"head_sha": a}})]))
                self.assertEqual(report["waves"][0]["row"],
                                 "| `wave=1` | `builders=1 reviewers=1` | `throughput=0.00/h` | "
                                 "`latency_median=5.00m latency_max=5.00m` | `rework=0/1` | "
                                 "`freshness=0` |")
                self.assertEqual(report["waves"][1]["units"][0]["outcome"], "verified-closed")
                self.assertEqual(self.metric(report, 2, "throughput")["value"], "2.00/h")
                self.assertEqual(self.metric(report, 2, "freshness")["value"], "0")
                self.assertIn("excluded", report["waves"][1]["units"][0]["latency"])

    def test_an_approval_before_the_carry_is_voided_by_the_close_after_it(self):
        # Sweep: freshness judged a close only against its own wave's approvals, so wave 1's
        # approval of A, superseded when wave 2 closed at B, was counted in neither wave.
        a, b = sha("a1"), sha("b1")
        report = self.derive(two_wave_stream(
            wave1=[("task.done", "10:10:00", {"dispatch": "d1", "data": {"head_sha": a}}),
                   ("review.verdict", "10:12:00", {"data": {"verdict": "approve", "reviewed_sha": a}})],
            wave2=[("task.done", "10:40:00", {"dispatch": "d1", "data": {"head_sha": b}}),
                   ("review.verdict", "10:42:00", {"data": {"verdict": "approve", "reviewed_sha": b}}),
                   ("verify.verdict", "10:45:00", {"data": {"exit": 0, "head_sha": b}}),
                   ("unit.closed", "10:50:00", {"data": {"head_sha": b}})]))
        self.assertEqual([self.metric(report, k, "freshness")["value"] for k in (1, 2)], ["0", "1"])
        self.assertEqual(report["waves"][1]["units"][0]["voided_reviews"], [a])
        self.assertEqual(self.metric(report, 2, "latency_max")["value"], "5.00m")

    def test_a_void_counted_in_an_earlier_wave_is_not_counted_again_after_a_reopen(self):
        # Sweep (cross-wave counts): t closed at B in wave 1, which voided the approval of A
        # there; it was reopened in wave 2, where the void of A was recorded late. Wave 2 counted
        # it again as "a void without its approval": one voided review, two violations.
        a, b, c = sha("a1"), sha("b1"), sha("c1")
        report = self.derive(two_wave_stream(
            wave1=[("task.done", "10:05:00", {"dispatch": "d1", "data": {"head_sha": a}}),
                   ("review.verdict", "10:06:00", {"data": {"verdict": "approve", "reviewed_sha": a}}),
                   ("task.done", "10:08:00", {"dispatch": "d1", "data": {"head_sha": b}}),
                   ("review.verdict", "10:09:00", {"data": {"verdict": "approve", "reviewed_sha": b}}),
                   ("verify.verdict", "10:10:00", {"data": {"exit": 0, "head_sha": b}}),
                   ("unit.closed", "10:12:00", {"data": {"head_sha": b}})],
            wave2=[("review.voided", "10:35:00", {"data": {"reviewed_sha": a, "head_sha": b}}),
                   ("task.done", "10:40:00", {"dispatch": "d1", "data": {"head_sha": c}}),
                   ("review.verdict", "10:42:00", {"data": {"verdict": "approve", "reviewed_sha": c}}),
                   ("verify.verdict", "10:45:00", {"data": {"exit": 0, "head_sha": c}}),
                   ("unit.closed", "10:50:00", {"data": {"head_sha": c}})]))
        self.assertEqual([self.metric(report, k, "freshness")["value"] for k in (1, 2)], ["1", "0"])

    def test_a_park_before_any_worker_done_ended_no_interval(self):
        # PR #638 review (P1): every earlier park at a head counted as an interval already
        # measured. t parked at A in wave 1 before any worker_done (that wave measured nothing),
        # resumed unchanged and finished at A in wave 2: its done -> pass there was dropped.
        a = sha("a1")
        report = self.derive(two_wave_stream(
            wave1=[("unit.parked", "10:15:00", {"data": {"park_class": "needs-human", "head_sha": a}})],
            wave2=[("task.done", "10:40:00", {"dispatch": "d1", "data": {"head_sha": a}}),
                   ("review.verdict", "10:42:00", {"data": {"verdict": "approve", "reviewed_sha": a}}),
                   ("verify.verdict", "10:45:00", {"data": {"exit": 0, "head_sha": a}}),
                   ("unit.closed", "10:50:00", {"data": {"head_sha": a}})]))
        self.assertIn("parked with no worker_done", report["waves"][0]["units"][0]["latency"]["excluded"])
        self.assertEqual(report["waves"][1]["units"][0]["latency"]["value"], "5.00m")
        self.assertEqual(self.metric(report, 2, "latency_max")["value"], "5.00m")

    def test_an_interval_an_earlier_wave_ended_is_not_measured_again(self):
        # Sweep guard: with earlier worker_done events as interval starts, a head parked in
        # wave 1 and verified in wave 2 would get a second latency spanning the park, and a
        # re-review a second queue time. Each is measured once, where its first end is placed.
        a = sha("a1")
        report = self.derive(two_wave_stream(
            wave1=[("task.done", "10:10:00", {"dispatch": "d1", "data": {"head_sha": a}}),
                   ("review.started", "10:11:00", {"dispatch": "r1", "data": {"head_sha": a}}),
                   ("unit.parked", "10:15:00", {"data": {"park_class": "needs-human", "head_sha": a}})],
            wave2=[("review.started", "10:35:00", {"dispatch": "r1", "data": {"head_sha": a}}),
                   ("review.verdict", "10:36:00", {"data": {"verdict": "approve", "reviewed_sha": a}}),
                   ("verify.verdict", "10:40:00", {"data": {"exit": 0, "head_sha": a}}),
                   ("unit.closed", "10:50:00", {"data": {"head_sha": a}})]))
        self.assertEqual(self.metric(report, 1, "latency_max")["value"], "5.00m")
        self.assertEqual(self.metric(report, 1, "review_queue_max")["value"], "1.00m")
        unit = report["waves"][1]["units"][0]
        self.assertEqual((unit["outcome"], unit["latency"]["value"]), ("verified-closed", None))
        self.assertIn("ended in an earlier wave", unit["latency"]["excluded"])
        self.assertEqual(self.metric(report, 2, "review_queue_max")["unavailable"],
                         ["wave 2: only re-reviews of heads an earlier wave measured"])


def inflight_stream():
    """Wave 1 plans t and u; t's worker d1 launches in wave 1 and is still running when wave 1
    closes; wave 2 re-plans t, and d1 finishes it there. u closes in wave 1.

    Hand calculation: wave 1 10:00-10:20 (1200 s), u closed -> 3.00/h; u done 10:10 -> pass
    10:15 = 5 m; t carried with no latency there. Wave 2 10:30-11:00 (1800 s), t closed ->
    2.00/h; t done 10:40 -> pass 10:45 = 5 m."""
    c = ONE
    t, u = sha("a1"), sha("c1")
    return [
        ev("run.start", "10:00:00", data={"coordinator": "c1"}, **c),
        ev("wave.open", "10:00:00", data={"wave": 1, "builders": 2, "reviewers": 1,
                                          "tasks": ["t", "u"]}, **c),
        ev("dispatch.launched", "10:01:00", task="t", dispatch="d1", **c),
        ev("dispatch.launched", "10:02:00", task="u", dispatch="e1", **c),
        ev("task.done", "10:10:00", task="u", dispatch="e1", data={"head_sha": u}, **c),
        ev("review.verdict", "10:12:00", task="u", data={"verdict": "approve", "reviewed_sha": u}, **c),
        ev("verify.verdict", "10:15:00", task="u", data={"exit": 0, "head_sha": u}, **c),
        ev("unit.closed", "10:18:00", task="u", data={"head_sha": u}, **c),
        ev("wave.close", "10:20:00", data={"wave": 1}, **c),
        ev("wave.open", "10:30:00", data={"wave": 2, "builders": 1, "reviewers": 1, "tasks": ["t"]}, **c),
        ev("task.done", "10:40:00", task="t", dispatch="d1", data={"head_sha": t}, **c),
        ev("review.verdict", "10:42:00", task="t", data={"verdict": "approve", "reviewed_sha": t}, **c),
        ev("verify.verdict", "10:45:00", task="t", data={"exit": 0, "head_sha": t}, **c),
        ev("unit.closed", "10:50:00", task="t", data={"head_sha": t}, **c),
        ev("wave.close", "11:00:00", data={"wave": 2}, **c),
    ]


def two_wave_stream(wave1, wave2):
    """Task t planned in wave 1 (10:00-10:20) and again in wave 2 (10:30-11:00), its worker d1
    launched at 10:01; `wave1`/`wave2` are (kind, time, fields) placed inside each window."""
    c = ONE

    def placed(specs):
        return [ev(kind, at, task="t", **fields, **c) for kind, at, fields in specs]
    return ([ev("run.start", "10:00:00", data={"coordinator": "c1"}, **c),
             ev("wave.open", "10:00:00", data={"wave": 1, "builders": 1, "reviewers": 1,
                                               "tasks": ["t"]}, **c),
             ev("dispatch.launched", "10:01:00", task="t", dispatch="d1", **c)]
            + placed(wave1)
            + [ev("wave.close", "10:20:00", data={"wave": 1}, **c),
               ev("wave.open", "10:30:00", data={"wave": 2, "builders": 1, "reviewers": 1,
                                                 "tasks": ["t"]}, **c)]
            + placed(wave2)
            + [ev("wave.close", "11:00:00", data={"wave": 2}, **c)])


class TestRedispatchIsRework(Base):
    """PR #638 review (P1): rework is the share of units bounced 'by evidence-manifest.md §2
    (re-dispatch / SUSPECT)' — a replaced worker is a re-dispatch, verdict or not."""

    def test_a_worker_that_died_and_was_replaced_counts_as_rework(self):
        evs = unit_stream()
        evs.insert(3, ev("dispatch.died", "10:05:00", task="t", dispatch="d", **ONE))
        evs.insert(4, ev("dispatch.launched", "10:06:00", task="t", dispatch="d2", **ONE))
        evs[5]["dispatch"] = "d2"
        report = self.derive(evs)
        self.assertEqual(self.metric(report, 1, "rework")["value"], "1/1")
        self.assertEqual(self.metric(report, 1, "retries")["value"], "1")

    def test_control_a_single_dispatch_is_not_rework(self):
        self.assertEqual(self.metric(self.derive(unit_stream()), 1, "rework")["value"], "0/1")

    def test_a_replacement_that_reuses_the_dispatch_id_is_still_a_retry(self):
        # PR #638 review (P1): multiclaude's worker_start names a worker of-<task_id>, so a
        # restart of the task reuses the dispatch id. ingest-state records each launch of the
        # re-recorded row at its creation time, but derive keyed attempts on the id alone and
        # merged them: the first worker died, the second finished with no failing verdict or
        # SUSPECT, and the unit read no retry and no rework.
        def launch(at):
            return ev("dispatch.launched", at, task="t", dispatch="of-t", producer="local_state",
                      basis="occurred", ref="local-state:dispatches/of-t",
                      event_id=f"local-state:dispatch:of-t@{at}", **ONE)
        evs = unit_stream()
        evs[2] = launch("10:01:00")
        evs[3:3] = [ev("dispatch.died", "10:03:00", task="t", dispatch="of-t", **ONE), launch("10:05:00")]
        for event in evs:
            if event["dispatch"] == "d":
                event["dispatch"] = "of-t"
        report = self.derive(evs)
        self.assertEqual([self.metric(report, 1, m)["value"] for m in ("retries", "rework")], ["1", "1/1"])
        self.assertEqual(report["waves"][0]["units"][0]["dispatches"], ["of-t"])

    def test_a_worker_carried_between_waves_is_one_attempt_even_with_its_launch_identity(self):
        # Control: the launch of d1 read from its store row in wave 1 and its worker_done in
        # wave 2 are one attempt — the same launch identity — so wave 2 counts no retry.
        evs = inflight_stream()
        evs[2] = ev("dispatch.launched", "10:01:00", task="t", dispatch="d1", producer="local_state",
                    basis="occurred", ref="local-state:dispatches/d1",
                    event_id="local-state:dispatch:d1@10:01", **ONE)
        report = self.derive(evs)
        self.assertEqual([self.metric(report, 2, m)["value"] for m in ("retries", "rework")], ["0", "0/1"])

    def test_a_unit_re_dispatched_into_a_later_wave_is_rework_there(self):
        report = self.derive(carried_stream())
        self.assertEqual(self.metric(report, 1, "rework")["value"], "0/1")
        self.assertEqual(self.metric(report, 2, "rework")["value"], "1/1")

    def test_a_retry_into_a_later_wave_is_counted_there(self):
        # PR #638 review (P1): retries were each wave's dispatches minus one, so d1 in wave 1
        # and its replacement d2 in wave 2 read as 0 and 0, hiding the retry that carried the
        # unit into wave 2. Counted against the task's earlier dispatches, wave 2 has one; a
        # second replacement inside wave 2 is a second.
        report = self.derive(carried_stream())
        self.assertEqual([self.metric(report, k, "retries")["value"] for k in (1, 2)], ["0", "1"])
        evs = carried_stream()
        evs.insert(8, ev("dispatch.launched", "10:35:00", task="t", dispatch="d3", **ONE))
        report = self.derive(evs)
        self.assertEqual([self.metric(report, k, "retries")["value"] for k in (1, 2)], ["0", "2"])


class TestFreshnessCountsReviews(Base):
    def test_two_approvals_of_one_head_voided_count_twice(self):
        # PR #638 review (P2): freshness counted distinct reviewed SHAs, so two reviews of the
        # same head, both voided when it moved, counted once. A duplicate delivery or a
        # re-observation of ONE review (same reviewer, same head) still counts once.
        a, b = sha("aa"), sha("bb")

        def approve(at, reviewer, head, **kw):
            return ev("review.verdict", at, task="t", dispatch=reviewer,
                      data={"verdict": "approve", "reviewed_sha": head}, **ONE, **kw)
        first_r1 = approve("10:11:00", "r1", a)
        evs = unit_stream()[:4] + [
            first_r1, approve("10:12:00", "r2", a), first_r1,
            approve("10:13:00", "r1", a, event_id="r1-seen-again"),
            ev("task.done", "10:20:00", task="t", dispatch="d", data={"head_sha": b}, **ONE),
            approve("10:22:00", "r3", b),
            ev("verify.verdict", "10:25:00", task="t", data={"exit": 0, "head_sha": b}, **ONE),
            ev("unit.closed", "10:30:00", task="t", data={"head_sha": b}, **ONE),
            ev("wave.close", "10:40:00", data={"wave": 1}, **ONE),
        ]
        report = self.derive(evs)
        self.assertEqual(self.metric(report, 1, "freshness")["value"], "2")
        self.assertEqual(report["waves"][0]["units"][0]["voided_reviews"], [a, a])


class TestUsage(Base):
    def test_unknown_cost_stays_null_with_provenance_never_zero(self):
        report = self.derive(scenario_clean())
        cost = report["usage"]["models"]["claude-fixture"]["cost_usd"]
        self.assertIsNone(cost["value"])
        self.assertEqual(cost["known_sum"], "1.00")
        self.assertIn("1 of 5", cost["unavailable"])
        self.assertIn("fixture stream d2 result line 31; not reported: cost_usd",
                      report["usage"]["models"]["claude-fixture"]["provenance"])
        self.assertIsNone(report["usage"]["run_total"]["cost_usd"]["value"])
        cache = report["usage"]["run_total"]["cache_read_input_tokens"]
        self.assertIsNone(cache["value"], "a field nobody reported is null, not 0")

    def test_a_dispatch_with_no_usage_observation_leaves_the_run_total_unknown(self):
        evs = [e for e in scenario_clean() if not (e["kind"] == "model.usage" and e["dispatch"] == "d5")]
        report = self.derive(evs)
        self.assertEqual(report["usage"]["unobserved_dispatches"], ["d5"])
        self.assertIsNone(report["usage"]["run_total"]["input_tokens"]["value"])

    def _stream(self, lines):
        path = self.tmp / "worker.jsonl"
        path.write_text("".join(json.dumps(x) + "\n" for x in lines), encoding="utf-8")
        return path

    def test_ingest_usage_records_what_the_result_line_carries_and_nulls_the_rest(self):
        stream = self._stream([{"type": "system", "subtype": "init", "model": "claude-fixture"},
                               {"type": "assistant", "message": {}},
                               {"type": "result", "usage": {"input_tokens": 12, "output_tokens": 3}}])
        proc = self.cli("ingest-usage", "--stream", str(stream), "--run", "r", "--epoch", "1",
                        "--clock", "host-a", "--dispatch", "d", "--observed-at", "2026-10-20T10:00:00Z")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        recorded, _sha, _head = events.read_log(self.log)
        data = recorded[0]["data"]
        self.assertEqual((data["model"], data["input_tokens"], data["output_tokens"]),
                         ("claude-fixture", 12, 3))
        self.assertIsNone(data["cost_usd"])
        self.assertIn("not reported: cache_read_input_tokens, cache_creation_input_tokens, cost_usd",
                      data["provenance"])
        again = self.cli("ingest-usage", "--stream", str(stream), "--run", "r", "--epoch", "1",
                         "--clock", "host-a", "--dispatch", "d", "--observed-at", "2026-10-20T10:00:00Z")
        self.assertIn("duplicate", again.stdout)

    def test_excluded_dispatch_evidence_leaves_usage_coverage_unknown(self):
        # PR #638 review (P1): coverage was checked against ADMITTED dispatch evidence only, so
        # a worker whose launch was fenced out, or carried by a conflicting re-delivery, fell
        # out of it, and the other workers' tokens read as the run's total.
        def usage(dispatch, tokens, **kw):
            return ev("model.usage", "10:41:00", task="t", dispatch=dispatch,
                      data={"model": "m", "input_tokens": tokens, "provenance": "p"}, **{**ONE, **kw})
        resumed = {"run": "r", "epoch": 2, "clock": "host-a"}
        fenced = unit_stream() + [
            usage("d", 5), ev("coordinator.resume", "10:42:00", data={"coordinator": "c2"}, **resumed),
            ev("dispatch.launched", "10:43:00", task="t", dispatch="d9", **ONE)]  # a stale writer
        conflicting = unit_stream() + [usage("d", 5)]
        conflicting.append(ev("dispatch.launched", "10:01:00", task="t", dispatch="d9",
                              event_id=conflicting[2]["event_id"], **ONE))
        for name, evs in (("fenced", fenced), ("conflicting", conflicting)):
            with self.subTest(name):
                total = self.derive(evs)["usage"]["run_total"]["input_tokens"]
                self.assertIsNone(total["value"], total)
                self.assertTrue(any("['d9']" in r and "coverage" in r for r in total["unavailable"]),
                                total)
        # Control: once the excluded worker's own usage is observed, its coverage is known.
        report = self.derive(fenced + [usage("d9", 7, epoch=2)])
        self.assertEqual(report["usage"]["run_total"]["input_tokens"], {"value": 12})

    def test_a_reviewer_dispatch_without_usage_leaves_the_run_total_unknown(self):
        # PR #638 review (P1, coverage): coverage counted only dispatches a launch, worker_done
        # or death names, so a reviewer named only on its review events fell outside it and the
        # builders' tokens read as the whole run's. Every dispatch the record admits counts.
        def usage(dispatch, tokens):
            return ev("model.usage", "10:41:00", task="t", dispatch=dispatch,
                      data={"model": "m", "input_tokens": tokens, "provenance": "p"}, **ONE)
        evs = unit_stream() + [
            ev("review.started", "10:12:00", task="t", dispatch="r1", data={"head_sha": sha("aa")}, **ONE),
            ev("review.verdict", "10:16:00", task="t", dispatch="r2",
               data={"verdict": "approve", "reviewed_sha": sha("aa")}, **ONE),
            usage("d", 5)]
        report = self.derive(evs)
        total = report["usage"]["run_total"]["input_tokens"]
        self.assertIsNone(total["value"], total)
        self.assertIn("dispatch(es) ['r1', 'r2'] have no usage observation", total["unavailable"])
        self.assertEqual(report["usage"]["unobserved_dispatches"], ["r1", "r2"])
        # Control: with the reviewers' own usage observed, the total is the whole run's.
        report = self.derive(evs + [usage("r1", 3), usage("r2", 4)])
        self.assertEqual(report["usage"]["run_total"]["input_tokens"], {"value": 12})

    def test_a_dispatch_id_launched_for_two_tasks_needs_usage_for_each(self):
        # Sweep (coverage): a dispatch id an external provider recorded again for another task
        # is two launches under one id. Usage was covered per dispatch id, so one task's usage
        # observation made the run total read complete without the other task's spend.
        def launch(task, at):
            return ev("dispatch.launched", at, task=task, dispatch="agent-7", producer="local_state",
                      basis="occurred", ref="local-state:dispatches/agent-7",
                      event_id=f"local-state:dispatch:agent-7@{at}", **ONE)

        def usage(task, tokens):
            return ev("model.usage", "11:00:00", task=task, dispatch="agent-7",
                      data={"model": "m", "input_tokens": tokens, "provenance": f"p {task}"}, **ONE)
        base = [ev("run.start", "10:00:00", data={"coordinator": "c1"}, **ONE),
                launch("t1", "10:01:00"), launch("t2", "10:30:00")]
        total = self.derive(base + [usage("t1", 5)])["usage"]["run_total"]["input_tokens"]
        self.assertIsNone(total["value"], total)
        self.assertTrue(any("agent-7" in r and "t2" in r for r in total["unavailable"]), total)
        # Control: with each task's usage observed, the total is known.
        report = self.derive(base + [usage("t1", 5), usage("t2", 7)])
        self.assertEqual(report["usage"]["run_total"]["input_tokens"], {"value": 12})

    def test_a_wave_only_excluded_evidence_opens_is_reported_not_dropped(self):
        # Sweep (coverage that silently shrinks): waves were enumerated from admitted wave.open
        # and wave.close only, so a last wave whose open was fenced vanished from the report
        # and the run read complete. Waves are enumerated from the excluded evidence too.
        self.assertTrue(self.derive(unit_stream())["complete"])
        evs = unit_stream() + [
            ev("wave.open", "10:50:00", data={"wave": 2, "builders": 1, "reviewers": 1,
                                              "tasks": ["t2"]}, run="r", epoch=3, clock="host-a")]
        report = self.derive(evs)
        self.assertEqual([w["wave"] for w in report["waves"]], [1, 2])
        self.assertFalse(report["complete"])
        reasons = self.metric(report, 2, "throughput")["unavailable"]
        self.assertTrue(any("epoch 3" in r for r in reasons), reasons)

    def test_ingest_usage_without_a_result_line_records_nothing(self):
        stream = self._stream([{"type": "system", "subtype": "init", "model": "m"}])
        proc = self.cli("ingest-usage", "--stream", str(stream), "--run", "r", "--epoch", "1",
                        "--clock", "host-a")
        self.assertEqual(proc.returncode, 1)
        self.assertFalse(self.log.exists())


class TestRecordIntegrity(Base):
    BIND = ("--run", "r", "--epoch", "1", "--clock", "host-a")

    def emit(self, *extra, kind="run.start", data='{"coordinator": "c1"}'):
        return self.cli("emit", "--kind", kind, *self.BIND, "--source-ref", "ledger:header",
                        "--observed-at", "2026-10-20T10:00:00Z", "--data", data, *extra)

    def test_emit_appends_a_chained_0600_line_and_is_idempotent(self):
        first = self.emit("--event-id", "start-1")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(stat.S_IMODE(self.log.stat().st_mode), 0o600)
        again = self.emit("--event-id", "start-1")
        self.assertEqual(again.stdout.strip(), "duplicate start-1")
        self.assertEqual(len(self.log.read_text(encoding="utf-8").splitlines()), 1)
        self.assertEqual(self.cli("verify").returncode, 0)

    def test_emit_without_an_id_is_still_idempotent(self):
        self.assertEqual(self.emit().returncode, 0)
        self.assertTrue(self.emit().stdout.startswith("duplicate content:"))

    def test_appending_to_a_record_without_a_final_newline_keeps_it_readable(self):
        # PR #638 review (P2): the reader accepts a last line with no newline; the next append
        # must not glue a second object onto it.
        self.log.parent.mkdir(parents=True)
        self.log.write_text(chain(unit_stream()[:1]).rstrip("\n"), encoding="utf-8")
        self.assertEqual(self.cli("verify").returncode, 0)
        proc = self.emit("--event-id", "start-2", data='{"coordinator": "c2"}', kind="coordinator.resume")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        verify = self.cli("verify")
        self.assertEqual(verify.returncode, 0, verify.stderr)
        self.assertEqual(len(events.read_log(self.log)[0]), 2)

    def test_emit_records_a_conflict_and_says_so(self):
        self.emit("--event-id", "start-1")
        proc = self.emit("--event-id", "start-1", data='{"coordinator": "c9"}')
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(len(self.log.read_text(encoding="utf-8").splitlines()), 2)

    def test_emit_refuses_a_schema_violation(self):
        for extra, data in ((("--kind",), None), ((), '{"coordinator": "c1", "note": "x"}'),
                            ((), '{"coordinator": "not an id"}')):
            with self.subTest(data=data):
                proc = self.emit(data=data) if data else self.cli("emit", *self.BIND, "--source-ref", "x")
                self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertFalse(self.log.exists())

    def test_an_unhashable_value_is_refused_not_a_traceback(self):
        # PR #638 review (P2): set() over `"tasks": [{}]` raised TypeError before any id was
        # checked — a traceback (exit 1) on emit, and an escape from the reader's fail-closed path.
        plan = '{"wave": 1, "builders": 1, "reviewers": 1, "tasks": [{}]}'
        proc = self.emit(kind="wave.open", data=plan)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertFalse(self.log.exists())
        for field, value in (("data", {"wave": 1, "builders": 1, "reviewers": 1, "tasks": [{}]}),
                             ("kind", ["wave.open"])):
            with self.subTest(field=field):
                evs = unit_stream()[:2]
                evs[1][field] = value
                self.write(evs)
                proc = self.cli("report")
                self.assertEqual(proc.returncode, 3, proc.stderr)
                self.assertNotIn("Traceback", proc.stderr)

    def test_emit_refuses_a_credential_shape_and_writes_nothing(self):
        token = "gh" + "p_" + "A" * 36
        for extra in (("--source-ref", f"https://ci.example/{token}"),
                      ("--source-ref", "https://user:" + "hunter2hunter2" + "@example.com/x")):
            with self.subTest(extra=extra[1][:20]):
                proc = self.cli("emit", "--kind", "run.start", *self.BIND, *extra,
                                "--data", '{"coordinator": "c1"}')
                self.assertEqual(proc.returncode, 2)
                self.assertNotIn(token, proc.stderr)
        self.assertFalse(self.log.exists())

    def test_report_redacts_a_credential_already_in_the_record(self):
        token = "gh" + "p_" + "B" * 36
        evs = unit_stream()
        evs[5]["source"]["ref"] = f"https://ci.example/run?{token}"
        self.write(evs)
        proc = self.cli("report", "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(token, proc.stdout)
        self.assertIn("[REDACTED:github-token]", proc.stdout)

    def test_report_redacts_a_credential_in_a_key(self):
        token = "gh" + "p_" + "C" * 36
        evs = unit_stream() + [ev("model.usage", "10:41:00", dispatch="d", **ONE,
                                  data={"model": "m", "provenance": "p"})]
        evs[-1]["data"]["model"] = token  # written by hand, past emit's refusal
        self.write(evs)
        proc = self.cli("report", "--json")
        self.assertNotIn(token, proc.stdout)
        self.assertIn('"[REDACTED:github-token]": {', proc.stdout)

    def test_concurrent_emitters_keep_one_intact_chain(self):
        procs = [subprocess.Popen([sys.executable, str(EVENTS), "--log", str(self.log), "emit",
                                   "--kind", "unit.suspect", *self.BIND, "--task", f"t{i}",
                                   "--source-ref", "ledger", "--observed-at",
                                   "2026-10-20T10:00:00Z"], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE) for i in range(12)]
        self.assertEqual([p.wait() for p in procs], [0] * 12)
        for p in procs:
            p.stdout.close()
            p.stderr.close()
        recorded, _sha, _head = events.read_log(self.log)
        self.assertEqual(sorted(e["task"] for e in recorded), sorted(f"t{i}" for i in range(12)))

    def test_an_edited_event_fails_closed(self):
        self.write(scenario_clean())
        lines = self.log.read_text(encoding="utf-8").splitlines()
        lines[20] = lines[20].replace('"exit":0', '"exit":2')
        self.log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        for cmd in (("report",), ("verify",)):
            with self.subTest(cmd=cmd):
                proc = self.cli(*cmd)
                self.assertEqual(proc.returncode, 3)
                self.assertIn(":22: prev does not match", proc.stderr)

    def test_a_dropped_event_fails_closed(self):
        self.write(scenario_clean())
        lines = self.log.read_text(encoding="utf-8").splitlines()
        del lines[16]
        self.log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertEqual(self.cli("report").returncode, 3)

    def test_a_rewritten_record_is_caught_only_by_an_anchor(self):
        self.write(scenario_clean())
        head = self.cli("verify").stdout.split("head ")[1].split()[0]
        evs = scenario_clean()
        evs[20]["data"]["exit"] = 2  # rewritten from scratch: the chain is internally intact
        self.write(evs)
        self.assertEqual(self.cli("verify").returncode, 0)
        self.assertEqual(self.cli("report", "--expect-head", head).returncode, 3)
        self.assertEqual(self.cli("verify", "--expect-ancestor", head).returncode, 3)

    def test_a_schema_invalid_line_fails_closed(self):
        evs = scenario_clean()[:3]
        evs[2]["kind"] = "task.teleported"
        self.write(evs)
        proc = self.cli("report")
        self.assertEqual(proc.returncode, 3)
        self.assertIn("task.teleported", proc.stderr)

    def test_several_runs_need_run(self):
        self.write(scenario_crash())
        self.assertEqual(self.cli("report").returncode, 2)
        self.assertEqual(self.cli("report", "--run", "run-b").returncode, 1)


class TestCheckAgainstARunReport(Base):
    def report_file(self, rows):
        path = self.tmp / "run.md"
        path.write_text("RUN: mission=ship-it waves=2\n\n## WIP-curve protocol row\n\n"
                        "| Wave | WIP setting | Builder throughput | Verification latency | "
                        "Rework rate | Freshness violations |\n|---|---|---|---|---|---|\n"
                        + "".join(r + "\n" for r in rows), encoding="utf-8")
        return path

    def test_the_derived_rows_check_clean(self):
        self.write(scenario_clean())
        proc = self.cli("check", "--run-report", str(self.report_file(CLEAN_ROWS)))
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_a_deliberately_altered_metric_row_is_detected(self):
        self.write(scenario_clean())
        altered = [CLEAN_ROWS[0].replace("throughput=1.14/h", "throughput=1.71/h"), CLEAN_ROWS[1]]
        proc = self.cli("check", "--run-report", str(self.report_file(altered)))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("wave 1 throughput: the report says '1.71/h', the record derives '1.14/h'",
                      proc.stderr)

    def test_a_dropped_or_invented_wave_is_detected(self):
        self.write(scenario_clean())
        invented = CLEAN_ROWS[1].replace("wave=2", "wave=3")
        proc = self.cli("check", "--run-report", str(self.report_file([CLEAN_ROWS[0], invented])))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("wave 2: the record derives a row the report does not carry", proc.stderr)
        self.assertIn("wave 3: the report carries a row for a wave the record never", proc.stderr)

    def test_empty_evidence_does_not_check_clean(self):
        # PR #638 review (P1): no wave in the record and no row in the report compared nothing,
        # and nothing compared exited 0.
        self.write(unit_stream()[:1])
        proc = self.cli("check", "--run-report", str(self.report_file([])))
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("the record derives no WIP-curve row", proc.stderr)

    def test_a_measured_value_the_record_cannot_support_is_detected(self):
        self.write(scenario_crash())
        claimed = [CRASH_ROWS[0].replace("throughput=unavailable", "throughput=2.00/h")]
        proc = self.cli("check", "--run", "run-b", "--run-report", str(self.report_file(claimed)))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("wave 1 throughput: the record cannot derive it, yet the report claims '2.00/h'",
                      proc.stderr)


class TestIngest(Base):
    def store(self):
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        LocalStateStore = importlib.import_module("runtime.providers.local_state").LocalStateStore
        db = self.tmp / "runtime.db"
        store = LocalStateStore(db, env={})
        ten = calendar.timegm((2026, 10, 20, 10, 0, 0))  # 2026-10-20T10:00:00Z as the DB stores it
        with store._connect() as conn:
            for disp, task, handle, state, created in (("disp_1", "task_1", "term_1", "completed", ten),
                                                       ("disp_2", "task_2", "term_2", "died", ten + 60.5)):
                conn.execute("INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, "
                             "terminal_handle, state, created_at, updated_at) VALUES "
                             "(?, ?, 'run_x', '/w', 'claude', ?, ?, ?, ?)",
                             (disp, task, handle, state, created, created + 600))
        store.send_message(subject="done", msg_type="worker_done", sender="term_1", run="run_x",
                           attrs={"headSha": sha("c4")})
        store.send_message(subject="done", msg_type="worker_done", sender="term_ghost", run="run_x")
        store.send_message(subject="other", msg_type="worker_done", sender="term_1", run="run_y")
        return db

    def ingest(self, db):
        return self.cli("ingest-state", "--db", str(db), "--run", "run_x", "--epoch", "1",
                        "--clock", "host-a")

    def test_ingest_state_reads_launches_done_and_deaths_read_only(self):
        db = self.store()
        before = {p.name: p.read_bytes() for p in self.tmp.iterdir() if p.name.startswith("runtime.db")}
        proc = self.ingest(db)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("1 worker_done message(s) name no single dispatch", proc.stderr)
        after = {p.name: p.read_bytes() for p in self.tmp.iterdir() if p.name.startswith("runtime.db")}
        self.assertEqual(before, after, "ingest must not write beside or into the DB")
        recorded, _sha, _head = events.read_log(self.log)
        kinds = sorted((e["kind"], e["dispatch"]) for e in recorded)
        self.assertEqual(kinds, [("dispatch.died", "disp_2"), ("dispatch.launched", "disp_1"),
                                 ("dispatch.launched", "disp_2"), ("task.done", "disp_1")])
        done = next(e for e in recorded if e["kind"] == "task.done")
        self.assertEqual((done["task"], done["data"]["head_sha"], done["basis"]),
                         ("task_1", sha("c4"), "occurred"))
        launch = next(e for e in recorded if e["dispatch"] == "disp_2" and e["kind"] == "dispatch.launched")
        self.assertEqual(launch["observed_at"], "2026-10-20T10:01:00.500000+00:00")
        died = next(e for e in recorded if e["kind"] == "dispatch.died")
        self.assertEqual(died["observed_at"], "2026-10-20T10:11:00.500000+00:00")

    def test_re_ingesting_the_same_db_records_nothing_new(self):
        db = self.store()
        self.ingest(db)
        size = self.log.stat().st_size
        proc = self.ingest(db)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.count("duplicate"), 4)
        self.assertEqual(self.log.stat().st_size, size)

    def test_re_ingesting_the_db_after_a_resume_is_a_duplicate_not_a_conflict(self):
        # PR #638 review (P1): the ingesting coordinator's epoch is who RECORDED a row, not what
        # the row says; a resumed coordinator re-reading the same DB must not contest it.
        db = self.store()
        bind = ("--run", "run_x", "--clock", "host-a", "--source-ref", "ledger",
                "--observed-at", "2026-10-20T09:59:00Z")
        self.cli("emit", "--kind", "run.start", "--epoch", "1", *bind,
                 "--data", '{"coordinator": "c1"}')
        self.ingest(db)
        self.cli("emit", "--kind", "coordinator.resume", "--epoch", "2", *bind,
                 "--data", '{"coordinator": "c2"}')
        proc = self.cli("ingest-state", "--db", str(db), "--run", "run_x", "--epoch", "2",
                        "--clock", "host-a")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.count("duplicate"), 4, proc.stdout)
        recorded, file_sha, head = events.read_log(self.log)
        self.assertEqual(events.derive(recorded, "run_x", file_sha, head)["record"]["conflicts"], 0)

    def test_re_ingesting_usage_later_is_a_duplicate_not_a_conflict(self):
        # PR #638 review (P1): without --observed-at the time is the ingest's own clock; a second
        # ingest of the same unchanged stream must not turn the observation into a conflict.
        path = self.tmp / "worker.jsonl"
        path.write_text(json.dumps({"type": "result", "usage": {"input_tokens": 5}}) + "\n",
                        encoding="utf-8")
        argv = ["--log", str(self.log), "ingest-usage", "--stream", str(path), "--run", "r",
                "--epoch", "1", "--clock", "host-a", "--dispatch", "d"]
        codes, out = [], io.StringIO()
        for now in ("2026-10-20T10:00:00+00:00", "2026-10-20T11:00:00+00:00"):
            with mock.patch.object(events, "_now", return_value=now), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                codes.append(events.main(argv))
        self.assertEqual(codes, [0, 0], out.getvalue())
        self.assertIn("duplicate", out.getvalue())
        self.assertEqual(len(events.read_log(self.log)[0]), 1)

    def test_a_stream_that_grows_is_not_counted_twice(self):
        # PR #638 review (P1): each observation's id was derived from the WHOLE file's digest,
        # so any line the worker or monitor appended gave every earlier result line a new id and
        # usage_summary added its tokens again. Bound to the bytes through its own result line,
        # an observation survives appends — including the newline its writer had not flushed yet.
        path = self.tmp / "worker.jsonl"
        init = json.dumps({"type": "system", "subtype": "init", "model": "m"}) + "\n"
        result = json.dumps({"type": "result", "total_cost_usd": 0.5,
                             "usage": {"input_tokens": 5, "output_tokens": 1}})
        path.write_text(init + result, encoding="utf-8")  # its newline is not flushed yet
        argv = ("ingest-usage", "--stream", str(path), "--run", "r", "--epoch", "1",
                "--clock", "host-a", "--dispatch", "d", "--observed-at", "2026-10-20T10:00:00Z")
        events.append_events(self.log, [ev("run.start", "09:00:00", data={"coordinator": "c1"}, **ONE)])
        procs = [self.cli(*argv)]
        with path.open("a", encoding="utf-8") as fh:  # an unrelated line arrives
            fh.write("\n" + json.dumps({"type": "system", "subtype": "status"}) + "\n")
        procs.append(self.cli(*argv))
        with path.open("a", encoding="utf-8") as fh:  # and then a second result
            fh.write(json.dumps({"type": "result", "total_cost_usd": 0.25,
                                 "usage": {"input_tokens": 7, "output_tokens": 2}}) + "\n")
        procs.append(self.cli(*argv))
        self.assertEqual([p.returncode for p in procs], [0, 0, 0], [p.stdout for p in procs])
        self.assertEqual([line.split()[0] for p in procs for line in p.stdout.splitlines()],
                         ["appended", "duplicate", "duplicate", "appended"])
        recorded, file_sha, head = events.read_log(self.log)
        report = events.derive(recorded, "r", file_sha, head)
        self.assertEqual(report["record"]["conflicts"], 0)
        model = report["usage"]["models"]["m"]
        self.assertEqual((model["observations"], model["input_tokens"]["value"],
                          model["output_tokens"]["value"], model["cost_usd"]["value"]),
                         (2, 12, 3, "0.75"))
        usage = [e for e in recorded if e["kind"] == "model.usage"]
        self.assertEqual(usage[0]["source"]["sha256"], events.sha256_hex(init + result),
                         "the source digest is the stream through the result line, not the file")

    def test_a_copy_recorded_again_after_a_resume_does_not_contest_the_unit(self):
        evs = unit_stream()
        evs.insert(4, ev("coordinator.resume", "10:12:00", data={"coordinator": "c2"},
                         run="r", epoch=2, clock="host-a"))
        for event in evs[5:]:
            event["epoch"] = 2
        evs.append(dict(evs[3], epoch=2))  # the epoch-1 worker_done, re-recorded by epoch 2
        report = self.derive(evs)
        self.assertEqual((report["record"]["conflicts"], report["record"]["duplicates"]), (0, 1))
        self.assertEqual(self.metric(report, 1, "latency_max")["value"], "10.00m")

    def running_store(self, attrs=None):
        """One dispatch still running — the store writes its head only when the worker exits
        (local_state.py:ensure_terminal_or_died) — and the worker_done it already sent."""
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        LocalStateStore = importlib.import_module("runtime.providers.local_state").LocalStateStore
        db = self.tmp / "runtime.db"
        store = LocalStateStore(db, env={})
        ten = calendar.timegm((2026, 10, 20, 10, 0, 0))
        with store._connect() as conn:
            conn.execute("INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, "
                         "terminal_handle, state, created_at, updated_at) VALUES "
                         "('disp_1', 'task_1', 'run_x', '/w', 'claude', 'term_1', 'running', ?, ?)",
                         (ten, ten))
        store.send_message(subject="done", msg_type="worker_done", sender="term_1", run="run_x",
                           attrs=attrs)
        with store._connect() as conn:  # sent at 10:10, so the wave's times are hand-checkable
            conn.execute("UPDATE messages SET created_at = ?", (ten + 600,))
        return store, db

    def exit_worker(self, store, head):
        store.ensure_terminal_or_died(dispatch_id="disp_1", worker_handle="term_1", exit_code=0,
                                      worktree_head_sha=head, run_id="run_x")

    def test_an_import_before_exit_and_one_after_keep_the_wave_measured(self):
        # PR #638 review (P1): a worker_done naming no head fell back to dispatches.head_sha,
        # null until the worker exits. An import before exit recorded a null head, the import
        # after it the real one under the same message id: a conflict that left the unit's wave
        # unmeasurable for good. The message is deferred until its dispatch has exited instead.
        # Hand calculation: wave 10:00-10:40 (2400 s), one close -> 1.50/h; done 10:10 -> pass
        # 10:20 = 10 m.
        store, db = self.running_store()
        c = {"run": "run_x", "epoch": 1, "clock": "host-a"}
        events.append_events(self.log, [
            ev("run.start", "09:59:00", data={"coordinator": "c1"}, **c),
            ev("wave.open", "10:00:00", data={"wave": 1, "builders": 1, "reviewers": 1,
                                              "tasks": ["task_1"]}, **c)])
        before = self.ingest(db)
        self.exit_worker(store, sha("c4"))
        after = self.ingest(db)
        self.assertEqual((before.returncode, after.returncode), (0, 0), after.stdout + after.stderr)
        head = sha("c4")
        events.append_events(self.log, [
            ev("review.verdict", "10:15:00", task="task_1",
               data={"verdict": "approve", "reviewed_sha": head}, **c),
            ev("verify.verdict", "10:20:00", task="task_1", data={"exit": 0, "head_sha": head}, **c),
            ev("unit.closed", "10:30:00", task="task_1", data={"head_sha": head}, **c),
            ev("wave.close", "10:40:00", data={"wave": 1}, **c)])
        again = self.ingest(db)
        self.assertEqual(again.stdout.split()[::2], ["duplicate", "duplicate"], again.stdout)
        recorded, file_sha, digest = events.read_log(self.log)
        report = events.derive(recorded, "run_x", file_sha, digest)
        self.assertEqual(report["record"]["conflicts"], 0)
        self.assertEqual(report["waves"][0]["row"],
                         "| `wave=1` | `builders=1 reviewers=1` | `throughput=1.50/h` | "
                         "`latency_median=10.00m latency_max=10.00m` | `rework=0/1` | "
                         "`freshness=0` |")
        self.assertIn("deferred until its dispatch exits", before.stderr)
        self.assertNotIn("local-state:message:", before.stdout, "nothing recorded before exit")

    TEN = calendar.timegm((2026, 10, 20, 10, 0, 0))  # 2026-10-20T10:00:00Z as the DB stores it

    def gated_store(self, *dispatches):
        """#597's launch gate: worker-start dispatch rows that carry a launch intent, registered
        `ready` before any spawn, each (dispatch, terminal, minute after 10:00) of task_1."""
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        LocalStateStore = importlib.import_module("runtime.providers.local_state").LocalStateStore
        db = self.tmp / "runtime.db"
        store = LocalStateStore(db, env={})
        with store._connect() as conn:
            for disp, handle, minute in dispatches:
                at = self.TEN + 60 * minute
                conn.execute("INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, "
                             "terminal_handle, state, created_at, updated_at, intent_id) VALUES "
                             "(?, 'task_1', 'run_x', '/w', 'claude', ?, 'ready', ?, ?, ?)",
                             (disp, handle, at, at, f"intent_{disp}"))
        return store, db

    def worker_runs(self, store, disp, handle, head=None, minute=10):
        """A monitor claims the gate; with a head the worker reports done and exits, without one
        it dies before reporting."""
        self.assertTrue(store.claim_monitor(disp, 4242))
        if head:
            store.send_message(subject="done", msg_type="worker_done", sender=handle, run="run_x",
                               attrs={"headSha": head})
            with store._connect() as conn:
                conn.execute("UPDATE messages SET created_at = ? WHERE sender = ?",
                             (self.TEN + 60 * minute, handle))
        store.ensure_terminal_or_died(dispatch_id=disp, worker_handle=handle, exit_code=0 if head else 1,
                                      worktree_head_sha=head or "", run_id="run_x")

    def launches(self):
        return sorted(e["dispatch"] for e in events.read_log(self.log)[0]
                      if e["kind"] == "dispatch.launched")

    def test_a_dispatch_the_gate_proves_never_ran_is_not_a_launch(self):
        # PR #638 review (P1): ingest-state recorded every dispatch row as launched, including
        # one recovery abandoned at the launch gate before any monitor claimed it (#597). Beside
        # the replacement that did run, the unit read one retry and rework 1/1, and run usage
        # stayed unavailable for a dispatch that can never spend anything.
        # Hand calculation: wave 10:00-10:40 (2400 s), one close -> 1.50/h; done@C4 10:10 ->
        # pass 10:20 = 10 m.
        c4 = sha("c4")
        store, db = self.gated_store(("disp_a", "term_a", 1), ("disp_b", "term_b", 2))
        self.assertTrue(store.abandon_unlaunched("disp_a"))  # recovery won the gate: nothing ran
        self.worker_runs(store, "disp_b", "term_b", c4)
        c = {"run": "run_x", "epoch": 1, "clock": "host-a"}
        events.append_events(self.log, [
            ev("run.start", "09:59:00", data={"coordinator": "c1"}, **c),
            ev("wave.open", "10:00:00", data={"wave": 1, "builders": 1, "reviewers": 1,
                                              "tasks": ["task_1"]}, **c)])
        proc = self.ingest(db)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        events.append_events(self.log, [
            ev("model.usage", "10:11:00", task="task_1", dispatch="disp_b",
               data={"model": "m", "input_tokens": 9, "provenance": "p"}, **c),
            ev("review.verdict", "10:15:00", task="task_1",
               data={"verdict": "approve", "reviewed_sha": c4}, **c),
            ev("verify.verdict", "10:20:00", task="task_1", data={"exit": 0, "head_sha": c4}, **c),
            ev("unit.closed", "10:30:00", task="task_1", data={"head_sha": c4}, **c),
            ev("wave.close", "10:40:00", data={"wave": 1}, **c)])
        recorded, file_sha, digest = events.read_log(self.log)
        report = events.derive(recorded, "run_x", file_sha, digest)
        self.assertEqual([self.metric(report, 1, m)["value"] for m in ("retries", "rework")], ["0", "0/1"])
        self.assertEqual(report["usage"]["run_total"]["input_tokens"], {"value": 9})
        self.assertEqual(report["waves"][0]["row"],
                         "| `wave=1` | `builders=1 reviewers=1` | `throughput=1.50/h` | "
                         "`latency_median=10.00m latency_max=10.00m` | `rework=0/1` | `freshness=0` |")
        self.assertEqual(self.launches(), ["disp_b"])
        self.assertIn("never launched", proc.stderr)

    def test_a_replacement_after_a_worker_that_ran_is_still_a_retry(self):
        # Control: both dispatches passed the gate, the first died — a genuine retry.
        store, db = self.gated_store(("disp_a", "term_a", 1), ("disp_b", "term_b", 2))
        self.worker_runs(store, "disp_a", "term_a")
        self.worker_runs(store, "disp_b", "term_b", sha("c4"))
        events.append_events(self.log, [
            ev("run.start", "09:59:00", data={"coordinator": "c1"}, run="run_x", epoch=1, clock="host-a"),
            ev("wave.open", "10:00:00", data={"wave": 1, "builders": 1, "reviewers": 1,
                                              "tasks": ["task_1"]}, run="run_x", epoch=1, clock="host-a")])
        self.assertEqual(self.ingest(db).returncode, 0)
        self.assertEqual(self.launches(), ["disp_a", "disp_b"])
        recorded, file_sha, digest = events.read_log(self.log)
        units = events.derive(recorded, "run_x", file_sha, digest)["waves"][0]["units"]
        self.assertEqual((units[0]["dispatches"], units[0]["bounced"]), (["disp_a", "disp_b"], True))

    def test_an_unresolved_launch_is_deferred_and_recorded_once_it_resolves(self):
        # Control: a registered dispatch no monitor has claimed and no fence has closed may
        # still run. It is deferred, not counted, and each later import records it exactly
        # once if a monitor claims it, or never if the gate closes on it.
        store, db = self.gated_store(("disp_c", "term_c", 1), ("disp_d", "term_d", 2))
        # The rows and the mail are two reads: a worker can claim and report between them, so
        # mail can name a row this import saw unclaimed. It waits with its dispatch.
        store.send_message(subject="done", msg_type="worker_done", sender="term_c", run="run_x",
                           attrs={"headSha": sha("c4")})
        first = self.ingest(db)
        self.assertEqual(self.launches() if self.log.exists() else [], [])
        self.assertIn("deferred until the store shows whether it ran", first.stderr)
        self.assertIn("disp_c", first.stderr)
        self.assertIn("deferred with it", first.stderr)
        self.assertTrue(store.claim_monitor("disp_c", 4242))
        self.assertTrue(store.abandon_unlaunched("disp_d"))
        second, third = self.ingest(db), self.ingest(db)
        self.assertEqual([p.returncode for p in (second, third)], [0, 0], second.stderr)
        self.assertEqual(self.launches(), ["disp_c"])
        done = [e["dispatch"] for e in events.read_log(self.log)[0] if e["kind"] == "task.done"]
        self.assertEqual(done, ["disp_c"])
        self.assertEqual(third.stdout.split()[::2], ["duplicate", "duplicate"], third.stdout)

    def test_a_death_keeps_its_time_when_the_row_is_touched_after_it(self):
        # PR #638 review (P1): dispatch.died took the row's updated_at as its time. A fast worker
        # can die before worker_start publishes the launch, and publication rewrites updated_at
        # on the dead row; imports before and after it recorded two times under one death id —
        # a conflict that left the unit's wave unavailable. The death's own record is the
        # synthetic worker_died message written in the same transaction.
        store, db = self.gated_store(("disp_a", "term_a", 1))
        self.worker_runs(store, "disp_a", "term_a")  # claims the gate, then dies with no mail
        with store._connect() as conn:
            conn.execute("UPDATE messages SET created_at = ? WHERE msg_type = 'escalation'",
                         (self.TEN + 300,))  # died at 10:05
        before = self.ingest(db)
        with store._connect() as conn:  # posix.py's publication step, after the death
            conn.execute("UPDATE dispatches SET pid = 77, backend = 'tmux', updated_at = ? "
                         "WHERE dispatch_id = 'disp_a'", (self.TEN + 900,))
        after = self.ingest(db)
        self.assertEqual((before.returncode, after.returncode), (0, 0), after.stdout)
        self.assertEqual(after.stdout.split()[::2], ["duplicate", "duplicate"], after.stdout)
        died = [e for e in events.read_log(self.log)[0] if e["kind"] == "dispatch.died"]
        self.assertEqual([d["observed_at"] for d in died], ["2026-10-20T10:05:00.000000+00:00"])

    def test_a_dispatch_id_recorded_again_is_a_new_launch_not_a_conflict(self):
        # Sweep (identity drift): external providers record dispatch rows with INSERT OR
        # REPLACE under upstream ids (paperclip's agent id, multiclaude's agent name), so one id
        # can be recorded again for another task. The launch was keyed by the id alone, so the
        # second import conflicted with the first; and mail the first holder sent was re-read
        # as the second task's. A launch is bound to its row's creation time, and mail older
        # than the row it names belongs to an earlier holder of the id.
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        LocalStateStore = importlib.import_module("runtime.providers.local_state").LocalStateStore
        db = self.tmp / "runtime.db"
        store = LocalStateStore(db, env={})

        def record(task, minute):
            at = self.TEN + 60 * minute
            with store._connect() as conn:
                conn.execute("INSERT OR REPLACE INTO dispatches(dispatch_id, task_id, run_id, "
                             "worktree, agent, terminal_handle, state, created_at, updated_at) VALUES "
                             "('agent-7', ?, 'run_x', '/w', 'claude', 'agent-7', 'ready', ?, ?)",
                             (task, at, at))
        record("task_1", 1)
        store.send_message(subject="done", msg_type="worker_done", sender="agent-7", run="run_x",
                           attrs={"headSha": sha("c4")})
        with store._connect() as conn:
            conn.execute("UPDATE messages SET created_at = ?", (self.TEN + 600,))
        first = self.ingest(db)
        record("task_2", 30)  # the same agent id, now working task_2
        second = self.ingest(db)
        self.assertEqual((first.returncode, second.returncode), (0, 0), second.stdout)
        self.assertNotIn("conflict", second.stdout)
        recorded = events.read_log(self.log)[0]
        self.assertEqual(sorted((e["kind"], e["task"]) for e in recorded),
                         [("dispatch.launched", "task_1"), ("dispatch.launched", "task_2"),
                          ("task.done", "task_1")])
        self.assertIn("earlier holder", second.stderr)

    def test_a_restarted_task_that_reuses_its_worker_name_counts_the_retry(self):
        # PR #638 review (P1), end to end: multiclaude records of-<task_id> again when the task
        # is restarted (INSERT OR REPLACE). Its first worker died; the restart finished.
        # Hand calculation: wave 10:00-10:40, one close -> 1.50/h; done@C4 10:10 -> pass 10:20 =
        # 10 m; two launch attempts -> one retry, rework 1/1.
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        LocalStateStore = importlib.import_module("runtime.providers.local_state").LocalStateStore
        db, c4 = self.tmp / "runtime.db", sha("c4")
        store = LocalStateStore(db, env={})

        def record(minute):
            at = self.TEN + 60 * minute
            with store._connect() as conn:
                conn.execute("INSERT OR REPLACE INTO dispatches(dispatch_id, task_id, run_id, "
                             "worktree, agent, terminal_handle, state, created_at, updated_at) VALUES "
                             "('of-task_1', 'task_1', 'run_x', '/w', 'claude', 'of-task_1', 'ready', ?, ?)",
                             (at, at))
        c = {"run": "run_x", "epoch": 1, "clock": "host-a"}
        events.append_events(self.log, [
            ev("run.start", "09:59:00", data={"coordinator": "c1"}, **c),
            ev("wave.open", "10:00:00", data={"wave": 1, "builders": 1, "reviewers": 1,
                                              "tasks": ["task_1"]}, **c)])
        record(1)
        store.ensure_terminal_or_died(dispatch_id="of-task_1", worker_handle="of-task_1",
                                      exit_code=1, run_id="run_x")  # died, no mail
        with store._connect() as conn:
            conn.execute("UPDATE messages SET created_at = ?", (self.TEN + 180,))
        first = self.ingest(db)
        record(5)  # the restart, under the same worker name
        store.send_message(subject="done", msg_type="worker_done", sender="of-task_1", run="run_x",
                           attrs={"headSha": c4})
        with store._connect() as conn:
            conn.execute("UPDATE messages SET created_at = ? WHERE msg_type = 'worker_done'",
                         (self.TEN + 600,))
        second = self.ingest(db)
        self.assertEqual((first.returncode, second.returncode), (0, 0), second.stdout + second.stderr)
        events.append_events(self.log, [
            ev("review.verdict", "10:15:00", task="task_1",
               data={"verdict": "approve", "reviewed_sha": c4}, **c),
            ev("verify.verdict", "10:20:00", task="task_1", data={"exit": 0, "head_sha": c4}, **c),
            ev("unit.closed", "10:30:00", task="task_1", data={"head_sha": c4}, **c),
            ev("wave.close", "10:40:00", data={"wave": 1}, **c)])
        recorded, file_sha, digest = events.read_log(self.log)
        report = events.derive(recorded, "run_x", file_sha, digest)
        self.assertEqual(report["record"]["conflicts"], 0)
        self.assertEqual(self.metric(report, 1, "retries")["value"], "1")
        self.assertEqual(report["waves"][0]["row"],
                         "| `wave=1` | `builders=1 reviewers=1` | `throughput=1.50/h` | "
                         "`latency_median=10.00m latency_max=10.00m` | `rework=1/1` | `freshness=0` |")

    def test_a_head_the_message_carries_is_recorded_at_once_and_kept(self):
        # Control: a worker_done that names its head is stable evidence in itself — recorded
        # on the first import, and a duplicate after exit even if the store's row head differs.
        store, db = self.running_store(attrs={"headSha": sha("c4")})
        first = self.ingest(db)
        self.assertIn("appended local-state:message:", first.stdout)
        self.exit_worker(store, sha("d5"))
        again = self.ingest(db)
        self.assertEqual((again.returncode, again.stdout.split()[::2]),
                         (0, ["duplicate", "duplicate"]), again.stdout)
        done = [e for e in events.read_log(self.log)[0] if e["kind"] == "task.done"]
        self.assertEqual([d["data"]["head_sha"] for d in done], [sha("c4")])

    def _transcript(self, exit_code=0, signed=False, manifest_bytes=None):
        manifest = self.tmp / "manifest.json"
        manifest.write_bytes(manifest_bytes or json.dumps({"unit": "u", "head_sha": sha("d9")}).encode())
        record = {"unit": "u", "manifest": str(manifest),
                  "manifest_sha256": events.sha256_hex(manifest.read_bytes()), "exit": exit_code,
                  "fatal": [], "notes": [], "timestamp": "2026-10-20T10:40:00+00:00"}
        path = self.tmp / "transcript.json"
        path.write_text(json.dumps({"record": record, "sig_b64": "AAAA"} if signed else record),
                        encoding="utf-8")
        return path, manifest

    def _ingest_transcript(self, path):
        return self.cli("ingest-transcript", "--transcript", str(path), "--task", "t", "--run", "r",
                        "--epoch", "1", "--clock", "host-a")

    def test_ingest_transcript_binds_the_verdict_to_the_judged_head(self):
        for signed in (False, True):
            with self.subTest(signed=signed):
                self.log.unlink(missing_ok=True)
                path, _manifest = self._transcript(signed=signed)
                proc = self._ingest_transcript(path)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                recorded, _sha, _head = events.read_log(self.log)
                event = recorded[0]
                self.assertEqual((event["kind"], event["data"]["exit"], event["data"]["head_sha"]),
                                 ("verify.verdict", 0, sha("d9")))
                self.assertEqual(event["source"]["sha256"], events.sha256_hex(path.read_bytes()))
                self.assertIn("duplicate", self._ingest_transcript(path).stdout)

    def test_a_manifest_changed_since_the_verdict_binds_no_head(self):
        path, manifest = self._transcript()
        manifest.write_text(json.dumps({"unit": "u", "head_sha": sha("ee")}), encoding="utf-8")
        proc = self._ingest_transcript(path)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("not the bytes the verdict judged", proc.stderr)
        recorded, _sha, _head = events.read_log(self.log)
        self.assertIsNone(recorded[0]["data"]["head_sha"])

    def test_a_file_that_is_no_transcript_is_a_usage_error(self):
        path = self.tmp / "nope.json"
        path.write_text('{"exit": true}', encoding="utf-8")
        self.assertEqual(self._ingest_transcript(path).returncode, 2)
        self.assertFalse(self.log.exists())

    def test_a_manifest_changed_or_gone_on_a_later_import_does_not_contest_the_verdict(self):
        # PR #638 review (P1): the verdict's id was the transcript digest alone, so a first
        # import that bound the judged head and a later one that found the manifest changed or
        # gone (no head) were the same id with two bodies — a conflict that left the unit's
        # wave unmeasurable. The head binding is part of the observation's identity now: the
        # unbound re-import is its own observation, and the bound one stands.
        # Hand calculation: wave 10:00-10:50 (3000 s), one close -> 1.20/h; done at D9 10:10 ->
        # the transcript's pass at D9 10:40 = 30 m.
        d9 = sha("d9")
        events.append_events(self.log, [
            ev("run.start", "10:00:00", data={"coordinator": "c1"}, **ONE),
            ev("wave.open", "10:00:00", data={"wave": 1, "builders": 1, "reviewers": 1,
                                              "tasks": ["t"]}, **ONE),
            ev("dispatch.launched", "10:01:00", task="t", dispatch="d", **ONE),
            ev("task.done", "10:10:00", task="t", dispatch="d", data={"head_sha": d9}, **ONE),
            ev("review.verdict", "10:15:00", task="t", data={"verdict": "approve", "reviewed_sha": d9},
               **ONE)])
        path, manifest = self._transcript()
        codes = [self._ingest_transcript(path).returncode]
        manifest.write_text(json.dumps({"unit": "u", "head_sha": sha("ee")}), encoding="utf-8")
        codes.append(self._ingest_transcript(path).returncode)
        manifest.unlink()
        codes.append(self._ingest_transcript(path).returncode)
        self.assertEqual(codes, [0, 0, 0])
        events.append_events(self.log, [
            ev("unit.closed", "10:45:00", task="t", data={"head_sha": d9}, **ONE),
            ev("wave.close", "10:50:00", data={"wave": 1}, **ONE)])
        recorded, file_sha, head = events.read_log(self.log)
        verdicts = [e["data"]["head_sha"] for e in recorded if e["kind"] == "verify.verdict"]
        self.assertEqual(verdicts, [d9, None], "the changed and the missing manifest bind no head")
        report = events.derive(recorded, "r", file_sha, head)
        self.assertEqual(report["record"]["conflicts"], 0)
        self.assertEqual(report["waves"][0]["row"],
                         "| `wave=1` | `builders=1 reviewers=1` | `throughput=1.20/h` | "
                         "`latency_median=30.00m latency_max=30.00m` | `rework=0/1` | "
                         "`freshness=0` |")

    def test_the_same_source_bytes_read_from_another_path_are_a_duplicate(self):
        # Sweep (PR #638 review, identity drift): source.ref is the path as typed, so the same
        # transcript or stream imported from another working directory, or from a copy, said
        # something "different" under the same id. A source with a digest is its bytes.
        path, _manifest = self._transcript()
        self._ingest_transcript(path)
        relative = self.cli("ingest-transcript", "--transcript", path.name, "--task", "t",
                            "--run", "r", "--epoch", "1", "--clock", "host-a")  # cwd is self.tmp
        stream = self.tmp / "worker.jsonl"
        stream.write_text(json.dumps({"type": "result", "usage": {"input_tokens": 5}}) + "\n",
                          encoding="utf-8")
        copy = self.tmp / "copy-of-worker.jsonl"
        shutil.copyfile(stream, copy)
        bind = ("--run", "r", "--epoch", "1", "--clock", "host-a", "--dispatch", "d")
        usage = [self.cli("ingest-usage", "--stream", str(p), *bind) for p in (stream, copy)]
        self.assertEqual([p.stdout.split()[0] for p in (relative, *usage)],
                         ["duplicate", "appended", "duplicate"],
                         [p.stdout + p.stderr for p in (relative, *usage)])

    def test_a_head_the_store_rewrites_after_exit_is_a_second_observation_not_a_conflict(self):
        # Sweep (PR #638 review, identity drift): a worker_done naming no head takes the
        # dispatch row's, and multiclaude's worker_verify and ao's head preservation rewrite
        # dispatches.head_sha after exit. The row-derived head is part of the done's identity,
        # so the rewrite is a second observation that SHA binding sorts out, not a conflict.
        store, db = self.running_store()
        c4, d5 = sha("c4"), sha("d5")
        c = {"run": "run_x", "epoch": 1, "clock": "host-a"}
        events.append_events(self.log, [
            ev("run.start", "09:59:00", data={"coordinator": "c1"}, **c),
            ev("wave.open", "10:00:00", data={"wave": 1, "builders": 1, "reviewers": 1,
                                              "tasks": ["task_1"]}, **c)])
        self.exit_worker(store, c4)
        first = self.ingest(db)
        with store._connect() as conn:
            conn.execute("UPDATE dispatches SET head_sha = ? WHERE dispatch_id = 'disp_1'", (d5,))
        rewritten = self.ingest(db)
        self.assertEqual((first.returncode, rewritten.returncode), (0, 0), rewritten.stdout)
        self.assertNotIn("conflict", rewritten.stdout)
        events.append_events(self.log, [
            ev("review.verdict", "10:15:00", task="task_1",
               data={"verdict": "approve", "reviewed_sha": c4}, **c),
            ev("verify.verdict", "10:20:00", task="task_1", data={"exit": 0, "head_sha": c4}, **c),
            ev("unit.closed", "10:30:00", task="task_1", data={"head_sha": c4}, **c),
            ev("wave.close", "10:40:00", data={"wave": 1}, **c)])
        recorded, file_sha, digest = events.read_log(self.log)
        done = sorted(e["data"]["head_sha"] for e in recorded if e["kind"] == "task.done")
        self.assertEqual(done, [c4, d5])
        report = events.derive(recorded, "run_x", file_sha, digest)
        self.assertEqual(report["record"]["conflicts"], 0)
        self.assertEqual(self.metric(report, 1, "latency_max")["value"], "10.00m")
        self.assertTrue(report["complete"], report["waves"][0]["metrics"])


class TestStateDBNotTouched(unittest.TestCase):
    def test_a_db_that_is_not_local_state_fails_closed(self):
        tmp = Path(tempfile.mkdtemp(prefix="events-db-"))
        try:
            db = tmp / "x.db"
            sqlite3.connect(str(db)).close()
            proc = subprocess.run([sys.executable, str(EVENTS), "--log", str(tmp / "e.jsonl"),
                                   "ingest-state", "--db", str(db), "--run", "r", "--epoch", "1",
                                   "--clock", "h"], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 3, proc.stderr)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


SEEDS = range(64)


def random_unit_life(seed, reuse=False):
    """A seeded life of task t across W planning waves (2 or 3), beside u (wave 1 only), on one
    clock: replacements, heads reused or new, worker_done or none, reviews, and each earlier wave
    ending in a park, a pass or a carry; the last passes and closes.

    Returns (lifecycle events, W, dispatches of t, measured): `measured` is how many latency
    intervals the stated rules measure, written from the rules and not from the derivation — a
    pass at a head ends its interval, a park ends one only after a worker_done at that head, an
    interval already ended is never measured again, and a measurement needs a known worker_done.

    With `reuse`, every launch is read from its store row (its attempt is the row's creation
    time) and a replacement reuses the worker's dispatch id half the time, as multiclaude's
    of-<task_id> does; the dispatches returned then list one id per launch attempt."""
    rng = random.Random(seed)
    c = {"run": "rp", "epoch": 1, "clock": "host-a"}
    u = sha("ee")
    life = [ev("dispatch.launched", wave_at(1, 2), task="u", dispatch="du", **c),
            ev("task.done", wave_at(1, 5), task="u", dispatch="du", data={"head_sha": u}, **c),
            ev("review.verdict", wave_at(1, 6), task="u", dispatch="ru",
               data={"verdict": "approve", "reviewed_sha": u}, **c),
            ev("verify.verdict", wave_at(1, 7), task="u", data={"exit": 0, "head_sha": u}, **c),
            ev("unit.closed", wave_at(1, 8), task="u", data={"head_sha": u}, **c)]
    waves, dispatches, head, heads = rng.choice([2, 3]), [], None, 0
    known, ended, measured = set(), set(), 0
    for k in range(1, waves + 1):
        if k == 1 or rng.random() < 0.4:
            reused = reuse and dispatches and rng.random() < 0.5
            dispatches.append(dispatches[-1] if reused else f"d{len(set(dispatches)) + 1}")
            store = {"producer": "local_state", "basis": "occurred",
                     "ref": f"local-state:dispatches/{dispatches[-1]}",
                     "event_id": f"local-state:dispatch:{dispatches[-1]}@{wave_at(k, 1)}"} if reuse else {}
            life.append(ev("dispatch.launched", wave_at(k, 1), task="t", dispatch=dispatches[-1],
                           **store, **c))
        if head is None or rng.random() < 0.5:
            heads += 1
            head = sha(f"{heads:02x}")
        if rng.random() < 0.65:
            life.append(ev("task.done", wave_at(k, 10), task="t", dispatch=dispatches[-1],
                           data={"head_sha": head}, **c))
            known.add(head)
        if rng.random() < 0.5:
            life.append(ev("review.started", wave_at(k, 11), task="t", dispatch=f"r{k}",
                           data={"head_sha": head}, **c))
        last = k == waves
        if last or rng.random() < 0.7:
            life.append(ev("review.verdict", wave_at(k, 12), task="t", dispatch=f"r{k}",
                           data={"verdict": "approve", "reviewed_sha": head}, **c))
        end = "pass" if last else rng.choice(["park", "pass", "carry"])
        if end == "pass":
            life.append(ev("verify.verdict", wave_at(k, 20), task="t",
                           data={"exit": 0, "head_sha": head}, **c))
            measured += head not in ended and head in known
            ended.add(head)
        elif end == "park":
            life.append(ev("unit.parked", wave_at(k, 20), task="t",
                           data={"park_class": "needs-human", "head_sha": head}, **c))
            if head not in ended and head in known:
                measured += 1
                ended.add(head)
        if last:
            life.append(ev("unit.closed", wave_at(k, 30), task="t", data={"head_sha": head}, **c))
    return life, waves, dispatches, measured


def wave_at(k, minute):
    """Wave k opens at 10:00 + 60(k-1) minutes; `minute` is minutes after that."""
    total = (k - 1) * 60 + minute
    return f"{10 + total // 60:02d}:{total % 60:02d}:00"


def planned(life, waves):
    """The life planned across `waves` waves (t in each, u in wave 1 only), or in one wave."""
    c = {"run": "rp", "epoch": 1, "clock": "host-a"}
    frame = [ev("run.start", "09:59:00", data={"coordinator": "c1"}, **c)]
    for k in range(1, waves + 1):
        frame += [ev("wave.open", wave_at(k, 0), data={"wave": k, "builders": 1, "reviewers": 1,
                                                       "tasks": ["t", "u"] if k == 1 else ["t"]}, **c),
                  ev("wave.close", wave_at(k, 55), data={"wave": k}, **c)]
    if waves == 1:  # one wave holding the whole life: it closes after the last event
        frame[-1] = ev("wave.close", wave_at(3, 59), data={"wave": 1}, **c)
    return frame + life


class TestProperties(Base):
    """Property-style checks over seeded multi-wave lives (PR #638 review, fifth round): the
    same facts in any order and imported again derive the same rows, and counts are conserved
    across waves — each dispatch, void, close and latency counted once, in one wave."""

    def unit_t(self, report):
        return [u for w in report["waves"] for u in w["units"] if u["task"] == "t"]

    def test_any_order_and_any_re_import_derive_the_same_report(self):
        for seed in SEEDS:
            life, waves, _d, _m = random_unit_life(seed)
            evs = planned(life, waves)
            with self.subTest(seed=seed):
                rng = random.Random(1000 + seed)
                log = self.tmp / f"s{seed}" / "events.jsonl"
                shuffled = evs[:1] + rng.sample(evs[1:], len(evs) - 1)
                first = events.append_events(log, shuffled)
                raw = log.read_bytes()
                again = events.append_events(log, evs[:1] + rng.sample(evs[1:], len(evs) - 1))
                self.assertEqual({s for _i, s in first}, {"appended"})
                self.assertEqual({s for _i, s in again}, {"duplicate"})
                self.assertEqual(log.read_bytes(), raw, "a re-import appends nothing")
                recorded, _sha, _head = events.read_log(log)
                # Everything but the raw line digests a unit cites, which follow append order.
                canonical, derived = self.derive(evs), events.derive(recorded, "rp")
                for report in (canonical, derived):
                    for unit in (u for w in report["waves"] for u in w["units"]):
                        unit.pop("events")
                self.assertEqual(derived["waves"], canonical["waves"])
                self.assertEqual(derived["usage"], canonical["usage"])

    def test_counts_are_conserved_across_waves(self):
        for seed in SEEDS:
            life, waves, dispatches, measured = random_unit_life(seed)
            multi, single = self.derive(planned(life, waves)), self.derive(planned(life, 1))
            with self.subTest(seed=seed, waves=waves):
                self.assertEqual(multi["record"]["conflicts"], 0)
                units = self.unit_t(multi)
                self.assertEqual(len(units), waves)
                # each dispatch seen once, and each after the first is one retry, somewhere
                self.assertEqual(sorted({d for u in units for d in u["dispatches"]}), dispatches)
                self.assertEqual(sum(int(w["metrics"]["retries"]["value"]) for w in multi["waves"]),
                                 len(dispatches) - 1)
                self.assertEqual(single["waves"][0]["metrics"]["retries"]["value"],
                                 str(len(dispatches) - 1))
                # the close is verified-CLOSED once, and every voided review is counted once
                self.assertEqual(sum(u["outcome"] == "verified-closed" for u in units), 1)
                self.assertEqual(sum(int(w["metrics"]["freshness"]["value"]) for w in multi["waves"]),
                                 int(single["waves"][0]["metrics"]["freshness"]["value"]))
                # each latency interval is measured once, in the wave its end is placed in
                self.assertEqual(sum(u["latency"]["value"] is not None for u in units), measured)

    def test_reused_dispatch_ids_conserve_launch_attempts_across_waves(self):
        # PR #638 review (P1): with restarts that reuse the dispatch id (multiclaude's
        # of-<task_id>), retries still sum to launch attempts - 1, across waves and in one, a
        # worker carried between waves stays one attempt, and re-importing changes nothing.
        reusing = 0
        for seed in SEEDS:
            life, waves, attempts, measured = random_unit_life(seed, reuse=True)
            reusing += len(set(attempts)) < len(attempts)
            evs = planned(life, waves)
            multi, single = self.derive(evs), self.derive(planned(life, 1))
            with self.subTest(seed=seed, waves=waves, attempts=attempts):
                units = self.unit_t(multi)
                self.assertEqual(sorted({d for u in units for d in u["dispatches"]}),
                                 sorted(set(attempts)))
                self.assertEqual(sum(int(w["metrics"]["retries"]["value"]) for w in multi["waves"]),
                                 len(attempts) - 1)
                self.assertEqual(single["waves"][0]["metrics"]["retries"]["value"],
                                 str(len(attempts) - 1))
                self.assertEqual(sum(u["latency"]["value"] is not None for u in units), measured)
                log = self.tmp / f"reuse-{seed}" / "events.jsonl"
                rng = random.Random(2000 + seed)
                events.append_events(log, evs[:1] + rng.sample(evs[1:], len(evs) - 1))
                again = events.append_events(log, evs[:1] + rng.sample(evs[1:], len(evs) - 1))
                self.assertEqual({s for _i, s in again}, {"duplicate"})
        self.assertGreater(reusing, len(SEEDS) // 8, "the generator must actually reuse ids")

    def test_re_importing_a_store_after_every_change_it_allows_never_conflicts(self):
        """Seeded walks over the changes the local-state store allows a worker-start dispatch —
        register, claim, abandon before any claim, worker_done with and without a head, exit
        or death, publication touching updated_at, a provider rewriting the head — importing
        after each. No import conflicts; the last one is all duplicates; a dispatch is
        recorded as launched once iff a monitor claimed it."""
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        LocalStateStore = importlib.import_module("runtime.providers.local_state").LocalStateStore
        ten = calendar.timegm((2026, 10, 20, 10, 0, 0))
        for seed in range(10):
            rng = random.Random(seed)
            root = self.tmp / f"store-{seed}"
            root.mkdir()
            store, log = LocalStateStore(root / "runtime.db", env={}), root / "events.jsonl"
            events.append_events(log, [ev("run.start", "09:00:00", data={"coordinator": "c1"},
                                          run="run_x", epoch=1, clock="host-a")])
            rows, statuses = {}, []

            def ingest(log=log, root=root):
                out = io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    code = events.main(["--log", str(log), "ingest-state", "--db",
                                        str(root / "runtime.db"), "--run", "run_x", "--epoch", "1",
                                        "--clock", "host-a"])
                return code, [ln.split()[0] for ln in out.getvalue().splitlines()]
            for step in range(20):
                now = ten + 60 * step
                ready = [d for d, r in rows.items() if r == "ready"]
                running = [d for d, r in rows.items() if r == "claimed"]
                exited = [d for d, r in rows.items() if r == "exited"]
                ops = ["register"] + ["claim", "abandon"] * bool(ready) \
                    + ["done", "exit"] * bool(running) + ["touch"] * bool(rows) + ["rewrite"] * bool(exited)
                op = rng.choice(ops)
                if op == "register":
                    disp = f"disp_{len(rows)}"
                    with store._connect() as conn:
                        conn.execute("INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, "
                                     "agent, terminal_handle, state, created_at, updated_at, intent_id) "
                                     "VALUES (?, ?, 'run_x', '/w', 'claude', ?, 'ready', ?, ?, ?)",
                                     (disp, f"task_{len(rows) % 2}", f"term_{disp}", now, now, f"i_{disp}"))
                    rows[disp] = "ready"
                elif op == "claim":
                    disp = rng.choice(ready)
                    self.assertTrue(store.claim_monitor(disp, 4242))
                    rows[disp] = "claimed"
                elif op == "abandon":
                    disp = rng.choice(ready)
                    self.assertTrue(store.abandon_unlaunched(disp))
                    rows[disp] = "abandoned"
                elif op == "done":
                    disp = rng.choice(running)
                    attrs = {"headSha": sha("c4")} if rng.random() < 0.5 else None
                    sent = store.send_message(subject="done", msg_type="worker_done",
                                              sender=f"term_{disp}", run="run_x", attrs=attrs)
                    with store._connect() as conn:
                        conn.execute("UPDATE messages SET created_at = ? WHERE id = ?",
                                     (now, sent["messageId"]))
                elif op == "exit":
                    disp = rng.choice(running)
                    store.ensure_terminal_or_died(dispatch_id=disp, worker_handle=f"term_{disp}",
                                                  exit_code=0, worktree_head_sha=sha("d5"),
                                                  run_id="run_x")
                    rows[disp] = "exited"
                elif op == "touch":  # mostly an exited row: publication after a fast death
                    target = rng.choice(exited if exited and rng.random() < 0.7 else sorted(rows))
                    with store._connect() as conn:
                        conn.execute("UPDATE dispatches SET updated_at = ? WHERE dispatch_id = ?",
                                     (now + 30, target))
                else:
                    with store._connect() as conn:
                        conn.execute("UPDATE dispatches SET head_sha = ? WHERE dispatch_id = ?",
                                     (sha(f"{step:02x}"), rng.choice(exited)))
                code, out = ingest()
                statuses += out
                with self.subTest(seed=seed, step=step, op=op):
                    self.assertIn(code, (0, 1))
                    self.assertNotIn("conflict", out)
            code, last = ingest()
            recorded = events.read_log(log)[0]
            launched = sorted(e["dispatch"] for e in recorded if e["kind"] == "dispatch.launched")
            with self.subTest(seed=seed):
                self.assertNotIn("conflict", statuses)
                self.assertEqual(set(last) - {"duplicate"}, set())
                self.assertEqual(launched, sorted(d for d, r in rows.items() if r in ("claimed", "exited")))
                self.assertEqual(events.derive(recorded, "run_x")["record"]["conflicts"], 0)

    def test_cross_run_event_id_conflict_surfaces_in_both_runs_and_taints_completeness_c42(self):
        stream = list(scenario_clean())
        # Add an event in another run that reuses an event_id from run-a ('local-state:dispatch:d1')
        foreign_conflict = ev(
            "dispatch.launched", "10:01:00", task="t1", dispatch="d1",
            data={"agent": "codex"}, event_id="local-state:dispatch:d1",
            producer="local_state", basis="occurred",
            run="run-other", epoch=1, clock="host-a",
        )
        other_start = ev(
            "run.start", "10:00:00", data={"coordinator": "coord-other"},
            run="run-other", epoch=1, clock="host-a",
        )
        report_a = self.derive(stream + [other_start, foreign_conflict], run="run-a")
        self.assertEqual(report_a["record"]["conflicts"], 1)
        self.assertEqual(report_a["conflicts"][0]["event_id"], "local-state:dispatch:d1")
        self.assertFalse(report_a["complete"])

        # Also test when the foreign run comes FIRST in the log and run-a is second
        report_a_second = self.derive([other_start, foreign_conflict] + stream, run="run-a")
        self.assertEqual(report_a_second["record"]["conflicts"], 1)
        self.assertEqual(report_a_second["conflicts"][0]["event_id"], "local-state:dispatch:d1")
        self.assertFalse(report_a_second["complete"])

    def test_blank_line_insertion_fails_verification_and_append_c43(self):
        base_text = chain(scenario_clean()[:3])
        lines = base_text.splitlines()
        for label, mutated in (
            ("leading blank line", "\n" + base_text),
            ("interior blank line", lines[0] + "\n\n" + "\n".join(lines[1:]) + "\n"),
            ("trailing blank line", base_text + "\n"),
            ("whitespace-only line", lines[0] + "\n   \n" + "\n".join(lines[1:]) + "\n"),
        ):
            with self.subTest(label=label):
                self.log.parent.mkdir(parents=True, exist_ok=True)
                self.log.write_text(mutated, encoding="utf-8")
                with self.assertRaises(events.EventsError):
                    events.read_log(self.log)
                with self.assertRaises(events.EventsError):
                    events.append_events(self.log, scenario_clean()[3:4])
                self.assertEqual(self.cli("verify").returncode, 3)


if __name__ == "__main__":
    unittest.main()
