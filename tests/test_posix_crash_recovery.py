#!/usr/bin/env python3
"""Crash-injection tests for the POSIX worker launch (#597; spec: docs/runtimes.md).

A REAL coordinator subprocess runs `worker_start` and parks at one committed launch boundary
(`LAUNCH_BOUNDARIES`, through the provider's `on_launch_boundary` observer); this test SIGKILLs
it there, so no `finally`, no rollback and no receipt of the coordinator ever runs. The test
process then plays the restarted coordinator. Workers are INERT: a fake `claude` in the test's
temp dir that logs its identity (and, where a test asks, commits) and sleeps. Every other
harness name resolves to a tripwire that records a hit, so no real agent can start.

Backend: `setsid` (real processes). tmux and cmux are NOT exercised here (docs/runtimes.md says
so); the Docker `danger` path runs against a fake `docker` CLI, the fixture tier, never a daemon.
"""
from __future__ import annotations

import importlib
import json
import os
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent

CHILD = r'''
import json, os, sys
sys.path.insert(0, sys.argv[1])
from runtime.providers import get_provider

args = json.loads(sys.argv[2])
prov = get_provider("posix", env=dict(os.environ))
park_at = args.get("park_at")


def hook(stage, info):
    print(json.dumps({"boundary": stage, "info": info, "pid": os.getpid()}), flush=True)
    if stage == park_at:
        # Parked right after the boundary committed: the test SIGKILLs this process here
        # (or, in the takeover tests, lets it go on by writing a line).
        sys.stdin.readline()


prov.on_launch_boundary = hook
try:
    res = prov.worker_start(**args["start"])
    print(json.dumps({"result": res}), flush=True)
except Exception as exc:
    print(json.dumps({"error": getattr(exc, "code", type(exc).__name__), "message": str(exc)}), flush=True)
    sys.exit(3)
'''


def _git(*args, cwd, env=None, check=True):
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=check, capture_output=True, text=True)


def _wait_for(pred, timeout=20.0, step=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(step)
    return False


def _alive(pid):
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    proc = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True)
    return proc.returncode == 0 and not proc.stdout.strip().startswith("Z")


class FakeClock:
    """Stands in for posix.py's `time`: only its own sleeps advance it, so a grace is measured, never waited."""

    def __init__(self):
        self.now = time.time()
        self.slept = 0.0

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds
        self.slept += seconds


class Coordinator:
    """A coordinator subprocess and the boundary lines it printed."""

    def __init__(self, proc):
        self.proc = proc
        self.lines: queue.Queue = queue.Queue()
        self.seen: list[str] = []
        self.info: dict = {}
        self.pump = threading.Thread(target=self._pump, daemon=True)
        self.pump.start()

    def _pump(self):
        for line in self.proc.stdout:
            self.lines.put(json.loads(line))
        self.lines.put(None)

    def until(self, boundary, timeout=60.0):
        deadline = time.time() + timeout
        while True:
            msg = self.lines.get(timeout=max(0.1, deadline - time.time()))
            if msg is None:
                raise AssertionError(f"coordinator ended before {boundary!r}; saw {self.seen}")
            if "boundary" in msg:
                self.seen.append(msg["boundary"])
                self.info = msg["info"]
                if msg["boundary"] == boundary:
                    return msg
            elif boundary is None:
                return msg

    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=30)
        self.pump.join(timeout=10)
        for pipe in (self.proc.stdin, self.proc.stdout):
            if pipe is not None:
                pipe.close()

    def finish(self, timeout=60.0):
        """Every remaining line, through the final result/error line."""
        out = []
        deadline = time.time() + timeout
        while True:
            msg = self.lines.get(timeout=max(0.1, deadline - time.time()))
            if msg is None:
                break
            if "boundary" in msg:
                self.seen.append(msg["boundary"])
                self.info = msg["info"]
            out.append(msg)
        self.proc.wait(timeout=timeout)
        return out


class CrashRecoveryBase(unittest.TestCase):
    def setUp(self):
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        self.providers = importlib.import_module("runtime.providers")
        self.posix = importlib.import_module("runtime.providers.posix")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name).resolve()
        self.base = base
        self.repo = base / "repo"
        self.repo.mkdir()
        _git("init", "-q", "-b", "main", cwd=self.repo)
        _git("config", "user.email", "t@example.com", cwd=self.repo)
        _git("config", "user.name", "T", cwd=self.repo)
        (self.repo / "README.md").write_text("# r\n", encoding="utf-8")
        _git("add", "README.md", cwd=self.repo)
        _git("commit", "-qm", "init", cwd=self.repo)
        self.bin = base / "bin"
        self.bin.mkdir()
        self.tripwire = base / "tripwire"
        self.tripwire.mkdir()
        self.tripwire_log = base / "tripwire.log"
        for harness in self.providers.SUPPORTED_HARNESSES:
            trip = self.tripwire / harness
            trip.write_text(f'#!/bin/sh\necho "{harness} $*" >> "{self.tripwire_log}"\nexit 97\n', encoding="utf-8")
            trip.chmod(0o755)
        self.agent_log = base / "agent.log"
        self.child = base / "coordinator.py"
        self.child.write_text(CHILD, encoding="utf-8")
        self.env = {
            **os.environ,
            "OPEN_FLEET_STATE_DB": str(base / "state" / "runtime.db"),
            "OPEN_FLEET_CLI_CWD": str(self.repo),
            "OPEN_FLEET_POSIX_BACKEND": "setsid",
            "PATH": os.pathsep.join([str(self.bin), str(self.tripwire), os.environ.get("PATH", "")]),
            "SHELL": "/bin/sh",
        }
        self.env.pop("PYTHON", None)
        self.coordinators: list[Coordinator] = []
        self.addCleanup(self._no_tripwire_hit)
        self.addCleanup(self._kill_all)
        self.agent("sleeper")
        self.task = self.restart().task_create(spec="inert work", run="run-r04")["task"]["id"]

    # --- fixtures ---
    def agent(self, kind):
        """The fake `claude`: logs `<dispatch> <run> <pid>` once, then behaves per `kind`."""
        tail = {
            "sleeper": "exec sleep 30",
            "committer": (
                'echo work > work.txt && git add work.txt && '
                'git -c user.email=w@x -c user.name=w commit -qm worker-commit && '
                f'echo committed >> "{self.agent_log}.commit"\nexec sleep 30'
            ),
            "quick_exit": "exit 0",
        }[kind]
        path = self.bin / "claude"
        path.write_text(
            f'#!/bin/sh\necho "$OPEN_FLEET_DISPATCH_ID $OPEN_FLEET_RUN_ID $$" >> "{self.agent_log}"\n{tail}\n',
            encoding="utf-8",
        )
        path.chmod(0o755)

    def restart(self):
        """A fresh coordinator in THIS process (the crashed one was another process)."""
        return self.providers.get_provider("posix", env=self.env)

    def start_kwargs(self, **over):
        kw = {"task_id": self.task, "worktree": "new-child", "agent": "claude", "profile": "rw", "run": "run-r04"}
        kw.update(over)
        return kw

    def coordinator(self, park_at, env=None, **start):
        proc = subprocess.Popen(
            [sys.executable, "-I", str(self.child), str(ROOT), json.dumps({"park_at": park_at, "start": self.start_kwargs(**start)})],
            env=env or self.env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        c = Coordinator(proc)
        self.coordinators.append(c)
        return c

    def crash_at(self, boundary, env=None, **start):
        """SIGKILL a real coordinator right after `boundary` committed; return its identity."""
        c = self.coordinator(boundary, env=env, **start)
        msg = c.until(boundary)
        os.kill(c.proc.pid, signal.SIGKILL)
        c.proc.wait(timeout=30)
        self.assertEqual(c.proc.returncode, -signal.SIGKILL)
        order = list(self.posix.LAUNCH_BOUNDARIES)
        self.assertEqual(c.seen, order[: order.index(boundary) + 1], "boundaries must be crossed in their committed order")
        return {**msg["info"], "coordinatorPid": msg["pid"]}

    def agent_lines(self):
        return self.agent_log.read_text().splitlines() if self.agent_log.exists() else []

    def assert_no_worker_ran(self, settle=1.5):
        time.sleep(settle)
        self.assertEqual(self.agent_lines(), [], "no worker may run for a launch that recovery rolled back")

    def dispatch(self, prov, dispatch_id):
        with prov.state._connect() as conn:
            row = conn.execute("SELECT * FROM dispatches WHERE dispatch_id = ?", (dispatch_id,)).fetchone()
        return dict(row) if row else None

    def task_status(self, prov):
        return {t["id"]: t["status"] for t in prov.task_list()["tasks"]}[self.task]

    def dispatches_for_task(self, prov):
        with prov.state._connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM dispatches WHERE task_id = ?", (self.task,)).fetchall()]

    # --- cleanup ---
    def _no_tripwire_hit(self):
        hits = self.tripwire_log.read_text() if self.tripwire_log.exists() else ""
        self.assertEqual(hits, "", f"an agent resolved past the fake bin to the tripwire: {hits!r}")

    def _ours(self, pid):
        """Only a process whose command line lies in THIS test's temp dir is ever signalled."""
        proc = subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True, text=True)
        return proc.returncode == 0 and str(self.base) in proc.stdout

    def _kill_all(self):
        for c in self.coordinators:
            c.close()
        pids = set()
        db = self.base / "state" / "runtime.db"
        if db.exists():
            with self.restart().state._connect() as conn:
                for r in conn.execute("SELECT pid, monitor_pid FROM dispatches WHERE lane_dir IS NOT NULL").fetchall():
                    pids.update(int(x) for x in (r["pid"], r["monitor_pid"]) if x and int(x) > 0)
        # A monitor is its own session leader: its group holds the worker (and a fake sandbox).
        mine = [pid for pid in pids if self._ours(pid)]
        for pid in mine:
            try:
                os.killpg(pid, signal.SIGKILL)
            except OSError:
                continue
        for pid in mine:
            _wait_for(lambda pid=pid: not _alive(pid), timeout=10)


class TestCrashMatrixSetsid(CrashRecoveryBase):
    """One SIGKILL per committed boundary, in the order a launch crosses them."""

    def test_kill_after_intent_claimed_rolls_back_and_replays_the_failure(self):
        info = self.crash_at("intent_claimed", retry_request="req-1")
        prov = self.restart()
        shown = prov.request_show("req-1")
        self.assertEqual(shown["state"], "pending", "the request is recorded before any side effect")
        self.assertEqual(shown["intent"]["id"], info["intentId"])
        self.assertEqual(shown["intent"]["phase"], "claimed")
        self.assertEqual(self.task_status(prov), "dispatched")
        rec = prov.launch_reconcile()["reconciled"]
        self.assertEqual(len(rec), 1)
        r = rec[0]
        self.assertEqual(r["resolution"], "failed")
        self.assertEqual(r["error"]["code"], "launch_interrupted")
        self.assertEqual(r["dispatchId"], info["dispatchId"], "recovery never mints a new identity")
        self.assertEqual(r["owner"]["previous"]["pid"], info["coordinatorPid"])
        self.assertIs(r["owner"]["previous"]["alive"], False)
        self.assertEqual(r["task"], {"id": self.task, "before": "dispatched", "after": "ready"})
        self.assertIs(r["completionInferred"], False)
        self.assertEqual(prov.request_show("req-1")["state"], "failed")
        with self.assertRaises(self.providers.ProviderError) as ctx:
            prov.worker_start(**self.start_kwargs(retry_request="req-1"))
        self.assertEqual(ctx.exception.code, "launch_interrupted", "a retry replays the recorded failure")
        self.assertTrue(ctx.exception.data["replayed"])
        self.assertEqual(prov.launch_reconcile()["count"], 0)
        self.assert_no_worker_ran()

    def test_kill_after_worktree_created_keeps_and_pins_the_worktree(self):
        info = self.crash_at("worktree_created", retry_request="req-1")
        wt = Path(info["worktree"])
        self.assertTrue((wt / ".git").is_file(), "the worktree exists when the coordinator dies")
        prov = self.restart()
        r = prov.launch_reconcile(request="req-1")["reconciled"][0]
        self.assertEqual(r["resolution"], "failed")
        self.assertEqual(r["task"]["after"], "ready")
        kept = [c for c in r["cleanup"] if c["kind"] == "worktree"]
        self.assertEqual(kept, [{"kind": "worktree", "target": str(wt), "action": "kept", "why": "recovery never deletes a worktree or a branch"}])
        self.assertTrue(wt.is_dir())
        head = _git("rev-parse", "HEAD", cwd=wt).stdout.strip()
        self.assertEqual(r["preservedRefs"][0]["ref"], f"refs/open-fleet/preserved/{info['dispatchId']}")
        self.assertEqual(r["preservedRefs"][0]["sha"], head)
        self.assertEqual(_git("rev-parse", r["preservedRefs"][0]["ref"], cwd=self.repo).stdout.strip(), head)
        self.assert_no_worker_ran()
        # The task really is startable again: a NEW request reuses the kept worktree, one worker.
        res = prov.worker_start(**self.start_kwargs(retry_request="req-2"))
        self.assertEqual(res["worker"]["worktree"], str(wt))
        self.assertTrue(_wait_for(lambda: len(self.agent_lines()) == 1))

    def test_kill_after_registered_abandons_the_unlaunched_dispatch(self):
        info = self.crash_at("registered", retry_request="req-1")
        prov = self.restart()
        before = self.dispatch(prov, info["dispatchId"])
        self.assertEqual((before["state"], before["pid"]), ("ready", 0))
        # Through the CLI verb a coordinator runs (`orchestration launch-reconcile`).
        out = prov.dispatch(["orchestration", "launch-reconcile", "--request", "req-1", "--json"])
        self.assertEqual(out["count"], 1)
        r = out["reconciled"][0]
        self.assertEqual(r["resolution"], "failed")
        self.assertEqual(r["dispatch"], {"id": info["dispatchId"], "before": "ready", "after": "abandoned"})
        self.assertIn({"kind": "dispatch", "target": info["dispatchId"], "action": "abandoned",
                       "why": "kept for its identity; a late monitor is refused at the launch gate"}, r["cleanup"])
        monitor = [p for p in r["processes"] if p["role"] == "monitor"]
        self.assertEqual(monitor[0]["action"], "refused_at_gate")
        self.assertEqual(r["task"]["after"], "ready")
        self.assertEqual(prov.request_show("req-1")["state"], "failed")
        self.assert_no_worker_ran()

    def test_kill_after_monitor_spawned_adopts_the_live_worker(self):
        self.agent("committer")
        info = self.crash_at("monitor_spawned", retry_request="req-1")
        disp = info["dispatchId"]
        self.assertTrue(_wait_for(lambda: Path(f"{self.agent_log}.commit").exists()), "the inert worker never committed")
        prov = self.restart()
        row = self.dispatch(prov, disp)
        self.assertEqual(row["pid"], 0, "the dead coordinator never published a pid")
        self.assertGreater(row["monitor_pid"], 0, "the monitor recorded itself at the launch gate")
        # Restart + retry in ONE call: the request resolves to the live dispatch, no new worker.
        res = prov.worker_start(**self.start_kwargs(retry_request="req-1"))
        self.assertEqual((res["state"], res["dispatchId"]), ("ready", disp))
        rec = res["recovery"]
        self.assertEqual(rec["resolution"], "live")
        monitor = [p for p in rec["processes"] if p["role"] == "monitor"][0]
        self.assertEqual((monitor["action"], monitor["pid"], monitor["alive"]), ("adopted", row["monitor_pid"], True))
        self.assertEqual(self.dispatch(prov, disp)["pid"], row["monitor_pid"], "adoption publishes the monitor's pid")
        wt = Path(info["worktree"])
        commit = _git("rev-parse", "HEAD", cwd=wt).stdout.strip()
        self.assertEqual(_git("log", "-1", "--format=%s", commit, cwd=wt).stdout.strip(), "worker-commit")
        self.assertEqual(rec["preservedRefs"][0]["sha"], commit, "the worker's commit is pinned, never lost")
        self.assertEqual(_git("rev-parse", f"refs/open-fleet/preserved/{disp}", cwd=self.repo).stdout.strip(), commit)
        again = prov.worker_start(**self.start_kwargs(retry_request="req-1"))
        self.assertEqual(again["dispatchId"], disp)
        time.sleep(1.0)
        self.assertEqual(len(self.agent_lines()), 1, "retrying the same request never spawns a second worker")
        self.assertEqual(len(self.dispatches_for_task(prov)), 1)
        self.assertEqual(self.agent_lines()[0].split()[:2], [disp, "run-r04"], "the worker runs under the recorded identity")
        agent_pid = int(self.agent_lines()[0].split()[-1])
        prov.worker_fence("stop", disp)
        self.assertTrue(_wait_for(lambda: not _alive(agent_pid)), "stop must reach the adopted worker")

    def test_kill_after_published_adopts_and_completes_the_request(self):
        info = self.crash_at("published", retry_request="req-1")
        self.assertTrue(_wait_for(lambda: len(self.agent_lines()) == 1))
        prov = self.restart()
        self.assertGreater(self.dispatch(prov, info["dispatchId"])["pid"], 0)
        self.assertEqual(prov.request_show("req-1")["state"], "pending", "the receipt never committed")
        r = prov.launch_reconcile(intent=info["intentId"])["reconciled"][0]
        self.assertEqual((r["resolution"], r["requestState"]), ("live", "completed"))
        replay = prov.worker_start(**self.start_kwargs(retry_request="req-1"))
        self.assertEqual(replay["dispatchId"], info["dispatchId"])
        self.assertEqual(replay["recovery"]["intentId"], info["intentId"])
        time.sleep(1.0)
        self.assertEqual(len(self.agent_lines()), 1)

    def test_kill_after_receipted_leaves_nothing_to_settle(self):
        info = self.crash_at("receipted", retry_request="req-1")
        prov = self.restart()
        self.assertEqual(prov.request_show("req-1")["state"], "completed")
        self.assertEqual(prov.launch_reconcile()["count"], 0)
        replay = prov.worker_start(**self.start_kwargs(retry_request="req-1"))
        self.assertEqual(replay["dispatchId"], info["dispatchId"])
        self.assertNotIn("recovery", replay, "an uninterrupted receipt is replayed as recorded")
        self.assertTrue(_wait_for(lambda: len(self.agent_lines()) == 1))
        time.sleep(0.5)
        self.assertEqual(len(self.agent_lines()), 1)


class TestUninterruptedControl(CrashRecoveryBase):
    def test_clean_launch_crosses_every_boundary_and_leaves_no_open_intent(self):
        c = self.coordinator(None, retry_request="req-1")
        out = c.finish()
        self.assertEqual(c.seen, list(self.posix.LAUNCH_BOUNDARIES))
        res = out[-1]["result"]
        self.assertEqual(res["state"], "ready")
        prov = self.restart()
        self.assertEqual(prov.request_show("req-1")["state"], "completed")
        it = prov.state.launch_intent(c.info["intentId"])
        self.assertEqual((it["phase"], it["outcome"]), ("receipted", "completed"))
        self.assertEqual(prov.launch_reconcile()["count"], 0)
        self.assertTrue(_wait_for(lambda: len(self.agent_lines()) == 1))
        self.assertFalse((Path(c.info["laneDir"]) / "recovery.json").exists(), "nothing was recovered")
        self.assertFalse(prov.state.db_path.parent.joinpath("intents", f"{c.info['intentId']}.lock").exists())
        self.assertEqual([w["state"] for w in prov.worker_list()["workers"]], ["ready"])


class TestNoCompletionFromProcessExit(CrashRecoveryBase):
    def test_worker_exit_without_mail_is_a_death_not_a_completion(self):
        self.agent("quick_exit")
        info = self.crash_at("monitor_spawned", retry_request="req-1")
        lane = Path(info["laneDir"])
        prov = self.restart()
        self.assertTrue(_wait_for(lambda: prov.state.dispatch_state(info["dispatchId"]) == "died"))
        r = prov.launch_reconcile()["reconciled"][0]
        self.assertEqual(r["resolution"], "exited")
        self.assertEqual(r["dispatch"]["after"], "died")
        self.assertEqual(r["task"]["after"], "dispatched", "an exit 0 never completes the task")
        self.assertIs(r["completionInferred"], False)
        self.assertTrue((lane / "recovery.json").is_file())
        died = [m for m in prov.check_messages(terminal="coordinator", run="run-r04")["messages"]
                if m["subject"].startswith(f"worker_died:{info['dispatchId']}")]
        self.assertEqual(len(died), 1)

    def test_monitor_killed_with_the_coordinator_is_reported_dead_with_its_commit(self):
        self.agent("committer")
        info = self.crash_at("published", retry_request="req-1")
        self.assertTrue(_wait_for(lambda: Path(f"{self.agent_log}.commit").exists()))
        prov = self.restart()
        pid = self.dispatch(prov, info["dispatchId"])["pid"]
        os.killpg(pid, signal.SIGKILL)  # the whole host went down: monitor and worker too
        self.assertTrue(_wait_for(lambda: not _alive(pid)))
        r = prov.launch_reconcile()["reconciled"][0]
        monitor = [p for p in r["processes"] if p["role"] == "monitor"][0]
        self.assertEqual((r["resolution"], monitor["action"], monitor["alive"]), ("exited", "reported_dead", False))
        self.assertEqual(r["dispatch"]["after"], "died")
        commit = _git("rev-parse", "HEAD", cwd=info["worktree"]).stdout.strip()
        self.assertEqual(r["preservedRefs"][0]["sha"], commit)
        payload = json.loads([m for m in prov.check_messages(terminal="coordinator", run="run-r04")["messages"]
                              if info["dispatchId"] in m["subject"]][0]["payload"])
        self.assertEqual((payload["exitCode"], payload["headSha"]), (-1, commit))


class TestLaunchGateAndFencing(CrashRecoveryBase):
    def test_gate_claim_and_abandon_are_mutually_exclusive(self):
        store = self.restart().state
        with store._connect() as conn:
            for d in ("disp_a", "disp_b"):
                conn.execute(
                    "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, pid, created_at, updated_at) "
                    "VALUES (?, 't', 'default', '/w', 'claude', ?, 'ready', 0, 0, 0)",
                    (d, f"term_{d}"),
                )
        self.assertTrue(store.claim_monitor("disp_a", 111))
        self.assertFalse(store.abandon_unlaunched("disp_a"), "a gated dispatch is adopted, never abandoned")
        self.assertFalse(store.claim_monitor("disp_a", 222), "one monitor per dispatch")
        self.assertTrue(store.abandon_unlaunched("disp_b"))
        self.assertFalse(store.claim_monitor("disp_b", 333), "an abandoned dispatch refuses a late monitor")
        self.assertEqual(store.dispatch_state("disp_b"), "abandoned")

    def test_late_monitor_after_rollback_is_refused_at_the_gate(self):
        # A launcher that outlived its coordinator starts the monitor AFTER recovery ran.
        wrapper = self.base / "slow-python"
        wrapper.write_text(f'#!/bin/sh\ncase "$2" in -c) ;; *) sleep 3 ;; esac\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
        wrapper.chmod(0o755)
        info = self.crash_at("monitor_spawned", env={**self.env, "PYTHON": str(wrapper)}, retry_request="req-1")
        prov = self.restart()
        r = prov.launch_reconcile()["reconciled"][0]
        self.assertEqual(r["resolution"], "failed", "no monitor had claimed the gate yet: roll back")
        events = Path(info["laneDir"]) / "events.jsonl"
        self.assertTrue(_wait_for(lambda: "launch_refused" in events.read_text(), timeout=30), "the late monitor must be refused")
        self.assert_no_worker_ran(settle=0.5)
        self.assertEqual(prov.state.dispatch_state(info["dispatchId"]), "abandoned")
        self.assertEqual(self.task_status(prov), "ready")

    def test_stop_after_a_crash_reaches_a_gated_but_unpublished_monitor(self):
        info = self.crash_at("monitor_spawned")
        self.assertTrue(_wait_for(lambda: len(self.agent_lines()) == 1))
        agent_pid = int(self.agent_lines()[0].split()[-1])
        prov = self.restart()
        self.assertEqual(self.dispatch(prov, info["dispatchId"])["pid"], 0)
        out = prov.worker_fence("stop", info["dispatchId"])
        self.assertEqual(out["termination"].get("pidGroup"), "terminated", out)
        self.assertTrue(_wait_for(lambda: not _alive(agent_pid)), "`stopped` must mean the agent stopped")
        r = prov.launch_reconcile()["reconciled"][0]
        self.assertEqual((r["resolution"], r["error"]["code"]), ("failed", "dispatch_fenced"))
        self.assertEqual(r["task"]["after"], "ready")

    def test_worker_list_settles_an_ownerless_launch(self):
        info = self.crash_at("registered")
        prov = self.restart()
        states = {w["dispatchId"]: w["state"] for w in prov.worker_list()["workers"]}
        self.assertEqual(states, {info["dispatchId"]: "abandoned"})
        self.assertEqual(self.task_status(prov), "ready")
        lane = Path(info["laneDir"])
        self.assertEqual(json.loads((lane / "recovery.json").read_text())["resolution"], "failed")


class TestInspectableUnknown(CrashRecoveryBase):
    """When recovery cannot prove what happened, it says so and changes nothing (#597)."""

    def test_owner_on_another_host_is_reported_and_left_untouched(self):
        info = self.crash_at("registered", retry_request="req-1")
        prov = self.restart()
        with prov.state._connect() as conn:  # a state dir shared with another host
            conn.execute("UPDATE launch_intents SET owner_host = 'elsewhere' WHERE intent_id = ?", (info["intentId"],))
        r = prov.launch_reconcile()["reconciled"][0]
        self.assertEqual((r["resolution"], r["requestState"]), ("unknown", "pending"))
        self.assertIsNone(r["owner"]["previous"]["alive"], "another host's coordinator cannot be checked from here")
        self.assertEqual(prov.state.dispatch_state(info["dispatchId"]), "ready")
        res = prov.worker_start(**self.start_kwargs(retry_request="req-1"))
        self.assertEqual((res["state"], res["dispatchId"]), ("outcome_unknown", info["dispatchId"]))
        self.assertIn(f"orchestration worker-show --dispatch {info['dispatchId']} --json", res["nextCommands"])
        self.assertEqual(prov.request_show("req-1")["state"], "pending")
        settled = prov.launch_reconcile(intent=info["intentId"], takeover=True)["reconciled"][0]
        self.assertEqual(settled["resolution"], "failed")
        self.assert_no_worker_ran()

    def test_unprovable_liveness_is_recorded_unknown_and_never_redecided_by_polling(self):
        self.env = {**self.env, "OPEN_FLEET_POSIX_BACKEND": "dry-run"}  # no process to observe
        info = self.crash_at("published", retry_request="req-1")
        prov = self.restart()
        r = prov.launch_reconcile()["reconciled"][0]
        self.assertEqual((r["resolution"], r["requestState"]), ("unknown", "unknown"))
        self.assertEqual(prov.request_show("req-1")["state"], "unknown")
        epoch = prov.state.launch_intent(info["intentId"])["epoch"]
        prov.worker_list()
        prov.worker_show(info["dispatchId"])
        self.assertEqual(prov.state.launch_intent(info["intentId"])["epoch"], epoch, "polling never re-decides an unknown launch")
        replay = prov.worker_start(**self.start_kwargs(retry_request="req-1"))
        self.assertEqual((replay["state"], replay["dispatchId"]), ("outcome_unknown", info["dispatchId"]))
        self.assertEqual(replay["recovery"]["resolution"], "unknown")
        again = prov.launch_reconcile(intent=info["intentId"])["reconciled"][0]
        self.assertEqual(again["resolution"], "unknown")
        self.assertEqual(again["owner"]["epoch"], epoch + 1, "an explicit reconcile does visit it again")
        self.assertEqual((prov.state.dispatch_state(info["dispatchId"]), self.task_status(prov)), ("ready", "dispatched"))


class TestTakeoverFencesOldWriters(CrashRecoveryBase):
    def test_live_owner_is_left_alone_without_takeover_and_new_starts_name_it(self):
        c = self.coordinator("registered", retry_request="req-1")
        info = c.until("registered")["info"]
        prov = self.restart()
        r = prov.launch_reconcile(intent=info["intentId"])["reconciled"][0]
        self.assertEqual(r["resolution"], "pending")
        self.assertIs(r["owner"]["previous"]["alive"], True)
        self.assertEqual(prov.state.dispatch_state(info["dispatchId"]), "ready", "a live owner's launch is never touched")
        self.assertEqual(prov.worker_start(**self.start_kwargs(retry_request="req-1"))["state"], "outcome_unknown")
        with self.assertRaises(self.providers.ProviderError) as ctx:
            prov.worker_start(**self.start_kwargs(retry_request="req-other"))
        self.assertEqual(ctx.exception.code, "task_not_startable")
        self.assertEqual(ctx.exception.data["openLaunch"]["intentId"], info["intentId"])
        self.assertIn("launch-reconcile", ctx.exception.data["nextSteps"][0])
        os.kill(c.proc.pid, signal.SIGKILL)
        c.proc.wait(timeout=30)
        # Once its owner is gone, the next start settles the stale launch and proceeds.
        res = prov.worker_start(**self.start_kwargs(retry_request="req-other"))
        self.assertNotEqual(res["dispatchId"], info["dispatchId"])
        self.assertEqual(prov.state.dispatch_state(info["dispatchId"]), "abandoned")
        self.assertTrue(_wait_for(lambda: len(self.agent_lines()) == 1))
        self.assertEqual(self.agent_lines()[0].split()[0], res["dispatchId"])

    def test_takeover_before_spawn_fences_the_old_writer(self):
        c = self.coordinator("registered", retry_request="req-1")
        info = c.until("registered")["info"]
        prov = self.restart()
        r = prov.launch_reconcile(intent=info["intentId"], takeover=True)["reconciled"][0]
        self.assertEqual(r["resolution"], "failed")
        self.assertIs(r["takeover"], True)
        self.assertIs(r["owner"]["previous"]["alive"], True)
        self.assertEqual(r["owner"]["epoch"], 2)
        c.proc.stdin.write("\n")
        c.proc.stdin.flush()
        tail = c.finish()
        self.assertEqual(tail[-1].get("error"), "launch_fenced", tail)
        self.assertEqual(c.proc.returncode, 3)
        self.assertNotIn("monitor_spawned", c.seen, "a fenced coordinator never spawns")
        row = self.dispatch(prov, info["dispatchId"])
        self.assertEqual((row["state"], row["pid"]), ("abandoned", 0), "the old writer published nothing")
        self.assertEqual(prov.request_show("req-1")["state"], "failed", "the new owner's outcome stands")
        self.assertEqual(self.task_status(prov), "ready")
        self.assert_no_worker_ran()

    def test_takeover_after_spawn_adopts_and_the_old_writer_leaves_it_running(self):
        c = self.coordinator("monitor_spawned", retry_request="req-1")
        info = c.until("monitor_spawned")["info"]
        self.assertTrue(_wait_for(lambda: len(self.agent_lines()) == 1))
        agent_pid = int(self.agent_lines()[0].split()[-1])
        prov = self.restart()
        r = prov.launch_reconcile(intent=info["intentId"], takeover=True)["reconciled"][0]
        self.assertEqual((r["resolution"], r["takeover"]), ("live", True))
        self.assertEqual((r["runId"], r["taskId"], r["dispatchId"]), ("run-r04", self.task, info["dispatchId"]))
        adopted_pid = self.dispatch(prov, info["dispatchId"])["pid"]
        c.proc.stdin.write("\n")
        c.proc.stdin.flush()
        tail = c.finish()
        self.assertEqual(tail[-1].get("error"), "launch_fenced", tail)
        self.assertNotIn("published", c.seen, "the old writer's publication is refused")
        self.assertTrue(_alive(agent_pid), "a fenced writer terminates nothing the new owner adopted")
        self.assertEqual(self.dispatch(prov, info["dispatchId"])["pid"], adopted_pid)
        self.assertEqual(prov.worker_start(**self.start_kwargs(retry_request="req-1"))["dispatchId"], info["dispatchId"])
        self.assertEqual(self.agent_lines()[0].split()[:2], [info["dispatchId"], "run-r04"])
        self.assertEqual(len(self.agent_lines()), 1)


class TestRequestPayloadBinding(CrashRecoveryBase):
    def test_changed_payload_never_reuses_a_result(self):
        prov = self.restart()
        res = prov.worker_start(**self.start_kwargs(retry_request="req-1"))
        for change in ({"prompt": "something else"}, {"agent": "codex"}, {"profile": "ro"}, {"name": "other-wt"}):
            with self.assertRaises(self.providers.ProviderError) as ctx:
                prov.worker_start(**self.start_kwargs(retry_request="req-1", **change))
            self.assertEqual(ctx.exception.code, "request_mismatch", change)
        self.assertEqual(prov.worker_start(**self.start_kwargs(retry_request="req-1"))["dispatchId"], res["dispatchId"])

    def test_changed_payload_is_refused_for_a_crashed_request_too(self):
        self.crash_at("intent_claimed", retry_request="req-1")
        prov = self.restart()
        with self.assertRaises(self.providers.ProviderError) as ctx:
            prov.worker_start(**self.start_kwargs(retry_request="req-1", prompt="a different assignment"))
        self.assertEqual(ctx.exception.code, "request_mismatch")
        self.assertEqual(prov.request_show("req-1")["state"], "pending", "a mismatched retry settles nothing")

    def test_launch_reconcile_is_refused_where_there_is_no_intent_store(self):
        base = importlib.import_module("runtime.providers.base")
        with self.assertRaises(self.providers.ProviderError) as ctx:
            base.RuntimeProvider().dispatch(["orchestration", "launch-reconcile", "--takeover"])
        self.assertEqual(ctx.exception.code, "unsupported_operation")
        with self.assertRaises(self.providers.ProviderError) as ctx:
            self.restart().dispatch(["orchestration", "launch-reconcile", "--request", "nope"])
        self.assertEqual(ctx.exception.code, "request_not_found")

    def test_store_binds_payload_for_other_methods_that_pass_one(self):
        store = self.restart().state
        store.save_request("req-x", "task-create", "completed", {"ok": 1})
        self.assertEqual(store.get_or_record_request("req-x", "task-create", payload_sha256="aa"), {"ok": 1})
        with store._connect() as conn:
            conn.execute("UPDATE requests SET payload_sha256 = 'aa' WHERE request_id = 'req-x'")
        with self.assertRaises(self.providers.ProviderError) as ctx:
            store.get_or_record_request("req-x", "task-create", payload_sha256="bb")
        self.assertEqual(ctx.exception.code, "request_mismatch")


class TestSandboxCommitsSurviveCrash(CrashRecoveryBase):
    """Docker `danger` with a FAKE `docker` CLI (fixture tier): no daemon is ever contacted."""

    def test_sandbox_commit_is_synced_back_when_coordinator_and_monitor_die(self):
        docker_log = self.base / "docker.log"
        fake = self.bin / "docker"
        fake.write_text(
            f"#!{sys.executable}\n"
            "import os, subprocess, sys, time\n"
            "args = sys.argv[1:]\n"
            f"open({str(docker_log)!r}, 'a').write(' '.join(args) + '\\n')\n"
            "if args[:1] == ['run']:\n"
            "    mount = ':/open-fleet/sandbox.git'\n"
            "    sb = next(a[: -len(mount)] for a in args if a.endswith(mount))\n"
            "    wt = args[args.index('-w') + 1]\n"
            "    env = {**os.environ, 'GIT_DIR': sb, 'GIT_WORK_TREE': wt}\n"
            "    subprocess.run(['git', '-c', 'user.email=w@x', '-c', 'user.name=w', 'commit', '--allow-empty', '-qm',\n"
            "                    'sandboxed-work'], cwd=wt, env=env, check=True)\n"
            f"    open({str(self.agent_log)!r}, 'a').write('sandbox run ' + str(os.getpid()) + '\\n')\n"
            "    time.sleep(60)\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        info = self.crash_at("published", retry_request="req-1", profile="danger", on_env="sandbox-img")
        self.assertTrue(_wait_for(lambda: len(self.agent_lines()) == 1), "the fake sandbox never ran")
        prov = self.restart()
        pid = self.dispatch(prov, info["dispatchId"])["pid"]
        os.killpg(pid, signal.SIGKILL)  # host crash: monitor and container client die unsynced
        self.assertTrue(_wait_for(lambda: not _alive(pid)))
        lane = Path(info["laneDir"])
        sandbox_head = _git("--git-dir", str(lane / "sandbox.git"), "rev-parse", "HEAD", cwd=self.repo).stdout.strip()
        branch = f"refs/heads/fleet/{self.task}"
        self.assertNotEqual(_git("rev-parse", branch, cwd=self.repo).stdout.strip(), sandbox_head, "not synced yet")
        r = prov.launch_reconcile()["reconciled"][0]
        self.assertEqual(r["resolution"], "exited")
        sandbox_refs = [x for x in r["preservedRefs"] if x.get("source") == "sandbox"]
        self.assertEqual(sandbox_refs, [{"ref": f"refs/open-fleet/sandbox/{info['dispatchId']}", "sha": sandbox_head, "source": "sandbox"}])
        self.assertEqual(_git("rev-parse", branch, cwd=self.repo).stdout.strip(), sandbox_head, "the worker's commit reached the host branch")
        self.assertIn({"kind": "container", "target": f"openfleet-{info['dispatchId']}", "action": "removed", "rc": 0}, r["cleanup"])
        self.assertIn(f"rm -f openfleet-{info['dispatchId']}", docker_log.read_text())
        self.assertEqual(r["dispatch"]["after"], "died")


class TestOneSettlerPerIntent(CrashRecoveryBase):
    """One reconciler settles an intent at a time, a takeover included (#597 review).

    The seam is the settling reconciler's own `_settle_intent`: a second reconciler runs from
    inside it, after the first one won the owner swap and before it decided anything.
    """

    def settle_with(self, prov, during):
        settle = prov._settle_intent

        def paused(it, token, previous, *, takeover):
            during()
            return settle(it, token, previous, takeover=takeover)

        prov._settle_intent = paused

    def reconcile(self, prov, intent_id, **kw):
        try:
            return prov.launch_reconcile(intent=intent_id, **kw)["reconciled"][0]
        except self.providers.ProviderError as exc:
            return {"raised": exc.code}

    def test_takeover_keeps_recovery_when_the_old_owner_exits_mid_settlement(self):
        c = self.coordinator("registered", retry_request="req-1")
        info = c.until("registered")["info"]
        seen = {}

        def owner_exits_then_a_poll_reconciles():
            # The live owner goes on, is fenced at its next commit and releases its launch lease.
            c.proc.stdin.write("\n")
            c.proc.stdin.flush()
            seen["owner"] = c.finish()
            other = self.restart()
            seen["reconcile"] = self.reconcile(other, info["intentId"])
            other.worker_list()
            seen["epoch"] = other.state.launch_intent(info["intentId"])["epoch"]
            seen["dispatch"] = other.state.dispatch_state(info["dispatchId"])

        taker = self.restart()
        self.settle_with(taker, owner_exits_then_a_poll_reconciles)
        r = self.reconcile(taker, info["intentId"], takeover=True)
        self.assertEqual(seen["owner"][-1].get("error"), "launch_fenced", seen["owner"])
        self.assertEqual(seen["reconcile"].get("resolution"), "pending", "a second reconciler never settles beside a takeover")
        self.assertEqual((seen["epoch"], seen["dispatch"]), (2, "ready"), "nothing moved while the takeover held recovery")
        self.assertEqual((r.get("resolution"), r.get("takeover")), ("failed", True), r)
        self.assertEqual(r["owner"]["epoch"], 2)
        prov = self.restart()
        self.assertEqual(prov.request_show("req-1")["state"], "failed")
        self.assertEqual(prov.state.dispatch_state(info["dispatchId"]), "abandoned")
        self.assertEqual(self.task_status(prov), "ready")
        self.assertEqual(prov.launch_reconcile()["count"], 0)
        locks = prov.state.db_path.parent / "intents"
        self.assertFalse((locks / f"{info['intentId']}.recovery.lock").exists(), "a settled intent keeps no recovery lock")
        self.assert_no_worker_ran()

    def test_takeover_leaves_the_live_owners_lease_to_it(self):
        c = self.coordinator("registered", retry_request="req-1")
        info = c.until("registered")["info"]
        lease = self.restart().state.db_path.parent / "intents" / f"{info['intentId']}.lock"
        r = self.reconcile(self.restart(), info["intentId"], takeover=True)
        self.assertEqual(r.get("resolution"), "failed", r)
        self.assertTrue(lease.exists(), "a takeover never unlinks a lease it does not hold")
        c.proc.stdin.write("\n")
        c.proc.stdin.flush()
        self.assertEqual(c.finish()[-1].get("error"), "launch_fenced")
        self.assertFalse(lease.exists(), "its holder removes it")

    def test_takeover_never_steals_a_settlement_in_progress(self):
        info = self.crash_at("registered", retry_request="req-1")
        seen = {}

        def takeover_arrives():
            seen["takeover"] = self.reconcile(self.restart(), info["intentId"], takeover=True)
            seen["epoch"] = self.restart().state.launch_intent(info["intentId"])["epoch"]

        settler = self.restart()
        self.settle_with(settler, takeover_arrives)
        r = self.reconcile(settler, info["intentId"])
        self.assertEqual(seen["takeover"].get("resolution"), "pending", "the settling reconciler is live: a takeover waits")
        self.assertEqual(seen["epoch"], 2)
        self.assertEqual((r.get("resolution"), r.get("takeover")), ("failed", False), r)
        self.assertEqual(self.restart().request_show("req-1")["state"], "failed")
        self.assert_no_worker_ran()


class TestRecordedExitIsSettled(CrashRecoveryBase):
    """A monitor that wrote `exit.json` and died before `ensure_terminal_or_died` (#597 review).

    Staged without a real monitor: a pid that has exited claims the launch gate and the lane
    gets the exit record the generated monitor writes, so the death between the two is exact.
    """

    def dead_pid(self):
        proc = subprocess.Popen(["true"])
        proc.wait()
        return proc.pid

    def record_exit(self, lane, *, rc, head, pid):
        lane.mkdir(parents=True, exist_ok=True)
        (lane / "events.jsonl").write_text(json.dumps({"type": "turn_started"}) + "\nagent said goodbye\n", encoding="utf-8")
        (lane / "exit.json").write_text(json.dumps({"rc": rc, "ts": time.time(), "headSha": head, "monitorPid": pid}), encoding="utf-8")

    def died_payloads(self, prov, dispatch_id):
        return [json.loads(m["payload"]) for m in prov.check_messages(terminal="coordinator", run="run-r04")["messages"]
                if m["subject"].startswith(f"worker_died:{dispatch_id}")]

    def test_reconcile_settles_an_exit_the_dead_monitor_recorded(self):
        info = self.crash_at("registered", retry_request="req-1")
        prov = self.restart()
        pid = self.dead_pid()
        self.assertTrue(prov.state.claim_monitor(info["dispatchId"], pid), "the monitor passed the launch gate")
        head = _git("rev-parse", "HEAD", cwd=info["worktree"]).stdout.strip()
        self.record_exit(Path(info["laneDir"]), rc=0, head=head, pid=pid)
        r = prov.launch_reconcile(request="req-1")["reconciled"][0]
        monitor = [p for p in r["processes"] if p["role"] == "monitor"][0]
        self.assertEqual((r["resolution"], monitor["alive"]), ("exited", False))
        self.assertEqual(r["dispatch"], {"id": info["dispatchId"], "before": "ready", "after": "died"},
                         "a recorded exit is settled, never left ready")
        self.assertEqual(monitor["action"], "settled_recorded_exit")
        self.assertEqual(monitor["exit"]["exitCode"], 0)
        died = self.died_payloads(prov, info["dispatchId"])
        self.assertEqual([(d["exitCode"], d["headSha"]) for d in died], [(0, head)], "the recorded exit, not a guess")
        self.assertIn("agent said goodbye", died[0]["lastTail"])
        self.assertEqual(r["task"]["after"], "dispatched", "an exit 0 without terminal mail never completes the task")
        self.assertIs(r["completionInferred"], False)
        self.assertEqual(prov.request_show("req-1")["state"], "completed")
        self.assertEqual([w["state"] for w in prov.worker_list()["workers"]], ["died"])
        self.assertEqual(len(self.died_payloads(prov, info["dispatchId"])), 1, "settling twice never sends twice")

    def test_liveness_sweep_settles_an_exit_the_dead_monitor_recorded(self):
        prov = self.restart()
        rows = {}
        for label, pid in (("dead", self.dead_pid()), ("finishing", os.getpid())):
            disp, lane = f"disp_{label}", self.base / "state" / "lanes" / f"disp_{label}"
            self.record_exit(lane, rc=3, head="abc123", pid=pid)
            with prov.state._connect() as conn:
                conn.execute(
                    "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, pid, backend, "
                    "lane_dir, monitor_pid, created_at, updated_at) VALUES (?, ?, 'run-r04', '', 'claude', ?, 'ready', ?, 'setsid', ?, ?, 0, 0)",
                    (disp, self.task, f"term_{label}", pid, str(lane), pid),
                )
            rows[label] = disp
        states = {w["dispatchId"]: w["state"] for w in prov.worker_list()["workers"]}
        self.assertEqual(states[rows["dead"]], "died", "the sweep settles what the dead monitor recorded")
        self.assertEqual(states[rows["finishing"]], "ready", "a live monitor still settles its own exit")
        self.assertEqual([(d["exitCode"], d["headSha"]) for d in self.died_payloads(prov, rows["dead"])], [(3, "abc123")])
        self.assertEqual(self.died_payloads(prov, rows["finishing"]), [])
        self.assertEqual(prov.worker_show(rows["dead"])["worker"]["state"], "died")
        self.assertEqual(len(self.died_payloads(prov, rows["dead"])), 1)


class TestRecordedRoCompletionIsRelayed(CrashRecoveryBase):
    """#596 review (PRRT_kwDOTWxN9c6vvwnc): a ro monitor wrote `exit.json`, then died BEFORE relaying
    the completion line its worker printed. Recovery must re-read that line from the recorded
    transcript, with the monitor's own final-answer reader, before any death message.

    Staged as TestRecordedExitIsSettled stages its window: a real coordinator is SIGKILLed after
    `registered`, a pid that has exited claims the launch gate as the monitor, and the lane gets
    the transcript and exit record that monitor wrote, so the death falls exactly between the two.
    """

    def dead_pid(self):
        proc = subprocess.Popen(["true"])
        proc.wait()
        return proc.pid

    def transcript(self, disp, outcome, pid):
        """What a ro claude prints: a rehearsed line in its reasoning, the real one ending its answer."""
        rehearsed = "succeeded" if outcome == "failed" else "failed"
        events = [
            {"type": "turn_started", "dispatchId": disp, "monitorPid": pid},
            {"type": "assistant", "message": {"role": "assistant", "content": [
                {"type": "thinking", "thinking": f"OPEN_FLEET_WORKER_DONE {disp} {rehearsed}"}]}},
            {"type": "result", "subtype": "success", "result": f"REPORT: done.\nOPEN_FLEET_WORKER_DONE {disp} {outcome}"},
        ]
        return "\n".join(json.dumps(e) for e in events) + "\n"

    def stage(self, outcome, *, rc=0, profile="ro"):
        info = self.crash_at("registered", retry_request="req-1", profile=profile)
        prov = self.restart()
        pid = self.dead_pid()
        self.assertTrue(prov.state.claim_monitor(info["dispatchId"], pid), "the monitor passed the launch gate")
        head = _git("rev-parse", "HEAD", cwd=info["worktree"]).stdout.strip()
        lane = Path(info["laneDir"])
        lane.mkdir(parents=True, exist_ok=True)
        (lane / "events.jsonl").write_text(self.transcript(info["dispatchId"], outcome, pid), encoding="utf-8")
        (lane / "exit.json").write_text(json.dumps({"rc": rc, "ts": time.time(), "headSha": head, "monitorPid": pid}),
                                        encoding="utf-8")
        return info, prov, head

    def mail(self, prov, disp):
        return [m for m in prov.check_messages(terminal="coordinator", run="run-r04")["messages"] if disp in m["subject"]]

    def reconcile(self, prov):
        return prov.launch_reconcile(request="req-1")["reconciled"][0]

    def test_recovery_relays_the_failure_the_worker_reported(self):
        info, prov, head = self.stage("failed")
        r = self.reconcile(prov)
        self.assertEqual(r["dispatch"]["after"], "completed", "the worker reported; it did not die")
        mail = self.mail(prov, info["dispatchId"])
        self.assertEqual([(m["type"], m["outcome"]) for m in mail], [("worker_done", "failed")],
                         "the worker's own `failed`, never a worker_died (exit=0) that drops it")
        self.assertEqual(json.loads(mail[0]["payload"])["headSha"], head)

    def test_recovery_relays_the_success_the_worker_reported(self):
        info, prov, _ = self.stage("succeeded")
        self.assertEqual(self.reconcile(prov)["dispatch"]["after"], "completed")
        self.assertEqual([(m["type"], m["outcome"]) for m in self.mail(prov, info["dispatchId"])],
                         [("worker_done", "succeeded")])

    def test_the_liveness_sweep_relays_it_too(self):
        info, prov, _ = self.stage("failed")
        self.assertEqual({w["dispatchId"]: w["state"] for w in prov.worker_list()["workers"]}[info["dispatchId"]],
                         "completed")
        self.assertEqual([(m["type"], m["outcome"]) for m in self.mail(prov, info["dispatchId"])],
                         [("worker_done", "failed")])

    def test_a_monitor_that_did_relay_is_never_doubled(self):
        # It relayed, then died before settling: recovery settles on that mail and adds none.
        info, prov, head = self.stage("failed")
        relayed = self.posix.relay_ro_completion(
            prov.state, dispatch_id=info["dispatchId"], worker_handle=info["terminalHandle"], agent="claude",
            run_id="run-r04", log_path=Path(info["laneDir"]) / "events.jsonl", head_sha=head)
        self.assertTrue(relayed["relayed"])
        self.assertEqual(self.reconcile(prov)["dispatch"]["after"], "completed")
        self.reconcile(prov)
        self.assertEqual([(m["type"], m["outcome"]) for m in self.mail(prov, info["dispatchId"])],
                         [("worker_done", "failed")], "exactly one report, whoever relayed it")

    def test_a_crash_or_an_rw_worker_still_dies(self):
        # The monitor relays only a ro worker's CLEAN exit; recovery reads no more than it would.
        for profile, rc in (("ro", 3), ("rw", 0)):
            with self.subTest(profile=profile, rc=rc):
                info, prov, _ = self.stage("succeeded", rc=rc, profile=profile)
                try:
                    self.assertEqual(self.reconcile(prov)["dispatch"]["after"], "died")
                    mail = self.mail(prov, info["dispatchId"])
                    self.assertEqual([m["type"] for m in mail], ["escalation"])
                    self.assertEqual(json.loads(mail[0]["payload"])["exitCode"], rc)
                finally:
                    self.tearDown_task(prov)

    def tearDown_task(self, prov):
        """Hand the task back so the next subtest's coordinator can claim it again."""
        with prov.state._connect() as conn:
            conn.execute("UPDATE tasks SET status = 'ready' WHERE id = ?", (self.task,))
            conn.execute("DELETE FROM requests WHERE request_id = 'req-1'")


class TestSandboxSalvageIsRetried(CrashRecoveryBase):
    """A vanished `danger` monitor's cleanup that fails keeps recovery open (#597 review).

    Fixture tier: a FAKE `docker` CLI whose `rm` fails while `docker-down` exists, and a seam on
    `sync_sandbox_git` for the sync failures. No daemon is ever contacted.
    """

    def setUp(self):
        super().setUp()
        self.docker_log = self.base / "docker.log"
        self.docker_down = self.base / "docker-down"
        fake = self.bin / "docker"
        fake.write_text(
            f"#!{sys.executable}\n"
            "import os, subprocess, sys, time\n"
            "args = sys.argv[1:]\n"
            f"open({str(self.docker_log)!r}, 'a').write(' '.join(args) + '\\n')\n"
            f"if args[:1] == ['rm'] and os.path.exists({str(self.docker_down)!r}):\n"
            "    sys.stderr.write('Cannot connect to the Docker daemon. Is the docker daemon running?\\n')\n"
            "    sys.exit(1)\n"
            "if args[:1] == ['run']:\n"
            "    mount = ':/open-fleet/sandbox.git'\n"
            "    sb = next(a[: -len(mount)] for a in args if a.endswith(mount))\n"
            "    wt = args[args.index('-w') + 1]\n"
            "    env = {**os.environ, 'GIT_DIR': sb, 'GIT_WORK_TREE': wt}\n"
            "    subprocess.run(['git', '-c', 'user.email=w@x', '-c', 'user.name=w', 'commit', '--allow-empty', '-qm',\n"
            "                    'sandboxed-work'], cwd=wt, env=env, check=True)\n"
            f"    open({str(self.agent_log)!r}, 'a').write('sandbox run ' + str(os.getpid()) + '\\n')\n"
            "    time.sleep(60)\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)

    def vanished_sandbox(self):
        """A host crash after publication: coordinator, monitor and container client die unsynced."""
        info = self.crash_at("published", retry_request="req-1", profile="danger", on_env="sandbox-img")
        self.assertTrue(_wait_for(lambda: len(self.agent_lines()) == 1), "the fake sandbox never ran")
        prov = self.restart()
        pid = self.dispatch(prov, info["dispatchId"])["pid"]
        os.killpg(pid, signal.SIGKILL)
        self.assertTrue(_wait_for(lambda: not _alive(pid)))
        lane = Path(info["laneDir"])
        info["sandboxHead"] = _git("--git-dir", str(lane / "sandbox.git"), "rev-parse", "HEAD", cwd=self.repo).stdout.strip()
        info["branch"] = f"refs/heads/fleet/{self.task}"
        info["baseHead"] = _git("rev-parse", info["branch"], cwd=self.repo).stdout.strip()
        self.assertNotEqual(info["baseHead"], info["sandboxHead"], "not synced yet")
        return prov, info

    def died_payloads(self, prov, dispatch_id):
        return [json.loads(m["payload"]) for m in prov.check_messages(terminal="coordinator", run="run-r04")["messages"]
                if m["subject"].startswith(f"worker_died:{dispatch_id}")]

    def sandbox_ref(self, dispatch_id):
        return _git("rev-parse", "--verify", "--quiet", f"refs/open-fleet/sandbox/{dispatch_id}", cwd=self.repo, check=False).stdout.strip()

    def assert_still_open(self, prov, info, r):
        disp = info["dispatchId"]
        self.assertEqual((r["resolution"], r["requestState"]), ("cleanup_pending", "pending"), r)
        self.assertEqual(r["dispatch"]["after"], "ready", "never declared dead before its cleanup succeeded")
        self.assertEqual(self.died_payloads(prov, disp), [], "no worker_died invites a retry beside a live container")
        self.assertIsNone(prov.state.launch_intent(info["intentId"])["outcome"], "recovery stays open")
        self.assertEqual(prov.request_show("req-1")["state"], "pending")
        self.assertEqual(self.task_status(prov), "dispatched")

    def assert_settled(self, prov, info):
        disp = info["dispatchId"]
        self.assertEqual(prov.state.dispatch_state(disp), "died")
        self.assertEqual([d["headSha"] for d in self.died_payloads(prov, disp)], [info["sandboxHead"]], "worker_died carries the synced head")
        self.assertEqual(_git("rev-parse", info["branch"], cwd=self.repo).stdout.strip(), info["sandboxHead"], "the commit reached the host branch")
        self.assertEqual(prov.state.launch_intent(info["intentId"])["outcome"], "completed")
        self.assertEqual(prov.request_show("req-1")["state"], "completed")
        receipt = json.loads((Path(info["laneDir"]) / "recovery.json").read_text())
        self.assertEqual(receipt["resolution"], "exited")
        self.assertIn({"kind": "container", "target": f"openfleet-{disp}", "action": "removed", "rc": 0}, receipt["cleanup"])
        self.assertEqual(prov.launch_reconcile()["count"], 0)

    def test_failed_container_removal_is_never_reported_removed_and_is_retried(self):
        prov, info = self.vanished_sandbox()
        disp = info["dispatchId"]
        self.docker_down.touch()
        r = prov.launch_reconcile()["reconciled"][0]
        self.assert_still_open(prov, info, r)
        container = [c for c in r["cleanup"] if c["kind"] == "container"]
        self.assertEqual([(c["action"], c["rc"]) for c in container], [("removal_failed", 1)], "a failed removal is never `removed`")
        self.assertIn("Cannot connect to the Docker daemon", container[0]["error"])
        sync = [c for c in r["cleanup"] if c["kind"] == "sandbox_sync"]
        self.assertEqual([c["action"] for c in sync], ["deferred"], "no sync while the container may still write")
        self.assertEqual(self.sandbox_ref(disp), "")
        self.assertEqual(_git("rev-parse", info["branch"], cwd=self.repo).stdout.strip(), info["baseHead"])
        # The automatic paths retry it too, and refuse the same way while Docker is down.
        self.assertEqual({w["dispatchId"]: w["state"] for w in prov.worker_list()["workers"]}, {disp: "ready"})
        self.assertEqual(self.died_payloads(prov, disp), [])
        self.docker_down.unlink()  # Docker is back: the next poll removes, syncs and settles
        self.assertEqual({w["dispatchId"]: w["state"] for w in prov.worker_list()["workers"]}, {disp: "died"})
        self.assert_settled(prov, info)
        self.assertGreaterEqual(self.docker_log.read_text().count(f"rm -f openfleet-{disp}"), 3)

    def test_failed_sandbox_sync_keeps_recovery_open_and_is_retried(self):
        prov, info = self.vanished_sandbox()
        err = self.providers.ProviderError("sandbox_git_failed", "fetch sandbox commits: unable to lock packed-refs")
        with mock.patch.object(self.posix, "sync_sandbox_git", side_effect=err):
            r = prov.launch_reconcile()["reconciled"][0]
            replay = prov.worker_start(**self.start_kwargs(retry_request="req-1", profile="danger", on_env="sandbox-img"))
        self.assert_still_open(prov, info, r)
        self.assertEqual((replay["state"], replay["stage"], replay["dispatchId"]), ("outcome_unknown", "launch_recovery", info["dispatchId"]))
        self.assertEqual(replay["recovery"]["resolution"], "cleanup_pending", "a retried request retries the salvage")
        self.assertEqual(len(self.agent_lines()), 1, "and never starts a second worker")
        self.assertIn({"kind": "container", "target": f"openfleet-{info['dispatchId']}", "action": "removed", "rc": 0}, r["cleanup"])
        sync = [c for c in r["cleanup"] if c["kind"] == "sandbox_sync"]
        self.assertEqual([(c["action"], c["error"]) for c in sync], [("failed", str(err))])
        self.assertEqual(self.sandbox_ref(info["dispatchId"]), "", "the commits are still only in the sandbox")
        self.assertEqual(prov.worker_show(info["dispatchId"])["worker"]["state"], "died", "worker-show retries and settles")
        self.assert_settled(prov, info)

    def test_tampered_sandbox_is_refused_once_and_never_retried(self):
        prov, info = self.vanished_sandbox()
        err = self.providers.ProviderError("sandbox_git_tampered", "sandbox git dir contains a symlink (hooks); refusing to sync")
        with mock.patch.object(self.posix, "sync_sandbox_git", side_effect=err):
            r = prov.launch_reconcile()["reconciled"][0]
        self.assertEqual((r["resolution"], r["dispatch"]["after"]), ("exited", "died"), "a refusal is final: retrying cannot pass")
        sync = [c for c in r["cleanup"] if c["kind"] == "sandbox_sync"]
        self.assertEqual([(c["action"], c["error"]) for c in sync], [("refused", str(err))])
        self.assertEqual(len(self.died_payloads(prov, info["dispatchId"])), 1)
        self.assertEqual(prov.launch_reconcile()["count"], 0)
        self.assertTrue((Path(info["laneDir"]) / "sandbox.git").is_dir(), "the refused sandbox stays in the lane")

    def test_abandoned_after_its_monitor_vanished_is_settled_without_waiting_the_sync_grace(self):
        self.env["OPEN_FLEET_SANDBOX_SYNC_GRACE_S"] = "120"
        prov, info = self.vanished_sandbox()
        disp = info["dispatchId"]
        self.docker_down.touch()
        self.assertEqual(prov.launch_reconcile()["reconciled"][0]["resolution"], "cleanup_pending")
        prov.worker_fence("abandon", disp)  # the give-up step a cleanup_pending receipt names
        clock = FakeClock()
        with mock.patch.object(self.posix, "time", clock):
            held = prov.launch_reconcile()["reconciled"][0]
        self.assertLess(clock.slept, 1.0, "a dead monitor never writes exit.json: recovery never waits the sync grace for it")
        monitor = [p for p in held["processes"] if p["role"] == "monitor"][0]
        self.assertEqual((monitor["alive"], monitor["action"]), (False, "reported_dead"))
        self.assertEqual((held["resolution"], held["dispatch"]["after"], held["task"]["after"]), ("cleanup_pending", "abandoned", "dispatched"),
                         "its container is not confirmed gone: the task is not handed back yet")
        self.assertEqual([c["action"] for c in held["cleanup"] if c["kind"] == "container"], ["removal_failed"])
        self.docker_down.unlink()
        real_sync, synced_after = self.posix.sync_sandbox_git, []

        def sync_after_removal(meta, dispatch_id):
            synced_after.append(self.docker_log.read_text().count(f"rm -f openfleet-{disp}"))
            return real_sync(meta, dispatch_id)

        removals = self.docker_log.read_text().count(f"rm -f openfleet-{disp}")
        with mock.patch.object(self.posix, "time", clock), mock.patch.object(self.posix, "sync_sandbox_git", side_effect=sync_after_removal):
            r = prov.launch_reconcile()["reconciled"][0]
        self.assertLess(clock.slept, 1.0)
        self.assertEqual(synced_after, [removals + 1], "the container is removed, then the sandbox synced")
        self.assertEqual((r["resolution"], r["error"]["code"]), ("failed", "dispatch_fenced"))
        self.assertEqual((r["dispatch"]["after"], r["task"]["after"]), ("abandoned", "ready"), "the operator's fence stands")
        self.assertIn({"kind": "container", "target": f"openfleet-{disp}", "action": "removed", "rc": 0}, r["cleanup"])
        self.assertEqual(self.sandbox_ref(disp), info["sandboxHead"], "giving up never loses the worker's commits")
        self.assertEqual(self.died_payloads(prov, disp), [], "a fenced dispatch's exit is expected: no worker_died")
        self.assertEqual(prov.request_show("req-1")["state"], "failed")

    def test_fenced_live_monitor_still_gets_the_whole_sync_grace(self):
        self.env["OPEN_FLEET_SANDBOX_SYNC_GRACE_S"] = "120"
        info = self.crash_at("published", retry_request="req-1", profile="danger", on_env="sandbox-img")
        self.assertTrue(_wait_for(lambda: len(self.agent_lines()) == 1), "the fake sandbox never ran")
        prov = self.restart()
        disp = info["dispatchId"]
        pid = self.dispatch(prov, disp)["pid"]
        with prov.state._connect() as conn:  # a stop recorded whose caller died before its teardown
            conn.execute("UPDATE dispatches SET state = 'stopped', terminal_state = 'stopped' WHERE dispatch_id = ?", (disp,))
        clock = FakeClock()
        with mock.patch.object(self.posix, "time", clock):
            r = prov.launch_reconcile()["reconciled"][0]
        monitor = [p for p in r["processes"] if p["role"] == "monitor"][0]
        self.assertEqual((monitor["alive"], monitor["action"]), (True, "terminated"))
        self.assertGreaterEqual(clock.slept, 120, "a live monitor may still be syncing: it gets the whole grace")
        self.assertEqual(monitor["termination"]["sandboxSync"], {"error": "monitor did not report a finished sync"})
        self.assertTrue(_wait_for(lambda: not _alive(pid)), "and is stopped after it")
        self.assertEqual((r["resolution"], r["error"]["code"], r["task"]["after"]), ("failed", "dispatch_fenced", "ready"))


# The `dispatches` table as the first local-state schema created it, before any additive migration.
OLD_DISPATCHES_SCHEMA = """
CREATE TABLE dispatches (
    dispatch_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL DEFAULT 'default',
    worktree TEXT NOT NULL,
    agent TEXT NOT NULL,
    profile TEXT NOT NULL DEFAULT 'rw',
    terminal_handle TEXT NOT NULL,
    state TEXT NOT NULL,
    terminal_state TEXT NOT NULL DEFAULT 'active',
    pid INTEGER,
    backend TEXT DEFAULT 'setsid',
    launch_effective TEXT,
    lane_dir TEXT,
    session_id TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
"""


class TestFenceClosesTheGate(CrashRecoveryBase):
    """A stop, abandon or release before any monitor claimed closes the launch gate for good (#597).

    `retain` still rewrites the state (inspection keeps working) but can never reopen the gate,
    so a late monitor from a dead coordinator's launcher never runs under a fenced dispatch.
    """

    def died_payloads(self, prov, dispatch_id):
        return [json.loads(m["payload"]) for m in prov.check_messages(terminal="coordinator", run="run-r04")["messages"]
                if m["subject"].startswith(f"worker_died:{dispatch_id}")]

    def insert_dispatch(self, prov, dispatch_id, *, state="ready"):
        lane = self.base / "state" / "lanes" / dispatch_id
        lane.mkdir(parents=True, exist_ok=True)
        with prov.state._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, pid, backend, "
                "lane_dir, created_at, updated_at) VALUES (?, ?, 'run-r04', '', 'claude', ?, ?, 0, 'setsid', ?, 0, 0)",
                (dispatch_id, self.task, f"term_{dispatch_id}", state, str(lane)),
            )

    def test_abandon_then_retain_never_lets_a_late_monitor_start(self):
        # A launcher that outlived its SIGKILLed coordinator starts the monitor 3 s late.
        wrapper = self.base / "slow-python"
        wrapper.write_text(f'#!/bin/sh\ncase "$2" in -c) ;; *) sleep 3 ;; esac\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
        wrapper.chmod(0o755)
        info = self.crash_at("monitor_spawned", env={**self.env, "PYTHON": str(wrapper)})
        prov = self.restart()
        disp = info["dispatchId"]
        events = Path(info["laneDir"]) / "events.jsonl"
        prov.worker_fence("abandon", disp)
        self.assertIsNone(self.dispatch(prov, disp)["monitor_started_at"], "fenced before any monitor claimed the gate")
        self.assertEqual(prov.worker_fence("retain", disp)["state"], "retained", "retain still changes the state, for inspection")
        self.assertTrue(_wait_for(lambda: any(k in events.read_text() for k in ('"launch_refused"', '"turn_started"')), timeout=30),
                        "the late monitor never reached the gate")
        refused = [json.loads(line) for line in events.read_text().splitlines() if '"launch_refused"' in line]
        self.assertEqual(len(refused), 1, "a retained dispatch fenced before any claim still refuses a late monitor")
        self.assertIn("launch gate closed", refused[0]["reason"])
        self.assert_no_worker_ran(settle=0.5)
        row = self.dispatch(prov, disp)
        self.assertEqual((row["state"], row["monitor_started_at"], int(row["monitor_pid"] or 0)), ("retained", None, 0))
        self.assertIsNotNone(row["gate_closed_at"])
        states = {w["dispatchId"]: w["state"] for w in prov.worker_list()["workers"]}
        self.assertNotEqual(states[disp], "died", "nothing ran under it, so nothing is declared dead")
        self.assertEqual(self.died_payloads(prov, disp), [], "and no worker_died is sent for it")

    def test_a_fence_before_any_claim_closes_the_gate_and_retain_cannot_reopen_it(self):
        prov = self.restart()
        store = prov.state
        for verb in ("stop", "abandon", "release"):
            disp = f"disp_{verb}"
            self.insert_dispatch(prov, disp)
            prov.worker_fence(verb, disp)
            self.assertIsNotNone(self.dispatch(prov, disp)["gate_closed_at"], verb)
            prov.worker_fence("retain", disp)
            self.assertFalse(store.claim_monitor(disp, os.getpid()), f"{verb} then retain: the gate stays closed")
            self.assertIn("launch gate closed", store.gate_refusal(disp))
            self.assertEqual(store.dispatch_state(disp), "retained")
        self.insert_dispatch(prov, "disp_kept")
        prov.worker_fence("retain", "disp_kept")
        self.assertIsNone(self.dispatch(prov, "disp_kept")["gate_closed_at"], "retain alone never closes the gate")
        self.insert_dispatch(prov, "disp_unlaunched")
        self.assertTrue(store.abandon_unlaunched("disp_unlaunched"))
        self.assertIsNotNone(self.dispatch(prov, "disp_unlaunched")["gate_closed_at"], "recovery's abandon closes it too")
        prov.worker_fence("retain", "disp_unlaunched")
        self.assertFalse(store.claim_monitor("disp_unlaunched", os.getpid()))

    def test_a_fence_after_a_claim_leaves_the_gate_to_the_monitor_that_ran(self):
        prov = self.restart()
        self.insert_dispatch(prov, "disp_ran")
        monitor = subprocess.Popen(["sleep", "30"], start_new_session=True)
        self.addCleanup(monitor.wait)
        self.addCleanup(monitor.kill)
        self.assertTrue(prov.state.claim_monitor("disp_ran", monitor.pid))
        self.assertIn("held by monitor", prov.state.gate_refusal("disp_ran"))
        prov.worker_fence("stop", "disp_ran")
        row = self.dispatch(prov, "disp_ran")
        self.assertIsNone(row["gate_closed_at"], "a monitor already ran: the gate is closed only before any claim")
        self.assertIsNotNone(row["monitor_started_at"])
        self.assertTrue(_wait_for(lambda: monitor.poll() is not None), "the stop reached the monitor that ran")

    def test_an_older_store_gains_the_gate_column(self):
        import sqlite3

        db = self.base / "old-state" / "runtime.db"
        db.parent.mkdir()
        with sqlite3.connect(db) as conn:
            conn.executescript(OLD_DISPATCHES_SCHEMA)
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, worktree, agent, terminal_handle, state, pid, created_at, updated_at) "
                "VALUES ('disp_old', 't', '/w', 'claude', 'term_old', 'abandoned', 0, 0, 0)"
            )
        local_state = importlib.import_module("runtime.providers.local_state")
        for _ in range(2):  # opening it again is a no-op
            store = local_state.LocalStateStore(db_path=db)
        with sqlite3.connect(db) as conn:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(dispatches)").fetchall()}
        self.assertIn("gate_closed_at", cols)
        self.assertEqual(store.dispatch_state("disp_old"), "abandoned", "existing rows survive the migration")
        self.assertIsNone(store.launch_intent("li_none"))
        self.assertFalse(store.claim_monitor("disp_old", os.getpid()), "a fenced row still refuses the gate")


class TestClosedGateSkipsTheSyncGrace(CrashRecoveryBase):
    """A gate closed before any claim proves no monitor ran or can run, so no exit.json can come (#597).

    Fake clock: a grace is measured, never waited. Fixture tier: a FAKE `docker` CLI whose `run`
    sleeps like a live container client; no daemon is ever contacted.
    """

    def setUp(self):
        super().setUp()
        self.env["OPEN_FLEET_SANDBOX_SYNC_GRACE_S"] = "120"
        self.docker_log = self.base / "docker.log"
        fake = self.bin / "docker"
        fake.write_text(
            f'#!/bin/sh\necho "$*" >> "{self.docker_log}"\n'
            f'if [ "$1" = run ]; then echo "sandbox run $$" >> "{self.agent_log}"; exec sleep 60; fi\nexit 0\n',
            encoding="utf-8",
        )
        fake.chmod(0o755)

    def unlaunched_danger(self, **start):
        """A coordinator killed after registering a `danger` dispatch and before any monitor spawn."""
        return self.crash_at("registered", profile="danger", on_env="sandbox-img", **start)

    def died_payloads(self, prov, dispatch_id):
        return [json.loads(m["payload"]) for m in prov.check_messages(terminal="coordinator", run="run-r04")["messages"]
                if m["subject"].startswith(f"worker_died:{dispatch_id}")]

    def test_stop_and_abandon_of_a_never_launched_dispatch_do_not_wait_the_grace(self):
        tasks = {"stop": self.task, "abandon": self.restart().task_create(spec="inert work 2", run="run-r04")["task"]["id"]}
        for verb, task in tasks.items():
            info = self.unlaunched_danger(task_id=task)
            prov = self.restart()
            self.assertEqual(self.dispatch(prov, info["dispatchId"])["pid"], 0)
            clock = FakeClock()
            with mock.patch.object(self.posix, "time", clock):
                out = prov.worker_fence(verb, info["dispatchId"])
            self.assertLess(clock.slept, 1.0, f"{verb}: the gate closed before any claim, so no sync can ever be reported")
            self.assertEqual(out["termination"].get("gate"), "closed", out)
            self.assertEqual(out["termination"]["container"]["name"], f"openfleet-{info['dispatchId']}", "removed all the same")
        self.assert_no_worker_ran()

    def test_setsid_recovery_of_a_fenced_never_launched_dispatch_does_not_wait_the_grace(self):
        info = self.unlaunched_danger(retry_request="req-1")
        prov = self.restart()
        clock = FakeClock()
        with mock.patch.object(self.posix, "time", clock):
            prov.worker_fence("abandon", info["dispatchId"])
            fenced = clock.slept
            r = prov.launch_reconcile()["reconciled"][0]
        self.assertLess(clock.slept - fenced, 1.0, "recovery: the closed gate is as good as a confirmed death")
        monitor = [p for p in r["processes"] if p["role"] == "monitor"][0]
        self.assertEqual((monitor["alive"], monitor["action"], monitor["gate"]), (None, "refused_at_gate", "closed"))
        self.assertEqual((r["resolution"], r["error"]["code"]), ("failed", "dispatch_fenced"))
        self.assertEqual((r["dispatch"]["after"], r["task"]["after"]), ("abandoned", "ready"))
        self.assertIn({"kind": "container", "target": f"openfleet-{info['dispatchId']}", "action": "removed", "rc": 0}, r["cleanup"])
        self.assertEqual(self.died_payloads(prov, info["dispatchId"]), [])
        self.assertEqual(prov.request_show("req-1")["state"], "failed")
        self.assert_no_worker_ran()

    def test_a_retain_after_the_gate_closed_never_turns_into_a_false_worker_died(self):
        info = self.unlaunched_danger()
        prov = self.restart()
        disp = info["dispatchId"]
        with mock.patch.object(self.posix, "time", FakeClock()):
            prov.worker_fence("abandon", disp)
        prov.worker_fence("retain", disp)  # inspection, after the gate closed
        died = prov.state.ensure_terminal_or_died(dispatch_id=disp, worker_handle=info["terminalHandle"], exit_code=-1, run_id="run-r04")
        self.assertIs(died["syntheticDied"], False, died)
        self.assertEqual(prov.state.dispatch_state(disp), "retained", "nothing ran under it, so nothing died")
        self.assertEqual(self.died_payloads(prov, disp), [])

    def test_a_retain_landing_mid_recovery_never_declares_a_never_launched_dispatch_dead(self):
        info = self.unlaunched_danger()
        prov = self.restart()
        disp = info["dispatchId"]
        clock = FakeClock()
        with mock.patch.object(self.posix, "time", clock):
            prov.worker_fence("abandon", disp)
        fenced, vanish, retained = clock.slept, prov._report_vanished, []

        def retain_lands_first(r):
            retained.append(prov.worker_fence("retain", disp)["state"])
            return vanish(r)

        prov._report_vanished = retain_lands_first
        with mock.patch.object(self.posix, "time", clock):
            r = prov.launch_reconcile()["reconciled"][0]
        self.assertLess(clock.slept - fenced, 1.0)
        self.assertEqual(retained, ["retained"], "the retain landed between the reconciler's read and its settlement")
        self.assertEqual(r["dispatch"]["after"], "retained", "the operator's retain stands, never turned into a death")
        self.assertEqual(self.died_payloads(prov, disp), [])
        self.assert_no_worker_ran()

    def test_a_fence_that_never_closed_the_gate_still_waits_the_whole_grace(self):
        # A fence recorded before the gate could be closed (an older store or provider): nothing
        # proves no monitor started, so the monitor that cannot be probed keeps the whole grace.
        info = self.unlaunched_danger()
        prov = self.restart()
        with prov.state._connect() as conn:
            conn.execute("UPDATE dispatches SET state = 'abandoned', terminal_state = 'abandoned' WHERE dispatch_id = ?", (info["dispatchId"],))
        clock = FakeClock()
        with mock.patch.object(self.posix, "time", clock):
            r = prov.launch_reconcile()["reconciled"][0]
        monitor = [p for p in r["processes"] if p["role"] == "monitor"][0]
        self.assertEqual((monitor["alive"], monitor["action"]), (None, "terminated"))
        self.assertNotIn("gate", monitor)
        self.assertGreaterEqual(clock.slept, 120, "an unproven gate keeps the whole grace")

    def test_stop_of_a_monitor_that_claimed_still_waits_the_whole_grace(self):
        info = self.crash_at("published", profile="danger", on_env="sandbox-img")
        self.assertTrue(_wait_for(lambda: len(self.agent_lines()) == 1), "the fake container client never ran")
        prov = self.restart()
        pid = self.dispatch(prov, info["dispatchId"])["pid"]
        clock = FakeClock()
        with mock.patch.object(self.posix, "time", clock):
            out = prov.worker_fence("stop", info["dispatchId"])
        self.assertNotIn("gate", out["termination"])
        self.assertGreaterEqual(clock.slept, 120, "a monitor that passed the gate may still be syncing: the whole grace")
        self.assertTrue(_wait_for(lambda: not _alive(pid)), "and is stopped after it")

    def test_the_gate_proves_nothing_for_work_started_without_it(self):
        prov = self.restart()
        with prov.state._connect() as conn:  # injected work: a dispatch with no launch intent
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, pid, backend, "
                "created_at, updated_at) VALUES ('disp_inj', ?, 'run-r04', '', 'custom', 'term_inj', 'ready', 0, 'setsid', 0, 0)",
                (self.task,),
            )
        self.assertNotIn("gate", prov.worker_fence("stop", "disp_inj")["termination"])
        prov.worker_fence("retain", "disp_inj")
        died = prov.state.ensure_terminal_or_died(dispatch_id="disp_inj", worker_handle="term_inj", exit_code=-1, run_id="run-r04")
        self.assertIs(died["syntheticDied"], True, "its work never needed the gate, so the gate cannot vouch it never ran")
        info = self.unlaunched_danger()
        with mock.patch.object(self.posix, "time", FakeClock()):
            prov.worker_fence("abandon", info["dispatchId"])
        row = self.dispatch(prov, info["dispatchId"])
        self.assertTrue(prov._gate_proves_never_ran(row))
        runner = self.posix.PosixWorktreeProvider(env=self.env, runner=lambda **kw: {"pid": 0})
        self.assertFalse(runner._gate_proves_never_ran(row), "an injected runner starts work without the gate")


class TestFallbackWorktreeNameIsRecorded(CrashRecoveryBase):
    """A worker name that sanitizes to nothing gets its fallback worktree name BEFORE the intent (#597 review)."""

    def test_crash_after_a_fallback_named_worktree_is_created_keeps_and_pins_it(self):
        info = self.crash_at("worktree_created", retry_request="req-1", name="---")
        wt = Path(info["worktree"])
        self.assertTrue((wt / ".git").is_file(), "the fallback-named worktree exists when the coordinator dies")
        self.assertRegex(wt.name, r"^wt-[0-9a-f]{6}$")
        prov = self.restart()
        self.assertEqual(prov.state.launch_intent(info["intentId"])["worktree"], str(wt),
                         "the intent named this worktree before it was created")
        self.assertEqual(_git("rev-parse", "--verify", "--quiet", f"refs/heads/fleet/{wt.name}", cwd=self.repo).returncode, 0,
                         "and its branch follows from that recorded name")
        r = prov.launch_reconcile(request="req-1")["reconciled"][0]
        self.assertEqual((r["resolution"], r["worktree"]), ("failed", str(wt)))
        self.assertIn({"kind": "worktree", "target": str(wt), "action": "kept", "why": "recovery never deletes a worktree or a branch"},
                      r["cleanup"])
        head = _git("rev-parse", "HEAD", cwd=wt).stdout.strip()
        self.assertEqual(r["preservedRefs"][0], {"ref": f"refs/open-fleet/preserved/{info['dispatchId']}", "sha": head,
                                                 "source": "worktree", "worktree": str(wt)})
        self.assertEqual(_git("rev-parse", f"refs/open-fleet/preserved/{info['dispatchId']}", cwd=self.repo).stdout.strip(), head)
        self.assert_no_worker_ran()

    def test_an_uninterrupted_launch_creates_exactly_the_worktree_its_intent_named(self):
        c = self.coordinator(None, retry_request="req-1", name="!!!")
        out = c.finish()
        res = out[-1]["result"]
        prov = self.restart()
        recorded = prov.state.launch_intent(c.info["intentId"])["worktree"]
        claimed = [m["info"]["worktree"] for m in out if m.get("boundary") == "intent_claimed"]
        self.assertEqual(claimed, [recorded], "named at the claim, before any side effect")
        self.assertEqual(res["worker"]["worktree"], recorded)
        self.assertRegex(Path(recorded).name, r"^wt-[0-9a-f]{6}$")
        self.assertEqual(sorted(p.name for p in (self.base / "state" / "worktrees").iterdir()), [Path(recorded).name],
                         "one worktree, the one the intent named: no second fallback name was drawn")

    def test_a_worktree_other_than_the_recorded_one_fails_the_attempt(self):
        prov = self.restart()
        create = prov.worktree_create
        prov.worktree_create = lambda name, **kw: create(f"{name}-elsewhere", **kw)  # a creator that drifts
        with self.assertRaises(self.providers.ProviderError) as ctx:
            prov.worker_start(**self.start_kwargs(retry_request="req-1", name="---"))
        self.assertEqual(ctx.exception.code, "worktree_create_failed")
        self.assertEqual(prov.request_show("req-1")["state"], "failed")
        self.assertEqual(self.task_status(prov), "ready", "the attempt is withdrawn, never launched in an unnamed worktree")
        self.assert_no_worker_ran()


class TestOrphanedWorkerIsStopped(CrashRecoveryBase):
    """2026-10-26 review: the monitor leads the process group its agent runs in. `kill -9` of the
    monitor ALONE left the agent running in the worktree while the liveness sweep reported the
    dispatch died, and a later stop skipped termination as "already finished". The sweep and the
    stop now end a group proven to be this worker's (a live member working in its worktree or
    lane) and leave a group id the kernel handed to someone else alone; a live pid that is not
    this lane's monitor is a vanished monitor, not a live one."""

    def launch_and_orphan(self):
        prov = self.restart()
        res = prov.worker_start(**self.start_kwargs())
        did = res["dispatchId"]
        self.assertTrue(_wait_for(lambda: len(self.agent_lines()) == 1), "the sleeper never started")
        agent_pid = int(self.agent_lines()[0].split()[-1])
        monitor_pid = int(self.dispatch(prov, did)["pid"])
        self.assertNotEqual(monitor_pid, agent_pid)
        os.kill(monitor_pid, signal.SIGKILL)  # the monitor alone: its worker keeps running
        self.assertTrue(_wait_for(lambda: not _alive(monitor_pid)))
        self.assertTrue(_alive(agent_pid), "precondition: the agent outlives its monitor")
        return prov, did, agent_pid, monitor_pid

    def lane_events(self, prov, did):
        lane = Path(self.dispatch(prov, did)["lane_dir"])
        out = []
        for line in (lane / "events.jsonl").read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    def test_the_sweep_that_reports_the_death_stops_the_worker_the_monitor_left(self):
        prov, did, agent_pid, monitor_pid = self.launch_and_orphan()
        states = {w["dispatchId"]: w["state"] for w in prov.worker_list()["workers"]}
        self.assertEqual(states[did], "died")
        self.assertTrue(_wait_for(lambda: not _alive(agent_pid), timeout=10),
                        "the orphaned agent kept running after the death report")
        stopped = [e for e in self.lane_events(prov, did) if e.get("type") == "orphaned_worker_stopped"]
        self.assertEqual([(e["pgid"], e["action"]) for e in stopped], [(monitor_pid, "terminated")])
        self.assertIn(agent_pid, stopped[0]["members"])

    def test_a_stop_after_the_death_was_recorded_still_ends_a_live_orphan(self):
        prov, did, agent_pid, monitor_pid = self.launch_and_orphan()
        with prov.state._connect() as conn:  # an older sweep recorded the death and stopped nothing
            conn.execute("UPDATE dispatches SET state = 'died' WHERE dispatch_id = ?", (did,))
        out = prov.worker_fence("stop", did)
        self.assertEqual(out["termination"]["skipped"], "dispatch already finished")
        self.assertEqual((out["termination"]["orphans"]["pgid"], out["termination"]["orphans"]["action"]),
                         (monitor_pid, "terminated"))
        self.assertTrue(_wait_for(lambda: not _alive(agent_pid), timeout=10))

    def test_a_live_pid_that_is_not_this_lanes_monitor_is_swept_and_its_group_left_alone(self):
        prov = self.restart()
        other = subprocess.Popen(["sleep", "30"], start_new_session=True, cwd=str(self.base))
        self.addCleanup(lambda: (other.kill(), other.wait()))
        lane = self.base / "state" / "lanes" / "disp_reused"
        lane.mkdir(parents=True)
        (lane / "run_worker.py").write_text("# the monitor script a pid this row names never ran\n", encoding="utf-8")
        with prov.state._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, pid, backend, "
                "lane_dir, monitor_pid, created_at, updated_at) VALUES ('disp_reused', ?, 'run-r04', '', 'claude', "
                "'term_reused', 'ready', ?, 'setsid', ?, ?, 0, 0)",
                (self.task, other.pid, str(lane), other.pid),
            )
        states = {w["dispatchId"]: w["state"] for w in prov.worker_list()["workers"]}
        self.assertEqual(states["disp_reused"], "died", "a live pid that is not this lane's monitor is a vanished monitor")
        self.assertIsNone(other.poll(), "a group whose members work elsewhere is never signalled")
        self.assertTrue(_alive(other.pid))

    def test_cross_run_worker_cannot_reconcile_or_replay_another_runs_launch(self):
        ProviderError = self.providers.ProviderError
        get_provider = self.providers.get_provider

        prov = self.restart()
        run_a_task = prov.task_create(spec="run A work", run="run-A")["task"]["id"]
        disp_a = prov.worker_start(
            task_id=run_a_task,
            worktree="new-child",
            agent="claude",
            run="run-A",
            retry_request="req-run-a",
        )
        self.addCleanup(lambda: prov.worker_fence("stop", disp_a["dispatchId"]))

        info_b = self.crash_at("intent_claimed", retry_request="req-run-b")
        intent_b = info_b["intentId"]
        self.assertIsNone(prov.state.launch_intent(intent_b)["outcome"], "precondition: run-r04 intent is open")

        worker_env = dict(self.env)
        worker_env["OPEN_FLEET_DISPATCH_ID"] = disp_a["dispatchId"]
        worker_a = get_provider("posix", env=worker_env)

        # 1. Omitting `run` on `worker_start` for run-r04's task raises `cross_run_access` WITHOUT reconciling intent_b.
        with self.assertRaises(ProviderError) as err_start:
            worker_a.worker_start(task_id=self.task, worktree="new-child", agent="claude")
        self.assertEqual(err_start.exception.code, "cross_run_access")
        self.assertIsNone(
            prov.state.launch_intent(intent_b)["outcome"],
            "cross-run worker_start must not reconcile run-r04's dead launch intent",
        )

        # 2. Replaying run-r04's pending `retry_request` also raises `cross_run_access` WITHOUT reconciling intent_b.
        with self.assertRaises(ProviderError) as err_replay:
            worker_a.worker_start(
                task_id=self.task,
                worktree="new-child",
                agent="claude",
                retry_request="req-run-b",
            )
        self.assertEqual(err_replay.exception.code, "cross_run_access")
        self.assertIsNone(
            prov.state.launch_intent(intent_b)["outcome"],
            "cross-run retry_request must not reconcile run-r04's pending launch intent",
        )

        # 3. `launch_reconcile` from worker_a leaves foreign open intents untouched and rejects explicit foreign intent.
        self.assertEqual(worker_a.launch_reconcile()["count"], 0)
        self.assertIsNone(prov.state.launch_intent(intent_b)["outcome"])
        with self.assertRaises(ProviderError) as err_rec:
            worker_a.launch_reconcile(intent=intent_b)
        self.assertEqual(err_rec.exception.code, "cross_run_access")
        self.assertIsNone(prov.state.launch_intent(intent_b)["outcome"])


if __name__ == "__main__":
    unittest.main()
