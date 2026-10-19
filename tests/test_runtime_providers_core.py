#!/usr/bin/env python3
"""Tests for core Runtime Provider Interface (RPI): base, local_state, posix, orca_cli, and spawn_worker (#578, #579, #580, #590)."""
from __future__ import annotations

import importlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SPAWN = ROOT / "runtime" / "scripts" / "spawn_worker.sh"
ORCA_CLI = ROOT / "runtime" / "scripts" / "orca_cli.py"


def _load_providers():
    root_str = str(ROOT)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    return importlib.import_module("runtime.providers")


def _load_base():
    root_str = str(ROOT)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    return importlib.import_module("runtime.providers.base")


def _load_local_state():
    root_str = str(ROOT)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    return importlib.import_module("runtime.providers.local_state")


def _load_posix():
    root_str = str(ROOT)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    return importlib.import_module("runtime.providers.posix")


class TestBaseHarnessAndMonotonicProfile(unittest.TestCase):
    def setUp(self):
        self.base = _load_base()

    def test_monotonic_profile_narrowing_allows_equal_or_narrower(self):
        for parent, child in (
            ("danger", "danger"),
            ("danger", "rw"),
            ("danger", "ro"),
            ("rw", "rw"),
            ("rw", "ro"),
            ("ro", "ro"),
            (None, "danger"),
        ):
            with self.subTest(parent=parent, child=child):
                self.assertEqual(self.base.check_monotonic_profile(parent, child), child)

    def test_monotonic_profile_narrowing_refuses_escalation(self):
        for parent, child in (("ro", "rw"), ("ro", "danger"), ("rw", "danger")):
            with self.subTest(parent=parent, child=child):
                with self.assertRaises(self.base.ProviderError) as ctx:
                    self.base.check_monotonic_profile(parent, child)
                self.assertEqual(ctx.exception.code, "privilege_escalation")

    def test_env_get_prefers_open_fleet_and_falls_back_to_orca(self):
        env = {"OPEN_FLEET_RUNTIME": "posix", "ORCA_FLEET_RUNTIME": "orca"}
        self.assertEqual(
            self.base.env_get("OPEN_FLEET_RUNTIME", "ORCA_FLEET_RUNTIME", env=env),
            "posix",
        )
        env2 = {"ORCA_FLEET_RUNTIME": "superset"}
        self.assertEqual(
            self.base.env_get("OPEN_FLEET_RUNTIME", "ORCA_FLEET_RUNTIME", env=env2),
            "superset",
        )

    def test_build_harness_command_covers_all_9_harnesses_and_profiles(self):
        harnesses = ("claude", "codex", "opencode", "omp", "pi", "jcode", "goose", "hermes", "crush")
        for agent in harnesses:
            for profile in ("ro", "rw"):
                with self.subTest(agent=agent, profile=profile):
                    spec = self.base.build_harness_command(agent, profile, "/tmp/wt")
                    self.assertIn("command", spec)
                    self.assertIn("profile_flag", spec)
                    self.assertTrue(spec["command"])
        # Verify JCode ro uses explicit --disabled-tools, never --profile minimal
        jcode_ro = self.base.build_harness_command("jcode", "ro", "/tmp/wt")
        self.assertIn("--disabled-tools", jcode_ro["command"])
        self.assertNotIn("--profile minimal", jcode_ro["command"])
        # Verify Hermes ro sets HERMES_WRITE_SAFE_ROOT=/dev/null
        hermes_ro = self.base.build_harness_command("hermes", "ro", "/tmp/wt")
        self.assertEqual(hermes_ro["env"]["HERMES_WRITE_SAFE_ROOT"], "/dev/null")
        # Verify Pi ro excludes write/bash tools
        pi_ro = self.base.build_harness_command("pi", "ro", "/tmp/wt")
        self.assertIn("--exclude-tools", pi_ro["command"])


class TestLocalStateStore(unittest.TestCase):
    def setUp(self):
        self.ls = _load_local_state()
        self.base = _load_base()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = self.ls.LocalStateStore(Path(self.tmp.name) / "state.db")

    def test_task_dag_promotes_dependent_when_dep_completes(self):
        t1 = self.store.task_create(spec="Step 1", title="T1")["task"]
        self.assertEqual(t1["status"], "ready")
        t2 = self.store.task_create(spec="Step 2", title="T2", deps=[t1["id"]])["task"]
        self.assertEqual(t2["status"], "pending")

        self.store.task_update(task_id=t1["id"], status="completed")
        tasks = {t["id"]: t for t in self.store.task_list()["tasks"]}
        self.assertEqual(tasks[t2["id"]]["status"], "ready")

    def test_durable_mutation_idempotency_and_request_mismatch(self):
        t1 = self.store.task_create(spec="S", title="T", retry_request="req_abc")
        t1_replay = self.store.task_create(spec="S", title="T", retry_request="req_abc")
        self.assertEqual(t1["task"]["id"], t1_replay["task"]["id"])

        with self.assertRaises(self.base.ProviderError) as ctx:
            self.store.task_update(task_id=t1["task"]["id"], status="completed", retry_request="req_abc")
        self.assertEqual(ctx.exception.code, "request_mismatch")

        shown = self.store.request_show("req_abc")
        self.assertEqual(shown["state"], "completed")

    def test_mailbox_consumer_fencing_and_ack(self):
        sent = self.store.send_message(
            subject="unit_done",
            msg_type="worker_done",
            to="coordinator",
            sender="term_w1",
            payload='{"summary": "ok"}',
            run="run_1",
        )
        self.assertTrue(sent["sent"])

        first = self.store.check_messages(terminal="coord_1", run="run_1", wait=False)
        self.assertEqual(len(first["messages"]), 1)
        msg_id = first["messages"][0]["id"]

        # A second coordinator handle on the same run is fenced
        with self.assertRaises(self.base.ProviderError) as ctx:
            self.store.check_messages(terminal="coord_2", run="run_1", wait=False)
        self.assertEqual(ctx.exception.code, "consumer_fenced")

        # Ack marks the delivery read
        after_ack = self.store.check_messages(terminal="coord_1", run="run_1", ack=msg_id, wait=False)
        self.assertEqual(len(after_ack["messages"]), 0)

        reply = self.store.reply_message(msg_id=msg_id, body="ack")
        self.assertTrue(reply["replied"])

    def test_synthetic_worker_died_on_silent_exit(self):
        res = self.store.ensure_terminal_or_died(
            dispatch_id="disp_dead",
            worker_handle="term_dead",
            exit_code=137,
            last_tail="OOM killed",
            worktree_head_sha="abc1234",
            run_id="run_2",
        )
        self.assertTrue(res["syntheticDied"])

        inbox = self.store.check_messages(terminal="coord_a", run="run_2", wait=False)
        self.assertEqual(len(inbox["messages"]), 1)
        self.assertEqual(inbox["messages"][0]["type"], "escalation")
        self.assertIn("worker_died", inbox["messages"][0]["subject"])

        # Subsequent call after terminal mail exists does not duplicate
        res2 = self.store.ensure_terminal_or_died(
            dispatch_id="disp_dead",
            worker_handle="term_dead",
            exit_code=137,
            run_id="run_2",
        )
        self.assertFalse(res2["syntheticDied"])

    def test_file_touch_line_range_conflict_detection(self):
        r1 = self.store.record_file_touch(
            worker_id="disp_1", file_path="src/app.py", start_line=10, end_line=30, op="edit"
        )
        self.assertFalse(r1["conflict"])
        self.assertEqual(r1["conflicts"], [])

        # Disjoint hunk in same file -> informational disjointTouches, conflict=False
        r2 = self.store.record_file_touch(
            worker_id="disp_2", file_path="src/app.py", start_line=50, end_line=70, op="edit"
        )
        self.assertFalse(r2["conflict"])
        self.assertEqual(len(r2["disjointTouches"]), 1)
        self.assertEqual(r2["disjointTouches"][0]["kind"], "same_file_disjoint_hunk")

        # Overlapping hunk in same file -> conflict=True, overlapping_hunk
        r3 = self.store.record_file_touch(
            worker_id="disp_3", file_path="src/app.py", start_line=20, end_line=40, op="edit"
        )
        self.assertTrue(r3["conflict"])
        self.assertEqual(len(r3["conflicts"]), 1)
        self.assertEqual(r3["conflicts"][0]["kind"], "overlapping_hunk")
        self.assertEqual(r3["conflicts"][0]["otherWorker"], "disp_1")


class TestPosixProviderAndSpawnIntegration(unittest.TestCase):
    def setUp(self):
        self.posix_mod = _load_posix()
        self.providers = _load_providers()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-b", "main"], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=self.repo, check=True)
        (self.repo / "README.md").write_text("# Test\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=self.repo, check=True, capture_output=True)

    def test_install_worktree_hooks_writes_configs_for_all_harnesses(self):
        wt = Path(self.tmp.name) / "wt"
        wt.mkdir()
        for agent in ("claude", "codex", "opencode", "omp", "crush"):
            self.posix_mod.install_worktree_hooks(wt, agent=agent, profile="ro")
        self.assertTrue((wt / ".claude" / "settings.local.json").is_file())
        self.assertTrue((wt / ".codex" / "hooks.json").is_file())
        self.assertTrue((wt / ".openhands" / "hooks.json").is_file())
        self.assertTrue((wt / ".opencode" / "plugin" / "orca-deny-hook.ts").is_file())
        self.assertTrue((wt / ".open-fleet" / "bridges" / "omp_pi_deny_bridge.ts").is_file())
        self.assertTrue((wt / ".crush-orca-ro" / "crush.json").is_file())

    def test_posix_provider_worktree_and_worker_lifecycle(self):
        state_db = Path(self.tmp.name) / "state.db"
        env = {
            "OPEN_FLEET_RUNTIME": "posix",
            "OPEN_FLEET_STATE_DB": str(state_db),
            "OPEN_FLEET_POSIX_MUX": "dry-run",
            "OPEN_FLEET_CLI_CWD": str(self.repo),
        }
        with mock.patch.dict(os.environ, env, clear=False):
            prov = self.providers.get_provider("posix")
            task = prov.dispatch(["orchestration", "task-create", "--spec", "Build feature", "--task-title", "Feat"])["task"]
            self.assertEqual(task["status"], "ready")

            ws = prov.dispatch([
                "orchestration", "worker-start",
                "--task", task["id"],
                "--worktree", "new-child",
                "--name", "feat-wt",
                "--agent", "jcode",
                "--profile", "rw",
            ])
            self.assertEqual(ws["state"], "ready")
            self.assertIn("--disabled-tools selfdev,desktop_selfdev", ws["launch"]["effective"]["args"])

            workers = prov.dispatch(["orchestration", "worker-list"])["workers"]
            self.assertEqual(len(workers), 1)
            self.assertEqual(workers[0]["dispatchId"], ws["dispatchId"])

            handle = ws["agentTerminalHandle"]
            ts = prov.terminal_send(handle, text="turn_started", enter=True)
            self.assertTrue(ts["send"]["accepted"])
            tw = prov.terminal_wait(handle, timeout_ms=100)
            self.assertTrue(tw["wait"]["satisfied"])
            di = prov.dispatch_inject(task["id"], handle)
            self.assertTrue(di["injected"])
            wt_dir = Path(prov.terminal_show(handle)["terminal"]["worktree"])
            self.assertTrue((wt_dir / ".open-fleet" / "inbox.jsonl").is_file())

            with self.assertRaises(self.providers.ProviderError) as ctx:
                prov.worker_start(
                    task_id=task["id"],
                    worktree="current",
                    name="danger-no-env",
                    agent="claude",
                    profile="danger",
                )
            self.assertEqual(ctx.exception.code, "danger_requires_sandbox")

    def test_spawn_worker_sh_runs_end_to_end_on_posix_provider_with_multi_harness(self):
        state_db = Path(self.tmp.name) / "state.db"
        scratch = Path(self.tmp.name) / "scratch"
        scratch.mkdir()
        env = {
            **os.environ,
            "OPEN_FLEET_RUNTIME": "posix",
            "OPEN_FLEET_STATE_DB": str(state_db),
            "OPEN_FLEET_POSIX_MUX": "dry-run",
            "OPEN_FLEET_CLI_CWD": str(self.repo),
            "OPEN_FLEET_COORD_ALLOW_AUTONOMOUS_WRITE": "1",
            "PROFILE": "rw",
            "SP": str(scratch),
            "SETTLE_SECS": "0",
        }
        p = subprocess.run(
            ["bash", str(SPAWN), "--spec", "Implement RPI test", "--task-title", "RPI", "new-child", "rpi-unit", "jcode"],
            env=env,
            cwd=self.repo,
            capture_output=True,
            text=True,
        )
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("READY=ready", p.stdout)
        self.assertIn("DISPATCH=disp_", p.stdout)

    def test_spawn_worker_sh_enforces_monotonic_parent_profile(self):
        scratch = Path(self.tmp.name) / "scratch2"
        scratch.mkdir()
        env = {
            **os.environ,
            "OPEN_FLEET_COORD_ALLOW_AUTONOMOUS_WRITE": "1",
            "PROFILE": "rw",
            "SP": str(scratch),
        }
        p = subprocess.run(
            ["bash", str(SPAWN), "--parent-profile", "ro", "task_1", "current", "title", "claude"],
            env=env,
            cwd=self.repo,
            capture_output=True,
            text=True,
        )
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertIn("monotonic privilege narrowing violation", p.stderr)


if __name__ == "__main__":
    unittest.main()
