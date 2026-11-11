#!/usr/bin/env python3
"""Tests for core Runtime Provider Interface (RPI): base, local_state, posix, orca_cli, and spawn_worker (#578, #579, #580, #590)."""
from __future__ import annotations

import importlib
import json
import os
import re
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


class TestFlagValuesAndEnvKeysStayData(unittest.TestCase):
    """W2-01: a flag VALUE that starts with `-` must stay the value, and a bare `--` ends the
    flags, so text is never read as an option and never silently becomes a bool. W2-02: a launch
    env KEY lands in a shell word position (`env K=v …`, `docker run -e K=v … sh -c`), where
    quoting the value alone makes nothing safe — a key that is not a shell identifier is refused."""

    def setUp(self):
        self.base = _load_base()

    def test_key_equals_value_carries_a_dash_leading_value(self):
        pos, flags = self.base._parse_flag_map(["--text=--hello", "--terminal=t1", "--text-x", "y"])
        self.assertEqual(pos, [])
        self.assertEqual(flags, {"text": "--hello", "terminal": "t1", "text-x": "y"})
        self.assertEqual(self.base._parse_flag_map(["--text=-R"])[1], {"text": "-R"})
        self.assertEqual(self.base._parse_flag_map(["--text="])[1], {"text": ""})

    def test_a_bare_double_dash_ends_the_flags(self):
        pos, flags = self.base._parse_flag_map(["--terminal", "t1", "--", "--text", "-R"])
        self.assertEqual(flags, {"terminal": "t1"})
        self.assertEqual(pos, ["--text", "-R"])

    def test_text_that_parsed_as_a_bool_is_a_clean_error(self):
        posix = _load_posix()
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, "OPEN_FLEET_STATE_DB": str(Path(tmp) / "s" / "runtime.db"),
                   "OPEN_FLEET_CLI_CWD": tmp, "OPEN_FLEET_POSIX_BACKEND": "dry-run"}
            prov = posix.PosixWorktreeProvider(env=env)
            for argv in (["terminal", "send", "--terminal", "t1", "--text", "--"],
                         ["terminal", "send", "--terminal", "t1", "--text"],
                         ["terminal", "send", "--terminal", "t1", "--text", "a", "--text", "b"]):
                with self.subTest(argv=argv):
                    with self.assertRaises(self.base.ProviderError) as ctx:
                        prov.dispatch(argv)
                    self.assertEqual(ctx.exception.code, "invalid_argument")
                    self.assertIn("--text=", ctx.exception.message)

    def _sent(self, argv):
        """What `terminal send` hands the terminal when routed through the public dispatch()."""
        posix = _load_posix()
        sent = []
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, "OPEN_FLEET_STATE_DB": str(Path(tmp) / "s" / "runtime.db"),
                   "OPEN_FLEET_CLI_CWD": tmp, "OPEN_FLEET_POSIX_BACKEND": "dry-run"}
            prov = posix.PosixWorktreeProvider(env=env, runner=lambda **kw: sent.append(kw["text"]))
            with prov.state._connect() as conn:
                conn.execute(
                    "INSERT INTO terminals(handle, worktree, title, command, shell, pid, backend, log_path, state, created_at) "
                    "VALUES ('t1', '', 't', 'x', '/bin/sh', 0, 'dry-run', '', 'running', 0)")
            prov.dispatch(argv)
        return sent

    def test_only_the_dispatchers_own_json_flag_is_consumed(self):
        # PR #720 review (P2): dispatch() stripped EVERY `--json` before parsing, so a text whose
        # value is `--json` lost its operand, and a `--json` after a bare `--` was deleted as well.
        send = ["terminal", "send", "--terminal", "t1"]
        for argv, want in (([*send, "--text", "--json"], "--json\n"),
                           ([*send, "--text", "--", "--json"], "--json\n"),
                           ([*send, "--", "--json"], "--json\n"),
                           ([*send, "--text", "--hello"], "--hello\n"),
                           (["terminal", "send", "t1", "--", "-R", "x"], "-R x\n"),
                           (["--json", *send, "--text", "hi", "--json"], "hi\n")):
            with self.subTest(argv=argv):
                self.assertEqual(self._sent(argv), [want])
        with self.assertRaises(self.base.ProviderError) as ctx:
            self._sent([*send, "--text", "a", "--", "b"])
        self.assertEqual(ctx.exception.code, "invalid_argument")

    def test_orca_forwards_its_json_flag_only_in_option_position(self):
        orca = importlib.import_module("runtime.providers.orca")
        seen = []

        def run(cmd, **_kw):
            seen.append(cmd)
            raise OSError("recorded")
        prov = orca.OrcaProvider(env={})
        send = ["terminal", "send", "--terminal", "t1"]
        with mock.patch.object(orca.OrcaProvider, "binary", return_value="/x/orca"), \
                mock.patch.object(orca.subprocess, "run", side_effect=run):
            for argv in ([*send, "--text", "--json"], [*send, "--", "--json"], ["--json", *send, "--text", "hi"]):
                with self.assertRaises(self.base.ProviderError):
                    prov.dispatch(argv)
        self.assertEqual(seen, [["/x/orca", *send, "--text", "--json", "--json"],
                                ["/x/orca", *send, "--json", "--", "--json"],
                                ["/x/orca", *send, "--text", "hi", "--json"]])

    def test_a_launch_env_key_must_be_a_shell_identifier(self):
        ok = self.base.shell_launch_line({"env": {"A_1": "v w", "_B": "x"}, "argv": ["run"]})
        self.assertEqual(ok, "env A_1='v w' _B=x run")
        for key in ("A B", "A;touch x", "1A", "", "A-B", "A=B", "A\nB", "$(id)"):
            with self.subTest(key=key):
                with self.assertRaises(self.base.ProviderError) as ctx:
                    self.base.shell_launch_line({"env": {key: "v"}, "argv": ["run"]})
                self.assertEqual(ctx.exception.code, "invalid_env_key")

    def test_a_docker_env_key_must_be_a_shell_identifier(self):
        posix = _load_posix()
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, "OPEN_FLEET_STATE_DB": str(Path(tmp) / "s" / "runtime.db"),
                   "OPEN_FLEET_CLI_CWD": tmp, "OPEN_FLEET_POSIX_BACKEND": "dry-run"}
            prov = posix.PosixWorktreeProvider(env=env)
            kw = dict(image="img", wt_path=tmp, inner="true", dispatch_id="d",
                      sandbox_meta={"sandbox_git": str(Path(tmp) / "sb")})
            cmd, _ = prov._docker_command(env={"GOOD_KEY": "v"}, **kw)
            self.assertIn("-e GOOD_KEY=v ", cmd)
            for key in ("A B", "A;touch x", "-v/:/host"):
                with self.subTest(key=key):
                    with self.assertRaises(self.base.ProviderError) as ctx:
                        prov._docker_command(env={key: "v"}, **kw)
                    self.assertEqual(ctx.exception.code, "invalid_env_key")


class TestPreRenameEnvNames(unittest.TestCase):
    """orca-fleet became open-fleet: every reader takes the OPEN_FLEET_* name and still reads
    the pre-rename ORCA_FLEET_* spelling installed users export when the new one is unset;
    the new name wins when both are set."""

    def test_runtime_selection_reads_the_legacy_name(self):
        providers = _load_providers()
        self.assertEqual(providers.active_provider_name(env={"ORCA_FLEET_RUNTIME": "posix"}),
                         "posix")
        self.assertEqual(providers.active_provider_name(
            env={"OPEN_FLEET_RUNTIME": "posix", "ORCA_FLEET_RUNTIME": "superset"}), "posix")
        self.assertEqual(providers.active_provider_name(env={}), "orca")

    def test_state_store_location_reads_the_legacy_names(self):
        local_state = _load_local_state()
        with tempfile.TemporaryDirectory() as tmp:
            legacy_db, new_db = Path(tmp) / "legacy.db", Path(tmp) / "new.db"
            self.assertEqual(local_state.default_db_path({"ORCA_FLEET_STATE_DB": str(legacy_db)}),
                             legacy_db.resolve())
            self.assertEqual(local_state.default_db_path(
                {"OPEN_FLEET_STATE_DB": str(new_db), "ORCA_FLEET_STATE_DB": str(legacy_db)}),
                new_db.resolve())
            self.assertEqual(local_state.default_db_path({"ORCA_FLEET_STATE_DIR": tmp}),
                             Path(tmp).resolve() / "runtime.db")


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
        # A dispatch nobody recorded (withdrawn before launch) never produces a death notice.
        ghost = self.store.ensure_terminal_or_died(dispatch_id="disp_ghost", run_id="run_2")
        self.assertFalse(ghost["syntheticDied"])
        with self.store._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp_dead', 't', 'run_2', '/w', 'claude', 'term_dead', 'ready', 0, 0)"
            )
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

    def test_install_worktree_hooks_never_writes_through_a_link(self):
        # A worktree's content is the worker's: a landed commit can carry `.claude` (or a guard file)
        # as a symbolic link, and the guard must never be written through it (PR #653 review sweep).
        for planted in (".claude", ".codex/hooks.json", ".open-fleet"):
            with self.subTest(planted=planted):
                wt, escape = Path(self.tmp.name) / f"wt-{len(planted)}", Path(self.tmp.name) / f"escape-{len(planted)}"
                wt.mkdir()
                escape.mkdir()
                link = wt / planted
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(escape if planted.count("/") == 0 else escape / "hooks.json")
                with self.assertRaises(self.posix_mod.ProviderError) as caught:
                    self.posix_mod.install_worktree_hooks(wt, agent="claude", profile="rw")
                self.assertEqual(caught.exception.code, "worktree_guard_link")
                self.assertEqual(list(escape.iterdir()), [], f"the guard was written through {planted}")
        clean = Path(self.tmp.name) / "wt-clean"
        self.posix_mod.install_worktree_hooks(clean, agent="claude", profile="rw")
        written = {str(f.relative_to(clean)) for f in clean.rglob("*") if f.is_file()}
        self.assertLessEqual(written, set(self.posix_mod.GUARD_FILES), "a guard file the link check does not cover")

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
            # dry-run delivery is labelled as simulated, never as a real turn start
            self.assertIn("simulated", ts["send"]["prompt"]["stages"])
            self.assertNotIn("turn_started", ts["send"]["prompt"]["stages"])
            tw = prov.terminal_wait(handle, condition="tui-idle", timeout_ms=3000)
            self.assertTrue(tw["wait"]["satisfied"])
            # a marker that never appears after the wait began times out (no pre-written success)
            with self.assertRaises(self.providers.ProviderError) as ctx_wait:
                prov.terminal_wait(handle, condition="never-printed", timeout_ms=200)
            self.assertEqual(ctx_wait.exception.code, "terminal_wait_timeout")

            task_inj = prov.dispatch(
                ["orchestration", "task-create", "--spec", "Inject task", "--task-title", "Inj"]
            )["task"]
            di = prov.dispatch_inject(task_inj["id"], handle)
            self.assertTrue(di["injected"])
            # injected work is a real dispatch visible in worker-list
            self.assertIn(di["dispatchId"], [w["dispatchId"] for w in prov.worker_list()["workers"]])
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

            # Issue 4: dispatch_inject claims ready task atomically and restores on delivery failure
            with self.assertRaises(self.providers.ProviderError) as ctx_dup:
                prov.dispatch_inject(task_inj["id"], handle)
            self.assertEqual(ctx_dup.exception.code, "task_not_startable")

            # Delivery failure (terminal stopped -> nothing accepted) restores task to ready
            task_fail = prov.dispatch(
                ["orchestration", "task-create", "--spec", "Fail inject", "--task-title", "FailInj"]
            )["task"]
            prov.worker_fence("stop", ws["dispatchId"])
            with self.assertRaises(self.providers.ProviderError):
                prov.dispatch_inject(task_fail["id"], handle)
            restored = [t for t in prov.task_list()["tasks"] if t["id"] == task_fail["id"]][0]
            self.assertEqual(restored["status"], "ready")

            # Issue 1 & 2: danger never mounts the host .git writable, never copies the guard
            # into the worktree, and gives the container a private git dir.
            ws_danger = prov.worker_start(
                task_id=task_fail["id"],
                worktree="new-child",
                name="danger-wt",
                agent="omp",
                profile="danger",
                on_env="sandbox-img:latest",
            )
            danger_wt = Path(ws_danger["worker"]["worktree"])
            self.assertTrue((danger_wt / ".git").is_file(), "host worktree pointer must stay intact")
            self.assertFalse((danger_wt / ".open-fleet" / "hooks").exists(), "guard must not live inside the worktree")
            with prov.state._connect() as conn:
                d_row = conn.execute(
                    "SELECT launch_effective, lane_dir FROM dispatches WHERE dispatch_id = ?",
                    (ws_danger["dispatchId"],),
                ).fetchone()
            eff = json.loads(d_row["launch_effective"])
            cmd = eff["command"]
            self.assertIn("OPEN_FLEET_DENY_HOOK=", cmd)
            self.assertIn("GIT_DIR=/open-fleet/sandbox.git", cmd)
            self.assertIn("--cap-drop ALL", cmd)
            self.assertIn("--name openfleet-" + ws_danger["dispatchId"], cmd)
            self.assertEqual(eff["container"], "openfleet-" + ws_danger["dispatchId"])
            self.assertNotIn(f"{self.repo / '.git'}:", cmd, "host .git must never be mounted")
            self.assertRegex(cmd, r"/runtime:\S*/runtime:ro")
            self.assertTrue((Path(d_row["lane_dir"]) / "sandbox.git").is_dir())

            # Issue 5: dispatch fenced during startup terminates backend and raises dispatch_fenced
            task_race = prov.dispatch(
                ["orchestration", "task-create", "--spec", "Race fence", "--task-title", "Race"]
            )["task"]

            def fencing_runner(**kw):
                prov.worker_fence("stop", kw["dispatch_id"])
                return {"pid": 0, "backend": "dry-run"}

            prov.runner = fencing_runner
            with self.assertRaises(self.providers.ProviderError) as ctx_race:
                prov.worker_start(
                    task_id=task_race["id"],
                    worktree="current",
                    name="race-wt",
                    agent="claude",
                    profile="ro",
                )
            self.assertEqual(ctx_race.exception.code, "dispatch_fenced")

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
            # No OPEN_FLEET_ALLOW_UNVERIFIED_DENY_HOOK: off Orca the provider installs and verifies
            # the guard inside worker-start, so the pre-launch gate defers (W4-06).
            "PROFILE": "rw",
            "SP": str(scratch),
            "HOME": self.tmp.name,  # the spawn registry, never the developer's own
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

    def test_worker_start_refuses_before_launch_when_the_installed_guard_is_unarmed(self):
        # W4-06 (Codex g1 r2 P1): the deny-hook registration is verified at worker-start, after it
        # is installed and BEFORE the agent process starts -- the real enforcement point a
        # new-child spawn's pre-launch gate cannot reach. A registration naming a hook that cannot
        # load aborts the launch: ProviderError, and the agent process (the runner) never runs.
        env = {"OPEN_FLEET_STATE_DB": str(Path(self.tmp.name) / "guard.db")}
        runner = mock.Mock(return_value={"pid": 0, "backend": "runner"})
        provider = self.posix_mod.PosixWorktreeProvider(repo_root=self.repo, env=env, runner=runner)
        task = provider.task_create(spec="x", title="Guard")["task"]
        with mock.patch.object(self.posix_mod, "CANONICAL_DENY_HOOK",
                               Path(self.tmp.name) / "missing" / "deny-hook.sh"):
            with self.assertRaises(self.posix_mod.ProviderError) as caught:
                provider.worker_start(task_id=task["id"], worktree="current", agent="claude",
                                      profile="ro")
        self.assertEqual(caught.exception.code, "deny_hook_unverified")
        self.assertFalse(runner.called, "the agent must not start when the installed guard is unarmed")

    def test_inject_claim_excludes_worker_start_during_delivery(self):
        # The delivery callback fixes the interleaving: a second provider competes
        # after inject enters its transport but before that transport returns.
        env = {
            "OPEN_FLEET_STATE_DB": str(Path(self.tmp.name) / "state.db"),
            "OPEN_FLEET_POSIX_MUX": "dry-run",
        }
        provider = self.posix_mod.PosixWorktreeProvider(repo_root=self.repo, env=env)
        competing_runner = mock.Mock(return_value={"pid": 0, "backend": "dry-run"})
        competitor = self.posix_mod.PosixWorktreeProvider(
            repo_root=self.repo, env=env, runner=competing_runner
        )
        host_task = provider.task_create(spec="Host terminal", title="Host")["task"]
        host = provider.worker_start(
            task_id=host_task["id"], worktree="current", agent="claude", profile="ro"
        )
        injected_task = provider.task_create(spec="Inject once", title="Inject")["task"]
        deliver = provider._deliver_terminal_input

        def deliver_while_start_competes(term_row, text, enter=True):
            self.assertEqual(json.loads(text)["taskId"], injected_task["id"])
            with self.assertRaises(self.providers.ProviderError) as blocked:
                competitor.worker_start(
                    task_id=injected_task["id"], worktree="current",
                    agent="claude", profile="ro",
                )
            self.assertEqual(blocked.exception.code, "task_not_startable")
            with competitor.state._connect() as conn:
                status = conn.execute(
                    "SELECT status FROM tasks WHERE id = ?", (injected_task["id"],)
                ).fetchone()["status"]
            self.assertEqual(status, "dispatched")
            return deliver(term_row, text, enter=enter)

        with mock.patch.object(
            provider, "_deliver_terminal_input", side_effect=deliver_while_start_competes
        ) as delivery:
            injected = provider.dispatch_inject(injected_task["id"], host["agentTerminalHandle"])

        self.assertTrue(injected["injected"])
        delivery.assert_called_once()
        competing_runner.assert_not_called()
        workers = competitor.worker_list(task=injected_task["id"])["workers"]
        self.assertEqual([w["dispatchId"] for w in workers], [injected["dispatchId"]])
        inbox = self.repo / ".open-fleet" / "inbox.jsonl"
        messages = [json.loads(line) for line in inbox.read_text().splitlines()]
        self.assertEqual(len(messages), 1)
        self.assertEqual(json.loads(messages[0]["text"])["taskId"], injected_task["id"])

    def test_spawn_worker_sh_enforces_monotonic_parent_profile(self):
        scratch = Path(self.tmp.name) / "scratch2"
        scratch.mkdir()
        env = {
            **os.environ,
            "OPEN_FLEET_COORD_ALLOW_AUTONOMOUS_WRITE": "1",
            "PROFILE": "rw",
            "SP": str(scratch),
            "HOME": self.tmp.name,  # the spawn registry, never the developer's own
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


class GuardConfigsMergeWhatIsAlreadyThere(unittest.TestCase):
    """2026-10-26 review: install_worktree_hooks REPLACED any JSON config at a guard path, so a
    repository's checked-in `.crush/crush.json` or `.codex/hooks.json`, or an operator's own
    `.claude/settings.local.json` in a reused worktree, lost every other key. Now their plain
    settings survive and the keys that could disarm the guard are dropped. Nothing the harness
    would EXECUTE survives (#707 review): a kept hook ran beside the guard, never through it, and
    Codex launches with --dangerously-bypass-hook-trust."""

    def setUp(self):
        self.posix_mod = _load_posix()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.wt = Path(self.tmp.name) / "wt"
        self.wt.mkdir()

    def install(self, agent="claude", profile="rw"):
        return self.posix_mod.install_worktree_hooks(self.wt, agent=agent, profile=profile)

    def read(self, rel):
        return json.loads((self.wt / rel).read_text(encoding="utf-8"))

    def test_operator_settings_survive_and_the_guard_hook_runs_first(self):
        settings = self.wt / ".claude" / "settings.local.json"
        settings.parent.mkdir()
        settings.write_text(json.dumps({
            "permissions": {"allow": ["Bash(ls)"]},
            "env": {"KEEP_ME": "1", "ORCA_HOOK_STRICT_EXIT": "0", "OPEN_FLEET_UNIT_WORKTREE": "/elsewhere"},
            "disableAllHooks": True,
            "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo theirs"}]}],
                      "Stop": [{"hooks": [{"type": "command", "command": "echo bye"}]}]},
        }), encoding="utf-8")
        self.install()
        doc = self.read(".claude/settings.local.json")
        self.assertEqual(doc["permissions"], {"allow": ["Bash(ls)"]})
        self.assertEqual(doc["env"], {"KEEP_ME": "1"}, "env that steers the guard is dropped, the rest kept")
        self.assertNotIn("disableAllHooks", doc)
        pre = doc["hooks"]["PreToolUse"]
        self.assertIn(str(self.posix_mod.CANONICAL_DENY_HOOK), pre[0]["hooks"][0]["command"])
        self.assertEqual(len(pre), 1, "their PreToolUse hook would run beside the guard, unchecked")
        self.assertEqual(list(doc["hooks"]), ["PreToolUse"], "their Stop hook is executable too")

    def test_env_that_steers_the_hook_shell_is_dropped(self):
        # #707 review: the guard command runs a bare `sh`, so a kept env.PATH naming a directory
        # with its own `sh` ran that instead of deny-hook.sh. Every key --verify-settings refuses
        # as steering is dropped on merge, for every harness config.
        steer = {"PATH": "/planted/bin", "BASH_ENV": "/planted/rc", "ENV": "/planted/rc",
                 "LD_PRELOAD": "/planted/x.so", "SHELL": "/planted/sh", "IFS": "/"}
        for rel in (".claude/settings.local.json", ".codex/hooks.json", ".crush/crush.json"):
            (self.wt / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.wt / rel).write_text(json.dumps({"env": {**steer, "KEEP_ME": "1"}}), encoding="utf-8")
        self.install(agent="crush")
        for rel in (".claude/settings.local.json", ".codex/hooks.json", ".crush/crush.json"):
            self.assertEqual(self.read(rel)["env"], {"KEEP_ME": "1"}, rel)

    def test_the_dropped_keys_cover_what_verify_settings_refuses(self):
        hook = (Path(__file__).resolve().parents[1] / "runtime" / "scripts" / "deny-hook.sh").read_text(
            encoding="utf-8")
        listed = re.search(r"^STEERING = \(([^)]*)\)", hook, re.M)
        self.assertIsNotNone(listed, "deny-hook.sh no longer names its STEERING keys")
        refused = set(re.findall(r'"([A-Z_]+)"', listed.group(1)))
        self.assertTrue(refused)
        self.assertLessEqual(refused, set(self.posix_mod._SHELL_STEERING_KEYS))

    def test_installing_twice_adds_no_second_guard_entry(self):
        self.install()
        once = self.read(".claude/settings.local.json")
        self.install()
        self.assertEqual(self.read(".claude/settings.local.json"), once)
        self.assertEqual(len(once["hooks"]["PreToolUse"]), 1)
        for rel in (".codex/hooks.json", ".openhands/hooks.json",
                    ".agents/plugins/orca-deny-hook/hooks/hooks.json", ".crush/crush.json"):
            self.assertEqual(len(self.read(rel)["hooks"]["PreToolUse"]), 1, rel)

    def test_a_repositorys_crush_and_codex_configs_keep_their_other_keys(self):
        (self.wt / ".crush").mkdir()
        (self.wt / ".crush" / "crush.json").write_text(
            json.dumps({"options": {"debug": True}, "lsp": {"go": {"command": "gopls"}}}), encoding="utf-8")
        (self.wt / ".codex").mkdir()
        (self.wt / ".codex" / "hooks.json").write_text(
            json.dumps({"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": "echo after"}]}]}}),
            encoding="utf-8")
        self.install(agent="crush")
        crush = self.read(".crush/crush.json")
        self.assertEqual(crush["options"], {"debug": True})
        self.assertNotIn("lsp", crush, "a setting that names a command to run is dropped")
        self.assertEqual(len(crush["hooks"]["PreToolUse"]), 1)
        codex = self.read(".codex/hooks.json")
        self.assertEqual(list(codex["hooks"]), ["PreToolUse"])
        self.assertIn("ORCA_HOOK_STRICT_EXIT=1", codex["hooks"]["PreToolUse"][0]["hooks"][0]["command"])

    def test_no_repository_command_survives_beside_the_guard(self):
        # #707 review: a checked-in `.codex/hooks.json` kept its shell hooks beside the guard,
        # and Codex launches with --dangerously-bypass-hook-trust, so they ran unchecked.
        planted = "touch /tmp/pwned-by-repo-hook"
        (self.wt / ".codex").mkdir()
        (self.wt / ".codex" / "hooks.json").write_text(json.dumps({"hooks": {
            "PreToolUse": [{"matcher": ".*", "hooks": [{"type": "command", "command": planted}]}],
            "PostToolUse": [{"hooks": [{"type": "command", "command": planted}]}],
            "SessionStart": [{"hooks": [{"type": "command", "command": planted}]}],
        }}), encoding="utf-8")
        (self.wt / ".claude").mkdir()
        (self.wt / ".claude" / "settings.local.json").write_text(json.dumps({
            "statusLine": {"type": "command", "command": planted},
            "permissions": {"allow": ["Bash(ls)"]},
        }), encoding="utf-8")
        self.install()
        for rel in (".codex/hooks.json", ".claude/settings.local.json"):
            with self.subTest(rel=rel):
                self.assertNotIn(planted, (self.wt / rel).read_text(encoding="utf-8"))
        self.assertEqual(self.read(".claude/settings.local.json")["permissions"], {"allow": ["Bash(ls)"]})

    def test_an_unreadable_config_is_replaced_by_the_guard(self):
        (self.wt / ".openhands").mkdir()
        (self.wt / ".openhands" / "hooks.json").write_text("{not json", encoding="utf-8")
        (self.wt / ".codex").mkdir()
        (self.wt / ".codex" / "hooks.json").write_text("[1, 2]", encoding="utf-8")
        self.install()
        for rel in (".openhands/hooks.json", ".codex/hooks.json"):
            doc = self.read(rel)
            self.assertEqual(list(doc), ["hooks"], rel)
            self.assertEqual(len(doc["hooks"]["PreToolUse"]), 1, rel)


class StateAndLanesArePrivateToTheFleetUser(unittest.TestCase):
    """2026-10-26 review: the state dir holds every worker's transcript, launch env and the
    mailbox, and was created with the umask's default mode. What the store and a launch create
    is now user-private; a directory the operator already had keeps its mode."""

    def test_a_fresh_state_dir_db_lane_and_transcript_are_user_private(self):
        import stat

        providers = _load_providers()
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
            subprocess.run(["git", "-c", "user.email=t@x", "-c", "user.name=T", "commit", "-q", "--allow-empty", "-m", "init"],
                           cwd=repo, check=True)
            state_db = Path(tmp) / "state" / "runtime.db"
            env = {**os.environ, "OPEN_FLEET_RUNTIME": "posix", "OPEN_FLEET_STATE_DB": str(state_db),
                   "OPEN_FLEET_POSIX_MUX": "dry-run", "OPEN_FLEET_CLI_CWD": str(repo)}
            prov = providers.get_provider("posix", env=env)
            task = prov.task_create(spec="x")["task"]
            ws = prov.worker_start(task_id=task["id"], worktree="new-child", agent="claude", profile="rw")
            with prov.state._connect() as conn:
                lane = Path(conn.execute("SELECT lane_dir FROM dispatches WHERE dispatch_id = ?",
                                         (ws["dispatchId"],)).fetchone()["lane_dir"])

            def mode(p):
                return stat.S_IMODE(Path(p).stat().st_mode)

            self.assertEqual(mode(state_db.parent), 0o700)
            self.assertEqual(mode(state_db), 0o600)
            for side in ("-wal", "-shm"):
                if Path(str(state_db) + side).exists():
                    self.assertEqual(mode(str(state_db) + side), 0o600, side)
            self.assertEqual(mode(lane), 0o700)
            self.assertEqual(mode(lane / "events.jsonl"), 0o600)
            pre = Path(tmp) / "pre"
            pre.mkdir(mode=0o755)
            os.chmod(pre, 0o755)
            providers.get_provider("posix", env={**env, "OPEN_FLEET_STATE_DB": str(pre / "runtime.db")})
            self.assertEqual(mode(pre), 0o755, "an operator's existing directory keeps its mode")


if __name__ == "__main__":
    unittest.main()
