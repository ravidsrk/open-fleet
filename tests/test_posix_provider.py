#!/usr/bin/env python3
"""Real-process tests for the zero-daemon POSIX provider (#580, #590, PR #591 re-review).

Every test here drives REAL processes/git (setsid, tmux when installed) rather than the
dry-run backend, because the gaps the re-review found were all invisible to dry-run:
workers that never got their environment, fences that recorded `stopped` while the agent kept
running, Docker commits that never reached the host, cleanup that deleted unsaved work.
"""
from __future__ import annotations

import importlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _providers():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    return importlib.import_module("runtime.providers")


def _posix():
    _providers()
    return importlib.import_module("runtime.providers.posix")


def _git(*args, cwd, env=None, check=True):
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=check, capture_output=True, text=True)


def _group_alive(pid):
    try:
        os.killpg(int(pid), 0)
        return True
    except OSError:
        return False


def _process_gone(pid):
    """True once `pid` has exited. A zombie counts: its fds, a listening socket among them, are
    closed, and an un-reaped daemon is a zombie wherever pid 1 does not reap."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    stat = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return stat == "" or stat.startswith("Z")


def _wait_for(pred, timeout=15.0, step=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(step)
    return False


class PosixRealProcessBase(unittest.TestCase):
    backend = "setsid"

    def setUp(self):
        self.providers = _providers()
        self.posix = _posix()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
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
        # Every harness name resolves to a TRIPWIRE ahead of the developer's real binary: an
        # unfaked agent, or a launch that loses the fake `bin`, records a hit and exits instead
        # of starting a real agent with --dangerously-skip-permissions (2026-10-23 review, P1-11).
        self.tripwire = base / "tripwire"
        self.tripwire.mkdir()
        self.tripwire_log = base / "tripwire.log"
        for harness in self.providers.SUPPORTED_HARNESSES:
            trip = self.tripwire / harness
            trip.write_text(f'#!/bin/sh\necho "{harness} $*" >> "{self.tripwire_log}"\nexit 97\n', encoding="utf-8")
            trip.chmod(0o755)
        self.env = {
            **os.environ,
            "OPEN_FLEET_STATE_DB": str(base / "state" / "runtime.db"),
            "OPEN_FLEET_CLI_CWD": str(self.repo),
            "OPEN_FLEET_POSIX_BACKEND": self.backend,
            "PATH": os.pathsep.join([str(self.bin), str(self.tripwire), os.environ.get("PATH", "")]),
            # No rc file of a login shell (zsh sources ~/.zshenv even for `-c`) may reorder PATH.
            "SHELL": "/bin/sh",
        }
        self.prov = self.providers.get_provider("posix", env=self.env)
        self.addCleanup(self._no_tripwire_hit)
        self.addCleanup(self._kill_all)

    def _no_tripwire_hit(self):
        """Runs after `_kill_all`: no test in this module may launch anything but its fake agent."""
        hits = self.tripwire_log.read_text() if self.tripwire_log.exists() else ""
        self.assertEqual(hits, "", f"an agent resolved past the fake bin to the tripwire: {hits!r}")

    def _kill_all(self):
        # Stop every live worker (retained ones too) and let its monitor finish writing into
        # the temp state dir before the TemporaryDirectory cleanup removes it.
        try:
            for w in self.prov.worker_list()["workers"]:
                if w["state"] in ("ready", "running", "retained"):
                    self.prov.worker_fence("stop", w["dispatchId"])
            with self.prov.state._connect() as conn:
                pids = [r["pid"] for r in conn.execute("SELECT pid FROM dispatches WHERE pid > 0").fetchall()]
            for pid in pids:
                _wait_for(lambda pid=pid: not _group_alive(pid), timeout=10)
        except Exception:
            pass

    def wait_monitor_done(self, dispatch_id, timeout=30.0):
        """The monitor's LAST write is the dispatch state; wait until it has left the live states."""
        return _wait_for(
            lambda: self.prov.state.dispatch_state(dispatch_id) not in ("ready", "running", "retained"),
            timeout=timeout,
        )

    def fake_agent(self, name: str, body: str) -> None:
        """Put a fake `claude` on PATH; `body` is POSIX sh run with the worker's env."""
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
        path.chmod(0o755)

    def start(self, spec="do the thing", agent="claude", profile="rw", worktree="new-child", name=None):
        task = self.prov.dispatch(["orchestration", "task-create", "--spec", spec])["task"]
        res = self.prov.dispatch(
            ["orchestration", "worker-start", "--task", task["id"], "--worktree", worktree,
             "--agent", agent, "--profile", profile, "--name", name or task["id"]]
        )
        return task, res


class TestSetsidWorkerLifecycle(PosixRealProcessBase):
    def test_worker_gets_prompt_and_environment(self):
        out = Path(self.tmp.name) / "seen.json"
        self.fake_agent(
            "claude",
            f'python3 -c \'import json,os,sys; json.dump({{"argv": sys.argv[1:], "hook": os.environ.get("OPEN_FLEET_DENY_HOOK"), '
            f'"profile": os.environ.get("OPEN_FLEET_SANDBOX_PROFILE"), "parent": os.environ.get("OPEN_FLEET_PARENT_PROFILE"), '
            f'"dispatch": os.environ.get("OPEN_FLEET_DISPATCH_ID")}}, open("{out}", "w"))\' "$@"',
        )
        _, res = self.start(spec="SENTINEL-SPEC-123")
        self.assertTrue(_wait_for(out.is_file), "fake agent never ran")
        seen = json.loads(out.read_text())
        self.assertIn("SENTINEL-SPEC-123", seen["argv"], "the task spec must reach the agent")
        self.assertEqual(seen["hook"], str(self.posix.CANONICAL_DENY_HOOK), "hook must be the canonical, out-of-worktree path")
        self.assertEqual(seen["profile"], "rw")
        self.assertEqual(seen["parent"], "rw")
        self.assertEqual(seen["dispatch"], res["dispatchId"])

    def test_crash_without_terminal_mail_emits_worker_died_with_head(self):
        self.fake_agent("claude", "exit 3")
        _, res = self.start()
        disp = res["dispatchId"]
        self.assertTrue(_wait_for(lambda: self.prov.worker_show(disp)["worker"]["state"] == "died"))
        mail = self.prov.check_messages(terminal="coordinator")
        died = [m for m in mail["messages"] if m["subject"].startswith(f"worker_died:{disp}")]
        self.assertEqual(len(died), 1)
        payload = json.loads(died[0]["payload"])
        self.assertEqual(payload["exitCode"], 3)
        self.assertRegex(payload["headSha"], r"^[0-9a-f]{40}$")

    def test_fence_stops_process_group_and_suppresses_worker_died(self):
        marker = Path(self.tmp.name) / "still-alive"
        self.fake_agent("claude", f'trap "" TERM HUP; while :; do date > "{marker}"; sleep 0.1; done')
        _, res = self.start()
        disp = res["dispatchId"]
        self.assertTrue(_wait_for(marker.is_file))
        out = self.prov.worker_fence("stop", disp)
        self.assertEqual(out["state"], "stopped")
        stamp = marker.stat().st_mtime
        time.sleep(0.6)
        self.assertEqual(marker.stat().st_mtime, stamp, "agent kept running after stop (SIGKILL escalation missing)")
        self.assertEqual(self.prov.worker_show(disp)["worker"]["state"], "stopped")
        mail = self.prov.check_messages(terminal="coordinator")
        self.assertFalse([m for m in mail["messages"] if disp in m["subject"]], "a fenced exit is not a death")

    def test_retain_never_terminates(self):
        marker = Path(self.tmp.name) / "tick"
        self.fake_agent("claude", f'while :; do date > "{marker}"; sleep 0.1; done')
        _, res = self.start()
        self.assertTrue(_wait_for(marker.is_file))
        self.prov.worker_fence("retain", res["dispatchId"])
        stamp = marker.stat().st_mtime
        self.assertTrue(_wait_for(lambda: marker.stat().st_mtime != stamp, timeout=3))

    def test_a_retain_after_settlement_survives_every_later_read(self):
        # #641 settles a dispatch from exit.json when its monitor died BEFORE settling it. A
        # dispatch its own monitor already settled, then retained by the coordinator, is not that
        # case: a later show or list must keep reading `retained`, never re-settle it (#596: the
        # first run retains, then releases, and reads the state back after each).
        go = Path(self.tmp.name) / "go"
        self.fake_agent("claude", f'while [ ! -f "{go}" ]; do sleep 0.05; done')
        for mail, settled in ((None, "died"), ("worker_done", "completed")):
            with self.subTest(settled=settled):
                go.unlink(missing_ok=True)
                _, res = self.start()
                disp = res["dispatchId"]
                if mail:
                    with self.prov.state._connect() as conn:
                        run = conn.execute("SELECT run_id FROM dispatches WHERE dispatch_id = ?", (disp,)).fetchone()[0]
                    self.prov.state.send_message(subject=f"worker_done:{disp}", msg_type=mail, sender=disp,
                                                 outcome="succeeded", run=run)
                go.touch()
                self.assertTrue(self.wait_monitor_done(disp), "the monitor never settled the dispatch")
                self.assertEqual(self.prov.worker_show(disp)["worker"]["state"], settled)
                self.assertEqual(self.prov.worker_fence("retain", disp)["state"], "retained")
                for _ in range(2):
                    self.assertEqual(self.prov.worker_show(disp)["worker"]["state"], "retained")
                    listed = {w["dispatchId"]: w["state"] for w in self.prov.worker_list()["workers"]}
                    self.assertEqual(listed[disp], "retained")
                died = [m for m in self.prov.check_messages(terminal="coordinator")["messages"]
                        if m["subject"].startswith(f"worker_died:{disp}")]
                self.assertEqual(len(died), 1 if settled == "died" else 0, "a read never reports a death twice")

    def test_launch_gate_refuses_a_dispatch_fenced_before_launch(self):
        ran = Path(self.tmp.name) / "ran"
        self.fake_agent("claude", f'touch "{ran}"')
        task = self.prov.dispatch(["orchestration", "task-create", "--spec", "x"])["task"]
        real_spawn = self.prov._spawn_process

        def fence_then_spawn(**kw):
            with self.prov.state._connect() as _c:
                _c.execute(
                "UPDATE dispatches SET state = 'stopped' WHERE dispatch_id = ?", (kw["dispatch_id"],)
            )
            return real_spawn(**kw)

        self.prov._spawn_process = fence_then_spawn
        with self.assertRaises(self.providers.ProviderError) as ctx:
            self.prov.worker_start(task_id=task["id"], worktree="new-child", agent="claude", profile="rw")
        self.assertEqual(ctx.exception.code, "dispatch_fenced")
        time.sleep(1.0)
        self.assertFalse(ran.exists(), "a fenced dispatch must never run its agent")

    def test_launch_gate_itself_refuses_without_post_spawn_help(self):
        """Drive the generated monitor directly: only the gate stands between a fenced dispatch
        and its agent (the post-spawn teardown must not be what makes this pass)."""
        ran = Path(self.tmp.name) / "gate-ran"
        self.fake_agent("claude", f'touch "{ran}"')
        captured = {}

        def capture(**kw):
            captured.update(kw)
            return {"pid": 0, "backend": "setsid"}

        task = self.prov.dispatch(["orchestration", "task-create", "--spec", "x"])["task"]
        self.prov.runner = None
        real = self.prov._spawn_process
        self.prov._spawn_process = lambda **kw: (captured.update(kw), {"pid": 0, "backend": "dry-run"})[1]
        res = self.prov.worker_start(task_id=task["id"], worktree="new-child", agent="claude", profile="rw")
        self.prov._spawn_process = real
        disp = res["dispatchId"]
        with self.prov.state._connect() as _c:
            _c.execute("UPDATE dispatches SET state = 'stopped' WHERE dispatch_id = ?", (disp,))
        self.prov.backend = "setsid"
        real(**captured)  # writes run_worker.py and launches it
        lane = Path(captured["lane_dir"])
        self.assertTrue(_wait_for(lambda: "launch_refused" in (lane / "events.jsonl").read_text()))
        time.sleep(0.3)
        self.assertFalse(ran.exists())

    def test_failure_after_spawn_withdraws_dispatch_and_frees_task(self):
        ran = Path(self.tmp.name) / "late"
        self.fake_agent("claude", f'touch "{ran}"')
        task = self.prov.dispatch(["orchestration", "task-create", "--spec", "x"])["task"]
        real = self.prov._spawn_process

        def spawn_then_fail(**kw):
            real(**kw)
            raise KeyboardInterrupt()

        self.prov._spawn_process = spawn_then_fail
        with self.assertRaises(KeyboardInterrupt):
            self.prov.worker_start(task_id=task["id"], worktree="new-child", agent="claude", profile="rw")
        time.sleep(1.0)
        self.assertFalse(ran.exists(), "a withdrawn dispatch must not run its agent")
        self.assertEqual(self.prov.task_list()["tasks"][0]["status"], "ready")
        self.assertEqual(self.prov.check_messages(terminal="coordinator")["count"], 0, "no orphan worker_died")

    def test_fenced_during_startup_returns_task_to_ready(self):
        task = self.prov.dispatch(["orchestration", "task-create", "--spec", "x"])["task"]
        self.prov.runner = lambda **kw: (self.prov.worker_fence("stop", kw["dispatch_id"]), {"pid": 0, "backend": "dry-run"})[1]
        with self.assertRaises(self.providers.ProviderError):
            self.prov.worker_start(task_id=task["id"], worktree="new-child", agent="claude")
        self.assertEqual(self.prov.task_list()["tasks"][0]["status"], "ready")

    def test_starting_tmux_row_is_not_declared_dead(self):
        with self.prov.state._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, pid, backend, created_at, updated_at) "
                "VALUES ('disp_new', 't', 'default', '/w', 'claude', 'term_new', 'ready', 0, 'tmux', 0, 0)"
            )
        self.assertEqual(self.prov.worker_show("disp_new")["worker"]["state"], "ready")
        self.assertEqual(self.prov.check_messages(terminal="coordinator")["count"], 0)

    def test_terminal_state_follows_supervised_exit(self):
        self.fake_agent("claude", "exit 0")
        _, res = self.start()
        handle = res["agentTerminalHandle"]
        self.assertTrue(_wait_for(lambda: self.prov.terminal_show(handle)["terminal"]["state"] == "exited"))
        self.assertTrue(self.prov.terminal_wait(handle, condition="exit", timeout_ms=1000)["wait"]["satisfied"])

    def test_work_injected_into_a_terminal_dies_with_it(self):
        t = self.prov.terminal_create(worktree="current", title="custom", command="sleep 0.8; exit 3")
        handle = t["terminal"]["handle"]
        task = self.prov.dispatch(["orchestration", "task-create", "--spec", "x"])["task"]
        with self.prov.state._connect() as conn:  # what dispatch_inject records (tmux/cmux only)
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp_inj', ?, 'default', '/w', 'custom', ?, 'ready', 0, 0)",
                (task["id"], handle),
            )
        self.assertTrue(_wait_for(lambda: self.prov.state.dispatch_state("disp_inj") == "died"))
        subjects = [m["subject"] for m in self.prov.check_messages(terminal="coordinator")["messages"]]
        self.assertTrue(any(sub.startswith("worker_died:disp_inj") for sub in subjects), subjects)

    def test_fence_of_finished_dispatch_never_kills_a_reused_pid(self):
        bystander = subprocess.Popen(["sleep", "30"], start_new_session=True)
        self.addCleanup(bystander.wait)  # reap it (cleanups run last-in, first-out)
        self.addCleanup(bystander.kill)
        with self.prov.state._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, pid, backend, created_at, updated_at) "
                "VALUES ('disp_old', 't', 'default', '/w', 'claude', 'term_old', 'completed', ?, 'setsid', 0, 0)",
                (bystander.pid,),
            )
        out = self.prov.worker_fence("release", "disp_old")
        self.assertEqual(out["termination"], {"skipped": "dispatch already finished"})
        self.assertIsNone(bystander.poll(), "an unrelated process group was signalled")

    def test_signing_seed_never_reaches_a_worker(self):
        out = Path(self.tmp.name) / "seed.txt"
        self.env["OPEN_FLEET_SIGNING_SEED"] = "00" * 32
        self.env["ORCA_DISPATCH_SIGNING_SEED"] = "11" * 32
        self.prov = self.providers.get_provider("posix", env=self.env)
        self.fake_agent("claude", f'echo "[$OPEN_FLEET_SIGNING_SEED][$ORCA_DISPATCH_SIGNING_SEED]" > "{out}"')
        self.start()
        self.assertTrue(_wait_for(out.is_file))
        self.assertEqual(out.read_text().strip(), "[][]")

    def test_the_operator_denylist_and_custody_tokens_never_reach_a_worker(self):
        # 2026-10-26 review: a worker inherits the coordinator's environment (harness credentials
        # live there), so the coordinator's own custody tokens are stripped by name and the
        # operator strips anything else with OPEN_FLEET_WORKER_ENV_DENY (names or globs).
        out = Path(self.tmp.name) / "deny.txt"
        self.env.update(GH_TOKEN="ghp_coordinator", AWS_SECRET_ACCESS_KEY="aws_coordinator",
                        ORCA_CLOUD_AUTH_TOKEN="orca_cloud", KEEP_ME="kept",
                        OPEN_FLEET_WORKER_ENV_DENY="GH_TOKEN, AWS_*")
        self.prov = self.providers.get_provider("posix", env=self.env)
        self.fake_agent("claude", f'echo "[$GH_TOKEN][$AWS_SECRET_ACCESS_KEY][$ORCA_CLOUD_AUTH_TOKEN][$KEEP_ME]" > "{out}"')
        self.start()
        self.assertTrue(_wait_for(out.is_file))
        self.assertEqual(out.read_text().strip(), "[][][][kept]")

    def test_retain_during_startup_does_not_cancel_the_launch(self):
        ran = Path(self.tmp.name) / "retained-ran"
        self.fake_agent("claude", f'touch "{ran}"')
        task = self.prov.dispatch(["orchestration", "task-create", "--spec", "x"])["task"]
        real = self.prov._spawn_process

        def retain_then_spawn(**kw):
            self.prov.worker_fence("retain", kw["dispatch_id"])
            return real(**kw)

        self.prov._spawn_process = retain_then_spawn
        res = self.prov.worker_start(task_id=task["id"], worktree="new-child", agent="claude", profile="rw")
        self.assertEqual(res["state"], "ready")
        self.assertTrue(_wait_for(ran.exists, timeout=30), "retaining a dispatch must not cancel its work")
        self.assertTrue(self.wait_monitor_done(res["dispatchId"]))

    def test_monitor_strips_secrets_inherited_from_its_own_environment(self):
        """A tmux server started with a seed hands it to the monitor's os.environ."""
        out = Path(self.tmp.name) / "inherited.txt"
        self.fake_agent("claude", f'echo "[$OPEN_FLEET_SIGNING_SEED][$ORCA_DISPATCH_SIGNING_SEED]" > "{out}"')
        captured = {}
        task = self.prov.dispatch(["orchestration", "task-create", "--spec", "x"])["task"]
        real = self.prov._spawn_process
        self.prov._spawn_process = lambda **kw: (captured.update(kw), {"pid": 0, "backend": "dry-run"})[1]
        self.prov.worker_start(task_id=task["id"], worktree="new-child", agent="claude", profile="rw")
        self.prov._spawn_process = real
        self.prov.backend = "setsid"
        real(**captured)  # writes run_worker.py (then launches a first copy without secrets)
        disp = captured["dispatch_id"]
        self.assertTrue(_wait_for(out.is_file, timeout=30))
        # Wait for the first monitor's FINAL write (the dispatch state) before re-arming, or its
        # late `died` lands after the re-arm and the launch gate rightly refuses the re-run.
        self.assertTrue(self.wait_monitor_done(disp))
        out.unlink(missing_ok=True)
        script = Path(captured["lane_dir"]) / "run_worker.py"
        # The first run finished (and was recorded); re-arm the dispatch for the inherited-env run.
        with self.prov.state._connect() as _c:
            _c.execute(
            "UPDATE dispatches SET state = 'ready' WHERE lane_dir = ?", (str(captured["lane_dir"]),))
        env = {**os.environ, "PATH": self.env["PATH"], "OPEN_FLEET_SIGNING_SEED": "aa" * 32,
               "ORCA_DISPATCH_SIGNING_SEED": "bb" * 32}
        subprocess.run([sys.executable, "-I", str(script)], env=env, cwd=captured["wt_path"], timeout=120)
        self.assertTrue(out.is_file(), "the re-run is synchronous: its agent has already written")
        self.assertEqual(out.read_text().strip(), "[][]")

    def test_vanished_monitor_is_detected_by_liveness_sweep(self):
        self.fake_agent("claude", "sleep 30")
        _, res = self.start()
        disp = res["dispatchId"]
        with self.prov.state._connect() as conn:
            pid = conn.execute("SELECT pid FROM dispatches WHERE dispatch_id = ?", (disp,)).fetchone()["pid"]
        self.assertGreater(pid, 0)
        os.killpg(pid, 9)
        self.assertTrue(_wait_for(lambda: self.prov.worker_show(disp)["worker"]["state"] == "died"))
        mail = self.prov.check_messages(terminal="coordinator")
        self.assertEqual(len([m for m in mail["messages"] if disp in m["subject"]]), 1)

    def test_setsid_input_is_refused_not_faked(self):
        self.fake_agent("claude", "sleep 5")
        _, res = self.start()
        with self.assertRaises(self.providers.ProviderError) as ctx:
            self.prov.terminal_send(res["agentTerminalHandle"], "hello")
        self.assertEqual(ctx.exception.code, "unsupported_operation")

    def test_cmux_send_ends_its_options_before_a_dash_leading_payload(self):
        # W2-01, cmux leg: `cmux send --workspace <id> <text>` puts the text in the last
        # positional, so a `-`-leading one is read as a flag. Recorded by a stand-in `cmux` (no
        # cmux here): a dash-leading payload rides after `--`; any other payload is unchanged.
        argv_log = Path(self.tmp.name) / "cmux-argv.jsonl"
        fake = self.bin / "cmux"
        fake.write_text(f"#!{sys.executable}\nimport json, sys\n"
                        f"open({str(argv_log)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n",
                        encoding="utf-8")
        fake.chmod(0o755)
        with self.prov.state._connect() as conn:
            conn.execute(
                "INSERT INTO terminals(handle, worktree, title, command, shell, pid, backend, backend_ref, log_path, state, created_at) "
                "VALUES ('term_cmux', '', 't', 'x', '/bin/sh', 0, 'cmux', 'ws1', '', 'running', 0)")
        with mock.patch.dict(os.environ, {"PATH": self.env["PATH"]}):
            for text in ("-R", "--help", "hello"):
                self.assertTrue(self.prov.terminal_send("term_cmux", text)["send"]["accepted"])
        sent = [json.loads(line) for line in argv_log.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(sent, [["send", "--workspace", "ws1", "--", "-R\n"],
                                ["send", "--workspace", "ws1", "--", "--help\n"],
                                ["send", "--workspace", "ws1", "hello\n"]])

    def _hermes_user_home(self, config_text):
        user_home = Path(self.tmp.name) / "hermes-user"
        user_home.mkdir(exist_ok=True)
        if config_text is not None:
            (user_home / "config.yaml").write_text(config_text, encoding="utf-8")
        (user_home / ".env").write_text("KEY=secret\n", encoding="utf-8")
        self.env["HERMES_HOME"] = str(user_home)
        self.prov = self.providers.get_provider("posix", env=self.env)
        return user_home

    def _run_fake_hermes(self):
        out = Path(self.tmp.name) / "hermes.txt"
        self.fake_agent("hermes", f'cat "$HERMES_HOME/config.yaml" > "{out}"; echo "ACCEPT=$HERMES_ACCEPT_HOOKS ENV=$(cat "$HERMES_HOME/.env")" >> "{out}"')
        _, res = self.start(agent="hermes")
        self.assertTrue(_wait_for(lambda: out.is_file() and "ACCEPT=" in out.read_text()))
        text = out.read_text()
        cfg = json.loads(text.split("ACCEPT=")[0])  # written as JSON: valid YAML, no emitter needed
        hook = cfg["hooks"]["pre_tool_call"][0]
        self.assertTrue(hook["fail_closed"])
        self.assertIn("ORCA_HOOK_STRICT_EXIT=1", hook["command"])
        self.assertIn(str(self.posix.CANONICAL_DENY_HOOK), hook["command"])
        self.assertIn("ACCEPT=1 ENV=KEY=secret", text)
        return cfg, res

    def test_hermes_gets_fail_closed_hook_in_private_home(self):
        # PyYAML present on the coordinator (stubbed: CI installs no test dependencies).
        stub = types.SimpleNamespace(safe_load=lambda t: json.loads(t) if t.strip() else None)
        user_home = self._hermes_user_home('{"model": "my-model", "hooks": {"pre_tool_call": [{"command": "mine"}]}}')
        with mock.patch.dict(sys.modules, {"yaml": stub}):
            cfg, res = self._run_fake_hermes()
        self.assertEqual(cfg["model"], "my-model", "user config preserved")
        self.assertEqual(cfg["hooks"]["pre_tool_call"][1], {"command": "mine"}, "user's own hooks kept, ours first")
        self.assertNotIn("deny-hook", (user_home / "config.yaml").read_text(), "user's own config untouched")
        self.assertFalse(str(Path(cfg["hooks"]["pre_tool_call"][0]["command"].split("sh ")[-1])).startswith(res["worker"]["worktree"]))

    def test_hermes_without_user_config_needs_no_yaml_parser(self):
        self._hermes_user_home(None)
        with mock.patch.dict(sys.modules, {"yaml": None}):  # `import yaml` raises ImportError
            cfg, _ = self._run_fake_hermes()
        self.assertEqual(list(cfg), ["hooks"])

    def test_hermes_config_parsed_with_hermes_own_interpreter(self):
        stubdir = Path(self.tmp.name) / "yamlstub"
        stubdir.mkdir()
        (stubdir / "yaml.py").write_text("import json\ndef safe_load(f):\n    return json.load(f)\n", encoding="utf-8")
        wrapper = Path(self.tmp.name) / "hermes-python"
        # Stands in for the venv Python Hermes ships with (which has PyYAML).
        wrapper.write_text(f'#!/bin/sh\n[ "$1" = "-I" ] && shift\nPYTHONPATH={stubdir} exec {sys.executable} "$@"\n', encoding="utf-8")
        wrapper.chmod(0o755)
        (self.bin / "hermes").write_text(f"#!{wrapper}\nprint('hermes')\n", encoding="utf-8")
        (self.bin / "hermes").chmod(0o755)
        cfg_file = Path(self.tmp.name) / "c.yaml"
        cfg_file.write_text('{"model": "via-hermes-python"}', encoding="utf-8")
        with mock.patch.dict(sys.modules, {"yaml": None}):
            loaded = self.posix._load_hermes_config(cfg_file, self.env)
        self.assertEqual(loaded, {"model": "via-hermes-python"})

    def test_hermes_with_a_config_and_no_parser_is_refused(self):
        self._hermes_user_home("model: my-model\n")
        self.fake_agent("hermes", "exit 0")  # a shell launcher: no Python to borrow PyYAML from
        task = self.prov.dispatch(["orchestration", "task-create", "--spec", "x"])["task"]
        with mock.patch.dict(sys.modules, {"yaml": None}):
            with self.assertRaises(self.providers.ProviderError) as ctx:
                self.prov.worker_start(task_id=task["id"], worktree="new-child", agent="hermes")
        self.assertEqual(ctx.exception.code, "hermes_hooks_unavailable")
        self.assertEqual(self.prov.task_list()["tasks"][0]["status"], "ready", "claim released")

    def test_missing_spec_is_refused_before_claim(self):
        task = self.prov.state.task_create(spec="")["task"]
        with self.assertRaises(self.providers.ProviderError) as ctx:
            self.prov.worker_start(task_id=task["id"], worktree="new-child", agent="claude")
        self.assertEqual(ctx.exception.code, "missing_task_spec")
        self.assertEqual(self.prov.task_list()["tasks"][0]["status"], "ready")

    def test_terminal_create_runs_and_exits_without_worker_died(self):
        t = self.prov.terminal_create(worktree="current", title="custom", command="echo hello-term")
        handle = t["terminal"]["handle"]
        self.assertTrue(_wait_for(lambda: self.prov.terminal_show(handle)["terminal"]["state"] == "exited"))
        self.assertIn("hello-term", "\n".join(self.prov.terminal_read(handle)["terminal"]["tail"]))
        self.assertEqual(self.prov.check_messages(terminal="coordinator")["count"], 0)


class TestTmuxWorkerLifecycle(PosixRealProcessBase):
    """The worker env travels inside the monitor script, so a tmux server that is ALREADY
    running (which ignores the client's env — the original bug) still hands it over."""

    backend = "tmux"

    def setUp(self):
        super().setUp()
        # The leak test reads OPENCODE_CONFIG_CONTENT, so only a WORKER's launch may put it there.
        # A shell that already exports it (a coordinator running inside OpenCode) hands it to every
        # worker as part of the coordinator's env, by design, and that read as "leaked" (2026-10-27).
        self.env.pop("OPENCODE_CONFIG_CONTENT", None)
        self.has_tmux = bool(shutil.which("tmux"))
        if not self.has_tmux:
            # No tmux on this host: exercise the same env-file mechanism through setsid.
            self.env["OPEN_FLEET_POSIX_BACKEND"] = "setsid"
        else:
            # A private socket dir and HOME: never the developer's own server (an inherited
            # $TMUX would point every tmux call, kill-server included, at it) or rc files.
            home = Path(self.tmp.name) / "home"
            home.mkdir()
            # The provider's own fence/liveness tmux calls read os.environ: patch it, restored.
            patcher = mock.patch.dict(os.environ, {"TMUX_TMPDIR": self.tmp.name})
            patcher.start()
            self.addCleanup(patcher.stop)
            for var in ("TMUX", "TMUX_PANE", "ZDOTDIR", "XDG_CONFIG_HOME"):
                self.env.pop(var, None)
                os.environ.pop(var, None)
            self.env.update({"TMUX_TMPDIR": self.tmp.name, "HOME": str(home)})
            # The pre-existing server's shell rewrites PATH the way a login rc does (zsh sources
            # ~/.zshenv even for `-c`; that put the developer's real `claude` first) and its own
            # PATH lacks the fake `bin`: an agent the provider lets resolve on either PATH hits
            # the tripwire and fails this test closed instead of running anything real.
            rc_shell = Path(self.tmp.name) / "rc-shell"
            rc_shell.write_text(f'#!/bin/sh\nPATH="{self.tripwire}:$PATH"; export PATH\nexec /bin/sh "$@"\n', encoding="utf-8")
            rc_shell.chmod(0o755)
            tmux_env = {k: v for k, v in self.env.items() if k != "PATH"}
            self.server_env = {
                **tmux_env,
                "SHELL": str(rc_shell),
                "PATH": os.pathsep.join([str(self.tripwire), os.environ.get("PATH", "")]),
            }
            subprocess.run(["tmux", "-f", os.devnull, "new-session", "-d", "-s", "preexisting"], env=self.server_env, check=True)
            self.addCleanup(lambda: subprocess.run(["tmux", "kill-server"], env=self.server_env, capture_output=True))
        self.prov = self.providers.get_provider("posix", env=self.env)

    def kill_tmux_server_and_wait(self):
        """`tmux kill-server` returns before the server has exited, and a client that connects in
        that window gets "server exited unexpectedly" (CI shard 6; 27 of 200 kill-then-new-session
        rounds under CPU load here, 0 of 200 once the old pid is awaited). Wait until it is gone."""
        pid = subprocess.run(["tmux", "display-message", "-p", "#{pid}"], env=self.server_env,
                             capture_output=True, text=True).stdout.strip()
        subprocess.run(["tmux", "kill-server"], env=self.server_env, capture_output=True)
        if pid.isdigit():
            self.assertTrue(_wait_for(lambda: _process_gone(int(pid))), "the old tmux server never exited")

    def test_env_survives_preexisting_tmux_server_and_stop_kills(self):
        out = Path(self.tmp.name) / "env.txt"
        self.fake_agent(
            "claude",
            f'echo "$OPEN_FLEET_DENY_HOOK|$OPEN_FLEET_SANDBOX_PROFILE" > "{out}"; trap "" HUP TERM; while :; do sleep 0.1; done',
        )
        _, res = self.start()
        _wait_for(lambda: out.is_file() or self.tripwire_log.exists())
        self.assertFalse(self.tripwire_log.exists(), "the agent resolved on the tmux SERVER's PATH, not the spawner's")
        self.assertTrue(_wait_for(out.is_file))
        hook, profile = out.read_text().strip().split("|")
        self.assertEqual(hook, str(self.posix.CANONICAL_DENY_HOOK))
        self.assertEqual(profile, "rw")
        with self.prov.state._connect() as conn:
            lane = Path(conn.execute("SELECT lane_dir FROM dispatches WHERE dispatch_id = ?", (res["dispatchId"],)).fetchone()["lane_dir"])
        env_file = lane / "worker_env.json"
        self.assertEqual(json.loads(env_file.read_text())["OPEN_FLEET_DENY_HOOK"], hook)
        self.assertEqual(json.loads(env_file.read_text())["PATH"], self.env["PATH"], "the spawner's PATH travels with the worker")
        self.assertEqual(env_file.stat().st_mode & 0o777, 0o600)
        self.prov.worker_fence("stop", res["dispatchId"])
        stamp = out.stat().st_mtime
        if self.has_tmux:
            sess = f"openfleet-{res['agentTerminalHandle']}"
            self.assertNotEqual(subprocess.run(["tmux", "has-session", "-t", sess], capture_output=True).returncode, 0)
        self.assertEqual(self.prov.worker_show(res["dispatchId"])["worker"]["state"], "stopped")
        self.assertEqual(out.stat().st_mtime, stamp)

    def test_the_tmux_send_argv_ends_options_before_a_dash_leading_payload(self):
        # W2-01, tmux-free half (re-attack P3): the provider's own send argv must put `--` before
        # the text, so a `-R`/`--help` payload is never read as a tmux flag. This fails on revert
        # even where tmux is absent, unlike the delivery half below.
        for text in ("-R", "--help", "plain"):
            self.assertEqual(self.posix.tmux_send_keys_argv("pane", text),
                             ["tmux", "send-keys", "-t", "pane", "-l", "--", text])
            argv = self.posix.tmux_send_keys_argv("pane", text)
            self.assertEqual(argv[argv.index("--") + 1], text, "the payload rides after `--`")

    def test_a_dash_leading_payload_arrives_and_is_never_read_as_a_flag(self):
        # W2-01: `tmux send-keys -l -R` parsed the text as -R (reset terminal), exited 0, and the
        # send was recorded as accepted with nothing delivered. This half needs a real pane; where
        # tmux is absent the revert-failing coverage is the argv test above (a floor_guard waiver
        # would be needed to skipUnless here, and the argv test already fails on revert everywhere).
        if not self.has_tmux:
            return
        got = Path(self.tmp.name) / "got.txt"
        reader = f"IFS= read -r line; printf '%s' \"$line\" > {shlex.quote(str(got))}"
        handle = self.prov.terminal_create(worktree="current", title="reader", command=reader)["terminal"]["handle"]
        sent = self.prov.dispatch(["terminal", "send", "--terminal", handle, "--text=-R"])
        self.assertTrue(sent["send"]["accepted"])
        self.assertTrue(_wait_for(got.is_file), "the reader never got a line")
        self.assertEqual(got.read_text(encoding="utf-8"), "-R", "the payload was eaten as a tmux flag")

    def test_a_server_the_spawn_starts_never_hands_one_workers_launch_env_to_the_next(self):
        """The first spawn into NO server starts one, and that client's env becomes the server's
        global env for every later session (2026-10-23 review, P1-11)."""
        if self.has_tmux:
            self.kill_tmux_server_and_wait()
        first = Path(self.tmp.name) / "first-up"
        out = Path(self.tmp.name) / "second.txt"
        self.fake_agent("opencode", f'touch "{first}"; trap "" HUP TERM; while :; do sleep 0.1; done')
        self.fake_agent("claude", f'echo "[$OPENCODE_CONFIG_CONTENT]" > "{out}"')
        self.start(agent="opencode")
        self.assertTrue(_wait_for(first.is_file), "the first worker never ran")
        self.start(agent="claude")
        self.assertTrue(_wait_for(out.is_file), "the second worker never ran")
        self.assertEqual(out.read_text().strip(), "[]", "the first worker's launch env leaked into the second")


class TestWorktreeSafety(PosixRealProcessBase):
    def test_hook_artifacts_are_git_excluded(self):
        wt = Path(self.prov.worktree_create("art")["worktree"]["path"])
        self.posix.install_worktree_hooks(wt, "claude", "rw")
        status = _git("status", "--porcelain", cwd=wt).stdout
        self.assertEqual(status.strip(), "", f"hook artifacts leak into git status: {status}")
        self.assertFalse((wt / ".open-fleet" / "hooks").exists())

    def test_rm_refuses_main_checkout_even_with_force_and_dotdot(self):
        with self.assertRaises(self.providers.ProviderError):
            self.prov.worktree_rm(f"path:{self.repo}/../{self.repo.name}", force=True)
        self.assertTrue((self.repo / "README.md").is_file())

    def test_rm_keeps_dirty_worktree_and_removes_clean_one(self):
        wt = Path(self.prov.worktree_create("dirty")["worktree"]["path"])
        self.posix.install_worktree_hooks(wt, "claude", "rw")
        (wt / "unsaved.txt").write_text("work", encoding="utf-8")
        with self.assertRaises(self.providers.ProviderError) as ctx:
            self.prov.worktree_rm(f"path:{wt}")
        self.assertEqual(ctx.exception.code, "worktree_dirty")
        self.assertTrue((wt / "unsaved.txt").is_file())
        (wt / "unsaved.txt").unlink()
        self.assertTrue(self.prov.worktree_rm(f"path:{wt}")["removed"], "hook artifacts alone must not count as dirty")

    def test_only_exact_generated_files_count_as_disposable(self):
        ext = importlib.import_module("runtime.providers._external")
        ov = importlib.import_module("runtime.providers.overstory")
        wt = Path(self.prov.worktree_create("exact")["worktree"]["path"])
        self.posix.install_worktree_hooks(wt, "claude", "rw")
        for rel in ("AGENTS.md", ".claude/CLAUDE.md", "AGENTS.md.backup", ".claude/commands/mine.md", ".codex/config.toml"):
            (wt / rel).parent.mkdir(parents=True, exist_ok=True)
            (wt / rel).write_text("x", encoding="utf-8")

        def run(argv):
            return subprocess.run(argv, capture_output=True, text=True).stdout

        dirty = ext.foreign_dirty_paths(run, str(wt), ov.OV_ARTIFACTS)
        self.assertIn("AGENTS.md.backup", dirty)
        self.assertIn(".claude/commands/mine.md", dirty)
        self.assertIn(".codex/config.toml", dirty, "a user file in .codex/ is never exempted (nor git-excluded)")
        self.assertNotIn("AGENTS.md", dirty)
        self.assertNotIn(".claude/CLAUDE.md", dirty)
        self.assertNotIn(".claude/settings.local.json", dirty)

    def test_rm_decides_linkedness_from_the_repo_not_the_worktree_pointer(self):
        # W4-08: `.git` inside the worktree is the worker's to rewrite. Deleted, it once steered a
        # forced removal onto the plain-directory rmtree branch, past the `git worktree remove` that
        # refuses it, leaving the repository's admin entry and branch registered to a tree that was
        # gone. The repository's own worktree list decides; git then refuses the broken pointer.
        wt = Path(self.prov.worktree_create("ptr")["worktree"]["path"])
        (wt / ".git").unlink()
        (wt / "junk.txt").write_text("x", encoding="utf-8")
        with self.assertRaises(self.providers.ProviderError) as ctx:
            self.prov.worktree_rm(f"path:{wt}", force=True)
        self.assertEqual(ctx.exception.code, "worktree_rm_failed")
        self.assertTrue((wt / "junk.txt").is_file(), "no rmtree fallback for a registered worktree")
        listed = _git("worktree", "list", "--porcelain", cwd=self.repo).stdout
        self.assertIn(f"worktree {wt}", listed)
        # A pointer rewritten to ANOTHER worktree's admin entry is refused by git's back-pointer
        # check, and neither worktree loses its registration (the finding's stated exploit).
        a = Path(self.prov.worktree_create("ptr-a")["worktree"]["path"])
        b = Path(self.prov.worktree_create("ptr-b")["worktree"]["path"])
        (a / ".git").write_text((b / ".git").read_text(encoding="utf-8"), encoding="utf-8")
        with self.assertRaises(self.providers.ProviderError):
            self.prov.worktree_rm(f"path:{a}", force=True)
        listed = _git("worktree", "list", "--porcelain", cwd=self.repo).stdout
        self.assertIn(f"worktree {a}", listed)
        self.assertIn(f"worktree {b}", listed)
        self.assertTrue(b.is_dir())

    def test_a_registered_worktree_under_a_quoted_path_is_still_recognised(self):
        # Codex round 2 (P1): `worktree list --porcelain` without -z C-quotes a path holding a
        # newline or backslash, so the parsed path matched nothing, the registered worktree looked
        # unregistered, and a forced removal of one with a deleted pointer reached rmtree again.
        odd = Path(self.tmp.name) / "st\nate\\x"
        prov = self.providers.get_provider("posix", env={**self.env, "OPEN_FLEET_STATE_DB": str(odd / "runtime.db")})
        wt = Path(prov.worktree_create("odd")["worktree"]["path"])
        self.assertIn("\n", str(wt))
        # A git-reported row carries its branch; the base-dir fallback row for the same dir does not.
        rows = prov.worktree_list()["worktrees"]
        self.assertTrue(any(Path(r["path"]) == wt and r.get("branch") == "fleet/odd" for r in rows),
                        f"worktree list reported a quoted path: {rows}")
        (wt / ".git").unlink()
        (wt / "junk.txt").write_text("x", encoding="utf-8")
        with self.assertRaises(self.providers.ProviderError) as ctx:
            prov.worktree_rm(f"path:{wt}", force=True)
        self.assertEqual(ctx.exception.code, "worktree_rm_failed")
        self.assertTrue((wt / "junk.txt").is_file(), "a registered worktree went to rmtree")

    def test_a_registered_worktree_under_any_byte_path_is_still_recognised(self):
        # Codex round 3 (P1): `-z` kept the list raw, but _git decoded it as text, which turns a
        # `\r` or `\r\n` into `\n` (and dies on a non-UTF-8 byte), so the parsed path matched
        # nothing and a forced removal of a registered worktree with a deleted pointer reached
        # rmtree. Every byte a POSIX path may hold must come back as the same path.
        for name in ("cr\rstate", "crlf\r\nstate", os.fsdecode(b"bytes\xff\xfestate"), "tab\tback\\slash"):
            with self.subTest(name=name):
                odd = Path(self.tmp.name) / name
                prov = self.providers.get_provider("posix", env={**self.env, "OPEN_FLEET_STATE_DB": str(odd / "runtime.db")})
                wt = Path(prov.worktree_create(f"odd{len(name)}")["worktree"]["path"])
                rows = prov.worktree_list()["worktrees"]
                self.assertTrue(any(Path(r["path"]) == wt and r.get("branch") == f"fleet/odd{len(name)}" for r in rows),
                                f"worktree list reported a mangled path: {rows}")
                (wt / ".git").unlink()
                (wt / "junk.txt").write_text("x", encoding="utf-8")
                with self.assertRaises(self.providers.ProviderError) as ctx:
                    prov.worktree_rm(f"path:{wt}", force=True)
                self.assertEqual(ctx.exception.code, "worktree_rm_failed")
                self.assertTrue((wt / "junk.txt").is_file(), "a registered worktree went to rmtree")

    def test_rm_keeps_a_worktree_holding_a_checked_out_submodule(self):
        # Codex round 3: the clean check is no longer git's own (an unforced `worktree remove` runs
        # `status` under the repository's config), so its refusal of a checked-out submodule, whose
        # unsaved work no coordinator `status` inspects, is the custody's to keep.
        sub = Path(self.tmp.name) / "sub"
        sub.mkdir()
        _git("init", "-q", "-b", "main", cwd=sub)
        _git("-c", "user.email=t@e", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "s", cwd=sub)
        wt = Path(self.prov.worktree_create("withsub")["worktree"]["path"])
        _git("-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "sm", cwd=wt)
        _git("commit", "-qm", "sm", cwd=wt)
        (wt / "sm" / "unsaved.txt").write_text("work", encoding="utf-8")
        with self.assertRaises(self.providers.ProviderError) as ctx:
            self.prov.worktree_rm(f"path:{wt}")
        self.assertEqual(ctx.exception.code, "worktree_dirty")
        self.assertIn("submodules", ctx.exception.message)
        self.assertTrue((wt / "sm" / "unsaved.txt").is_file())
        self.assertTrue(self.prov.worktree_rm(f"path:{wt}", force=True)["removed"])
        self.assertFalse(wt.exists())

    def test_rm_refuses_when_the_worktree_list_cannot_be_read(self):
        # W4-08 review (PR #720): with the repository's worktree list unreadable (a malformed shared
        # config makes git die), an empty answer read as "not registered" and a registered worktree
        # whose pointer was deleted went to rmtree again. Unreadable is a refusal, forced or not.
        wt = Path(self.prov.worktree_create("unreadable")["worktree"]["path"])
        (wt / ".git").unlink()
        (wt / "junk.txt").write_text("x", encoding="utf-8")
        with open(self.repo / ".git" / "config", "a", encoding="utf-8") as fh:
            fh.write("[core\n\tbroken = = =\n")
        for force in (False, True):
            with self.subTest(force=force):
                with self.assertRaises(self.providers.ProviderError) as ctx:
                    self.prov.worktree_rm(f"path:{wt}", force=force)
                self.assertEqual(ctx.exception.code, "worktree_list_unreadable")
                self.assertTrue((wt / "junk.txt").is_file(), "the tree went to rmtree")
        self.assertTrue((self.repo / ".git" / "worktrees" / "unreadable").is_dir(), "admin entry kept")

    def test_rm_refuses_paths_outside_provider_base(self):
        stray = Path(self.tmp.name) / "stray"
        stray.mkdir()
        (stray / "keep").write_text("x", encoding="utf-8")
        with self.assertRaises(self.providers.ProviderError):
            self.prov.worktree_rm(f"path:{stray}", force=True)
        self.assertTrue((stray / "keep").exists())

    def test_create_never_resets_existing_branch(self):
        wt = Path(self.prov.worktree_create("keep")["worktree"]["path"])
        (wt / "f.txt").write_text("1", encoding="utf-8")
        _git("add", "f.txt", cwd=wt)
        _git("commit", "-qm", "unit work", cwd=wt)
        head = _git("rev-parse", "HEAD", cwd=wt).stdout.strip()
        _git("worktree", "remove", str(wt), cwd=self.repo)
        again = Path(self.prov.worktree_create("keep")["worktree"]["path"])
        self.assertEqual(_git("rev-parse", "HEAD", cwd=again).stdout.strip(), head)

    def test_create_refuses_stale_non_worktree_dir(self):
        base = self.prov._worktree_base_dir() / "stale"
        base.mkdir(parents=True)
        with self.assertRaises(self.providers.ProviderError):
            self.prov.worktree_create("stale")

    def test_bad_base_raises(self):
        with self.assertRaises(self.providers.ProviderError) as ctx:
            self.prov.worktree_create("bad", base="no-such-ref")
        self.assertEqual(ctx.exception.code, "worktree_create_failed")

    def test_a_dash_leading_base_is_a_commit_ish_never_an_option(self):
        # W2-04: `worktree add -b <br> <path> --force` read the base as a flag and created the
        # worktree at HEAD — the requested base silently became a different answer.
        for base in ("--force", "--lock"):
            with self.subTest(base=base):
                with self.assertRaises(self.providers.ProviderError) as ctx:
                    self.prov.worktree_create(f"dash{base}", base=base)
                self.assertEqual(ctx.exception.code, "worktree_create_failed")
                self.assertIn("invalid reference", ctx.exception.message)
                self.assertFalse((self.prov._worktree_base_dir() / f"dash{base}").exists())


class TestCoordinatorGitRunsNothingTheRepoNames(PosixRealProcessBase):
    """W4-01 (P0): the provider's own git — `worktree add`/`remove`, the sandbox seed and sync —
    runs as the COORDINATOR over the shared `.git/config` a worker writes with one plain
    `git config` (linked worktrees share it), and over the same-uid `~/.gitconfig`. No hook,
    fsmonitor or attribute-selected filter planted there may run. Every probe only appends its
    channel name to a marker in this test's temp dir; GREEN = the marker never appears."""

    def setUp(self):
        super().setUp()
        self.base = Path(self.tmp.name)
        self.marker = self.base / "pwned"
        (self.repo / "a.txt").write_text("a\n", encoding="utf-8")
        _git("add", "a.txt", cwd=self.repo)
        _git("commit", "-qm", "a", cwd=self.repo)

    def probe(self, channel, passthrough=True):
        return f"sh -c 'echo {channel} >> {shlex.quote(str(self.marker))}" + ("; cat'" if passthrough else "'")

    def hooks_dir(self, name):
        hooks = self.base / name
        hooks.mkdir()
        for hook in ("post-checkout", "reference-transaction", "post-index-change"):
            (hooks / hook).write_text(f"#!/bin/sh\necho hook-{hook} >> {shlex.quote(str(self.marker))}\n",
                                      encoding="utf-8")
            (hooks / hook).chmod(0o755)
        return hooks

    def config_file(self, name, pairs):
        """A standalone config file, written by `git config -f` so each value is quoted as git
        reads it back (a hand-written `;` would start a comment and cut the probe short)."""
        path = self.base / name
        for key, value in pairs:
            _git("config", "-f", str(path), key, value, cwd=self.base)
        return path

    def plant_repo(self):
        """What a worker does in its own worktree: config lands in the SHARED `.git/config`. The
        test's own git never touches the repo after this (a bare `git` would run the plants)."""
        inc = self.config_file("linked-only.gitconfig", (("filter.inc.smudge", self.probe("inc-smudge")),
                                                         ("filter.inc.clean", self.probe("inc-clean"))))
        for key, value in (("core.hooksPath", str(self.hooks_dir("evilhooks"))),
                           ("core.fsmonitor", self.probe("fsmonitor", passthrough=False)),
                           ("filter.evil.smudge", self.probe("smudge")),
                           ("filter.evil.clean", self.probe("clean")),
                           # Declared only where git runs IN a linked worktree: the drivers must
                           # be read there, not in the main checkout.
                           ("includeIf.gitdir:**/worktrees/**.path", str(inc))):
            _git("config", key, value, cwd=self.repo)
        (self.repo / ".git" / "info").mkdir(exist_ok=True)
        (self.repo / ".git" / "info" / "attributes").write_text("* filter=evil\nREADME.md filter=inc\n",
                                                                 encoding="utf-8")

    def fired(self):
        return sorted(set(self.marker.read_text().split())) if self.marker.exists() else []

    def test_worktree_create_runs_no_planted_hook_fsmonitor_or_filter(self):
        self.plant_repo()
        wt = Path(self.prov.worktree_create("victim")["worktree"]["path"])
        self.assertEqual(self.fired(), [], "the coordinator's worktree add ran a repo-planted command")
        self.assertEqual((wt / "a.txt").read_text(encoding="utf-8"), "a\n", "checked out raw, unsmudged")
        self.assertEqual((wt / "README.md").read_text(encoding="utf-8"), "# r\n")
        self.assertTrue((wt / ".git").is_file())

    def test_worktree_rm_runs_no_planted_fsmonitor_or_clean_filter(self):
        wt = Path(self.prov.worktree_create("victim")["worktree"]["path"])
        self.plant_repo()
        later = time.time() + 5
        os.utime(wt / "a.txt", (later, later))  # stat changed: the clean check re-reads it
        self.assertTrue(self.prov.worktree_rm(f"path:{wt}")["removed"])
        self.assertEqual(self.fired(), [], "the coordinator's worktree remove ran a repo-planted command")
        self.assertFalse(wt.exists())

    def test_the_same_uid_global_config_is_never_read(self):
        (self.repo / ".gitattributes").write_text("a.txt filter=glob\n", encoding="utf-8")
        _git("add", ".gitattributes", cwd=self.repo)
        _git("commit", "-qm", "attrs", cwd=self.repo)
        glob = self.config_file("worker-written.gitconfig", (
            ("core.hooksPath", str(self.hooks_dir("globalhooks"))),
            ("filter.glob.smudge", self.probe("global-smudge")),
            ("filter.glob.clean", self.probe("global-clean"))))
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(glob)}):
            wt = Path(self.prov.worktree_create("victim")["worktree"]["path"])
            self.assertEqual(self.fired(), [], "worktree add read the worker-writable global config")
            lane = self.base / "lane"
            lane.mkdir()
            self.posix.prepare_sandbox_git(str(wt), lane)
        self.assertEqual(self.fired(), [], "the sandbox seed's index refresh ran a global clean filter")

    def test_a_git_call_made_without_blanks_still_runs_no_planted_filter(self):
        # A future content call written without `blanks=` must not reopen W4-01. A content call
        # the custody runs in its own git dir (`status`, located by `-C`/cwd or by
        # `--git-dir`/`--work-tree`) runs nothing; one it does not (`commit -a`, `checkout`,
        # `reset --hard`) is refused, never run (Codex round 3: blanking enumerated names left a race).
        wt = Path(self.prov.worktree_create("noblanks")["worktree"]["path"])
        admin = self.repo / ".git" / "worktrees" / "noblanks"
        for key, value in (("user.email", "t@e"), ("user.name", "t")):
            _git("config", key, value, cwd=self.repo)
        self.plant_repo()
        (wt / "a.txt").write_text("changed\n", encoding="utf-8")
        calls = ((["commit", "-qam", "w"], {"cwd": wt}, False),
                 (["checkout", "--", "a.txt"], {"cwd": wt}, False),
                 (["--git-dir", str(admin), "--work-tree", str(wt), "reset", "--hard", "-q"], {}, False),
                 (["status", "--porcelain"], {"cwd": wt}, True),
                 (["--git-dir", str(admin), "--work-tree", str(wt), "status", "--porcelain"], {}, True))
        for args, kw, runs in calls:
            with self.subTest(args=args[:3]):
                proc = self.posix._git(args, **kw)
                self.assertEqual(proc.returncode == 0, runs, proc.stderr)
                self.assertEqual(proc.stdout, " M a.txt\n" if runs else "")
                self.assertEqual(self.fired(), [], f"_git {args[0]} ran a planted command without blanks=")
        self.assertEqual((wt / "a.txt").read_text(encoding="utf-8"), "changed\n")

    def test_a_supplied_env_cannot_point_git_at_a_repository_never_enumerated(self):
        # Codex round 2 (P2): the drivers were listed where `-C`/cwd/`--git-dir` points, but a
        # caller-supplied GIT_DIR (or GIT_WORK_TREE, GIT_COMMON_DIR, GIT_INDEX_FILE, GIT_CONFIG*)
        # made the call read ANOTHER repository, whose smudge filter then ran unblanked.
        wt = Path(self.prov.worktree_create("envsel")["worktree"]["path"])
        other = self.base / "other"
        other.mkdir()
        _git("init", "-q", "-b", "main", cwd=other)
        (other / "a.txt").write_text("other\n", encoding="utf-8")
        _git("add", "a.txt", cwd=other)
        _git("-c", "user.email=t@e", "-c", "user.name=t", "commit", "-qm", "o", cwd=other)
        _git("config", "filter.evil.smudge", self.probe("other-smudge"), cwd=other)
        (other / ".git" / "info").mkdir(exist_ok=True)
        (other / ".git" / "info" / "attributes").write_text("* filter=evil\n", encoding="utf-8")
        for var, value in (("GIT_DIR", str(other / ".git")), ("GIT_COMMON_DIR", str(other / ".git")),
                           ("GIT_INDEX_FILE", str(other / ".git" / "index"))):
            with self.subTest(var=var):
                later = time.time() + 5
                os.utime(wt / "a.txt", (later, later))  # stat changed: the status re-reads it
                proc = self.posix._git(["status", "--porcelain"], cwd=wt, env={**os.environ, var: value})
                self.assertEqual(self.fired(), [], f"a supplied {var} ran another repository's filter")
                self.assertEqual(proc.returncode, 0, proc.stderr)
                # Clean against wt's own HEAD ("a\n"); against `other` it would be ` M a.txt`.
                self.assertEqual(proc.stdout, "", "read from wt's own repo")
                self.assertEqual((wt / "a.txt").read_text(encoding="utf-8"), "a\n")

    def test_no_bare_git_argv_is_left_in_the_provider(self):
        # Every git the provider (and the monitor script it generates) runs goes through _git, so
        # through gitexec's absolute git and floor; a literal `["git", ...]` argv is the bypass.
        src = Path(self.posix.__file__).read_text(encoding="utf-8")
        self.assertEqual(re.findall(r'\[\s*"git"\s*,', src), [])


def racing_sibling(case, repo, git):
    """Patch subprocess.run so that a sibling worker adds a NEVER-SEEN driver to the shared config,
    and selects it for every path through the shared `info/attributes`, immediately before EVERY
    launch of `git` (the custody's absolute git): after any listing of the declared drivers and
    before the command reads its config. Codex round 3 (P1): enumerating names cannot close this."""
    real = subprocess.run
    seq = case.__dict__.setdefault("_race_seq", [0])  # a name no earlier race declared either
    common = repo / ".git"
    (common / "info").mkdir(exist_ok=True)

    def quoted(cmd):
        return '"' + cmd.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def run(argv, *a, **kw):
        if isinstance(argv, (list, tuple)) and argv and argv[0] == git:
            seq[0] += 1
            name = f"fresh{seq[0]}"
            with open(common / "config", "a", encoding="utf-8") as fh:
                fh.write(f'[filter "{name}"]\n\tsmudge = {quoted(case.probe(name + "-smudge"))}\n'
                         f'\tclean = {quoted(case.probe(name + "-clean"))}\n'
                         f'[diff "{name}"]\n\ttextconv = {quoted(case.probe(name + "-textconv", passthrough=False))}\n'
                         f'[merge "{name}"]\n\tdriver = {quoted(case.probe(name + "-merge", passthrough=False))}\n')
            with open(common / "info" / "attributes", "a", encoding="utf-8") as fh:
                fh.write(f"* filter={name} diff={name} merge={name}\n")
        return real(argv, *a, **kw)

    return mock.patch.object(subprocess, "run", run)


class TestCoordinatorGitRunsNoDriverAddedMidCall(PosixRealProcessBase):
    """Codex round 3 (P1): the drivers were listed, then the command ran, and a sibling worker that
    adds a NEW `filter.<name>.smudge` in between (selected through the shared `info/attributes`)
    had it run as the coordinator. Every coordinator git that could apply an attribute-selected
    driver must read a config no worker can write; anything else is refused. Each scenario ends
    with a bare-git control under the same race, which DOES fire: the plant is live."""

    probe = TestCoordinatorGitRunsNothingTheRepoNames.probe
    fired = TestCoordinatorGitRunsNothingTheRepoNames.fired

    def setUp(self):
        super().setUp()
        self.base = Path(self.tmp.name)
        self.marker = self.base / "pwned"
        (self.repo / "a.txt").write_text("a\n", encoding="utf-8")
        _git("add", "a.txt", cwd=self.repo)
        _git("commit", "-qm", "a", cwd=self.repo)
        self.clean_env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}

    def race(self):
        return racing_sibling(self, self.repo, self.posix.gitexec.GIT)

    def control(self, *args, cwd):
        """The same kind of call with a bare git, under the race: the planted driver runs."""
        with self.race():
            subprocess.run([self.posix.gitexec.GIT, *args], cwd=cwd, env=self.clean_env, capture_output=True)
        self.assertNotEqual(self.fired(), [], f"control `git {' '.join(args)}` ran no planted driver: the race is not live")

    def test_worktree_create_runs_no_driver_added_after_any_listing(self):
        with self.race():
            wt = Path(self.prov.worktree_create("race")["worktree"]["path"])
        self.assertEqual(self.fired(), [], "the coordinator's checkout ran a driver a sibling added mid-call")
        self.assertEqual((wt / "a.txt").read_text(encoding="utf-8"), "a\n")
        self.assertEqual(_git("status", "--porcelain", cwd=wt, env=self.clean_env).stdout, "", "index matches the checkout")
        self.marker.unlink(missing_ok=True)
        (wt / "a.txt").unlink()
        self.control("reset", "--hard", "-q", cwd=wt)

    def test_worktree_rm_runs_no_driver_added_after_any_listing(self):
        wt = Path(self.prov.worktree_create("race-rm")["worktree"]["path"])
        other = Path(self.prov.worktree_create("race-ctl")["worktree"]["path"])
        later = time.time() + 5
        for tree in (wt, other):
            os.utime(tree / "a.txt", (later, later))  # stat changed: a clean check re-reads it
        with self.race():
            self.assertTrue(self.prov.worktree_rm(f"path:{wt}")["removed"])
        self.assertEqual(self.fired(), [], "the coordinator's clean check ran a driver a sibling added mid-call")
        self.assertFalse(wt.exists())
        self.control("status", "--porcelain", cwd=other)

    def test_a_dirty_worktree_is_still_refused_under_the_race(self):
        wt = Path(self.prov.worktree_create("race-dirty")["worktree"]["path"])
        (wt / "a.txt").write_text("unsaved\n", encoding="utf-8")
        with self.race():
            with self.assertRaises(self.providers.ProviderError) as ctx:
                self.prov.worktree_rm(f"path:{wt}")
        self.assertEqual(ctx.exception.code, "worktree_dirty")
        self.assertEqual(self.fired(), [])
        self.assertEqual((wt / "a.txt").read_text(encoding="utf-8"), "unsaved\n")

    def test_sandbox_seed_and_sync_run_no_driver_added_after_any_listing(self):
        wt = Path(self.prov.worktree_create("race-sbx")["worktree"]["path"])
        lane = self.base / "lane"
        lane.mkdir()
        later = time.time() + 5
        os.utime(wt / "a.txt", (later, later))
        with self.race():
            meta = self.posix.prepare_sandbox_git(str(wt), lane)
        self.assertEqual(self.fired(), [], "the sandbox seed ran a driver a sibling added mid-call")
        cenv = {**self.clean_env, "GIT_DIR": meta["sandbox_git"], "GIT_WORK_TREE": str(wt),
                "GIT_AUTHOR_NAME": "w", "GIT_AUTHOR_EMAIL": "w@x", "GIT_COMMITTER_NAME": "w", "GIT_COMMITTER_EMAIL": "w@x"}
        (wt / "feature.txt").write_text("done\n", encoding="utf-8")
        subprocess.run(["git", "add", "feature.txt"], cwd=wt, env=cenv, check=True)
        subprocess.run(["git", "commit", "-qm", "feature"], cwd=wt, env=cenv, check=True)
        os.utime(wt / "a.txt", (later + 5, later + 5))
        with self.race():
            res = self.posix.sync_sandbox_git(meta, "disp_race")
        self.assertTrue(res["branchUpdated"])
        self.assertEqual(self.fired(), [], "the host-side sync ran a driver a sibling added mid-call")
        self.control("status", "--porcelain", cwd=wt)

    def test_a_driver_applying_command_outside_the_custody_is_refused(self):
        # Fail closed: a subcommand that could apply a driver and that the custody does not run in
        # its own git dir is refused, not run; a future `commit`/`checkout`/`diff` cannot reopen it.
        wt = Path(self.prov.worktree_create("race-refuse")["worktree"]["path"])
        (wt / "a.txt").write_text("unsaved\n", encoding="utf-8")
        refused = (["commit", "-qam", "w"], ["checkout", "--", "a.txt"], ["diff"], ["reset", "-q"], ["reset", "--hard"],
                   ["add", "-A"], ["stash"], ["update-index", "-q", "--refresh"], ["read-tree", "-m", "-u", "HEAD"],
                   ["checkout-index", "-a", "-f"], ["archive", "HEAD"], ["cat-file", "--filters", "HEAD:a.txt"],
                   ["worktree", "add", str(self.base / "full"), "HEAD"], ["worktree", "remove", "--", str(wt)],
                   ["clone", str(self.repo), str(self.base / "clone")], ["log", "-p", "-1"], ["-c", "x.y=z", "status"])
        with self.race():
            for args in refused:
                with self.subTest(args=args):
                    proc = self.posix._git(args, cwd=wt)
                    self.assertNotEqual(proc.returncode, 0, f"`git {' '.join(args)}` ran")
                    self.assertIn("custody", proc.stderr)
        self.assertEqual(self.fired(), [], "a refused command ran a planted driver")
        self.assertEqual((wt / "a.txt").read_text(encoding="utf-8"), "unsaved\n")
        self.assertFalse((self.base / "full").exists())
        self.assertTrue(wt.is_dir())


class TestCustodyStatusMatchesTheRepo(PosixRealProcessBase):
    """Codex round 4 (P2): the custody git dir must give the repository's own clean/dirty verdict,
    so a clean worktree removes without --force. It copies the shared index, honours the repo's
    data-only settings (filemode, ignorecase, sparse, object format) and its `info/exclude`, and
    refuses an `extensions.*` it cannot honour (a planted partial clone) rather than guess."""

    def _provider_on(self, repo):
        db = Path(self.tmp.name) / f"state-{repo.name}" / "runtime.db"
        return self.providers.get_provider("posix", env={**self.env, "OPEN_FLEET_CLI_CWD": str(repo),
                                                         "OPEN_FLEET_REPO_ROOT": str(repo), "OPEN_FLEET_STATE_DB": str(db)})

    def _clean_removes(self, prov, name, prepare):
        wt = Path(prov.worktree_create(name)["worktree"]["path"])
        prepare(wt)
        self.assertEqual(_git("status", "--porcelain", cwd=wt).stdout, "", f"{name}: the tree really is clean to git")
        self.assertTrue(prov.worktree_rm(f"path:{wt}")["removed"], f"{name}: a clean worktree read dirty")

    def test_a_split_index_worktree_reads_clean(self):
        def prep(wt):
            _git("update-index", "--split-index", cwd=wt)
            self.assertTrue(any(c.name.startswith("sharedindex.")
                                for c in (self.repo / ".git" / "worktrees" / "split").iterdir()))
            later = time.time() + 5
            os.utime(wt / "README.md", (later, later))  # stat dirty: a status that cannot load the shared index dies
        self._clean_removes(self.prov, "split", prep)

    def test_a_filemode_false_worktree_ignores_an_exec_bit_change(self):
        _git("config", "core.filemode", "false", cwd=self.repo)
        self._clean_removes(self.prov, "fmode", lambda wt: os.chmod(wt / "README.md", 0o755))

    def test_an_info_exclude_ignored_untracked_file_reads_clean(self):
        with open(self.repo / ".git" / "info" / "exclude", "a", encoding="utf-8") as fh:
            fh.write("ignored-*.tmp\n")
        self._clean_removes(self.prov, "excl", lambda wt: (wt / "ignored-1.tmp").write_text("x", encoding="utf-8"))

    def test_a_sparse_checkout_worktree_reads_clean(self):
        for d in ("keep", "drop"):
            (self.repo / d).mkdir()
            (self.repo / d / "f.txt").write_text(f"{d}\n", encoding="utf-8")
        _git("add", "-A", cwd=self.repo)
        _git("commit", "-qm", "two", cwd=self.repo)

        def prep(wt):
            _git("sparse-checkout", "init", "--cone", cwd=wt)
            _git("sparse-checkout", "set", "keep", cwd=wt)
            self.assertFalse((wt / "drop").exists(), "sparse really dropped the directory")
        self._clean_removes(self.prov, "sparse", prep)

    def test_a_sha256_worktree_reads_clean(self):
        repo = Path(self.tmp.name) / "repo256"
        _git("init", "-q", "-b", "main", "--object-format=sha256", str(repo), cwd=Path(self.tmp.name))
        _git("config", "user.email", "t@e", cwd=repo)
        _git("config", "user.name", "t", cwd=repo)
        (repo / "a.txt").write_text("a\n", encoding="utf-8")
        _git("add", "a.txt", cwd=repo)
        _git("commit", "-qm", "init", cwd=repo)
        prov = self._provider_on(repo)
        wt = Path(prov.worktree_create("s256")["worktree"]["path"])
        self.assertEqual((wt / "a.txt").read_text(encoding="utf-8"), "a\n", "sha256 worktree checked out")
        self.assertTrue(prov.worktree_rm(f"path:{wt}")["removed"], "a clean sha256 worktree read dirty")

    def test_a_planted_unhonourable_extension_is_refused_not_guessed(self):
        wt = Path(self.prov.worktree_create("pc")["worktree"]["path"])
        _git("config", "extensions.partialClone", "origin", cwd=self.repo)
        _git("config", "core.repositoryformatversion", "1", cwd=self.repo)
        with self.assertRaises(self.providers.ProviderError) as ctx:
            self.prov.worktree_rm(f"path:{wt}")
        self.assertEqual(ctx.exception.code, "worktree_rm_failed")
        self.assertTrue(wt.is_dir(), "the worktree was neither removed nor its state guessed")


class TestSandboxGitRoundTrip(PosixRealProcessBase):
    """The container's private git dir: commits reach the host, the host repo stays untouched."""

    def _sandbox(self):
        wt = Path(self.prov.worktree_create("sbx")["worktree"]["path"])
        lane = Path(self.tmp.name) / "lane"
        lane.mkdir()
        meta = self.posix.prepare_sandbox_git(str(wt), lane)
        cenv = {**os.environ, "GIT_DIR": meta["sandbox_git"], "GIT_WORK_TREE": str(wt),
                "GIT_AUTHOR_NAME": "w", "GIT_AUTHOR_EMAIL": "w@x", "GIT_COMMITTER_NAME": "w", "GIT_COMMITTER_EMAIL": "w@x"}
        return wt, meta, cenv

    def test_commit_inside_sandbox_reaches_host_branch(self):
        wt, meta, cenv = self._sandbox()
        self.assertTrue((wt / ".git").is_file(), "host pointer untouched")
        (wt / "feature.txt").write_text("done\n", encoding="utf-8")
        subprocess.run(["git", "add", "feature.txt"], cwd=wt, env=cenv, check=True)
        subprocess.run(["git", "commit", "-qm", "feature"], cwd=wt, env=cenv, check=True)
        new = subprocess.run(["git", "rev-parse", "HEAD"], cwd=wt, env=cenv, check=True, capture_output=True, text=True).stdout.strip()
        res = self.posix.sync_sandbox_git(meta, "disp_x")
        self.assertEqual(res["head"], new)
        self.assertTrue(res["branchUpdated"])
        self.assertEqual(_git("rev-parse", "refs/heads/fleet/sbx", cwd=self.repo).stdout.strip(), new)
        self.assertEqual(_git("rev-parse", "refs/open-fleet/sandbox/disp_x", cwd=self.repo).stdout.strip(), new)
        self.assertEqual(_git("status", "--porcelain", cwd=wt).stdout.strip(), "", "host index refreshed")
        _git("merge-base", "--is-ancestor", "main", new, cwd=self.repo)

    def test_planted_hooks_and_config_are_stripped_before_host_reads(self):
        wt, meta, cenv = self._sandbox()
        sb = Path(meta["sandbox_git"])
        pwned = Path(self.tmp.name) / "pwned"
        (sb / "hooks").mkdir(exist_ok=True)
        for hook in ("post-checkout", "reference-transaction", "pre-auto-gc"):
            (sb / "hooks" / hook).write_text(f"#!/bin/sh\ntouch {pwned}\n", encoding="utf-8")
            (sb / "hooks" / hook).chmod(0o755)
        with open(sb / "config", "a", encoding="utf-8") as fh:
            fh.write(f"[core]\n\tfsmonitor = touch {pwned}\n\thooksPath = {sb / 'hooks'}\n")
        self.posix.sync_sandbox_git(meta, "disp_y")
        self.assertFalse(pwned.exists(), "host git executed sandbox-planted code")
        self.assertFalse((sb / "hooks").exists())

    def test_sync_runs_nothing_the_shared_host_config_plants(self):
        # W4-01: the sync's host-side `reset` reads the SHARED `.git/config` (the worktree's admin
        # dir resolves to it), which the worker can write from its own worktree.
        wt, meta, cenv = self._sandbox()
        (wt / "feature.txt").write_text("done\n", encoding="utf-8")
        subprocess.run(["git", "add", "feature.txt"], cwd=wt, env=cenv, check=True)
        subprocess.run(["git", "commit", "-qm", "feature"], cwd=wt, env=cenv, check=True)
        pwned = Path(self.tmp.name) / "pwned"
        probe = f"sh -c 'echo x >> {shlex.quote(str(pwned))}; cat'"
        for key, value in (("core.fsmonitor", f"sh -c 'echo x >> {shlex.quote(str(pwned))}'"),
                           ("filter.evil.clean", probe), ("filter.evil.smudge", probe)):
            _git("config", key, value, cwd=self.repo)
        (self.repo / ".git" / "info").mkdir(exist_ok=True)
        (self.repo / ".git" / "info" / "attributes").write_text("* filter=evil\n", encoding="utf-8")
        later = time.time() + 5
        os.utime(wt / "README.md", (later, later))
        res = self.posix.sync_sandbox_git(meta, "disp_p")
        self.assertTrue(res["branchUpdated"])
        self.assertFalse(pwned.exists(), "the host-side sync ran a command the shared config names")

    def test_sync_fetch_runs_no_command_the_shared_config_names_for_its_transport(self):
        # Codex round 3 sweep: the sync's `fetch` reads the SHARED config. A fixed key the floor did
        # not override (`core.alternateRefsCommand`, run for an alternate the worker plants) ran as
        # the coordinator, and so did a name-indexed `url.<base>.insteadOf` that turned the
        # sandbox path into `ssh://` (running `core.sshCommand`) or `<helper>::` (`git-remote-*`).
        pwned = Path(self.tmp.name) / "pwned"
        probe = f"sh -c 'echo x >> {shlex.quote(str(pwned))}; exit 1'"
        alt = Path(self.tmp.name) / "alt"
        _git("init", "-q", "--bare", str(alt), cwd=Path(self.tmp.name))
        helper = self.bin / "git-remote-evil"
        helper.write_text(f"#!/bin/sh\necho helper >> {shlex.quote(str(pwned))}\nexit 1\n", encoding="utf-8")
        helper.chmod(0o755)
        wt, meta, cenv = self._sandbox()
        for n, plant in enumerate(("alternates", "ssh", "helper")):
            with self.subTest(plant=plant):
                (wt / f"f{n}.txt").write_text("done\n", encoding="utf-8")
                subprocess.run(["git", "add", f"f{n}.txt"], cwd=wt, env=cenv, check=True)
                subprocess.run(["git", "commit", "-qm", f"f{n}"], cwd=wt, env=cenv, check=True)
                if plant == "alternates":
                    (self.repo / ".git" / "objects" / "info" / "alternates").write_text(f"{alt}/objects\n", encoding="utf-8")
                    _git("config", "core.alternateRefsCommand", probe, cwd=self.repo)
                else:
                    target = "ssh://evil.invalid/x" if plant == "ssh" else "evil::x"
                    scheme = "ssh" if plant == "ssh" else "evil"
                    _git("config", f"url.{target}.insteadOf", meta["sandbox_git"], cwd=self.repo)
                    _git("config", "core.sshCommand", probe, cwd=self.repo)
                    # Codex round 4: a per-protocol allow beats the generic `protocol.allow=never`,
                    # so the floor must not rely on config precedence (GIT_ALLOW_PROTOCOL does not).
                    _git("config", f"protocol.{scheme}.allow", "always", cwd=self.repo)
                with mock.patch.dict(os.environ, {"PATH": self.env["PATH"]}):
                    try:
                        res = self.posix.sync_sandbox_git(meta, f"disp_t{n}")
                    except self.providers.ProviderError as exc:
                        # A rewritten sandbox URL fails closed (no transport but `file` is allowed),
                        # and the host branch is left where it was.
                        self.assertNotEqual(plant, "alternates", exc.message)
                        self.assertEqual(exc.code, "sandbox_git_failed")
                        res = None
                self.assertFalse(pwned.exists(), f"the sync's fetch ran a {plant} command the shared config names")
                if res is not None:
                    self.assertTrue(res["branchUpdated"])
                if plant != "alternates":
                    _git("config", "--unset", f"url.{target}.insteadOf", cwd=self.repo)
                    _git("config", "--unset", f"protocol.{scheme}.allow", cwd=self.repo)

    def test_a_planted_promisor_remote_never_lazily_fetches_through_the_coordinator(self):
        # Codex round 4 class sweep: `extensions.partialClone=x` + `remote.x.promisor` +
        # `remote.x.uploadpack=<payload>` makes even a plain `rev-parse <ref>^{commit}` lazily
        # fetch a missing object and run the payload as the coordinator (GIT_ALLOW_PROTOCOL=file
        # does not stop it, the fetch target being a file remote). GIT_NO_LAZY_FETCH does.
        pwned = Path(self.tmp.name) / "pwned"
        donor = Path(self.tmp.name) / "donor.git"
        _git("init", "-q", "--bare", str(donor), cwd=Path(self.tmp.name))
        _git("config", "remote.x.url", str(donor), cwd=self.repo)
        _git("config", "remote.x.promisor", "true", cwd=self.repo)
        _git("config", "remote.x.uploadpack", f"sh -c 'echo up >> {shlex.quote(str(pwned))}; exit 1'", cwd=self.repo)
        _git("config", "extensions.partialClone", "x", cwd=self.repo)
        _git("config", "core.repositoryformatversion", "1", cwd=self.repo)
        (self.repo / ".git" / "refs" / "heads" / "ghost").write_text("1" * 40 + "\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {"PATH": self.env["PATH"]}):
            proc = self.posix._git(["rev-parse", "--verify", "-q", "ghost^{commit}"], cwd=self.repo)
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(pwned.exists(), "a coordinator rev-parse lazily fetched through a planted promisor")
            subprocess.run([self.posix.gitexec.GIT, "-C", str(self.repo), "rev-parse", "--verify", "-q", "ghost^{commit}"],
                           env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}, capture_output=True)
        self.assertTrue(pwned.exists(), "control: a bare git never lazily fetched; the exploit is not set up")

    def test_symlink_planted_in_sandbox_is_refused_and_host_untouched(self):
        wt, meta, cenv = self._sandbox()
        victim = Path(self.tmp.name) / "victim.txt"
        victim.write_text("precious\n", encoding="utf-8")
        cfg = Path(meta["sandbox_git"]) / "config"
        cfg.unlink()
        cfg.symlink_to(victim)
        with self.assertRaises(self.providers.ProviderError) as ctx:
            self.posix.sync_sandbox_git(meta, "disp_s")
        self.assertEqual(ctx.exception.code, "sandbox_git_tampered")
        self.assertEqual(victim.read_text(), "precious\n")
        info = Path(meta["sandbox_git"]) / "info"
        shutil.rmtree(info, ignore_errors=True)
        cfg.unlink()
        cfg.write_text("[core]\n\tbare = true\n", encoding="utf-8")
        info.symlink_to(Path(self.tmp.name))
        with self.assertRaises(self.providers.ProviderError):
            self.posix.sync_sandbox_git(meta, "disp_s2")
        self.assertTrue(victim.exists())

    def test_decoy_dot_git_cannot_choose_the_recorded_commit(self):
        wt, meta, cenv = self._sandbox()
        (wt / "real.txt").write_text("real\n", encoding="utf-8")
        subprocess.run(["git", "add", "real.txt"], cwd=wt, env=cenv, check=True)
        subprocess.run(["git", "commit", "-qm", "real"], cwd=wt, env=cenv, check=True)
        real = subprocess.run(["git", "rev-parse", "HEAD"], cwd=wt, env=cenv, check=True, capture_output=True, text=True).stdout.strip()
        decoy = Path(meta["sandbox_git"]) / ".git"
        subprocess.run(["git", "init", "-q", "--bare", str(decoy)], check=True)
        dwt = Path(self.tmp.name) / "decoy-wt"
        dwt.mkdir()
        denv = {**cenv, "GIT_DIR": str(decoy), "GIT_WORK_TREE": str(dwt)}
        (dwt / "evil.txt").write_text("evil\n", encoding="utf-8")
        subprocess.run(["git", "add", "evil.txt"], cwd=dwt, env=denv, check=True)
        subprocess.run(["git", "commit", "-qm", "evil"], cwd=dwt, env=denv, check=True)
        res = self.posix.sync_sandbox_git(meta, "disp_d")
        self.assertEqual(res["head"], real)
        self.assertEqual(_git("rev-parse", "refs/open-fleet/sandbox/disp_d", cwd=self.repo).stdout.strip(), real)

    def test_stopping_a_sandboxed_worker_still_syncs_its_commits(self):
        """Stop = remove the container, let the host monitor finish the sync, THEN kill it."""
        wt, meta, cenv = self._sandbox()
        (wt / "work.txt").write_text("done\n", encoding="utf-8")
        subprocess.run(["git", "add", "work.txt"], cwd=wt, env=cenv, check=True)
        subprocess.run(["git", "commit", "-qm", "work"], cwd=wt, env=cenv, check=True)
        new = subprocess.run(["git", "rev-parse", "HEAD"], cwd=wt, env=cenv, check=True, capture_output=True, text=True).stdout.strip()
        docker_log = Path(self.tmp.name) / "docker.log"
        self.fake_agent("docker", f'echo "$*" >> "{docker_log}"')
        lane = Path(meta["sandbox_git"]).parent
        with self.prov.state._connect() as conn:
            conn.execute(
                "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, terminal_handle, state, created_at, updated_at) "
                "VALUES ('disp_sbx', 't', 'default', ?, 'claude', 'term_sbx', 'ready', 0, 0)",
                (str(wt),),
            )
        # The "agent" stands in for `docker run`: it returns once the container is removed.
        spawn = self.prov._spawn_process(
            dispatch_id="disp_sbx", term_handle="term_sbx", wt_path=str(wt), command="sleep 1",
            env_vars={}, lane_dir=lane, run_id="default", sandbox_meta=meta,
        )
        time.sleep(0.4)  # monitor is waiting on the agent
        report = self.prov._terminate_backend(
            "setsid", "term_sbx", spawn["pid"], container="openfleet-disp_sbx", lane_dir=str(lane), grace_s=0.5,
        )
        self.assertIn("rm -f openfleet-disp_sbx", docker_log.read_text())
        self.assertEqual(report["sandboxSync"].get("headSha"), new, report)
        self.assertEqual(_git("rev-parse", "refs/heads/fleet/sbx", cwd=self.repo).stdout.strip(), new)

    def test_history_rewrite_does_not_move_host_branch(self):
        wt, meta, cenv = self._sandbox()
        base = _git("rev-parse", "refs/heads/fleet/sbx", cwd=self.repo).stdout.strip()
        subprocess.run(["git", "commit", "-q", "--amend", "-m", "rewritten", "--allow-empty"], cwd=wt, env=cenv, check=True)
        res = self.posix.sync_sandbox_git(meta, "disp_z")
        self.assertTrue(res["nonFastForward"])
        self.assertEqual(_git("rev-parse", "refs/heads/fleet/sbx", cwd=self.repo).stdout.strip(), base)

    def test_danger_refuses_main_checkout_and_foreign_paths(self):
        task = self.prov.dispatch(["orchestration", "task-create", "--spec", "x"])["task"]
        for wt in ("current", f"path:{self.repo}"):
            with self.assertRaises(self.providers.ProviderError) as ctx:
                self.prov.worker_start(task_id=task["id"], worktree=wt, agent="claude", profile="danger", on_env="img")
            self.assertEqual(ctx.exception.code, "danger_requires_linked_worktree")
        self.assertEqual(self.prov.task_list()["tasks"][0]["status"], "ready", "claim released on refusal")


class TestPosixDoctorFailsClosed(PosixRealProcessBase):
    def test_doctor_reports_fail_without_docker(self):
        env = {**self.env, "PATH": str(self.bin)}
        prov = self.providers.get_provider("posix", env=env)
        res = prov.vm_recipe_doctor("img:latest")
        self.assertFalse(res["ok"])
        self.assertTrue(res["failures"])

    def test_base_provider_doctor_never_certifies(self):
        base = importlib.import_module("runtime.providers.base")
        with self.assertRaises(base.ProviderError):
            base.RuntimeProvider().vm_recipe_doctor("anything")


# A stand-in for a ro model: it can only PRINT (stream-json, like `claude -p`). It finds its own
# dispatch id where a model would — in its assignment, never in an env var it has no tool to read.
_RO_MODEL = r"""python3 - "$@" <<'PY'
import json, re, sys
prompt = sys.argv[-1]
m = re.search(r"OPEN_FLEET_WORKER_DONE (disp_[0-9a-f]+) <outcome>", prompt)
lines = ["REPORT: nothing to change."] + ([f"OPEN_FLEET_WORKER_DONE {m.group(1)} {OUTCOME}"] if m else [])
print(json.dumps({"type": "result", "result": "\n".join(lines)}))
PY"""


class TestRoWorkerSignalsCompletion(PosixRealProcessBase):
    """#596 certification finding: a PROFILE=ro worker could never send `worker_done`. Every ro
    line strips the tool that would (no shell to run send_msg.py; codex's read-only sandbox and
    hermes' /dev/null write root also deny the state-DB write it needs), so posix recorded its
    clean exit as `worker_died (exit=0)`. Now the ro prompt names a completion line and the exit
    monitor — which already holds the dispatch's identity and the state DB — relays it as that
    worker's `worker_done`. The worker gains no tool and no writable path."""

    def ro_model(self, outcome="succeeded", tail=""):
        self.fake_agent("claude", _RO_MODEL.replace("{OUTCOME}", outcome) + tail)

    def mine(self, disp):
        return [m for m in self.prov.check_messages(terminal="coordinator")["messages"] if disp in m["subject"]]

    def settled(self, disp, state):
        self.assertTrue(self.wait_monitor_done(disp))
        self.assertEqual(self.prov.worker_show(disp)["worker"]["state"], state)
        return self.mine(disp)

    def test_a_ro_completion_line_reaches_the_coordinator_as_worker_done(self):
        for outcome in ("succeeded", "failed"):
            with self.subTest(outcome=outcome):
                self.ro_model(outcome)
                _, res = self.start(profile="ro")
                disp = res["dispatchId"]
                mail = self.settled(disp, "completed")
                self.assertEqual([(m["type"], m["outcome"]) for m in mail], [("worker_done", outcome)], mail)
                self.assertEqual(mail[0]["from"], res["agentTerminalHandle"])
                self.assertRegex(json.loads(mail[0]["payload"])["headSha"], r"^[0-9a-f]{40}$")

    def test_a_clean_ro_exit_without_the_line_is_still_worker_died(self):
        self.fake_agent("claude", 'echo \'{"type": "result", "result": "REPORT only"}\'')
        _, res = self.start(profile="ro")
        mail = self.settled(res["dispatchId"], "died")
        self.assertEqual([m["type"] for m in mail], ["escalation"])
        self.assertEqual(json.loads(mail[0]["payload"])["exitCode"], 0)

    def test_echoed_instructions_and_other_dispatches_lines_are_not_relayed(self):
        # The assignment itself (echoed back verbatim) and a line naming another dispatch.
        self.fake_agent("claude", 'printf "%s\\n" "$@"; echo "OPEN_FLEET_WORKER_DONE disp_0123456789 succeeded"')
        _, res = self.start(profile="ro")
        mail = self.settled(res["dispatchId"], "died")
        self.assertEqual([m["type"] for m in mail], ["escalation"])

    def test_a_ro_worker_that_crashes_after_the_line_is_a_death(self):
        self.ro_model("succeeded", "\nexit 3")
        _, res = self.start(profile="ro")
        mail = self.settled(res["dispatchId"], "died")
        self.assertEqual([m["type"] for m in mail], ["escalation"])
        self.assertEqual(json.loads(mail[0]["payload"])["exitCode"], 3)

    def test_rw_gets_no_relay_and_no_footer(self):
        # rw has its own mail tool (send_msg.py); the relay must not become a second channel.
        seen = Path(self.tmp.name) / "rw-argv.json"
        self.fake_agent("claude", f'python3 -c \'import json,sys; json.dump(sys.argv[1:], open("{seen}", "w"))\' "$@"; '
                                  'echo "OPEN_FLEET_WORKER_DONE $OPEN_FLEET_DISPATCH_ID succeeded"')
        _, res = self.start(spec="RW-SPEC", profile="rw")
        mail = self.settled(res["dispatchId"], "died")
        self.assertEqual([m["type"] for m in mail], ["escalation"])
        self.assertEqual(json.loads(seen.read_text())[-1], "RW-SPEC")

    def test_the_relay_widens_nothing_the_ro_launch_can_do(self):
        import shlex
        self.ro_model()
        _, res = self.start(spec="RO-SPEC", profile="ro")
        base = self.providers.build_harness_command("claude", "ro", "/w", prompt="RO-SPEC")
        argv = shlex.split(res["launch"]["effective"]["command"])
        self.assertEqual(argv[:-1], base["argv"][:-1], "the ro launch gained a flag")
        self.assertTrue(argv[-1].startswith("RO-SPEC"), "the assignment must lead the prompt")
        self.assertEqual(res["launch"]["effective"]["args"], base["profile_flag"])
        self.settled(res["dispatchId"], "completed")

    def test_a_marker_rehearsed_in_reasoning_is_not_a_completion(self):
        # #596 review (PRRT_kwDOTWxN9c6vvwnW): the worker rehearses its completion line in a
        # thinking block, then ends its FINAL answer without it. Exit 0 is still a clean death.
        found = Path(self.tmp.name) / "footer-found"
        self.fake_agent("claude", f"""python3 - "$@" <<'PY'
import json, re, sys
m = re.search(r"OPEN_FLEET_WORKER_DONE (disp_[0-9a-f]+) <outcome>", sys.argv[-1])
if m:
    open("{found}", "w").close()
line = f"OPEN_FLEET_WORKER_DONE {{m.group(1)}} succeeded" if m else ""
print(json.dumps({{"type": "assistant", "message": {{"role": "assistant",
                  "content": [{{"type": "thinking", "thinking": line}}]}}}}))
print(json.dumps({{"type": "result", "subtype": "success", "result": "REPORT: still reviewing."}}))
PY""")
        _, res = self.start(profile="ro")
        mail = self.settled(res["dispatchId"], "died")
        self.assertTrue(found.exists(), "the stand-in never saw its completion footer")
        self.assertEqual([m["type"] for m in mail], ["escalation"])
        self.assertEqual(json.loads(mail[0]["payload"])["exitCode"], 0)

    def test_no_exit_monitor_no_promise(self):
        # dry-run and an injected runner never run the monitor that relays the line, so a ro
        # worker there is not told it has one: its prompt is exactly the spec. Each provider gets
        # its OWN state DB, which _kill_all never fences (dry-run records a placeholder pid).
        import shlex
        for backend, runner in (("dry-run", None), ("setsid", lambda **_kw: {"pid": 0, "backend": "setsid"})):
            with self.subTest(backend=backend, runner=runner is not None):
                env = {**self.env, "OPEN_FLEET_POSIX_BACKEND": backend,
                       "OPEN_FLEET_STATE_DB": str(Path(self.tmp.name) / f"own-{backend}" / "runtime.db")}
                prov = self.providers.get_provider("posix", env=env)
                prov.runner = runner
                task = prov.dispatch(["orchestration", "task-create", "--spec", "RO-SPEC"])["task"]
                res = prov.worker_start(task_id=task["id"], worktree="new-child", agent="claude", profile="ro")
                self.assertEqual(shlex.split(res["launch"]["effective"]["command"])[-1], "RO-SPEC")


DISP = "disp_ab12"


def _done(outcome="succeeded", disp=DISP):
    return f"OPEN_FLEET_WORKER_DONE {disp} {outcome}"


def _jl(*events):
    return "\n".join(json.dumps(e) for e in events)


def _goose(mid, role, *content):
    return {"type": "message", "message": {"id": mid, "role": role, "content": list(content)}}


# Per format: (transcript whose FINAL answer is `final`, with the marker planted only where it is
# NOT the final answer: reasoning, a tool result, an echoed user message, an earlier turn). Shapes
# follow test_certification.py's UPSTREAM_STDOUT, read from each harness's source.
def _formats(final, m=None):
    m = m or _done()
    return {
        "claude": _jl(
            {"type": "system", "subtype": "init"},
            {"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": m}]}},
            {"type": "assistant", "message": {"role": "assistant", "content": [
                {"type": "thinking", "thinking": m}, {"type": "text", "text": m},
                {"type": "tool_use", "id": "t1", "name": "Read", "input": {}}]}},
            {"type": "user", "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": m}]}},
            {"type": "result", "subtype": "success", "is_error": False, "result": final}),
        "codex": _jl(
            {"type": "thread.started", "thread_id": "t"}, {"type": "turn.started"},
            {"type": "item.completed", "item": {"id": "i0", "type": "reasoning", "text": m}},
            {"type": "item.completed", "item": {"id": "i1", "type": "agent_message", "text": m}},
            {"type": "item.completed", "item": {"id": "i2", "type": "command_execution", "command": "cat x",
                                                "aggregated_output": m, "exit_code": 0}},
            {"type": "item.completed", "item": {"id": "i3", "type": "agent_message", "text": final}},
            {"type": "turn.completed", "usage": {}}),
        "opencode": _jl(
            {"type": "step_start", "part": {"id": "p0", "type": "step-start"}},
            {"type": "reasoning", "part": {"id": "p1", "type": "reasoning", "text": m}},
            {"type": "text", "part": {"id": "p2", "type": "text", "text": m}},
            {"type": "tool_use", "part": {"id": "p3", "type": "tool", "tool": "read", "state": {"output": m}}},
            {"type": "step_finish", "part": {"id": "p4", "type": "step-finish", "reason": "tool-calls"}},
            {"type": "step_start", "part": {"id": "p5", "type": "step-start"}},
            {"type": "text", "part": {"id": "p6", "type": "text", "text": final}},
            {"type": "step_finish", "part": {"id": "p7", "type": "step-finish", "reason": "stop"}}),
        "pi": _jl(
            {"type": "agent_start"},
            {"type": "message_end", "message": {"role": "user", "content": [{"type": "text", "text": m}]}},
            {"type": "message_end", "message": {"role": "assistant", "content": [
                {"type": "text", "text": m}, {"type": "toolCall", "id": "c1", "name": "read", "arguments": {}}]}},
            {"type": "message_end", "message": {"role": "toolResult", "toolCallId": "c1",
                                                "content": [{"type": "text", "text": m}]}},
            {"type": "message_end", "message": {"role": "assistant", "content": [
                {"type": "thinking", "thinking": m}, {"type": "text", "text": final}]}},
            {"type": "agent_end", "messages": []}),
        "goose": _jl(
            _goose("m1", "assistant", {"type": "text", "text": m}),
            _goose("m2", "assistant", {"type": "toolRequest", "id": "r1"}),
            _goose("m3", "user", {"type": "toolResponse", "id": "r1", "toolResult": {"value": [{"type": "text", "text": m}]}}),
            _goose("m4", "assistant", {"type": "thinking", "thinking": m}, {"type": "text", "text": final}),
            {"type": "complete", "total_tokens": 1}),
        # jcode's done.text and plain text carry EVERY turn's text, so there only the final
        # answer's last line separates a completion from a rehearsal of one.
        "jcode": _jl(
            {"type": "start"}, {"type": "text_delta", "text": m + "\n"},
            {"type": "tool_start", "id": "t1", "name": "read"}, {"type": "tool_done", "id": "t1", "output": m},
            {"type": "text_delta", "text": final},
            {"type": "done", "text": m + "\n" + final}),
        "gemini": "\n".join(["Loaded cached credentials.", m, "thinking it over", final]),
    }


class TestRoCompletionReadsTheFinalAnswer(unittest.TestCase):
    """#596 review (PRRT_kwDOTWxN9c6vvwnW): the completion line counts only as the LAST line of the
    harness's FINAL answer, read with first_run.py's per-harness reader (now shared in
    runtime/providers/transcript.py). A marker rehearsed in reasoning, quoted from a tool result,
    echoed back from the prompt, or said in an earlier turn is not the worker's completion."""

    def setUp(self):
        self.read = _posix().ro_completion_outcome

    def test_the_final_answers_last_line_counts_in_every_format(self):
        for outcome in ("succeeded", "failed"):
            final = "REPORT: nothing to change.\n" + _done(outcome)
            for agent, transcript in _formats(final).items():
                with self.subTest(agent=agent, outcome=outcome):
                    self.assertEqual(self.read(transcript, DISP, agent), outcome)

    def test_reasoning_tool_results_echoes_and_earlier_turns_never_count(self):
        for agent, transcript in _formats("REPORT: nothing to change.").items():
            with self.subTest(agent=agent):
                self.assertIn(_done(), transcript, "the marker must be planted somewhere")
                self.assertIsNone(self.read(transcript, DISP, agent))

    def test_a_marker_rehearsed_mid_answer_is_not_the_last_line(self):
        final = f"I will end with:\n{_done()}\nbut first the report.\nREPORT: nothing to change."
        for agent, transcript in _formats(final, m="unrelated").items():
            with self.subTest(agent=agent):
                self.assertIsNone(self.read(transcript, DISP, agent))

    def test_markup_around_the_last_line_and_a_closing_fence(self):
        for last, want in ((f"**{_done('failed')}**", "failed"), (f"> `{_done()}`.", "succeeded"),
                           (f"```\n{_done()}\n```\n", "succeeded"), (f"`{DISP}`".join(["OPEN_FLEET_WORKER_DONE ", " failed"]), "failed")):
            with self.subTest(last=last):
                self.assertEqual(self.read(_formats("REPORT\n" + last, m="x")["claude"], DISP, "claude"), want)

    def test_only_a_whole_line_naming_this_dispatch(self):
        footer = _posix().ro_completion_footer(DISP)
        for last in (_done(disp="disp_ab13"), footer, "done: " + _done(), _done() + " and more", ""):
            with self.subTest(last=last[:40]):
                for agent, transcript in _formats("REPORT\n" + last, m="x").items():
                    self.assertIsNone(self.read(transcript, DISP, agent), agent)

    def test_an_unknown_harness_reads_no_completion(self):
        self.assertIsNone(self.read(_done(), DISP, "kilo"))


class TestPosixAdversarialRemediation750(PosixRealProcessBase):
    """#750 C1, C6, C9, C28, C32, C37, C38, C40: POSIX provider & worker_ops regressions."""

    def test_c1_and_c40_terminal_and_worker_read_cursor_limit_source_and_truncation(self):
        self.fake_agent("claude", "exit 0")
        t = self.prov.task_create(spec="read test")["task"]["id"]
        ws = self.prov.worker_start(task_id=t, worktree="new-child", agent="claude", profile="ro")
        disp_id = ws["dispatchId"]
        handle = ws["agentTerminalHandle"]
        self.assertTrue(self.wait_monitor_done(disp_id))
        with self.prov.state._connect() as conn:
            row = conn.execute("SELECT lane_dir FROM dispatches WHERE dispatch_id = ?", (disp_id,)).fetchone()
            lane_dir = Path(row["lane_dir"])
        ev = lane_dir / "events.jsonl"
        ev.write_text("\n".join(f"line-{i}" for i in range(6)) + "\n", encoding="utf-8")

        # C40: cursor=0 renders as CURSOR=0 in worker_ops.format_read and TRUNCATED=yes in terminal_ops.format_read
        worker_ops = importlib.import_module("runtime.scripts.worker_ops")
        terminal_ops = importlib.import_module("runtime.scripts.terminal_ops")
        tr0_res = self.prov.terminal_read(terminal=handle, cursor=0, limit=0)
        tr0 = tr0_res["terminal"]
        self.assertEqual(tr0["cursor"], 0)
        self.assertEqual(tr0["source"], "stream")
        self.assertTrue(tr0["truncated"])
        term_rendered = "\n".join(terminal_ops.format_read(tr0_res))
        self.assertIn("SOURCE=stream", term_rendered)
        self.assertIn("TRUNCATED=yes", term_rendered)

        zero_page = self.prov.worker_read(dispatch_id=disp_id, source="terminal", cursor=0, limit=0)
        self.assertEqual(zero_page["cursor"], 0)
        self.assertTrue(zero_page["truncated"])
        rendered = "\n".join(worker_ops.format_read(zero_page))
        self.assertIn("CURSOR=0", rendered)
        self.assertIn("SOURCE=terminal", rendered)

        # C1: forward pagination with cursor + limit neither repeats nor skips lines
        p1 = self.prov.terminal_read(terminal=handle, cursor=0, limit=2)["terminal"]
        self.assertEqual(p1["tail"], ["line-0", "line-1"])
        self.assertEqual(p1["cursor"], 2)
        self.assertTrue(p1["truncated"])

        p2 = self.prov.terminal_read(terminal=handle, cursor=p1["cursor"], limit=2)["terminal"]
        self.assertEqual(p2["tail"], ["line-2", "line-3"])
        self.assertEqual(p2["cursor"], 4)
        self.assertTrue(p2["truncated"])

        p3 = self.prov.terminal_read(terminal=handle, cursor=p2["cursor"], limit=2)["terminal"]
        self.assertEqual(p3["tail"], ["line-4", "line-5"])
        self.assertEqual(p3["cursor"], 6)
        self.assertFalse(p3["truncated"])

        # C40: worker_read honors cursor and limit and reports truncated accurately
        wr1 = self.prov.worker_read(dispatch_id=disp_id, source="terminal", cursor=1, limit=3)
        self.assertEqual(wr1["terminal"]["tail"], ["line-1", "line-2", "line-3"])
        self.assertEqual(wr1["cursor"], 4)
        self.assertTrue(wr1["truncated"])

        wr2 = self.prov.worker_read(dispatch_id=disp_id, source="terminal", cursor=4, limit=3)
        self.assertEqual(wr2["terminal"]["tail"], ["line-4", "line-5"])
        self.assertEqual(wr2["cursor"], 6)
        self.assertFalse(wr2["truncated"])

    def test_c6_paperclip_and_openhands_denylist_stripped_across_spawn_mux_and_inherited_server(self):
        six_keys = (
            "OPEN_FLEET_PAPERCLIP_API_KEY",
            "ORCA_PAPERCLIP_API_KEY",
            "OPEN_FLEET_OPENHANDS_SESSION_API_KEY",
            "ORCA_OPENHANDS_SESSION_API_KEY",
            "OPEN_FLEET_OPENHANDS_LLM_API_KEY",
            "ORCA_OPENHANDS_LLM_API_KEY",
        )
        for k in six_keys:
            self.assertIn(k, self.posix.WORKER_ENV_DENYLIST)

        out = Path(self.tmp.name) / "c6-env.txt"
        echo_expr = "".join(f"[${k}]" for k in six_keys)
        self.fake_agent("claude", f'echo "{echo_expr}" > "{out}"')
        for k in six_keys:
            self.env[k] = f"secret-{k}"
        self.prov = self.providers.get_provider("posix", env=self.env)

        # 1. Spawn & mux worker_env.json path
        _, ws = self.start(profile="rw")
        disp = ws["dispatchId"]
        self.assertTrue(_wait_for(out.is_file, timeout=30))
        self.assertTrue(self.wait_monitor_done(disp))
        self.assertEqual(out.read_text().strip(), "[]" * len(six_keys))

        with self.prov.state._connect() as conn:
            lane_dir = Path(conn.execute("SELECT lane_dir, worktree FROM dispatches WHERE dispatch_id = ?", (disp,)).fetchone()["lane_dir"])
        worker_env = json.loads((lane_dir / "worker_env.json").read_text(encoding="utf-8"))
        for k in six_keys:
            self.assertNotIn(k, worker_env)

        # 2. Inherited-server path: run_worker.py strips all 6 from its own os.environ
        out.unlink(missing_ok=True)
        with self.prov.state._connect() as conn:
            conn.execute("UPDATE dispatches SET state = 'ready', monitor_pid = 0, monitor_started_at = NULL WHERE dispatch_id = ?", (disp,))
        inherited_env = {**os.environ, "PATH": self.env["PATH"], **{k: f"inherited-{k}" for k in six_keys}}
        subprocess.run([sys.executable, "-I", str(lane_dir / "run_worker.py")], env=inherited_env, cwd=ws["worker"]["worktree"], timeout=60, check=True)
        self.assertTrue(out.is_file())
        self.assertEqual(out.read_text().strip(), "[]" * len(six_keys))

    def test_c9_sync_sandbox_git_tampered_head_deletes_ref_and_raises(self):
        wt = Path(self.prov.worktree_create("wt-c9")["worktree"]["path"])
        lane = Path(self.tmp.name) / "lane-c9"
        lane.mkdir()
        meta = self.posix.prepare_sandbox_git(str(wt), lane)
        sandbox_git = Path(meta["sandbox_git"])
        _git("--git-dir", str(sandbox_git), "-c", "user.email=t@x", "-c", "user.name=T",
             "commit", "--allow-empty", "-m", "c1", cwd=wt)
        head1 = _git("--git-dir", str(sandbox_git), "rev-parse", "HEAD", cwd=wt).stdout.strip()
        _git("--git-dir", str(sandbox_git), "-c", "user.email=t@x", "-c", "user.name=T",
             "commit", "--allow-empty", "-m", "c2", cwd=wt)
        head2 = _git("--git-dir", str(sandbox_git), "rev-parse", "HEAD", cwd=wt).stdout.strip()
        # Reset sandbox HEAD to head1; during fetch, flip sandbox HEAD to head2 so fetched != new_head
        _git("--git-dir", str(sandbox_git), "update-ref", "HEAD", head1, cwd=wt)
        real_git_ok = self.posix._git_ok

        def racing_git_ok(args, desc="", **kw):
            if desc == "fetch sandbox commits":
                _git("--git-dir", str(sandbox_git), "update-ref", "HEAD", head2, cwd=wt)
            return real_git_ok(args, desc, **kw)

        with mock.patch.object(self.posix, "_git_ok", side_effect=racing_git_ok):
            with self.assertRaises(self.posix.ProviderError) as ctx:
                self.posix.sync_sandbox_git(meta, "disp_c9")
        self.assertEqual(ctx.exception.code, "sandbox_git_tampered")
        # Verify the mismatched ref was deleted from common_dir
        ref_check = _git("--git-dir", meta["common_dir"], "rev-parse", "--verify", "refs/open-fleet/sandbox/disp_c9",
                         cwd=self.repo, check=False)
        self.assertNotEqual(ref_check.returncode, 0)

    def test_c28_posix_worker_start_and_dispatch_inject_refuse_cross_run(self):
        self.fake_agent("claude", "exit 0")
        self.prov.state.run_create(run="run-1", sender="coord-1")
        self.prov.state.run_create(run="run-2", sender="coord-2")
        t1 = self.prov.task_create(spec="in run 1", run="run-1")["task"]["id"]
        with self.assertRaises(self.posix.ProviderError) as ctx:
            self.prov.worker_start(task_id=t1, worktree="new-child", agent="claude", profile="ro", run="run-2")
        self.assertEqual(ctx.exception.code, "cross_run_access")

        ws = self.prov.worker_start(task_id=t1, worktree="new-child", agent="claude", profile="ro", run="run-1")
        self.assertTrue(self.wait_monitor_done(ws["dispatchId"]))
        t2 = self.prov.task_create(spec="in run 2", run="run-2")["task"]["id"]
        with self.assertRaises(self.posix.ProviderError) as ctx:
            self.prov.dispatch_inject(task_id=t1, to_handle=ws["agentTerminalHandle"], run="run-2")
        self.assertEqual(ctx.exception.code, "cross_run_access")
        with self.assertRaises(self.posix.ProviderError) as ctx:
            self.prov.dispatch_inject(task_id=t2, to_handle=ws["agentTerminalHandle"], run="run-2")
        self.assertEqual(ctx.exception.code, "cross_run_access")

        unreg_term = self.prov.terminal_create(title="unsupervised")["terminal"]["handle"]
        t1_next = self.prov.task_create(spec="in run 1 next", run="run-1")["task"]["id"]
        bound_prov = self.providers.get_provider(
            "posix",
            env={**self.env, "OPEN_FLEET_DISPATCH_ID": ws["dispatchId"]},
        )
        for bad_op in (
            lambda: bound_prov.terminal_create(title="escaped"),
            lambda: bound_prov.terminal_read(unreg_term),
            lambda: bound_prov.terminal_send(unreg_term, "hi"),
            lambda: bound_prov.dispatch_inject(task_id=t1_next, to_handle=unreg_term),
        ):
            with self.assertRaises(self.posix.ProviderError) as bctx:
                bad_op()
            self.assertEqual(bctx.exception.code, "cross_run_access")
        self.assertEqual(
            [t["handle"] for t in bound_prov.terminal_list()["terminals"]],
            [ws["agentTerminalHandle"]],
        )

    def test_c32_send_body_flag_and_fence_retry_request_idempotency(self):
        from unittest import mock

        self.fake_agent("claude", "exit 0")
        # orchestration send --body maps to payload and --retry-request commits message + request
        # atomically via LocalStateStore._save_request_in_tx (never the two-tx save_request fallback).
        with mock.patch.object(
            self.prov.state,
            "save_request",
            side_effect=AssertionError("CLI send must commit retry_request in-tx, not via separate save_request"),
        ):
            s1 = self.prov.dispatch(
                ["orchestration", "send", "--subject", "sub", "--type", "info", "--to", "coordinator",
                 "--body", "hello-body", "--retry-request", "req-send-1"],
            )
            s2 = self.prov.dispatch(
                ["orchestration", "send", "--subject", "sub", "--type", "info", "--to", "coordinator",
                 "--body", "hello-body", "--retry-request", "req-send-1"],
            )
        self.assertEqual(s1["messageId"], s2["messageId"])
        msgs = self.prov.check_messages(terminal="coordinator")["messages"]
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]["payload"], "hello-body")
        self.prov.check_messages(terminal="coordinator", ack=s1["deliveryId"])

        # Crash before COMMIT rolls back BOTH message and request; retry delivers once.
        orig_save_in_tx = self.prov.state._save_request_in_tx
        with mock.patch.object(self.prov.state, "_save_request_in_tx", side_effect=RuntimeError("boom-pre-commit")):
            with self.assertRaisesRegex(RuntimeError, "boom-pre-commit"):
                self.prov.dispatch(
                    ["orchestration", "send", "--subject", "sub-crash", "--type", "info", "--to", "coordinator",
                     "--body", "crash-body", "--retry-request", "req-send-crash"],
                )
        self.assertEqual(self.prov.check_messages(terminal="coordinator")["messages"], [])
        self.assertEqual(self.prov.request_show("req-send-crash")["state"], "absent")
        recovered = self.prov.dispatch(
            ["orchestration", "send", "--subject", "sub-crash", "--type", "info", "--to", "coordinator",
             "--body", "crash-body", "--retry-request", "req-send-crash"],
        )
        self.assertIsNotNone(orig_save_in_tx)
        msgs_after = self.prov.check_messages(terminal="coordinator")["messages"]
        self.assertEqual([m["id"] for m in msgs_after], [recovered["messageId"]])

        # worker-stop with --retry-request deduplicates and rejects changed verb
        t = self.prov.task_create(spec="fence retry")["task"]["id"]
        ws = self.prov.worker_start(task_id=t, worktree="new-child", agent="claude", profile="ro")
        self.assertTrue(self.wait_monitor_done(ws["dispatchId"]))
        f1 = self.prov.dispatch(
            ["orchestration", "worker-stop", "--dispatch", ws["dispatchId"], "--retry-request", "req-fence-1"],
        )
        f2 = self.prov.dispatch(
            ["orchestration", "worker-stop", "--dispatch", ws["dispatchId"], "--retry-request", "req-fence-1"],
        )
        self.assertEqual(f1["dispatchId"], f2["dispatchId"])
        with self.assertRaises(self.posix.ProviderError) as ctx:
            self.prov.dispatch(
                ["orchestration", "worker-abandon", "--dispatch", ws["dispatchId"], "--retry-request", "req-fence-1"],
            )
        self.assertEqual(ctx.exception.code, "request_mismatch")

    def test_c37_worker_list_filters_terminal_state_and_paginates(self):
        self.fake_agent("claude", "exit 0")
        ids = []
        for i in range(3):
            tid = self.prov.task_create(spec=f"w-{i}")["task"]["id"]
            ws = self.prov.worker_start(task_id=tid, worktree="new-child", agent="claude", profile="ro")
            ids.append(ws["dispatchId"])
            self.assertTrue(self.wait_monitor_done(ws["dispatchId"]))
        self.prov.worker_fence(verb="stop", dispatch_id=ids[0])

        # Filter by terminal_state via CLI dispatch
        stopped = self.prov.dispatch(["orchestration", "worker-list", "--terminal-state", "stopped"])
        self.assertEqual([w["dispatchId"] for w in stopped["workers"]], [ids[0]])

        # Paginate with cursor + limit
        page1 = self.prov.worker_list(limit=2)
        self.assertEqual(len(page1["workers"]), 2)
        self.assertIsNotNone(page1["page"]["nextCursor"])
        page2 = self.prov.worker_list(cursor=page1["page"]["nextCursor"], limit=2)
        self.assertEqual(len(page2["workers"]), 1)
        self.assertIsNone(page2["page"]["nextCursor"])
        self.assertEqual(
            {w["dispatchId"] for w in page1["workers"] + page2["workers"]},
            set(ids),
        )

    def test_c38_inbox_permissions_and_purge_on_fence(self):
        import stat
        self.fake_agent("claude", "exit 0")
        tid = self.prov.task_create(spec="inbox test")["task"]["id"]
        ws = self.prov.worker_start(task_id=tid, worktree="new-child", agent="claude", profile="ro")
        self.assertTrue(self.wait_monitor_done(ws["dispatchId"]))
        wt = Path(ws["worker"]["worktree"])
        old_umask = os.umask(0)
        try:
            self.prov._deliver_terminal_input(
                {
                    "handle": ws["agentTerminalHandle"],
                    "worktree": str(wt),
                    "backend": "dry-run",
                    "state": "running",
                    "log_path": "",
                },
                "secret prompt",
            )
        finally:
            os.umask(old_umask)
        of_dir = wt / ".open-fleet"
        inbox = of_dir / "inbox.jsonl"
        self.assertTrue(inbox.exists())
        self.assertEqual(stat.S_IMODE(of_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(inbox.stat().st_mode), 0o600)

        # Stopping the worker purges .open-fleet/inbox.jsonl without leaking file descriptors
        import fcntl

        def _open_fd_count() -> int:
            cnt = 0
            for fd_num in range(256):
                try:
                    fcntl.fcntl(fd_num, fcntl.F_GETFD)
                    cnt += 1
                except OSError:
                    pass
            return cnt

        self.prov.worker_fence(verb="stop", dispatch_id=ws["dispatchId"])
        self.assertFalse(inbox.exists())
        fds_before = _open_fd_count()
        for _ in range(5):
            of_dir.mkdir(mode=0o700, exist_ok=True)
            inbox.write_text('{"text":"x"}\n', encoding="utf-8")
            self.prov._purge_private_inbox(str(wt))
            self.assertFalse(inbox.exists())
        self.assertEqual(_open_fd_count(), fds_before)

    def test_c28_and_c40_terminal_send_run_isolation_and_strict_read_cursor_validation(self) -> None:
        t_a = self.prov.task_create(spec="task a", run="run-a")["task"]["id"]
        ws_a = self.prov.worker_start(task_id=t_a, agent="claude", profile="rw", prompt="work a", run="run-a")
        term_a = ws_a["agentTerminalHandle"]
        with self.assertRaises(self.posix.ProviderError) as ctx:
            self.prov.terminal_send(term_a, "cross-run", run="run-b")
        self.assertEqual(ctx.exception.code, "cross_run_access")

        for bad in (-1, "-5", "abc", "²", "١", True):
            with self.assertRaises(self.posix.ProviderError) as ctx:
                self.prov.worker_read(ws_a["dispatchId"], cursor=bad)
            self.assertEqual(ctx.exception.code, "invalid_argument")
            with self.assertRaises(self.posix.ProviderError) as ctx:
                self.prov.worker_read(ws_a["dispatchId"], limit=bad)
            self.assertEqual(ctx.exception.code, "invalid_argument")
        self.prov.worker_fence(verb="stop", dispatch_id=ws_a["dispatchId"])


if __name__ == "__main__":
    unittest.main()
