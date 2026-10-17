#!/usr/bin/env python3
"""Contract tests for runtime/scripts/spawn_worker.sh (issues #43, #44; v5 re-pin).

The hardening tests exercise the real script through its SW_SELFTEST hook, which computes
the two hardened values (validated effort, collision-safe scratch key) and exits before any
orchestration side effect. The lane tests stub `orca` per subcommand and assert the v5
receipt contracts against Orca v1.4.199 — the SHIPPED tag, not upstream HEAD. Standard
library only.
"""
import copy
import json
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPAWN = ROOT / "runtime" / "scripts" / "spawn_worker.sh"
HOOK = ROOT / "runtime" / "scripts" / "deny-hook.sh"


def run(title, agent="claude", effort="high", task="task_test"):
    """Invoke spawn_worker.sh in self-test mode; return (rc, stdout, stderr)."""
    p = subprocess.run(
        ["bash", str(SPAWN), task, "active", title, agent, effort],
        env={"SW_SELFTEST": "1", "PATH": "/usr/bin:/bin", "ORCA_CLI_COMMAND": "orca"},
        capture_output=True, text=True,
    )
    return p.returncode, p.stdout, p.stderr


def run_spawn(args, env_extra=None, task_list=None):
    """Invoke spawn_worker.sh past the selftest hook; return (rc, stdout, stderr).

    env_extra: extra env vars on top of a minimal PATH. task_list: if given, a
    stub `orca` is put on PATH whose `task-list --json` output is that payload
    (written to a file the stub cats, so no shell quoting of the JSON).
    """
    with tempfile.TemporaryDirectory() as tmp:
        env = {"PATH": "/usr/bin:/bin", "SP": tmp, "ORCA_CLI_COMMAND": "orca"}
        if task_list is not None:
            payload = Path(tmp) / "task-list.json"
            payload.write_text(json.dumps(task_list))
            stub = Path(tmp) / "orca"
            stub.write_text(f'#!/bin/sh\ncat "{payload}"\n')
            stub.chmod(0o755)
            env["PATH"] = f"{tmp}:/usr/bin:/bin"
        env.update(env_extra or {})
        p = subprocess.run(
            ["bash", str(SPAWN), *args],
            env=env, capture_output=True, text=True,
        )
        return p.returncode, p.stdout, p.stderr


def task_list_payload(*tasks):
    return {"result": {"tasks": list(tasks)}}


class TestDangerSandboxEvidence(unittest.TestCase):
    """PROFILE=danger needs evidence of a sandbox, and the evidence has to be PRODUCED here.

    `ORCA_COORD_ALLOW_DANGER=1` alone said only that a coordinator meant it. A transcript the
    caller names said only that the caller could name a file: `ORCA_SANDBOX_RECIPE=root` with
    `ORCA_SANDBOX_DOCTOR=/etc/passwd` spawned a danger worker, while a real transcript reporting
    `"failures": []` was refused because the substring "fail" was in it (#283).

    So spawn_worker.sh runs `orca vm recipe doctor <recipe> --provision` itself and reads the
    verdict; ORCA_SANDBOX_DOCTOR is now where the transcript is WRITTEN.
    """

    ENV = {"PROFILE": "danger", "ORCA_COORD_ALLOW_AUTONOMOUS_WRITE": "1",
           "ORCA_COORD_ALLOW_DANGER": "1"}
    ARGS = ["t1", "wt", "some title", "claude"]

    def _spawn(self, **extra):
        env = dict(self.ENV)
        env.update(extra)
        return run_spawn(self.ARGS, env_extra=env)

    def _with_doctor(self, output, rc=0, **extra):
        """Run spawn with a stub `orca` whose `vm recipe doctor` prints `output` and exits `rc`."""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "doctor-output"
            out.write_text(output, encoding="utf-8")
            stub = Path(tmp) / "orca"
            stub.write_text(
                "#!/bin/sh\n"
                'case "$*" in\n'
                f'  *"recipe doctor"*) cat "{out}"; exit {rc} ;;\n'
                '  *) echo "{}" ;;\n'
                "esac\n")
            stub.chmod(0o755)
            env = dict(self.ENV)
            env.update(extra)
            env["PATH"] = f"{tmp}:/usr/bin:/bin"
            return run_spawn(self.ARGS, env_extra=env)

    def test_the_opt_in_alone_is_refused(self):
        rc, _out, err = self._spawn()
        self.assertEqual(rc, 2, err)
        self.assertIn("ORCA_SANDBOX_RECIPE", err)

    def test_a_non_recipe_id_is_refused(self):
        rc, _out, err = self._spawn(ORCA_SANDBOX_RECIPE="ab")
        self.assertEqual(rc, 2, err)
        self.assertIn("is not a recipe id", err)

    def test_a_recipe_id_with_shell_metacharacters_is_refused(self):
        rc, _out, err = self._spawn(ORCA_SANDBOX_RECIPE="lane-7; rm -rf /")
        self.assertEqual(rc, 2, err)
        self.assertIn("is not a recipe id", err)

    def test_without_orca_the_lane_is_refused(self):
        # #283: a sandbox cannot be certified without the runtime that provides it. Before this,
        # any readable file stood in for the runtime's own verdict.
        rc, _out, err = self._spawn(ORCA_SANDBOX_RECIPE="lane-7")
        self.assertEqual(rc, 2, err)
        self.assertIn("needs `orca` on PATH", err)

    def test_a_caller_named_transcript_is_no_longer_evidence(self):
        # THE bug: ORCA_SANDBOX_RECIPE=root + ORCA_SANDBOX_DOCTOR=/etc/passwd spawned a danger
        # worker. /etc/passwd names "root" and carries neither "fail" nor "warn". With no orca on
        # PATH the lane is now refused outright, and the named file is never read as evidence.
        rc, _out, err = self._spawn(ORCA_SANDBOX_RECIPE="root",
                                    ORCA_SANDBOX_DOCTOR="/etc/passwd")
        self.assertEqual(rc, 2, err)
        self.assertIn("needs `orca` on PATH", err)
        self.assertNotIn("SPAWN=NOTE", err)

    def test_a_doctor_that_exits_nonzero_is_refused(self):
        rc, _out, err = self._with_doctor("provisioning lane-7\n", rc=3,
                                          ORCA_SANDBOX_RECIPE="lane-7")
        self.assertEqual(rc, 2, err)
        self.assertIn("did not come up clean", err)

    def test_a_transcript_for_another_recipe_is_refused(self):
        rc, _out, err = self._with_doctor('{"recipe": "other-lane", "ok": true}',
                                          ORCA_SANDBOX_RECIPE="lane-7")
        self.assertEqual(rc, 2, err)
        self.assertIn("not clear", err)

    def test_a_warn_is_refused(self):
        # sandbox-policy.md: clear means no fail AND no warn; ok:true proves nothing.
        rc, _out, err = self._with_doctor(
            '{"recipe": "lane-7", "ok": true, "warnings": ["low disk"]}',
            ORCA_SANDBOX_RECIPE="lane-7")
        self.assertEqual(rc, 2, err)
        self.assertIn("no fail AND no warn", err)

    def test_a_fail_is_refused(self):
        rc, _out, err = self._with_doctor(
            '{"recipe": "lane-7", "ok": false, "checks": [{"name": "net", "status": "fail"}]}',
            ORCA_SANDBOX_RECIPE="lane-7")
        self.assertEqual(rc, 2, err)
        self.assertIn("no fail AND no warn", err)

    def test_an_empty_findings_list_is_clear(self):
        # The other half of #283: a REAL clear transcript says `"failures": []`, and the old
        # substring grep refused it for containing "fail".
        rc, _out, err = self._with_doctor(
            '{"recipe": "lane-7", "ok": true, "failures": [], "warnings": []}',
            ORCA_SANDBOX_RECIPE="lane-7")
        self.assertIn("doctored clear by this script", err)
        self.assertEqual(rc, 2, err)
        self.assertIn("authoritative placement", err)

    def test_a_clear_text_transcript_passes_the_gate(self):
        rc, _out, err = self._with_doctor("recipe lane-7 ok:true\n0 warnings, no failures\n",
                                          ORCA_SANDBOX_RECIPE="lane-7")
        self.assertIn("doctored clear by this script", err)
        self.assertEqual(rc, 2, err)
        self.assertIn("authoritative placement", err)

    def test_the_transcript_is_written_where_the_ledger_wants_it(self):
        # ORCA_SANDBOX_DOCTOR inverted: an OUTPUT path for the lane ledger, not a trusted input.
        with tempfile.TemporaryDirectory() as out_dir:
            dest = Path(out_dir) / "lane-7-doctor.json"
            payload = '{"recipe": "lane-7", "ok": true, "failures": []}'
            rc, _out, err = self._with_doctor(payload, ORCA_SANDBOX_RECIPE="lane-7",
                                              ORCA_SANDBOX_DOCTOR=str(dest))
            self.assertIn("doctored clear by this script", err)
            self.assertTrue(dest.is_file(), "the doctor transcript was not recorded")
            self.assertIn("lane-7", dest.read_text(encoding="utf-8"))

    def test_an_unwritable_ledger_path_is_refused(self):
        rc, _out, err = self._with_doctor('{"recipe": "lane-7", "ok": true, "failures": []}',
                                          ORCA_SANDBOX_RECIPE="lane-7",
                                          ORCA_SANDBOX_DOCTOR="/nonexistent-dir/doctor.json")
        self.assertEqual(rc, 2, err)
        self.assertIn("could not write the doctor transcript", err)

    def test_ro_and_rw_do_not_need_a_sandbox_recipe(self):
        for profile, opt_in in (("ro", {}), ("rw", {"ORCA_COORD_ALLOW_AUTONOMOUS_WRITE": "1"})):
            env = {"PROFILE": profile}
            env.update(opt_in)
            _rc, _out, err = run_spawn(self.ARGS, env_extra=env)
            self.assertNotIn("ORCA_SANDBOX_RECIPE", err, profile)


class TestSpawnWorkerHardening(unittest.TestCase):

    def test_scratch_key_distinguishes_tr_colliding_titles(self):
        # #44: "Fix: a/b" and "Fix: a\\b" both tr-squash to the same name; the raw-title
        # checksum must keep their scratch keys distinct so parallel spawns don't clobber.
        _, out_a, _ = run("Fix: a/b")
        _, out_b, _ = run("Fix: a\\b")
        key_a = next(l for l in out_a.splitlines() if l.startswith("safe_title="))
        key_b = next(l for l in out_b.splitlines() if l.startswith("safe_title="))
        self.assertNotEqual(key_a, key_b,
                            "tr-colliding titles must yield distinct scratch keys")

    def test_invalid_effort_is_refused(self):
        # #43: effort is interpolated into the codex launch command; an unknown value must
        # be rejected (fail closed), never interpolated verbatim. Same strict contract as
        # the other refusals (#173): exit 2 with the SPAWN=REFUSED marker.
        rc, _, err = run("t", effort='high"; touch /tmp/pwned; echo "')
        self.assertEqual(rc, 2, f"expected exit 2, got {rc}; stderr: {err}")
        self.assertIn("SPAWN=REFUSED", err)
        self.assertIn("invalid effort", err)

    def test_valid_effort_accepted(self):
        for eff in ("minimal", "low", "medium", "high", "xhigh"):
            rc, out, _ = run("t", effort=eff)
            self.assertEqual(rc, 0, f"valid effort {eff} should pass")
            self.assertIn(f"effort={eff}", out)


class TestSpawnWorkerRefusals(unittest.TestCase):
    """#173: every SPAWN=REFUSED branch must exit 2 with the marker on stderr.

    These run PAST the SW_SELFTEST hook — the refusal gates are the only thing
    between a fat-fingered coordinator invocation and an autonomous
    permission-bypass worker, so deleting one must turn this suite red.
    """

    BASE_ARGS = ["task_test", "path:/tmp/wt", "t"]

    def assert_refused(self, rc, err, needle):
        self.assertEqual(rc, 2, f"expected exit 2, got {rc}; stderr: {err}")
        self.assertIn("SPAWN=REFUSED", err)
        self.assertIn(needle, err)

    def test_unknown_agent_refused(self):
        rc, _, err = run_spawn(self.BASE_ARGS + ["bogus"])
        self.assert_refused(rc, err, "unknown agent 'bogus'")

    def test_unknown_profile_refused(self):
        rc, _, err = run_spawn(self.BASE_ARGS, env_extra={"PROFILE": "bogus"})
        self.assert_refused(rc, err, "unknown PROFILE='bogus'")

    def test_rw_without_optin_refused(self):
        # rw is the default profile; a bare invocation must fail closed.
        rc, _, err = run_spawn(self.BASE_ARGS)
        self.assert_refused(rc, err, "ORCA_COORD_ALLOW_AUTONOMOUS_WRITE=1")

    RW = {"PROFILE": "rw", "ORCA_COORD_ALLOW_AUTONOMOUS_WRITE": "1"}

    def test_named_hook_settings_without_registration_refused(self):
        # #562: claiming an armed guard that is not registered refuses.
        with tempfile.TemporaryDirectory() as tmp:
            settings = Path(tmp) / "settings.json"
            settings.write_text("{}")
            rc, _, err = run_spawn(self.BASE_ARGS, env_extra={
                **self.RW, "ORCA_DENY_HOOK_SETTINGS": str(settings)})
            self.assert_refused(rc, err, "not armed")

    def test_missing_hook_settings_file_refused(self):
        rc, _, err = run_spawn(self.BASE_ARGS, env_extra={
            **self.RW, "ORCA_DENY_HOOK_SETTINGS": "/nonexistent/settings.json"})
        self.assert_refused(rc, err, "not armed")

    def _armed_settings(self, tmp):
        wt = Path(tmp) / "wt"
        wt.mkdir()
        block = subprocess.run(
            ["sh", str(HOOK), "--settings", str(wt)],
            capture_output=True, text=True, check=True).stdout
        settings = Path(tmp) / "settings.json"
        settings.write_text(block)
        return settings

    def test_valid_registration_passes_the_arming_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._armed_settings(tmp)
            _rc, _, err = run_spawn(self.BASE_ARGS, env_extra={
                **self.RW, "ORCA_DENY_HOOK_SETTINGS": str(settings)})
            self.assertNotIn("not armed", err)
            self.assertNotIn("UNVERIFIED", err)

    def test_registered_command_that_never_denies_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._armed_settings(tmp)
            data = json.loads(settings.read_text())
            for entry in data["hooks"]["PreToolUse"]:
                for hook in entry["hooks"]:
                    hook["command"] = "true # deny-hook.sh"
            settings.write_text(json.dumps(data))
            rc, _, err = run_spawn(self.BASE_ARGS, env_extra={
                **self.RW, "ORCA_DENY_HOOK_SETTINGS": str(settings)})
            self.assert_refused(rc, err, "not armed")

    def test_unverified_arming_warns_but_proceeds_past_the_gate(self):
        # Unset: the spawn must SAY the guard is unverified (then go on to
        # fail later for want of a real orca — the warning is what we pin).
        _rc, _, err = run_spawn(self.BASE_ARGS, env_extra=dict(self.RW))
        self.assertIn("deny-hook arming UNVERIFIED", err)

    def test_danger_without_optin_refused(self):
        rc, _, err = run_spawn(self.BASE_ARGS, env_extra={"PROFILE": "danger"})
        self.assert_refused(rc, err, "ORCA_COORD_ALLOW_DANGER=1")

    def test_cmd_override_without_optin_refused(self):
        rc, _, err = run_spawn(
            self.BASE_ARGS,
            env_extra={"PROFILE": "ro", "WORKER_CMD": "echo hi"},
        )
        self.assert_refused(rc, err, "ORCA_COORD_ALLOW_CMD_OVERRIDE=1")

    def test_grok_ro_no_verified_flag_refused(self):
        # grok has no read-only mode in Orca's flag map and no WORKER_CMD given.
        rc, _, err = run_spawn(
            self.BASE_ARGS + ["grok"], env_extra={"PROFILE": "ro"},
        )
        self.assert_refused(rc, err, "no verified PROFILE=ro launch flag")

    def test_pending_without_mark_ready_refused(self):
        rc, _, err = run_spawn(
            self.BASE_ARGS, env_extra={"PROFILE": "ro"},
            task_list=task_list_payload({"id": "task_test", "status": "pending"}),
        )
        self.assert_refused(rc, err, "status=pending")

    def test_pending_unreadable_deps_refused(self):
        # deps present but not parseable JSON must fail closed, not count as none.
        rc, _, err = run_spawn(
            ["--mark-ready"] + self.BASE_ARGS, env_extra={"PROFILE": "ro"},
            task_list=task_list_payload(
                {"id": "task_test", "status": "pending", "deps": "not-json"}),
        )
        self.assert_refused(rc, err, "deps metadata unreadable")

    def test_pending_unmet_deps_refused(self):
        rc, _, err = run_spawn(
            ["--mark-ready"] + self.BASE_ARGS, env_extra={"PROFILE": "ro"},
            task_list=task_list_payload(
                {"id": "task_test", "status": "pending", "deps": ["dep1"]},
                {"id": "dep1", "status": "pending"}),
        )
        self.assert_refused(rc, err, "unmet_deps=1")

    def test_ready_with_unmet_deps_refused(self):
        # `ready` is settable by anyone with task-update; it used to dispatch
        # without the DAG check that `pending` had to clear.
        rc, _, err = run_spawn(
            self.BASE_ARGS, env_extra={"PROFILE": "ro"},
            task_list=task_list_payload(
                {"id": "task_test", "status": "ready", "deps": ["dep1"]},
                {"id": "dep1", "status": "in_progress"}),
        )
        self.assert_refused(rc, err, "status=ready unmet_deps=1")

    def test_ready_with_unreadable_deps_refused(self):
        rc, _, err = run_spawn(
            self.BASE_ARGS, env_extra={"PROFILE": "ro"},
            task_list=task_list_payload(
                {"id": "task_test", "status": "ready", "deps": {"dep1": 1}}),
        )
        self.assert_refused(rc, err, "deps metadata unreadable")

    def test_task_not_found_refused(self):
        rc, _, err = run_spawn(
            self.BASE_ARGS, env_extra={"PROFILE": "ro"},
            task_list=task_list_payload(),
        )
        self.assert_refused(rc, err, "not found in task-list")

    def test_non_ready_status_refused(self):
        rc, _, err = run_spawn(
            self.BASE_ARGS, env_extra={"PROFILE": "ro"},
            task_list=task_list_payload({"id": "task_test", "status": "in_progress"}),
        )
        self.assert_refused(rc, err, "only ready")


class TestSpawnWorkerV5Lanes(unittest.TestCase):
    """v5 (2026-09-10 upstream re-pin, source-witnessed at v1.4.199).

    The v4 lane shipped three false mechanisms: a blind re-Enter/heartbeat loop on a preamble
    `--inject` had ALREADY submitted, four of ten refusal codes handled, and a `terminal wait`
    result nobody read. Each of those is a way to put a second writer on a live worktree, so
    deleting any assertion below must turn this suite red.
    """

    READY_RECEIPT = {
        "result": {
            "runId": "run_x", "taskId": "task_test", "dispatchId": "ctx_x",
            "state": "ready", "stage": "dispatch_input",
            "launch": {"requested": {"agent": "claude"},
                       "effective": {"agent": "claude", "args": "--dangerously-skip-permissions"}},
            "effects": [{"kind": "terminal", "role": "agent", "action": "created",
                         "id": "term_agent1"}],
        }
    }

    def _stub(self, tmp, *, receipt=None, ws_rc=0, inject=None, wait=None,
              preamble=None, send=None, send_rc=0):
        """Stub orca per subcommand. Each payload is written to a file the stub cats, so no
        JSON ever passes through shell quoting."""
        files = {
            "task-list.json": task_list_payload({"id": "task_test", "status": "ready"}),
            "receipt.json": receipt if receipt is not None else self.READY_RECEIPT,
            "inject.json": inject if inject is not None else {
                "result": {"dispatch": {"id": "ctx_x"}, "injected": True,
                           "prompt": {"requestId": "req_1", "stages": ["input_accepted",
                                                                      "turn_started"],
                                      "provider": "claude", "observation": "supported"}}},
            "wait.json": wait if wait is not None else {"result": {"wait": {"satisfied": True}}},
            "preamble.json": preamble if preamble is not None else {
                "result": {"dispatch": {"id": "ctx_x"}, "preamble": "PREAMBLE BODY"}},
            "send.json": send if send is not None else {
                "result": {"send": {"accepted": True,
                                    "prompt": {"requestId": "req_1",
                                               "stages": ["input_accepted", "turn_started"]}}}},
            "terminal-create.json": {"result": {"terminal": {"handle": "term_shell1"}}},
        }
        for name, payload in files.items():
            (Path(tmp) / name).write_text(json.dumps(payload))
        log = Path(tmp) / "orca-calls.log"
        stub = Path(tmp) / "orca"
        stub.write_text(f"""#!/bin/sh
printf '%s\\n' "$*" >> "{log}"
case "$*" in
  *task-list*)          cat "{tmp}/task-list.json" ;;
  *worker-start*)       cat "{tmp}/receipt.json"; exit {ws_rc} ;;
  *dispatch-show*)      cat "{tmp}/preamble.json" ;;
  *dispatch*--inject*)  cat "{tmp}/inject.json" ;;
  *terminal\\ create*)   cat "{tmp}/terminal-create.json" ;;
  *terminal\\ wait*)     cat "{tmp}/wait.json" ;;
  *terminal\\ send*)     cat "{tmp}/send.json"; exit {send_rc} ;;
  *)                    printf '%s' '{{"result": {{}}}}' ;;
esac
""")
        stub.chmod(0o755)
        return log

    def _run(self, tmp, args, env_extra=None):
        env = {"PATH": f"{tmp}:/usr/bin:/bin", "SP": tmp, "ORCA_CLI_COMMAND": "orca",
               "SETTLE_SECS": "0", "SUBMIT_SECS": "1"}
        env.update(env_extra or {})
        return subprocess.run(["bash", str(SPAWN), *args], env=env,
                              capture_output=True, text=True)

    RW = {"PROFILE": "rw", "ORCA_COORD_ALLOW_AUTONOMOUS_WRITE": "1"}
    RO = {"PROFILE": "ro"}
    ARGS = ["task_test", "path:/tmp/wt", "t"]

    def _parallel_scratch_attempts(self, profile, pattern):
        # AC-2: two distinct tasks with one title, followed by parallel retries of both.
        # Assert retained receipt contents, not just a generated name or a timing-dependent race.
        with tempfile.TemporaryDirectory(prefix="spawn shared ") as tmp:
            root = Path(tmp)
            self._stub(tmp)
            (root / "task-list.json").write_text(json.dumps(task_list_payload(
                {"id": "task_a", "status": "ready"}, {"id": "task_b", "status": "ready"})))
            stub = root / "orca"
            text = stub.read_text()
            for name in ("receipt", "inject", "terminal-create"):
                text = text.replace(f'cat "{tmp}/{name}.json"',
                                    f'cat "{tmp}/{name}-$TEST_ATTEMPT.json"')
            stub.write_text(text)
            attempts = ["a1", "b1", "a2", "b2"]
            for attempt in attempts:
                receipt = copy.deepcopy(self.READY_RECEIPT)
                receipt["result"].update(taskId=f"task_{attempt[0]}", dispatchId=attempt)
                receipt["result"]["effects"][0]["id"] = f"term_{attempt}"
                (root / f"receipt-{attempt}.json").write_text(json.dumps(receipt))
                injection = json.loads((root / "inject.json").read_text())
                injection["result"]["dispatch"]["id"] = attempt
                (root / f"inject-{attempt}.json").write_text(json.dumps(injection))
                (root / f"terminal-create-{attempt}.json").write_text(json.dumps(
                    {"result": {"terminal": {"handle": f"term_{attempt}"}}}))

            def start(attempt):
                return self._run(tmp, [f"task_{attempt[0]}", "current", "Review unit"],
                                 dict(profile, TEST_ATTEMPT=attempt))

            results = []
            with ThreadPoolExecutor(max_workers=2) as pool:
                results.extend(pool.map(start, attempts[:2]))
                results.extend(pool.map(start, attempts[2:]))
            for result in results:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            receipts = list(root.rglob(pattern))
            self.assertEqual(len(receipts), 4, "each attempt must retain its own receipt")
            directories = {p.parent for p in receipts}
            self.assertEqual(len(directories), 4, "all scratch files need per-attempt storage")
            ids = set()
            for receipt in receipts:
                data = json.loads(receipt.read_text())["result"]
                ids.add(data.get("dispatchId") or data["dispatch"]["id"])
                self.assertEqual(len(list(receipt.parent.glob("tl-*.json"))), 1)
            self.assertEqual(ids, set(attempts))
            for attempt, result in zip(attempts, results, strict=True):
                self.assertIn(f"HANDLE=term_{attempt} ", result.stdout)
                scratch = next(line.removeprefix("SCRATCH=") for line in result.stdout.splitlines()
                               if line.startswith("SCRATCH="))
                self.assertIn(Path(scratch), directories)

    def test_parallel_same_title_tasks_and_retries_keep_supervised_receipts(self):
        self._parallel_scratch_attempts(self.RW, "ws-*.json")

    def test_parallel_same_title_tasks_and_retries_keep_custom_lane_receipts(self):
        self._parallel_scratch_attempts(self.RO, "dispatch-*.json")

    def test_danger_refuses_unbound_placement_after_clear_doctor_in_both_lanes(self):
        # AC-1: a healthy recipe is not proof of where the worker will execute.
        # Even a ready receipt with the bypass flag cannot establish this BEFORE launch.
        for selector in ("current", "path:/tmp/local", "id:repo-b::/sandbox-b"):
            for override in (False, True):
                with self.subTest(selector=selector, override=override):
                    with tempfile.TemporaryDirectory() as tmp:
                        log = self._stub(tmp)
                        doctor = Path(tmp) / "doctor.json"
                        doctor.write_text(json.dumps({"recipe": "lane-7", "ok": True,
                                                      "failures": [], "warnings": []}))
                        stub = Path(tmp) / "orca"
                        stub.write_text(stub.read_text().replace(
                            'case "$*" in',
                            f'case "$*" in\n  *"recipe doctor"*) cat "{doctor}" ;;', 1))
                        env = {"PROFILE": "danger", "ORCA_COORD_ALLOW_DANGER": "1",
                               "ORCA_SANDBOX_RECIPE": "lane-7"}
                        if override:
                            env.update(WORKER_CMD="claude --dangerously-skip-permissions",
                                       ORCA_COORD_ALLOW_CMD_OVERRIDE="1")
                        p = self._run(tmp, ["task_test", selector, "t"], env)
                        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                        self.assertIn("doctored clear by this script", p.stderr)
                        self.assertIn("SPAWN=REFUSED", p.stderr)
                        self.assertIn("authoritative placement", p.stderr)
                        self.assertIn("PROFILE=ro or PROFILE=rw", p.stderr)
                        calls = log.read_text()
                        self.assertIn("recipe doctor lane-7", calls)
                        # #335 review: the refusal is unconditional, so no doctor verdict can
                        # authorize this lane and provisioning a VM only bills for the privilege.
                        self.assertNotIn("--provision", calls)
                        for launch in ("worker-start", "terminal create", "--inject",
                                       "task-update"):
                            self.assertNotIn(launch, calls)

    # --- (a) custom-argv lane: receipted sends, no blind Enter ---------------------------

    def test_no_blind_enter_and_no_loop(self):
        # §7 item 2: `dispatch --inject` ALREADY submits the preamble, so a bare
        # `terminal send --enter` is a stray keystroke outside the receipt model, and the guide's
        # rule is "never resend on silence". The lane must issue NO --enter send at all when the
        # receipt already carries turn_started, and must never poll dispatch-show for a heartbeat.
        with tempfile.TemporaryDirectory() as tmp:
            log = self._stub(tmp)
            p = self._run(tmp, self.ARGS, self.RO)
            self.assertEqual(p.returncode, 0, p.stderr)
            calls = log.read_text()
            self.assertNotIn("terminal send", calls,
                             "a receipt carrying turn_started needs no send at all")
            self.assertNotIn("dispatch-show", calls,
                             "the heartbeat poll loop is gone; the receipt is the verdict")
            self.assertIn("STAGES=input_accepted,turn_started", p.stdout)
            self.assertIn("HANDLE=term_shell1", p.stdout)

    def test_input_accepted_only_is_exit_3_unproven(self):
        # `accepted: true` proves input acceptance, NOT a started turn. With no requestId there is
        # nothing to replay, so the lane must report UNPROVEN — never resend, never respawn.
        with tempfile.TemporaryDirectory() as tmp:
            log = self._stub(tmp, inject={"result": {"injected": True, "prompt": {
                "requestId": "", "stages": ["input_accepted"]}}})
            p = self._run(tmp, self.ARGS, self.RO)
            self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
            self.assertIn("STAGES=input_accepted", p.stdout)
            self.assertIn("SPAWN=UNPROVEN", p.stderr)
            self.assertIn("--screen", p.stderr,
                          "exit 3 must name the runtime's own inspection command")
            self.assertNotIn("terminal send", log.read_text(),
                             "no replay is possible without a requestId — and no resend either")

    def test_dispatch_request_cannot_be_retried_as_terminal_send(self):
        # AC-3 / pin helper-regenerated-retry: Orca 1.4.200 rejects the cross-method
        # retry with request_mismatch. Even --return-preamble's original bytes cannot
        # change the mutation method bound to a dispatch request. All identities here
        # are synthetic; no real helper, capability, or terminal is reused.
        for original in (None, "ORIGINAL BODY\n\n"):
            with self.subTest(original_available=original is not None):
                with tempfile.TemporaryDirectory() as tmp:
                    injection = {"result": {"dispatch": {"id": "ctx_x"}, "injected": True,
                                           "prompt": {"requestId": "req_1",
                                                      "stages": ["input_accepted"]}}}
                    if original is not None:
                        injection["result"]["preamble"] = original
                    log = self._stub(tmp, inject=injection,
                                     preamble={"result": {"dispatch": {"id": "ctx_x"},
                                                          "preamble": "REGENERATED BODY"}},
                                     send={"error": {"code": "request_mismatch",
                                                     "message": "Request used with different input"}},
                                     send_rc=1)
                    p = self._run(tmp, self.ARGS, self.RO)
                    calls = log.read_text()
                    self.assertNotIn("terminal send", calls,
                                     "a dispatch request must never become a terminal-send retry")
                    self.assertNotIn("dispatch-show", calls,
                                     "a generated preview is not the original retry payload")
                    self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
                    self.assertIn("HANDLE=term_shell1 STAGES=input_accepted", p.stdout)
                    self.assertIn("SPAWN=UNPROVEN", p.stderr)
                    self.assertIn("original", p.stderr)
                    self.assertIn("orca terminal read --terminal term_shell1 --screen", p.stderr)
                    self.assertIn("never respawn", p.stderr)
                    self.assertEqual(calls.count("orchestration dispatch --task"), 1)
                    self.assertEqual(calls.count("terminal create"), 1)
                    for cleanup in ("worker-stop", "worker-abandon", "worker-release", "terminal close"):
                        self.assertNotIn(cleanup, calls)
                    receipts = list(Path(tmp).rglob("dispatch-*.json"))
                    self.assertEqual(len(receipts), 1)
                    self.assertEqual(json.loads(receipts[0].read_text()), injection)
                    self.assertEqual(len(list(receipts[0].parent.glob("sw-*.json"))), 1)

    def test_unbound_replay_turn_start_cannot_prove_dispatch(self):
        # A different request's activity and a nonzero send with success-shaped JSON
        # are neither proof of this dispatch starting. The wrapper must keep its
        # original accepted-only receipt, including on a permissive/changed host.
        for send_rc in (0, 1):
            with self.subTest(send_rc=send_rc):
                with tempfile.TemporaryDirectory() as tmp:
                    log = self._stub(tmp, inject={"result": {"injected": True, "prompt": {
                        "requestId": "req_1", "stages": ["input_accepted"]}}},
                        send={"result": {"send": {"accepted": True, "prompt": {
                            "requestId": "req_unrelated", "stages": ["turn_started"]}}}},
                        send_rc=send_rc)
                    p = self._run(tmp, self.ARGS, self.RO)
                    self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
                    self.assertIn("STAGES=input_accepted", p.stdout)
                    self.assertNotIn("turn_started", p.stdout)
                    self.assertNotIn("terminal send", log.read_text())

    # --- (c) terminal wait: read wait.satisfied ------------------------------------------

    def test_unsatisfied_wait_fails_closed_on_the_field(self):
        # v4 failed closed only because the CLI also sets exit 1 for this case. Read the field.
        with tempfile.TemporaryDirectory() as tmp:
            log = self._stub(tmp, wait={"result": {"wait": {"satisfied": False}}})
            p = self._run(tmp, self.ARGS, self.RO)
            self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
            self.assertIn("wait.satisfied=false", p.stderr)
            self.assertNotIn("--inject", log.read_text(),
                             "a preamble must never be injected into a pane that never went idle")

    def test_absent_wait_field_is_not_a_false(self):
        # An older host that omits the field is absence, not a negative verdict.
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp, wait={"result": {}})
            p = self._run(tmp, self.ARGS, self.RO)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    # --- (b) supervised lane: every typed refusal, nextSteps, outcome_unknown -------------

    POLICY_CODES = ["task_not_found", "task_not_startable", "inject_rejected",
                    "nested_worker_depth_exceeded", "consumer_fenced", "dispatch_inactive"]

    def test_every_typed_refusal_is_exit_2_with_next_steps(self):
        # v4 whitelisted four codes; task_not_found / inject_rejected / runtime_error fell through
        # to "spawn failed" and were retried as transport errors. Branch on error.code.
        for code in self.POLICY_CODES:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                self._stub(tmp, ws_rc=1, receipt={"error": {
                    "code": code, "message": "refused",
                    "data": {"nextSteps": [f"do the {code} thing", "then this"]}}})
                p = self._run(tmp, self.ARGS, self.RW)
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertIn("SPAWN=REFUSED", p.stderr)
                self.assertIn(code, p.stderr)
                self.assertIn(f"nextStep: do the {code} thing", p.stderr,
                              "error.data.nextSteps is the runtime's own recovery text and is "
                              "surfaced verbatim")
                self.assertIn("nextStep: then this", p.stderr)

    def test_runtime_error_is_exit_1_not_a_policy_refusal(self):
        # runtime_error is the documented catch-all: "do not retry unchanged".
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp, ws_rc=1, receipt={"error": {
                "code": "runtime_error", "message": "boom",
                "data": {"nextSteps": ["read the message"]}}})
            p = self._run(tmp, self.ARGS, self.RW)
            self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
            self.assertIn("SPAWN=FAILED", p.stderr)
            self.assertIn("runtime_error", p.stderr)
            self.assertIn("nextStep: read the message", p.stderr)

    def test_refusal_without_data_still_branches(self):
        # Older hosts may omit `data` entirely — every field is optional.
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp, ws_rc=1, receipt={"error": {"code": "consumer_fenced"}})
            p = self._run(tmp, self.ARGS, self.RW)
            self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
            self.assertIn("consumer_fenced", p.stderr)

    def test_nonzero_call_with_unparseable_receipt_fails_closed(self):
        # A missing binary / truncated write / unknown response shape exits nonzero with nothing
        # the parser can object to. That must READ AS FAILURE, never as ready — a fail-open here
        # would report a worker that was never started.
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp, ws_rc=127, receipt={})
            p = self._run(tmp, self.ARGS, self.RW)
            self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
            self.assertIn("SPAWN=FAILED", p.stderr)
            self.assertNotIn("READY=", p.stdout)

    def test_outcome_unknown_is_exit_4_with_next_commands(self):
        # The next release returns this for an unobserved turn start. It is NOT a failure: a
        # respawn here puts a second writer beside a possibly-live pane (the 2026-07-15 class).
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp, ws_rc=1, receipt={"result": {
                "taskId": "task_test", "dispatchId": "ctx_x",
                "state": "outcome_unknown", "stage": "turn_start_unobserved",
                "effects": [{"kind": "terminal", "role": "agent", "id": "term_agent1"}],
                "nextCommands": [
                    "orca orchestration worker-show --dispatch ctx_x --json",
                    "orca orchestration worker-abandon --dispatch ctx_x --json"]}})
            p = self._run(tmp, self.ARGS, self.RW)
            self.assertEqual(p.returncode, 4, p.stdout + p.stderr)
            self.assertIn("SPAWN=OUTCOME_UNKNOWN", p.stderr)
            self.assertIn("nextCommand: orca orchestration worker-show --dispatch ctx_x", p.stderr)
            self.assertIn("nextCommand: orca orchestration worker-abandon --dispatch ctx_x",
                          p.stderr)
            self.assertRegex(p.stderr, r"(?i)never\s+respawn")
            self.assertIn("HANDLE=term_agent1", p.stdout)

    # --- (e) launch.effective -------------------------------------------------------------

    def test_launch_effective_is_printed_when_present(self):
        # Never claim a permission flag, model, or effort from the REQUESTED args alone.
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp)
            p = self._run(tmp, self.ARGS, self.RW)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("LAUNCH_EFFECTIVE=", p.stdout)
            self.assertIn("--dangerously-skip-permissions", p.stdout)

    def test_launch_effective_absent_is_not_invented(self):
        # An absent field is reported as absent, never fabricated. Since #298 it is also not a
        # pass — the exit is 5, LAUNCHED_UNUSABLE — but the no-fabrication half is unchanged and
        # is what this test is for: the launcher never prints a launch it did not receive.
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp, receipt={"result": {
                "taskId": "task_test", "dispatchId": "ctx_x", "state": "ready",
                "effects": [{"kind": "terminal", "role": "agent", "id": "term_agent1"}]}})
            p = self._run(tmp, self.ARGS, self.RW)
            self.assertEqual(p.returncode, 5, p.stderr)
            self.assertNotIn("LAUNCH_EFFECTIVE=", p.stdout)

    # --- #301: the runtime pin is compared to the binary on PATH ----------------------------

    def _stub_version(self, tmp, version_output):
        """Re-point the stub's `--version` answer without disturbing the other subcommands."""
        stub = Path(tmp) / "orca"
        text = stub.read_text()
        stub.write_text(text.replace("case \"$*\" in",
                                     f'case "$*" in\n  --version) echo {version_output!r} ;;', 1))
        stub.chmod(0o755)

    def _notes(self, tmp, version_output):
        self._stub_version(tmp, version_output)
        p = self._run(tmp, self.ARGS, self.RW)
        return [ln for ln in p.stderr.splitlines() if "pins.json" in ln], p

    def test_a_drifted_runtime_arms_pin_it(self):
        """#301: runtime/pins.json records the Orca the catalog was witnessed against, and
        nothing compared it to the binary on PATH.

        Every behaviour this script depends on — the YOLO flag map, the receipt shape — was read
        off the pinned version's source. Drift does not make them wrong; it makes them
        unwitnessed, and nothing said so.
        """
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp)
            notes, p = self._notes(tmp, "orca 1.5.0 (build abc)")
            self.assertTrue(notes, "a drifted runtime produced no note at all")
            self.assertIn("1.5.0", notes[0])
            self.assertIn("v1.4.229", notes[0], "the note must name the version it expected")
            self.assertIn("pin-it", notes[0], "the note must arm the mission that re-witnesses")
            self.assertEqual(p.returncode, 0,
                             "drift is a NOTE, not a refusal — an upstream release must not "
                             "stop every spawn in the fleet")

    def test_a_matching_runtime_is_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp)
            notes, p = self._notes(tmp, "orca v1.4.229")
            self.assertEqual(notes, [], "a matching runtime must say nothing")

    def test_an_owed_app_update_advises_the_update_not_a_completed_pin(self):
        # Review on #501 (pin then v1.4.209; v1.4.224 at the last bump, now v1.4.229):
        # pins.json advanced while PATH still runs an older witnessed build
        # (1.4.224 is onpath_at_witness at the 229 pin) — the owed-update case.
        # The note must say 'update the app', never 're-run a completed pin-it'. A version
        # that is NOT the recorded one (1.5.0 above) still arms pin-it as fresh drift.
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp)
            notes, p = self._notes(tmp, "orca 1.4.204")
            self.assertTrue(notes, "the owed-update divergence produced no note at all")
            self.assertIn("update Orca to v1.4.229", notes[0])
            self.assertNotIn("run pin-it to re-witness", notes[0])
            self.assertEqual(p.returncode, 0)
            self.assertEqual(p.returncode, 0, p.stderr)

    def test_a_previous_pin_advises_the_update(self):
        # Review on #507: the pin advanced to v1.4.229 while a host may still run
        # the previous pin v1.4.224. Older-than-pin is a lagging app, not fresh
        # drift — the advice is to update, never to re-run the completed pin.
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp)
            notes, p = self._notes(tmp, "orca 1.4.224")
            self.assertTrue(notes, "the previous pin produced no note at all")
            self.assertIn("update Orca to v1.4.229", notes[0])
            self.assertNotIn("run pin-it to re-witness", notes[0])
            self.assertEqual(p.returncode, 0)

    def test_a_newer_patch_arms_pin_it(self):
        # The comparator's other direction: a version AHEAD of the pin is
        # genuinely unwitnessed and must arm pin-it, not advise an update.
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp)
            notes, p = self._notes(tmp, "orca 1.4.230")
            self.assertTrue(notes, "a newer patch produced no note at all")
            self.assertIn("run pin-it to re-witness", notes[0])
            self.assertEqual(p.returncode, 0)

    def test_the_v_prefix_is_not_a_difference(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp)
            self.assertEqual(self._notes(tmp, "orca 1.4.229")[0], [],
                             "`1.4.229` and `v1.4.229` are the same version")

    def test_an_unreadable_version_says_so_rather_than_passing(self):
        # "Nothing noticed the drift" is the defect this check exists to fix, so a check that
        # quietly stops working — because the output format moved — is that defect wearing a fix.
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp)
            notes, p = self._notes(tmp, "orca (no version here)")
            self.assertTrue(notes, "an unreadable version passed in silence")
            self.assertIn("could not be checked", notes[0])
            self.assertEqual(p.returncode, 0, p.stderr)

    # --- #298: four fail-open paths in the launcher ----------------------------------------

    def _task_status(self, tmp, status):
        (Path(tmp) / "task-list.json").write_text(
            json.dumps(task_list_payload({"id": "task_test", "status": status})))

    def test_an_exit_zero_receipt_naming_no_state_is_not_a_success(self):
        """#298: "the receipt is the verdict" — and a receipt naming no state is not one.

        This read as READY on the call's exit status alone, which the header three lines above it
        says is NOT the verdict. So a changed receipt shape silently disabled the state check.
        UNKNOWN rather than FAILED: worker-start exited 0, so a worker may be live, and a respawn
        beside it is the dual-writer class.
        """
        stateless = {"result": {"runId": "r", "dispatchId": "ctx_x",
                                "effects": [{"kind": "terminal", "role": "agent",
                                             "action": "created", "id": "term_a"}]}}
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp, receipt=stateless, ws_rc=0)
            p = self._run(tmp, self.ARGS, self.RW)
            self.assertEqual(p.returncode, 4, p.stdout + p.stderr)
            self.assertIn("OUTCOME_UNKNOWN", p.stderr)
            self.assertIn("NEVER RESPAWN", p.stderr)
            self.assertNotIn("READY=exit0", p.stdout)

    def test_a_receipt_that_is_not_even_a_dict_is_not_a_success(self):
        # The worst shape: no handle and no dispatch id to inspect with, reported as READY.
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp, receipt={"result": "surprise"}, ws_rc=0)
            p = self._run(tmp, self.ARGS, self.RW)
            self.assertEqual(p.returncode, 4, p.stdout + p.stderr)
            self.assertIn("OUTCOME_UNKNOWN", p.stderr)

    def test_a_stateless_receipt_from_a_FAILED_call_is_still_a_failure(self):
        # rc=127 is a missing binary: no worker exists, so this stays FAILED rather than sending
        # a coordinator to inspect for one. Only the exit-0 case is UNKNOWN.
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp, receipt={}, ws_rc=127)
            p = self._run(tmp, self.ARGS, self.RW)
            self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
            self.assertIn("SPAWN=FAILED", p.stderr)

    def test_a_launch_that_lacks_the_profiles_flag_is_refused(self):
        """#298: the PROFILE is a capability grant; launch.effective is what the host launched.

        worker-start takes its args from the host's agentDefaultArgs, not from anything this
        script builds, so the two CAN disagree — and when they did the launch proceeded, which
        made the profile advisory rather than enforced.
        """
        for agent, wrong in (("claude", "--permission-mode plan"),
                             ("codex", "--sandbox read-only"),
                             ("cursor", "--permission-mode plan"),
                             ("antigravity", "--yolo")):
            with self.subTest(agent=agent):
                receipt = copy.deepcopy(self.READY_RECEIPT)
                receipt["result"]["launch"]["effective"] = {"agent": agent, "args": wrong}
                with tempfile.TemporaryDirectory() as tmp:
                    self._stub(tmp, receipt=receipt)
                    p = self._run(tmp, self.ARGS + [agent], self.RW)
                    self.assertEqual(p.returncode, 5, p.stdout + p.stderr)
                    self.assertIn("LAUNCHED_UNUSABLE", p.stderr)
                    self.assertIn("NEVER RESPAWN", p.stderr)
                    self.assertIn("HANDLE=", p.stdout,
                                  "the handle is how the live worker gets stopped")

    def test_a_multiword_flag_must_appear_contiguously(self):
        # grok's flag is `--permission-mode bypassPermissions`. Finding its two words far apart,
        # beside `--permission-mode plan`, is not finding the flag.
        receipt = copy.deepcopy(self.READY_RECEIPT)
        receipt["result"]["launch"]["effective"] = {
            "agent": "grok", "args": "--permission-mode plan --other bypassPermissions"}
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp, receipt=receipt)
            p = self._run(tmp, self.ARGS + ["grok"], self.RW)
            self.assertEqual(p.returncode, 5, p.stdout + p.stderr)

    def test_the_profiles_flag_is_accepted_in_every_shape_a_host_reports_it(self):
        for eff in ("--dangerously-skip-permissions",
                    {"agent": "claude", "args": "--dangerously-skip-permissions"},
                    {"agent": "claude", "args": ["--dangerously-skip-permissions"]},
                    ["claude", "--dangerously-skip-permissions"]):
            with self.subTest(eff=eff):
                receipt = copy.deepcopy(self.READY_RECEIPT)
                receipt["result"]["launch"]["effective"] = eff
                with tempfile.TemporaryDirectory() as tmp:
                    self._stub(tmp, receipt=receipt)
                    p = self._run(tmp, self.ARGS, self.RW)
                    self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_an_absent_launch_effective_is_not_a_pass(self):
        """PR #308 review, P1. I first had this warn and proceed; that was wrong.

        `sandbox-policy.md:16-20` makes this field THE way to tell an autonomous worker from a
        prompting one — "neither is knowable from source: read launch.effective off the start
        receipt" — and `dispatch-lifecycle.md:20` has it in the documented receipt shape. So a
        receipt without it is a receipt this script cannot read, which is the same fail-open the
        missing-`state` fix removed one field over. On a manual host the worker blocks on
        invisible dialogs while the fleet believes it is autonomous.
        """
        for launch in ({"requested": {"agent": "claude"}}, {}):
            with self.subTest(launch=launch):
                receipt = copy.deepcopy(self.READY_RECEIPT)
                receipt["result"]["launch"] = launch
                with tempfile.TemporaryDirectory() as tmp:
                    self._stub(tmp, receipt=receipt)
                    p = self._run(tmp, self.ARGS, self.RW)
                    self.assertEqual(p.returncode, 5, p.stdout + p.stderr)
                    self.assertIn("LAUNCHED_UNUSABLE", p.stderr)
                    self.assertIn("no launch.effective", p.stderr)

    def test_unusable_is_neither_failed_nor_unknown(self):
        # A worker IS live: reporting "failed" invites a respawn beside it, and "unknown" claims
        # not to know something the receipt just said. Exit 5 says stop it, and names the handle.
        receipt = copy.deepcopy(self.READY_RECEIPT)
        receipt["result"]["launch"]["effective"] = {"agent": "claude", "args": "--permission-mode plan"}
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp, receipt=receipt)
            p = self._run(tmp, self.ARGS, self.RW)
            self.assertEqual(p.returncode, 5)
            self.assertNotIn("SPAWN=FAILED", p.stderr)
            self.assertNotIn("OUTCOME_UNKNOWN", p.stderr)
            self.assertIn("HANDLE=term_agent1", p.stdout)

    def test_a_failed_call_is_not_upgraded_to_unusable(self):
        # rc!=0 plus an unreadable capability is still a failed call, not a live worker.
        receipt = copy.deepcopy(self.READY_RECEIPT)
        del receipt["result"]["launch"]["effective"]
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp, receipt=receipt, ws_rc=127)
            p = self._run(tmp, self.ARGS, self.RW)
            self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
            self.assertIn("SPAWN=FAILED", p.stderr)

    def test_a_status_is_read_as_a_token_not_word_split(self):
        """#298: `read -r status unmet` split the status, so its FIRST WORD decided dispatch.

        `ready for review` read as `ready` and was dispatched. The shape matters more than the
        example: any status the DAG grows whose first word is a dispatchable one would dispatch.
        """
        for status in ("ready for review", "ready to merge", "not ready"):
            with self.subTest(status=status):
                with tempfile.TemporaryDirectory() as tmp:
                    self._stub(tmp)
                    self._task_status(tmp, status)
                    p = self._run(tmp, self.ARGS, self.RW)
                    self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                    self.assertIn(status, p.stderr,
                                  "the refusal must name the whole status it read")

    def test_an_exact_status_still_dispatches(self):
        for status in ("ready", "pending"):
            with self.subTest(status=status):
                with tempfile.TemporaryDirectory() as tmp:
                    self._stub(tmp)
                    self._task_status(tmp, status)
                    extra = ["--mark-ready"] if status == "pending" else []
                    p = self._run(tmp, self.ARGS + extra, self.RW)
                    self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    # --- (d) roster: cursor in, kilo deliberately out --------------------------------------

    def test_cursor_is_on_the_roster_for_write_tiers(self):
        # Orca maps cursor to --yolo (tui-agent-permissions.ts:21 at v1.4.199); v4 excluded it.
        # The receipt has to report cursor's OWN flag: the shared fixture reports claude's, and
        # since #298 a launch.effective that does not carry the profile's flag is refused.
        receipt = copy.deepcopy(self.READY_RECEIPT)
        receipt["result"]["launch"]["effective"] = {"agent": "cursor", "args": "--yolo"}
        with tempfile.TemporaryDirectory() as tmp:
            log = self._stub(tmp, receipt=receipt)
            p = self._run(tmp, self.ARGS + ["cursor"], self.RW)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("--agent cursor", log.read_text())

    def test_cursor_ro_has_no_verified_flag(self):
        # Orca has no read-only mode for cursor — fail closed, exactly like grok.
        rc, _, err = run_spawn(self.ARGS + ["cursor"], env_extra={"PROFILE": "ro"})
        self.assertEqual(rc, 2, err)
        self.assertIn("no verified PROFILE=ro launch flag", err)

    def test_antigravity_is_on_the_roster_for_write_tiers(self):
        # Pinned coordinator-loop: worker-start accepts --agent antigravity. Its autonomous
        # flag is claude's (`tui-agent-permissions.ts`), so the default receipt already
        # carries it. ro stays fail-closed: Orca's map has no read-only flag for it.
        with tempfile.TemporaryDirectory() as tmp:
            log = self._stub(tmp)
            p = self._run(tmp, self.ARGS + ["antigravity"], self.RW)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("--agent antigravity", log.read_text())

    def test_antigravity_ro_has_no_verified_flag(self):
        rc, _, err = run_spawn(self.ARGS + ["antigravity"], env_extra={"PROFILE": "ro"})
        self.assertEqual(rc, 2, err)
        self.assertIn("no verified PROFILE=ro launch flag", err)

    def test_antigravity_argv_is_the_hosts_or_the_callers_never_the_map(self):
        # worker-start's agent id is antigravity; Orca's detectCmd resolves it to `agy`
        # (tui-agent-config.ts), so on the write tier the HOST names the binary and the launch
        # map's rw entry is only the verified-flag gate. The one custom-argv launch antigravity
        # has is WORKER_CMD, which must reach `terminal create` exactly as the caller wrote it.
        with tempfile.TemporaryDirectory() as tmp:
            log = self._stub(tmp)
            p = self._run(tmp, self.ARGS + ["antigravity"], self.RW)
            self.assertEqual(p.returncode, 0, p.stderr)
            calls = log.read_text()
            self.assertIn("--agent antigravity", calls)
            self.assertNotIn("terminal create", calls)
        for profile in (self.RO, self.RW):
            with self.subTest(profile=profile["PROFILE"]):
                with tempfile.TemporaryDirectory() as tmp:
                    log = self._stub(tmp)
                    env = dict(profile, WORKER_CMD="agy", ORCA_COORD_ALLOW_CMD_OVERRIDE="1")
                    p = self._run(tmp, self.ARGS + ["antigravity"], env)
                    self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                    calls = log.read_text()
                    self.assertNotIn("worker-start", calls)
                    create = next(l for l in calls.splitlines() if "terminal create" in l)
                    self.assertIn("--command agy --json", create)
                    self.assertIn("--inject", calls)

    def test_kilo_stays_off_the_roster(self):
        # Orca STRIPS --dangerously-skip-permissions from kilo as it does from opencode
        # (tui-agent-launch-defaults.ts:5-8), so kilo must not silently launch a prompting worker.
        rc, _, err = run_spawn(self.ARGS + ["kilo"], env_extra=dict(self.RW))
        self.assertEqual(rc, 2, err)
        self.assertIn("unknown agent 'kilo'", err)

    # --- lane contracts carried forward from v3/v4 (still true at v1.4.199) ----------------

    def test_worker_start_lane_omits_name_on_existing_worktree(self):
        # Creation flags (--name et al.) are rejected for current/existing worktrees.
        with tempfile.TemporaryDirectory() as tmp:
            log = self._stub(tmp)
            p = self._run(tmp, self.ARGS, self.RW)
            self.assertEqual(p.returncode, 0, p.stderr)
            ws_call = next(l for l in log.read_text().splitlines() if "worker-start" in l)
            self.assertNotIn("--name", ws_call)
            self.assertIn("--task task_test", ws_call)

    def test_worker_start_lane_names_new_child_worktrees(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = self._stub(tmp)
            p = self._run(tmp, ["task_test", "new-child", "t"], self.RW)
            self.assertEqual(p.returncode, 0, p.stderr)
            ws_call = next(l for l in log.read_text().splitlines() if "worker-start" in l)
            self.assertIn("--name", ws_call)

    def test_ro_never_takes_worker_start(self):
        # A worker-start launch takes its args from the host's agentDefaultArgs, whose migrated
        # default is the YOLO map — a PROFILE=ro reviewer must never ride it.
        with tempfile.TemporaryDirectory() as tmp:
            log = self._stub(tmp)
            p = self._run(tmp, self.ARGS, self.RO)
            self.assertEqual(p.returncode, 0, p.stderr)
            calls = log.read_text()
            self.assertNotIn("worker-start", calls)
            self.assertIn("--permission-mode plan", calls)

    def test_flat_receipt_parses_handle_from_effects(self):
        # The receipt is flat; the agent terminal is effects[kind=terminal, role=agent].
        with tempfile.TemporaryDirectory() as tmp:
            self._stub(tmp)
            p = self._run(tmp, self.ARGS, self.RW)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("HANDLE=term_agent1", p.stdout)
            self.assertIn("DISPATCH=ctx_x", p.stdout)


if __name__ == "__main__":
    unittest.main()
