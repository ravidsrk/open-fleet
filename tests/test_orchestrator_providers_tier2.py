#!/usr/bin/env python3
"""#591 audit fixes for the external orchestrator adapters (#588 AO / JCode Swarm, #589 Emdash /
Vibe-Kanban / Paperclip / Multiclaude): every acceptance criterion gets a positive test AND a
negative control.

  C1  the task spec reaches upstream through `dispatch(task-create)` -> `dispatch(worker-start)`
  C2  bad JSON / missing ids / missing binary / timeout -> ProviderError (`ok:false`)
  C3  fence verbs: retain is non-destructive; unknown dispatch -> dispatch_not_found
  AO  the WORKER's HEAD is preserved in the worker's repo (real git), never the coordinator's
  VK  the auto-commit guard runs after exit and rejects by default (real git)
  MC  release needs a durable worker-verify bound to the worker's current HEAD (real git)
"""
from __future__ import annotations

import io
import importlib
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_mod = importlib.import_module  # repo-local package loaded by path, not a distributable import
common = _mod("runtime.providers._external")
ComposioAOProvider = _mod("runtime.providers.ao").ComposioAOProvider
ProviderError = _mod("runtime.providers.base").ProviderError
_emdash = _mod("runtime.providers.emdash")
EmdashProvider, encode_frame = _emdash.EmdashProvider, _emdash.encode_frame
JCodeSwarmProvider = _mod("runtime.providers.jcode_swarm").JCodeSwarmProvider
LocalStateStore = _mod("runtime.providers.local_state").LocalStateStore
MulticlaudeProvider = _mod("runtime.providers.multiclaude").MulticlaudeProvider
PaperclipProvider = _mod("runtime.providers.paperclip").PaperclipProvider
VibeKanbanProvider = _mod("runtime.providers.vibe_kanban").VibeKanbanProvider

SPEC = "Implement the frobnicator and add a regression test (spec-marker-7f3a)"
GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
}


def git(cwd: Path | str, *args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True, env=env or GIT_ENV
    ).stdout.strip()


def make_repo(path: Path) -> str:
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", "-b", "main")
    (path / "f.txt").write_text("one\n")
    git(path, "add", "f.txt")
    git(path, "commit", "-q", "-m", "base")
    return git(path, "rev-parse", "HEAD")


def commit(path: Path, msg: str, when: int | None = None) -> str:
    (path / "f.txt").write_text((path / "f.txt").read_text() + msg + "\n")
    git(path, "add", "f.txt")
    env = dict(GIT_ENV)
    if when is not None:
        env["GIT_COMMITTER_DATE"] = env["GIT_AUTHOR_DATE"] = f"@{when} +0000"
    git(path, "commit", "-q", "-m", msg, env=env)
    return git(path, "rev-parse", "HEAD")


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="t2-")
        self.tmp = Path(self._tmp.name)
        self.state = LocalStateStore(db_path=self.tmp / "state.db")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def start_via_dispatch(self, prov: Any, *extra: str) -> dict[str, Any]:
        task = prov.dispatch(["orchestration", "task-create", "--spec", SPEC], env={})
        return prov.dispatch(
            ["orchestration", "worker-start", "--task", task["task"]["id"], "--profile", "rw", *extra], env={}
        )


# ----------------------------------------------------------------------------------------- AO
class AOFake:
    def __init__(self, wt: Path | None) -> None:
        self.calls: list[Any] = []
        self.wt = wt
        self.session: dict[str, Any] = {"session": {"id": "ao-1"}, "promptBytes": 10}

    def __call__(self, call: Any, **_kw: Any) -> Any:
        self.calls.append(call)
        if isinstance(call, list):
            return common.run_cli(call, provider="ao")
        if call["path"] == "/api/v1/sessions":
            return self.session
        if call["path"].endswith("/workspace"):
            if self.wt is None:
                raise ProviderError("ao_http_error", "404", {"status": 404})
            return {"sessionId": "ao-1", "workspacePath": str(self.wt)}
        if call["path"].endswith("/conversation?limit=50"):
            return {"latestSequence": 4, "messages": [{"id": "m1", "role": "assistant", "text": "working"}]}
        return {"ok": True}

    def kills(self) -> list[Any]:
        return [c for c in self.calls if isinstance(c, dict) and c["path"].endswith("/kill")]


class TestAO(Base):
    def setUp(self) -> None:
        super().setUp()
        self.coord_repo = self.tmp / "coordinator"
        self.coord_head = make_repo(self.coord_repo)
        self.main_repo = self.tmp / "project"
        make_repo(self.main_repo)
        self.wt = self.tmp / "wt-ao-1"
        git(self.main_repo, "worktree", "add", "-q", "-b", "ao/ao-1", str(self.wt))
        self.worker_head = commit(self.wt, "worker work")

    def test_spec_reaches_spawn_prompt_via_dispatch(self) -> None:
        fake = AOFake(self.wt)
        prov = ComposioAOProvider(state=self.state, runner=fake, project="p1")
        res = self.start_via_dispatch(prov)
        self.assertEqual(fake.calls[0]["body"]["prompt"], SPEC)
        self.assertEqual(res["worktree"], str(self.wt.resolve()))
        self.assertTrue((self.wt / ".claude" / "settings.local.json").is_file())

    def test_negative_missing_spec_and_missing_id(self) -> None:
        fake = AOFake(self.wt)
        prov = ComposioAOProvider(state=self.state, runner=fake, project="p1")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="nope", profile="rw")
        self.assertEqual(ctx.exception.code, "missing_task_spec")
        self.assertEqual(fake.calls, [])
        fake.session = {"promptBytes": 3}
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t", profile="rw", prompt="x")
        self.assertEqual(ctx.exception.code, "upstream_no_id")
        self.assertFalse(ctx.exception.to_envelope()["ok"])

    def test_preserves_worker_head_not_coordinator(self) -> None:
        fake = AOFake(self.wt)
        prov = ComposioAOProvider(state=self.state, runner=fake, project="p1")
        prov.worker_start(task_id="t", profile="rw", prompt="x")
        old = os.getcwd()
        os.chdir(self.coord_repo)
        try:
            res = prov.worker_fence(verb="stop", dispatch_id="ao-1")
        finally:
            os.chdir(old)
        ref = "refs/open-fleet/preserved/ao-1"
        self.assertEqual(res["preservedRef"], ref)
        self.assertEqual(git(self.main_repo, "rev-parse", ref), self.worker_head)
        self.assertNotEqual(self.worker_head, self.coord_head)
        with self.assertRaises(subprocess.CalledProcessError):
            git(self.coord_repo, "rev-parse", "--verify", ref)
        self.assertEqual(len(fake.kills()), 1)
        self.assertEqual(res["state"], "stopped")

    def test_negative_unknown_worktree_refuses_kill(self) -> None:
        fake = AOFake(None)
        prov = ComposioAOProvider(state=self.state, runner=fake, project="p1")
        prov.worker_start(task_id="t", profile="rw", prompt="x")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_fence(verb="release", dispatch_id="ao-1")
        self.assertEqual(ctx.exception.code, "worktree_unknown")
        self.assertEqual(fake.kills(), [])

    def test_runaway_session_stoppable_without_a_resolvable_worktree(self) -> None:
        for verb in ("stop", "abandon"):
            with self.subTest(verb=verb):
                fake = AOFake(None)
                prov = ComposioAOProvider(state=LocalStateStore(db_path=self.tmp / f"{verb}.db"), runner=fake, project="p1")
                prov.worker_start(task_id="t", profile="rw", prompt="x")
                res = prov.worker_fence(verb=verb, dispatch_id="ao-1")
                self.assertEqual(len(fake.kills()), 1)
                self.assertIsNone(res["preservedRef"])
                self.assertEqual(res["preserveError"]["code"], "worktree_unknown")
                self.assertEqual(res["state"], "stopped" if verb == "stop" else "abandoned")

    def test_release_refuses_a_pin_that_would_not_survive_the_worktree(self) -> None:
        standalone = self.tmp / "standalone-wt"  # its own .git: the ref would die with the worktree
        make_repo(standalone)
        fake = AOFake(standalone)
        prov = ComposioAOProvider(state=self.state, runner=fake, project="p1")
        prov.worker_start(task_id="t", profile="rw", prompt="x")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_fence(verb="release", dispatch_id="ao-1")
        self.assertEqual(ctx.exception.code, "preserve_failed")
        self.assertEqual(fake.kills(), [])
        res = prov.worker_fence(verb="stop", dispatch_id="ao-1")  # stopping is still possible
        self.assertEqual(res["preserveError"]["code"], "preserve_failed")
        self.assertEqual(len(fake.kills()), 1)

    def test_retain_never_kills_and_unknown_dispatch(self) -> None:
        fake = AOFake(self.wt)
        prov = ComposioAOProvider(state=self.state, runner=fake, project="p1")
        prov.worker_start(task_id="t", profile="rw", prompt="x")
        res = prov.worker_fence(verb="retain", dispatch_id="ao-1")
        self.assertEqual((res["state"], res["terminalState"]), ("retained", "retained"))
        self.assertEqual(fake.kills(), [])
        for fn in (lambda: prov.worker_fence(verb="stop", dispatch_id="ghost"),
                   lambda: prov.worker_show(dispatch_id="ghost"),
                   lambda: prov.worker_read(dispatch_id="ghost")):
            with self.assertRaises(ProviderError) as ctx:
                fn()
            self.assertEqual(ctx.exception.code, "dispatch_not_found")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_fence(verb="explode", dispatch_id="ao-1")
        self.assertEqual(ctx.exception.code, "invalid_verb")

    def test_read_and_show_are_normalized(self) -> None:
        fake = AOFake(self.wt)
        prov = ComposioAOProvider(state=self.state, runner=fake, project="p1")
        prov.worker_start(task_id="t", profile="rw", prompt="x")
        read = prov.worker_read(dispatch_id="ao-1")
        self.assertEqual(read["source"], "transcript")
        self.assertEqual(read["transcript"]["messages"][0]["blocks"][0]["text"], "working")
        show = prov.worker_show(dispatch_id="ao-1")
        self.assertEqual(show["dispatch"]["id"], "ao-1")
        self.assertEqual(show["worker"]["state"], "ready")

    def test_ref_name_is_sanitised(self) -> None:
        safe_ref_component = importlib.import_module("runtime.providers.ao").safe_ref_component
        self.assertEqual(safe_ref_component("../../etc/x"), "etc-x")
        self.assertNotIn("/", safe_ref_component("a/b"))
        with self.assertRaises(ProviderError):
            safe_ref_component("..")

    def test_bad_json_from_daemon_is_ok_false(self) -> None:
        prov = ComposioAOProvider(state=self.state, project="p1", base_url="http://127.0.0.1:1")

        class Resp(io.BytesIO):
            def __enter__(self) -> "Resp":
                return self

            def __exit__(self, *a: Any) -> None:
                return None

        with mock.patch.object(common.urllib.request, "urlopen", return_value=Resp(b"<html>oops</html>")):
            with self.assertRaises(ProviderError) as ctx:
                prov.worker_start(task_id="t", profile="rw", prompt="x")
        self.assertEqual(ctx.exception.code, "ao_bad_json")
        self.assertFalse(ctx.exception.to_envelope()["ok"])


# ---------------------------------------------------------------------------------- JCode
class JFake:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.touches: list[dict[str, Any]] = []
        self.spawn_reply: dict[str, Any] | None = None

    def __call__(self, req: dict[str, Any], **_kw: Any) -> dict[str, Any]:
        self.calls.append(req)
        t = req["type"]
        if t == "comm_spawn":
            return self.spawn_reply or {"type": "comm_spawn_response", "id": req["id"], "session_id": "c", "new_session_id": "jc-9"}
        if t == "debug_command":
            return {"type": "debug_response", "id": req["id"], "ok": True, "output": json.dumps(self.touches)}
        if t == "comm_read_context":
            return {"type": "comm_context_history", "id": req["id"], "session_id": "jc-9",
                    "messages": [{"role": "assistant", "content": "done"}]}
        if t == "comm_status":
            return {"type": "comm_status_response", "id": req["id"], "snapshot": {"status": "running"}}
        return {"type": "ack", "id": req["id"]}


class TestJCode(Base):
    def setUp(self) -> None:
        super().setUp()
        self.wt = self.tmp / "jwt"
        self.wt.mkdir()

    def test_spec_reaches_comm_spawn_and_agent_is_jcode(self) -> None:
        fake = JFake()
        prov = JCodeSwarmProvider(state=self.state, runner=fake, coordinator_session="coord")
        res = self.start_via_dispatch(prov, "--worktree", str(self.wt), "--agent", "jcode")
        spawn = [c for c in fake.calls if c["type"] == "comm_spawn"][0]
        self.assertEqual(spawn["initial_message"], SPEC)
        self.assertEqual(spawn["session_id"], "coord")
        self.assertEqual(res["launch"]["effective"]["agent"], "jcode")
        self.assertNotIn("claude", json.dumps(res["launch"]["effective"]))

    def test_negative_claude_agent_missing_id_and_socket(self) -> None:
        fake = JFake()
        prov = JCodeSwarmProvider(state=self.state, runner=fake, coordinator_session="coord")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t", worktree=str(self.wt), agent="claude", prompt="x")
        self.assertEqual(ctx.exception.code, "unsupported_agent")
        fake.spawn_reply = {"type": "comm_spawn_response", "id": 1}
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t", worktree=str(self.wt), prompt="x")
        self.assertEqual(ctx.exception.code, "upstream_no_id")
        p2 = JCodeSwarmProvider(state=self.state, env={"OPEN_FLEET_JCODE_SOCKET": str(self.tmp / "nope.sock")},
                                coordinator_session="coord")
        self.assertEqual(p2.socket_path, str(self.tmp / "nope.sock"))
        with self.assertRaises(ProviderError) as ctx:
            p2.worker_start(task_id="t", worktree=str(self.wt), prompt="x")
        self.assertEqual(ctx.exception.code, "jcode_unreachable")

    def test_default_runner_rejects_non_json_daemon_line(self) -> None:
        sock_path = str(self.tmp / "j.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(1)

        def serve() -> None:
            conn, _ = srv.accept()
            conn.recv(65536)
            conn.sendall(b"this is not json\n")
            time.sleep(0.2)
            conn.close()

        th = threading.Thread(target=serve, daemon=True)
        th.start()
        prov = JCodeSwarmProvider(state=self.state, socket_path=sock_path, coordinator_session="coord")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t", worktree=str(self.wt), prompt="x")
        self.assertEqual(ctx.exception.code, "jcode_bad_json")
        th.join(2)
        srv.close()

    def test_file_touches_reachable_from_show_with_known_and_unknown_ranges(self) -> None:
        fake = JFake()
        prov = JCodeSwarmProvider(state=self.state, runner=fake, coordinator_session="coord")
        prov.worker_start(task_id="t", worktree=str(self.wt), prompt="x")
        fake.touches = [
            {"path": "a.py", "session_id": "w1", "op": "edited", "summary": "edited lines 45-60", "timestamp_unix": 1},
            {"path": "a.py", "session_id": "w2", "op": "edited", "summary": "edited lines 100-120", "timestamp_unix": 2},
            {"path": "b.py", "session_id": "w3", "op": "wrote", "summary": "wrote file", "timestamp_unix": 3},
            {"path": "c.py", "session_id": "w1", "op": "read", "summary": "read lines 1-5", "timestamp_unix": 4},
        ]
        show = prov.worker_show(dispatch_id="jc-9")
        sync = show["fileTouches"]
        self.assertEqual(sync["synced"], 3)
        self.assertFalse(sync["results"][1]["conflict"])
        self.assertEqual(sync["results"][1]["disjointTouches"][0]["kind"], "same_file_disjoint_hunk")
        self.assertTrue(sync["results"][0]["rangeKnown"])
        self.assertFalse(sync["results"][2]["rangeKnown"])
        again = prov.sync_file_touches(run_id="default")
        self.assertEqual(again["synced"], 0)

    def test_read_fence_retain_and_unknown(self) -> None:
        fake = JFake()
        prov = JCodeSwarmProvider(state=self.state, runner=fake, coordinator_session="coord")
        prov.worker_start(task_id="t", worktree=str(self.wt), prompt="x")
        read = prov.worker_read(dispatch_id="jc-9")
        self.assertEqual(read["transcript"]["messages"][0]["blocks"][0]["text"], "done")
        n = len(fake.calls)
        res = prov.worker_fence(verb="retain", dispatch_id="jc-9")
        self.assertEqual(res["state"], "retained")
        self.assertEqual(len(fake.calls), n)
        stop = prov.worker_fence(verb="stop", dispatch_id="jc-9")
        self.assertEqual(fake.calls[-1]["type"], "comm_stop")
        self.assertEqual(stop["state"], "stopped")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_fence(verb="stop", dispatch_id="ghost")
        self.assertEqual(ctx.exception.code, "dispatch_not_found")


# --------------------------------------------------------------------------------- Emdash
class EmFake:
    def __init__(self) -> None:
        self.msgs: list[dict[str, Any]] = []
        self.start_value: Any = {"outcome": "started"}

    def __call__(self, msg: dict[str, Any], **_kw: Any) -> dict[str, Any]:
        self.msgs.append(msg)
        if msg.get("path") == "tuiAgents.startSession":
            value = self.start_value
        elif msg.get("kind") == "snapshot":
            value = {"sequence": 1, "data": {"baseOffset": 0, "text": "a\nb\n", "truncated": False}}
        else:
            value = {"success": True, "data": None}
        return {"kind": "result", "id": msg["id"], "ok": True, "value": value}


class TestEmdash(Base):
    def setUp(self) -> None:
        super().setUp()
        self.wt = self.tmp / "ewt"
        self.wt.mkdir()

    def test_spec_reaches_initial_prompt_and_ro_hooks_precede_start(self) -> None:
        fake = EmFake()
        prov = EmdashProvider(state=self.state, runner=fake)
        self.start_via_dispatch(prov, "--worktree", str(self.wt))
        self.assertEqual(fake.msgs[-1]["input"]["initialPrompt"], SPEC)
        prov.worker_start(task_id="t", worktree=str(self.wt), profile="ro", prompt="look")
        self.assertTrue((self.wt / ".claude" / "settings.local.json").is_file())
        self.assertNotIn("look", fake.msgs[-1]["input"]["extraArgs"])

    def test_negative_no_invented_worktree_and_bad_outcome(self) -> None:
        fake = EmFake()
        prov = EmdashProvider(state=self.state, runner=fake, env={})
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t", worktree="new-child", prompt="x")
        self.assertEqual(ctx.exception.code, "missing_repository")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t", worktree=str(self.tmp / "missing"), prompt="x")
        self.assertEqual(ctx.exception.code, "worktree_unknown")
        fake.start_value = {}
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t", worktree=str(self.wt), prompt="x")
        self.assertEqual(ctx.exception.code, "emdash_start_failed")
        with self.state._connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) c FROM dispatches").fetchone()["c"], 0)

    def test_fence_uses_conversation_id_and_retain_is_local(self) -> None:
        fake = EmFake()
        prov = EmdashProvider(state=self.state, runner=fake)
        res = prov.worker_start(task_id="t", worktree=str(self.wt), prompt="x")
        cid = res["dispatchId"]
        n = len(fake.msgs)
        self.assertEqual(prov.worker_fence(verb="retain", dispatch_id=cid)["state"], "retained")
        self.assertEqual(len(fake.msgs), n)
        prov.worker_fence(verb="stop", dispatch_id=cid)
        self.assertEqual(fake.msgs[-1]["path"], "tuiAgents.stop")
        self.assertEqual(fake.msgs[-1]["input"], {"conversationId": cid})
        read = prov.worker_read(dispatch_id=cid)
        self.assertEqual(read["source"], "terminal")
        self.assertEqual(read["fallbackReason"], "emdash exposes PTY output only")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_read(dispatch_id="ghost")
        self.assertEqual(ctx.exception.code, "dispatch_not_found")

    @staticmethod
    def _claude_positionals(argv: list[str]) -> tuple[list[str], dict[str, list[str]]]:
        """Parse argv the way claude's commander CLI does: `<tools...>` options are variadic."""
        variadic = {"--disallowedTools", "--disallowed-tools", "--allowedTools", "--allowed-tools", "--add-dir"}
        valued = {"--permission-mode", "--session-id", "--model", "--output-format", "--resume"}
        positionals: list[str] = []
        opts: dict[str, list[str]] = {}
        active: str | None = None
        it = iter(argv)
        for arg in it:
            if arg.startswith("--") and "=" in arg:
                key, val = arg.split("=", 1)
                opts.setdefault(key, []).append(val)
                active = None  # commander: `--opt=value` never opens a variadic run
            elif arg in variadic:
                opts.setdefault(arg, []).append(next(it))
                active = arg
            elif arg in valued:
                opts.setdefault(arg, []).append(next(it))
                active = None
            elif arg.startswith("-"):
                active = None
            elif active:
                opts[active].append(arg)  # a variadic option swallows following non-flags
            else:
                positionals.append(arg)
        return positionals, opts

    def test_ro_prompt_is_the_positional_claude_receives(self) -> None:
        fake = EmFake()
        prov = EmdashProvider(state=self.state, runner=fake)
        prov.worker_start(task_id="t", worktree=str(self.wt), profile="ro", prompt=SPEC)
        params = fake.msgs[-1]["input"]
        # emdash buildStandardCommand: [--session-id <id>, ...extraArgs, initialPrompt]
        argv = ["--session-id", params["conversationId"], *params["extraArgs"], params["initialPrompt"]]
        positionals, opts = self._claude_positionals(argv)
        self.assertEqual(positionals, [SPEC])
        self.assertEqual(opts["--disallowedTools"], ["Edit,Write,MultiEdit,NotebookEdit"])
        self.assertEqual(opts["--permission-mode"], ["plan"])
        self.assertNotIn("-p", params["extraArgs"])

    def test_trust_workspace_is_requested_so_claude_never_stalls_at_folder_trust(self) -> None:
        fake = EmFake()
        prov = EmdashProvider(state=self.state, runner=fake)
        for profile in ("ro", "rw"):
            res = prov.worker_start(task_id="t", worktree=str(self.wt), profile=profile, prompt="x")
            self.assertIs(fake.msgs[-1]["input"]["trustWorkspace"], True)
            self.assertIs(res["launch"]["effective"]["trustWorkspace"], True)

    def _emdash_with_worktree(self) -> tuple[Any, EmFake, Path, str]:
        main = self.tmp / "em-main"
        make_repo(main)
        wt = self.tmp / "em-linked"
        git(main, "worktree", "add", "-q", "-b", "em-feat", str(wt))
        head = commit(wt, "worker work")
        fake = EmFake()
        orig = fake.__call__

        def runner(msg: dict[str, Any], **kw: Any) -> dict[str, Any]:
            if msg.get("path") == "workspaceRegistry.createWorktree":
                fake.msgs.append(msg)
                data = {"id": "ws-em-1", "path": str(wt)}
                return {"kind": "result", "id": msg["id"], "ok": True, "value": {"success": True, "data": data}}
            return orig(msg, **kw)

        prov = EmdashProvider(state=self.state, runner=runner, env={"OPEN_FLEET_EMDASH_REPOSITORY_ID": "repo-1"},
                              git_runner=lambda argv: subprocess.run(argv, check=True, capture_output=True, text=True,
                                                                     env=GIT_ENV).stdout)
        prov.worktree_create(name="em-feat", base="main")
        return prov, fake, main, head

    def test_worktree_rm_unforced_refuses_dirty_and_always_preserves_head(self) -> None:
        prov, fake, main, head = self._emdash_with_worktree()
        wt = self.tmp / "em-linked"
        (wt / "unsaved.py").write_text("wip\n")
        with self.assertRaises(ProviderError) as ctx:
            prov.worktree_rm(selector="ws-em-1")
        self.assertEqual(ctx.exception.code, "uncommitted_work")
        self.assertFalse([m for m in fake.msgs if m.get("path") == "workspaceRegistry.deleteWorktree"])
        self.assertTrue((wt / "unsaved.py").is_file())
        self.assertEqual(git(main, "rev-parse", "refs/open-fleet/preserved/emdash-ws-em-1"), head)

        removed = prov.worktree_rm(selector="ws-em-1", force=True)  # explicit force: dirt discarded, HEAD pinned
        self.assertEqual(fake.msgs[-1]["path"], "workspaceRegistry.deleteWorktree")
        self.assertEqual(removed["preserved"]["sha"], head)
        self.assertEqual(removed["discardedDirty"], ["unsaved.py"])

    def test_worktree_rm_clean_unforced_deletes_after_preserving(self) -> None:
        prov, fake, main, head = self._emdash_with_worktree()
        removed = prov.worktree_rm(selector="ws-em-1")
        self.assertEqual(fake.msgs[-1]["input"], {"workspaceId": "ws-em-1", "deleteBranch": False})
        self.assertEqual(git(main, "rev-parse", removed["preserved"]["ref"]), head)

    def test_worktree_rm_unknown_workspace_never_reaches_upstream(self) -> None:
        fake = EmFake()
        prov = EmdashProvider(state=self.state, runner=fake)
        for force in (False, True):
            with self.assertRaises(ProviderError) as ctx:
                prov.worktree_rm(selector="ws-unknown", force=force)
            self.assertEqual(ctx.exception.code, "worktree_unknown")
        self.assertEqual(fake.msgs, [])

    def test_default_runner_speaks_length_prefixed_frames_over_unix_socket(self) -> None:
        sock_path = str(self.tmp / "ws.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(1)
        seen: list[dict[str, Any]] = []

        def read_frame(conn: socket.socket) -> dict[str, Any]:
            hdr = b""
            while len(hdr) < 5:
                hdr += conn.recv(5 - len(hdr))
            n = struct.unpack(">I", hdr[1:5])[0]
            body = b""
            while len(body) < n:
                body += conn.recv(n - len(body))
            return json.loads(body)

        def serve() -> None:
            conn, _ = srv.accept()
            init = read_frame(conn)
            seen.append(init)
            conn.sendall(encode_frame({"kind": "result", "id": init["id"], "ok": True, "value": {"protocolVersion": "12.0.0"}}))
            call = read_frame(conn)
            seen.append(call)
            conn.sendall(encode_frame({"kind": "result", "id": call["id"], "ok": False, "code": "HANDLER_ERROR", "message": "boom"}))
            conn.close()

        th = threading.Thread(target=serve, daemon=True)
        th.start()
        prov = EmdashProvider(state=self.state, socket_path=sock_path)
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t", worktree=str(self.wt), prompt="x")
        th.join(2)
        srv.close()
        self.assertEqual(ctx.exception.code, "emdash_handler_error")
        self.assertEqual(seen[0]["path"], "initialize")
        self.assertEqual(seen[1]["path"], "tuiAgents.startSession")


# ---------------------------------------------------------------------------- Vibe-Kanban
class VKFake:
    def __init__(self, container: Path) -> None:
        self.reqs: list[dict[str, Any]] = []
        self.container = container
        self.statuses = ["running", "completed"]
        self.completed_at = "2026-01-01T00:00:00Z"
        self.profiles: dict[str, Any] = {"executors": {"CLAUDE_CODE": {"DEFAULT": {"CLAUDE_CODE": {"dangerously_skip_permissions": True}}}}}
        self.start: dict[str, Any] = {"workspace": {"id": "ws-1", "container_ref": None},
                                      "execution_process": {"id": "p-1", "run_reason": "codingagent"}}

    def __call__(self, req: dict[str, Any], **_kw: Any) -> dict[str, Any]:
        self.reqs.append(req)
        m, p = req["method"], req["path"]
        if p == "/api/profiles":
            if m == "PUT":
                self.profiles = req["body"]
                return {"success": True, "data": None}
            return {"success": True, "data": {"content": json.dumps(self.profiles)}}
        if p == "/api/workspaces/start":
            return {"success": True, "data": self.start}
        if p.startswith("/api/workspaces/") and m == "GET":
            return {"success": True, "data": {"id": "ws-1", "container_ref": str(self.container)}}
        if p.startswith("/api/execution-processes/"):
            status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
            return {"success": True, "data": {"id": "p-1", "status": status, "completed_at": self.completed_at}}
        return {"success": True, "data": None}


class TestVibeKanban(Base):
    ENV = {"OPEN_FLEET_VIBE_KANBAN_REPO_ID": "r1", "OPEN_FLEET_VIBE_KANBAN_TARGET_BRANCH": "main"}

    def setUp(self) -> None:
        super().setUp()
        self.container = self.tmp / "vk-ws"
        self.repo = self.container / "proj"
        make_repo(self.repo)

    def prov(self, fake: VKFake, **kw: Any) -> VibeKanbanProvider:
        return VibeKanbanProvider(state=self.state, runner=fake, env=dict(self.ENV, **kw.pop("env", {})),
                                  sleep=lambda _s: None, **kw)

    def test_spec_reaches_workspace_start_and_real_worktree_recorded(self) -> None:
        fake = VKFake(self.container)
        res = self.start_via_dispatch(self.prov(fake))
        start = [r for r in fake.reqs if r["path"] == "/api/workspaces/start"][0]
        self.assertEqual(start["body"]["prompt"], SPEC)
        self.assertEqual(start["body"]["executor_config"]["executor"], "CLAUDE_CODE")
        self.assertEqual(res["worktree"], str(self.repo.resolve()))

    def test_ro_refused_when_profile_does_not_read_back_safe(self) -> None:
        fake = VKFake(self.container)

        def sticky(req: dict[str, Any], **kw: Any) -> dict[str, Any]:
            if req["path"] == "/api/profiles" and req["method"] == "PUT":
                fake.reqs.append(req)
                return {"success": True, "data": None}  # server ignores the override
            return fake(req)

        prov = VibeKanbanProvider(state=self.state, runner=sticky, env=self.ENV, sleep=lambda _s: None)
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t", profile="ro", prompt="x")
        self.assertEqual(ctx.exception.code, "ro_profile_unverified")
        self.assertFalse(any(r["path"] == "/api/workspaces/start" for r in fake.reqs))

    def test_auto_commit_rejected_by_default_after_exit(self) -> None:
        fake = VKFake(self.container)
        prov = self.prov(fake)
        prov.worker_start(task_id="t", prompt="x")
        worker_own = commit(self.repo, "worker commit", when=1767225000)  # before completed_at
        auto = commit(self.repo, "Implemented the frobnicator", when=1767225600)  # == completed_at
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_fence(verb="release", dispatch_id="ws-1")
        self.assertEqual(ctx.exception.code, "unverified_auto_commit")
        order = [r["path"] for r in fake.reqs]
        stop_i = order.index("/api/workspaces/ws-1/execution/stop")
        self.assertGreater(len([p for p in order[stop_i:] if p.startswith("/api/execution-processes/")]), 1)
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), auto)  # nothing stripped
        with self.state._connect() as conn:
            row = conn.execute("SELECT state FROM dispatches WHERE dispatch_id='ws-1'").fetchone()
        self.assertEqual(row["state"], "stopped")
        self.assertNotEqual(worker_own, auto)

    def test_auto_commit_stripped_only_when_allowed_and_head_reverified(self) -> None:
        fake = VKFake(self.container)
        prov = self.prov(fake, env={"OPEN_FLEET_VIBE_KANBAN_STRIP_AUTO_COMMIT": "1"})
        prov.worker_start(task_id="t", prompt="x")
        worker_own = commit(self.repo, "worker commit", when=1767225000)
        commit(self.repo, "Commit changes from coding agent for workspace ws-1", when=1767225601)
        res = prov.worker_fence(verb="release", dispatch_id="ws-1")
        self.assertTrue(res["autoCommitGuard"]["stripped"])
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), worker_own)
        self.assertEqual(res["state"], "released")

    def test_negative_worker_commit_before_exit_passes(self) -> None:
        fake = VKFake(self.container)
        prov = self.prov(fake)
        prov.worker_start(task_id="t", prompt="x")
        own = commit(self.repo, "worker commit", when=1767225000)
        res = prov.worker_fence(verb="stop", dispatch_id="ws-1")
        self.assertFalse(res["autoCommitGuard"]["autoCommitDetected"])
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), own)

    def test_still_running_refuses_inspection_and_retain_is_local(self) -> None:
        fake = VKFake(self.container)
        fake.statuses = ["running"]
        prov = self.prov(fake, exit_timeout_s=0)
        prov.worker_start(task_id="t", prompt="x")
        n = len(fake.reqs)
        self.assertEqual(prov.worker_fence(verb="retain", dispatch_id="ws-1")["state"], "retained")
        self.assertEqual(len(fake.reqs), n)
        # worker-stop succeeded upstream: ok, with the guard's refusal carried as data ...
        stopped = prov.worker_fence(verb="stop", dispatch_id="ws-1")
        self.assertEqual(stopped["state"], "stopped")
        self.assertFalse(stopped["autoCommitGuard"]["releasable"])
        self.assertEqual(stopped["autoCommitGuard"]["error"]["code"], "process_still_running")
        # ... while release still refuses.
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_fence(verb="release", dispatch_id="ws-1")
        self.assertEqual(ctx.exception.code, "process_still_running")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_fence(verb="stop", dispatch_id="ghost")
        self.assertEqual(ctx.exception.code, "dispatch_not_found")

    def lagging_git(self, on_poll: dict[int, Any]) -> tuple[Any, list[int]]:
        """git runner that runs `on_poll[n]` before the n-th `git status` (the exit monitor lagging)."""
        polls = [0]

        def run(argv: list[str]) -> dict[str, Any]:
            if "status" in argv:
                polls[0] += 1
                action = on_poll.get(polls[0])
                if action:
                    action()
            return common.run_cli(argv, provider="git")
        return run, polls

    def test_completed_before_auto_commit_lands_is_not_judged_early(self) -> None:
        fake = VKFake(self.container)
        landed: dict[str, str] = {}

        def exit_monitor_commits() -> None:  # upstream: status=completed, THEN try_commit_changes
            git(self.repo, "add", "-A")
            env = dict(GIT_ENV, GIT_COMMITTER_DATE="@1767225601 +0000", GIT_AUTHOR_DATE="@1767225601 +0000")
            git(self.repo, "commit", "-q", "-m", "Implemented the frobnicator", env=env)
            landed["auto"] = git(self.repo, "rev-parse", "HEAD")

        run, polls = self.lagging_git({3: exit_monitor_commits})
        prov = self.prov(fake, git_runner=run)
        prov.worker_start(task_id="t", prompt="x")
        own = commit(self.repo, "worker commit", when=1767225000)
        (self.repo / "f.txt").write_text("agent edits the exit monitor has not committed yet\n")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_fence(verb="release", dispatch_id="ws-1")
        self.assertEqual(ctx.exception.code, "unverified_auto_commit")
        self.assertEqual(ctx.exception.data["head"], landed["auto"])
        self.assertNotEqual(landed["auto"], own)
        self.assertGreaterEqual(polls[0], 3 + 2)  # waited for the commit, then for HEAD to hold still

    def test_cleanup_script_commit_after_settle_start_is_stripped_too(self) -> None:
        fake = VKFake(self.container)
        prov_env = {"OPEN_FLEET_VIBE_KANBAN_STRIP_AUTO_COMMIT": "1"}

        def cleanup_script_commits() -> None:  # the next action (cleanup script) commits again
            commit(self.repo, "Cleanup script changes for workspace ws-1", when=1767225700)

        run, _ = self.lagging_git({2: cleanup_script_commits})
        prov = self.prov(fake, env=prov_env, git_runner=run)
        prov.worker_start(task_id="t", prompt="x")
        own = commit(self.repo, "worker commit", when=1767225000)
        commit(self.repo, "Commit changes from coding agent for workspace ws-1", when=1767225601)
        res = prov.worker_fence(verb="release", dispatch_id="ws-1")
        self.assertEqual(len(res["autoCommitGuard"]["removedCommits"]), 2)
        self.assertEqual(git(self.repo, "rev-parse", "HEAD"), own)

    def test_worktree_that_never_settles_refuses_release_but_stop_reports_success(self) -> None:
        fake = VKFake(self.container)
        prov = self.prov(fake, settle_max_polls=5)
        prov.worker_start(task_id="t", prompt="x")
        (self.repo / "pending.txt").write_text("never committed\n")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_fence(verb="release", dispatch_id="ws-1")
        self.assertEqual(ctx.exception.code, "auto_commit_pending")
        self.assertEqual(ctx.exception.data["dirty"], ["pending.txt"])
        stopped = prov.worker_fence(verb="stop", dispatch_id="ws-1")
        self.assertEqual(stopped["state"], "stopped")
        self.assertEqual(stopped["autoCommitGuard"], {"releasable": False, "error": stopped["autoCommitGuard"]["error"]})
        self.assertEqual(stopped["autoCommitGuard"]["error"]["code"], "auto_commit_pending")

    def test_stop_reports_success_when_guard_rejects_auto_commit(self) -> None:
        fake = VKFake(self.container)
        prov = self.prov(fake)
        prov.worker_start(task_id="t", prompt="x")
        commit(self.repo, "Implemented the frobnicator", when=1767225600)
        res = prov.worker_fence(verb="stop", dispatch_id="ws-1")
        self.assertEqual(res["state"], "stopped")
        self.assertFalse(res["autoCommitGuard"]["releasable"])
        self.assertEqual(res["autoCommitGuard"]["error"]["code"], "unverified_auto_commit")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_fence(verb="release", dispatch_id="ws-1")
        self.assertEqual(ctx.exception.code, "unverified_auto_commit")

    def test_missing_ids_and_bad_envelope(self) -> None:
        fake = VKFake(self.container)
        fake.start = {"workspace": {}}
        with self.assertRaises(ProviderError) as ctx:
            self.prov(fake).worker_start(task_id="t", prompt="x")
        self.assertEqual(ctx.exception.code, "upstream_no_id")
        prov = VibeKanbanProvider(state=self.state, runner=lambda req, **k: {"weird": 1}, env=self.ENV)
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t", prompt="x")
        self.assertEqual(ctx.exception.code, "vibe_kanban_bad_response")


# ------------------------------------------------------------------------------ Paperclip
def paperclip_tool_policy(adapter_type: str, cfg: dict[str, Any]) -> str:
    """What upstream Paperclip actually does with an agent's tool calls for `adapterConfig`.

    Mirrors `claude-local/src/server/acp.ts normalizeEngine` (unset/unknown -> ACP),
    `acpx-engine/execute.ts normalizePermissionMode` (unset/unknown -> `approve-all`, the
    ACP lane ignores `dangerouslySkipPermissions`) and the CLI lane
    (`execute.ts asBoolean(config.dangerouslySkipPermissions, true)`).
    """
    raw = str(cfg.get("engine") or "").strip().lower()
    engine = raw if raw in ("cli", "acp") else "acp"
    if engine == "acp":
        mode = str(cfg.get("permissionMode") or "").strip()
        return mode if mode in ("approve-reads", "deny-all") else "approve-all"
    flag = "dangerouslySkipPermissions" if adapter_type == "claude_local" else "dangerouslyBypassApprovalsAndSandbox"
    return "approve-all" if cfg.get(flag, True) is not False else "cli-non-interactive-deny"


class PCFake:
    def __init__(self) -> None:
        self.reqs: list[dict[str, Any]] = []
        self.agents: dict[str, dict[str, Any]] = {}
        self.rewrite: dict[str, Any] | None = None
        self.drop_config: tuple[str, ...] = ()

    def policy(self, aid: str) -> str:
        return paperclip_tool_policy(self.agents[aid]["adapterType"], self.agents[aid]["adapterConfig"])

    def __call__(self, req: dict[str, Any], **_kw: Any) -> Any:
        self.reqs.append(req)
        m, p = req["method"], req["path"]
        if m == "POST" and p.endswith("/agents"):
            aid = f"ag-{len(self.agents) + 1}"
            body = json.loads(json.dumps(req["body"]))
            if self.rewrite:
                body.update(self.rewrite)
            for key in self.drop_config:
                body.get("adapterConfig", {}).pop(key, None)
            self.agents[aid] = body
            return {"id": aid, **body}
        if m == "GET" and p.startswith("/api/agents/"):
            aid = p.split("/")[3]
            return {"id": aid, "status": "running", **self.agents[aid]}
        if m == "POST" and p.endswith("/issues"):
            return {"id": "iss-7"}
        if p.endswith("/execution"):
            return {"runId": "run-3"}
        if p.endswith("/log"):
            return {"runId": "run-3", "content": json.dumps({"stream": "stdout", "chunk": "hello\nworld"}) + "\n"}
        return {"ok": True}


class TestPaperclip(Base):
    def setUp(self) -> None:
        super().setUp()
        self.wt = self.tmp / "pwt"
        self.wt.mkdir()

    def test_spec_becomes_issue_description_via_dispatch(self) -> None:
        fake = PCFake()
        prov = PaperclipProvider(state=self.state, runner=fake, company_id="co")
        res = self.start_via_dispatch(prov, "--worktree", str(self.wt))
        issue = [r for r in fake.reqs if r["path"] == "/api/companies/co/issues"][0]
        self.assertEqual(issue["body"]["description"], SPEC)
        self.assertEqual(res["launch"]["effective"]["runId"], "run-3")
        read = prov.worker_read(dispatch_id=res["dispatchId"], source="terminal")
        self.assertEqual(fake.reqs[-1]["path"], "/api/heartbeat-runs/run-3/log")
        self.assertEqual(read["terminal"]["tail"], ["hello", "world"])

    def test_negative_ro_read_back_true_deletes_agent(self) -> None:
        fake = PCFake()
        fake.rewrite = {"adapterConfig": {"dangerouslySkipPermissions": True, "cwd": str(self.wt)}}
        prov = PaperclipProvider(state=self.state, runner=fake, company_id="co")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t", worktree=str(self.wt), profile="ro", prompt="x")
        self.assertEqual(ctx.exception.code, "permissions_unverified")
        self.assertEqual(fake.reqs[-1]["method"], "DELETE")
        self.assertFalse(any(r["path"].endswith("/checkout") for r in fake.reqs))

    def test_ro_agent_is_not_approve_all_under_upstream_engine_defaults(self) -> None:
        fake = PCFake()
        prov = PaperclipProvider(state=self.state, runner=fake, company_id="co")
        res = prov.worker_start(task_id="t", worktree=str(self.wt), profile="ro", prompt="x")
        aid = res["dispatchId"]
        # Upstream defaults claude_local to the ACP engine, whose approve-all ignores
        # dangerouslySkipPermissions: the stored config must select a lane that denies writes.
        self.assertNotEqual(fake.policy(aid), "approve-all")
        self.assertEqual(fake.agents[aid]["adapterConfig"]["engine"], "cli")
        read_back = res["launch"]["effective"]["adapterConfigReadBack"]
        self.assertEqual((read_back["engine"], read_back["dangerouslySkipPermissions"]), ("cli", False))
        self.assertEqual(read_back["permissionMode"], "approve-reads")
        # Negative control: the same config without the engine pin IS approve-all upstream.
        self.assertEqual(paperclip_tool_policy("claude_local", {"dangerouslySkipPermissions": False}), "approve-all")
        rw = prov.worker_start(task_id="t2", worktree=str(self.wt), profile="rw", prompt="x")
        self.assertEqual(fake.agents[rw["dispatchId"]]["adapterConfig"]["engine"], "cli")

    def test_negative_engine_dropped_on_read_back_deletes_agent(self) -> None:
        for dropped in ("engine", "permissionMode"):
            with self.subTest(dropped=dropped):
                fake = PCFake()
                fake.drop_config = (dropped,)
                prov = PaperclipProvider(state=self.state, runner=fake, company_id="co")
                with self.assertRaises(ProviderError) as ctx:
                    prov.worker_start(task_id="t", worktree=str(self.wt), profile="ro", prompt="x")
                self.assertEqual(ctx.exception.code, "permissions_unverified")
                self.assertIn(dropped, ctx.exception.message)
                self.assertEqual(fake.reqs[-1]["method"], "DELETE")
                self.assertFalse(any(r["path"].endswith("/checkout") for r in fake.reqs))

    def test_negative_runner_rewrite_is_refused(self) -> None:
        fake = PCFake()
        fake.rewrite = {"adapterType": "paperclip_runner"}
        prov = PaperclipProvider(state=self.state, runner=fake, company_id="co")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t", worktree=str(self.wt), profile="rw", prompt="x")
        self.assertEqual(ctx.exception.code, "permissions_unverified")

    def test_missing_id_company_and_retain(self) -> None:
        prov = PaperclipProvider(state=self.state, runner=lambda req, **k: {"name": "x"}, company_id="co")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t", worktree=str(self.wt), prompt="x")
        self.assertEqual(ctx.exception.code, "upstream_no_id")
        with self.assertRaises(ProviderError) as ctx:
            PaperclipProvider(state=self.state, runner=PCFake(), env={}).worker_start(task_id="t", prompt="x")
        self.assertEqual(ctx.exception.code, "missing_company")
        fake = PCFake()
        prov = PaperclipProvider(state=self.state, runner=fake, company_id="co")
        res = prov.worker_start(task_id="t", worktree=str(self.wt), prompt="x")
        n = len(fake.reqs)
        self.assertEqual(prov.worker_fence(verb="retain", dispatch_id=res["dispatchId"])["state"], "retained")
        self.assertEqual(len(fake.reqs), n)
        prov.worker_fence(verb="release", dispatch_id=res["dispatchId"])
        self.assertEqual([r["path"] for r in fake.reqs[n:]], [f"/api/agents/{res['dispatchId']}/pause", "/api/issues/iss-7/release"])
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_show(dispatch_id="ghost")
        self.assertEqual(ctx.exception.code, "dispatch_not_found")


# ---------------------------------------------------------------------------- Multiclaude
class MCFake:
    def __init__(self, home: Path, repo_src: Path) -> None:
        self.home = home
        self.repo_src = repo_src
        self.msgs: list[dict[str, Any]] = []
        self.events: list[str] = []
        self.windows: set[str] = set()
        self.copy_hooks = True

    def __call__(self, msg: dict[str, Any], **_kw: Any) -> dict[str, Any]:
        self.msgs.append(msg)
        self.events.append(msg["command"])
        if msg["command"] == "spawn_agent":
            name = msg["args"]["name"]
            self.windows.add(name)  # the daemon opens tmux window mc-proj:<name> running claude
            wt = self.home / "wts" / "proj" / name
            wt.parent.mkdir(parents=True, exist_ok=True)
            git(self.repo_src, "worktree", "add", "-q", "-b", f"work/{name}", str(wt))
            src = self.home / "repos" / "proj" / ".multiclaude" / "hooks.json"
            if self.copy_hooks and src.is_file():
                (wt / ".claude").mkdir(exist_ok=True)
                (wt / ".claude" / "settings.json").write_text(src.read_text())
            return {"success": True, "data": {"name": name, "worktree_path": str(wt)}}
        if msg["command"] == "list_agents":
            return {"success": True, "data": [{"name": "mc-a", "status": "running"}]}
        return {"success": True, "data": None}

    def commands(self) -> list[str]:
        return [m["command"] for m in self.msgs]


class TestMulticlaude(Base):
    def setUp(self) -> None:
        super().setUp()
        self.home = self.tmp / "mch"
        self.repo_src = self.home / "repos" / "proj"
        self.base = make_repo(self.repo_src)
        self.fake = MCFake(self.home, self.repo_src)
        self.cli: list[list[str]] = []
        self.tmux_down = False  # tmux reachable but the kill errors (wrong server/socket)
        self.kill_noop = False  # kill-window "succeeds" but the window survives

        def cli(argv: list[str]) -> dict[str, Any]:
            self.cli.append(argv)
            if argv[0] == "tmux":
                self.fake.events.append(f"tmux {argv[1]}")
                if self.tmux_down:
                    raise ProviderError("multiclaude_cli_error", "no server running on /tmp/tmux-1000/default")
                if argv[1] == "kill-window":
                    window = argv[3].split(":", 1)[1]
                    if window not in self.fake.windows:
                        raise ProviderError("multiclaude_cli_error", f"can't find window: {window}")
                    if not self.kill_noop:
                        self.fake.windows.discard(window)
                    return {"stdout": "", "raw": ""}
                if argv[1] == "list-windows":
                    out = "".join(f"{w}\n" for w in sorted(self.fake.windows | {"supervisor"}))
                    return {"stdout": out, "raw": out.strip()}
                return {"stdout": "pane line\n", "raw": "pane line"}
            return common.run_cli(argv, provider="multiclaude")

        self.prov = MulticlaudeProvider(state=self.state, runner=self.fake, home=self.home, repo="proj", cli_runner=cli)

    def start(self, profile: str = "rw") -> dict[str, Any]:
        return self.prov.worker_start(task_id="t", name="mc-a", profile=profile, prompt=SPEC)

    def manifest(self, head: str, base: str | None = None, name: str = "m.json") -> str:
        path = self.tmp / name
        doc: dict[str, Any] = {"head_sha": head}
        if base is not None:
            doc["base_sha"] = base
        path.write_text(json.dumps(doc))
        return str(path)

    def test_spec_reaches_spawn_prompt_and_kickoff_via_dispatch(self) -> None:
        res = self.start_via_dispatch(self.prov, "--name", "mc-a")
        spawn = [m for m in self.fake.msgs if m["command"] == "spawn_agent"][0]
        self.assertIn(SPEC, spawn["args"]["prompt"])
        self.assertIn("route_messages", self.fake.commands())
        self.assertEqual(len(list((self.home / "messages" / "proj" / "mc-a").glob("msg-*.json"))), 1)
        settings = json.loads((Path(res["worktree"]) / ".claude" / "settings.json").read_text())
        self.assertIn("deny-hook.sh", json.dumps(settings))

    def test_ro_settings_block_writes_and_missing_copy_fails_closed(self) -> None:
        (self.repo_src / ".multiclaude").mkdir()
        user_hooks = {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "true"}]}]}}
        (self.repo_src / ".multiclaude" / "hooks.json").write_text(json.dumps(user_hooks))
        res = self.start("ro")
        settings = json.loads((Path(res["worktree"]) / ".claude" / "settings.json").read_text())
        self.assertEqual(settings["permissions"]["deny"][:4], ["Edit", "Write", "MultiEdit", "NotebookEdit"])
        self.assertIn("exit 2", settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"])
        self.assertNotIn("Stop", settings["hooks"])  # untrusted repo hooks are stripped (#774)
        self.assertEqual(json.loads((self.repo_src / ".multiclaude" / "hooks.json").read_text()), user_hooks)  # restored
        self.fake.copy_hooks = False
        with self.assertRaises(ProviderError) as ctx:
            self.prov.worker_start(task_id="t", name="mc-b", profile="ro", prompt=SPEC)
        self.assertEqual(ctx.exception.code, "hooks_not_installed")
        self.assertIn("remove_agent", self.fake.commands())

    def test_release_refused_without_durable_verify_even_with_flag(self) -> None:
        self.start()
        with self.assertRaises(ProviderError) as ctx:
            self.prov.worker_fence(verb="release", dispatch_id="mc-a", verified=True)
        self.assertEqual(ctx.exception.code, "unverified_release_blocked")
        with self.assertRaises(ProviderError) as ctx:
            self.prov.dispatch(["orchestration", "worker-release", "--dispatch", "mc-a", "--verified"], env={})
        self.assertEqual(ctx.exception.code, "unverified_release_blocked")
        self.assertNotIn("complete_agent", self.fake.commands())
        with self.assertRaises(ProviderError):
            self.prov.mark_verified("mc-a")

    def test_release_accepted_after_worker_verify_and_survives_stop_retain(self) -> None:
        res = self.start()
        wt = Path(res["worktree"])
        head = commit(wt, "worker change")
        manifest = self.tmp / "m.json"
        manifest.write_text(json.dumps({"head_sha": head, "base_sha": self.base}))
        out = self.prov.dispatch(
            ["orchestration", "worker-verify", "--dispatch", "mc-a", "--sha", head[:12], "--manifest", str(manifest)], env={}
        )
        self.assertEqual(out["verifiedSha"], head)
        self.prov.worker_fence(verb="retain", dispatch_id="mc-a")
        fresh = MulticlaudeProvider(state=LocalStateStore(db_path=self.tmp / "state.db"), runner=self.fake,
                                    home=self.home, repo="proj", cli_runner=self.prov._cli)
        released = fresh.worker_fence(verb="release", dispatch_id="mc-a", reason="merged")
        self.assertEqual(released["verifiedSha"], head)
        self.assertEqual(self.fake.msgs[-1], {"command": "complete_agent", "args": {"repo": "proj", "agent": "mc-a", "summary": "merged"}})

    def test_release_refused_when_head_moved_after_verify(self) -> None:
        res = self.start()
        wt = Path(res["worktree"])
        head = commit(wt, "worker change")
        self.prov.worker_verify(dispatch_id="mc-a", sha=head, manifest=self.manifest(head, self.base))
        commit(wt, "sneaky later change")
        with self.assertRaises(ProviderError) as ctx:
            self.prov.worker_fence(verb="release", dispatch_id="mc-a")
        self.assertEqual(ctx.exception.code, "verification_stale")
        self.assertNotIn("complete_agent", self.fake.commands())

    def test_verify_negative_controls(self) -> None:
        res = self.start()
        wt = Path(res["worktree"])
        head = commit(wt, "worker change")
        with self.assertRaises(ProviderError) as ctx:
            self.prov.worker_verify(dispatch_id="mc-a", sha=self.base, manifest=self.manifest(self.base, self.base))
        self.assertEqual(ctx.exception.code, "head_mismatch")
        bad = self.tmp / "bad.json"
        bad.write_text(json.dumps({"head_sha": self.base}))
        with self.assertRaises(ProviderError) as ctx:
            self.prov.worker_verify(dispatch_id="mc-a", sha=head, manifest=str(bad))
        self.assertEqual(ctx.exception.code, "manifest_mismatch")
        with self.assertRaises(ProviderError) as ctx:
            self.prov.worker_verify(dispatch_id="ghost", sha=head)
        self.assertEqual(ctx.exception.code, "dispatch_not_found")
        self.assertIsNone(self.prov._verification("mc-a"))

    def test_verify_requires_manifest_with_head_and_ancestor_base(self) -> None:
        res = self.start()
        wt = Path(res["worktree"])
        head = commit(wt, "worker change")
        # The repro: `--sha <HEAD>` alone must never unlock release.
        with self.assertRaises(ProviderError) as ctx:
            self.prov.dispatch(["orchestration", "worker-verify", "--dispatch", "mc-a", "--sha", head], env={})
        self.assertEqual(ctx.exception.code, "manifest_required")
        with self.assertRaises(ProviderError) as ctx:
            self.prov.worker_verify(dispatch_id="mc-a", sha=head, manifest=self.manifest(head))
        self.assertEqual(ctx.exception.code, "manifest_incomplete")
        git(self.repo_src, "checkout", "-q", "-b", "elsewhere")
        unrelated = commit(self.repo_src, "not under the worker")
        with self.assertRaises(ProviderError) as ctx:
            self.prov.worker_verify(dispatch_id="mc-a", sha=head, manifest=self.manifest(head, unrelated))
        self.assertEqual(ctx.exception.code, "not_on_base")
        with self.assertRaises(ProviderError) as ctx:
            self.prov.worker_verify(dispatch_id="mc-a", sha=head, manifest=self.manifest(head, "f" * 40))
        self.assertEqual(ctx.exception.code, "not_on_base")
        self.assertIsNone(self.prov._verification("mc-a"))
        with self.assertRaises(ProviderError) as ctx:
            self.prov.worker_fence(verb="release", dispatch_id="mc-a")
        self.assertEqual(ctx.exception.code, "unverified_release_blocked")
        self.assertNotIn("complete_agent", self.fake.commands())
        ok = self.prov.worker_verify(dispatch_id="mc-a", sha=head, manifest=self.manifest(head, self.base))
        self.assertEqual(ok["verifiedSha"], head)

    def test_release_refused_while_worktree_has_uncommitted_work(self) -> None:
        res = self.start()
        wt = Path(res["worktree"])
        head = commit(wt, "worker change")
        self.prov.worker_verify(dispatch_id="mc-a", sha=head, manifest=self.manifest(head, self.base))
        (wt / "notes.txt").write_text("uncommitted\n")
        (wt / "f.txt").write_text("edited but not committed\n")
        with self.assertRaises(ProviderError) as ctx:
            self.prov.worker_fence(verb="release", dispatch_id="mc-a")
        self.assertEqual(ctx.exception.code, "dirty_worktree_release_blocked")
        self.assertEqual(sorted(ctx.exception.data["dirty"]), ["f.txt", "notes.txt"])
        self.assertNotIn("complete_agent", self.fake.commands())
        self.assertTrue((wt / "notes.txt").is_file())
        # Negative control: once clean (the daemon's own .claude/settings.json copy is not work) it releases.
        (wt / "notes.txt").unlink()
        git(wt, "checkout", "--", "f.txt")
        self.assertTrue((wt / ".claude" / "settings.json").is_file())
        self.assertEqual(self.prov.worker_fence(verb="release", dispatch_id="mc-a")["state"], "released")

    def test_stop_fails_closed_when_kill_fails_or_window_survives(self) -> None:
        self.start()
        self.tmux_down = True  # the repro: tmux kill-window errors
        with self.assertRaises(ProviderError) as ctx:
            self.prov.worker_fence(verb="stop", dispatch_id="mc-a")
        self.assertEqual(ctx.exception.code, "stop_failed")
        self.assertNotIn("remove_agent", self.fake.commands())
        with self.state._connect() as conn:
            row = conn.execute("SELECT state FROM dispatches WHERE dispatch_id='mc-a'").fetchone()
        self.assertEqual(row["state"], "ready")
        self.tmux_down, self.kill_noop = False, True
        with self.assertRaises(ProviderError) as ctx:
            self.prov.worker_fence(verb="abandon", dispatch_id="mc-a")
        self.assertEqual(ctx.exception.code, "stop_unconfirmed")
        self.assertNotIn("remove_agent", self.fake.commands())
        self.kill_noop = False
        self.assertEqual(self.prov.worker_fence(verb="abandon", dispatch_id="mc-a")["state"], "abandoned")
        self.assertEqual(self.fake.commands()[-1], "remove_agent")

    def test_stop_keeps_worktree_order_and_read_show(self) -> None:
        res = self.start()
        head = git(res["worktree"], "rev-parse", "HEAD")
        out = self.prov.worker_fence(verb="stop", dispatch_id="mc-a")
        tail = self.fake.events[-3:]
        self.assertEqual(tail, ["tmux kill-window", "tmux list-windows", "remove_agent"])  # kill, confirm, then forget
        self.assertNotIn("mc-a", self.fake.windows)
        self.assertEqual(out["upstream"]["preserved"]["sha"], head)
        self.assertEqual(git(self.repo_src, "rev-parse", "refs/open-fleet/preserved/mc-a"), head)
        self.assertTrue(Path(res["worktree"]).is_dir())
        read = self.prov.worker_read(dispatch_id="mc-a", source="terminal")
        self.assertEqual(read["terminal"]["tail"], ["pane line"])
        show = self.prov.worker_show(dispatch_id="mc-a")
        self.assertEqual(show["worker"]["state"], "stopped")

    def test_default_runner_bad_json_is_ok_false(self) -> None:
        sock_path = str(self.tmp / "d.sock")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(1)

        def serve() -> None:
            conn, _ = srv.accept()
            conn.recv(65536)
            conn.sendall(b"garbage")
            conn.close()

        th = threading.Thread(target=serve, daemon=True)
        th.start()
        prov = MulticlaudeProvider(state=self.state, home=self.home, repo="proj", socket_path=sock_path)
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t", name="mc-z", prompt="x")
        th.join(2)
        srv.close()
        self.assertEqual(ctx.exception.code, "multiclaude_bad_json")
        self.assertFalse(ctx.exception.to_envelope()["ok"])


# ------------------------------------------------------------------------------- shared
class TestCommonTransport(unittest.TestCase):
    def test_missing_binary_and_timeout_are_provider_errors(self) -> None:
        with self.assertRaises(ProviderError) as ctx:
            common.run_cli(["open-fleet-definitely-not-a-binary"], provider="ao")
        self.assertEqual(ctx.exception.code, "ao_cli_missing")
        with self.assertRaises(ProviderError) as ctx:
            common.run_cli([sys.executable, "-c", "import time; time.sleep(5)"], provider="ao", timeout=0.2)
        self.assertEqual(ctx.exception.code, "ao_timeout")
        with self.assertRaises(ProviderError) as ctx:
            common.run_cli([sys.executable, "-c", "import sys; sys.exit(3)"], provider="ao")
        self.assertEqual(ctx.exception.code, "ao_cli_error")

    def test_unreachable_http_is_provider_error(self) -> None:
        with self.assertRaises(ProviderError) as ctx:
            common.http_json("http://127.0.0.1:9", "GET", "/x", provider="paperclip", timeout=1)
        self.assertIn(ctx.exception.code, ("paperclip_unreachable", "paperclip_http_error"))


class TestCredentialsNeverFollowARedirect(unittest.TestCase):
    """2026-10-27 audit, W5-08's class at its neighbours: an adapter's API key rode an ordinary
    header (`Request(headers=...)`), which urllib copies onto the request a 3xx makes, to whatever
    host its Location names. paperclip's bearer (through http_json) and OpenHands' session key now
    ride unredirected headers, and an answer from another origin is refused."""

    def serve(self, handler: type) -> int:
        from http.server import ThreadingHTTPServer
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def redirect_pair(self) -> tuple[str, dict[str, Any]]:
        from http.server import BaseHTTPRequestHandler
        seen: dict[str, Any] = {}

        class Elsewhere(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                seen["elsewhere"] = {k.lower(): v for k, v in self.headers.items()}
                body = b'{"ok": true, "id": "x", "conversations": []}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        far = self.serve(Elsewhere)

        class Redirector(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                seen["first"] = {k.lower(): v for k, v in self.headers.items()}
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{far}{self.path}")
                self.send_header("Content-Length", "0")
                self.end_headers()

        return f"http://127.0.0.1:{self.serve(Redirector)}", seen

    def test_http_json_never_resends_a_callers_header_and_refuses_the_answer(self) -> None:
        base, seen = self.redirect_pair()
        with self.assertRaises(ProviderError) as ctx:
            common.http_json(base, "GET", "/api/x", provider="paperclip", timeout=5,
                             headers={"Authorization": "Bearer PAPERCLIP-KEY"})
        self.assertEqual(ctx.exception.code, "paperclip_redirected")
        self.assertEqual(seen["first"].get("authorization"), "Bearer PAPERCLIP-KEY")
        self.assertNotIn("authorization", seen["elsewhere"], "the key followed the redirect")

    def test_openhands_session_key_never_follows_a_redirect(self) -> None:
        openhands = _mod("runtime.providers.openhands")
        base, seen = self.redirect_pair()
        with tempfile.TemporaryDirectory() as tmp:
            prov = openhands.OpenHandsProvider(db_path=Path(tmp) / "state.db", base_url=base,
                                               env={"OPEN_FLEET_OPENHANDS_SESSION_API_KEY": "OH-KEY"})
            with self.assertRaises(ProviderError) as ctx:
                prov._default_runner({"method": "GET", "path": "/api/conversations/search"}, timeout=5)
        self.assertEqual(ctx.exception.code, "openhands_redirected")
        self.assertEqual(seen["first"].get("x-session-api-key"), "OH-KEY")
        self.assertNotIn("x-session-api-key", seen["elsewhere"], "the session key followed the redirect")


if __name__ == "__main__":
    unittest.main()
