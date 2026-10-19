#!/usr/bin/env python3
"""Unit tests and negative controls for all 12 external orchestrator RuntimeProviders (#582, #583, #584, #588, #589)."""
from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_providers() -> dict[str, types.ModuleType]:
    root_str = str(ROOT)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    import importlib

    importlib.import_module("runtime.providers")
    loaded: dict[str, types.ModuleType] = {}
    for mod_name in (
        "base",
        "local_state",
        "superset",
        "gastown",
        "worktrunk",
        "openhands",
        "overstory",
        "t3code",
        "ao",
        "jcode_swarm",
        "emdash",
        "vibe_kanban",
        "paperclip",
        "multiclaude",
    ):
        loaded[mod_name] = importlib.import_module(f"runtime.providers.{mod_name}")
    return loaded


MODS = _load_providers()
ProviderError = MODS["base"].ProviderError
LocalStateStore = MODS["local_state"].LocalStateStore
SupersetProvider = MODS["superset"].SupersetProvider
GastownProvider = MODS["gastown"].GastownProvider
WorktrunkProvider = MODS["worktrunk"].WorktrunkProvider
OpenHandsProvider = MODS["openhands"].OpenHandsProvider
OverstoryProvider = MODS["overstory"].OverstoryProvider
T3CodeProvider = MODS["t3code"].T3CodeProvider
ComposioAOProvider = MODS["ao"].ComposioAOProvider
JCodeSwarmProvider = MODS["jcode_swarm"].JCodeSwarmProvider
EmdashProvider = MODS["emdash"].EmdashProvider
VibeKanbanProvider = MODS["vibe_kanban"].VibeKanbanProvider
PaperclipProvider = MODS["paperclip"].PaperclipProvider
MulticlaudeProvider = MODS["multiclaude"].MulticlaudeProvider


class ProviderTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)
        self.state = LocalStateStore(db_path=self.tmp_path / "state.db")

    def tearDown(self) -> None:
        self._tmp.cleanup()


class TestSupersetProvider(ProviderTestBase):
    """#582: SupersetProvider (`superset-sh/superset`) CLI/Desktop adapter."""

    def test_worktree_lifecycle_and_worker_profiles(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str], **_kw: object) -> dict[str, object]:
            calls.append(argv)
            return {"id": "sup-123", "workspaces": [{"id": "ws-1"}]}

        prov = SupersetProvider(state=self.state, runner=runner, env={})
        wt_list = prov.worktree_list()
        self.assertEqual(calls[-1], ["superset", "workspaces", "list", "--local", "--json"])
        self.assertEqual(wt_list["worktrees"], [{"id": "ws-1"}])

        prov.worktree_show(selector="ws-1")
        self.assertEqual(calls[-1], ["superset", "workspaces", "get", "ws-1", "--local", "--json"])

        prov.worktree_create(name="feat-a", base="main")
        self.assertEqual(
            calls[-1],
            ["superset", "workspaces", "create", "--name", "feat-a", "--local", "--json", "--base", "main"],
        )

        prov.worktree_rm(selector="ws-1", force=True)
        self.assertEqual(calls[-1], ["superset", "workspaces", "delete", "ws-1", "--local", "--json", "--force"])

        # PROFILE=ro MUST use `superset terminals create` (never `superset agents create`)
        ro_res = prov.worker_start(task_id="t1", worktree="ws-1", agent="claude", profile="ro")
        self.assertEqual(calls[-1][:3], ["superset", "terminals", "create"])
        self.assertNotEqual(calls[-1][:3], ["superset", "agents", "create"])
        self.assertIn("--permission-mode plan", ro_res["launch"]["effective"]["command"])
        self.assertEqual(ro_res["launch"]["effective"]["mechanism"], "terminals.create")

        # PROFILE=rw uses `superset agents create`
        rw_res = prov.worker_start(task_id="t2", worktree="ws-1", agent="claude", profile="rw")
        self.assertEqual(
            calls[-1],
            ["superset", "agents", "create", "--workspace", "ws-1", "--agent", "claude", "--json"],
        )
        self.assertEqual(rw_res["launch"]["effective"]["profile_flag"], "--dangerously-skip-permissions")

        # PROFILE=danger fails closed without OPEN_FLEET_SANDBOX_RECIPE / ORCA_SANDBOX_RECIPE
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t3", worktree="ws-1", agent="claude", profile="danger")
        self.assertEqual(ctx.exception.code, "missing_sandbox_recipe")

        # PROFILE=danger succeeds with recipe and passes `--environment`
        prov_cloud = SupersetProvider(
            state=self.state,
            runner=runner,
            env={"OPEN_FLEET_SANDBOX_RECIPE": "rcp-cloud-1"},
        )
        danger_res = prov_cloud.worker_start(task_id="t3", worktree="ws-1", agent="claude", profile="danger")
        self.assertIn("--environment", calls[-1])
        self.assertIn("rcp-cloud-1", calls[-1])
        self.assertEqual(danger_res["launch"]["effective"]["environment"], "rcp-cloud-1")

        # Monotonic privilege narrowing negative control
        with self.assertRaises(ProviderError) as pctx:
            prov.worker_start(task_id="t4", worktree="ws-1", agent="claude", profile="rw", parent_profile="ro")
        self.assertEqual(pctx.exception.code, "privilege_escalation")

        # Worker list / show / read / fence
        prov.worker_list()
        self.assertEqual(calls[-1], ["superset", "snapshot", "--json"])
        prov.worker_show(dispatch_id="sup-123")
        self.assertEqual(calls[-1], ["superset", "agents", "explain", "sup-123", "--json"])
        prov.worker_read(dispatch_id="sup-123", limit=25)
        self.assertEqual(calls[-1], ["superset", "agents", "read", "sup-123", "--limit", "25", "--json"])
        prov.worker_fence(verb="stop", dispatch_id="sup-123")
        self.assertEqual(calls[-1], ["superset", "terminals", "kill", "sup-123", "--json"])


class TestGastownProvider(ProviderTestBase):
    """#583: GastownProvider (`gt` + `bd` Beads)."""

    def test_beads_dag_ro_alias_and_mail_bridge(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str], **_kw: object) -> dict[str, object]:
            calls.append(argv)
            return {"id": "bd-1", "polecatId": "pc-1", "messages": [{"id": "m1"}]}

        prov = GastownProvider(state=self.state, runner=runner, rig="rig-alpha")
        created = prov.task_create(spec="fix bug", title="Fix bug")
        self.assertEqual(calls[-1], ["bd", "create", "Fix bug", "--json"])
        task_id = created["task"]["id"]

        prov.task_update(task_id=task_id, status="completed")
        self.assertEqual(calls[-1], ["bd", "update", task_id, "--status", "completed", "--json"])

        listed = prov.task_list()
        self.assertEqual(calls[-1], ["bd", "list", "--json"])
        self.assertEqual(len(listed["tasks"]), 1)

        # PROFILE=ro registers `<agent>-ro` alias and passes `--no-merge`
        ro_res = prov.worker_start(task_id=task_id, worktree="/tmp/wt", agent="claude", profile="ro")
        self.assertEqual(calls[-2][:4], ["gt", "config", "agent", "set"])
        self.assertEqual(calls[-2][4], "claude-ro")
        self.assertEqual(
            calls[-1],
            ["gt", "sling", task_id, "rig-alpha", "--agent", "claude-ro", "--no-merge", "--json"],
        )
        self.assertEqual(ro_res["launch"]["effective"]["agentAlias"], "claude-ro")

        # PROFILE=rw uses `<agent>` and `--no-merge`
        prov.worker_start(task_id=task_id, worktree="/tmp/wt", agent="codex", profile="rw")
        self.assertEqual(
            calls[-1],
            ["gt", "sling", task_id, "rig-alpha", "--agent", "codex", "--no-merge", "--json"],
        )

        # Mail send & check bridge
        prov.send_message(subject="done", msg_type="worker_done", to="mayor", payload="ok")
        self.assertEqual(
            calls[-1],
            ["gt", "mail", "send", "mayor", "--subject", "done", "--type", "worker_done", "--body", "ok", "--json"],
        )
        inbox = prov.check_messages()
        self.assertEqual(calls[-1], ["gt", "mail", "inbox", "--unread", "--json"])
        self.assertEqual(len(inbox["messages"]), 1)
        self.assertEqual(inbox["upstreamInbox"], [{"id": "m1"}])


class TestWorktrunkProvider(ProviderTestBase):
    """#583: WorktrunkProvider (`wt`)."""

    def test_cow_worktree_dispatch_and_merge_prediction(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str], **_kw: object) -> dict[str, object]:
            calls.append(argv)
            return {"path": "/tmp/wt/feat-1", "merged": True, "conflicts": []}

        prov = WorktrunkProvider(state=self.state, runner=runner)
        res = prov.worker_start(task_id="t10", name="feat-1", agent="omp", profile="ro")
        self.assertEqual(calls[0], ["wt", "switch", "--create", "feat-1", "--no-cd", "-y", "--format=json"])
        self.assertEqual(calls[1], ["wt", "step", "copy-ignored"])
        self.assertEqual(calls[2][:5], ["wt", "switch", "feat-1", "--no-cd", "-y"])
        self.assertIn("--approval-mode always-ask", res["launch"]["effective"]["command"])

        merge_res = prov.predict_and_merge("feat-1", target="main")
        self.assertEqual(calls[-1], ["wt", "merge", "feat-1", "--format=json", "--target", "main"])
        self.assertTrue(merge_res["merged"])

        prov.worktree_rm(selector="feat-1", force=True)
        self.assertEqual(calls[-1], ["wt", "remove", "--reap", "feat-1", "--force"])


class TestOpenHandsProvider(ProviderTestBase):
    """#584: OpenHandsProvider (`openhands.agent_server` REST API)."""

    def test_ro_tool_stripping_hooks_and_danger_containers(self) -> None:
        reqs: list[dict[str, object]] = []

        def runner(req: dict[str, object], **_kw: object) -> dict[str, object]:
            reqs.append(req)
            return {"conversation_id": "conv-99", "events": [{"id": "ev-1"}]}

        prov = OpenHandsProvider(state=self.state, runner=runner)
        wt_dir = self.tmp_path / "oh-wt"
        wt_dir.mkdir(parents=True, exist_ok=True)

        ro_res = prov.worker_start(task_id="t1", worktree=str(wt_dir), profile="ro")
        conv_req = reqs[0]
        self.assertEqual(conv_req["path"], "/api/conversations")
        body = conv_req["body"]
        assert isinstance(body, dict)
        self.assertEqual(body["tools"], ["glob", "grep", "planning_file_editor"])
        self.assertIn("terminal", body["disabled_tools"])
        self.assertIn("file_editor", body["disabled_tools"])
        self.assertTrue((wt_dir / ".openhands" / "hooks.json").is_file())
        self.assertEqual(ro_res["dispatchId"], "conv-99")

        # PROFILE=danger uses docker or apptainer, rejects unknown workspace_type
        danger_res = prov.worker_start(task_id="t2", worktree=str(wt_dir), profile="danger", workspace_type="apptainer")
        self.assertEqual(danger_res["launch"]["effective"]["workspace_type"], "apptainer")

        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t3", worktree=str(wt_dir), profile="danger", workspace_type="host")
        self.assertEqual(ctx.exception.code, "invalid_workspace_type")

        prov.worker_read(dispatch_id="conv-99", limit=10)
        self.assertEqual(reqs[-1]["path"], "/api/conversations/conv-99/events/search?limit=10")

        prov.worker_fence(verb="stop", dispatch_id="conv-99", reason="timeout")
        self.assertEqual(reqs[-1]["path"], "/api/conversations/conv-99/interrupt")


class TestOverstoryProvider(ProviderTestBase):
    """#588: OverstoryProvider (`ov`)."""

    def test_scout_vs_builder_capability_and_mail(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str], **_kw: object) -> dict[str, object]:
            calls.append(argv)
            return {"agentName": "ov-worker-1", "messages": []}

        prov = OverstoryProvider(state=self.state, runner=runner)
        ro = prov.worker_start(task_id="t-ro", agent="claude", profile="ro")
        self.assertEqual(calls[-1], ["ov", "sling", "t-ro", "--capability", "scout", "--runtime", "claude", "--json"])
        self.assertEqual(ro["capability"], "scout")

        rw = prov.worker_start(task_id="t-rw", agent="codex", profile="rw")
        self.assertEqual(calls[-1], ["ov", "sling", "t-rw", "--capability", "builder", "--runtime", "codex", "--json"])
        self.assertEqual(rw["capability"], "builder")

        prov.send_message(subject="ready", msg_type="merge_ready", to="orchestrator", payload="sha123")
        self.assertEqual(
            calls[-1],
            ["ov", "mail", "send", "--type", "merge_ready", "--subject", "ready", "--body", "sha123", "--json", "--to", "orchestrator"],
        )


class TestT3CodeProvider(ProviderTestBase):
    """#588: T3CodeProvider (`t3` OrchestratorV2)."""

    def test_session_modes_and_turn_dispatch(self) -> None:
        calls: list[dict[str, object]] = []

        def runner(call: dict[str, object], **_kw: object) -> dict[str, object]:
            calls.append(call)
            return {"sessionId": "t3-sess-1"}

        prov = T3CodeProvider(state=self.state, runner=runner)
        ro = prov.worker_start(task_id="t1", agent="claude", profile="ro", prompt="Audit")
        self.assertEqual(calls[0]["method"], "orchestration.createSession")
        p0 = calls[0]["params"]
        assert isinstance(p0, dict)
        self.assertEqual(p0["isolationMode"], "worktree")
        self.assertEqual(p0["interactionMode"], "plan")
        self.assertEqual(p0["runtimeMode"], "approval-required")
        self.assertEqual(calls[1]["method"], "orchestration.sendTurn")
        self.assertEqual(ro["launch"]["effective"]["interactionMode"], "plan")

        rw = prov.worker_start(task_id="t2", agent="claude", profile="rw")
        self.assertEqual(rw["launch"]["effective"]["interactionMode"], "default")
        self.assertEqual(rw["launch"]["effective"]["runtimeMode"], "full-access")


class TestComposioAOProvider(ProviderTestBase):
    """#588: ComposioAOProvider (`ao`)."""

    def test_ro_custom_launch_and_preserved_refs(self) -> None:
        calls: list[object] = []

        def runner(call: object, **_kw: object) -> dict[str, object]:
            calls.append(call)
            return {"sessionId": "ao-sess-1", "output": "hello"}

        prov = ComposioAOProvider(state=self.state, runner=runner, project="orca-proj")
        ro = prov.worker_start(task_id="t1", agent="pi", profile="ro", worktree="/tmp/wt")
        first = calls[0]
        assert isinstance(first, dict)
        self.assertEqual(first["path"], "/api/v1/sessions")
        self.assertEqual(first["body"]["permissions"], "plan")
        self.assertIn("--exclude-tools", first["body"]["launch_command"])
        self.assertEqual(ro["launch"]["effective"]["mechanism"], "api.sessions.ro")

        prov.worker_start(task_id="t2", agent="claude", profile="rw")
        self.assertEqual(calls[-1], ["ao", "spawn", "orca-proj", "t2", "--agent", "claude", "--json"])

        prov.terminal_read(terminal="ao:ao-sess-1")
        self.assertEqual(calls[-1], {"method": "GET", "path": "/api/v1/sessions/ao-sess-1/output", "body": None})

        fenced = prov.worker_fence(verb="release", dispatch_id="ao-sess-1")
        self.assertEqual(fenced["preservedRef"], "refs/ao/preserved/ao-sess-1")
        self.assertIn(["git", "update-ref", "refs/ao/preserved/ao-sess-1", "HEAD"], calls)


class TestJCodeSwarmProvider(ProviderTestBase):
    """#588: JCodeSwarmProvider (`jcode serve` + `jcode api-bridge`)."""

    def test_ro_explicit_disabled_tools_and_file_touches(self) -> None:
        calls: list[dict[str, object]] = []

        def runner(call: dict[str, object], **_kw: object) -> dict[str, object]:
            calls.append(call)
            if call.get("op") == "file_touches":
                return {
                    "touches": [
                        {"worker_id": "w1", "file_path": "src/a.py", "start_line": 10, "end_line": 20, "op": "write"},
                        {"worker_id": "w2", "file_path": "src/a.py", "start_line": 15, "end_line": 25, "op": "write"},
                    ]
                }
            return {"session_id": "jc-1"}

        prov = JCodeSwarmProvider(state=self.state, runner=runner)
        ro = prov.worker_start(task_id="t1", worktree="/tmp/wt", profile="ro")
        sess_call = calls[0]["payload"]
        assert isinstance(sess_call, dict)
        self.assertFalse(sess_call["use_minimal_profile"])
        self.assertIn("bash,write,edit,replace,apply_patch", sess_call["disabled_tools"])
        self.assertEqual(ro["launch"]["effective"]["disabled_tools"], sess_call["disabled_tools"])

        sync = prov.sync_file_touches(run_id="r1")
        self.assertEqual(sync["synced"], 2)
        self.assertTrue(sync["results"][1]["conflict"])
        self.assertEqual(sync["results"][1]["conflicts"][0]["kind"], "overlapping_hunk")


class TestEmdashProvider(ProviderTestBase):
    """#589: EmdashProvider (`workspace-server` JSON-RPC 2.0)."""

    def test_jsonrpc_auto_approve_and_pty(self) -> None:
        rpcs: list[dict[str, object]] = []

        def runner(payload: dict[str, object], **_kw: object) -> dict[str, object]:
            rpcs.append(payload)
            return {"path": "/tmp/emdash/w1", "streamId": "em-1", "ptyId": "pty-1", "snapshot": "ready$"}

        prov = EmdashProvider(state=self.state, runner=runner)
        ro = prov.worker_start(task_id="t1", worktree="/tmp/emdash/w1", agent="claude", profile="ro")
        self.assertEqual(rpcs[-1]["method"], "agent.startStream")
        params = rpcs[-1]["params"]
        assert isinstance(params, dict)
        self.assertFalse(params["autoApprove"])
        self.assertIn("plan", params["extraArgs"])
        self.assertFalse(ro["launch"]["effective"]["autoApprove"])

        rw = prov.worker_start(task_id="t2", worktree="/tmp/emdash/w1", agent="claude", profile="rw")
        self.assertTrue(rw["launch"]["effective"]["autoApprove"])

        snap = prov.terminal_read(terminal="emdash:pty-1")
        self.assertEqual(rpcs[-1]["method"], "pty.snapshot")
        self.assertEqual(snap["snapshot"], "ready$")


class TestVibeKanbanProvider(ProviderTestBase):
    """#589: VibeKanbanProvider (`BloopAI/vibe-kanban`)."""

    def test_ro_dangerously_skip_permissions_false_and_auto_commit_guard(self) -> None:
        reqs: list[dict[str, object]] = []

        def runner(req: dict[str, object], **_kw: object) -> dict[str, object]:
            reqs.append(req)
            return {"attempt_id": "vk-1", "execution_process_id": "proc-1", "logs": ["line1"]}

        prov = VibeKanbanProvider(state=self.state, runner=runner)
        ro = prov.worker_start(
            task_id="t1",
            worktree="/tmp/vk-wt",
            agent="claude",
            profile="ro",
            head_subject="Changes from coding agent (vibe-kanban 123)",
            strip_auto_commit=True,
        )
        # 1. Profile registration explicitly sets dangerously_skip_permissions: False
        prof_req = reqs[0]
        self.assertEqual(prof_req["path"], "/api/profiles")
        self.assertEqual(prof_req["body"]["name"], "ORCA_RO")
        self.assertIs(prof_req["body"]["dangerously_skip_permissions"], False)
        self.assertEqual(prof_req["body"]["permission_policy"], "plan")

        # 2. Task attempt also enforces dangerously_skip_permissions: False
        att_req = reqs[1]
        self.assertEqual(att_req["path"], "/api/task-attempts")
        self.assertIs(att_req["body"]["dangerously_skip_permissions"], False)

        # 3. Auto-commit "Changes from coding agent" is stripped when strip_auto_commit=True
        self.assertEqual(reqs[2]["path"], "/api/task-attempts/strip-auto-commit")
        self.assertTrue(ro["launch"]["effective"]["autoCommitGuard"]["stripped"])

        # Negative control: strip_auto_commit=False rejects the auto-commit with ProviderError
        with self.assertRaises(ProviderError) as ctx:
            prov.inspect_or_strip_auto_commit(
                "/tmp/vk-wt",
                head_subject="Changes from coding agent",
                strip_auto_commit=False,
            )
        self.assertEqual(ctx.exception.code, "unverified_auto_commit")


class TestPaperclipProvider(ProviderTestBase):
    """#589: PaperclipProvider (`paperclipai/paperclip`)."""

    def test_ro_permission_override_409_checkout_and_bwrap_danger(self) -> None:
        reqs: list[dict[str, object]] = []
        conflict_mode = False

        def runner(req: dict[str, object], **_kw: object) -> dict[str, object]:
            reqs.append(req)
            if conflict_mode and str(req.get("path", "")).endswith("/checkout"):
                return {"status": 409, "error": "conflict"}
            return {"agent_id": "pc-agent-1", "status": 200}

        prov = PaperclipProvider(state=self.state, runner=runner, company_id="co-1")

        # 1. PROFILE=ro explicitly sets dangerouslySkipPermissions=False & dangerouslyBypassApprovalsAndSandbox=False
        ro = prov.worker_start(task_id="iss-1", worktree="/tmp/pc", agent="claude", profile="ro")
        agent_body = reqs[0]["body"]
        assert isinstance(agent_body, dict)
        self.assertIs(agent_body["dangerouslySkipPermissions"], False)
        self.assertIs(agent_body["dangerouslyBypassApprovalsAndSandbox"], False)
        self.assertEqual(agent_body["work_mode"], "planning")
        self.assertIs(ro["launch"]["effective"]["dangerouslySkipPermissions"], False)

        # 2. PROFILE=danger configures bwrap filesystemScope="workspace" and networkScope="deny"
        danger = prov.worker_start(task_id="iss-2", worktree="/tmp/pc", agent="codex", profile="danger")
        eff = danger["launch"]["effective"]
        self.assertEqual(eff["filesystemScope"], "workspace")
        self.assertEqual(eff["networkScope"], "deny")
        self.assertEqual(eff["sandbox"]["driver"], "bwrap")

        # 3. 409 Conflict on /api/issues/{id}/checkout raises ProviderError("task_not_startable")
        conflict_mode = True
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="iss-locked", worktree="/tmp/pc", agent="claude", profile="rw")
        self.assertEqual(ctx.exception.code, "task_not_startable")


class TestMulticlaudeProvider(ProviderTestBase):
    """#589: MulticlaudeProvider (`~/.multiclaude/daemon.sock`)."""

    def test_ro_wrapper_strips_skip_permissions_and_blocks_unverified_complete(self) -> None:
        msgs: list[dict[str, object]] = []

        def runner(msg: dict[str, object], **_kw: object) -> dict[str, object]:
            msgs.append(msg)
            return {"agent_id": "mc-1", "ok": True}

        prov = MulticlaudeProvider(state=self.state, runner=runner)
        ro = prov.worker_start(task_id="t1", worktree="/tmp/mc", agent="claude", profile="ro")
        spawn_msg = msgs[-1]
        self.assertEqual(spawn_msg["action"], "spawn_agent")
        self.assertIs(spawn_msg["strip_dangerously_skip_permissions"], True)
        self.assertEqual(spawn_msg["permission_mode"], "plan")
        self.assertIn("--permission-mode plan", str(spawn_msg["wrapper_command"]))
        self.assertEqual(ro["dispatchId"], "mc-1")

        # Negative control: releasing (`complete_agent`) before verification is blocked!
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_fence(verb="release", dispatch_id="mc-1")
        self.assertEqual(ctx.exception.code, "unverified_release_blocked")

        # Once verified, `complete_agent` succeeds
        prov.mark_verified("mc-1")
        released = prov.worker_fence(verb="release", dispatch_id="mc-1", reason="merged")
        self.assertTrue(released["verified"])
        self.assertEqual(msgs[-1]["action"], "complete_agent")


if __name__ == "__main__":
    unittest.main()
