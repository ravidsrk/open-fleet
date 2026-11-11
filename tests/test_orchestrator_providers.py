#!/usr/bin/env python3
"""Unit tests and negative controls for all 12 external orchestrator RuntimeProviders (#582, #583, #584, #588, #589)."""
from __future__ import annotations

import json
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


class AFailedLaunchReleasesItsClaim(ProviderTestBase):
    """PR #707 review: get_or_record_request claims the request id inside its transaction, and an
    adapter whose worker_start then refused (an unsupported profile, a service error) left the
    claim pending, so a coordinator retrying the same id read the pending marker for ten minutes."""

    def test_a_refused_launch_leaves_no_pending_claim_and_a_retry_acts(self):
        prov = ComposioAOProvider(state=self.state, runner=lambda call: {"ok": True}, project="orca-proj")
        for attempt in range(2):
            with self.subTest(attempt=attempt):
                with self.assertRaises(ProviderError) as ctx:
                    prov.worker_start(task_id="t1", agent="pi", profile="ro", prompt="Audit",
                                      retry_request="req-refused")
                self.assertEqual(ctx.exception.code, "unsupported_profile",
                                 "the second attempt must be refused again, not answered with a pending marker")
        self.assertIsNone(self.state.request_row("req-refused"), "a refused launch keeps no claim")

    def test_a_launch_that_may_have_started_keeps_its_claim(self):
        # #707 review: the claim was released on EVERY exception, so a launch whose reply was
        # lost or malformed freed the id and the retry slung a second worker beside the first.
        # Once worker_start has reached the runtime the claim stays until it is checked or stopped.
        slings = []

        def runner(argv, **_kw):
            if argv[:3] == ["ov", "spec", "write"]:
                return {"success": True, "path": "/repo/.overstory/specs/t1.md"}
            if argv[:2] == ["ov", "sling"]:
                slings.append(argv)
                return {"success": True}  # the worker launched; the reply names no agent
            raise AssertionError(argv)

        prov = OverstoryProvider(state=self.state, runner=runner, env={})
        with self.assertRaises(ProviderError):
            prov.worker_start(task_id="t1", agent="claude", profile="rw", prompt="Build",
                              retry_request="req-lost")
        self.assertEqual(self.state.request_row("req-lost")["state"], "pending")
        again = prov.worker_start(task_id="t1", agent="claude", profile="rw", prompt="Build",
                                  retry_request="req-lost")
        self.assertEqual(again, {"state": "pending", "requestId": "req-lost"})
        self.assertEqual(len(slings), 1, "a retry must not launch a second worker")

    def test_a_cli_that_is_not_installed_releases_the_claim(self):
        # Nothing ran: the binary was never found, so no worker can exist and a retry may act.
        def runner(argv, **_kw):
            raise FileNotFoundError(argv[0])

        prov = OverstoryProvider(state=self.state, runner=runner, env={})
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t1", agent="claude", profile="rw", prompt="Build",
                              retry_request="req-nocli")
        self.assertEqual(ctx.exception.code, "overstory_cli_missing")
        self.assertIsNone(self.state.request_row("req-nocli"))


class TestSupersetProvider(ProviderTestBase):
    """#582: SupersetProvider (`superset-sh/superset`) CLI adapter (full suite: test_superset_provider.py)."""

    def test_worktree_lifecycle_and_worker_profiles(self) -> None:
        import os
        import subprocess

        calls: list[list[str]] = []
        git_env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e"}
        main, wt = self.tmp_path / "repo", self.tmp_path / "ws-1"
        subprocess.run(["git", "init", "-q", str(main)], check=True, env=git_env)
        subprocess.run(["git", "-C", str(main), "commit", "-q", "--allow-empty", "-m", "base"], check=True, env=git_env)
        subprocess.run(["git", "-C", str(main), "worktree", "add", "-q", "-b", "ws-1", str(wt)], check=True, env=git_env)

        def runner(argv: list[str], **_kw: object) -> object:
            calls.append(argv)
            if argv[0] == "git":  # worktree_rm pins HEAD / checks dirt in the real worktree first
                return subprocess.run(argv, capture_output=True, text=True, check=True, env=git_env).stdout
            if argv[:3] == ["superset", "workspaces", "get"]:
                return {"id": "ws-1", "worktreePath": str(wt), "worktreeExists": True}
            if argv[:3] == ["superset", "workspaces", "list"]:
                return [{"id": "ws-1"}]
            if argv[:3] == ["superset", "workspaces", "delete"]:
                return {"deleted": ["ws-1"], "notFound": [], "failed": []}
            if argv[:3] == ["superset", "terminals", "create"]:
                return {"terminalId": "term-1", "status": "active"}
            if argv[:3] == ["superset", "agents", "create"]:
                return {"kind": "terminal", "sessionId": "term-2", "label": "claude"}
            if argv[:3] == ["superset", "workspaces", "create"]:
                return {"id": "cloud-1", "branch": "b", "status": "provisioning"}
            if argv[:3] == ["superset", "terminals", "close"]:
                return {"terminalId": "term-1", "status": "disposed"}
            if argv[:2] == ["superset", "snapshot"]:
                return {"workspaces": []}
            raise AssertionError(argv)

        hooks: list[str] = []
        prov = SupersetProvider(state=self.state, runner=runner, env={}, install_hooks=lambda w, a, p: hooks.append(w) or {})
        self.assertEqual(prov.worktree_list()["worktrees"], [{"id": "ws-1"}])
        self.assertEqual(calls[-1], ["superset", "workspaces", "list", "--local", "--json"])
        prov.worktree_show(selector="ws-1")
        self.assertEqual(calls[-1], ["superset", "workspaces", "get", "ws-1", "--local", "--json"])
        prov.worktree_rm(selector="ws-1", force=True)
        self.assertEqual(calls[-1], ["superset", "workspaces", "delete", "ws-1", "--local", "--json"])
        self.assertIn(["git", "-C", str(wt), "update-ref", "refs/open-fleet/preserved/superset-ws-1",
                       subprocess.run(["git", "-C", str(wt), "rev-parse", "HEAD"], capture_output=True, text=True,
                                      check=True).stdout.strip()], calls)

        # PROFILE=ro MUST use `superset terminals create` (never `superset agents create`)
        ro_res = prov.worker_start(task_id="t1", worktree="ws-1", agent="claude", profile="ro", prompt="Audit")
        self.assertEqual(calls[-1][:3], ["superset", "terminals", "create"])
        self.assertFalse([c for c in calls if c[:3] == ["superset", "agents", "create"]])
        self.assertIn("--permission-mode plan", ro_res["launch"]["effective"]["shell"])
        self.assertIn("Audit", ro_res["launch"]["effective"]["shell"])
        self.assertEqual(ro_res["launch"]["effective"]["mechanism"], "terminals.create")
        self.assertEqual(hooks, [str(wt)])

        # PROFILE=rw uses `superset agents create` and hands it the prompt
        prov.worker_start(task_id="t2", worktree="ws-1", agent="claude", profile="rw", prompt="Fix it")
        self.assertEqual(
            calls[-1],
            ["superset", "agents", "create", "--local", "--json", "--workspace", "ws-1", "--agent", "claude", "--prompt", "Fix it"],
        )

        # PROFILE=danger fails closed without a recipe, else cloud `workspaces create --environment`
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t3", worktree="ws-1", agent="claude", profile="danger", prompt="x")
        self.assertEqual(ctx.exception.code, "missing_sandbox_recipe")
        prov_cloud = SupersetProvider(state=self.state, runner=runner, env={"OPEN_FLEET_SANDBOX_RECIPE": "rcp-cloud-1"})
        danger_res = prov_cloud.worker_start(task_id="t3", agent="claude", profile="danger", prompt="x")
        self.assertEqual(calls[-1][:3], ["superset", "workspaces", "create"])
        self.assertIn("rcp-cloud-1", calls[-1])
        self.assertEqual(danger_res["launch"]["effective"]["environment"], "rcp-cloud-1")

        with self.assertRaises(ProviderError) as pctx:
            prov.worker_start(task_id="t4", worktree="ws-1", agent="claude", profile="rw", parent_profile="ro", prompt="x")
        self.assertEqual(pctx.exception.code, "privilege_escalation")

        prov.worker_fence(verb="stop", dispatch_id=ro_res["dispatchId"])
        self.assertEqual(calls[-1], ["superset", "terminals", "close", "--workspace", "ws-1", "--terminal", "term-1", "--local", "--json"])


class TestGastownProvider(ProviderTestBase):
    """#583: GastownProvider (`gt` + `bd` Beads) (full suite: test_gastown_worktrunk_providers.py)."""

    def test_beads_dag_ro_alias_and_mail_bridge(self) -> None:
        calls: list[list[str]] = []
        wt = self.tmp_path / "polecat"
        wt.mkdir()

        def runner(argv: list[str], **_kw: object) -> object:
            calls.append(argv)
            if argv[:2] == ["bd", "create"]:
                return {"id": "bd-1"}
            if argv[:2] in (["bd", "update"], ["bd", "list"]):
                return []
            if argv[:2] == ["gt", "sling"]:
                return "🎯 Slinging bd-1 to rig-alpha/polecats/Toast...\n"
            if argv[:3] == ["gt", "polecat", "status"]:
                return {"clone_path": str(wt), "state": "working", "session_id": "ra-Toast"}
            if argv[:3] == ["gt", "mail", "inbox"]:
                return [{"id": "m1"}]
            return ""

        prov = GastownProvider(state=self.state, runner=runner, rig="rig-alpha", install_hooks=lambda w, a, p: {})
        created = prov.task_create(spec="fix bug", title="Fix bug")
        self.assertEqual(calls[-1], ["bd", "create", "--title=Fix bug", "--description=fix bug", "--json"])
        task_id = created["task"]["id"]
        self.assertEqual(created["task"]["beadId"], "bd-1")

        prov.task_update(task_id=task_id, status="completed")
        self.assertEqual(calls[-1], ["bd", "update", "bd-1", "--status", "closed", "--json"])
        self.assertEqual(len(prov.task_list()["tasks"]), 1)
        prov.task_update(task_id=task_id, status="ready")

        # PROFILE=ro registers `<agent>-ro` alias and slings the BEAD with `--no-merge`
        ro_res = prov.worker_start(task_id=task_id, agent="claude", profile="ro")
        alias = [c for c in calls if c[:4] == ["gt", "config", "agent", "set"]][-1]
        self.assertEqual(alias[4], "claude-ro")
        sling = [c for c in calls if c[:2] == ["gt", "sling"]][-1]
        self.assertEqual(sling, ["gt", "sling", "bd-1", "rig-alpha", "--agent", "claude-ro", "--no-merge", "--review-only"])
        self.assertEqual(ro_res["launch"]["effective"]["agentAlias"], "claude-ro")
        self.assertEqual(ro_res["worktree"], str(wt))

        prov.task_update(task_id=task_id, status="ready")
        prov.worker_start(task_id=task_id, agent="codex", profile="rw")
        sling = [c for c in calls if c[:2] == ["gt", "sling"]][-1]
        self.assertEqual(sling, ["gt", "sling", "bd-1", "rig-alpha", "--agent", "codex", "--no-merge"])

        prov.task_update(task_id=task_id, status="completed")
        self.assertEqual(calls[-1], ["bd", "update", "bd-1", "--status", "closed", "--json"])
        self.assertEqual(len(prov.task_list()["tasks"]), 1)

        # Mail send & check bridge (worker mailboxes are scoped: read the recipient's own)
        prov.send_message(subject="done", msg_type="worker_done", to="mayor", payload="ok")
        self.assertEqual(
            calls[-1],
            ["gt", "mail", "send", "mayor", "-s", "[worker_done] done", "-m", "ok", "--type", "notification"],
        )
        inbox = prov.check_messages(terminal="mayor")
        self.assertEqual(calls[-1], ["gt", "mail", "inbox", "--json", "--unread", "--address", "mayor"])
        self.assertEqual(len(inbox["messages"]), 1)
        self.assertEqual(inbox["upstreamInbox"], [{"id": "m1"}])


class TestWorktrunkProvider(ProviderTestBase):
    """#583: WorktrunkProvider (`wt`) (full suite: test_gastown_worktrunk_providers.py)."""

    def test_cow_worktree_dispatch_and_merge_prediction(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str], **_kw: object) -> object:
            calls.append(argv)
            if argv[:3] == ["wt", "switch", "--create"]:
                return {"action": "created", "branch": "feat-1", "path": "/tmp/wt/feat-1"}
            if argv[:2] == ["wt", "list"]:
                return {"items": [{"branch": "feat-1", "worktree": {"path": "/tmp/wt/feat-1"}, "default_branch": {"merge_conflicts": False}}]}
            if argv[:2] == ["wt", "merge"]:
                return {"branch": "feat-1", "target": "main", "squashed": True}
            if argv[:2] == ["wt", "remove"]:
                return [{"kind": "worktree", "branch": "feat-1"}]
            return {} if argv[0] == "wt" else ""

        prov = WorktrunkProvider(state=self.state, runner=runner, install_hooks=lambda w, a, p: {})
        res = prov.worker_start(task_id="t10", name="feat-1", agent="omp", profile="ro", prompt="Survey")
        self.assertEqual(calls[0], ["wt", "switch", "--create", "feat-1", "--no-cd", "--no-hooks", "--format=json"])
        self.assertEqual(calls[1], ["wt", "step", "copy-ignored", "--to", "/tmp/wt/feat-1", "--format=json"])
        launch = [c for c in calls if c[:2] == ["tmux", "new-session"]][0]
        self.assertEqual(launch[:7], ["tmux", "new-session", "-d", "-s", f"feat-1-{res['dispatchId']}", "-c", "/tmp/wt/feat-1"])
        self.assertIn("--approval-mode always-ask", launch[7])
        self.assertIn("Survey", launch[7])
        self.assertEqual(res["worktree"], "/tmp/wt/feat-1")

        merge_res = prov.predict_and_merge("feat-1", target="main")
        self.assertEqual(calls[-1], ["wt", "merge", "main", "--branch", "feat-1", "--no-remove", "--format=json"])
        self.assertTrue(merge_res["merged"])

        prov.worktree_rm(selector="feat-1", force=True)
        self.assertEqual(calls[-1], ["wt", "remove", "feat-1", "--reap", "--foreground", "--format=json", "--force"])


class TestOpenHandsProvider(ProviderTestBase):
    """#584: OpenHandsProvider (`openhands.agent_server` REST API) (full suite: test_openhands_provider.py)."""

    def test_ro_tool_stripping_hooks_and_danger_containers(self) -> None:
        reqs: list[dict[str, object]] = []
        runtime = {"conversation_runtime": "local"}

        def runner(req: dict[str, object], **_kw: object) -> dict[str, object]:
            reqs.append(req)
            if req["path"] == "/server_info":
                return runtime
            if str(req["path"]).startswith("/api/conversations/conv-99/events/search"):
                return {"items": [], "next_page_id": None}
            return {"id": "conv-99", "success": True}

        prov = OpenHandsProvider(state=self.state, runner=runner, env={"OPEN_FLEET_OPENHANDS_MODEL": "m"},
                                 install_hooks=lambda w, a, p: {})
        wt_dir = self.tmp_path / "oh-wt"
        wt_dir.mkdir(parents=True, exist_ok=True)

        ro_res = prov.worker_start(task_id="t1", worktree=str(wt_dir), profile="ro", prompt="Review auth")
        body = reqs[0]["body"]
        assert isinstance(body, dict)
        self.assertEqual(reqs[0]["path"], "/api/conversations")
        self.assertEqual([t["name"] for t in body["agent"]["tools"]], ["glob", "grep", "planning_file_editor"])
        self.assertIn("deny-hook.sh", body["hook_config"]["pre_tool_use"][0]["hooks"][0]["command"])
        self.assertEqual(body["initial_message"]["content"][0]["text"], "Review auth")
        self.assertEqual(ro_res["dispatchId"], "conv-99")

        # PROFILE=danger needs a docker conversation runtime on the server; apptainer is client-side only
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t2", worktree=str(wt_dir), profile="danger", prompt="x")
        self.assertEqual(ctx.exception.code, "sandbox_unavailable")
        with self.assertRaises(ProviderError) as ctx2:
            prov.worker_start(task_id="t3", worktree=str(wt_dir), profile="danger", workspace_type="host", prompt="x")
        self.assertEqual(ctx2.exception.code, "invalid_workspace_type")
        runtime["conversation_runtime"] = "docker"
        danger_res = prov.worker_start(task_id="t2", worktree=str(wt_dir), profile="danger", prompt="x")
        self.assertEqual(danger_res["launch"]["effective"]["conversation_runtime"], "docker")

        prov.worker_read(dispatch_id="conv-99", limit=10)
        self.assertTrue(str(reqs[-1]["path"]).startswith("/api/conversations/conv-99/events/search?limit=10"))
        prov.worker_fence(verb="stop", dispatch_id="conv-99", reason="timeout")
        self.assertEqual(reqs[-1]["path"], "/api/conversations/conv-99/interrupt")


class TestOverstoryProvider(ProviderTestBase):
    """#588: OverstoryProvider (`ov`) (full suite: test_orchestrator_providers_tier1.py)."""

    def test_scout_vs_builder_capability_and_mail(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str], **_kw: object) -> dict[str, object]:
            calls.append(argv)
            if argv[:3] == ["ov", "spec", "write"]:
                return {"success": True, "path": f"/r/.overstory/specs/{argv[3]}.md"}
            return {"success": True, "agentName": "ov-worker-1", "worktree": "/r/.overstory/worktrees/ov-worker-1", "messages": []}

        prov = OverstoryProvider(state=self.state, runner=runner)
        ro = prov.worker_start(task_id="t-ro", agent="claude", profile="ro", prompt="Scout it")
        self.assertEqual(calls[-2], ["ov", "spec", "write", "t-ro", "--body", "Scout it", "--json"])
        self.assertEqual(
            calls[-1],
            ["ov", "sling", "t-ro", "--capability", "scout", "--runtime", "claude", "--spec", "/r/.overstory/specs/t-ro.md",
             "--skip-task-check", "--json"],
        )
        self.assertEqual(ro["capability"], "scout")
        with self.assertRaises(ProviderError):
            prov.worker_start(task_id="t-ro", agent="claude", profile="ro", capability="builder", prompt="x")

        rw = prov.worker_start(task_id="t-rw", agent="codex", profile="rw", prompt="Build it")
        self.assertEqual(calls[-1][:6], ["ov", "sling", "t-rw", "--capability", "builder", "--runtime"])
        self.assertEqual(rw["capability"], "builder")

        prov.send_message(subject="ready", msg_type="merge_ready", to="orchestrator", payload="sha123")
        self.assertEqual(
            calls[-1],
            ["ov", "mail", "send", "--to", "orchestrator", "--subject", "ready", "--body", "sha123", "--type", "merge_ready", "--json"],
        )


class TestT3CodeProvider(ProviderTestBase):
    """#588: T3CodeProvider (T3 MCP tools via `t3 acp-mcp-call`) (full suite: test_orchestrator_providers_tier1.py)."""

    def test_session_modes_and_turn_dispatch(self) -> None:
        import os
        import subprocess

        calls: list[dict[str, object]] = []
        repo = self.tmp_path / "t3-repo"
        git_env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e"}
        subprocess.run(["git", "init", "-q", str(repo)], check=True, env=git_env)
        subprocess.run(["git", "-C", str(repo), "commit", "-q", "--allow-empty", "-m", "base"], check=True, env=git_env)

        def runner(call: dict[str, object], **_kw: object) -> dict[str, object]:
            calls.append(call)
            if call["tool"] == "t3_thread_read":
                data: dict[str, object] = {"thread": {"threadId": "t3-thr-1", "status": "running", "worktreePath": None}, "items": []}
            elif call["tool"] == "t3_project_read":
                data = {"id": "p-1", "workspaceRoot": str(repo)}
            else:
                data = {"threadId": "t3-thr-1", "status": "running"}
            return {"content": [], "structuredContent": data, "isError": False}

        prov = T3CodeProvider(state=self.state, runner=runner, install_hooks=lambda w, a, p: {},
                              env={"OPEN_FLEET_T3_PROJECT_ID": "p-1", "OPEN_FLEET_T3_WORKTREE_ROOT": str(self.tmp_path / "wts")})
        ro = prov.worker_start(task_id="t1", agent="claude", profile="ro", prompt="Audit")
        self.assertEqual(calls[0]["tool"], "t3_thread_launch")
        p0 = calls[0]["arguments"]
        assert isinstance(p0, dict)
        self.assertEqual(p0["workspaceStrategy"]["type"], "worktree")
        self.assertEqual(p0["interactionMode"], "plan")
        self.assertEqual(p0["runtimeMode"], "approval-required")
        self.assertEqual(p0["message"], "Audit")
        self.assertEqual(ro["launch"]["effective"]["interactionMode"], "plan")

        rw = prov.worker_start(task_id="t2", agent="claude", profile="rw", prompt="Fix")
        self.assertEqual(rw["launch"]["effective"]["interactionMode"], "default")
        self.assertEqual(rw["launch"]["effective"]["runtimeMode"], "full-access")
        # rw never hands T3 the create-and-start `worktree` strategy: the worktree is cut (and hooked) first.
        self.assertEqual(calls[-1]["tool"], "t3_thread_read")
        self.assertEqual(calls[-2]["arguments"]["workspaceStrategy"]["type"], "existing_worktree")
        self.assertEqual(rw["worktree"], os.path.realpath(self.tmp_path / "wts" / "t3-t2"))
        with self.assertRaises(ProviderError):
            prov.worker_start(task_id="t3", profile="danger", prompt="x")


class TestComposioAOProvider(ProviderTestBase):
    """#588: ComposioAOProvider (`ao`) — POST /api/v1/sessions + worker-HEAD preserved refs."""

    def test_rw_spawn_body_ro_fails_closed_and_worker_head_preserved(self) -> None:
        calls: list[object] = []
        wt = self.tmp_path / "ao-wt"
        wt.mkdir()
        head = "a" * 40
        common_dir = self.tmp_path / "project.git"  # a linked worktree's common dir lives outside it

        def runner(call: object, **_kw: object) -> dict[str, object]:
            calls.append(call)
            if isinstance(call, list):
                if "--git-common-dir" in call:
                    return {"raw": str(common_dir)}
                return {"raw": head} if "rev-parse" in call else {"raw": ""}
            assert isinstance(call, dict)
            if call["path"] == "/api/v1/sessions":
                return {"session": {"id": "ao-sess-1"}, "promptBytes": 9}
            if str(call["path"]).endswith("/workspace"):
                return {"sessionId": "ao-sess-1", "workspacePath": str(wt)}
            return {"ok": True}

        prov = ComposioAOProvider(state=self.state, runner=runner, project="orca-proj")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t1", agent="pi", profile="ro", prompt="Audit")
        self.assertEqual(ctx.exception.code, "unsupported_profile")

        rw = prov.worker_start(task_id="t2", agent="claude", profile="rw", prompt="Fix bug")
        body = calls[0]["body"]
        self.assertEqual(body["harness"], "claude-code")
        self.assertEqual(body["prompt"], "Fix bug")
        self.assertEqual(body["approvalMode"], "bypass-permissions")
        self.assertEqual(rw["dispatchId"], "ao-sess-1")
        self.assertEqual(rw["worktree"], str(wt.resolve()))

        fenced = prov.worker_fence(verb="release", dispatch_id="ao-sess-1")
        self.assertEqual(fenced["preservedRef"], "refs/open-fleet/preserved/ao-sess-1")
        self.assertIn(["git", "-C", str(wt.resolve()), "update-ref", "refs/open-fleet/preserved/ao-sess-1", head], calls)
        self.assertIn(["git", "-C", str(wt.resolve()), "rev-parse", "--verify", "refs/open-fleet/preserved/ao-sess-1"], calls)
        self.assertNotIn(["git", "update-ref", "refs/ao/preserved/ao-sess-1", "HEAD"], calls)
        self.assertEqual(calls[-1]["path"], "/api/v1/sessions/ao-sess-1/kill")
        self.assertEqual(fenced["state"], "released")


class TestJCodeSwarmProvider(ProviderTestBase):
    """#588: JCodeSwarmProvider (`jcode serve` daemon socket)."""

    def test_comm_spawn_ro_fails_closed_and_file_touch_ranges(self) -> None:
        calls: list[dict[str, object]] = []
        wt = self.tmp_path / "jc-wt"
        wt.mkdir()

        def runner(req: dict[str, object], **_kw: object) -> dict[str, object]:
            calls.append(req)
            if req["type"] == "comm_spawn":
                return {"type": "comm_spawn_response", "id": req["id"], "session_id": "coord", "new_session_id": "jc-1"}
            if req["type"] == "debug_command":
                touches = [
                    {"path": "src/a.py", "session_id": "w1", "op": "edited", "summary": "edited lines 10-20"},
                    {"path": "src/a.py", "session_id": "w2", "op": "edited", "summary": "edited lines 15-25"},
                ]
                return {"type": "debug_response", "id": req["id"], "ok": True, "output": json.dumps(touches)}
            return {"type": "ack", "id": req["id"]}

        prov = JCodeSwarmProvider(state=self.state, runner=runner, coordinator_session="coord")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t1", worktree=str(wt), profile="ro", prompt="look")
        self.assertEqual(ctx.exception.code, "unsupported_profile")

        rw = prov.worker_start(task_id="t2", worktree=str(wt), profile="rw", prompt="Build it")
        spawn = calls[-1]
        self.assertEqual(spawn["type"], "comm_spawn")
        self.assertEqual(spawn["initial_message"], "Build it")
        self.assertEqual(rw["agent"], "jcode")
        self.assertEqual(rw["dispatchId"], "jc-1")

        sync = prov.sync_file_touches(run_id="r1")
        self.assertEqual(sync["synced"], 2)
        self.assertTrue(sync["results"][1]["conflict"])
        self.assertEqual(sync["results"][1]["conflicts"][0]["kind"], "overlapping_hunk")
        self.assertEqual(sync["results"][1]["conflicts"][0]["lines"], [15, 25])


class TestEmdashProvider(ProviderTestBase):
    """#589: EmdashProvider (`workspace-server` wire protocol over a unix socket)."""

    def test_start_session_auto_approve_and_pty(self) -> None:
        msgs: list[dict[str, object]] = []
        wt = self.tmp_path / "em-wt"
        wt.mkdir()

        def runner(msg: dict[str, object], **_kw: object) -> dict[str, object]:
            msgs.append(msg)
            if msg.get("path") == "tuiAgents.startSession":
                value: object = {"outcome": "started"}
            elif msg.get("kind") == "snapshot":
                value = {"sequence": 3, "data": {"baseOffset": 0, "text": "ready$\n", "truncated": False}}
            else:
                value = {"success": True, "data": None}
            return {"kind": "result", "id": msg["id"], "ok": True, "value": value}

        prov = EmdashProvider(state=self.state, runner=runner)
        ro = prov.worker_start(task_id="t1", worktree=str(wt), agent="claude", profile="ro", prompt="Audit")
        params = msgs[-1]["input"]
        assert isinstance(params, dict)
        self.assertFalse(params["autoApprove"])
        self.assertIn("plan", params["extraArgs"])
        self.assertNotIn("-p", params["extraArgs"])
        self.assertEqual(params["initialPrompt"], "Audit")
        self.assertEqual(ro["dispatchId"], params["conversationId"])

        rw = prov.worker_start(task_id="t2", worktree=str(wt), agent="claude", profile="rw", prompt="Fix")
        self.assertTrue(rw["launch"]["effective"]["autoApprove"])

        snap = prov.worker_read(dispatch_id=rw["dispatchId"], source="terminal")
        self.assertEqual(msgs[-1]["kind"], "snapshot")
        self.assertIn(rw["dispatchId"], str(msgs[-1]["topic"]))
        self.assertEqual(snap["terminal"]["tail"], ["ready$"])


class TestVibeKanbanProvider(ProviderTestBase):
    """#589: VibeKanbanProvider (`BloopAI/vibe-kanban` workspaces API)."""

    def test_ro_profile_read_back_false_and_start_body(self) -> None:
        reqs: list[dict[str, object]] = []
        profiles = {"executors": {"CLAUDE_CODE": {"DEFAULT": {"CLAUDE_CODE": {"dangerously_skip_permissions": True}}}}}

        def runner(req: dict[str, object], **_kw: object) -> dict[str, object]:
            reqs.append(req)
            if req["path"] == "/api/profiles" and req["method"] == "GET":
                return {"success": True, "data": {"content": json.dumps(profiles), "path": "/x"}}
            if req["path"] == "/api/profiles" and req["method"] == "PUT":
                profiles.clear()
                profiles.update(req["body"])
                return {"success": True, "data": None}
            if req["path"] == "/api/workspaces/start":
                return {"success": True, "data": {"workspace": {"id": "ws-1", "container_ref": None},
                                                  "execution_process": {"id": "proc-1", "run_reason": "codingagent"}}}
            return {"success": True, "data": {"id": "ws-1", "container_ref": None}}

        prov = VibeKanbanProvider(state=self.state, runner=runner,
                                  env={"OPEN_FLEET_VIBE_KANBAN_REPO_ID": "repo-1", "OPEN_FLEET_VIBE_KANBAN_TARGET_BRANCH": "main"})
        ro = prov.worker_start(task_id="t1", agent="claude", profile="ro", prompt="Review")
        put = next(r for r in reqs if r["method"] == "PUT")
        variant = put["body"]["executors"]["CLAUDE_CODE"]["ORCA_RO"]["CLAUDE_CODE"]
        self.assertIs(variant["dangerously_skip_permissions"], False)
        start = next(r for r in reqs if r["path"] == "/api/workspaces/start")
        body = start["body"]
        assert isinstance(body, dict)
        self.assertEqual(body["executor_config"], {"executor": "CLAUDE_CODE", "permission_policy": "PLAN", "variant": "ORCA_RO"})
        self.assertEqual(body["prompt"], "Review")
        self.assertEqual(ro["dispatchId"], "ws-1")
        self.assertFalse(any("strip-auto-commit" in str(r["path"]) for r in reqs))


class TestPaperclipProvider(ProviderTestBase):
    """#589: PaperclipProvider (`paperclipai/paperclip`)."""

    def test_ro_adapter_config_read_back_409_and_bwrap_danger(self) -> None:
        reqs: list[dict[str, object]] = []
        agents: dict[str, dict[str, object]] = {}
        conflict = {"on": False}

        def runner(req: dict[str, object], **_kw: object) -> object:
            reqs.append(req)
            path, method = str(req["path"]), req["method"]
            if method == "POST" and path.endswith("/agents"):
                aid = f"ag-{len(agents) + 1}"
                agents[aid] = dict(req["body"])
                return {"id": aid, **agents[aid]}
            if method == "GET" and path.startswith("/api/agents/"):
                return {"id": path.rsplit("/", 1)[1], **agents[path.rsplit("/", 1)[1]]}
            if method == "POST" and path.endswith("/issues"):
                return {"id": "iss-1"}
            if path.endswith("/checkout") and conflict["on"]:
                raise ProviderError("paperclip_http_error", "409", {"status": 409, "response": {"error": "Issue checkout conflict"}})
            if method == "DELETE":
                return {"ok": True}
            return {"id": "iss-1", "status": "in_progress", "runId": "run-1"}

        prov = PaperclipProvider(state=self.state, runner=runner, company_id="co-1")
        wt = self.tmp_path / "pc"
        wt.mkdir()
        ro = prov.worker_start(task_id="t1", worktree=str(wt), agent="claude", profile="ro", prompt="Plan it")
        body = reqs[0]["body"]
        assert isinstance(body, dict)
        self.assertEqual(body["adapterType"], "claude_local")
        self.assertEqual(body["runner"], "legacy")
        self.assertIs(body["adapterConfig"]["dangerouslySkipPermissions"], False)
        # claude_local defaults to the ACP engine (approve-all, flag ignored): ro must pin the CLI lane.
        self.assertEqual(body["adapterConfig"]["engine"], "cli")
        self.assertEqual(body["adapterConfig"]["permissionMode"], "approve-reads")
        read_back = ro["launch"]["effective"]["adapterConfigReadBack"]
        self.assertIs(read_back["dangerouslySkipPermissions"], False)
        self.assertEqual((read_back["engine"], read_back["permissionMode"]), ("cli", "approve-reads"))
        issue = next(r for r in reqs if str(r["path"]).endswith("/issues"))
        self.assertEqual(issue["body"]["description"], "Plan it")

        danger = prov.worker_start(task_id="t2", worktree=str(wt), agent="codex", profile="danger", prompt="Go")
        cfg = danger["launch"]["effective"]["adapterConfig"]
        self.assertEqual((cfg["filesystemScope"], cfg["networkScope"], cfg["engine"]), ("workspace", "deny", "cli"))

        conflict["on"] = True
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="t3", worktree=str(wt), agent="claude", profile="rw", prompt="Locked")
        self.assertEqual(ctx.exception.code, "task_not_startable")
        self.assertEqual(reqs[-1]["method"], "DELETE")


class TestMulticlaudeProvider(ProviderTestBase):
    """#589: MulticlaudeProvider (`~/.multiclaude/daemon.sock`)."""

    def test_ro_settings_injected_and_release_needs_durable_verify(self) -> None:
        home = self.tmp_path / "mc-home"
        (home / "repos" / "proj").mkdir(parents=True)
        msgs: list[dict[str, object]] = []

        def runner(msg: dict[str, object], **_kw: object) -> dict[str, object]:
            msgs.append(msg)
            if msg["command"] == "spawn_agent":
                args = msg["args"]
                assert isinstance(args, dict)
                wt = home / "wts" / "proj" / str(args["name"])
                (wt / ".claude").mkdir(parents=True)
                src = home / "repos" / "proj" / ".multiclaude" / "hooks.json"
                (wt / ".claude" / "settings.json").write_text(src.read_text())
                return {"success": True, "data": {"name": args["name"], "worktree_path": str(wt)}}
            return {"success": True, "data": None}

        prov = MulticlaudeProvider(state=self.state, runner=runner, home=home, repo="proj")
        ro = prov.worker_start(task_id="t1", agent="claude", profile="ro", prompt="Review only", name="mc-1")
        spawn = next(m for m in msgs if m["command"] == "spawn_agent")
        self.assertIn("Review only", str(spawn["args"]["prompt"]))
        settings = json.loads((Path(ro["worktree"]) / ".claude" / "settings.json").read_text())
        self.assertIn("Edit", settings["permissions"]["deny"])
        self.assertFalse((home / "repos" / "proj" / ".multiclaude" / "hooks.json").exists())

        with self.assertRaises(ProviderError) as ctx:
            prov.worker_fence(verb="release", dispatch_id="mc-1", verified=True)
        self.assertEqual(ctx.exception.code, "unverified_release_blocked")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_verify(dispatch_id="mc-1", sha="a" * 40)  # a bare --sha is not evidence
        self.assertEqual(ctx.exception.code, "manifest_required")
        self.assertIsNone(prov._verification("mc-1"))
        self.assertFalse(any(m["command"] == "complete_agent" for m in msgs))


class TestExternalAdversarialRemediation750(ProviderTestBase):
    """#750 C8, C24, C29, C33, C37, C38: External orchestrator provider regressions."""

    def test_c8_preserve_worker_head_readback_mismatch_refuses_cleanup(self) -> None:
        import importlib
        ext = importlib.import_module("runtime.providers._external")
        head_sha = "a" * 40
        mismatch_sha = "b" * 40
        wt = str(self.tmp_path / "wt")

        def fake_run(argv: list[str]) -> str:
            if argv[-2:] == ["--verify", "HEAD"]:
                return head_sha + "\n"
            if "update-ref" in argv:
                return ""
            if len(argv) >= 2 and argv[-2] == "--verify" and argv[-1].startswith("refs/open-fleet/preserved/"):
                return mismatch_sha + "\n"
            return str(self.tmp_path / ".git") + "\n"

        with self.assertRaises(ProviderError) as ctx:
            ext.preserve_worker_head(fake_run, wt, "disp-c8")
        self.assertEqual(ctx.exception.code, "preserve_failed")
        self.assertIn(mismatch_sha, ctx.exception.message)

    def test_c24_and_c38_multiclaude_release_preserves_head_and_purges_private_messages(self) -> None:
        import os
        import stat
        home = self.tmp_path / "mc-home"
        (home / "repos" / "proj").mkdir(parents=True)
        wt = home / "wts" / "proj" / "mc-24"
        wt.mkdir(parents=True)
        head_sha = "1" * 40
        common_dir = self.tmp_path / "common-git"
        common_dir.mkdir()
        msgs: list[dict[str, object]] = []
        git_calls: list[list[str]] = []

        def runner(msg: dict[str, object], **_kw: object) -> dict[str, object]:
            msgs.append(msg)
            if msg["command"] == "spawn_agent":
                (wt / ".claude").mkdir(parents=True, exist_ok=True)
                src = home / "repos" / "proj" / ".multiclaude" / "hooks.json"
                if src.exists():
                    (wt / ".claude" / "settings.json").write_text(src.read_text())
                return {"success": True, "data": {"name": "mc-24", "worktree_path": str(wt)}}
            return {"success": True, "data": {"completed": True}}

        def cli_runner(argv: list[str], **_kw: object) -> dict[str, object]:
            git_calls.append(argv)
            if "--verify" in argv and argv[-1] in ("HEAD", "HEAD^{commit}"):
                return {"stdout": head_sha + "\n", "raw": head_sha + "\n", "stderr": "", "returncode": 0}
            if "--verify" in argv and argv[-1].startswith("refs/open-fleet/preserved/"):
                return {"stdout": head_sha + "\n", "raw": head_sha + "\n", "stderr": "", "returncode": 0}
            if "--git-common-dir" in argv:
                return {"stdout": str(common_dir) + "\n", "raw": str(common_dir) + "\n", "stderr": "", "returncode": 0}
            return {"stdout": "", "raw": "", "stderr": "", "returncode": 0}

        prov = MulticlaudeProvider(state=self.state, runner=runner, cli_runner=cli_runner, home=home, repo="proj")
        prov.worker_start(task_id="t-mc", agent="claude", profile="ro", prompt="Audit", name="mc-24")

        # C38: send_message creates 0700 dirs and 0600 message file even under umask(0)
        old_umask = os.umask(0)
        try:
            prov.send_message(subject="hi", msg_type="info", to="mc-24", payload="secret")
        finally:
            os.umask(old_umask)
        msg_dir = home / "messages" / "proj" / "mc-24"
        msg_files = list(msg_dir.glob("*.json"))
        self.assertGreaterEqual(len(msg_files), 1)
        self.assertEqual(stat.S_IMODE(msg_dir.stat().st_mode), 0o700)
        for mf in msg_files:
            self.assertEqual(stat.S_IMODE(mf.stat().st_mode), 0o600)

        # Record durable verification in state DB and release
        with self.state._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO multiclaude_verifications(dispatch_id, sha, worktree, verified_at) VALUES (?, ?, ?, ?)",
                ("mc-24", head_sha, str(wt), 1.0),
            )
        rel = prov.worker_fence(verb="release", dispatch_id="mc-24")
        self.assertEqual(rel["state"], "released")
        self.assertEqual(rel["preservedRef"], "refs/open-fleet/preserved/mc-24")
        self.assertEqual(rel["preserved"]["sha"], head_sha)
        self.assertTrue(any("update-ref" in c for c in git_calls))
        self.assertTrue(any(m["command"] == "complete_agent" for m in msgs))
        # C38: agent message files purged on release
        self.assertEqual(list(msg_dir.glob("*.json")), [])

    def test_c29_and_c33_external_worker_start_claims_local_task_and_binds_retry_payload(self) -> None:
        wt = self.tmp_path / "wt-ext"
        wt.mkdir()

        def wt_runner(argv: list[str], **_kw: object) -> object:
            if argv[:3] == ["wt", "switch", "--create"]:
                return {"action": "created", "branch": argv[3], "path": str(wt)}
            if argv[:2] == ["wt", "list"]:
                return {"items": [{"branch": "feat/t1", "worktree": {"path": str(wt)}}]}
            return {} if argv[0] == "wt" else ""

        prov = WorktrunkProvider(
            state=self.state,
            runner=wt_runner,
            install_hooks=lambda w, a, p: {},
        )
        t1 = self.state.task_create(spec="implement x")["task"]["id"]
        t2 = self.state.task_create(spec="dependent", deps=[t1])["task"]["id"]

        # Non-ready task is refused with task_not_startable
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id=t2, agent="claude", profile="rw", prompt="go")
        self.assertEqual(ctx.exception.code, "task_not_startable")

        # Starting ready t1 transitions it to dispatched
        res1 = prov.worker_start(
            task_id=t1, agent="claude", profile="rw", prompt="go", retry_request="req-wt-1"
        )
        st = {t["id"]: t["status"] for t in self.state.task_list()["tasks"]}
        self.assertEqual(st[t1], "dispatched")

        # Duplicate launch without matching retry_request is refused because t1 is now dispatched
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id=t1, agent="claude", profile="rw", prompt="go")
        self.assertEqual(ctx.exception.code, "task_not_startable")

        # Exact retry with same retry_request returns cached receipt
        res_retry = prov.worker_start(
            task_id=t1, agent="claude", profile="rw", prompt="go", retry_request="req-wt-1"
        )
        self.assertEqual(res1["dispatchId"], res_retry["dispatchId"])

        # C33: Reusing retry_request with different prompt raises request_mismatch
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(
                task_id=t1, agent="claude", profile="rw", prompt="different", retry_request="req-wt-1"
            )
        self.assertEqual(ctx.exception.code, "request_mismatch")

    def test_c37_external_worker_list_filters_paginates_and_scopes_upstream(self) -> None:
        wt = self.tmp_path / "wt-list"
        wt.mkdir()

        def wt_runner(argv: list[str], **_kw: object) -> object:
            if argv[:3] == ["wt", "switch", "--create"]:
                return {"action": "created", "branch": argv[3], "path": str(wt)}
            if argv[:2] == ["wt", "list"]:
                return {
                    "items": [
                        {"branch": "feat/w1", "worktree": {"path": str(wt)}},
                        {"branch": "feat/foreign", "worktree": {"path": "/tmp/foreign"}},
                    ]
                }
            return {} if argv[0] == "wt" else ""

        prov = WorktrunkProvider(
            state=self.state,
            runner=wt_runner,
            install_hooks=lambda w, a, p: {},
        )
        t1 = self.state.task_create(spec="one")["task"]["id"]
        t2 = self.state.task_create(spec="two")["task"]["id"]
        w1 = prov.worker_start(task_id=t1, agent="claude", profile="ro", prompt="one")
        w2 = prov.worker_start(task_id=t2, agent="claude", profile="ro", prompt="two")

        # Default include_remote=False emits scope + page and paginates with cursor + limit
        listed = prov.worker_list(limit=1)
        self.assertEqual(len(listed["workers"]), 1)
        self.assertEqual(listed["scope"]["source"], "worktrunk")
        self.assertIsNotNone(listed["page"]["nextCursor"])

        page2 = prov.worker_list(cursor=listed["page"]["nextCursor"], limit=1)
        self.assertEqual(len(page2["workers"]), 1)
        self.assertIsNone(page2["page"]["nextCursor"])
        self.assertEqual(
            {listed["workers"][0]["dispatchId"], page2["workers"][0]["dispatchId"]},
            {w1["dispatchId"], w2["dispatchId"]},
        )

        # GastownProvider filters raw upstream records when include_remote=False
        gt_prov = GastownProvider(
            state=self.state,
            runner=lambda argv, **_kw: [{"name": "Toast"}, {"name": "ForeignPolecat"}] if argv[:3] == ["gt", "polecat", "list"] else {},
            rig="rig-alpha",
            install_hooks=lambda w, a, p: {},
        )
        gt_list = gt_prov.worker_list(include_remote=False)
        self.assertEqual(gt_list["upstream"], [])
        gt_list_remote = gt_prov.worker_list(include_remote=True)
        self.assertEqual(len(gt_list_remote["upstream"]), 2)

    def test_c28_and_c29_t3_inject_preserves_original_dispatch_and_post_contact_failure_retains_claim(self) -> None:
        wt_t3 = self.tmp_path / "wt-t3-orig"
        wt_t3.mkdir()
        seen_t3_calls: list[dict[str, object]] = []

        def t3_runner(call: dict[str, object], **_kw: object) -> dict[str, object]:
            seen_t3_calls.append(dict(call))
            tool = call["tool"]
            args = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}
            if tool == "t3_thread_launch":
                return {"structuredContent": {"threadId": "thr-1", "runId": "r1"}, "isError": False}
            if tool == "t3_thread_list":
                return {
                    "structuredContent": {
                        "threads": [
                            {"threadId": "thr-1", "status": "running"},
                            {"threadId": "thr-foreign", "status": "running"},
                        ]
                    },
                    "isError": False,
                }
            if tool == "t3_thread_read":
                if args.get("threadId") != "thr-1":
                    return {"content": [{"type": "text", "text": "unknown thread"}], "isError": True}
                if args.get("view") == "messages":
                    return {
                        "structuredContent": {
                            "items": [{"itemId": "m1", "createdBy": "assistant", "text": "injected reply"}],
                            "nextPosition": 2,
                        },
                        "isError": False,
                    }
                return {"structuredContent": {"thread": {"worktreePath": str(wt_t3), "status": "idle"}}, "isError": False}
            if tool == "t3_thread_send":
                return {"structuredContent": {"delivery": "queued"}, "isError": False}
            if tool == "t3_thread_interrupt":
                if args.get("threadId") != "thr-1":
                    return {"content": [{"type": "text", "text": "unknown thread"}], "isError": True}
                return {"structuredContent": {"interrupted": True}, "isError": False}
            return {"structuredContent": {}, "isError": False}

        t3 = T3CodeProvider(
            state=self.state,
            runner=t3_runner,
            env={"OPEN_FLEET_T3_PROJECT_ID": "proj-1"},
            hooks=lambda w, a, p: {},
        )
        t_orig = self.state.task_create(spec="first", run="run-t3")["task"]["id"]
        t_inj = self.state.task_create(spec="followup", run="run-t3")["task"]["id"]
        t3.worker_start(task_id=t_orig, worktree=str(wt_t3), agent="codex", profile="rw", run="run-t3")
        inj_res = t3.dispatch_inject(task_id=t_inj, to_handle="t3:thr-1", run="run-t3")
        with self.state._connect() as conn:
            rows = conn.execute(
                "SELECT dispatch_id, task_id, worktree, agent, profile FROM dispatches WHERE backend = 't3code' ORDER BY created_at ASC"
            ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["dispatch_id"], "thr-1")
        self.assertEqual(rows[0]["task_id"], t_orig)
        self.assertEqual(rows[0]["agent"], "codex")
        self.assertEqual(rows[0]["profile"], "rw")
        inj_did = str(rows[1]["dispatch_id"])
        self.assertTrue(inj_did.startswith("thr-1:inject:"))
        self.assertEqual(inj_res["dispatchId"], inj_did)
        self.assertEqual(rows[1]["task_id"], t_inj)
        self.assertEqual(rows[1]["worktree"], str(wt_t3))
        self.assertEqual(rows[1]["agent"], "codex")
        self.assertEqual(rows[1]["profile"], "rw")

        # Injected T3 dispatch IDs resolve upstream threadId (`thr-1`) across list, show, read, and fence:
        listed = t3.worker_list(run="run-t3")
        self.assertEqual([w["dispatchId"] for w in listed["workers"]], ["thr-1", inj_did])
        self.assertEqual([w["stage"] for w in listed["workers"]], ["running", "running"])
        listed_inj = t3.worker_list(run="run-t3", task=t_inj)
        self.assertEqual([w["dispatchId"] for w in listed_inj["workers"]], [inj_did])
        self.assertEqual([t["threadId"] for t in listed_inj["upstream"]["threads"]], ["thr-1"])

        shown = t3.worker_show(dispatch_id=inj_did)
        self.assertEqual(shown["worker"]["dispatchId"], inj_did)
        self.assertEqual(shown["worker"]["taskId"], t_inj)
        self.assertEqual(shown["worker"]["stage"], "idle")

        read_out = t3.worker_read(dispatch_id=inj_did)
        self.assertEqual(read_out["transcript"]["messages"][0]["blocks"][0]["text"], "injected reply")

        stopped = t3.worker_fence(verb="stop", dispatch_id=inj_did, reason="cancel-inject")
        self.assertEqual(stopped["dispatchId"], inj_did)
        self.assertEqual(stopped["state"], "stopped")
        interrupt_calls = [c for c in seen_t3_calls if c.get("tool") == "t3_thread_interrupt"]
        self.assertEqual(interrupt_calls[-1]["arguments"], {"threadId": "thr-1", "reason": "cancel-inject"})

        # C29: Post-runtime-contact ambiguous failure must NOT release claimed task back to ready
        t_ambig = self.state.task_create(spec="ambig", run="run-t3")["task"]["id"]

        def ambig_runner(call: dict[str, object], **_kw: object) -> dict[str, object]:
            if call["tool"] == "t3_thread_launch":
                return {"structuredContent": {}, "isError": False}  # missing threadId after contact
            return {"structuredContent": {}, "isError": False}

        t3_ambig = T3CodeProvider(
            state=self.state,
            runner=ambig_runner,
            env={"OPEN_FLEET_T3_PROJECT_ID": "proj-1"},
            hooks=lambda w, a, p: {},
        )
        with self.assertRaises(ProviderError):
            t3_ambig.worker_start(task_id=t_ambig, worktree=str(wt_t3), agent="claude", profile="rw", run="run-t3")
        st = {t["id"]: t["status"] for t in self.state.task_list(run="run-t3")["tasks"]}
        self.assertEqual(st[t_ambig], "dispatched")

        # C29: Ambiguous t3_thread_send failure in dispatch_inject AFTER upstream contact also retains claim
        t_inj_ambig = self.state.task_create(spec="inj-ambig", run="run-t3")["task"]["id"]

        def ambig_inject_runner(call: dict[str, object], **_kw: object) -> object:
            if call["tool"] == "t3_thread_send":
                return "not-json-after-delivery"
            return {"structuredContent": {}, "isError": False}

        t3_inj_ambig = T3CodeProvider(
            state=self.state,
            runner=ambig_inject_runner,
            env={"OPEN_FLEET_T3_PROJECT_ID": "proj-1"},
            hooks=lambda w, a, p: {},
        )
        with self.assertRaises(ProviderError) as ctx_inj_ambig:
            t3_inj_ambig.dispatch_inject(task_id=t_inj_ambig, to_handle="t3:thr-1", run="run-t3")
        self.assertEqual(ctx_inj_ambig.exception.code, "t3code_bad_json")
        st_inj = {t["id"]: t["status"] for t in self.state.task_list(run="run-t3")["tasks"]}
        self.assertEqual(st_inj[t_inj_ambig], "dispatched")
        with self.assertRaises(ProviderError) as ctx_dup:
            t3.dispatch_inject(task_id=t_inj_ambig, to_handle="t3:thr-1", run="run-t3")
        self.assertEqual(ctx_dup.exception.code, "task_not_startable")

        # Pre-contact failure in dispatch_inject (missing endpoint/auth before t3 runs) releases claim to ready
        t_inj_pre = self.state.task_create(spec="inj-pre", run="run-t3")["task"]["id"]
        t3_unconf = T3CodeProvider(
            state=self.state,
            env={"OPEN_FLEET_T3_PROJECT_ID": "proj-1"},
            hooks=lambda w, a, p: {},
        )
        with self.assertRaises(ProviderError) as ctx_pre:
            t3_unconf.dispatch_inject(task_id=t_inj_pre, to_handle="t3:thr-1", run="run-t3")
        self.assertEqual(ctx_pre.exception.code, "t3code_not_configured")
        self.assertEqual(
            {t["id"]: t["status"] for t in self.state.task_list(run="run-t3")["tasks"]}[t_inj_pre],
            "ready",
        )

        # C28/C29: Launched worker bound to run-t3 cannot claim, launch, or inject tasks in run-other
        # either implicitly (omitting run) or explicitly (passing run='run-other')
        t_foreign = self.state.task_create(spec="foreign-secret", run="run-other")["task"]["id"]
        t_own_ready = self.state.task_create(spec="own-ready", run="run-t3")["task"]["id"]
        bound_state = LocalStateStore(
            self.state.db_path,
            env={"OPEN_FLEET_DISPATCH_ID": "thr-1", "OPEN_FLEET_TERMINAL_HANDLE": "t3:thr-1"},
        )
        wt_calls: list[list[str]] = []

        def guard_wt_runner(argv: list[str], **_kw: object) -> object:
            wt_calls.append(list(argv))
            return {}

        bound_wt = WorktrunkProvider(
            state=bound_state,
            runner=guard_wt_runner,
            install_hooks=lambda w, a, p: {},
        )
        t3_calls: list[dict[str, object]] = []

        def guard_t3_runner(call: dict[str, object], **_kw: object) -> dict[str, object]:
            t3_calls.append(dict(call))
            return {"structuredContent": {}, "isError": False}

        bound_t3 = T3CodeProvider(
            state=bound_state,
            runner=guard_t3_runner,
            env={"OPEN_FLEET_T3_PROJECT_ID": "proj-1", "OPEN_FLEET_DISPATCH_ID": "thr-1"},
            hooks=lambda w, a, p: {},
        )
        # Start a foreign T3 worker on run-other as coordinator so we can verify observation/fencing isolation:
        t_foreign_disp = self.state.task_create(spec="foreign-disp", run="run-other")["task"]["id"]

        def foreign_t3_runner(call: dict[str, object], **_kw: object) -> dict[str, object]:
            if call["tool"] == "t3_thread_launch":
                return {"structuredContent": {"threadId": "thr-other", "runId": "r2"}, "isError": False}
            if call["tool"] == "t3_thread_read":
                return {"structuredContent": {"thread": {"worktreePath": str(wt_t3), "status": "running"}}, "isError": False}
            return {"structuredContent": {}, "isError": False}

        T3CodeProvider(
            state=self.state,
            runner=foreign_t3_runner,
            env={"OPEN_FLEET_T3_PROJECT_ID": "proj-1"},
            hooks=lambda w, a, p: {},
        ).worker_start(task_id=t_foreign_disp, worktree=str(wt_t3), agent="codex", profile="rw", run="run-other")

        for bad_call in (
            lambda: bound_wt.worker_start(task_id=t_foreign, agent="claude", profile="rw", prompt="go"),
            lambda: bound_wt.worker_start(task_id=t_own_ready, agent="claude", profile="rw", prompt="go", run="run-other"),
            lambda: bound_wt.worker_start(task_id=t_foreign, agent="claude", profile="rw"),
            lambda: bound_t3.dispatch_inject(task_id=t_foreign, to_handle="t3:thr-1", prompt="go"),
            lambda: bound_t3.dispatch_inject(task_id=t_own_ready, to_handle="t3:thr-1", prompt="go", run="run-other"),
            lambda: bound_t3.worker_list(run="run-other"),
            lambda: bound_t3.worker_list(include_remote=True),
            lambda: bound_t3.worker_show(dispatch_id="thr-other"),
            lambda: bound_t3.worker_read(dispatch_id="thr-other"),
            lambda: bound_t3.worker_fence(verb="stop", dispatch_id="thr-other", reason="cross-run"),
            lambda: bound_wt.worker_list(run="run-other"),
        ):
            with self.assertRaises(ProviderError) as ctx_bound:
                bad_call()
            self.assertEqual(ctx_bound.exception.code, "cross_run_access")
        self.assertEqual(wt_calls, [])
        self.assertEqual(t3_calls, [])
        # Implicit `worker_list()` from a bound worker scopes strictly to its bound run (`run-t3`), omitting `thr-other`:
        bound_list_t3 = T3CodeProvider(
            state=bound_state,
            runner=lambda call, **_kw: {
                "structuredContent": {
                    "threads": [
                        {"threadId": "thr-1", "status": "running"},
                        {"threadId": "thr-other", "status": "running"},
                    ]
                },
                "isError": False,
            },
            env={"OPEN_FLEET_T3_PROJECT_ID": "proj-1", "OPEN_FLEET_DISPATCH_ID": "thr-1"},
            hooks=lambda w, a, p: {},
        ).worker_list()
        self.assertNotIn("thr-other", [w["dispatchId"] for w in bound_list_t3["workers"]])
        self.assertEqual([t["threadId"] for t in bound_list_t3["upstream"]["threads"]], ["thr-1"])
        self.assertEqual(
            {t["id"]: t["status"] for t in self.state.task_list(run="run-other")["tasks"]}[t_foreign],
            "ready",
        )


if __name__ == "__main__":
    unittest.main()
