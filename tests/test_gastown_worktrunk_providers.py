#!/usr/bin/env python3
"""#583 acceptance: GastownProvider (`gt` + `bd`) and WorktrunkProvider (`wt` + tmux).

Covers: the task spec reaches the upstream worker through the shared command route, bead ids
are recorded and slung (deps via `bd dep add`), ro alias enforcement, receipts synthesized from
`gt polecat status --json`, blocking `check --wait` translation, unparseable output -> ok:false,
non-destructive `retain`, unknown dispatches, worker_ops read/show shapes, HEAD preservation
before `gt polecat nuke` / `wt remove --reap`, and detached tmux launch for Worktrunk.
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

base = importlib.import_module("runtime.providers.base")
local_state = importlib.import_module("runtime.providers.local_state")
gastown = importlib.import_module("runtime.providers.gastown")
worktrunk = importlib.import_module("runtime.providers.worktrunk")
ProviderError = base.ProviderError


def _load_worker_ops():
    spec = importlib.util.spec_from_file_location("worker_ops_t583", ROOT / "runtime" / "scripts" / "worker_ops.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


WORKER_OPS = _load_worker_ops()
SPEC = "Fix the flaky retry in payments/api.py; keep the public signature."
GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.com",
}


class Scripted:
    """Injected CLI runner: first rule whose prefix matches argv answers; `git` may run for real."""

    def __init__(self, rules: list[tuple[tuple[str, ...], Any]] | None = None, *, real_git: bool = False) -> None:
        self.rules = list(rules or [])
        self.calls: list[list[str]] = []
        self.real_git = real_git

    def add(self, prefix: tuple[str, ...], response: Any) -> None:
        self.rules.insert(0, (prefix, response))

    def __call__(self, argv: list[str], **_kw: Any) -> Any:
        self.calls.append(list(argv))
        for prefix, response in self.rules:
            if tuple(argv[: len(prefix)]) == prefix:
                if isinstance(response, BaseException):
                    raise response
                return response(argv) if callable(response) else response
        if self.real_git and argv[0] == "git":
            proc = subprocess.run(argv, capture_output=True, text=True, env=GIT_ENV, check=False)
            if proc.returncode != 0:
                raise ProviderError("git_error", proc.stderr.strip(), {"argv": argv, "returncode": proc.returncode})
            return proc.stdout
        raise AssertionError(f"unexpected upstream call: {argv}")

    def called(self, *prefix: str) -> list[list[str]]:
        return [c for c in self.calls if tuple(c[: len(prefix)]) == prefix]


def make_linked_worktree(tmp: Path, branch: str = "feat") -> tuple[Path, Path]:
    main = tmp / "repo"
    wt = tmp / "wt"
    subprocess.run(["git", "init", "-q", str(main)], check=True, env=GIT_ENV)
    (main / "README.md").write_text("x\n")
    subprocess.run(["git", "-C", str(main), "add", "."], check=True, env=GIT_ENV)
    subprocess.run(["git", "-C", str(main), "commit", "-qm", "init"], check=True, env=GIT_ENV)
    subprocess.run(["git", "-C", str(main), "worktree", "add", "-q", str(wt), "-b", branch], check=True, env=GIT_ENV)
    (wt / "fix.py").write_text("print('fixed')\n")
    subprocess.run(["git", "-C", str(wt), "add", "fix.py"], check=True, env=GIT_ENV)
    subprocess.run(["git", "-C", str(wt), "commit", "-qm", "worker fix"], check=True, env=GIT_ENV)
    return main, wt


def git_out(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True, env=GIT_ENV).stdout.strip()


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.state = local_state.LocalStateStore(db_path=self.tmp / "state.db")
        self.hook_calls: list[tuple[str, str, str]] = []

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def fake_hooks(self, wt: str, agent: str, profile: str) -> dict[str, str]:
        self.hook_calls.append((wt, agent, profile))
        return {"deny_hook": "fake"}


# --------------------------------------------------------------------------------------
# Gastown
# --------------------------------------------------------------------------------------
SLING_OUT = (
    "\x1b[1m🎯\x1b[0m Slinging gt-abc to rig-alpha/polecats/Toast...\n"
    "Created polecat: Toast\n✓ Work attached to hook (status=hooked)\n▶ Start prompt sent\n"
)


class TestGastownProvider(_Base):
    def make(self, runner: Scripted) -> Any:
        return gastown.GastownProvider(state=self.state, runner=runner, rig="rig-alpha", env={}, install_hooks=self.fake_hooks)

    def scripted(self, clone_path: str) -> Scripted:
        return Scripted(
            [
                (("bd", "create"), {"id": "gt-abc", "schema_version": 1}),
                (("bd", "dep", "add"), "✓ Added dependency\n"),
                (("bd", "update"), [{"id": "gt-abc", "status": "closed"}]),
                (("gt", "config", "agent", "set"), "Agent 'claude-ro' set\n"),
                (("gt", "sling"), SLING_OUT),
                (("gt", "polecat", "status"), {"rig": "rig-alpha", "name": "Toast", "state": "working", "issue": "gt-abc",
                                               "clone_path": clone_path, "session_id": "ra-Toast"}),
                (("gt", "peek"), "line one\nline two\n"),
                (("gt", "session", "stop"), "stopped\n"),
                (("gt", "polecat", "nuke"), "✓ nuked\n"),
            ],
            real_git=True,
        )

    def test_spec_reaches_bead_and_bead_is_slung(self) -> None:
        wt = self.tmp / "polecat-wt"
        wt.mkdir()
        runner = self.scripted(str(wt))
        prov = self.make(runner)
        created = prov.dispatch(["orchestration", "task-create", "--spec", SPEC, "--task-title", "Fix retry", "--json"])
        task_id = created["task"]["id"]
        self.assertEqual(created["task"]["beadId"], "gt-abc")
        self.assertEqual(runner.called("bd", "create")[0], ["bd", "create", "--title=Fix retry", f"--description={SPEC}", "--json"])

        res = prov.dispatch(["orchestration", "worker-start", "--task", task_id, "--profile", "rw", "--agent", "claude"], env={})
        self.assertEqual(runner.called("gt", "sling")[0], ["gt", "sling", "gt-abc", "rig-alpha", "--agent", "claude", "--no-merge"])
        self.assertEqual(res["dispatchId"], "rig-alpha/Toast@gt-abc")
        self.assertEqual(res["worktree"], str(wt))  # real clone_path, never "new-child"
        self.assertEqual(self.hook_calls, [(str(wt), "claude", "rw")])
        self.assertEqual(runner.called("gt", "polecat", "status")[0], ["gt", "polecat", "status", "rig-alpha/Toast", "--json"])
        self.assertFalse(runner.called("bd", "update"), "spec already in bead: no rewrite")

    def test_deps_use_bd_dep_add_and_status_maps_to_beads(self) -> None:
        runner = self.scripted("/nonexistent")
        prov = self.make(runner)
        dep = prov.task_create(spec="first", title="A")
        runner.add(("bd", "create"), {"id": "gt-def"})
        child = prov.task_create(spec="second", title="B", deps=[dep["task"]["id"]])
        self.assertEqual(runner.called("bd", "dep", "add")[-1], ["bd", "dep", "add", "gt-def", "gt-abc"])
        self.assertEqual(child["task"]["beadId"], "gt-def")
        prov.task_update(task_id=dep["task"]["id"], status="completed")
        self.assertEqual(runner.called("bd", "update")[-1], ["bd", "update", "gt-abc", "--status", "closed", "--json"])
        # Negative control: a dep with no bead never reaches bd.
        with self.assertRaises(ProviderError) as ctx:
            prov.task_create(spec="x", deps=["task_missing"])
        self.assertEqual(ctx.exception.code, "task_not_found")

    def test_explicit_prompt_rewrites_bead_description(self) -> None:
        wt = self.tmp / "w"
        wt.mkdir()
        runner = self.scripted(str(wt))
        prov = self.make(runner)
        tid = prov.task_create(spec=SPEC, title="T")["task"]["id"]
        prov.worker_start(task_id=tid, prompt="OVERRIDE", profile="rw")
        self.assertEqual(runner.called("bd", "update")[0], ["bd", "update", "gt-abc", "--description=OVERRIDE", "--json"])

    def test_ro_registers_cli_enforced_alias(self) -> None:
        wt = self.tmp / "w"
        wt.mkdir()
        runner = self.scripted(str(wt))
        prov = self.make(runner)
        tid = prov.task_create(spec=SPEC)["task"]["id"]
        res = prov.worker_start(task_id=tid, agent="claude", profile="ro")
        alias = runner.called("gt", "config", "agent", "set")[0]
        self.assertEqual(alias[4], "claude-ro")
        self.assertIn("--permission-mode plan", alias[5])
        self.assertNotIn("dangerously", alias[5])
        self.assertEqual(
            runner.called("gt", "sling")[0],
            ["gt", "sling", "gt-abc", "rig-alpha", "--agent", "claude-ro", "--no-merge", "--review-only"],
        )
        self.assertEqual(res["launch"]["effective"]["agentAlias"], "claude-ro")
        # Negative control: an agent whose ro line needs env/quoting cannot become a gt alias.
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id=tid, agent="opencode", profile="ro")
        self.assertEqual(ctx.exception.code, "unsupported_profile")

    def test_ro_alias_is_path_free_or_refused(self) -> None:
        wt = self.tmp / "w"
        wt.mkdir()
        runner = self.scripted(str(wt))
        prov = self.make(runner)
        tid = prov.task_create(spec=SPEC)["task"]["id"]
        prov.worker_start(task_id=tid, agent="codex", profile="ro", worktree=str(wt))
        alias = runner.called("gt", "config", "agent", "set")[-1]
        self.assertEqual(alias[4], "codex-ro")
        self.assertIn("--sandbox read-only", alias[5])
        for token in alias[5].split():
            self.assertNotIn("/", token)
            self.assertNotIn(token.split("=", 1)[0], ("--cwd", "--data-dir", "-C", "--in", "--dir"))
        self.assertNotIn(str(wt), alias[5])
        self.assertNotIn(os.getcwd(), alias[5])
        # Negative controls: a town-wide alias that names a directory would run in the wrong tree
        # (crush --cwd/--data-dir; hermes --in; opencode --dir), so those ro aliases are refused.
        for agent in ("crush", "opencode", "hermes"):
            for wt_arg in (str(wt), "new-child"):
                before = len(runner.called("gt", "config", "agent", "set"))
                with self.assertRaises(ProviderError) as ctx:
                    prov.worker_start(task_id=tid, agent=agent, profile="ro", worktree=wt_arg)
                self.assertEqual(ctx.exception.code, "unsupported_profile", agent)
                self.assertEqual(len(runner.called("gt", "config", "agent", "set")), before, agent)
        self.assertEqual(len(runner.called("gt", "sling")), 1)

    def test_reused_polecat_name_is_superseded_not_acted_on(self) -> None:
        main, wt = make_linked_worktree(self.tmp)
        runner = self.scripted(str(wt))
        prov = self.make(runner)
        tid = prov.task_create(spec=SPEC)["task"]["id"]
        did = prov.worker_start(task_id=tid, profile="rw")["dispatchId"]
        self.assertIn("STAGE=working", WORKER_OPS.format_show(prov.worker_show(dispatch_id=did)))
        # Toast finished and was handed another bead: the name now belongs to someone else.
        for issue in ("gt-other", None):
            status = {"rig": "rig-alpha", "name": "Toast", "state": "working", "clone_path": str(wt), "session_id": "ra-Toast"}
            if issue:
                status["issue"] = issue
            runner.add(("gt", "polecat", "status"), status)
            for call in (
                lambda: prov.worker_show(dispatch_id=did),
                lambda: prov.worker_read(dispatch_id=did),
                lambda: prov.worker_fence(verb="stop", dispatch_id=did),
                lambda: prov.worker_fence(verb="release", dispatch_id=did),
                lambda: prov.worker_fence(verb="abandon", dispatch_id=did),
            ):
                with self.assertRaises(ProviderError) as ctx:
                    call()
                self.assertEqual(ctx.exception.code, "dispatch_superseded")
        self.assertFalse(runner.called("gt", "peek"))
        self.assertFalse(runner.called("gt", "session", "stop"))
        self.assertFalse(runner.called("gt", "polecat", "nuke"))
        self.assertFalse(runner.called("git", "-C", str(wt), "update-ref"))
        with self.state._connect() as conn:
            self.assertEqual(conn.execute("SELECT terminal_state FROM dispatches").fetchone()["terminal_state"], "active")

    def test_worker_list_is_our_dispatches_not_raw_polecats(self) -> None:
        wt = self.tmp / "w"
        wt.mkdir()
        runner = self.scripted(str(wt))
        runner.add(("gt", "polecat", "list"), [
            {"rig": "rig-alpha", "name": "Toast", "state": "working", "issue": "gt-abc"},
            {"rig": "rig-alpha", "name": "Nux", "state": "working", "issue": "gt-foreign"},
        ])
        prov = self.make(runner)
        tid = prov.task_create(spec=SPEC)["task"]["id"]
        did = prov.worker_start(task_id=tid, profile="rw")["dispatchId"]
        listed = prov.worker_list()
        self.assertEqual(runner.called("gt", "polecat", "list")[0], ["gt", "polecat", "list", "--json", "rig-alpha"])
        self.assertEqual(WORKER_OPS.format_list(listed), ["ROWS=1", "SCOPE=gastown", "NEXT_CURSOR=none", f"{did} {tid} active"])
        self.assertEqual(listed["workers"][0]["stage"], "working")
        runner.add(("gt", "polecat", "list"), [{"rig": "rig-alpha", "name": "Toast", "state": "working", "issue": "gt-next"}])
        self.assertEqual(prov.worker_list()["workers"][0]["stage"], "superseded-or-gone")
        runner.add(("gt", "polecat", "list"), {"error": "no rig"})
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_list()
        self.assertEqual(ctx.exception.code, "gastown_bad_json")

    def test_ro_without_resolvable_worktree_fails_closed(self) -> None:
        runner = self.scripted("")
        prov = self.make(runner)
        tid = prov.task_create(spec=SPEC)["task"]["id"]
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id=tid, profile="ro")
        self.assertEqual(ctx.exception.code, "worktree_unresolved")
        self.assertEqual(runner.called("gt", "session", "stop")[0], ["gt", "session", "stop", "rig-alpha/Toast"])

    def test_danger_and_missing_rig_refused(self) -> None:
        prov = self.make(self.scripted("/x"))
        tid = prov.task_create(spec=SPEC)["task"]["id"]
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id=tid, profile="danger")
        self.assertEqual(ctx.exception.code, "unsupported_profile")
        no_rig = gastown.GastownProvider(state=self.state, runner=self.scripted("/x"), env={})
        with self.assertRaises(ProviderError) as ctx2:
            no_rig.worker_start(task_id=tid, profile="rw")
        self.assertEqual(ctx2.exception.code, "missing_rig")

    def test_unparseable_upstream_is_an_error(self) -> None:
        runner = self.scripted("/x")
        runner.add(("bd", "create"), "Created issue gt-abc (not json)")
        prov = self.make(runner)
        with self.assertRaises(ProviderError) as ctx:
            prov.dispatch(["orchestration", "task-create", "--spec", SPEC])
        self.assertFalse(ctx.exception.to_envelope()["ok"])
        self.assertEqual(ctx.exception.code, "gastown_bad_json")
        self.assertEqual(self.state.task_list()["tasks"][0]["status"], "failed")

        runner2 = self.scripted("/x")
        runner2.add(("gt", "sling"), "✓ done\n")  # names no polecat
        prov2 = self.make(runner2)
        tid = prov2.task_create(spec=SPEC)["task"]["id"]
        with self.assertRaises(ProviderError) as ctx2:
            prov2.worker_start(task_id=tid, profile="rw")
        self.assertEqual(ctx2.exception.code, "upstream_no_id")

        runner3 = self.scripted("/x")
        runner3.add(("bd", "create"), FileNotFoundError("bd"))
        with self.assertRaises(ProviderError) as ctx3:
            self.make(runner3).task_create(spec=SPEC)
        self.assertEqual(ctx3.exception.code, "gastown_cli_missing")

    def test_read_show_shapes_retain_and_unknown_dispatch(self) -> None:
        wt = self.tmp / "w"
        wt.mkdir()
        runner = self.scripted(str(wt))
        prov = self.make(runner)
        tid = prov.task_create(spec=SPEC)["task"]["id"]
        did = prov.worker_start(task_id=tid, profile="rw")["dispatchId"]

        shown = prov.dispatch(["orchestration", "worker-show", "--dispatch", did])
        lines = WORKER_OPS.format_show(shown)
        self.assertIn(f"DISPATCH={did}", lines)
        self.assertIn("STAGE=working", lines)
        read = prov.dispatch(["orchestration", "worker-read", "--dispatch", did, "--terminal", "--limit", "20"])
        self.assertIn("line two", WORKER_OPS.format_read(read))
        self.assertEqual(runner.called("gt", "peek")[0], ["gt", "peek", "rig-alpha/Toast", "-n", "20"])
        with self.assertRaises(WORKER_OPS.Failed):
            WORKER_OPS.format_read(prov.worker_read(dispatch_id=did, source="transcript"), want="transcript")

        before = len(runner.calls)
        fenced = prov.dispatch(["orchestration", "worker-retain", "--dispatch", did])
        self.assertEqual(len(runner.calls), before, "retain must make no upstream call")
        self.assertEqual(fenced["state"], "retained")

        for argv in (
            ["orchestration", "worker-show", "--dispatch", "nope"],
            ["orchestration", "worker-read", "--dispatch", "nope"],
            ["orchestration", "worker-stop", "--dispatch", "nope"],
        ):
            with self.assertRaises(ProviderError) as ctx:
                prov.dispatch(argv)
            self.assertEqual(ctx.exception.code, "dispatch_not_found")
        with self.assertRaises(ProviderError) as vctx:
            prov.worker_fence(verb="nuke", dispatch_id=did)
        self.assertEqual(vctx.exception.code, "invalid_verb")

    def test_stop_is_non_destructive_and_release_preserves_real_head(self) -> None:
        main, wt = make_linked_worktree(self.tmp)
        runner = self.scripted(str(wt))
        prov = self.make(runner)
        tid = prov.task_create(spec=SPEC)["task"]["id"]
        did = prov.worker_start(task_id=tid, profile="rw")["dispatchId"]

        stopped = prov.worker_fence(verb="stop", dispatch_id=did)
        self.assertEqual(stopped["state"], "stopped")
        self.assertTrue(runner.called("gt", "session", "stop"))
        self.assertFalse(runner.called("gt", "polecat", "nuke"))

        # Negative control: foreign uncommitted work blocks the release and nothing is nuked.
        (wt / "unsaved.py").write_text("wip\n")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_fence(verb="release", dispatch_id=did)
        self.assertEqual(ctx.exception.code, "uncommitted_work")
        self.assertFalse(runner.called("gt", "polecat", "nuke"))
        (wt / "unsaved.py").unlink()

        # Hook artifacts alone are ours: release pins HEAD in the shared repo, then nukes.
        (wt / ".open-fleet").mkdir()
        (wt / ".open-fleet" / "x").write_text("hook\n")
        released = prov.worker_fence(verb="release", dispatch_id=did)
        worker_head = git_out("-C", str(wt), "rev-parse", "HEAD")
        self.assertEqual(released["preserved"]["sha"], worker_head)
        ref = released["preserved"]["ref"]
        self.assertTrue(ref.startswith("refs/open-fleet/preserved/rig-alpha/Toast"))
        self.assertEqual(git_out("-C", str(main), "rev-parse", ref), worker_head)
        self.assertNotEqual(git_out("-C", str(main), "rev-parse", "HEAD"), worker_head)
        self.assertEqual(runner.called("gt", "polecat", "nuke")[0], ["gt", "polecat", "nuke", "rig-alpha/Toast", "--force"])
        self.assertEqual(released["state"], "released")

    def test_release_refuses_when_head_cannot_be_preserved(self) -> None:
        runner = self.scripted("/definitely/not/a/worktree")
        runner.add(("git",), ProviderError("git_error", "not a git repository"))
        prov = self.make(runner)
        tid = prov.task_create(spec=SPEC)["task"]["id"]
        did = prov.worker_start(task_id=tid, profile="rw")["dispatchId"]
        with self.assertRaises(ProviderError):
            prov.worker_fence(verb="abandon", dispatch_id=did)
        self.assertFalse(runner.called("gt", "polecat", "nuke"))

    def test_mail_bridge_and_blocking_wait(self) -> None:
        runner = self.scripted("/x")
        runner.add(("gt", "mail", "send"), "✓ Message sent to mayor\n")
        runner.add(("gt", "mail", "inbox"), [{"id": "hq-1", "subject": "hi"}])
        runner.add(("gt", "mol", "step", "await-signal"), {"reason": "signal", "elapsed": 1000})
        runner.add(("gt", "mail", "reply"), "✓ Reply sent\n")
        prov = self.make(runner)
        prov.send_message(subject="done", msg_type="worker_done", to="mayor", payload="ok")
        self.assertEqual(
            runner.called("gt", "mail", "send")[0],
            ["gt", "mail", "send", "mayor", "-s", "[worker_done] done", "-m", "ok", "--type", "notification"],
        )
        inbox = prov.check_messages(terminal="mayor")
        self.assertEqual(len(inbox["messages"]), 1)
        self.assertEqual(inbox["upstreamInbox"], [{"id": "hq-1", "subject": "hi"}])
        self.assertFalse(runner.called("gt", "mol"))

        waited = prov.check_messages(terminal="mayor", wait=True, timeout_ms=5000)
        self.assertEqual(runner.called("gt", "mol", "step", "await-signal")[0][-2:], ["--timeout", "5s"])
        self.assertEqual(waited["upstreamSignal"]["reason"], "signal")

        replied = prov.reply_message(msg_id="hq-1", body="ack")
        self.assertEqual(replied["scope"], "upstream")
        self.assertEqual(runner.called("gt", "mail", "reply")[0], ["gt", "mail", "reply", "hq-1", "-m", "ack"])

    def test_mail_retry_retains_post_contact_claims_and_replays_cached_inbox(self) -> None:
        runner = self.scripted("/x")
        runner.add(("gt", "mail", "inbox"), [{"id": "hq-cached", "subject": "once"}])
        prov = self.make(runner)

        first_check = prov.check_messages(terminal="mayor", retry_request="req-gt-check")
        second_check = prov.check_messages(terminal="mayor", retry_request="req-gt-check")
        self.assertEqual(first_check["upstreamInbox"], [{"id": "hq-cached", "subject": "once"}])
        self.assertEqual(second_check["upstreamInbox"], [{"id": "hq-cached", "subject": "once"}])
        self.assertEqual(len(runner.called("gt", "mail", "inbox")), 1)

        runner.add(("gt", "mail", "send"), ProviderError("gastown_cli_missing", "gt missing"))
        with self.assertRaises(ProviderError):
            prov.send_message(subject="s", msg_type="info", to="mayor", payload="p", retry_request="req-gt-pre")
        self.assertEqual(prov.request_show("req-gt-pre")["state"], "absent")

        runner_lost = self.scripted("/x")
        runner_lost.add(("gt", "mail", "send"), ProviderError("gastown_timeout", "gt mail send timed out"))
        runner_lost.add(("gt", "mail", "reply"), ProviderError("gastown_timeout", "gt mail reply timed out"))
        prov_lost = self.make(runner_lost)

        with self.assertRaises(ProviderError):
            prov_lost.send_message(subject="s", msg_type="info", to="mayor", payload="p", retry_request="req-gt-send")
        self.assertTrue(prov_lost.request_show("req-gt-send").get("ambiguousContact"))
        self.assertEqual(
            prov_lost.send_message(subject="s", msg_type="info", to="mayor", payload="p", retry_request="req-gt-send"),
            {"state": "pending", "requestId": "req-gt-send"},
        )
        self.assertEqual(len(runner_lost.called("gt", "mail", "send")), 1)

        with self.assertRaises(ProviderError):
            prov_lost.reply_message(msg_id="hq-up-1", body="ack", retry_request="req-gt-reply")
        self.assertTrue(prov_lost.request_show("req-gt-reply").get("ambiguousContact"))
        self.assertEqual(
            prov_lost.reply_message(msg_id="hq-up-1", body="ack", retry_request="req-gt-reply"),
            {"state": "pending", "requestId": "req-gt-reply"},
        )
        self.assertEqual(len(runner_lost.called("gt", "mail", "reply")), 1)


# --------------------------------------------------------------------------------------
# Worktrunk
# --------------------------------------------------------------------------------------
class TestWorktrunkProvider(_Base):
    def make(self, runner: Scripted, hooks: Any = None) -> Any:
        return worktrunk.WorktrunkProvider(state=self.state, runner=runner, env={}, install_hooks=hooks or self.fake_hooks)

    def scripted(self, wt_path: str, branch: str = "wt-feat") -> Scripted:
        return Scripted(
            [
                (("wt", "switch", "--create"), {"action": "created", "branch": branch, "path": wt_path, "created_branch": True}),
                (("wt", "step", "copy-ignored"), {"outcome": "copied", "entries": 2}),
                (("wt", "config", "state", "marker"), ""),
                (("wt", "list"), {"schema": 2, "items": [
                    {"branch": branch, "worktree": {"path": wt_path}, "default_branch": {"merge_conflicts": False}},
                    {"branch": "only-branch"},
                ]}),
                (("wt", "remove"), [{"kind": "worktree", "branch": branch, "path": wt_path, "branch_outcome": "retained_unmerged"}]),
                (("wt", "merge"), {"branch": branch, "target": "main", "squashed": True, "rebased": True, "removed": False}),
                (("tmux", "new-session"), ""),
                (("tmux", "has-session"), ""),
                (("tmux", "kill-session"), ""),
                (("tmux", "capture-pane"), "agent: working\nagent: done\n"),
            ],
            real_git=True,
        )

    def test_spec_reaches_detached_tmux_launch(self) -> None:
        wt = self.tmp / "wt-feat"
        wt.mkdir()
        runner = self.scripted(str(wt))
        prov = self.make(runner)
        tid = prov.dispatch(["orchestration", "task-create", "--spec", SPEC])["task"]["id"]
        res = prov.dispatch(
            ["orchestration", "worker-start", "--task", tid, "--name", "wt-feat", "--agent", "claude", "--profile", "rw"], env={}
        )
        # --no-hooks and never -y: -y auto-approves repo hook commands that run unsandboxed on the host.
        self.assertEqual(runner.calls[0], ["wt", "switch", "--create", "wt-feat", "--no-cd", "--no-hooks", "--format=json"])
        self.assertNotIn("-y", runner.calls[0])
        self.assertNotIn("--yes", runner.calls[0])
        self.assertEqual(runner.called("wt", "step", "copy-ignored")[0], ["wt", "step", "copy-ignored", "--to", str(wt), "--format=json"])
        launch = runner.called("tmux", "new-session")[0]
        self.assertEqual(launch[:7], ["tmux", "new-session", "-d", "-s", f"wt-feat-{res['dispatchId']}", "-c", str(wt)])
        self.assertIn(SPEC.split(";")[0], launch[7])  # the COMPLETE shell line carries the spec
        self.assertIn("--dangerously-skip-permissions", launch[7])
        self.assertFalse([c for c in runner.calls if "-x" in c], "never foreground `wt switch -x`")
        self.assertEqual(res["worktree"], str(wt))
        self.assertEqual(self.hook_calls, [(str(wt), "claude", "rw")])
        self.assertEqual(runner.called("wt", "config", "state", "marker")[0][-2:], ["🤖", "--branch=wt-feat"])

    def test_given_worktree_is_reused_not_created(self) -> None:
        wt = self.tmp / "existing"
        wt.mkdir()
        runner = self.scripted(str(wt), branch="existing")
        prov = self.make(runner)
        res = prov.worker_start(task_id="", worktree=str(wt), prompt=SPEC, profile="ro", agent="claude")
        self.assertFalse(runner.called("wt", "switch"))
        self.assertEqual(res["branch"], "existing")
        self.assertIn("--permission-mode", runner.called("tmux", "new-session")[0][7])
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="", worktree="/no/such/wt", prompt=SPEC)
        self.assertEqual(ctx.exception.code, "worktree_not_found")

    def test_real_hook_install_lands_in_new_worktree(self) -> None:
        wt = self.tmp / "wt-feat"
        wt.mkdir()
        runner = self.scripted(str(wt))
        posix = importlib.import_module("runtime.providers.posix")
        prov = self.make(runner, hooks=posix.install_worktree_hooks)
        prov.worker_start(task_id="", name="wt-feat", prompt=SPEC, agent="crush", profile="ro")
        self.assertTrue((wt / ".claude" / "settings.local.json").is_file())
        self.assertIn("disabled_tools", (wt / ".crush-orca-ro" / "crush.json").read_text())

    def test_missing_spec_and_danger_refused(self) -> None:
        prov = self.make(self.scripted("/x"))
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id="task_none")
        self.assertEqual(ctx.exception.code, "missing_task_spec")
        with self.assertRaises(ProviderError) as ctx2:
            prov.worker_start(task_id="", prompt=SPEC, profile="danger")
        self.assertEqual(ctx2.exception.code, "unsupported_profile")

    def test_bad_or_pathless_output_is_an_error(self) -> None:
        runner = self.scripted("/x")
        runner.add(("wt", "switch", "--create"), "Created worktree (text, not json)")
        with self.assertRaises(ProviderError) as ctx:
            self.make(runner).worker_start(task_id="", prompt=SPEC)
        self.assertEqual(ctx.exception.code, "worktrunk_bad_json")
        self.assertFalse(ctx.exception.to_envelope()["ok"])
        runner2 = self.scripted("/x")
        runner2.add(("wt", "switch", "--create"), {"action": "created"})
        with self.assertRaises(ProviderError) as ctx2:
            self.make(runner2).worker_start(task_id="", prompt=SPEC)
        self.assertEqual(ctx2.exception.code, "upstream_no_id")
        runner3 = self.scripted("/x")
        runner3.add(("wt",), subprocess.TimeoutExpired(["wt"], 60))
        with self.assertRaises(ProviderError) as ctx3:
            self.make(runner3).worktree_list()
        self.assertEqual(ctx3.exception.code, "worktrunk_cli_timeout")

    def test_launch_failure_rolls_back_dispatch(self) -> None:
        wt = self.tmp / "wt-feat"
        wt.mkdir()
        runner = self.scripted(str(wt))
        runner.add(("tmux", "new-session"), ProviderError("worktrunk_cli_error", "duplicate session"))
        prov = self.make(runner)
        with self.assertRaises(ProviderError):
            prov.worker_start(task_id="", name="wt-feat", prompt=SPEC)
        self.assertEqual(prov.worker_list()["workers"], [])

    def test_read_show_retain_stop_and_unknown(self) -> None:
        wt = self.tmp / "wt-feat"
        wt.mkdir()
        runner = self.scripted(str(wt))
        prov = self.make(runner)
        did = prov.worker_start(task_id="", name="wt-feat", prompt=SPEC)["dispatchId"]
        read = prov.dispatch(["orchestration", "worker-read", "--dispatch", did, "--terminal", "--limit", "10"])
        self.assertIn("agent: done", WORKER_OPS.format_read(read))
        self.assertEqual(runner.called("tmux", "capture-pane")[0], ["tmux", "capture-pane", "-p", "-t", f"=wt-feat-{did}:", "-S", "-10"])
        show_lines = WORKER_OPS.format_show(prov.dispatch(["orchestration", "worker-show", "--dispatch", did]))
        self.assertIn("STATE=ready", show_lines)
        self.assertIn("STAGE=running", show_lines)

        before = len(runner.calls)
        self.assertEqual(prov.worker_fence(verb="retain", dispatch_id=did)["state"], "retained")
        self.assertEqual(len(runner.calls), before)

        stopped = prov.worker_fence(verb="stop", dispatch_id=did)
        self.assertEqual(stopped["state"], "stopped")
        self.assertEqual(runner.called("tmux", "kill-session")[0], ["tmux", "kill-session", "-t", f"=wt-feat-{did}"])
        self.assertFalse(runner.called("wt", "remove"))

        for verb in ("stop", "release", "retain"):
            with self.assertRaises(ProviderError) as ctx:
                prov.worker_fence(verb=verb, dispatch_id="wt_dsp_missing")
            self.assertEqual(ctx.exception.code, "dispatch_not_found")

    def test_release_preserves_head_then_reaps(self) -> None:
        main, wt = make_linked_worktree(self.tmp, branch="wt-feat")
        runner = self.scripted(str(wt))
        prov = self.make(runner)
        did = prov.worker_start(task_id="", name="wt-feat", prompt=SPEC)["dispatchId"]

        (wt / "unsaved.py").write_text("wip\n")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_fence(verb="release", dispatch_id=did)
        self.assertEqual(ctx.exception.code, "uncommitted_work")
        self.assertFalse(runner.called("wt", "remove"))
        # The refused release checked BEFORE killing: the worker is still running and the row says so.
        self.assertFalse(runner.called("tmux", "kill-session"))
        self.assertEqual(prov.worker_show(dispatch_id=did)["worker"]["terminalState"], "active")
        (wt / "unsaved.py").unlink()

        released = prov.worker_fence(verb="release", dispatch_id=did)
        head = git_out("-C", str(wt), "rev-parse", "HEAD")
        self.assertEqual(git_out("-C", str(main), "rev-parse", f"refs/open-fleet/preserved/{did}"), head)
        self.assertEqual(
            runner.called("wt", "remove")[0],
            ["wt", "remove", "wt-feat", "--reap", "--foreground", "--format=json", "--force"],
        )
        self.assertEqual(released["state"], "released")

    def test_worktree_rm_requires_selector_and_merge_prediction(self) -> None:
        main, wt = make_linked_worktree(self.tmp, branch="wt-feat")
        subprocess.run(["git", "-C", str(main), "branch", "-m", "main"], check=True, env=GIT_ENV)
        runner = self.scripted(str(wt))
        prov = self.make(runner)
        with self.assertRaises(ProviderError) as ctx:
            prov.dispatch(["worktree", "rm"])
        self.assertEqual(ctx.exception.code, "invalid_selector")
        self.assertFalse(runner.called("wt", "remove"))
        prov.worktree_rm(selector="wt-feat", force=True)
        self.assertEqual(runner.called("wt", "remove")[0], ["wt", "remove", "wt-feat", "--reap", "--foreground", "--format=json", "--force"])

        merged = prov.predict_and_merge("wt-feat", target="main")
        # An explicit target is predicted too (wt list only simulates the default branch).
        self.assertTrue(runner.called("git", "-C", str(wt), "merge-tree", "--write-tree", "--name-only", "main", "wt-feat"))
        self.assertEqual(runner.called("wt", "merge")[0], ["wt", "merge", "main", "--branch", "wt-feat", "--no-remove", "--format=json"])
        self.assertTrue(merged["merged"])
        self.assertIs(merged["predictedConflicts"], False)
        runner.add(("wt", "list"), {"items": [{"branch": "wt-feat", "worktree": {"path": str(wt)}, "default_branch": {"merge_conflicts": True}}]})
        with self.assertRaises(ProviderError) as mctx:
            prov.predict_and_merge("wt-feat")
        self.assertEqual(mctx.exception.code, "merge_conflict_predicted")
        self.assertEqual(len(runner.called("wt", "merge")), 1)

        listed = prov.worktree_list()
        self.assertEqual(listed["worktrees"], [{"branch": "wt-feat", "path": str(wt)}])
        with self.assertRaises(ProviderError):
            prov.worktree_show(selector="nope")

    def test_merge_refuses_dirty_worktree_and_predicts_explicit_target(self) -> None:
        main, wt = make_linked_worktree(self.tmp, branch="wt-feat")
        subprocess.run(["git", "-C", str(main), "branch", "-m", "main"], check=True, env=GIT_ENV)
        runner = self.scripted(str(wt))
        prov = self.make(runner)
        # Dirty worktree: `wt merge` would commit/squash it — refused before any merge call.
        (wt / "unsaved.py").write_text("wip\n")
        with self.assertRaises(ProviderError) as dctx:
            prov.predict_and_merge("wt-feat", target="main")
        self.assertEqual(dctx.exception.code, "uncommitted_work")
        (wt / "unsaved.py").unlink()
        # A target that really conflicts: predicted via merge-tree even though a target was passed.
        (main / "fix.py").write_text("print('main side')\n")
        subprocess.run(["git", "-C", str(main), "add", "fix.py"], check=True, env=GIT_ENV)
        subprocess.run(["git", "-C", str(main), "commit", "-qm", "main conflicting fix"], check=True, env=GIT_ENV)
        with self.assertRaises(ProviderError) as cctx:
            prov.predict_and_merge("wt-feat", target="main")
        self.assertEqual(cctx.exception.code, "merge_conflict_predicted")
        # Undetermined default-branch prediction is a refusal, not a blind merge.
        runner.add(("wt", "list"), {"items": [{"branch": "wt-feat", "worktree": {"path": str(wt)}, "default_branch": {"merge_conflicts": None}}]})
        with self.assertRaises(ProviderError) as uctx:
            prov.predict_and_merge("wt-feat")
        self.assertEqual(uctx.exception.code, "merge_prediction_unavailable")
        self.assertFalse(runner.called("wt", "merge"))

    def test_same_branch_dispatches_get_distinct_sessions_and_shared_worktree_fence_refused(self) -> None:
        main, wt = make_linked_worktree(self.tmp, branch="wt-feat")
        runner = self.scripted(str(wt))
        runner.add(("tmux", "has-session"), "")
        prov = self.make(runner)
        first = prov.worker_start(task_id="", worktree=str(wt), prompt=SPEC, profile="ro")["dispatchId"]
        second = prov.worker_start(task_id="", worktree=str(wt), prompt=SPEC, profile="ro")["dispatchId"]
        sessions = [c[4] for c in runner.called("tmux", "new-session")]
        self.assertEqual(len(set(sessions)), 2, sessions)
        self.assertEqual(sessions, [f"wt-feat-{first}", f"wt-feat-{second}"])

        stopped = prov.worker_fence(verb="stop", dispatch_id=first)  # stop kills ONLY its own session
        self.assertEqual(runner.called("tmux", "kill-session"), [["tmux", "kill-session", "-t", f"={sessions[0]}"]])
        self.assertEqual(stopped["state"], "stopped")

        # `second` is still live on the same worktree: removing it would pull the tree from under it.
        before = len(runner.calls)
        for verb in ("release", "abandon"):
            with self.assertRaises(ProviderError) as ctx:
                prov.worker_fence(verb=verb, dispatch_id=first)
            self.assertEqual(ctx.exception.code, "worktree_shared")
        self.assertEqual(len(runner.calls), before, "a refused destructive fence makes no upstream call")
        released = prov.worker_fence(verb="release", dispatch_id=second)  # nothing else live: allowed
        self.assertEqual(released["state"], "released")

    def test_release_dirtied_between_check_and_kill_records_stopped(self) -> None:
        main, wt = make_linked_worktree(self.tmp, branch="wt-feat")
        runner = self.scripted(str(wt))

        def kill_and_dirty(argv: list[str]) -> str:
            (wt / "late.py").write_text("written as the session died\n")
            return ""

        runner.add(("tmux", "kill-session"), kill_and_dirty)
        prov = self.make(runner)
        did = prov.worker_start(task_id="", name="wt-feat", prompt=SPEC)["dispatchId"]
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_fence(verb="release", dispatch_id=did)
        self.assertEqual(ctx.exception.code, "uncommitted_work")
        self.assertFalse(runner.called("wt", "remove"))
        # The worker WAS killed: the row must not claim it is still active.
        self.assertEqual(prov.worker_show(dispatch_id=did)["worker"]["terminalState"], "stopped")


if __name__ == "__main__":
    unittest.main()
