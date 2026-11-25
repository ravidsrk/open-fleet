#!/usr/bin/env python3
"""Adversarial regression suite for runtime providers, local state, and operations scripts.

Loads every repository module strictly via `importlib.util.spec_from_file_location` (stdlib only).
Covers verified hardening findings B-00a, B-00b, B-01..B-14, and B-P2-1..B-P2-14.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


def _load_file(fqname: str, path: Path, *, is_pkg: bool = False) -> types.ModuleType:
    if fqname in sys.modules:
        return sys.modules[fqname]
    spec = importlib.util.spec_from_file_location(
        fqname,
        path,
        submodule_search_locations=[str(path.parent)] if is_pkg else None,
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[fqname] = mod
    spec.loader.exec_module(mod)
    return mod


def _ensure_runtime_packages() -> types.ModuleType:
    if "runtime" not in sys.modules:
        pkg = types.ModuleType("runtime")
        pkg.__path__ = [str(ROOT / "runtime")]
        sys.modules["runtime"] = pkg
    return _load_file("runtime.providers", ROOT / "runtime" / "providers" / "__init__.py", is_pkg=True)


PROVIDERS = _ensure_runtime_packages()
BASE = _load_file("runtime.providers.base", ROOT / "runtime" / "providers" / "base.py")
LOCAL_STATE = _load_file("runtime.providers.local_state", ROOT / "runtime" / "providers" / "local_state.py")
EXTERNAL = _load_file("runtime.providers._external", ROOT / "runtime" / "providers" / "_external.py")
POSIX = _load_file("runtime.providers.posix", ROOT / "runtime" / "providers" / "posix.py")
WORKTRUNK = _load_file("runtime.providers.worktrunk", ROOT / "runtime" / "providers" / "worktrunk.py")
SUPERSET = _load_file("runtime.providers.superset", ROOT / "runtime" / "providers" / "superset.py")
OPENHANDS = _load_file("runtime.providers.openhands", ROOT / "runtime" / "providers" / "openhands.py")
T3CODE = _load_file("runtime.providers.t3code", ROOT / "runtime" / "providers" / "t3code.py")
PAPERCLIP = _load_file("runtime.providers.paperclip", ROOT / "runtime" / "providers" / "paperclip.py")
VIBE_KANBAN = _load_file("runtime.providers.vibe_kanban", ROOT / "runtime" / "providers" / "vibe_kanban.py")
GASTOWN = _load_file("runtime.providers.gastown", ROOT / "runtime" / "providers" / "gastown.py")
OVERSTORY = _load_file("runtime.providers.overstory", ROOT / "runtime" / "providers" / "overstory.py")
EMDASH = _load_file("runtime.providers.emdash", ROOT / "runtime" / "providers" / "emdash.py")
MULTICLAUDE = _load_file("runtime.providers.multiclaude", ROOT / "runtime" / "providers" / "multiclaude.py")

SANDBOX_DOCTOR = _load_file("adv_sandbox_doctor", ROOT / "runtime" / "scripts" / "sandbox_doctor.py")
ORCA_CLI = _load_file("adv_orca_cli", ROOT / "runtime" / "scripts" / "orca_cli.py")
EVENTS = _load_file("adv_events", ROOT / "runtime" / "scripts" / "events.py")
WATCHDOG = _load_file("adv_watchdog", ROOT / "runtime" / "scripts" / "watchdog.py")
SEND_MSG = _load_file("adv_send_msg", ROOT / "runtime" / "scripts" / "send_msg.py")
CHECK_REPLY = _load_file("adv_check_reply", ROOT / "runtime" / "scripts" / "check_reply.py")
HITL_ASK = _load_file("adv_hitl_ask", ROOT / "runtime" / "scripts" / "hitl_ask.py")
SEARCH_SESSIONS = _load_file("adv_search_sessions", ROOT / "runtime" / "scripts" / "search_sessions.py")
MERGE_QUEUE = _load_file("adv_merge_queue", ROOT / "runtime" / "scripts" / "merge_queue.py")
FIRST_RUN = _load_file("adv_first_run", ROOT / "runtime" / "scripts" / "first_run.py")
WORKER_OPS = _load_file("adv_worker_ops", ROOT / "runtime" / "scripts" / "worker_ops.py")
PROOF_STATUS = _load_file("adv_proof_status", ROOT / "runtime" / "scripts" / "proof_status.py")

ProviderError = BASE.ProviderError


def _make_git_repo(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    subprocess.run(["git", "init", "-q", str(path)], check=True, env=env)
    (path / "README.md").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "-A"], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", "init"], check=True, env=env)


class TestProviderRegistryAuto(unittest.TestCase):
    """B-00a: get_provider('auto') auto-detects regardless of OPEN_FLEET_RUNTIME."""

    def test_get_provider_auto_detects_posix_when_orca_absent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            env = {"PATH": td, "OPEN_FLEET_STATE_DB": str(Path(td) / "state.db")}
            self.assertEqual(PROVIDERS.active_provider_name(env={}), "orca")
            self.assertEqual(PROVIDERS.get_provider(None, env={}).name, "orca")
            prov_lower = PROVIDERS.get_provider("auto", env=env)
            prov_upper = PROVIDERS.get_provider("AUTO", env={**env, "OPEN_FLEET_RUNTIME": "gastown"})
            self.assertEqual(prov_lower.name, "posix")
            self.assertEqual(prov_upper.name, "posix")

    def test_get_provider_auto_detects_orca_when_on_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fake_bin = Path(td) / "orca-ide"
            fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_bin.chmod(0o755)
            env = {"PATH": td, "OPEN_FLEET_RUNTIME": "posix"}
            prov = PROVIDERS.get_provider("auto", env=env, system="Linux")
            self.assertEqual(prov.name, "orca")


class TestExternalPrelaunchAndRollback(unittest.TestCase):
    """B-00b + B-02 + B-P2-5 + B-P2-6 across all 9 external adapters."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.state = LOCAL_STATE.LocalStateStore(db_path=self.tmp / "state.db")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _ready_task(self, spec: str = "Fix bug cleanly") -> str:
        return self.state.task_create(spec=spec, title="t")["task"]["id"]

    def _task_status(self, tid: str) -> str:
        with self.state._connect() as conn:
            row = conn.execute("SELECT status FROM tasks WHERE id = ?", (tid,)).fetchone()
        return str(row["status"])

    def test_worktrunk_prelaunch_validation_rollback_and_hermes_home(self) -> None:
        tid = self._ready_task()
        calls: list[list[str]] = []
        prov = WORKTRUNK.WorktrunkProvider(
            state=self.state,
            runner=lambda argv, **_kw: calls.append(list(argv)) or "{}",
            env={"OPEN_FLEET_STATE_DB": str(self.state.db_path)},
        )
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id=tid, agent="nonexistent-agent", prompt="go", retry_request="wt-bad-agent")
        self.assertEqual(ctx.exception.code, "unknown_agent")
        self.assertEqual(calls, [], "invalid agent must fail before any wt call")
        self.assertEqual(self._task_status(tid), "ready")
        self.assertIsNone(self.state.request_row("wt-bad-agent"))

        # Missing tmux during launch rolls back dispatch row, local task, and retry_request.
        wt_dir = self.tmp / "wt-hermes"
        wt_dir.mkdir()

        def fail_tmux(argv: list[str], **_kw: Any) -> Any:
            if argv[:2] == ["wt", "switch"]:
                return {"branch": "wt-b1", "path": str(wt_dir)}
            if argv[:3] == ["wt", "step", "copy-ignored"]:
                return {"copied": 0}
            if argv[:2] == ["wt", "config"]:
                return ""
            if argv[:2] == ["tmux", "new-session"]:
                raise ProviderError("worktrunk_cli_missing", "'tmux' not found")
            return {}

        prov2 = WORKTRUNK.WorktrunkProvider(
            state=self.state,
            runner=fail_tmux,
            install_hooks=lambda w, a, p: {},
            env={"HOME": str(self.tmp)},
        )
        with self.assertRaises(ProviderError) as ctx2:
            prov2.worker_start(task_id=tid, agent="claude", prompt="go", retry_request="wt-no-tmux")
        self.assertEqual(ctx2.exception.code, "worktrunk_cli_missing")
        self.assertEqual(self._task_status(tid), "ready")
        self.assertIsNone(self.state.request_row("wt-no-tmux"))

        # B-02: hermes worker wires prepare_hermes_home and exports HERMES_HOME.
        tmux_cmds: list[list[str]] = []

        def ok_runner(argv: list[str], **_kw: Any) -> Any:
            if argv[:2] == ["wt", "switch"]:
                return {"branch": "wt-hermes", "path": str(wt_dir)}
            if argv[:3] == ["wt", "step", "copy-ignored"]:
                return {"copied": 0}
            if argv[:2] == ["tmux", "new-session"]:
                tmux_cmds.append(list(argv))
                return ""
            return ""

        prov3 = WORKTRUNK.WorktrunkProvider(
            state=self.state,
            runner=ok_runner,
            install_hooks=lambda w, a, p: {},
            env={"HOME": str(self.tmp)},
        )
        res = prov3.worker_start(task_id=tid, agent="hermes", profile="rw", prompt="inspect")
        eff_env = res["launch"]["effective"]["env"]
        self.assertIn("HERMES_HOME", eff_env)
        self.assertEqual(eff_env["HERMES_ACCEPT_HOOKS"], "1")
        self.assertEqual(eff_env["HERMES_SAFE_MODE"], "0")
        cfg = json.loads((Path(eff_env["HERMES_HOME"]) / "config.yaml").read_text(encoding="utf-8"))
        self.assertTrue(cfg["hooks"]["pre_tool_call"][0]["fail_closed"])
        self.assertIn("HERMES_HOME=", tmux_cmds[0][-1])

    def test_superset_prelaunch_validation_and_worktree_failure_rollback(self) -> None:
        tid = self._ready_task()
        calls: list[list[str]] = []

        def fail_create(argv: list[str], **_kw: Any) -> Any:
            calls.append(list(argv))
            raise ProviderError("superset_cli_error", "workspace create failed")

        prov = SUPERSET.SupersetProvider(
            state=self.state,
            runner=fail_create,
            env={"OPEN_FLEET_SUPERSET_PROJECT": "proj-1"},
        )
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id=tid, agent="bogus-agent", profile="rw", prompt="go", retry_request="sup-1")
        self.assertEqual(ctx.exception.code, "unknown_agent")
        self.assertEqual(calls, [])
        self.assertEqual(self._task_status(tid), "ready")
        self.assertIsNone(self.state.request_row("sup-1"))

        with self.assertRaises(ProviderError) as ctx2:
            prov.worker_start(task_id=tid, agent="claude", profile="rw", prompt="go", retry_request="sup-2")
        self.assertEqual(ctx2.exception.code, "superset_cli_error")
        self.assertEqual(self._task_status(tid), "ready")
        self.assertIsNone(self.state.request_row("sup-2"))

    def test_openhands_prelaunch_and_probe_rollback(self) -> None:
        tid = self._ready_task()
        calls: list[dict[str, Any]] = []
        prov_no_llm = OPENHANDS.OpenHandsProvider(
            state=self.state,
            runner=lambda req, **_kw: calls.append(req) or {"conversation_runtime": "local"},
            env={},
        )
        with self.assertRaises(ProviderError) as ctx:
            prov_no_llm.worker_start(task_id=tid, profile="danger", prompt="go", retry_request="oh-nollm")
        self.assertEqual(ctx.exception.code, "missing_llm_config")
        self.assertEqual(calls, [], "missing LLM must fail before GET /server_info")
        self.assertEqual(self._task_status(tid), "ready")
        self.assertIsNone(self.state.request_row("oh-nollm"))

        # GET /server_info returning local does not poison rollback.
        prov_local = OPENHANDS.OpenHandsProvider(
            state=self.state,
            runner=lambda req, **_kw: {"conversation_runtime": "local"},
            env={"OPEN_FLEET_OPENHANDS_MODEL": "m"},
        )
        with self.assertRaises(ProviderError) as ctx2:
            prov_local.worker_start(task_id=tid, profile="danger", prompt="go", retry_request="oh-local")
        self.assertEqual(ctx2.exception.code, "sandbox_unavailable")
        self.assertEqual(self._task_status(tid), "ready")
        self.assertIsNone(self.state.request_row("oh-local"))

        # Server-cut conversation (run: False) failing guard verification before /run rolls back.
        prov_bad_dir = OPENHANDS.OpenHandsProvider(
            state=self.state,
            runner=lambda req, **_kw: {"id": "c1", "workspace": {"working_dir": "/nonexistent-dir-xyz"}},
            env={"OPEN_FLEET_OPENHANDS_MODEL": "m"},
        )
        with self.assertRaises(ProviderError) as ctx3:
            prov_bad_dir.worker_start(task_id=tid, profile="rw", prompt="go", retry_request="oh-guard")
        self.assertEqual(ctx3.exception.code, "deny_hook_unverified")
        self.assertEqual(self._task_status(tid), "ready")
        self.assertIsNone(self.state.request_row("oh-guard"))

    def test_t3code_prelaunch_cut_rollback_and_dispatch_inject_guards(self) -> None:
        tid = self._ready_task()
        calls: list[dict[str, Any]] = []

        def fail_proj(call: dict[str, Any], **_kw: Any) -> Any:
            calls.append(call)
            raise ProviderError("t3code_tool_error", "project not found")

        prov = T3CODE.T3CodeProvider(state=self.state, runner=fail_proj, project_id="p1")
        with self.assertRaises(ProviderError) as ctx:
            prov.worker_start(task_id=tid, worktree="/definitely/missing", profile="rw", prompt="go", retry_request="t3-1")
        self.assertEqual(ctx.exception.code, "worktree_unknown")
        self.assertEqual(calls, [])
        self.assertEqual(self._task_status(tid), "ready")
        self.assertIsNone(self.state.request_row("t3-1"))

        with self.assertRaises(ProviderError) as ctx2:
            prov.worker_start(task_id=tid, worktree="new-child", profile="rw", prompt="go", retry_request="t3-2")
        self.assertEqual(ctx2.exception.code, "t3code_tool_error")
        self.assertEqual(self._task_status(tid), "ready")
        self.assertIsNone(self.state.request_row("t3-2"))

        # B-04: launched worker rejected (worker_forbidden) and monotonic profile checked in dispatch_inject.
        EXTERNAL.insert_dispatch(
            self.state,
            dispatch_id="thr-rw",
            task_id="seed-t",
            run="run-1",
            worktree="",
            agent="claude",
            profile="rw",
            handle="t3:thr-rw",
            backend="t3code",
            effective={"threadId": "thr-rw"},
            session_id="thr-rw",
        )
        worker_state = LOCAL_STATE.LocalStateStore(
            db_path=self.state.db_path,
            env={"OPEN_FLEET_DISPATCH_ID": "thr-rw", "OPEN_FLEET_RUN_ID": "run-1"},
        )
        worker_t3 = T3CODE.T3CodeProvider(
            state=worker_state,
            runner=lambda call, **_kw: {"structuredContent": {"delivery": "queued"}},
            env={"OPEN_FLEET_DISPATCH_ID": "thr-rw", "OPEN_FLEET_RUN_ID": "run-1"},
        )
        with self.assertRaises(ProviderError) as wctx:
            worker_t3.dispatch_inject(task_id="", to_handle="t3:thr-rw", prompt="hijack")
        self.assertEqual(wctx.exception.code, "worker_forbidden")

        ro_parent_t3 = T3CODE.T3CodeProvider(
            state=self.state,
            runner=lambda call, **_kw: {"structuredContent": {"delivery": "queued"}},
            env={"OPEN_FLEET_PARENT_PROFILE": "ro"},
        )
        with self.assertRaises(ProviderError) as pctx:
            ro_parent_t3.dispatch_inject(task_id="", to_handle="t3:thr-rw", run="run-1", prompt="escalate")
        self.assertEqual(pctx.exception.code, "privilege_escalation")

    def test_paperclip_vibe_gastown_overstory_emdash_rollback(self) -> None:
        # Paperclip: checkout 409 deletes agent and resets launch contact -> rollback.
        tid = self._ready_task()
        deleted: list[str] = []

        def pc_runner(req: dict[str, Any], **_kw: Any) -> Any:
            m, p = req["method"], req["path"]
            if m == "POST" and p.endswith("/agents"):
                return {"id": "ag-1"}
            if m == "GET" and p == "/api/agents/ag-1":
                return {
                    "id": "ag-1",
                    "adapterType": "claude_local",
                    "adapterConfig": {"engine": "cli", "dangerouslySkipPermissions": True},
                }
            if m == "POST" and p.endswith("/issues"):
                return {"id": "iss-1"}
            if m == "POST" and p.endswith("/checkout"):
                return {"status": 409, "error": "locked"}
            if m == "DELETE" and p == "/api/agents/ag-1":
                deleted.append(p)
                return {}
            raise AssertionError(f"unexpected {m} {p}")

        pc = PAPERCLIP.PaperclipProvider(state=self.state, runner=pc_runner, company_id="co1")
        with self.assertRaises(ProviderError) as pctx:
            pc.worker_start(task_id=tid, agent="claude", profile="rw", prompt="go", retry_request="pc-409")
        self.assertEqual(pctx.exception.code, "task_not_startable")
        self.assertEqual(deleted, ["/api/agents/ag-1"])
        self.assertEqual(self._task_status(tid), "ready")
        self.assertIsNone(self.state.request_row("pc-409"))

        # Vibe-Kanban: ensure_ro_profile refusal does not poison rollback.
        def vk_runner(req: dict[str, Any], **_kw: Any) -> Any:
            if req["path"] == "/api/profiles" and req["method"] == "GET":
                return {"success": True, "data": {"content": json.dumps({"executors": {"CLAUDE_CODE": {}}})}}
            if req["path"] == "/api/profiles" and req["method"] == "PUT":
                return {"success": True, "data": None}
            raise AssertionError(f"unexpected {req}")

        vk = VIBE_KANBAN.VibeKanbanProvider(
            state=self.state,
            runner=vk_runner,
            env={"OPEN_FLEET_VIBE_KANBAN_REPO_ID": "r1", "OPEN_FLEET_VIBE_KANBAN_TARGET_BRANCH": "main"},
        )
        with self.assertRaises(ProviderError) as vkctx:
            vk.worker_start(task_id=tid, agent="claude", profile="ro", prompt="go", retry_request="vk-ro")
        self.assertEqual(vkctx.exception.code, "ro_profile_unverified")
        self.assertEqual(self._task_status(tid), "ready")
        self.assertIsNone(self.state.request_row("vk-ro"))

        # Gastown: pre-sling `gt config agent set` failure rolls back task & retry_request.
        def gt_runner(argv: list[str], **_kw: Any) -> Any:
            if argv[:2] == ["bd", "create"]:
                return json.dumps({"id": "bd-1"})
            if argv[:4] == ["gt", "config", "agent", "set"]:
                raise ProviderError("gastown_cli_error", "config write failed")
            raise AssertionError(f"unexpected {argv}")

        gt = GASTOWN.GastownProvider(state=self.state, runner=gt_runner, rig="rig1")
        with self.assertRaises(ProviderError):
            gt.worker_start(task_id=tid, agent="claude", profile="ro", prompt="go", retry_request="gt-pre")
        self.assertEqual(self._task_status(tid), "ready")
        self.assertIsNone(self.state.request_row("gt-pre"))

        # Overstory: `ov spec write` failure rolls back task & retry_request.
        ov = OVERSTORY.OverstoryProvider(
            state=self.state,
            runner=lambda argv, **_kw: (_ for _ in ()).throw(ProviderError("overstory_cli_error", "spec failed")),
        )
        with self.assertRaises(ProviderError):
            ov.worker_start(task_id=tid, agent="claude", profile="rw", prompt="go", retry_request="ov-spec")
        self.assertEqual(self._task_status(tid), "ready")
        self.assertIsNone(self.state.request_row("ov-spec"))

        # Emdash: `createWorktree` failure rolls back task & retry_request.
        em = EMDASH.EmdashProvider(
            state=self.state,
            runner=lambda msg, **_kw: {"kind": "result", "id": msg["id"], "ok": False, "code": "ERR", "message": "boom"},
            env={"OPEN_FLEET_EMDASH_REPOSITORY_ID": "repo1"},
        )
        with self.assertRaises(ProviderError):
            em.worker_start(task_id=tid, agent="claude", profile="rw", prompt="go", base="main", retry_request="em-wt")
        self.assertEqual(self._task_status(tid), "ready")
        self.assertIsNone(self.state.request_row("em-wt"))

    def test_vibe_kanban_dirty_uses_foreign_dirty_paths_and_run_cli_env(self) -> None:
        # B-P2-5: run_cli forwards env.
        out = EXTERNAL.run_cli(
            [sys.executable, "-c", "import os; print(os.environ.get('ADV_PROBE_KEY', ''))"],
            provider="test",
            env={**os.environ, "ADV_PROBE_KEY": "custom-val-77"},
        )
        self.assertEqual(out["raw"], "custom-val-77")

        # B-P2-6: vibe_kanban._dirty uses foreign_dirty_paths (handles -z paths and ignores hook artifacts).
        repo = self.tmp / "vk-repo"
        _make_git_repo(repo)
        (repo / "x -> AGENTS.md").write_text("user file disguised as rename\n", encoding="utf-8")
        vk = VIBE_KANBAN.VibeKanbanProvider(
            state=self.state,
            runner=lambda req, **_kw: {},
            env={"OPEN_FLEET_VIBE_KANBAN_REPO_ID": "r1", "OPEN_FLEET_VIBE_KANBAN_TARGET_BRANCH": "main"},
        )
        dirty = vk._dirty(str(repo))
        self.assertIn("x -> AGENTS.md", dirty)


class TestSandboxDoctorHardening(unittest.TestCase):
    """B-01: no isolation.* shadowing and full outer-envelope host-exposure scanning."""

    GOOD_DOCKER = {
        "recipeId": "lane-1",
        "backend": "docker",
        "ok": True,
        "ephemeral": True,
        "credential_mounts": [],
        "prelaunch_placement_bound": True,
        "isolation": {
            "capDrop": ["ALL"],
            "noNewPrivileges": True,
            "pidsLimit": 512,
            "privileged": False,
            "network": "bridge",
        },
        "mounts": [{"source": "/tmp/wt", "target": "/workspace", "mode": "rw"}],
        "failures": [],
    }
    GOOD_BWRAP = {
        "recipeId": "lane-1",
        "backend": "bwrap",
        "ok": True,
        "ephemeral": True,
        "credential_mounts": [],
        "prelaunch_placement_bound": True,
        "isolation": {"networkScope": "deny", "filesystemScope": "workspace"},
        "failures": [],
    }

    def test_top_level_contradiction_cannot_be_shadowed_by_isolation_dict(self) -> None:
        bad_docs = [
            dict(self.GOOD_DOCKER, noNewPrivileges=False),
            dict(self.GOOD_DOCKER, capDrop=[]),
            dict(self.GOOD_DOCKER, pidsLimit=0),
            dict(self.GOOD_BWRAP, filesystemScope="host"),
            dict(self.GOOD_BWRAP, networkScope="host"),
        ]
        for doc in bad_docs:
            with self.subTest(doc=doc):
                raw = json.dumps(doc)
                clear, _reason, exposes = SANDBOX_DOCTOR.assess(raw, "lane-1")
                self.assertFalse(clear)
                self.assertTrue(exposes)
                self.assertFalse(SANDBOX_DOCTOR.placement_bound(raw))

    def test_outer_envelope_mounts_and_isolation_flags_refused_as_host_exposure(self) -> None:
        hostile_outers = [
            {"ok": True, "mounts": ["/var/run/docker.sock:/var/run/docker.sock"]},
            {"ok": True, "mounts": ["~/.ssh:/root/.ssh"]},
            {"ok": True, "privileged": True},
            {"ok": True, "networkMode": "host"},
            {"ok": True, "devices": ["/dev/sda"]},
            {"ok": True, "capAdd": ["SYS_ADMIN"]},
            {"ok": True, "securityOpt": ["seccomp=unconfined"]},
            {"ok": True, "pidMode": "host"},
        ]
        for outer in hostile_outers:
            with self.subTest(outer=outer):
                raw = json.dumps({**outer, "result": self.GOOD_DOCKER})
                clear, _reason, exposes = SANDBOX_DOCTOR.assess(raw, "lane-1")
                self.assertFalse(clear)
                self.assertTrue(exposes)
                self.assertFalse(SANDBOX_DOCTOR.placement_bound(raw))


class TestEmdashMulticlaudeGastown(unittest.TestCase):
    """B-03 (Emdash), B-10 (Multiclaude), B-11 (Gastown)."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.state = LOCAL_STATE.LocalStateStore(db_path=self.tmp / "state.db")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_emdash_worker_forbidden_and_blob_frame_cap(self) -> None:
        EXTERNAL.insert_dispatch(
            self.state,
            dispatch_id="conv-1",
            task_id="t1",
            run="r1",
            worktree="",
            agent="claude",
            profile="rw",
            handle="emdash:conv-1",
            backend="emdash",
            effective={},
            session_id="conv-1",
        )
        w_state = LOCAL_STATE.LocalStateStore(
            db_path=self.state.db_path,
            env={"OPEN_FLEET_DISPATCH_ID": "conv-1", "OPEN_FLEET_RUN_ID": "r1"},
        )
        prov = EMDASH.EmdashProvider(
            state=w_state,
            runner=lambda msg, **_kw: {"ok": True},
            env={"OPEN_FLEET_DISPATCH_ID": "conv-1", "OPEN_FLEET_RUN_ID": "r1"},
        )
        with self.assertRaises(ProviderError) as ctx:
            prov.terminal_send(terminal="emdash:conv-1", text="hi")
        self.assertEqual(ctx.exception.code, "worker_forbidden")

        # Blob frame whose hdr_len + body_len > EMDASH_MAX_FRAME must fail before reading body_len.
        s1, s2 = socket.socketpair()
        try:
            # ftype=0x01, hdr_len=4, payload=b"abcd", body_len=0xFFFFFFFF (4 GiB)
            frame = b"\x01" + struct.pack(">I", 4) + b"abcd" + struct.pack(">I", 0xFFFFFFFF)
            s2.sendall(frame)
            with self.assertRaises(ProviderError) as fctx:
                prov._read_result(s1, "want-1")
            self.assertEqual(fctx.exception.code, "emdash_bad_frame")
        finally:
            s1.close()
            s2.close()

    def test_multiclaude_tmux_gone_and_worker_verify_forbidden(self) -> None:
        EXTERNAL.insert_dispatch(
            self.state,
            dispatch_id="ag-1",
            task_id="t1",
            run="r1",
            worktree=str(self.tmp),
            agent="claude",
            profile="rw",
            handle="multiclaude:ag-1",
            backend="multiclaude",
            effective={"repo": "myrepo"},
            session_id="ag-1",
        )

        # B-10a: _stop_upstream proceeds when tmux kill-window reports window already gone.
        cli_calls: list[list[str]] = []

        def fake_cli(argv: list[str]) -> dict[str, Any]:
            cli_calls.append(list(argv))
            if argv[:2] == ["tmux", "kill-window"]:
                raise ProviderError("multiclaude_cli_error", "can't find window: ag-1")
            if argv[:2] == ["tmux", "list-windows"]:
                return {"stdout": "other-win\n", "raw": "other-win"}
            return {"stdout": "", "raw": ""}

        mc = MULTICLAUDE.MulticlaudeProvider(
            state=self.state,
            runner=lambda msg, **_kw: {"success": True, "data": {"removed": True}},
            cli_runner=fake_cli,
            home=self.tmp,
            repo="myrepo",
        )
        res = mc._stop_upstream("myrepo", "ag-1", worktree=None)
        self.assertTrue(res["windowGone"])
        self.assertFalse(res["killWindow"])

        # B-10b: launched worker cannot self-verify in worker_verify.
        w_state = LOCAL_STATE.LocalStateStore(
            db_path=self.state.db_path,
            env={"OPEN_FLEET_DISPATCH_ID": "ag-1", "OPEN_FLEET_RUN_ID": "r1"},
        )
        w_mc = MULTICLAUDE.MulticlaudeProvider(
            state=w_state,
            runner=lambda msg, **_kw: {"success": True, "data": {}},
            cli_runner=fake_cli,
            home=self.tmp,
            repo="myrepo",
            env={"OPEN_FLEET_DISPATCH_ID": "ag-1", "OPEN_FLEET_RUN_ID": "r1"},
        )
        with self.assertRaises(ProviderError) as vctx:
            w_mc.worker_verify(dispatch_id="ag-1", sha="a" * 40, manifest=str(self.tmp / "m.json"))
        self.assertEqual(vctx.exception.code, "worker_forbidden")

    def test_gastown_task_create_and_task_update_retry_request(self) -> None:
        calls: list[list[str]] = []
        fail_dep = [True]

        def runner(argv: list[str], **_kw: Any) -> Any:
            calls.append(list(argv))
            if argv[:2] == ["bd", "create"]:
                return json.dumps({"id": f"bd-{len(calls)}"})
            if argv[:3] == ["bd", "dep", "add"]:
                if fail_dep[0]:
                    raise ProviderError("gastown_cli_error", "dep add transient failure")
                return ""
            if argv[:2] == ["bd", "update"]:
                return json.dumps({"id": argv[2], "status": "closed"})
            return "{}"

        gt = GASTOWN.GastownProvider(state=self.state, runner=runner, rig="rig1")
        dep_res = gt.task_create(spec="dep task", title="dep")
        dep_tid = dep_res["task"]["id"]

        # Failing bd dep add records bead, marks local task failed, and releases retry_request.
        with self.assertRaises(ProviderError):
            gt.task_create(spec="child task", title="child", deps=[dep_tid], retry_request="gt-tc-1")
        self.assertIsNone(self.state.request_row("gt-tc-1"))
        with self.state._connect() as conn:
            failed_rows = conn.execute("SELECT id, status FROM tasks WHERE title = 'child'").fetchall()
        self.assertEqual(failed_rows[0]["status"], "failed")
        self.assertIsNotNone(gt.bead_for(failed_rows[0]["id"]), "bead must be recorded before bd dep add")

        # Retrying with same retry_request succeeds (not returning stale cached ready over failed).
        fail_dep[0] = False
        ok_res = gt.task_create(spec="child task", title="child", deps=[dep_tid], retry_request="gt-tc-1")
        self.assertEqual(ok_res["task"]["status"], "pending")
        child_tid = ok_res["task"]["id"]

        # task_update replay with same retry_request skips duplicate bd update.
        calls.clear()
        u1 = gt.task_update(task_id=child_tid, status="completed", retry_request="gt-tu-1")
        u2 = gt.task_update(task_id=child_tid, status="completed", retry_request="gt-tu-1")
        self.assertEqual(u1["task"]["beadId"], u2["task"]["beadId"])
        self.assertEqual(sum(1 for c in calls if c[:2] == ["bd", "update"]), 1)


class TestPosixHardening(unittest.TestCase):
    """B-05, B-06, B-07, B-P2-4 on PosixWorktreeProvider."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.repo = self.tmp / "repo"
        _make_git_repo(self.repo)
        self.state = LOCAL_STATE.LocalStateStore(db_path=self.tmp / "state.db")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_resolve_backend_and_terminate_backend_and_run_git_worktree_eq(self) -> None:
        # B-05: _resolve_backend honors self.env["PATH"]
        empty_dir = self.tmp / "empty-path"
        empty_dir.mkdir()
        prov = POSIX.PosixWorktreeProvider(
            state=self.state,
            repo_root=self.repo,
            env={"PATH": str(empty_dir), "OPEN_FLEET_STATE_DB": str(self.state.db_path)},
        )
        self.assertEqual(prov.backend, "setsid")

        # B-06: _terminate_backend catches missing docker/tmux/cmux without aborting receipt.
        with mock.patch.object(POSIX.subprocess, "run", side_effect=FileNotFoundError("no binary")):
            rep_tmux = prov._terminate_backend("tmux", "term_1", 0, backend_ref="sess", container="ctr-1")
            rep_cmux = prov._terminate_backend("cmux", "term_1", 0, backend_ref="ws-1")
        self.assertIn("error", rep_tmux["container"])
        self.assertIn("error", rep_tmux["tmux"])
        self.assertIn("error", rep_cmux["cmux"])

        # B-P2-4: run_git handles --work-tree=<path> spelling.
        proc = POSIX.run_git(
            [f"--git-dir={self.repo / '.git'}", f"--work-tree={self.repo}", "status", "--porcelain"],
            cwd=str(self.repo),
        )
        self.assertEqual(proc.returncode, 0)

    def test_launched_worker_forbidden_on_worktree_rm_and_peer_reads(self) -> None:
        coord = POSIX.PosixWorktreeProvider(
            state=self.state,
            repo_root=self.repo,
            backend="dry-run",
            env={"OPEN_FLEET_STATE_DB": str(self.state.db_path)},
        )
        t1 = coord.task_create(spec="task 1", run="r1")["task"]["id"]
        t2 = coord.task_create(spec="task 2", run="r1")["task"]["id"]
        w1 = coord.worker_start(task_id=t1, run="r1", worktree="new-child", name="w1")
        w2 = coord.worker_start(task_id=t2, run="r1", worktree="new-child", name="w2")

        w1_env = {
            "OPEN_FLEET_STATE_DB": str(self.state.db_path),
            "OPEN_FLEET_DISPATCH_ID": w1["dispatchId"],
            "OPEN_FLEET_TERMINAL_HANDLE": w1["agentTerminalHandle"],
            "OPEN_FLEET_RUN_ID": "r1",
        }
        w1_state = LOCAL_STATE.LocalStateStore(db_path=self.state.db_path, env=w1_env)
        w1_prov = POSIX.PosixWorktreeProvider(state=w1_state, repo_root=self.repo, backend="dry-run", env=w1_env)

        # Own reads succeed.
        self.assertEqual(w1_prov.worker_show(w1["dispatchId"])["dispatch"]["id"], w1["dispatchId"])
        self.assertIn("transcript", w1_prov.worker_read(w1["dispatchId"]))
        self.assertEqual(w1_prov.terminal_show(w1["agentTerminalHandle"])["terminal"]["handle"], w1["agentTerminalHandle"])

        # Peer reads and worktree_rm raise worker_forbidden.
        for fn in (
            lambda: w1_prov.worktree_rm(w1["worker"]["worktree"]),
            lambda: w1_prov.worker_show(w2["dispatchId"]),
            lambda: w1_prov.worker_read(w2["dispatchId"]),
            lambda: w1_prov.terminal_show(w2["agentTerminalHandle"]),
            lambda: w1_prov.terminal_read(w2["agentTerminalHandle"]),
        ):
            with self.assertRaises(ProviderError) as ctx:
                fn()
            self.assertEqual(ctx.exception.code, "worker_forbidden")

    def test_dispatch_inject_retry_request_and_terminal_wait_exit_sweep(self) -> None:
        coord = POSIX.PosixWorktreeProvider(
            state=self.state,
            repo_root=self.repo,
            backend="dry-run",
            env={"OPEN_FLEET_STATE_DB": str(self.state.db_path)},
        )
        term = coord.terminal_create(worktree=str(self.repo), title="t", command="true")["terminal"]["handle"]
        t1 = coord.task_create(spec="injectable")["task"]["id"]
        r1 = coord.dispatch_inject(task_id=t1, to_handle=term, retry_request="inj-req-1")
        r2 = coord.dispatch_inject(task_id=t1, to_handle=term, retry_request="inj-req-1")
        self.assertEqual(r1["dispatchId"], r2["dispatchId"])

        # terminal_wait(..., condition='exit') sweeps dead standalone pid to exited.
        real_prov = POSIX.PosixWorktreeProvider(
            state=self.state,
            repo_root=self.repo,
            backend="setsid",
            env={"OPEN_FLEET_STATE_DB": str(self.state.db_path)},
        )
        with self.state._connect() as conn:
            conn.execute("UPDATE terminals SET pid = 999999, backend = 'setsid', state = 'running' WHERE handle = ?", (term,))
            conn.execute("DELETE FROM dispatches WHERE terminal_handle = ?", (term,))
        with mock.patch.object(POSIX.os, "kill", side_effect=ProcessLookupError()):
            wres = real_prov.terminal_wait(term, condition="exit", timeout_ms=2000)
        self.assertTrue(wres["wait"]["satisfied"])


class TestScriptsHardening(unittest.TestCase):
    """B-08, B-09, B-12, B-13, B-14, B-P2-1..3, B-P2-7..14."""

    def test_orca_cli_explicit_command_and_auto_resolving_to_orca(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            stub = Path(td) / "fake-orca"
            stub.write_text(
                '#!/usr/bin/env python3\nimport json, sys\n'
                'print(json.dumps({"ok": True, "result": {"timedOut": True, "messageId": "m-9"}}))\n'
                'sys.exit(1)\n',
                encoding="utf-8",
            )
            stub.chmod(0o755)
            # Explicit OPEN_FLEET_CLI_COMMAND takes subprocess path even under OPEN_FLEET_RUNTIME=posix.
            with mock.patch.dict(
                os.environ,
                {"OPEN_FLEET_RUNTIME": "posix", "OPEN_FLEET_CLI_COMMAND": str(stub)},
                clear=False,
            ):
                res = ORCA_CLI.run_json(["orchestration", "ask"], timeout=10, error=RuntimeError, nonzero="ignore")
                self.assertEqual(res["messageId"], "m-9")

            # OPEN_FLEET_RUNTIME=auto resolving to orca takes subprocess path honoring nonzero='ignore'.
            orca_bin = Path(td) / "orca-ide"
            orca_bin.write_text(stub.read_text(encoding="utf-8"), encoding="utf-8")
            orca_bin.chmod(0o755)
            clean_env = {
                "PATH": f"{td}:{os.environ.get('PATH', '')}",
                "OPEN_FLEET_RUNTIME": "auto",
            }
            with mock.patch.dict(os.environ, clean_env, clear=True):
                res2 = ORCA_CLI.run_json(["orchestration", "ask"], timeout=10, error=RuntimeError, nonzero="ignore")
                self.assertTrue(res2["timedOut"])

    def test_events_ingest_state_attrs_dispatch_id_and_unbound(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "state.db"
            ledger = Path(td) / "events.jsonl"
            st = LOCAL_STATE.LocalStateStore(db_path=db)
            now = time.time()
            sha = "a" * 40
            with st._connect() as conn:
                conn.execute(
                    "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, profile, "
                    "terminal_handle, state, terminal_state, backend, monitor_started_at, created_at, updated_at) "
                    "VALUES ('d-attr', 't-1', 'run-e', '/tmp', 'claude', 'rw', 'shared-h', 'completed', 'exited', 'posix', ?, ?, ?)",
                    (now, now, now),
                )
                conn.execute(
                    "INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, profile, "
                    "terminal_handle, state, terminal_state, backend, monitor_started_at, created_at, updated_at) "
                    "VALUES ('d-other', 't-2', 'run-e', '/tmp', 'claude', 'rw', 'shared-h', 'completed', 'exited', 'posix', ?, ?, ?)",
                    (now, now, now),
                )
                # Message 1: sender is shared handle (ambiguous), but attrs.dispatchId names d-attr.
                conn.execute(
                    "INSERT INTO messages(id, run_id, sender, recipient, msg_type, subject, outcome, payload, attrs_json, created_at) "
                    "VALUES ('m-1', 'run-e', 'shared-h', 'coordinator', 'worker_done', 'done', 'succeeded', '{}', ?, ?)",
                    (json.dumps({"dispatchId": "d-attr", "headSha": sha}), now + 1),
                )
                # Message 2: sender is unknown, attrs.dispatchUnbound is True alongside a spoofed dispatchId -> not attributed.
                conn.execute(
                    "INSERT INTO messages(id, run_id, sender, recipient, msg_type, subject, outcome, payload, attrs_json, created_at) "
                    "VALUES ('m-2', 'run-e', 'ghost-sender', 'coordinator', 'worker_done', 'done', 'succeeded', '{}', ?, ?)",
                    (json.dumps({"dispatchUnbound": True, "dispatchId": "d-other", "headSha": sha}), now + 1),
                )
            err_buf = io.StringIO()
            out_buf = io.StringIO()
            with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
                rc = EVENTS.main(
                    ["--log", str(ledger), "ingest-state", "--db", str(db), "--run", "run-e", "--epoch", "1", "--clock", "test@host"]
                )
            self.assertEqual(rc, 0)
            rows = [json.loads(ln) for ln in ledger.read_text(encoding="utf-8").splitlines() if ln.strip()]
            done_events = [r for r in rows if r["kind"] == "task.done"]
            self.assertEqual(len(done_events), 1)
            self.assertEqual(done_events[0]["dispatch"], "d-attr")
            self.assertIn("m-2", err_buf.getvalue())

    def test_watchdog_parse_ts_lock_state_dir_and_classification_log(self) -> None:
        # parse_ts rejects bool, nan, inf, and overflow.
        for bad in (True, False, float("nan"), float("inf"), float("-inf"), 1e30):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                WATCHDOG.parse_ts(bad, "ts")

        # build_failure_handover rejects bool attempt.
        with self.assertRaises(WATCHDOG.HeartbeatError):
            WATCHDOG.build_failure_handover(
                {
                    "task_id": "t1",
                    "failed_dispatch_id": "d1",
                    "attempt": True,
                    "reflection": {"what_failed": "x", "fix_change": "y", "repeating_same_approach": False},
                }
            )

        # _state_db_path supports OPEN_FLEET_STATE_DIR / ORCA_FLEET_STATE_DIR.
        self.assertEqual(
            WATCHDOG._state_db_path({"OPEN_FLEET_STATE_DIR": "/tmp/of-dir"}),
            Path("/tmp/of-dir/runtime.db"),
        )
        self.assertEqual(
            WATCHDOG._state_db_path({"ORCA_FLEET_STATE_DIR": "/tmp/orca-dir"}),
            Path("/tmp/orca-dir/runtime.db"),
        )

        # Re-entrant state_lock does not deadlock when save_state is called inside it,
        # and serializes a concurrent thread until released.
        with tempfile.TemporaryDirectory() as td:
            st_path = Path(td) / "watchdog-state.json"
            order: list[str] = []
            entered = threading.Event()
            with WATCHDOG.state_lock(st_path):
                WATCHDOG.save_state(st_path, {"workers": {"w1": {"nudges": []}}})

                def contender() -> None:
                    entered.set()
                    with WATCHDOG.state_lock(st_path):
                        order.append("contender")

                th = threading.Thread(target=contender)
                th.start()
                entered.wait(timeout=2)
                time.sleep(0.05)
                order.append("holder-done")
            th.join(timeout=5)
            self.assertEqual(order, ["holder-done", "contender"])
            self.assertEqual(WATCHDOG.load_state(st_path)["workers"]["w1"]["nudges"], [])

            # B-P2-8: CI nudge failure on OK worker logs 'OK NUDGE-FAILED', not 'HUNG NUDGE-FAILED'.
            now = WATCHDOG.parse_ts("2026-10-01T12:00:00Z", "now")
            hb = {
                "run_id": "r1",
                "workers": [
                    {
                        "worker_id": "w-ci",
                        "dispatch_id": "d-ci",
                        "dispatched_at": "2026-10-01T11:55:00Z",
                        "last_movement_at": "2026-10-01T11:59:00Z",
                        "ci_checks": [{"name": "lint", "conclusion": "failure"}],
                    }
                ],
            }
            cfg = dict(WATCHDOG.DEFAULTS, nudge_command=["/nonexistent/nudge-bin"])
            args = types.SimpleNamespace(dry_run=False, state=str(st_path), log=str(Path(td) / "log.jsonl"))
            err_buf = io.StringIO()
            with contextlib.redirect_stderr(err_buf):
                code = WATCHDOG.run_tick(args, cfg, hb, {"workers": {}}, now)
            self.assertEqual(code, 2)
            self.assertIn("w-ci OK NUDGE-FAILED", err_buf.getvalue())

    def test_send_check_hitl_ambient_handles_and_check_timeout(self) -> None:
        for mod in (SEND_MSG, CHECK_REPLY, HITL_ASK):
            with self.subTest(mod=mod.__name__):
                self.assertEqual(
                    mod.resolve_from(None, {"OPEN_FLEET_TERMINAL_HANDLE": "h-of"}),
                    "h-of",
                )
                self.assertEqual(
                    mod.resolve_from(None, {"OPEN_FLEET_TERMINAL_HANDLE": "h-same", "ORCA_TERMINAL_HANDLE": "h-same"}),
                    "h-same",
                )
                with self.assertRaises(mod.Refused):
                    mod.resolve_from(None, {"OPEN_FLEET_TERMINAL_HANDLE": "h-a", "ORCA_TERMINAL_HANDLE": "h-b"})

        # B-P2-10: check_reply scales subprocess timeout when --wait --timeout-ms is large.
        seen_timeouts: list[int] = []

        def fake_run_orca(argv: list[str], *, timeout: int = 300) -> dict[str, Any]:
            seen_timeouts.append(timeout)
            return {"messages": [], "count": 0, "timedOut": True}

        with mock.patch.object(CHECK_REPLY, "run_orca", side_effect=fake_run_orca), contextlib.redirect_stdout(io.StringIO()):
            rc = CHECK_REPLY.main(["check", "--wait", "--timeout-ms", "600000"])
        self.assertEqual(rc, 0)
        self.assertEqual(seen_timeouts, [630])

    def test_search_sessions_fallback_precedence(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"OPEN_FLEET_RUNTIME": "orca", "ORCA_FLEET_RUNTIME": "posix"},
            clear=True,
        ):
            self.assertFalse(SEARCH_SESSIONS._should_fallback_to_local())
        with mock.patch.dict(
            os.environ,
            {"OPEN_FLEET_RUNTIME": "", "ORCA_FLEET_RUNTIME": "posix"},
            clear=True,
        ):
            self.assertTrue(SEARCH_SESSIONS._should_fallback_to_local())

    def test_local_state_schema_version_env_and_options_and_base_flags(self) -> None:
        # B-P2-1: read-only WAL newer-schema DB refused BEFORE write tx/DDL.
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "newer.db"
            conn = sqlite3.connect(str(db))
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(f"PRAGMA user_version = {LOCAL_STATE.SCHEMA_VERSION + 5}")
            conn.commit()
            conn.close()
            db.chmod(stat.S_IRUSR)
            try:
                with self.assertRaises(ProviderError) as ctx:
                    LOCAL_STATE.LocalStateStore(db_path=db)
                self.assertEqual(ctx.exception.code, "state_schema_newer")
            finally:
                db.chmod(stat.S_IRUSR | stat.S_IWUSR)

            # B-P2-2: default_db_path(env={}) does not read os.environ["OPEN_FLEET_REPO_ROOT"].
            with mock.patch.dict(os.environ, {"OPEN_FLEET_REPO_ROOT": "/some/other/repo"}, clear=False):
                p_empty = LOCAL_STATE.default_db_path(env={})
                p_os = LOCAL_STATE.default_db_path(env=None)
            self.assertNotEqual(p_empty, p_os)

            # B-P2-3: ask_human rejects invalid JSON / non-list options cleanly.
            st = LOCAL_STATE.LocalStateStore(db_path=Path(td) / "ok.db")
            for bad_opt in ("[unterminated", True, 42):
                with self.assertRaises(ProviderError) as octx:
                    st.ask_human(question="q?", options=bad_opt)
                self.assertEqual(octx.exception.code, "invalid_argument")

        # B-P2-2, B-P2-3, B-P2-14 on base.py:
        class RecordingProvider(BASE.RuntimeProvider):
            name = "rec"

            def __init__(self) -> None:
                self.seen: dict[str, Any] = {}

            def worker_start(self, **kw: Any) -> dict[str, Any]:
                self.seen = kw
                return kw

            def send_message(self, **kw: Any) -> dict[str, Any]:
                self.seen = kw
                return kw

            def worker_fence(self, **kw: Any) -> dict[str, Any]:
                self.seen = kw
                return kw

            def gate_resolve(self, **kw: Any) -> dict[str, Any]:
                self.seen = kw
                return kw

            def run_create(self, **kw: Any) -> dict[str, Any]:
                self.seen = kw
                return kw

            def task_update(self, **kw: Any) -> dict[str, Any]:
                self.seen = kw
                return kw

        rec = RecordingProvider()
        with mock.patch.dict(os.environ, {"PROFILE": "danger"}, clear=False):
            rec.dispatch(["orchestration", "worker-start", "--task", "t1", "--prompt", "hi"], env={})
        self.assertEqual(rec.seen["profile"], "rw")

        # TEXT_FLAGS preserves `--json` value for payload, reason, resolution, objective, result.
        rec.dispatch(["orchestration", "send", "--subject", "s", "--payload", "--json"])
        self.assertEqual(rec.seen["payload"], "--json")
        rec.dispatch(["orchestration", "worker-stop", "--dispatch", "d1", "--reason", "--json"])
        self.assertEqual(rec.seen["reason"], "--json")
        rec.dispatch(["orchestration", "gate-resolve", "--id", "g1", "--resolution", "--json"])
        self.assertEqual(rec.seen["resolution"], "--json")
        rec.dispatch(["orchestration", "run-create", "--objective", "--json"])
        self.assertEqual(rec.seen["objective"], "--json")
        rec.dispatch(["orchestration", "task-update", "--id", "t1", "--status", "completed", "--result", "--json"])
        self.assertEqual(rec.seen["result"], "--json")

        # Bad int flag and bad --deps raise ProviderError('invalid_argument').
        with self.assertRaises(ProviderError) as ictx:
            rec.dispatch(["search", "q", "--limit", "not-an-int"])
        self.assertEqual(ictx.exception.code, "invalid_argument")
        with self.assertRaises(ProviderError) as dctx:
            rec.dispatch(["orchestration", "task-create", "--spec", "s", "--deps", "{bad"])
        self.assertEqual(dctx.exception.code, "invalid_argument")

        # version() returns 'unknown' when pins.json cannot be read.
        with mock.patch.object(Path, "read_text", side_effect=OSError("missing")):
            self.assertEqual(rec.version(), "unknown")

    def test_merge_queue_connect_bwrap_cache_and_drain_release(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            store = MERGE_QUEUE.Store(Path(td) / "mq.db")
            closed: list[bool] = []
            real_conn = sqlite3.connect(":memory:")

            class TrackConn:
                def __init__(self) -> None:
                    self.row_factory = None

                def execute(self, *_a: Any, **_kw: Any) -> Any:
                    raise sqlite3.OperationalError("boom")

                def close(self) -> None:
                    closed.append(True)
                    real_conn.close()

            with mock.patch.object(MERGE_QUEUE.sqlite3, "connect", return_value=TrackConn()):
                with self.assertRaises(sqlite3.OperationalError):
                    store.connect()
            self.assertEqual(closed, [True])

            # _bwrap_mode cache keyed by path_env.
            MERGE_QUEUE.MergeQueue._bwrap_mode_cached.cache_clear()
            with mock.patch.object(MERGE_QUEUE.shutil, "which", return_value=None) as wmock:
                MERGE_QUEUE.MergeQueue._bwrap_mode("/path/a")
                MERGE_QUEUE.MergeQueue._bwrap_mode("/path/b")
            self.assertEqual(wmock.call_count, 2)

            # drain with max_steps=0 on empty train succeeds and releases lease; unexpected error releases lease.
            bare = Path(td) / "remote.git"
            subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True)
            repo = Path(td) / "repo"
            _make_git_repo(repo)
            subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", str(bare)], check=True)
            subprocess.run(["git", "-C", str(repo), "push", "-q", "origin", "HEAD:refs/heads/main"], check=True)
            subprocess.run(["git", "-C", str(repo), "checkout", "-q", "-b", "queue-base"], check=True)
            subprocess.run(["git", "-C", str(repo), "push", "-q", "origin", "HEAD:refs/heads/queue-base"], check=True)
            mq = MERGE_QUEUE.MergeQueue(db_path=Path(td) / "mq2.db", repo_dir=repo, env=dict(os.environ))
            repo_id = mq._identity(str(bare))
            mq.init(repo=repo_id, base="queue-base", default="main", consent="c1", mode="git")
            res0 = mq.drain(repo=repo_id, base="queue-base", holder="h1", max_steps=0)
            self.assertTrue(res0["ok"])
            self.assertFalse(mq.status(repo_id, "queue-base")["lease"]["live"])

            with mock.patch.object(mq, "settle_in_flight", side_effect=RuntimeError("unexpected")):
                with self.assertRaises(RuntimeError):
                    mq.drain(repo=repo_id, base="queue-base", holder="h2")
            self.assertFalse(mq.status(repo_id, "queue-base")["lease"]["live"])

    def test_first_run_reap_uri_worker_ops_help_proof_status_and_wtree_traps(self) -> None:
        # B-P2-9: first_run.reap_groups opens DB whose path contains '#' and '?'.
        with tempfile.TemporaryDirectory() as td:
            tricky = Path(td) / "dir#1?q"
            tricky.mkdir()
            db = tricky / "runtime.db"
            LOCAL_STATE.LocalStateStore(db_path=db)
            sb = types.SimpleNamespace(state_db=db)
            rep = FIRST_RUN.reap_groups(sb, wait_s=0.1, grace_s=0.1)
            self.assertEqual(rep["survivors"], [])

        # B-P2-11: worker_ops --limit help strings match actual validators.
        buf_read = io.StringIO()
        with contextlib.redirect_stdout(buf_read), self.assertRaises(SystemExit):
            WORKER_OPS.parse_args(["read", "--help"])
        self.assertIn("positive integer", buf_read.getvalue())
        buf_list = io.StringIO()
        with contextlib.redirect_stdout(buf_list), self.assertRaises(SystemExit):
            WORKER_OPS.parse_args(["list", "--help"])
        self.assertIn("1-100", buf_list.getvalue())

        # B-P2-12: proof_status fails --check on parse error and invalid proof tier.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "skills" / "broken").mkdir(parents=True)
            (root / "skills" / "broken" / "SKILL.md").write_text("no frontmatter at all\n", encoding="utf-8")
            (root / "skills" / "badtier").mkdir(parents=True)
            (root / "skills" / "badtier" / "SKILL.md").write_text(
                "---\nname: badtier\nlicense: MIT\nmetadata:\n  proof: bogus-tier\n---\n",
                encoding="utf-8",
            )
            recs = PROOF_STATUS.collect(root / "skills", root)
            self.assertEqual(len(PROOF_STATUS.check_failures(recs)), 2)
            out_buf, err_buf = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
                rc = PROOF_STATUS.main(["--root", str(root), "--json", "--check"])
            self.assertEqual(rc, 1)
            jdata = json.loads(out_buf.getvalue())
            self.assertTrue(any(r["error"] is not None for r in jdata))

        # B-P2-13: wtree.sh separates EXIT cleanup from INT (130) and TERM (143).
        wtree_text = (ROOT / "runtime" / "scripts" / "wtree.sh").read_text(encoding="utf-8")
        self.assertIn("trap cleanup EXIT", wtree_text)
        self.assertIn("trap 'exit 130' INT", wtree_text)
        self.assertIn("trap 'exit 143' TERM", wtree_text)
        # Smoke-test wtree.sh still produces a valid 40-hex git tree hash on a real repo.
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            _make_git_repo(repo)
            proc = subprocess.run(
                ["sh", str(ROOT / "runtime" / "scripts" / "wtree.sh"), str(repo)],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(len(proc.stdout.strip()), 40)


if __name__ == "__main__":
    unittest.main(verbosity=2)
