#!/usr/bin/env python3
"""superset.py — Superset (`superset-sh/superset`) CLI/Desktop RuntimeProvider (#582).

Maps the canonical Runtime Provider Interface (RPI) onto Superset CLI/Desktop:
  - `worktree_list/show/create/rm` -> `superset workspaces list/get/create/delete --local --json`
  - `worker_start`:
    * `profile == "ro"`: NEVER invokes `superset agents create` (whose `buildAgentCommand`
      unconditionally injects YOLO flags). Instead routes through
      `superset terminals create --workspace <id> --title <name> --command <ro_cmd> --json`
      using `build_harness_command(agent, "ro", worktree)`.
    * `profile == "rw"`: invokes `superset agents create --workspace <id> --agent <agent> --json`
      and records `launch.effective.profile_flag`.
    * `profile == "danger"`: requires `OPEN_FLEET_SANDBOX_RECIPE` / `ORCA_SANDBOX_RECIPE`
      and passes `--environment <recipe>` for Superset Cloud Sandbox execution.
  - `worker_list/show/read/fence` -> `superset snapshot --json`, `superset agents explain --json`,
    `superset agents read --json`, `superset terminals kill --json`.
  - Task DAG, typed mailbox, and HITL gates delegate to `LocalStateStore`.
"""
from __future__ import annotations

import json
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from .base import (
    ProviderError,
    RuntimeProvider,
    build_harness_command,
    check_monotonic_profile,
    env_get,
)
from .local_state import LocalStateStore


class SupersetProvider(RuntimeProvider):
    """RuntimeProvider adapter for Superset (`superset` CLI / Desktop local & cloud workspaces)."""

    name = "superset"

    def __init__(
        self,
        state: LocalStateStore | None = None,
        runner: Callable[..., Any] | None = None,
        *,
        db_path: str | Path | None = None,
        env: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> None:
        self.env = dict(env) if env is not None else None
        self.state = state or LocalStateStore(db_path=db_path, env=self.env)
        self._runner = runner or self._default_runner
        self.call_log: list[Any] = []

    def capabilities(self) -> set[str]:
        return {"cap:core-orchestration", "cap:superset-workspaces", "cap:cloud-sandbox"}

    def _default_runner(self, argv: list[str], **kwargs: Any) -> dict[str, Any]:
        proc = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=kwargs.get("timeout", 60))
        if proc.returncode != 0:
            raise ProviderError(
                "superset_cli_error",
                proc.stderr.strip() or f"superset exited with {proc.returncode}",
                {"argv": argv, "returncode": proc.returncode},
            )
        out = (proc.stdout or "").strip()
        if not out:
            return {"ok": True}
        try:
            data = json.loads(out)
            return data if isinstance(data, dict) else {"items": data}
        except json.JSONDecodeError:
            return {"raw": out}

    def _run(self, argv: list[str], **kwargs: Any) -> dict[str, Any]:
        self.call_log.append(list(argv))
        res = self._runner(list(argv), **kwargs)
        if isinstance(res, dict):
            return res
        return {"result": res}

    # --- Worktree / Workspace operations ---
    def worktree_list(self, *, repo: str | None = None, limit: int | None = None, **kwargs: Any) -> dict[str, Any]:
        argv = ["superset", "workspaces", "list", "--local", "--json"]
        if repo:
            argv += ["--repo", str(repo)]
        if limit is not None:
            argv += ["--limit", str(limit)]
        raw = self._run(argv)
        workspaces = raw.get("workspaces", raw.get("items", []))
        return {"worktrees": workspaces, "upstream": raw}

    def worktree_show(self, *, selector: str = "current", **kwargs: Any) -> dict[str, Any]:
        argv = ["superset", "workspaces", "get", str(selector), "--local", "--json"]
        raw = self._run(argv)
        return {"worktree": raw.get("workspace", raw), "upstream": raw}

    def worktree_create(
        self,
        *,
        name: str = "worker",
        base: str | None = None,
        repo: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        argv = ["superset", "workspaces", "create", "--name", str(name), "--local", "--json"]
        if base:
            argv += ["--base", str(base)]
        if repo:
            argv += ["--repo", str(repo)]
        raw = self._run(argv)
        ws_id = raw.get("id") or raw.get("workspaceId") or name
        path = raw.get("path") or raw.get("worktree") or name
        return {"worktree": {"id": ws_id, "name": name, "path": path, "base": base}, "upstream": raw}

    def worktree_rm(self, *, selector: str = "", force: bool = False, **kwargs: Any) -> dict[str, Any]:
        argv = ["superset", "workspaces", "delete", str(selector), "--local", "--json"]
        if force:
            argv.append("--force")
        raw = self._run(argv)
        return {"removed": True, "selector": selector, "upstream": raw}

    # --- Task DAG, Mailbox & Gates (LocalStateStore) ---
    def task_create(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_create(**kwargs)

    def task_update(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_update(**kwargs)

    def task_list(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_list(**kwargs)

    def send_message(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.send_message(**kwargs)

    def check_messages(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.check_messages(**kwargs)

    def reply_message(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.reply_message(**kwargs)

    def ask_human(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.ask_human(**kwargs)

    def request_show(self, request_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.state.request_show(request_id)

    # --- Worker lifecycle ---
    def worker_start(
        self,
        *,
        task_id: str = "",
        worktree: str = "new-child",
        agent: str = "claude",
        name: str | None = None,
        run: str | None = None,
        sender: str | None = None,
        timeout_ms: int | None = None,
        on_env: str | None = None,
        retry_of: str | None = None,
        retry_request: str | None = None,
        profile: str = "rw",
        parent_profile: str | None = None,
        prompt: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        cached = self.state.get_or_record_request(retry_request, "worker-start")
        if cached:
            return cached

        check_monotonic_profile(parent_profile, profile)
        workspace_id = worktree or "new-child"
        worker_title = name or (f"worker-{task_id}" if task_id else f"worker-{uuid.uuid4().hex[:6]}")
        harness = build_harness_command(agent, profile, workspace_id, prompt=prompt)

        recipe: str | None = None
        if profile == "ro":
            # Superset `agents create` injects YOLO flags unconditionally; route `ro` via `terminals create`.
            argv = [
                "superset",
                "terminals",
                "create",
                "--workspace",
                str(workspace_id),
                "--title",
                worker_title,
                "--command",
                harness["command"],
                "--json",
            ]
            mechanism = "terminals.create"
        elif profile == "rw":
            argv = [
                "superset",
                "agents",
                "create",
                "--workspace",
                str(workspace_id),
                "--agent",
                str(agent),
                "--json",
            ]
            mechanism = "agents.create"
        elif profile == "danger":
            recipe = (
                on_env
                or kwargs.get("environment")
                or env_get("OPEN_FLEET_SANDBOX_RECIPE", "ORCA_SANDBOX_RECIPE", self.env, "")
            )
            if not recipe:
                raise ProviderError(
                    "missing_sandbox_recipe",
                    "Superset profile='danger' requires OPEN_FLEET_SANDBOX_RECIPE or ORCA_SANDBOX_RECIPE",
                )
            argv = [
                "superset",
                "agents",
                "create",
                "--workspace",
                str(workspace_id),
                "--agent",
                str(agent),
                "--environment",
                str(recipe),
                "--json",
            ]
            mechanism = "agents.create+cloud"
        else:
            raise ProviderError("invalid_profile", f"unknown profile {profile!r}")

        raw = self._run(argv)
        dispatch_id = str(raw.get("dispatchId") or raw.get("id") or f"sup_{uuid.uuid4().hex[:10]}")
        handle = str(raw.get("terminalId") or raw.get("agentTerminalHandle") or f"sup_term_{dispatch_id}")
        effective = {
            "agent": agent,
            "profile": profile,
            "command": harness["command"],
            "argv": harness["argv"],
            "env": harness["env"],
            "profile_flag": harness["profile_flag"],
            "mechanism": mechanism,
            "environment": recipe,
        }
        now = time.time()
        with self.state._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dispatches(
                    dispatch_id, task_id, run_id, worktree, agent, profile,
                    terminal_handle, state, terminal_state, backend, launch_effective, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', 'active', 'superset', ?, ?, ?)
                """,
                (dispatch_id, task_id, run or "default", workspace_id, agent, profile, handle, json.dumps(effective), now, now),
            )

        res = {
            "state": "ready",
            "dispatchId": dispatch_id,
            "agentTerminalHandle": handle,
            "worktree": workspace_id,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective},
            "upstream": raw,
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def worker_list(
        self,
        *,
        run: str | None = None,
        task: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw = self._run(["superset", "snapshot", "--json"])
        workers = raw.get("agents", raw.get("workers", []))
        return {"workers": workers, "snapshot": raw}

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        raw = self._run(["superset", "agents", "explain", str(dispatch_id), "--json"])
        return {"dispatchId": dispatch_id, "worker": raw}

    def worker_read(
        self,
        *,
        dispatch_id: str = "",
        source: str = "transcript",
        limit: int = 50,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw = self._run(["superset", "agents", "read", str(dispatch_id), "--limit", str(limit), "--json"])
        return {"dispatchId": dispatch_id, "source": source, "lines": raw.get("lines", []), "upstream": raw}

    def worker_fence(
        self,
        *,
        verb: str,
        dispatch_id: str = "",
        reason: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw = self._run(["superset", "terminals", "kill", str(dispatch_id), "--json"])
        with self.state._connect() as conn:
            conn.execute(
                "UPDATE dispatches SET state = ?, terminal_state = 'fenced', updated_at = ? WHERE dispatch_id = ?",
                (verb, time.time(), dispatch_id),
            )
        return {"dispatchId": dispatch_id, "verb": verb, "state": verb, "reason": reason, "upstream": raw}
