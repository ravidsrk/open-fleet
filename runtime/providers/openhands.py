#!/usr/bin/env python3
"""openhands.py — OpenHands Software Agent SDK (`openhands.agent_server`) RuntimeProvider (#584).

Maps the canonical Runtime Provider Interface (RPI) onto the OpenHands Agent Server REST API:
  - `POST /api/conversations` (`worktree: True`, `workspace_type`, `tools`, `hooks`)
  - `POST /api/conversations/{id}/run`
  - `POST /api/conversations/{id}/interrupt`
  - `GET /api/conversations/{id}/events/search`
  - Enforces `profile == "ro"` by stripping write/terminal tools
    (`tools=["glob", "grep", "planning_file_editor"]`) and installing `.openhands/hooks.json`.
  - Enforces `profile == "rw"` with `workspace_type="local"`.
  - Enforces `profile == "danger"` with `workspace_type="docker"` or `"apptainer"`.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable

from .base import (
    ProviderError,
    RuntimeProvider,
    check_monotonic_profile,
    env_get,
)
from .local_state import LocalStateStore

RO_ALLOWED_TOOLS = ["glob", "grep", "planning_file_editor"]
RO_DISABLED_TOOLS = ["terminal", "file_editor", "bash", "execute_bash"]
RW_TOOLS = ["terminal", "file_editor", "glob", "grep", "task_tracker"]


class OpenHandsProvider(RuntimeProvider):
    """RuntimeProvider adapter for OpenHands (`openhands.agent_server` REST API + CLI)."""

    name = "openhands"

    def __init__(
        self,
        state: LocalStateStore | None = None,
        runner: Callable[..., Any] | None = None,
        *,
        db_path: str | Path | None = None,
        env: dict[str, str] | None = None,
        base_url: str | None = None,
        **kwargs: Any,
    ) -> None:
        self.env = dict(env) if env is not None else None
        self.state = state or LocalStateStore(db_path=db_path, env=self.env)
        self.base_url = (
            base_url
            or env_get("OPEN_FLEET_OPENHANDS_URL", "ORCA_OPENHANDS_URL", self.env, "http://127.0.0.1:3000")
        ).rstrip("/")
        self._runner = runner or self._default_runner
        self.call_log: list[dict[str, Any]] = []

    def capabilities(self) -> set[str]:
        return {"cap:core-orchestration", "cap:container-sandbox", "cap:event-stream"}

    def _default_runner(self, req: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        method = req.get("method", "GET")
        path = req.get("path", "/")
        body = req.get("body")
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        http_req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(http_req, timeout=kwargs.get("timeout", 60)) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw.strip() else {"ok": True}
        except Exception as exc:
            raise ProviderError("openhands_http_error", str(exc), {"request": req}) from exc

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        req = {"method": method, "path": path, "body": body}
        self.call_log.append(req)
        res = self._runner(req, **kwargs)
        if isinstance(res, dict):
            return res
        return {"result": res}

    def _install_ro_hooks(self, worktree: str) -> dict[str, Any]:
        hook_cfg = {
            "PreToolUse": [
                {
                    "matcher": "terminal|file_editor|execute_bash|bash",
                    "action": "deny",
                    "reason": "OpenHands PROFILE=ro forbids terminal and file_editor mutations",
                }
            ]
        }
        if worktree and worktree not in ("new-child", "current", "active") and os.path.isdir(worktree):
            hooks_dir = Path(worktree) / ".openhands"
            hooks_dir.mkdir(parents=True, exist_ok=True)
            (hooks_dir / "hooks.json").write_text(json.dumps(hook_cfg, indent=2), encoding="utf-8")
        return hook_cfg

    def worker_start(
        self,
        *,
        task_id: str = "",
        worktree: str = "new-child",
        agent: str = "openhands",
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
        workspace_type: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        cached = self.state.get_or_record_request(retry_request, "worker-start")
        if cached:
            return cached

        check_monotonic_profile(parent_profile, profile)
        resolved_prompt = prompt
        if not resolved_prompt and task_id:
            with self.state._connect() as conn:
                t_row = conn.execute("SELECT spec, title FROM tasks WHERE id = ?", (task_id,)).fetchone()
                if t_row:
                    resolved_prompt = str(t_row["spec"] or t_row["title"] or "")

        hooks_cfg: dict[str, Any] = {}
        if profile == "ro":
            ws_type = "local"
            tools = list(RO_ALLOWED_TOOLS)
            disabled_tools = list(RO_DISABLED_TOOLS)
            hooks_cfg = self._install_ro_hooks(worktree)
            profile_flag = "tools=glob,grep,planning_file_editor"
        elif profile == "rw":
            ws_type = "local"
            tools = list(RW_TOOLS)
            disabled_tools = []
            profile_flag = "workspace_type=local"
        elif profile == "danger":
            ws_type = (
                workspace_type
                or on_env
                or env_get("OPEN_FLEET_OPENHANDS_WORKSPACE_TYPE", "ORCA_OPENHANDS_WORKSPACE_TYPE", self.env, "docker")
            )
            if ws_type not in ("docker", "apptainer"):
                raise ProviderError(
                    "invalid_workspace_type",
                    f"OpenHands profile='danger' requires workspace_type in ('docker', 'apptainer'), got {ws_type!r}",
                )
            tools = list(RW_TOOLS)
            disabled_tools = []
            profile_flag = f"workspace_type={ws_type}"
        else:
            raise ProviderError("invalid_profile", f"unknown profile {profile!r}")

        conv_payload: dict[str, Any] = {
            "task_id": task_id,
            "name": name or (f"oh-{task_id}" if task_id else "oh-worker"),
            "worktree": True,
            "worktree_path": worktree,
            "workspace_type": ws_type,
            "profile": profile,
            "read_only": profile == "ro",
            "tools": tools,
            "disabled_tools": disabled_tools,
            "hooks": hooks_cfg,
            "initial_prompt": resolved_prompt or "",
        }
        created = self._request("POST", "/api/conversations", conv_payload)
        conv_id = str(created.get("conversation_id") or created.get("id") or f"oh_conv_{uuid.uuid4().hex[:10]}")
        run_resp = self._request("POST", f"/api/conversations/{conv_id}/run", {"task_id": task_id, "profile": profile})

        handle = f"openhands:{conv_id}"
        effective = {
            "agent": agent,
            "profile": profile,
            "workspace_type": ws_type,
            "worktree": True,
            "tools": tools,
            "disabled_tools": disabled_tools,
            "hooks": hooks_cfg,
            "profile_flag": profile_flag,
            "conversationId": conv_id,
        }
        now = time.time()
        with self.state._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dispatches(
                    dispatch_id, task_id, run_id, worktree, agent, profile,
                    terminal_handle, state, terminal_state, backend, launch_effective, session_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', 'active', 'openhands', ?, ?, ?, ?)
                """,
                (conv_id, task_id, run or "default", worktree, agent, profile, handle, json.dumps(effective), conv_id, now, now),
            )

        res = {
            "state": "ready",
            "dispatchId": conv_id,
            "agentTerminalHandle": handle,
            "worktree": worktree,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective},
            "upstream": {"conversation": created, "run": run_resp},
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        raw = self._request("GET", "/api/conversations")
        return {"workers": raw.get("conversations", raw.get("items", [])), "upstream": raw}

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        raw = self._request("GET", f"/api/conversations/{dispatch_id}")
        return {"dispatchId": dispatch_id, "worker": raw}

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        raw = self._request("GET", f"/api/conversations/{dispatch_id}/events/search?limit={int(limit)}")
        return {"dispatchId": dispatch_id, "source": source, "events": raw.get("events", []), "upstream": raw}

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        raw = self._request("POST", f"/api/conversations/{dispatch_id}/interrupt", {"reason": reason, "verb": verb})
        with self.state._connect() as conn:
            conn.execute(
                "UPDATE dispatches SET state = ?, terminal_state = 'fenced', updated_at = ? WHERE dispatch_id = ?",
                (verb, time.time(), dispatch_id),
            )
        return {"dispatchId": dispatch_id, "verb": verb, "state": verb, "reason": reason, "upstream": raw}

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
