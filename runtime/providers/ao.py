#!/usr/bin/env python3
"""ao.py — Composio Agent Orchestrator (`ComposioHQ/agent-orchestrator`, `ao`) RuntimeProvider (#588).

Maps the canonical Runtime Provider Interface (RPI) onto `ao` CLI and HTTP daemon (`127.0.0.1:3001/api/v1/*`):
  - `worker_start`:
    * Enforces `check_monotonic_profile(parent_profile, profile)`.
    * On `profile == "ro"`: dispatches via `POST /api/v1/sessions` with custom read-only
      `launch_command` from `build_harness_command(agent, "ro", worktree)` (bypassing `ao`'s
      default `permissions: "permissionless"`).
    * On `profile in ("rw", "danger")`: dispatches via `ao spawn <project> <task_id> --agent <agent> --json`.
  - `terminal_read/send` -> `GET /api/v1/sessions/{id}/output`, `POST /api/v1/sessions/{id}/send`.
  - Preserves worktree refs (`refs/ao/preserved/<id>`) before cleanup so `verify.py` can
    verify commit ancestry even after session teardown.
"""
from __future__ import annotations

import json
import subprocess
import time
import urllib.request
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


class ComposioAOProvider(RuntimeProvider):
    """RuntimeProvider adapter for Composio Agent Orchestrator (`ao`)."""

    name = "ao"

    def __init__(
        self,
        state: LocalStateStore | None = None,
        runner: Callable[..., Any] | None = None,
        *,
        db_path: str | Path | None = None,
        env: dict[str, str] | None = None,
        base_url: str | None = None,
        project: str | None = None,
        **kwargs: Any,
    ) -> None:
        self.env = dict(env) if env is not None else None
        self.state = state or LocalStateStore(db_path=db_path, env=self.env)
        self.base_url = (
            base_url
            or env_get("OPEN_FLEET_AO_URL", "ORCA_AO_URL", self.env, "http://127.0.0.1:3001")
        ).rstrip("/")
        self.project = project or env_get("OPEN_FLEET_AO_PROJECT", "ORCA_AO_PROJECT", self.env, "default-project")
        self._runner = runner or self._default_runner
        self.call_log: list[Any] = []
        self.preserved_refs: dict[str, str] = {}

    def capabilities(self) -> set[str]:
        return {"cap:core-orchestration", "cap:ao-sessions", "cap:preserved-refs"}

    def _default_runner(self, call: Any, **kwargs: Any) -> dict[str, Any]:
        if isinstance(call, list):
            proc = subprocess.run(call, capture_output=True, text=True, check=False, timeout=kwargs.get("timeout", 60))
            if proc.returncode != 0:
                raise ProviderError(
                    "ao_cli_error",
                    proc.stderr.strip() or f"ao exited with {proc.returncode}",
                    {"argv": call, "returncode": proc.returncode},
                )
            out = (proc.stdout or "").strip()
            return json.loads(out) if out.startswith("{") else {"raw": out}

        method = call.get("method", "GET")
        path = call.get("path", "/")
        body = call.get("body")
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=kwargs.get("timeout", 60)) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw.strip() else {"ok": True}
        except Exception as exc:
            raise ProviderError("ao_http_error", str(exc), {"request": call}) from exc

    def _invoke(self, call: Any, **kwargs: Any) -> dict[str, Any]:
        self.call_log.append(call)
        res = self._runner(call, **kwargs)
        if isinstance(res, dict):
            return res
        return {"result": res}

    def preserve_worktree_ref(
        self,
        session_id: str,
        head_sha: str | None = None,
        worktree_path: str | None = None,
    ) -> str:
        """Preserve the worker worktree HEAD commit under `refs/ao/preserved/<id>` before cleanup."""
        ref_name = f"refs/ao/preserved/{session_id}"
        wt_dir = worktree_path
        if not wt_dir:
            with self.state._connect() as conn:
                row = conn.execute(
                    "SELECT worktree FROM dispatches WHERE dispatch_id = ? OR session_id = ? LIMIT 1",
                    (session_id, session_id),
                ).fetchone()
                if row and row["worktree"] and row["worktree"] not in ("new-child", "new-top-level", "current", "active"):
                    wt_dir = str(row["worktree"])
        target_sha = head_sha or "HEAD"
        if wt_dir and (not head_sha or head_sha == "HEAD"):
            rev = self._invoke(["git", "-C", str(wt_dir), "rev-parse", "HEAD"])
            resolved = str(rev.get("stdout") or rev.get("sha") or rev.get("result") or "").strip()
            if resolved:
                target_sha = resolved
        if wt_dir:
            self._invoke(["git", "-C", str(wt_dir), "update-ref", ref_name, target_sha])
        else:
            self._invoke(["git", "update-ref", ref_name, target_sha])
        self.preserved_refs[session_id] = ref_name
        return ref_name

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
        project: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        cached = self.state.get_or_record_request(retry_request, "worker-start")
        if cached:
            return cached

        check_monotonic_profile(parent_profile, profile)
        proj = project or self.project
        harness = build_harness_command(agent, profile, worktree, prompt=prompt)

        if profile == "ro":
            raw = self._invoke(
                {
                    "method": "POST",
                    "path": "/api/v1/sessions",
                    "body": {
                        "project": proj,
                        "taskId": task_id,
                        "agent": agent,
                        "profile": "ro",
                        "permissions": "plan",
                        "worktree": worktree,
                        "launch_command": harness["command"],
                        "argv": harness["argv"],
                    },
                }
            )
            mechanism = "api.sessions.ro"
        else:
            argv = [
                "ao",
                "spawn",
                str(proj),
                str(task_id or "adhoc"),
                "--agent",
                str(agent),
                "--json",
            ]
            raw = self._invoke(argv)
            mechanism = "ao.spawn"

        session_id = str(raw.get("sessionId") or raw.get("id") or f"ao_{uuid.uuid4().hex[:10]}")
        handle = f"ao:{session_id}"
        effective = {
            "agent": agent,
            "profile": profile,
            "project": proj,
            "command": harness["command"],
            "argv": harness["argv"],
            "env": harness["env"],
            "profile_flag": harness["profile_flag"],
            "mechanism": mechanism,
            "sessionId": session_id,
        }
        now = time.time()
        with self.state._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dispatches(
                    dispatch_id, task_id, run_id, worktree, agent, profile,
                    terminal_handle, state, terminal_state, backend, launch_effective, session_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', 'active', 'ao', ?, ?, ?, ?)
                """,
                (session_id, task_id, run or "default", worktree, agent, profile, handle, json.dumps(effective), session_id, now, now),
            )

        res = {
            "state": "ready",
            "dispatchId": session_id,
            "agentTerminalHandle": handle,
            "worktree": worktree,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective},
            "upstream": raw,
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def terminal_read(
        self,
        *,
        terminal: str = "",
        cursor: int | None = None,
        limit: int | None = None,
        screen: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        session_id = terminal.split(":", 1)[1] if ":" in terminal else terminal
        raw = self._invoke({"method": "GET", "path": f"/api/v1/sessions/{session_id}/output", "body": None})
        return {"terminal": terminal, "sessionId": session_id, "output": raw.get("output", ""), "upstream": raw}

    def terminal_send(
        self,
        *,
        terminal: str = "",
        text: str = "",
        enter: bool = True,
        **kwargs: Any,
    ) -> dict[str, Any]:
        session_id = terminal.split(":", 1)[1] if ":" in terminal else terminal
        raw = self._invoke(
            {
                "method": "POST",
                "path": f"/api/v1/sessions/{session_id}/send",
                "body": {"text": text, "enter": enter},
            }
        )
        return {"terminal": terminal, "sessionId": session_id, "sent": True, "upstream": raw}

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        return self.terminal_read(terminal=dispatch_id, limit=limit)

    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        raw = self._invoke({"method": "GET", "path": "/api/v1/sessions", "body": None})
        return {"workers": raw.get("sessions", raw.get("items", [])), "upstream": raw}

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        raw = self._invoke({"method": "GET", "path": f"/api/v1/sessions/{dispatch_id}", "body": None})
        return {"dispatchId": dispatch_id, "worker": raw}

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        preserved_ref = self.preserve_worktree_ref(dispatch_id)
        raw = self._invoke({"method": "POST", "path": f"/api/v1/sessions/{dispatch_id}/kill", "body": {"verb": verb, "reason": reason}})
        with self.state._connect() as conn:
            conn.execute(
                "UPDATE dispatches SET state = ?, terminal_state = 'fenced', updated_at = ? WHERE dispatch_id = ?",
                (verb, time.time(), dispatch_id),
            )
        return {
            "dispatchId": dispatch_id,
            "verb": verb,
            "state": verb,
            "preservedRef": preserved_ref,
            "reason": reason,
            "upstream": raw,
        }

    def worktree_rm(self, *, selector: str = "", force: bool = False, **kwargs: Any) -> dict[str, Any]:
        ref = self.preserve_worktree_ref(selector or "worktree")
        raw = self._invoke(["ao", "session", "cleanup", str(selector), "--json"])
        return {"removed": True, "selector": selector, "preservedRef": ref, "upstream": raw}

    # --- Task DAG, Mailbox & Gates (`LocalStateStore`) ---
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
