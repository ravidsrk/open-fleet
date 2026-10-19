#!/usr/bin/env python3
"""vibe_kanban.py — Vibe-Kanban (`BloopAI/vibe-kanban`) RuntimeProvider (#589).

Maps the canonical Runtime Provider Interface (RPI) onto the Vibe-Kanban REST API:
  - Targets `/api/profiles`, `/api/task-attempts`, `/api/execution-processes/{id}/NormalizedLogs`.
  - CRITICAL SAFETY FIX #1 (`claude.rs:220-226`): Vibe-Kanban's `PermissionPolicy::Plan`
    still leaves `dangerously_skip_permissions: true` unless the executor profile explicitly
    overrides `"dangerously_skip_permissions": false`! On `profile == "ro"`, `VibeKanbanProvider`
    registers the `ORCA_RO` profile with `"dangerously_skip_permissions": False` and
    `"permission_policy": "plan"` before creating the task attempt.
  - CRITICAL SAFETY FIX #2 (`container.rs:570`): Vibe-Kanban's `spawn_exit_monitor`
    unconditionally auto-commits dirty worktree changes as `"Changes from coding agent"` on
    process exit. `inspect_or_strip_auto_commit()` strips (`git reset --soft HEAD~1`) or rejects
    that synthetic commit before `verify.py` inspects HEAD.
"""
from __future__ import annotations

import json
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

VIBE_KANBAN_AUTO_COMMIT_PREFIX = "Changes from coding agent"


class VibeKanbanProvider(RuntimeProvider):
    """RuntimeProvider adapter for Vibe-Kanban (`BloopAI/vibe-kanban`)."""

    name = "vibe-kanban"

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
            or env_get("OPEN_FLEET_VIBE_KANBAN_URL", "ORCA_VIBE_KANBAN_URL", self.env, "http://127.0.0.1:3100")
        ).rstrip("/")
        self._runner = runner or self._default_runner
        self.call_log: list[dict[str, Any]] = []

    def capabilities(self) -> set[str]:
        return {"cap:core-orchestration", "cap:vibe-kanban-attempts", "cap:normalized-logs"}

    def _default_runner(self, req: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        method = req.get("method", "GET")
        path = req.get("path", "/")
        body = req.get("body")
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        http_req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method=method,
        )
        try:
            with urllib.request.urlopen(http_req, timeout=kwargs.get("timeout", 60)) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw.strip() else {"ok": True}
        except Exception as exc:
            raise ProviderError("vibe_kanban_http_error", str(exc), {"request": req}) from exc

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        req = {"method": method, "path": path, "body": body}
        self.call_log.append(req)
        res = self._runner(req, **kwargs)
        if isinstance(res, dict):
            return res
        return {"result": res}

    def inspect_or_strip_auto_commit(
        self,
        worktree: str,
        *,
        head_subject: str | None = None,
        strip_auto_commit: bool = True,
    ) -> dict[str, Any]:
        """Detect and strip/reject Vibe-Kanban's `Changes from coding agent` auto-commit (`container.rs:570`)."""
        subj = head_subject
        if subj is None and worktree and worktree not in ("new-child", "new-top-level", "current", "active"):
            wt_p = Path(worktree)
            if (wt_p / ".git").exists():
                import subprocess

                proc = subprocess.run(
                    ["git", "-C", str(wt_p), "log", "-1", "--format=%s"],
                    capture_output=True,
                    text=True,
                )
                if proc.returncode == 0:
                    subj = proc.stdout.strip()
        subj = subj or ""
        is_auto = subj.strip().startswith(VIBE_KANBAN_AUTO_COMMIT_PREFIX)
        if not is_auto:
            return {"autoCommitDetected": False, "stripped": False, "headSubject": subj}
        if not strip_auto_commit:
            raise ProviderError(
                "unverified_auto_commit",
                f"Vibe-Kanban spawn_exit_monitor auto-commit {subj!r} is not a worker-verified commit",
                {"worktree": worktree, "headSubject": subj},
            )
        self._request(
            "POST",
            "/api/task-attempts/strip-auto-commit",
            {"worktree": worktree, "reset": "HEAD~1", "reason": "strip spawn_exit_monitor auto-commit"},
        )
        return {"autoCommitDetected": True, "stripped": True, "worktree": worktree, "resetTo": "HEAD~1"}

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
        strip_auto_commit: bool = True,
        head_subject: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        cached = self.state.get_or_record_request(retry_request, "worker-start")
        if cached:
            return cached

        check_monotonic_profile(parent_profile, profile)
        harness = build_harness_command(agent, profile, worktree, prompt=prompt)

        if profile == "ro":
            variant = "ORCA_RO"
            skip_perms = False
            perm_policy = "plan"
        else:
            variant = "ORCA_RW"
            skip_perms = True
            perm_policy = "bypass"

        profile_payload = {
            "name": variant,
            "executor": agent.upper(),
            "dangerously_skip_permissions": skip_perms,
            "permission_policy": perm_policy,
            "profile": profile,
        }
        self._request("PUT", "/api/profiles", profile_payload)

        attempt_payload = {
            "task_id": task_id,
            "executor_profile_id": {"executor": agent.upper(), "variant": variant},
            "dangerously_skip_permissions": skip_perms,
            "permission_policy": perm_policy,
            "worktree": worktree,
            "prompt": prompt or "",
            "strip_auto_commit": strip_auto_commit,
        }
        created = self._request("POST", "/api/task-attempts", attempt_payload)
        attempt_id = str(created.get("attempt_id") or created.get("id") or f"vk_{uuid.uuid4().hex[:10]}")
        proc_id = str(created.get("execution_process_id") or attempt_id)

        auto_commit_status = None
        if head_subject is not None:
            auto_commit_status = self.inspect_or_strip_auto_commit(
                worktree,
                head_subject=head_subject,
                strip_auto_commit=strip_auto_commit,
            )

        handle = f"vibe-kanban:{proc_id}"
        effective = {
            "agent": agent,
            "profile": profile,
            "variant": variant,
            "dangerously_skip_permissions": skip_perms,
            "permission_policy": perm_policy,
            "command": harness["command"],
            "argv": harness["argv"],
            "env": harness["env"],
            "profile_flag": harness["profile_flag"],
            "attemptId": attempt_id,
            "executionProcessId": proc_id,
            "stripAutoCommit": strip_auto_commit,
            "autoCommitGuard": auto_commit_status,
        }
        now = time.time()
        with self.state._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dispatches(
                    dispatch_id, task_id, run_id, worktree, agent, profile,
                    terminal_handle, state, terminal_state, backend, launch_effective, session_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', 'active', 'vibe-kanban', ?, ?, ?, ?)
                """,
                (attempt_id, task_id, run or "default", worktree, agent, profile, handle, json.dumps(effective), proc_id, now, now),
            )

        res = {
            "state": "ready",
            "dispatchId": attempt_id,
            "agentTerminalHandle": handle,
            "worktree": worktree,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective},
            "upstream": created,
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def _resolve_dispatch_meta(self, dispatch_id: str) -> tuple[str, str, bool]:
        proc_id = dispatch_id
        wt = ""
        strip_auto = True
        with self.state._connect() as conn:
            row = conn.execute(
                "SELECT worktree, session_id, launch_effective FROM dispatches WHERE dispatch_id = ?",
                (dispatch_id,),
            ).fetchone()
            if row:
                if row["session_id"]:
                    proc_id = str(row["session_id"])
                wt = str(row["worktree"] or "")
                try:
                    eff = json.loads(row["launch_effective"] or "{}")
                    if "stripAutoCommit" in eff:
                        strip_auto = bool(eff["stripAutoCommit"])
                except json.JSONDecodeError:
                    strip_auto = True
        return proc_id, wt, strip_auto

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        proc_id, _, _ = self._resolve_dispatch_meta(dispatch_id)
        raw = self._request("GET", f"/api/execution-processes/{proc_id}/NormalizedLogs")
        logs = raw.get("logs", raw.get("items", []))
        if limit and isinstance(logs, list):
            logs = logs[-limit:]
        return {"dispatchId": dispatch_id, "executionProcessId": proc_id, "source": source, "logs": logs, "upstream": raw}

    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        raw = self._request("GET", "/api/task-attempts")
        return {"workers": raw.get("attempts", raw.get("items", [])), "upstream": raw}

    def worker_show(
        self,
        *,
        dispatch_id: str = "",
        head_subject: str | None = None,
        strip_auto_commit: bool | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        _, wt, saved_strip = self._resolve_dispatch_meta(dispatch_id)
        raw = self._request("GET", f"/api/task-attempts/{dispatch_id}")
        subj = head_subject if head_subject is not None else raw.get("head_subject")
        strip_flag = saved_strip if strip_auto_commit is None else strip_auto_commit
        guard = self.inspect_or_strip_auto_commit(wt, head_subject=subj, strip_auto_commit=strip_flag)
        return {"dispatchId": dispatch_id, "worker": raw, "autoCommitGuard": guard}

    def worker_fence(
        self,
        *,
        verb: str,
        dispatch_id: str = "",
        reason: str | None = None,
        head_subject: str | None = None,
        strip_auto_commit: bool | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        _, wt, saved_strip = self._resolve_dispatch_meta(dispatch_id)
        strip_flag = saved_strip if strip_auto_commit is None else strip_auto_commit
        guard = self.inspect_or_strip_auto_commit(wt, head_subject=head_subject, strip_auto_commit=strip_flag)
        raw = self._request("POST", f"/api/task-attempts/{dispatch_id}/stop", {"verb": verb, "reason": reason})
        with self.state._connect() as conn:
            conn.execute(
                "UPDATE dispatches SET state = ?, terminal_state = 'fenced', updated_at = ? WHERE dispatch_id = ?",
                (verb, time.time(), dispatch_id),
            )
        return {"dispatchId": dispatch_id, "verb": verb, "state": verb, "reason": reason, "autoCommitGuard": guard, "upstream": raw}

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
