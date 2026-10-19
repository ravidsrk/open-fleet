#!/usr/bin/env python3
"""paperclip.py — Paperclip (`paperclipai/paperclip`) RuntimeProvider (#589).

Maps the canonical Runtime Provider Interface (RPI) onto the Paperclip REST API:
  - Targets `/api/companies/{id}/agents`, `/api/issues/{id}/checkout`, `/api/agents/{id}/wakeup`.
  - Handles `409 Conflict` on `/api/issues/{id}/checkout` by raising
    `ProviderError("task_not_startable", ...)` (atomic single-assignee lock).
  - CRITICAL SAFETY FIX: Paperclip's `claude-local` and `codex-local` adapters default
    `dangerouslySkipPermissions` and `dangerouslyBypassApprovalsAndSandbox` to `True`!
    On `profile == "ro"`, `PaperclipProvider` explicitly sets:
      * `"dangerouslySkipPermissions": False`
      * `"dangerouslyBypassApprovalsAndSandbox": False`
      * `"work_mode": "planning"`
  - On `profile == "danger"`, configures Bubblewrap (`bwrap`) isolation with
    `filesystemScope: "workspace"` and `networkScope: "deny"`.
"""
from __future__ import annotations

import json
import time
import urllib.error
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


class PaperclipProvider(RuntimeProvider):
    """RuntimeProvider adapter for Paperclip (`paperclipai/paperclip`)."""

    name = "paperclip"

    def __init__(
        self,
        state: LocalStateStore | None = None,
        runner: Callable[..., Any] | None = None,
        *,
        db_path: str | Path | None = None,
        env: dict[str, str] | None = None,
        base_url: str | None = None,
        company_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        self.env = dict(env) if env is not None else None
        self.state = state or LocalStateStore(db_path=db_path, env=self.env)
        self.base_url = (
            base_url
            or env_get("OPEN_FLEET_PAPERCLIP_URL", "ORCA_PAPERCLIP_URL", self.env, "http://127.0.0.1:4000")
        ).rstrip("/")
        self.company_id = company_id or env_get("OPEN_FLEET_PAPERCLIP_COMPANY", "ORCA_PAPERCLIP_COMPANY", self.env, "default-co")
        self._runner = runner or self._default_runner
        self.call_log: list[dict[str, Any]] = []

    def capabilities(self) -> set[str]:
        return {"cap:core-orchestration", "cap:paperclip-checkout-lock", "cap:bwrap-sandbox"}

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
        except urllib.error.HTTPError as exc:
            if exc.code == 409:
                return {"status": 409, "error": "conflict"}
            raise ProviderError("paperclip_http_error", f"HTTP {exc.code}: {exc.reason}", {"request": req}) from exc
        except Exception as exc:
            raise ProviderError("paperclip_http_error", str(exc), {"request": req}) from exc

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        req = {"method": method, "path": path, "body": body}
        self.call_log.append(req)
        res = self._runner(req, **kwargs)
        if isinstance(res, dict):
            return res
        return {"result": res}

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
        company_id: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        cached = self.state.get_or_record_request(retry_request, "worker-start")
        if cached:
            return cached

        check_monotonic_profile(parent_profile, profile)
        co_id = company_id or self.company_id
        harness = build_harness_command(agent, profile, worktree, prompt=prompt)

        if profile == "ro":
            skip_perms = False
            bypass_sandbox = False
            work_mode = "planning"
            sandbox_cfg: dict[str, Any] = {"driver": "none", "filesystemScope": "read-only", "networkScope": "allow"}
            fs_scope = "read-only"
            net_scope = "allow"
        elif profile == "rw":
            skip_perms = True
            bypass_sandbox = True
            work_mode = "execution"
            sandbox_cfg = {"driver": "worktree", "filesystemScope": "workspace", "networkScope": "allow"}
            fs_scope = "workspace"
            net_scope = "allow"
        elif profile == "danger":
            skip_perms = True
            bypass_sandbox = False
            work_mode = "execution"
            sandbox_cfg = {"driver": "bwrap", "filesystemScope": "workspace", "networkScope": "deny"}
            fs_scope = "workspace"
            net_scope = "deny"
        else:
            raise ProviderError("invalid_profile", f"unknown profile {profile!r}")

        agent_payload: dict[str, Any] = {
            "name": name or (f"pc-{task_id}" if task_id else "pc-worker"),
            "adapter": f"{agent}-local",
            "agent": agent,
            "worktree": worktree,
            "profile": profile,
            "dangerouslySkipPermissions": skip_perms,
            "dangerouslyBypassApprovalsAndSandbox": bypass_sandbox,
            "work_mode": work_mode,
            "filesystemScope": fs_scope,
            "networkScope": net_scope,
            "sandbox": sandbox_cfg,
            "command": harness["command"],
        }
        created_agent = self._request("POST", f"/api/companies/{co_id}/agents", agent_payload)
        agent_id = str(created_agent.get("agent_id") or created_agent.get("id") or f"pc_ag_{uuid.uuid4().hex[:10]}")

        issue_id = task_id or "adhoc"
        checkout_resp = self._request(
            "POST",
            f"/api/issues/{issue_id}/checkout",
            {"agent_id": agent_id, "company_id": co_id, "work_mode": work_mode},
        )
        if checkout_resp.get("status") == 409 or checkout_resp.get("code") == 409 or checkout_resp.get("conflict") is True:
            raise ProviderError(
                "task_not_startable",
                f"Paperclip issue {issue_id!r} checkout returned 409 Conflict (already locked by another agent)",
                {"issueId": issue_id, "agentId": agent_id, "response": checkout_resp},
            )

        wakeup_resp = self._request(
            "POST",
            f"/api/agents/{agent_id}/wakeup",
            {
                "issue_id": issue_id,
                "work_mode": work_mode,
                "prompt": prompt or f"Work on issue {issue_id}",
                "dangerouslySkipPermissions": skip_perms,
                "dangerouslyBypassApprovalsAndSandbox": bypass_sandbox,
                "filesystemScope": fs_scope,
                "networkScope": net_scope,
            },
        )

        handle = f"paperclip:{agent_id}"
        effective = {
            "agent": agent,
            "profile": profile,
            "companyId": co_id,
            "agentId": agent_id,
            "dangerouslySkipPermissions": skip_perms,
            "dangerouslyBypassApprovalsAndSandbox": bypass_sandbox,
            "work_mode": work_mode,
            "filesystemScope": fs_scope,
            "networkScope": net_scope,
            "sandbox": sandbox_cfg,
            "command": harness["command"],
            "argv": harness["argv"],
            "env": harness["env"],
            "profile_flag": harness["profile_flag"],
        }
        now = time.time()
        with self.state._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dispatches(
                    dispatch_id, task_id, run_id, worktree, agent, profile,
                    terminal_handle, state, terminal_state, backend, launch_effective, session_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', 'active', 'paperclip', ?, ?, ?, ?)
                """,
                (agent_id, issue_id, run or "default", worktree, agent, profile, handle, json.dumps(effective), agent_id, now, now),
            )

        res = {
            "state": "ready",
            "dispatchId": agent_id,
            "agentTerminalHandle": handle,
            "worktree": worktree,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective},
            "upstream": {"agent": created_agent, "checkout": checkout_resp, "wakeup": wakeup_resp},
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        raw = self._request("GET", f"/api/companies/{self.company_id}/agents")
        return {"workers": raw.get("agents", raw.get("items", [])), "upstream": raw}

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        raw = self._request("GET", f"/api/agents/{dispatch_id}")
        return {"dispatchId": dispatch_id, "worker": raw}

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        raw = self._request("GET", f"/api/agents/{dispatch_id}/logs?limit={int(limit)}")
        return {"dispatchId": dispatch_id, "source": source, "lines": raw.get("lines", []), "upstream": raw}

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        raw = self._request("POST", f"/api/agents/{dispatch_id}/stop", {"verb": verb, "reason": reason})
        with self.state._connect() as conn:
            conn.execute(
                "UPDATE dispatches SET state = ?, terminal_state = 'fenced', updated_at = ? WHERE dispatch_id = ?",
                (verb, time.time(), dispatch_id),
            )
        return {"dispatchId": dispatch_id, "verb": verb, "state": verb, "reason": reason, "upstream": raw}

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
