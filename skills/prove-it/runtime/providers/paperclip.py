#!/usr/bin/env python3
"""paperclip.py — Paperclip (`paperclipai/paperclip`) RuntimeProvider (#589).

Source-verified against `server/src/routes` + `packages/shared/src/validators` +
`packages/adapters/{claude,codex}-local` (default `http://127.0.0.1:3100/api`; optional
bearer key from `OPEN_FLEET_PAPERCLIP_API_KEY`).

  - `worker_start`:
      1. `POST /api/companies/{co}/agents {name, role, adapterType: claude_local|codex_local,
         runner: "legacy", adapterConfig}`. `runner:"legacy"` is load-bearing: with the
         default `auto` runner the server rewrites the agent to `paperclip_runner` and DELETES
         `dangerouslySkipPermissions`. The permission flags live INSIDE `adapterConfig`, and
         both adapters default them to TRUE when omitted (`claude-local execute.ts`,
         `codex-local index.ts`), so every profile sets them explicitly.
         `engine:"cli"` is load-bearing too: both adapters default to the ACP engine
         (`acp.ts normalizeEngine`), whose `permissionMode` defaults to `approve-all`
         (`acpx-engine/constants.ts`) and IGNORES `dangerouslySkipPermissions`, so without it a
         `PROFILE=ro` agent would have every tool approved. Every profile pins the CLI engine
         (the lane that honours the permission flag and the worktree deny hooks); ro also sets
         ACP `permissionMode:"approve-reads"` so a server that rewrote the engine back to ACP
         would still not approve writes.
      2. `GET /api/agents/{id}` read-back: the adapter type must still be the legacy one and
         EVERY requested `adapterConfig` field (engine, permission flag, permissionMode, sandbox
         scopes) must read back exactly; otherwise the agent is deleted and the start fails closed.
      3. `POST /api/companies/{co}/issues {title, description=<task spec>, status:"todo",
         workMode}` — the issue description is how Paperclip hands an agent its task
         (`heartbeat/task-context.ts`); `workMode:"planning"` for ro.
      4. `POST /api/issues/{id}/checkout {agentId, expectedStatuses:["todo"]}` — the atomic
         lock; a board checkout wakes the assignee. A 409 deletes the just-created agent
         (no orphan) and raises `task_not_startable`.
  - `PROFILE=danger` adds the bubblewrap fields Paperclip actually reads from
    `adapterConfig` (`engine:"cli"`, `filesystemScope:"workspace"`, `networkScope:"deny"`).
  - Logs: `GET /api/heartbeat-runs/{runId}/log` (NDJSON `content`); fence: `pause`,
    `issues/{id}/release`.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from ._external import ExternalDispatchMixin, env_lookup, http_json, real_worktree
from .base import (
    ProviderError,
    RuntimeProvider,
    check_monotonic_profile,
    env_get,
    fence_state,
    normalize_read,
    normalize_show,
    require_id,
)
from .local_state import LocalStateStore
from .posix import install_worktree_hooks

PAPERCLIP_ADAPTERS = {"claude": "claude_local", "codex": "codex_local"}
# The harnesses worker_start accepts (capabilities.json `supported_harnesses` mirrors this).
SUPPORTED_HARNESSES = tuple(PAPERCLIP_ADAPTERS)
PAPERCLIP_SANDBOX = {"engine": "cli", "filesystemScope": "workspace", "networkScope": "deny"}
# The only engine whose permission semantics are the flags below (ACP defaults to approve-all).
PAPERCLIP_ENGINE = "cli"
# ACP permission mode for ro: defence in depth should the engine ever be rewritten to ACP.
PAPERCLIP_RO_ACP_PERMISSION_MODE = "approve-reads"


def _adapter_config(agent: str, profile: str, cwd: str | None) -> dict[str, Any]:
    cfg: dict[str, Any] = {"engine": PAPERCLIP_ENGINE}
    if agent == "claude":
        cfg["dangerouslySkipPermissions"] = profile != "ro"
    else:
        cfg["dangerouslyBypassApprovalsAndSandbox"] = profile != "ro"
    if profile == "ro":
        cfg["permissionMode"] = PAPERCLIP_RO_ACP_PERMISSION_MODE
    if cwd:
        cfg["cwd"] = cwd
    if profile == "danger":
        cfg.update(PAPERCLIP_SANDBOX)
    return cfg


class PaperclipProvider(ExternalDispatchMixin, RuntimeProvider):
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
            or env_get("OPEN_FLEET_PAPERCLIP_URL", "ORCA_PAPERCLIP_URL", self.env, "http://127.0.0.1:3100")
        ).rstrip("/")
        self.company_id = company_id or env_get("OPEN_FLEET_PAPERCLIP_COMPANY", "ORCA_PAPERCLIP_COMPANY", self.env, "")
        self._runner = runner or self._default_runner
        self.call_log: list[dict[str, Any]] = []

    def _default_runner(self, req: dict[str, Any], **kwargs: Any) -> Any:
        key = env_lookup(self.env, "OPEN_FLEET_PAPERCLIP_API_KEY", "ORCA_PAPERCLIP_API_KEY")
        headers = {"Authorization": f"Bearer {key}"} if key else None
        return http_json(self.base_url, req.get("method", "GET"), req.get("path", "/"), req.get("body"),
                         provider="paperclip", timeout=kwargs.get("timeout", 60), headers=headers,
                         allow_empty=req.get("method") == "DELETE")

    def _request(self, method: str, path: str, body: Any = None) -> Any:
        req = {"method": method, "path": path, "body": body}
        self.call_log.append(req)
        res = self._runner(req)
        if isinstance(res, dict) and res.get("status") in (409, 422) and "id" not in res:
            raise ProviderError("paperclip_http_error", f"{method} {path} -> HTTP {res['status']}",
                                {"status": res["status"], "response": res, "path": path})
        return res

    def _company(self, company_id: str | None) -> str:
        co = company_id or self.company_id
        if not co:
            raise ProviderError("missing_company", "paperclip: set OPEN_FLEET_PAPERCLIP_COMPANY to the company id")
        return co

    def _delete_agent(self, agent_id: str) -> dict[str, Any]:
        try:
            self._request("DELETE", f"/api/agents/{agent_id}")
            return {"agentDeleted": agent_id}
        except ProviderError as exc:
            return {"orphanAgent": agent_id, "deleteError": exc.code}

    def _verify_agent(self, agent_id: str, adapter_type: str, expected: dict[str, Any]) -> dict[str, Any]:
        back = self._request("GET", f"/api/agents/{agent_id}")
        cfg = back.get("adapterConfig") if isinstance(back, dict) else None
        problems: list[str] = []
        if not isinstance(back, dict) or back.get("adapterType") != adapter_type:
            problems.append(f"adapterType is {back.get('adapterType') if isinstance(back, dict) else None!r}, want {adapter_type!r}")
        if not isinstance(cfg, dict):
            problems.append("adapterConfig not readable")
        else:
            for k, v in expected.items():
                if k == "cwd":
                    continue
                if type(cfg.get(k)) is not type(v) or cfg.get(k) != v:
                    problems.append(f"adapterConfig.{k} is {cfg.get(k)!r}, want {v!r}")
        if problems:
            cleanup = self._delete_agent(agent_id)
            raise ProviderError(
                "permissions_unverified",
                "paperclip: agent did not read back with the requested permissions: " + "; ".join(problems),
                {"agentId": agent_id, **cleanup},
            )
        return cfg

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
        adapter_type = PAPERCLIP_ADAPTERS.get(agent)
        if not adapter_type:
            raise ProviderError("unsupported_agent", f"paperclip: no local adapter for {agent!r} (want {sorted(PAPERCLIP_ADAPTERS)})")
        if profile == "ro" and agent != "claude":
            raise ProviderError("unsupported_profile", "paperclip: only claude_local has a verified read-only configuration")
        co = self._company(company_id)
        task_prompt = self.resolve_task_prompt(task_id, prompt)
        cwd = real_worktree(worktree)
        if profile == "ro" and not cwd:
            raise ProviderError("worktree_required", "paperclip: PROFILE=ro needs an existing --worktree so deny hooks precede the agent")
        hooks = install_worktree_hooks(cwd, agent, profile) if cwd else None

        adapter_cfg = _adapter_config(agent, profile, cwd)
        agent_body = {
            "name": name or (f"of-{task_id}" if task_id else "of-worker"),
            "role": "engineer",
            "adapterType": adapter_type,
            "runner": "legacy",
            "adapterConfig": adapter_cfg,
        }
        created = self._request("POST", f"/api/companies/{co}/agents", agent_body)
        agent_id = require_id(created, "id", provider="paperclip", what="agent id")
        read_back = self._verify_agent(agent_id, adapter_type, adapter_cfg)

        try:
            issue = self._request(
                "POST",
                f"/api/companies/{co}/issues",
                {
                    "title": (task_prompt.strip().splitlines()[0][:200] or task_id or "open-fleet task"),
                    "description": task_prompt,
                    "status": "todo",
                    "workMode": "planning" if profile == "ro" else "standard",
                },
            )
            issue_id = require_id(issue, "id", provider="paperclip", what="issue id")
            checkout = self._request("POST", f"/api/issues/{issue_id}/checkout", {"agentId": agent_id, "expectedStatuses": ["todo"]})
        except ProviderError as exc:
            cleanup = self._delete_agent(agent_id)
            if exc.data.get("status") == 409:
                raise ProviderError(
                    "task_not_startable",
                    "paperclip: issue checkout returned 409 Conflict (locked by another agent)",
                    {"agentId": agent_id, "response": exc.data.get("response"), **cleanup},
                ) from exc
            exc.data.update(cleanup)
            raise

        run_id = None
        try:
            execu = self._request("GET", f"/api/issues/{issue_id}/execution")
            run_id = execu.get("runId") if isinstance(execu, dict) else None
        except ProviderError:
            run_id = None

        handle = f"paperclip:{agent_id}"
        effective = {
            "agent": agent,
            "profile": profile,
            "companyId": co,
            "agentId": agent_id,
            "issueId": issue_id,
            "runId": run_id,
            "adapterType": adapter_type,
            "adapterConfig": adapter_cfg,
            "adapterConfigReadBack": read_back,
            "hooks": hooks,
        }
        self._record_dispatch(
            dispatch_id=agent_id, task_id=task_id, run=run, worktree=cwd or "", agent=agent,
            profile=profile, handle=handle, effective=effective, session_id=issue_id,
        )
        res = {
            "state": "ready",
            "dispatchId": agent_id,
            "agentTerminalHandle": handle,
            "worktree": cwd,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective},
            "upstream": {"agent": created, "issue": issue, "checkout": checkout},
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def _run_id(self, row: Any) -> str:
        eff = self._effective(row)
        if eff.get("runId"):
            return str(eff["runId"])
        execu = self._request("GET", f"/api/issues/{eff.get('issueId') or row['session_id']}/execution")
        run_id = execu.get("runId") if isinstance(execu, dict) else None
        if not run_id:
            raise ProviderError("run_not_found", f"paperclip: no heartbeat run yet for agent {row['dispatch_id']!r}")
        self._patch_dispatch(row["dispatch_id"], effective={"runId": run_id})
        return str(run_id)

    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        return self._list_local(run=kwargs.get("run"), task=kwargs.get("task"), limit=kwargs.get("limit"))

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        row = self._dispatch_row(dispatch_id)
        raw = self._request("GET", f"/api/agents/{dispatch_id}")
        return normalize_show(
            row["dispatch_id"], row["state"], task_id=row["task_id"], terminal_state=row["terminal_state"],
            handle=row["terminal_handle"], worktree=row["worktree"],
            stage=str((raw or {}).get("status") or row["state"]) if isinstance(raw, dict) else row["state"], raw=raw,
        )

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        row = self._dispatch_row(dispatch_id)
        run_id = self._run_id(row)
        raw = self._request("GET", f"/api/heartbeat-runs/{run_id}/log")
        content = raw.get("content") if isinstance(raw, dict) else None
        if not isinstance(content, str):
            raise ProviderError("paperclip_bad_response", "paperclip: run log has no content", {"response": raw})
        lines: list[str] = []
        for ln in content.splitlines():
            try:
                rec = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and isinstance(rec.get("chunk"), str):
                lines.extend(rec["chunk"].splitlines())
        return normalize_read(
            "terminal",
            lines=lines[-int(limit):] if limit else lines,
            cursor=raw.get("nextOffset"),
            handle=row["terminal_handle"],
            fallback_reason="paperclip exposes the heartbeat run log only" if source == "transcript" else None,
        )

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        fence_state(verb)
        row = self._dispatch_row(dispatch_id)
        upstream: dict[str, Any] = {}
        if verb != "retain":
            upstream["pause"] = self._request("POST", f"/api/agents/{dispatch_id}/pause")
        if verb == "release":
            issue_id = self._effective(row).get("issueId") or row["session_id"]
            upstream["release"] = self._request("POST", f"/api/issues/{issue_id}/release")
        new_state, term_state = self._fence_local(dispatch_id, verb)
        return {"dispatchId": dispatch_id, "verb": verb, "state": new_state, "terminalState": term_state,
                "reason": reason, "upstream": upstream or None}

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
