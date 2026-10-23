#!/usr/bin/env python3
"""vibe_kanban.py — Vibe-Kanban (`BloopAI/vibe-kanban`) RuntimeProvider (#589).

Source-verified against `crates/server/src/routes` (workspaces / sessions / execution
processes — the old `/api/task-attempts` routes are gone):

  - Base URL: `OPEN_FLEET_VIBE_KANBAN_URL`, else the port file
    `<tmp>/vibe-kanban/vibe-kanban.port` (`main_port`). Replies are `{success, data, message}`.
  - `worker_start` -> `POST /api/workspaces/start {name, repos:[{repo_id, target_branch}],
    executor_config:{executor, variant, permission_policy}, prompt=<task spec>}`; ids are
    `data.workspace.id` / `data.execution_process.id`. The worktree is the repo folder inside
    `GET /api/workspaces/{id}` -> `container_ref` (null until the container exists).
  - SAFETY #1 (`executors/claude.rs`): `dangerously_skip_permissions` is emitted
    independently of `plan`/`approvals`, and the built-in DEFAULT variant sets it true. For
    `PROFILE=ro` the adapter merges an `ORCA_RO` variant
    (`{"CLAUDE_CODE": {"plan": true, "dangerously_skip_permissions": false}}`) into the full
    profiles document (`GET /api/profiles` -> `data.content`; `PUT /api/profiles` takes the raw
    ExecutorConfigs JSON), READS IT BACK and refuses to start unless the flag is false.
    Only `CLAUDE_CODE` has a verified read-only variant.
  - SAFETY #2 (`local-deployment/src/container.rs`): when a coding-agent process exits
    Completed/0 the exit monitor commits every dirty repo (`git commit -m <turn summary |
    "Commit changes from coding agent for workspace <id>">`) and there is no setting to turn
    it off. The guard runs AFTER the process has exited: stop, wait for a terminal status,
    then inspect HEAD of the REAL worktree; a commit whose committer time is not before the
    process' `completed_at` (or whose subject is a known auto-commit message) is rejected by
    default. Upstream marks the process `completed` BEFORE `try_commit_changes` runs and may
    then start a cleanup script that commits again (`container.rs spawn_exit_monitor`), so a
    `completed` process is only inspected once the worktree is clean AND HEAD has been stable
    for `settle_polls` consecutive observations; a tree that stays dirty or a HEAD that keeps
    moving is `auto_commit_pending` (refused). Only when explicitly allowed
    (`strip_auto_commit=True` or `OPEN_FLEET_VIBE_KANBAN_STRIP_AUTO_COMMIT=1`) are the
    auto-commits stripped locally with `git -C <wt> reset --soft HEAD~1` (one at a time, HEAD
    re-verified to equal the parent each time).
  - `worker-stop` reports the stop itself as success and the guard verdict as data
    (`autoCommitGuard.releasable`); `worker-release` refuses whenever the guard does.
  - Logs are WebSocket-only (`/normalized-logs/ws`), so `worker_read` fails closed.
"""
from __future__ import annotations

import json
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from ._external import ExternalDispatchMixin, coerce_output, env_flag, env_lookup, http_json, real_worktree, run_cli
from .base import (
    ProviderError,
    RuntimeProvider,
    check_monotonic_profile,
    fence_state,
    normalize_show,
    require_id,
)
from .local_state import LocalStateStore

VIBE_AUTO_COMMIT_PREFIXES = (
    "Commit changes from coding agent for workspace ",
    "Cleanup script changes for workspace ",
    "Changes from execution process ",
    "Changes from coding agent",
)
VIBE_EXECUTORS = {
    "claude": "CLAUDE_CODE",
    "codex": "CODEX",
    "opencode": "OPENCODE",
    "gemini": "GEMINI",
    "cursor": "CURSOR_AGENT",
    "droid": "DROID",
}
# The harnesses worker_start accepts (capabilities.json `supported_harnesses` mirrors this).
SUPPORTED_HARNESSES = tuple(VIBE_EXECUTORS)
ORCA_RO_VARIANT = "ORCA_RO"
# Upper bound on auto-commits stripped in one guard pass (agent turn + cleanup script).
VIBE_MAX_STRIPPED_COMMITS = 4
VIBE_TERMINAL_STATUSES = ("completed", "failed", "killed")
# Kept for callers importing the old name.
VIBE_KANBAN_AUTO_COMMIT_PREFIX = "Changes from coding agent"


def _parse_ts(value: Any) -> float | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


class VibeKanbanProvider(ExternalDispatchMixin, RuntimeProvider):
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
        git_runner: Callable[..., Any] | None = None,
        sleep: Callable[[float], Any] | None = None,
        exit_timeout_s: float = 60.0,
        settle_polls: int = 3,
        settle_max_polls: int = 30,
        settle_interval_s: float = 1.0,
        **kwargs: Any,
    ) -> None:
        self.env = dict(env) if env is not None else None
        self.state = state or LocalStateStore(db_path=db_path, env=self.env)
        self._base_url = (base_url or env_lookup(self.env, "OPEN_FLEET_VIBE_KANBAN_URL", "ORCA_VIBE_KANBAN_URL")).rstrip("/")
        self._runner = runner or self._default_runner
        self._git = git_runner or (lambda argv: run_cli(argv, provider="git", timeout=60))
        self._sleep = sleep or time.sleep
        self.exit_timeout_s = float(exit_timeout_s)
        self.settle_polls = max(2, int(settle_polls))
        self.settle_max_polls = max(self.settle_polls, int(settle_max_polls))
        self.settle_interval_s = float(settle_interval_s)
        self.call_log: list[dict[str, Any]] = []

    # --- transport -------------------------------------------------------------------
    @property
    def base_url(self) -> str:
        if self._base_url:
            return self._base_url
        port_file = Path(tempfile.gettempdir()) / "vibe-kanban" / "vibe-kanban.port"
        try:
            port = int(json.loads(port_file.read_text(encoding="utf-8"))["main_port"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ProviderError(
                "vibe_kanban_unreachable",
                f"vibe-kanban: set OPEN_FLEET_VIBE_KANBAN_URL (no readable port file at {port_file})",
            ) from exc
        return f"http://127.0.0.1:{port}"

    def _default_runner(self, req: dict[str, Any], **kwargs: Any) -> Any:
        return http_json(self.base_url, req.get("method", "GET"), req.get("path", "/"), req.get("body"),
                         provider="vibe_kanban", timeout=kwargs.get("timeout", 60))

    def _request(self, method: str, path: str, body: Any = None) -> Any:
        req = {"method": method, "path": path, "body": body}
        self.call_log.append(req)
        res = self._runner(req)
        if not isinstance(res, dict) or "success" not in res:
            raise ProviderError("vibe_kanban_bad_response", f"vibe-kanban: {method} {path} returned no ApiResponse envelope", {"response": res})
        if not res.get("success"):
            raise ProviderError("vibe_kanban_api_error", str(res.get("message") or f"{method} {path} failed"), {"response": res})
        return res.get("data")

    def _git_out(self, wt: str, *args: str) -> str:
        res = self._git(["git", "-C", wt, *args])
        return str((res or {}).get("raw") if isinstance(res, dict) else res or "").strip()

    def _dirty(self, wt: str) -> list[str]:
        """Every path the exit monitor's commit would pick up (porcelain, untracked included)."""
        res = self._git(["git", "-C", wt, "status", "--porcelain", "--untracked-files=all"])
        if isinstance(res, dict):
            text = str(res["stdout"] if res.get("stdout") is not None else res.get("raw") or "")
        else:
            text = coerce_output(res)
        return [ln[3:].strip().strip('"') for ln in text.splitlines() if len(ln) > 3]

    # --- executor profiles (SAFETY #1) ---------------------------------------------------
    def _profiles_doc(self) -> dict[str, Any]:
        data = self._request("GET", "/api/profiles")
        content = data.get("content") if isinstance(data, dict) else None
        try:
            doc = json.loads(content) if isinstance(content, str) else None
        except json.JSONDecodeError:
            doc = None
        if not isinstance(doc, dict) or not isinstance(doc.get("executors"), dict):
            raise ProviderError("vibe_kanban_bad_response", "vibe-kanban: /api/profiles content is not an ExecutorConfigs document")
        return doc

    def ensure_ro_profile(self) -> dict[str, Any]:
        """Merge the `ORCA_RO` CLAUDE_CODE variant into the profiles and verify it read back safe."""
        doc = self._profiles_doc()
        claude = doc["executors"].setdefault("CLAUDE_CODE", {})
        claude[ORCA_RO_VARIANT] = {"CLAUDE_CODE": {"plan": True, "dangerously_skip_permissions": False}}
        self._request("PUT", "/api/profiles", doc)
        back = self._profiles_doc()
        cfg = (((back.get("executors") or {}).get("CLAUDE_CODE") or {}).get(ORCA_RO_VARIANT) or {}).get("CLAUDE_CODE") or {}
        if cfg.get("dangerously_skip_permissions") is not False or cfg.get("plan") is not True:
            raise ProviderError(
                "ro_profile_unverified",
                "vibe-kanban: ORCA_RO did not read back with plan=true and dangerously_skip_permissions=false",
                {"readBack": cfg},
            )
        return cfg

    # --- worktree / process resolution -----------------------------------------------
    def _resolve_worktree(self, workspace_id: str) -> str | None:
        ws = self._request("GET", f"/api/workspaces/{workspace_id}")
        container = real_worktree((ws or {}).get("container_ref") if isinstance(ws, dict) else None)
        if not container:
            return None
        root = Path(container)
        if (root / ".git").exists():
            return str(root)
        repos = [p for p in sorted(root.iterdir()) if p.is_dir() and (p / ".git").exists()]
        return str(repos[0]) if len(repos) == 1 else None

    def _worker_worktree(self, row: Any) -> str:
        wt = real_worktree(row["worktree"]) or self._resolve_worktree(row["dispatch_id"])
        if not wt:
            raise ProviderError("worktree_unknown", f"vibe-kanban: cannot resolve the worktree of workspace {row['dispatch_id']!r}")
        if wt != row["worktree"]:
            self._patch_dispatch(row["dispatch_id"], worktree=wt)
        return wt

    def _process(self, proc_id: str) -> dict[str, Any]:
        data = self._request("GET", f"/api/execution-processes/{proc_id}")
        if not isinstance(data, dict):
            raise ProviderError("vibe_kanban_bad_response", f"vibe-kanban: execution process {proc_id!r} has no body")
        return data

    def _wait_for_exit(self, proc_id: str) -> dict[str, Any]:
        deadline = time.monotonic() + self.exit_timeout_s
        while True:
            proc = self._process(proc_id)
            if str(proc.get("status") or "").lower() in VIBE_TERMINAL_STATUSES:
                return proc
            if time.monotonic() >= deadline:
                raise ProviderError("process_still_running", f"vibe-kanban: process {proc_id!r} has not exited; refusing to inspect HEAD")
            self._sleep(1.0)

    # --- SAFETY #2: post-exit auto-commit guard ---------------------------------------
    def _await_commit_settled(self, wt: str) -> dict[str, Any]:
        """Wait until the post-`completed` auto-commit (and any cleanup-script commit) has landed."""
        last: str | None = None
        stable = 0
        head, dirty = "", []
        for poll in range(1, self.settle_max_polls + 1):
            head = self._git_out(wt, "rev-parse", "--verify", "HEAD^{commit}")
            dirty = self._dirty(wt)
            if dirty:
                stable, last = 0, None
            else:
                stable = stable + 1 if head == last else 1
                last = head
            if stable >= self.settle_polls:
                return {"settled": True, "polls": poll, "head": head}
            self._sleep(self.settle_interval_s)
        raise ProviderError(
            "auto_commit_pending",
            f"vibe-kanban: the process is completed but the worktree {'is still dirty' if dirty else 'HEAD keeps moving'} "
            f"after {self.settle_max_polls} polls; the exit monitor's commit has not settled, refusing to judge HEAD",
            {"worktree": wt, "head": head, "dirty": dirty[:20], "inspected": False},
        )

    def _head_verdict(self, wt: str, completed: float | None) -> tuple[str, str, bool]:
        head = self._git_out(wt, "rev-parse", "--verify", "HEAD^{commit}")
        subject, _, ctime = self._git_out(wt, "log", "-1", "--format=%s%x00%ct", "HEAD").partition("\x00")
        after_exit = completed is not None and ctime.strip().isdigit() and int(ctime) >= int(completed)
        return head, subject, bool(after_exit or subject.startswith(VIBE_AUTO_COMMIT_PREFIXES))

    def guard_auto_commit(self, dispatch_id: str, *, strip_auto_commit: bool | None = None, enforce: bool = True) -> dict[str, Any]:
        """Inspect HEAD of the real worktree once the agent process has exited; reject by default."""
        row = self._dispatch_row(dispatch_id)
        eff = self._effective(row)
        if eff.get("runReason") not in (None, "codingagent"):
            raise ProviderError(
                "agent_process_unknown",
                "vibe-kanban: the start response named a non-agent process (setup script); the coding-agent process "
                "cannot be tracked over REST, so the auto-commit guard cannot run",
            )
        proc = self._wait_for_exit(str(row["session_id"])) if enforce else self._process(str(row["session_id"]))
        status = str(proc.get("status") or "").lower()
        if status not in VIBE_TERMINAL_STATUSES:
            return {"autoCommitDetected": None, "processStatus": status, "inspected": False}
        wt = self._worker_worktree(row)
        settle = self._await_commit_settled(wt) if enforce and status == "completed" else None
        completed = _parse_ts(proc.get("completed_at"))
        head, subject, detected = self._head_verdict(wt, completed)
        out: dict[str, Any] = {"autoCommitDetected": detected, "head": head, "headSubject": subject,
                               "worktree": wt, "processStatus": status, "inspected": True, "stripped": False,
                               "settle": settle}
        if not detected or not enforce:
            return out
        allow = strip_auto_commit if strip_auto_commit is not None else env_flag(
            env_lookup(self.env, "OPEN_FLEET_VIBE_KANBAN_STRIP_AUTO_COMMIT", "ORCA_VIBE_KANBAN_STRIP_AUTO_COMMIT")
        )
        if not allow:
            raise ProviderError(
                "unverified_auto_commit",
                f"vibe-kanban: HEAD {head[:12]} ({subject!r}) was committed by the exit monitor after the agent exited, "
                "not by the worker; set OPEN_FLEET_VIBE_KANBAN_STRIP_AUTO_COMMIT=1 to strip it",
                out,
            )
        removed: list[str] = []
        while detected:
            if len(removed) >= VIBE_MAX_STRIPPED_COMMITS:
                raise ProviderError("auto_commit_strip_failed",
                                    f"vibe-kanban: more than {VIBE_MAX_STRIPPED_COMMITS} auto-commits on HEAD; refusing to strip further",
                                    {**out, "removedCommits": removed})
            parent = self._git_out(wt, "rev-parse", "--verify", "HEAD~1^{commit}")
            self._git(["git", "-C", wt, "reset", "--soft", "HEAD~1"])
            now_head = self._git_out(wt, "rev-parse", "--verify", "HEAD^{commit}")
            if now_head != parent:
                raise ProviderError("auto_commit_strip_failed", f"vibe-kanban: HEAD is {now_head} after reset, expected {parent}",
                                    {**out, "removedCommits": removed})
            removed.append(head)
            head, subject, detected = self._head_verdict(wt, completed)
        out.update({"stripped": True, "removedCommit": removed[0], "removedCommits": removed, "head": head, "headSubject": subject})
        self._patch_dispatch(dispatch_id, effective={"autoCommitStripped": removed[0], "autoCommitsStripped": removed})
        return out

    # --- Worker dispatch (`POST /api/workspaces/start`) ---
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
        repo_id: str | None = None,
        target_branch: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        cached = self.state.get_or_record_request(retry_request, "worker-start")
        if cached:
            return cached
        check_monotonic_profile(parent_profile, profile)
        if profile == "danger":
            raise ProviderError("unsupported_profile", "vibe-kanban: PROFILE=danger needs a sandbox; vibe-kanban runs agents on the host")
        executor = VIBE_EXECUTORS.get(agent)
        if not executor:
            raise ProviderError("unsupported_agent", f"vibe-kanban: no BaseCodingAgent for {agent!r} (want {sorted(VIBE_EXECUTORS)})")
        if profile == "ro" and executor != "CLAUDE_CODE":
            raise ProviderError("unsupported_profile", f"vibe-kanban: no verified read-only variant for {executor}")
        if worktree not in ("", "new-child", "new-top-level"):
            raise ProviderError("unsupported_worktree", "vibe-kanban: each workspace gets its own worktree; an explicit --worktree cannot be honoured")
        repo = repo_id or env_lookup(self.env, "OPEN_FLEET_VIBE_KANBAN_REPO_ID")
        branch = target_branch or env_lookup(self.env, "OPEN_FLEET_VIBE_KANBAN_TARGET_BRANCH")
        if not repo or not branch:
            raise ProviderError(
                "vibe_kanban_repo_unconfigured",
                "vibe-kanban: set OPEN_FLEET_VIBE_KANBAN_REPO_ID (a POST /api/repos id) and OPEN_FLEET_VIBE_KANBAN_TARGET_BRANCH",
            )
        task_prompt = self.resolve_task_prompt(task_id, prompt)
        executor_config: dict[str, Any] = {"executor": executor, "permission_policy": "PLAN" if profile == "ro" else "AUTO"}
        ro_cfg = None
        if profile == "ro":
            ro_cfg = self.ensure_ro_profile()
            executor_config["variant"] = ORCA_RO_VARIANT
        body = {
            "name": name or task_id or None,
            "repos": [{"repo_id": repo, "target_branch": branch}],
            "executor_config": executor_config,
            "prompt": task_prompt,
        }
        data = self._request("POST", "/api/workspaces/start", body)
        workspace_id = require_id(data, "workspace.id", provider="vibe-kanban", what="workspace id")
        proc_id = require_id(data, "execution_process.id", provider="vibe-kanban", what="execution process id")
        run_reason = ((data or {}).get("execution_process") or {}).get("run_reason")
        wt = None
        try:
            wt = self._resolve_worktree(workspace_id)
        except ProviderError:
            wt = None
        handle = f"vibe-kanban:{proc_id}"
        effective = {
            "agent": agent,
            "profile": profile,
            "executorConfig": executor_config,
            "roProfileReadBack": ro_cfg,
            "workspaceId": workspace_id,
            "executionProcessId": proc_id,
            "runReason": run_reason,
            "autoCommitGuard": "post-exit, reject-by-default",
        }
        self._record_dispatch(
            dispatch_id=workspace_id, task_id=task_id, run=run, worktree=wt or "", agent=agent,
            profile=profile, handle=handle, effective=effective, session_id=proc_id,
        )
        res = {
            "state": "ready",
            "dispatchId": workspace_id,
            "agentTerminalHandle": handle,
            "worktree": wt,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective},
            "upstream": data,
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def worker_read(self, **kwargs: Any) -> dict[str, Any]:
        raise ProviderError(
            "unsupported_operation",
            "vibe-kanban: execution logs are only served over WebSockets (/api/execution-processes/{id}/normalized-logs/ws)",
        )

    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        return self._list_local(run=kwargs.get("run"), task=kwargs.get("task"), limit=kwargs.get("limit"))

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        row = self._dispatch_row(dispatch_id)
        proc = self._process(str(row["session_id"]))
        out = normalize_show(
            row["dispatch_id"], row["state"], task_id=row["task_id"], terminal_state=row["terminal_state"],
            handle=row["terminal_handle"], worktree=row["worktree"], stage=str(proc.get("status") or row["state"]), raw=proc,
        )
        try:
            out["autoCommitGuard"] = self.guard_auto_commit(dispatch_id, enforce=False)
        except ProviderError as exc:
            out["autoCommitGuard"] = {"error": exc.to_envelope()["error"]}
        return out

    def worker_fence(
        self,
        *,
        verb: str,
        dispatch_id: str = "",
        reason: str | None = None,
        strip_auto_commit: bool | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        fence_state(verb)
        row = self._dispatch_row(dispatch_id)
        if verb == "retain":
            new_state, term_state = self._fence_local(dispatch_id, verb)
            return {"dispatchId": dispatch_id, "verb": verb, "state": new_state, "terminalState": term_state,
                    "reason": reason, "upstream": None}
        raw = self._request("POST", f"/api/workspaces/{row['dispatch_id']}/execution/stop")
        guard: dict[str, Any] | None = None
        if verb in ("stop", "release"):
            try:
                guard = dict(self.guard_auto_commit(dispatch_id, strip_auto_commit=strip_auto_commit), releasable=True)
            except ProviderError as exc:
                if verb == "release":
                    self._fence_local(dispatch_id, "stop")  # the process IS stopped; the release is what is refused
                    raise
                # worker-stop succeeded upstream: report it, with the guard's refusal as data.
                guard = {"releasable": False, "error": exc.to_envelope()["error"]}
        new_state, term_state = self._fence_local(dispatch_id, verb)
        return {"dispatchId": dispatch_id, "verb": verb, "state": new_state, "terminalState": term_state,
                "reason": reason, "autoCommitGuard": guard, "upstream": raw}

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
