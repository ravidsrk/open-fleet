#!/usr/bin/env python3
"""t3code.py — T3 Code (`pingdotgg/t3code`) RuntimeProvider (#588).

Source-verified against pingdotgg/t3code `apps/server/src/{binCli.ts,cli/acpMcpBridge.ts,
mcp/AcpMcpStdioBridge.ts,mcp/toolkits/**}` and `packages/contracts/src/{orchestratorMcp.ts,
providerPolicy.ts}`. T3 exposes orchestration to outside callers as MCP TOOLS on its `/mcp`
endpoint; `t3 acp-mcp-call <tool> <arguments-json>` calls one tool and prints the MCP result
(`{content, structuredContent, isError}`). It needs `T3_ACP_MCP_ENDPOINT` and
`T3_ACP_MCP_AUTHORIZATION` (a bearer token, env only) and, for a caller outside a T3 thread, a
`projectId` (`OPEN_FLEET_T3_PROJECT_ID`).
  - `worker_start` -> `t3_thread_launch {projectId, title, runtimeMode, interactionMode,
    workspaceStrategy, message: <task spec>}` (-> `threadId`), then `t3_thread_read` for the real
    `thread.worktreePath`. ro -> `runtimeMode: approval-required` + `interactionMode: plan`
    (Codex: read-only sandbox; Claude: every write waits on approval); rw -> `full-access` +
    `default`. T3's `worktree` strategy creates the worktree AND starts the agent in one call, so
    an rw worker never gets that strategy: its worktree is cut first (`t3_project_read` ->
    `workspaceRoot`, then `git worktree add -b <branch> <path> <base>`), the deny-hook configs are
    installed there, and only then is the thread launched with `existing_worktree`.
    PROFILE=danger is refused: T3 has no sandbox/container runner.
  - `worker_read/show` -> `t3_thread_read` (`items`, `thread.status`); `worker_list` -> OUR
    dispatch rows, `stage` annotated from `t3_thread_list` (`threads[].status`); `dispatch_inject` -> `t3_thread_send`; `worker_fence` ->
    `t3_thread_interrupt` (non-destructive); `retain` makes no upstream call.
"""
from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any, Callable

from .base import (
    ProviderError,
    RuntimeProvider,
    check_monotonic_profile,
    env_get,
    fence_state,
    normalize_read,
    parse_json_strict,
    require_id,
)
from .local_state import LocalStateStore
from ._external import (
    insert_dispatch,
    load_dispatch,
    local_worker_list,
    record_fence,
    ref_safe,
    run_cli_text,
    show_from_row,
)

PROFILE_MODES = {
    "ro": ("approval-required", "plan"),
    "rw": ("full-access", "default"),
}


def _is_placeholder(worktree: str | None) -> bool:
    return not worktree or worktree.startswith(("new-", "current", "active"))


class T3CodeProvider(RuntimeProvider):
    """RuntimeProvider adapter for T3 Code (MCP orchestration tools via `t3 acp-mcp-call`)."""

    name = "t3code"

    def __init__(
        self,
        state: LocalStateStore | None = None,
        runner: Callable[..., Any] | None = None,
        *,
        db_path: str | Path | None = None,
        env: dict[str, str] | None = None,
        project_id: str | None = None,
        install_hooks: Callable[..., Any] | None = None,
        git_runner: Callable[[list[str]], str] | None = None,
        **kwargs: Any,
    ) -> None:
        self.env = dict(env) if env is not None else None
        self.state = state or LocalStateStore(db_path=db_path, env=self.env)
        self._runner = runner or self._default_runner
        self._install_hooks = install_hooks
        self._git = git_runner or (lambda argv: run_cli_text(argv, self.name))
        self.project_id = project_id or env_get("OPEN_FLEET_T3_PROJECT_ID", "ORCA_T3_PROJECT_ID", self.env, "")
        self.worktree_root = env_get(
            "OPEN_FLEET_T3_WORKTREE_ROOT", "ORCA_T3_WORKTREE_ROOT", self.env,
            str(Path.home() / ".open-fleet" / "t3code-worktrees"),
        )
        self.call_log: list[dict[str, Any]] = []

    def _default_runner(self, call: dict[str, Any], **kwargs: Any) -> str:
        source = os.environ if self.env is None else self.env
        endpoint = source.get("T3_ACP_MCP_ENDPOINT", "")
        auth = source.get("T3_ACP_MCP_AUTHORIZATION", "")
        if not endpoint or not auth:
            raise ProviderError(
                "t3code_not_configured",
                "t3 acp-mcp-call needs T3_ACP_MCP_ENDPOINT and T3_ACP_MCP_AUTHORIZATION in the environment",
            )
        child_env = dict(os.environ)
        child_env.update({"T3_ACP_MCP_ENDPOINT": endpoint, "T3_ACP_MCP_AUTHORIZATION": auth})
        return run_cli_text(call["argv"], self.name, timeout=int(kwargs.get("timeout", 120)), env=child_env)

    def _tool(self, tool: str, arguments: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        """Call one T3 MCP tool; `isError` or a result without structured data is a ProviderError."""
        argv = ["t3", "acp-mcp-call", tool, json.dumps(arguments, sort_keys=True)]
        call = {"tool": tool, "arguments": arguments, "argv": argv}
        self.call_log.append(call)
        try:
            out = self._runner(call, **kwargs)
        except ProviderError:
            raise
        except (FileNotFoundError, OSError) as exc:
            raise ProviderError("t3code_cli_missing", f"t3 could not be launched: {exc}") from exc
        result = out if isinstance(out, dict) else parse_json_strict(str(out or ""), self.name)
        if not isinstance(result, dict):
            raise ProviderError("t3code_bad_json", f"{tool} returned no MCP result object", {"response": result})
        data = result.get("structuredContent")
        if data is None:
            for block in result.get("content") or []:
                if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
                    try:
                        data = json.loads(block["text"])
                    except json.JSONDecodeError:
                        data = None
                    break
        if result.get("isError"):
            raise ProviderError("t3code_tool_error", f"{tool} failed: {json.dumps(data)[:300]}", {"result": data})
        if not isinstance(data, dict):
            raise ProviderError("t3code_bad_json", f"{tool} returned no structured result", {"response": result})
        return data

    def _hooks(self, wt_path: str, agent: str, profile: str) -> dict[str, str]:
        if self._install_hooks is not None:
            return self._install_hooks(wt_path, agent, profile)
        from .posix import install_worktree_hooks

        return install_worktree_hooks(wt_path, agent, profile)

    def _cut_worktree(self, branch: str, base: str | None) -> dict[str, Any]:
        """Create the worker's git worktree OURSELVES so hooks land before any agent starts."""
        project = self._tool("t3_project_read", {"projectId": self.project_id})
        root = project.get("workspaceRoot")
        if not isinstance(root, str) or not os.path.isdir(root):
            raise ProviderError(
                "worktree_unresolved",
                f"t3_project_read reports no existing workspaceRoot for project {self.project_id!r}",
                {"project": project},
            )
        path = str(Path(self.worktree_root).expanduser() / branch)
        if os.path.exists(path):
            raise ProviderError("worktree_exists", f"t3code: worktree path {path!r} already exists; pass it as --worktree")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._git(["git", "-C", root, "worktree", "add", "-b", branch, path, base or "HEAD"])
        if not os.path.isdir(path):
            raise ProviderError("worktree_unresolved", f"git worktree add reported success but {path!r} does not exist")
        return {"path": os.path.realpath(path), "branch": branch, "workspaceRoot": root}

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
        base: str | None = None,
        model_selection: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        cached = self.state.get_or_record_request(retry_request, "worker-start")
        if cached:
            return cached

        check_monotonic_profile(parent_profile, profile)
        if profile == "danger":
            raise ProviderError(
                "unsupported_profile",
                "T3 Code has no sandbox/container runner; PROFILE=danger cannot be isolated there",
            )
        if profile not in PROFILE_MODES:
            raise ProviderError("invalid_profile", f"unknown profile {profile!r}")
        if not self.project_id:
            raise ProviderError("missing_project", "t3_thread_launch from outside T3 needs OPEN_FLEET_T3_PROJECT_ID")
        task_prompt = self.resolve_task_prompt(task_id, prompt)
        runtime_mode, interaction_mode = PROFILE_MODES[profile]
        title = name or (f"t3-{task_id}" if task_id else f"t3-worker-{uuid.uuid4().hex[:6]}")

        hooks: dict[str, str] | None = None
        cut: dict[str, Any] | None = None
        strategy: dict[str, Any]
        if _is_placeholder(worktree) and profile == "rw":
            # `worktree` strategy would start a full-access agent before any hook could exist.
            cut = self._cut_worktree(ref_safe(title), base)
            strategy = {"type": "existing_worktree", "worktreePath": cut["path"]}
            hooks = self._hooks(cut["path"], agent, profile)  # before the agent starts
        elif _is_placeholder(worktree):
            # ro: the thread itself is approval-required + plan; T3 cuts the worktree.
            strategy = {"type": "worktree", "baseRef": base or "HEAD", "branch": title, "startFromOrigin": False}
        else:
            wt_abs = os.path.abspath(worktree)
            if not os.path.isdir(wt_abs):
                raise ProviderError("worktree_unknown", f"t3code: worktree {worktree!r} does not exist")
            strategy = {"type": "existing_worktree", "worktreePath": wt_abs}
            hooks = self._hooks(wt_abs, agent, profile)  # before the agent starts

        params: dict[str, Any] = {
            "projectId": self.project_id,
            "title": title,
            "runtimeMode": runtime_mode,
            "interactionMode": interaction_mode,
            "workspaceStrategy": strategy,
            "message": task_prompt,
        }
        if model_selection:
            params["modelSelection"] = model_selection
        launched = self._tool("t3_thread_launch", params, timeout=300)
        thread_id = require_id(launched, "threadId", provider=self.name, what="thread id")
        detail = self._tool("t3_thread_read", {"threadId": thread_id, "limit": 1})
        thread = detail.get("thread") if isinstance(detail.get("thread"), dict) else {}
        wt_path = thread.get("worktreePath") or (strategy.get("worktreePath"))
        if hooks is None and wt_path and os.path.isdir(str(wt_path)):
            hooks = self._hooks(str(wt_path), agent, profile)

        handle = f"t3:{thread_id}"
        effective = {
            "agent": agent,
            "profile": profile,
            "runtimeMode": runtime_mode,
            "interactionMode": interaction_mode,
            "workspaceStrategy": strategy,
            "modelSelection": launched.get("modelSelection"),
            "worktree": wt_path,
            "branch": thread.get("branch"),
            "threadId": thread_id,
            "runId": launched.get("runId"),
            "mechanism": "mcp.t3_thread_launch",
            "hooks": hooks,
            "createdWorktree": cut,
            "profile_flag": f"runtimeMode={runtime_mode},interactionMode={interaction_mode}",
        }
        insert_dispatch(
            self.state,
            dispatch_id=thread_id,
            task_id=task_id,
            run=run,
            worktree=str(wt_path or ""),
            agent=agent,
            profile=profile,
            handle=handle,
            backend=self.name,
            effective=effective,
            session_id=thread_id,
        )
        res = {
            "state": "ready",
            "dispatchId": thread_id,
            "agentTerminalHandle": handle,
            "worktree": wt_path,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective},
            "upstream": {"launch": launched, "thread": thread},
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def dispatch_inject(
        self,
        *,
        task_id: str = "",
        to_handle: str = "",
        run: str | None = None,
        sender: str | None = None,
        prompt: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        thread_id = to_handle.split(":", 1)[1] if to_handle.startswith("t3:") else to_handle
        if not thread_id:
            raise ProviderError("invalid_handle", "dispatch --to needs a t3:<threadId> handle")
        message = self.resolve_task_prompt(task_id, prompt)
        args: dict[str, Any] = {"threadId": thread_id, "message": message, "mode": "queue"}
        if kwargs.get("retry_request"):
            args["clientRequestId"] = str(kwargs["retry_request"])
        raw = self._tool("t3_thread_send", args)
        return {"injected": True, "threadId": thread_id, "taskId": task_id, "delivery": raw.get("delivery"), "upstream": raw}

    def worker_list(
        self, *, run: str | None = None, task: str | None = None, limit: int | None = None, **kwargs: Any
    ) -> dict[str, Any]:
        if not self.project_id:
            raise ProviderError("missing_project", "t3_thread_list from outside T3 needs OPEN_FLEET_T3_PROJECT_ID")
        raw = self._tool("t3_thread_list", {"projectId": self.project_id})
        threads = raw.get("threads")
        if not isinstance(threads, list):
            raise ProviderError("t3code_bad_json", "t3_thread_list returned no threads array", {"response": raw})
        stages = {
            str(t["threadId"]): str(t.get("status") or "unknown")
            for t in threads
            if isinstance(t, dict) and t.get("threadId")
        }
        return local_worker_list(self.state, self.name, run=run, task=task, limit=limit, stages=stages, upstream=raw)

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        row = load_dispatch(self.state, dispatch_id, self.name)
        raw = self._tool("t3_thread_read", {"threadId": dispatch_id, "limit": 1})
        thread = raw.get("thread") if isinstance(raw.get("thread"), dict) else {}
        return show_from_row(row, stage=str(thread.get("status") or "unknown"), raw=thread, worktree=thread.get("worktreePath"))

    def worker_read(
        self,
        *,
        dispatch_id: str = "",
        source: str = "transcript",
        limit: int = 50,
        cursor: Any = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        load_dispatch(self.state, dispatch_id, self.name)
        args: dict[str, Any] = {"threadId": dispatch_id, "view": "messages", "limit": max(1, min(int(limit), 100))}
        if cursor not in (None, ""):
            args["afterPosition"] = int(cursor)
        raw = self._tool("t3_thread_read", args)
        items = raw.get("items")
        if not isinstance(items, list):
            raise ProviderError("t3code_bad_json", "t3_thread_read returned no items", {"response": raw})
        messages = [
            {
                "id": str(it.get("itemId") or f"item_{i}"),
                "role": "user" if it.get("createdBy") == "user" else ("system" if it.get("createdBy") == "system" else "assistant"),
                "blocks": [{"type": "text", "text": str(it.get("text") or it.get("title") or "")}],
            }
            for i, it in enumerate(items)
            if isinstance(it, dict)
        ]
        out = normalize_read("transcript", messages=messages, cursor=raw.get("nextPosition"))
        if source != "transcript":
            out["fallbackReason"] = "t3code_exposes_thread_timeline_only"
        return out

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        fence_state(verb)
        load_dispatch(self.state, dispatch_id, self.name)
        out: dict[str, Any] = {"dispatchId": dispatch_id, "verb": verb, "reason": reason}
        if verb == "retain":
            out["upstreamCalls"] = []
        else:
            args: dict[str, Any] = {"threadId": dispatch_id}
            if reason:
                args["reason"] = str(reason)[:2000]
            out["upstream"] = self._tool("t3_thread_interrupt", args)
        new_state, term_state = record_fence(self.state, dispatch_id, verb)
        out.update({"state": new_state, "terminalState": term_state})
        return out

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
