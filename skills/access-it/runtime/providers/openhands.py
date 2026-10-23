#!/usr/bin/env python3
"""openhands.py — OpenHands Software Agent SDK (`openhands.agent_server`) RuntimeProvider (#584).

Source-verified against OpenHands/software-agent-sdk `openhands-agent-server` (`conversation_router.py`,
`event_router.py`, `server_details_router.py`) and `openhands-sdk` (`conversation/request.py`,
`hooks/{config,executor}.py`, `security/confirmation_policy.py`):
  - `POST /api/conversations` with a `StartConversationRequest`:
    `agent {kind: Agent, llm, tools:[{name}]}`, `workspace {working_dir}`, `worktree`,
    `confirmation_policy {kind: NeverConfirm}`, `hook_config`, `initial_message` (the task spec)
    -> `ConversationInfo.id`; then `POST /api/conversations/{id}/run`.
  - Tools by profile (registry names): ro -> `glob, grep, planning_file_editor` (no `terminal` /
    `file_editor`); rw/danger -> `terminal, file_editor, glob, grep, task_tracker`.
  - Hooks: the server does NOT auto-load `.openhands/hooks.json`, so `hook_config` is sent in the
    request: a `PreToolUse` command hook running `deny-hook.sh` with `OPEN_FLEET_HOOK_EXIT2=1`
    (OpenHands blocks on exit code 2). A missing hook script exits 2 too (fail closed). The same
    deny-hook configs are installed into the worktree when it is a local directory.
  - danger: the API has no per-conversation workspace type; isolation exists only when the server
    runs `conversation_runtime: docker` (read from `GET /server_info`). Anything else is refused.
  - `worker_read` -> `GET /api/conversations/{id}/events/search` (`items`, `next_page_id`) converted
    to transcript messages; `worker_show` -> `GET /api/conversations/{id}` (`execution_status`);
    `worker_fence` -> `POST /api/conversations/{id}/interrupt` (non-destructive); `retain` makes no
    upstream call.
"""
from __future__ import annotations

import json
import os
import shlex
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from .base import (
    ProviderError,
    RuntimeProvider,
    check_monotonic_profile,
    env_get,
    fence_state,
    normalize_read,
    require_id,
)
from .local_state import LocalStateStore
from ._external import insert_dispatch, load_dispatch, local_worker_list, record_fence, show_from_row

RO_ALLOWED_TOOLS = ["glob", "grep", "planning_file_editor"]
RO_DISABLED_TOOLS = ["terminal", "file_editor", "apply_patch", "task_tracker", "browser_tool_set"]
RW_TOOLS = ["terminal", "file_editor", "glob", "grep", "task_tracker"]

DENY_HOOK = Path(__file__).resolve().parent.parent / "scripts" / "deny-hook.sh"


def _is_placeholder(worktree: str | None) -> bool:
    return not worktree or worktree.startswith(("new-", "current", "active"))


def deny_hook_config(profile: str, hook_path: str | None = None, unit_worktree: str | None = None) -> dict[str, Any]:
    """OpenHands `HookConfig`: a PreToolUse command hook with exit-2 deny semantics."""
    hook = hook_path or str(DENY_HOOK)
    # OPENHANDS_PROJECT_DIR is the conversation's working dir (hooks/executor.py) — the real
    # boundary even when the server made a dedicated worktree for this conversation.
    boundary = shlex.quote(unit_worktree) if unit_worktree else '"$OPENHANDS_PROJECT_DIR"'
    q = shlex.quote(hook)
    command = (
        f"[ -f {q} ] || {{ echo 'open-fleet deny-hook missing: fail-closed' >&2; exit 2; }}; "
        f"OPEN_FLEET_HOOK_EXIT2=1 OPEN_FLEET_HEADLESS_STRICT=1 OPEN_FLEET_SANDBOX_PROFILE={shlex.quote(profile)} "
        f"OPEN_FLEET_UNIT_WORKTREE={boundary} ORCA_UNIT_WORKTREE={boundary} sh {q}"
    )
    return {"pre_tool_use": [{"matcher": "*", "hooks": [{"type": "command", "command": command, "timeout": 60}]}]}


def _event_text(ev: dict[str, Any]) -> tuple[str, str]:
    """(role, text) for one OpenHands event (MessageEvent / ActionEvent / ObservationEvent / errors)."""
    kind = str(ev.get("kind") or "")
    parts: list[str] = []

    def texts(content: Any) -> None:
        for c in content or []:
            if isinstance(c, dict) and c.get("type") == "text" and isinstance(c.get("text"), str):
                parts.append(c["text"])

    role = "assistant" if ev.get("source") == "agent" else ("user" if ev.get("source") == "user" else "tool")
    if isinstance(ev.get("llm_message"), dict):
        msg = ev["llm_message"]
        role = str(msg.get("role") or role)
        texts(msg.get("content"))
    if kind == "ActionEvent" or "action" in ev:
        texts(ev.get("thought"))
        action = ev.get("action") if isinstance(ev.get("action"), dict) else {}
        if isinstance(action.get("message"), str):
            parts.append(action["message"])
        elif ev.get("tool_name"):
            parts.append(f"[tool:{ev['tool_name']}] {json.dumps({k: v for k, v in action.items() if k != 'kind'})[:500]}")
    if isinstance(ev.get("observation"), dict):
        role = "tool"
        texts(ev["observation"].get("content"))
    if isinstance(ev.get("rejection_reason"), str):
        parts.append(f"[rejected] {ev['rejection_reason']}")
    if isinstance(ev.get("error"), str):
        parts.append(f"[error] {ev['error']}")
    return role, "\n".join(parts)


class OpenHandsProvider(RuntimeProvider):
    """RuntimeProvider adapter for OpenHands (`openhands.agent_server` REST API)."""

    name = "openhands"

    def __init__(
        self,
        state: LocalStateStore | None = None,
        runner: Callable[..., Any] | None = None,
        *,
        db_path: str | Path | None = None,
        env: dict[str, str] | None = None,
        base_url: str | None = None,
        install_hooks: Callable[..., Any] | None = None,
        **kwargs: Any,
    ) -> None:
        self.env = dict(env) if env is not None else None
        self.state = state or LocalStateStore(db_path=db_path, env=self.env)
        self.base_url = (
            base_url
            or env_get("OPEN_FLEET_OPENHANDS_URL", "ORCA_OPENHANDS_URL", self.env, "http://127.0.0.1:8000")
        ).rstrip("/")
        self._runner = runner or self._default_runner
        self._install_hooks = install_hooks
        self.call_log: list[dict[str, Any]] = []

    def _env(self, primary: str, legacy: str, default: str = "") -> str:
        return env_get(primary, legacy, self.env, default)

    def _default_runner(self, req: dict[str, Any], **kwargs: Any) -> Any:
        method = req.get("method", "GET")
        url = f"{self.base_url}{req.get('path', '/')}"
        body = req.get("body")
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        api_key = self._env("OPEN_FLEET_OPENHANDS_SESSION_API_KEY", "ORCA_OPENHANDS_SESSION_API_KEY")
        if api_key:
            headers["X-Session-API-Key"] = api_key
        http_req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(http_req, timeout=kwargs.get("timeout", 60)) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500] if exc.fp else ""
            raise ProviderError("openhands_http_error", f"HTTP {exc.code} {method} {req.get('path')}: {detail}", {"status": exc.code}) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProviderError("openhands_unreachable", f"{method} {url}: {exc}") from exc
        if not raw.strip():
            raise ProviderError("openhands_empty_output", f"{method} {req.get('path')} returned an empty body")
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProviderError("openhands_bad_json", f"{method} {req.get('path')} returned non-JSON: {raw[:200]!r}") from exc

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        req = {"method": method, "path": path, "body": body}
        self.call_log.append(req)
        try:
            res = self._runner(req, **kwargs)
        except ProviderError:
            raise
        except (OSError, TimeoutError) as exc:
            raise ProviderError("openhands_unreachable", f"{method} {path}: {exc}") from exc
        if isinstance(res, str):
            try:
                res = json.loads(res)
            except json.JSONDecodeError as exc:
                raise ProviderError("openhands_bad_json", f"{method} {path} returned non-JSON: {res[:200]!r}") from exc
        if not isinstance(res, dict):
            raise ProviderError("openhands_bad_json", f"{method} {path} returned {type(res).__name__}, not an object", {"response": res})
        return res

    def _hooks(self, wt_path: str, agent: str, profile: str) -> dict[str, str]:
        if self._install_hooks is not None:
            return self._install_hooks(wt_path, agent, profile)
        from .posix import install_worktree_hooks

        return install_worktree_hooks(wt_path, agent, profile)

    def _llm(self) -> dict[str, Any]:
        model = self._env("OPEN_FLEET_OPENHANDS_MODEL", "ORCA_OPENHANDS_MODEL")
        if not model:
            raise ProviderError(
                "missing_llm_config",
                "OpenHands needs OPEN_FLEET_OPENHANDS_MODEL to build an agent with a restricted toolset",
            )
        llm: dict[str, Any] = {"model": model, "usage_id": "agent"}
        api_key = self._env("OPEN_FLEET_OPENHANDS_LLM_API_KEY", "ORCA_OPENHANDS_LLM_API_KEY")
        if api_key:
            llm["api_key"] = api_key
        base_url = self._env("OPEN_FLEET_OPENHANDS_LLM_BASE_URL", "ORCA_OPENHANDS_LLM_BASE_URL")
        if base_url:
            llm["base_url"] = base_url
        return llm

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
        task_prompt = self.resolve_task_prompt(task_id, prompt)

        server_runtime: str | None = None
        if profile == "ro":
            tools = list(RO_ALLOWED_TOOLS)
            disabled_tools = list(RO_DISABLED_TOOLS)
            profile_flag = "tools=glob,grep,planning_file_editor"
        elif profile == "rw":
            tools = list(RW_TOOLS)
            disabled_tools = []
            profile_flag = "tools=terminal,file_editor,glob,grep,task_tracker"
        elif profile == "danger":
            requested = (workspace_type or on_env or self._env(
                "OPEN_FLEET_OPENHANDS_WORKSPACE_TYPE", "ORCA_OPENHANDS_WORKSPACE_TYPE", "docker"
            ))
            if requested not in ("docker", "apptainer"):
                raise ProviderError(
                    "invalid_workspace_type",
                    f"OpenHands profile='danger' requires workspace_type in ('docker', 'apptainer'), got {requested!r}",
                )
            if requested == "apptainer":
                raise ProviderError(
                    "unsupported_workspace_type",
                    "the agent-server API has no apptainer conversation runtime (ApptainerWorkspace is a client-side SDK class)",
                )
            info = self._request("GET", "/server_info")
            server_runtime = str(info.get("conversation_runtime") or "local")
            if server_runtime != "docker":
                raise ProviderError(
                    "sandbox_unavailable",
                    f"OpenHands server runs conversation_runtime={server_runtime!r}; PROFILE=danger needs 'docker'",
                    {"server_info": {"conversation_runtime": server_runtime}},
                )
            tools = list(RW_TOOLS)
            disabled_tools = []
            profile_flag = "conversation_runtime=docker"
        else:
            raise ProviderError("invalid_profile", f"unknown profile {profile!r}")

        if _is_placeholder(worktree):
            # Let the server cut a dedicated git worktree from the repo root.
            working_dir = self._env("OPEN_FLEET_REPO_ROOT", "ORCA_REPO_ROOT", os.getcwd())
            use_worktree = True
            unit_boundary: str | None = None
        else:
            working_dir = os.path.abspath(worktree)
            use_worktree = False
            unit_boundary = working_dir

        local_hooks: dict[str, str] | None = None
        if not use_worktree and os.path.isdir(working_dir):
            local_hooks = self._hooks(working_dir, agent if agent != "openhands" else "claude", profile)
        # In a docker conversation runtime the host hook path does not exist; the container is
        # the boundary, so danger sends no host hook (it would exit 2 and block every tool).
        hook_config = deny_hook_config(profile, unit_worktree=unit_boundary) if profile != "danger" else None

        conv_payload: dict[str, Any] = {
            "agent": {
                "kind": "Agent",
                "llm": self._llm(),
                "tools": [{"name": t, "params": {}} for t in tools],
            },
            "workspace": {"working_dir": working_dir},
            "worktree": use_worktree,
            "confirmation_policy": {"kind": "NeverConfirm"},
            "initial_message": {"role": "user", "content": [{"type": "text", "text": task_prompt}], "run": False},
            # ConversationTags keys must be lowercase alphanumeric (sdk conversation/types.py).
            "tags": {"openfleettask": str(task_id)[:256], "openfleetprofile": profile} if task_id else {"openfleetprofile": profile},
        }
        if hook_config is not None:
            conv_payload["hook_config"] = hook_config
        created = self._request("POST", "/api/conversations", conv_payload)
        conv_id = require_id(created, "id", provider=self.name, what="conversation id")
        run_resp = self._request("POST", f"/api/conversations/{urllib.parse.quote(conv_id)}/run")
        actual_dir = (created.get("workspace") or {}).get("working_dir") if isinstance(created.get("workspace"), dict) else None
        real_worktree = str(actual_dir or working_dir)

        handle = f"openhands:{conv_id}"
        effective = {
            "agent": agent,
            "profile": profile,
            "worktree": real_worktree,
            "serverWorktree": use_worktree,
            "tools": tools,
            "disabled_tools": disabled_tools,
            "confirmation_policy": "NeverConfirm",
            "hook_config": hook_config,
            "localHooks": local_hooks,
            "conversation_runtime": server_runtime,
            "profile_flag": profile_flag,
            "conversationId": conv_id,
        }
        insert_dispatch(
            self.state,
            dispatch_id=conv_id,
            task_id=task_id,
            run=run,
            worktree=real_worktree,
            agent=agent,
            profile=profile,
            handle=handle,
            backend=self.name,
            effective=effective,
            session_id=conv_id,
        )
        res = {
            "state": "ready",
            "dispatchId": conv_id,
            "agentTerminalHandle": handle,
            "worktree": real_worktree,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective},
            "upstream": {"conversation": created, "run": run_resp},
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def worker_list(self, *, run: str | None = None, task: str | None = None, limit: int | None = None, **kwargs: Any) -> dict[str, Any]:
        """OUR dispatch rows; the server's search (every conversation on it) only annotates `stage`."""
        raw = self._request("GET", "/api/conversations/search?limit=100")
        items = raw.get("items")
        if not isinstance(items, list):
            raise ProviderError("openhands_bad_json", "conversation search returned no items", {"response": raw})
        stages = {
            str(it["id"]): str(it.get("execution_status") or "unknown")
            for it in items
            if isinstance(it, dict) and it.get("id")
        }
        return local_worker_list(self.state, self.name, run=run, task=task, limit=limit, stages=stages, upstream=raw)

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        row = load_dispatch(self.state, dispatch_id, self.name)
        raw = self._request("GET", f"/api/conversations/{urllib.parse.quote(dispatch_id)}")
        require_id(raw, "id", provider=self.name, what="conversation id")
        stage = str(raw.get("execution_status") or "unknown")
        ws = raw.get("workspace") if isinstance(raw.get("workspace"), dict) else {}
        return show_from_row(row, stage=stage, raw=raw, worktree=ws.get("working_dir") or row.get("worktree"))

    def worker_read(
        self,
        *,
        dispatch_id: str = "",
        source: str = "transcript",
        limit: int = 50,
        cursor: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        load_dispatch(self.state, dispatch_id, self.name)
        lim = max(1, min(int(limit), 100))
        query = {"limit": str(lim), "sort_order": "TIMESTAMP"}
        if cursor:
            query["page_id"] = str(cursor)
        path = f"/api/conversations/{urllib.parse.quote(dispatch_id)}/events/search?{urllib.parse.urlencode(query)}"
        raw = self._request("GET", path)
        items = raw.get("items")
        if not isinstance(items, list):
            raise ProviderError("openhands_bad_json", "events/search returned no items", {"response": raw})
        messages: list[dict[str, Any]] = []
        for ev in items:
            if not isinstance(ev, dict):
                continue
            role, text = _event_text(ev)
            if not text:
                continue
            messages.append({"id": str(ev.get("id") or f"ev_{len(messages)}"), "role": role, "blocks": [{"type": "text", "text": text}]})
        out = normalize_read("transcript", messages=messages, cursor=raw.get("next_page_id"))
        if source != "transcript":
            out["fallbackReason"] = "openhands_has_no_terminal_tail"
        out["upstream"] = {"next_page_id": raw.get("next_page_id"), "count": len(items)}
        return out

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        fence_state(verb)
        load_dispatch(self.state, dispatch_id, self.name)
        out: dict[str, Any] = {"dispatchId": dispatch_id, "verb": verb, "reason": reason}
        if verb == "retain":
            out["upstreamCalls"] = []
        else:
            # Interrupt cancels the in-flight call and pauses; the conversation and its workspace
            # are kept (DELETE would be the destructive step, and it is never issued here).
            out["upstream"] = self._request("POST", f"/api/conversations/{urllib.parse.quote(dispatch_id)}/interrupt")
        new_state, term_state = record_fence(self.state, dispatch_id, verb)
        out.update({"state": new_state, "terminalState": term_state})
        return out

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
