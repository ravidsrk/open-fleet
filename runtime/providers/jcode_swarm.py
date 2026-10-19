#!/usr/bin/env python3
"""jcode_swarm.py — JCode Swarm (`1jehuang/jcode`, `jcode serve` + `jcode api-bridge`) RuntimeProvider (#588).

Maps the canonical Runtime Provider Interface (RPI) onto JCode's native multi-agent swarm:
  - Targets `jcode serve` Unix socket via `jcode api-bridge` (`create_session`, `assign_task`,
    `dm`, `broadcast`, `create_plan`, `run_plan`, `file_touches`).
  - CRITICAL SAFETY FIX: `jcode --profile minimal` still enables `bash,write,edit,replace,apply_patch`!
    `JCodeSwarmProvider` NEVER uses `--profile minimal` for `profile == "ro"`; it enforces explicit
    `--tools read,agentgrep,ls,session_search,conversation_search,memory,web_search` and
    `--disabled-tools bash,write,edit,replace,apply_patch,swarm,selfdev,desktop_selfdev,bg,codemode,mcp`.
  - Queries `file_touches` and feeds `LocalStateStore.record_file_touch` for real-time line-range
    conflict detection (`overlapping_hunk` vs `same_file_disjoint_hunk`).
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
)
from .local_state import LocalStateStore

JCODE_RO_TOOLS = "read,agentgrep,ls,session_search,conversation_search,memory,web_search"
JCODE_RO_DISABLED_TOOLS = "bash,write,edit,replace,apply_patch,swarm,selfdev,desktop_selfdev,bg,codemode,mcp"
JCODE_RW_DISABLED_TOOLS = "selfdev,desktop_selfdev"


class JCodeSwarmProvider(RuntimeProvider):
    """RuntimeProvider adapter for JCode Swarm (`jcode serve` + `jcode api-bridge`)."""

    name = "jcode-swarm"

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
        self.call_log: list[dict[str, Any]] = []

    def capabilities(self) -> set[str]:
        return {"cap:core-orchestration", "cap:jcode-swarm", "cap:file-touches"}

    def _default_runner(self, call: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        argv = call.get("argv") or ["jcode", "api-bridge", str(call.get("op", "")), json.dumps(call.get("payload", {}))]
        proc = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=kwargs.get("timeout", 60))
        if proc.returncode != 0:
            raise ProviderError(
                "jcode_bridge_error",
                proc.stderr.strip() or f"jcode api-bridge exited with {proc.returncode}",
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

    def _bridge(self, op: str, payload: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        argv = ["jcode", "api-bridge", op, json.dumps(payload, sort_keys=True)]
        call = {"op": op, "payload": payload, "argv": argv}
        self.call_log.append(call)
        res = self._runner(call, **kwargs)
        if isinstance(res, dict):
            return res
        return {"result": res}

    # --- Task DAG (`create_plan` / `run_plan` + `LocalStateStore`) ---
    def task_create(
        self,
        *,
        spec: str = "",
        title: str | None = None,
        display_name: str | None = None,
        deps: list[str] | None = None,
        parent: str | None = None,
        run: str | None = None,
        sender: str | None = None,
        retry_request: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        local = self.state.task_create(
            spec=spec,
            title=title,
            display_name=display_name,
            deps=deps,
            parent=parent,
            run=run,
            sender=sender,
            retry_request=retry_request,
        )
        upstream = self._bridge(
            "create_plan",
            {
                "task_id": local["task"]["id"],
                "title": title or display_name or local["task"]["id"],
                "spec": spec,
                "deps": list(deps or []),
                "run_id": run or "default",
            },
        )
        local["task"]["jcodePlan"] = upstream
        return local

    def task_update(self, **kwargs: Any) -> dict[str, Any]:
        local = self.state.task_update(**kwargs)
        if kwargs.get("status") == "ready":
            self._bridge("run_plan", {"task_id": kwargs.get("task_id"), "status": "ready"})
        return local

    def task_list(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_list(**kwargs)

    # --- Worker Dispatch (`create_session` + `assign_task`) ---
    def worker_start(
        self,
        *,
        task_id: str = "",
        worktree: str = "new-child",
        agent: str = "jcode",
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
        harness = build_harness_command("jcode" if agent == "jcode-swarm" else agent, profile, worktree, prompt=prompt)

        if profile == "ro":
            tools = JCODE_RO_TOOLS
            disabled_tools = JCODE_RO_DISABLED_TOOLS
        else:
            tools = "*"
            disabled_tools = JCODE_RW_DISABLED_TOOLS

        session_payload = {
            "worktree": worktree,
            "agent": agent,
            "profile": profile,
            "tools": tools,
            "disabled_tools": disabled_tools,
            "use_minimal_profile": False,  # Never use `--profile minimal` (includes bash/write/edit!)
            "command": harness["command"],
            "argv": harness["argv"],
        }
        sess = self._bridge("create_session", session_payload)
        session_id = str(sess.get("session_id") or sess.get("id") or f"jc_sess_{uuid.uuid4().hex[:10]}")

        assigned = self._bridge(
            "assign_task",
            {
                "session_id": session_id,
                "task_id": task_id,
                "prompt": prompt or f"Execute task {task_id}",
                "profile": profile,
                "disabled_tools": disabled_tools,
            },
        )

        handle = f"jcode:{session_id}"
        effective = {
            "agent": agent,
            "profile": profile,
            "tools": tools,
            "disabled_tools": disabled_tools,
            "command": harness["command"],
            "argv": harness["argv"],
            "env": harness["env"],
            "profile_flag": harness["profile_flag"],
            "sessionId": session_id,
        }
        now = time.time()
        with self.state._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dispatches(
                    dispatch_id, task_id, run_id, worktree, agent, profile,
                    terminal_handle, state, terminal_state, backend, launch_effective, session_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', 'active', 'jcode-swarm', ?, ?, ?, ?)
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
            "upstream": {"session": sess, "assigned": assigned},
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    # --- File-Touch Coordination (`file_touches` + `LocalStateStore.record_file_touch`) ---
    def sync_file_touches(self, *, run_id: str = "default", **kwargs: Any) -> dict[str, Any]:
        raw = self._bridge("file_touches", {"run_id": run_id})
        touches = raw.get("touches", raw.get("items", []))
        results: list[dict[str, Any]] = []
        for t in touches:
            if not isinstance(t, dict):
                continue
            rec = self.state.record_file_touch(
                worker_id=str(t.get("worker_id") or t.get("session_id") or "worker"),
                file_path=str(t.get("file_path") or t.get("path") or ""),
                start_line=int(t.get("start_line", 1)),
                end_line=int(t.get("end_line", 999999)),
                op=str(t.get("op", "write")),
                run_id=run_id,
            )
            results.append(rec)
        return {"synced": len(results), "results": results, "upstream": raw}

    # --- Mailbox (`dm` / `broadcast` + `LocalStateStore`) ---
    def send_message(
        self,
        *,
        subject: str,
        msg_type: str = "info",
        to: str | None = None,
        outcome: str | None = None,
        sender: str | None = None,
        payload: str | None = None,
        run: str | None = None,
        attrs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        local = self.state.send_message(
            subject=subject,
            msg_type=msg_type,
            to=to,
            outcome=outcome,
            sender=sender,
            payload=payload,
            run=run,
            attrs=attrs,
        )
        body = payload if payload is not None else subject
        if to in ("all", "broadcast", "*"):
            upstream = self._bridge("broadcast", {"subject": subject, "type": msg_type, "body": body, "from": sender or "worker"})
        else:
            upstream = self._bridge("dm", {"to": to or "coordinator", "subject": subject, "type": msg_type, "body": body, "from": sender or "worker"})
        local["upstream"] = upstream
        return local

    def check_messages(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.check_messages(**kwargs)

    def reply_message(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.reply_message(**kwargs)

    def ask_human(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.ask_human(**kwargs)

    def request_show(self, request_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.state.request_show(request_id)

    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        raw = self._bridge("list_sessions", {})
        return {"workers": raw.get("sessions", []), "upstream": raw}

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        raw = self._bridge("get_session", {"session_id": dispatch_id})
        return {"dispatchId": dispatch_id, "worker": raw}

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        raw = self._bridge("read_session", {"session_id": dispatch_id, "limit": limit})
        return {"dispatchId": dispatch_id, "source": source, "lines": raw.get("lines", []), "upstream": raw}

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        raw = self._bridge("close_session", {"session_id": dispatch_id, "verb": verb, "reason": reason})
        with self.state._connect() as conn:
            conn.execute(
                "UPDATE dispatches SET state = ?, terminal_state = 'fenced', updated_at = ? WHERE dispatch_id = ?",
                (verb, time.time(), dispatch_id),
            )
        return {"dispatchId": dispatch_id, "verb": verb, "state": verb, "reason": reason, "upstream": raw}
