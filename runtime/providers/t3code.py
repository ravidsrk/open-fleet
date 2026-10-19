#!/usr/bin/env python3
"""t3code.py — T3Code (`pingdotgg/t3code`, `t3` OrchestratorV2) RuntimeProvider (#588).

Maps the canonical Runtime Provider Interface (RPI) onto `t3` OrchestratorV2:
  - `orchestration.createSession` with `isolationMode: "worktree"`
  - `orchestration.sendTurn` for prompt/turn injection
  - `t3 acp-mcp-call` for CLI RPC dispatch
  - Enforces `check_monotonic_profile(parent_profile, profile)`
  - Maps `profile == "ro"` -> `interactionMode: "plan"`, `runtimeMode: "approval-required"`
  - Maps `profile == "rw"` -> `interactionMode: "default"`, `runtimeMode: "full-access"`
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


class T3CodeProvider(RuntimeProvider):
    """RuntimeProvider adapter for T3Code (`t3` OrchestratorV2)."""

    name = "t3code"

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
        return {"cap:core-orchestration", "cap:t3-orchestrator-v2", "cap:acp-mcp"}

    def _default_runner(self, call: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        argv = call.get("argv") or [
            "t3",
            "acp-mcp-call",
            str(call.get("method", "")),
            "--params",
            json.dumps(call.get("params", {})),
            "--json",
        ]
        proc = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=kwargs.get("timeout", 60))
        if proc.returncode != 0:
            raise ProviderError(
                "t3code_cli_error",
                proc.stderr.strip() or f"t3 exited with {proc.returncode}",
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

    def _rpc(self, method: str, params: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        argv = ["t3", "acp-mcp-call", method, "--params", json.dumps(params, sort_keys=True), "--json"]
        call = {"method": method, "params": params, "argv": argv}
        self.call_log.append(call)
        res = self._runner(call, **kwargs)
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
        **kwargs: Any,
    ) -> dict[str, Any]:
        cached = self.state.get_or_record_request(retry_request, "worker-start")
        if cached:
            return cached

        check_monotonic_profile(parent_profile, profile)
        harness = build_harness_command(agent, profile, worktree, prompt=prompt)

        if profile == "ro":
            interaction_mode = "plan"
            runtime_mode = "approval-required"
        else:
            interaction_mode = "default"
            runtime_mode = "full-access"

        session_params: dict[str, Any] = {
            "taskId": task_id,
            "title": name or (f"t3-{task_id}" if task_id else "t3-worker"),
            "agent": agent,
            "isolationMode": "worktree",
            "worktree": worktree,
            "interactionMode": interaction_mode,
            "runtimeMode": runtime_mode,
            "profile": profile,
            "sandbox": "isolated" if profile == "danger" else "worktree",
        }
        created = self._rpc("orchestration.createSession", session_params)
        session_id = str(created.get("sessionId") or created.get("id") or f"t3_sess_{uuid.uuid4().hex[:10]}")

        turn_resp: dict[str, Any] = {}
        if prompt or task_id:
            turn_resp = self._rpc(
                "orchestration.sendTurn",
                {
                    "sessionId": session_id,
                    "taskId": task_id,
                    "prompt": prompt or f"Execute task {task_id}",
                    "interactionMode": interaction_mode,
                    "runtimeMode": runtime_mode,
                },
            )

        handle = f"t3:{session_id}"
        effective = {
            "agent": agent,
            "profile": profile,
            "isolationMode": "worktree",
            "interactionMode": interaction_mode,
            "runtimeMode": runtime_mode,
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
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', 'active', 't3code', ?, ?, ?, ?)
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
            "upstream": {"session": created, "turn": turn_resp},
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
        session_id = to_handle.split(":", 1)[1] if ":" in to_handle else to_handle
        raw = self._rpc(
            "orchestration.sendTurn",
            {"sessionId": session_id, "taskId": task_id, "prompt": prompt or f"Dispatch task {task_id}"},
        )
        return {"injected": True, "sessionId": session_id, "taskId": task_id, "upstream": raw}

    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        raw = self._rpc("orchestration.listSessions", {})
        return {"workers": raw.get("sessions", raw.get("items", [])), "upstream": raw}

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        raw = self._rpc("orchestration.getSession", {"sessionId": dispatch_id})
        return {"dispatchId": dispatch_id, "worker": raw}

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        raw = self._rpc("orchestration.readTranscript", {"sessionId": dispatch_id, "limit": limit, "source": source})
        return {"dispatchId": dispatch_id, "source": source, "lines": raw.get("lines", []), "upstream": raw}

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        raw = self._rpc("orchestration.stopSession", {"sessionId": dispatch_id, "verb": verb, "reason": reason})
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
