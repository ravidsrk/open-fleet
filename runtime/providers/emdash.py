#!/usr/bin/env python3
"""emdash.py — Emdash (`generalaction/emdash`, `workspace-server` JSON-RPC 2.0) RuntimeProvider (#589).

Maps the canonical Runtime Provider Interface (RPI) onto Emdash's `workspace-server` JSON-RPC 2.0 API:
  - `worktree.create`, `worktree.remove`, `worktree.list`
  - `agent.startStream` with:
    * `profile == "ro"`: `autoApprove: False` and read-only `extraArgs` from `build_harness_command`
    * `profile in ("rw", "danger")`: `autoApprove: True`
  - `pty.start`, `pty.input`, `pty.snapshot` for terminal lifecycle.
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


class EmdashProvider(RuntimeProvider):
    """RuntimeProvider adapter for Emdash (`workspace-server` JSON-RPC 2.0)."""

    name = "emdash"

    def __init__(
        self,
        state: LocalStateStore | None = None,
        runner: Callable[..., Any] | None = None,
        *,
        db_path: str | Path | None = None,
        env: dict[str, str] | None = None,
        rpc_url: str | None = None,
        **kwargs: Any,
    ) -> None:
        self.env = dict(env) if env is not None else None
        self.state = state or LocalStateStore(db_path=db_path, env=self.env)
        self.rpc_url = (
            rpc_url
            or env_get("OPEN_FLEET_EMDASH_URL", "ORCA_EMDASH_URL", self.env, "http://127.0.0.1:4120/rpc")
        )
        self._runner = runner or self._default_runner
        self.call_log: list[dict[str, Any]] = []
        self._rpc_seq = 0

    def capabilities(self) -> set[str]:
        return {"cap:core-orchestration", "cap:emdash-jsonrpc", "cap:pty-snapshot"}

    def _default_runner(self, rpc_payload: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        req = urllib.request.Request(
            self.rpc_url,
            data=json.dumps(rpc_payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=kwargs.get("timeout", 60)) as resp:
                raw = resp.read().decode("utf-8")
                parsed = json.loads(raw) if raw.strip() else {}
                if "error" in parsed and parsed["error"]:
                    raise ProviderError("emdash_rpc_error", str(parsed["error"]), {"rpc": rpc_payload})
                return parsed.get("result", parsed) if isinstance(parsed, dict) else {"result": parsed}
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError("emdash_http_error", str(exc), {"rpc": rpc_payload}) from exc

    def _rpc(self, method: str, params: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        self._rpc_seq += 1
        payload = {"jsonrpc": "2.0", "id": self._rpc_seq, "method": method, "params": params}
        self.call_log.append(payload)
        res = self._runner(payload, **kwargs)
        if isinstance(res, dict):
            return res.get("result", res) if "jsonrpc" in res else res
        return {"result": res}

    # --- Worktree JSON-RPC (`worktree.create` / `worktree.remove` / `worktree.list`) ---
    def worktree_create(
        self,
        *,
        name: str = "worker",
        base: str | None = None,
        repo: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw = self._rpc("worktree.create", {"name": name, "base": base, "repo": repo})
        return {"worktree": {"name": name, "path": raw.get("path", f"/tmp/emdash/{name}"), "base": base}, "upstream": raw}

    def worktree_rm(self, *, selector: str = "", force: bool = False, **kwargs: Any) -> dict[str, Any]:
        raw = self._rpc("worktree.remove", {"worktree": selector, "force": force})
        return {"removed": True, "selector": selector, "upstream": raw}

    def worktree_list(self, *, repo: str | None = None, limit: int | None = None, **kwargs: Any) -> dict[str, Any]:
        raw = self._rpc("worktree.list", {"repo": repo, "limit": limit})
        return {"worktrees": raw.get("worktrees", raw.get("items", [])), "upstream": raw}

    # --- Worker Dispatch (`agent.startStream`) ---
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
        resolved_prompt = prompt
        if not resolved_prompt and task_id:
            with self.state._connect() as conn:
                t_row = conn.execute("SELECT spec, title FROM tasks WHERE id = ?", (task_id,)).fetchone()
                if t_row:
                    resolved_prompt = str(t_row["spec"] or t_row["title"] or "")

        if worktree in ("new-child", ""):
            wt_res = self.worktree_create(name=name or f"emdash-{task_id or 'worker'}")
            wt_path = str(wt_res["worktree"]["path"])
        else:
            wt_path = worktree

        harness = build_harness_command(agent, profile, wt_path, prompt=resolved_prompt)
        auto_approve = profile != "ro"
        extra_args = list(harness["argv"][1:]) if profile == "ro" else []

        stream_params: dict[str, Any] = {
            "taskId": task_id,
            "worktree": wt_path,
            "agent": agent,
            "profile": profile,
            "autoApprove": auto_approve,
            "extraArgs": extra_args,
            "command": harness["command"],
            "prompt": resolved_prompt or "",
        }
        raw = self._rpc("agent.startStream", stream_params)
        stream_id = str(raw.get("streamId") or raw.get("ptyId") or raw.get("id") or f"em_{uuid.uuid4().hex[:10]}")
        handle = f"emdash:{stream_id}"

        effective = {
            "agent": agent,
            "profile": profile,
            "autoApprove": auto_approve,
            "extraArgs": extra_args,
            "command": harness["command"],
            "argv": harness["argv"],
            "env": harness["env"],
            "profile_flag": harness["profile_flag"],
            "streamId": stream_id,
        }
        now = time.time()
        with self.state._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dispatches(
                    dispatch_id, task_id, run_id, worktree, agent, profile,
                    terminal_handle, state, terminal_state, backend, launch_effective, session_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', 'active', 'emdash', ?, ?, ?, ?)
                """,
                (stream_id, task_id, run or "default", wt_path, agent, profile, handle, json.dumps(effective), stream_id, now, now),
            )

        res = {
            "state": "ready",
            "dispatchId": stream_id,
            "agentTerminalHandle": handle,
            "worktree": wt_path,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective},
            "upstream": raw,
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    # --- PTY / Terminal operations (`pty.start`, `pty.input`, `pty.snapshot`) ---
    def terminal_create(
        self,
        *,
        worktree: str | None = None,
        title: str | None = None,
        command: str | None = None,
        shell: str | None = None,
        focus: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw = self._rpc("pty.start", {"worktree": worktree, "title": title, "command": command, "shell": shell})
        pty_id = str(raw.get("ptyId") or raw.get("id") or f"pty_{uuid.uuid4().hex[:8]}")
        return {"terminal": {"handle": pty_id, "worktree": worktree, "title": title}, "upstream": raw}

    def terminal_send(self, *, terminal: str = "", text: str = "", enter: bool = True, **kwargs: Any) -> dict[str, Any]:
        pty_id = terminal.split(":", 1)[1] if ":" in terminal else terminal
        data = f"{text}\n" if enter and not text.endswith("\n") else text
        raw = self._rpc("pty.input", {"ptyId": pty_id, "data": data})
        return {"terminal": terminal, "sent": True, "upstream": raw}

    def terminal_read(
        self,
        *,
        terminal: str = "",
        cursor: int | None = None,
        limit: int | None = None,
        screen: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        pty_id = terminal.split(":", 1)[1] if ":" in terminal else terminal
        raw = self._rpc("pty.snapshot", {"ptyId": pty_id, "limit": limit, "screen": screen})
        return {"terminal": terminal, "snapshot": raw.get("snapshot", ""), "upstream": raw}

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        return self.terminal_read(terminal=dispatch_id, limit=limit)

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        raw = self._rpc("pty.kill", {"ptyId": dispatch_id, "verb": verb, "reason": reason})
        with self.state._connect() as conn:
            conn.execute(
                "UPDATE dispatches SET state = ?, terminal_state = 'fenced', updated_at = ? WHERE dispatch_id = ?",
                (verb, time.time(), dispatch_id),
            )
        return {"dispatchId": dispatch_id, "verb": verb, "state": verb, "reason": reason, "upstream": raw}

    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        with self.state._connect() as conn:
            rows = conn.execute("SELECT * FROM dispatches WHERE backend = 'emdash' ORDER BY created_at ASC").fetchall()
        return {"workers": [dict(r) for r in rows]}

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        with self.state._connect() as conn:
            row = conn.execute("SELECT * FROM dispatches WHERE dispatch_id = ?", (dispatch_id,)).fetchone()
        if not row:
            raise ProviderError("dispatch_not_found", f"dispatch {dispatch_id!r} not found")
        return {"dispatchId": dispatch_id, "worker": dict(row)}

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
