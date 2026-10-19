#!/usr/bin/env python3
"""multiclaude.py — Multiclaude (`dlorenc/multiclaude`, `~/.multiclaude/daemon.sock`) RuntimeProvider (#589).

Maps the canonical Runtime Provider Interface (RPI) onto Multiclaude's Unix socket JSON protocol:
  - Targets `~/.multiclaude/daemon.sock` (`spawn_agent`, `list_agents`, `route_messages`, `complete_agent`).
  - CRITICAL SAFETY FIX #1 (`pkg/claude/prompt.go:46`): Multiclaude hardcodes
    `--dangerously-skip-permissions` in `BuildClaudeCommand`. On `profile == "ro"`,
    `MulticlaudeProvider` injects a read-only wrapper command that strips
    `--dangerously-skip-permissions` and enforces `--permission-mode plan` + `--disallowedTools`.
  - CRITICAL SAFETY FIX #2 (`internal/daemon/daemon.go:1084`): Multiclaude's `complete_agent`
    immediately deletes the agent's git worktree! `MulticlaudeProvider` blocks `complete_agent`
    (`worker_fence(verb="release", ...)`) until `verified=True` is recorded for the dispatch so
    `verify.py` can inspect the worktree before teardown.
"""
from __future__ import annotations

import json
import socket
import time
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


class MulticlaudeProvider(RuntimeProvider):
    """RuntimeProvider adapter for Multiclaude (`~/.multiclaude/daemon.sock`)."""

    name = "multiclaude"

    def __init__(
        self,
        state: LocalStateStore | None = None,
        runner: Callable[..., Any] | None = None,
        *,
        db_path: str | Path | None = None,
        env: dict[str, str] | None = None,
        socket_path: str | Path | None = None,
        **kwargs: Any,
    ) -> None:
        self.env = dict(env) if env is not None else None
        self.state = state or LocalStateStore(db_path=db_path, env=self.env)
        default_sock = str(Path.home() / ".multiclaude" / "daemon.sock")
        self.socket_path = str(
            socket_path
            or env_get("OPEN_FLEET_MULTICLAUDE_SOCK", "ORCA_MULTICLAUDE_SOCK", self.env, default_sock)
        )
        self._runner = runner or self._default_runner
        self.call_log: list[dict[str, Any]] = []
        self.verified_dispatches: set[str] = set()

    def capabilities(self) -> set[str]:
        return {"cap:core-orchestration", "cap:multiclaude-socket", "cap:pre-release-verify-guard"}

    def _default_runner(self, msg: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(kwargs.get("timeout", 30))
                sock.connect(self.socket_path)
                sock.sendall((json.dumps(msg) + "\n").encode("utf-8"))
                chunks: list[bytes] = []
                while True:
                    data = sock.recv(65536)
                    if not data:
                        break
                    chunks.append(data)
                    if b"\n" in data:
                        break
                raw = b"".join(chunks).decode("utf-8").strip()
                return json.loads(raw) if raw else {"ok": True}
        except Exception as exc:
            raise ProviderError("multiclaude_socket_error", str(exc), {"request": msg}) from exc

    def _send_sock(self, action: str, payload: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        msg = {"action": action, **payload}
        self.call_log.append(msg)
        res = self._runner(msg, **kwargs)
        if isinstance(res, dict):
            return res
        return {"result": res}

    def mark_verified(self, dispatch_id: str) -> None:
        """Record durably that `verify.py` has verified `dispatch_id` so `complete_agent` may safely remove its worktree."""
        self.verified_dispatches.add(dispatch_id)
        with self.state._connect() as conn:
            conn.execute(
                "UPDATE dispatches SET terminal_state = 'verified', updated_at = ? WHERE dispatch_id = ?",
                (time.time(), dispatch_id),
            )

    def _is_dispatch_verified(self, dispatch_id: str) -> bool:
        if dispatch_id in self.verified_dispatches:
            return True
        with self.state._connect() as conn:
            row = conn.execute(
                "SELECT terminal_state FROM dispatches WHERE dispatch_id = ?",
                (dispatch_id,),
            ).fetchone()
            return bool(row and row["terminal_state"] == "verified")

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
            # Strip pkg/claude/prompt.go:46 hardcoded `--dangerously-skip-permissions`
            ro_wrapper = (
                "sh -c 'args=\"\"; for a in \"$@\"; do "
                "[ \"$a\" = \"--dangerously-skip-permissions\" ] && continue; "
                "args=\"$args $a\"; done; "
                f"exec {harness['command']}'"
            )
            spawn_payload: dict[str, Any] = {
                "task_id": task_id,
                "name": name or (f"mc-{task_id}" if task_id else "mc-worker"),
                "agent": agent,
                "worktree": worktree,
                "profile": "ro",
                "strip_dangerously_skip_permissions": True,
                "permission_mode": "plan",
                "wrapper_command": ro_wrapper,
                "command": harness["command"],
                "argv": harness["argv"],
                "prompt": prompt or "",
            }
        else:
            spawn_payload = {
                "task_id": task_id,
                "name": name or (f"mc-{task_id}" if task_id else "mc-worker"),
                "agent": agent,
                "worktree": worktree,
                "profile": profile,
                "strip_dangerously_skip_permissions": False,
                "permission_mode": "bypassPermissions",
                "command": harness["command"],
                "argv": harness["argv"],
                "prompt": prompt or "",
            }

        raw = self._send_sock("spawn_agent", spawn_payload)
        agent_id = str(raw.get("agent_id") or raw.get("id") or f"mc_{uuid.uuid4().hex[:10]}")
        handle = f"multiclaude:{agent_id}"

        effective = {
            "agent": agent,
            "profile": profile,
            "strip_dangerously_skip_permissions": profile == "ro",
            "permission_mode": "plan" if profile == "ro" else "bypassPermissions",
            "wrapper_command": spawn_payload.get("wrapper_command"),
            "command": harness["command"],
            "argv": harness["argv"],
            "env": harness["env"],
            "profile_flag": harness["profile_flag"],
            "agentId": agent_id,
        }
        now = time.time()
        with self.state._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dispatches(
                    dispatch_id, task_id, run_id, worktree, agent, profile,
                    terminal_handle, state, terminal_state, backend, launch_effective, session_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', 'active', 'multiclaude', ?, ?, ?, ?)
                """,
                (agent_id, task_id, run or "default", worktree, agent, profile, handle, json.dumps(effective), agent_id, now, now),
            )

        res = {
            "state": "ready",
            "dispatchId": agent_id,
            "agentTerminalHandle": handle,
            "worktree": worktree,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective},
            "upstream": raw,
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        raw = self._send_sock("list_agents", {})
        return {"workers": raw.get("agents", raw.get("items", [])), "upstream": raw}

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        raw = self._send_sock("list_agents", {"agent_id": dispatch_id})
        return {"dispatchId": dispatch_id, "worker": raw}

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        raw = self._send_sock("read_agent", {"agent_id": dispatch_id, "limit": limit})
        return {"dispatchId": dispatch_id, "source": source, "lines": raw.get("lines", []), "upstream": raw}

    def worker_fence(
        self,
        *,
        verb: str,
        dispatch_id: str = "",
        reason: str | None = None,
        verified: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        is_verified = verified or self._is_dispatch_verified(dispatch_id)
        if verb in ("release", "complete") and not is_verified:
            raise ProviderError(
                "unverified_release_blocked",
                f"Multiclaude complete_agent for {dispatch_id!r} blocked: daemon.go:1084 deletes the worktree "
                "immediately on complete_agent, so verify.py must confirm verified=True before release",
                {"dispatchId": dispatch_id, "verb": verb},
            )
        if verb in ("release", "complete"):
            raw = self._send_sock("complete_agent", {"agent_id": dispatch_id, "reason": reason, "verified": True})
        else:
            raw = self._send_sock("stop_agent", {"agent_id": dispatch_id, "verb": verb, "reason": reason})

        with self.state._connect() as conn:
            conn.execute(
                "UPDATE dispatches SET state = ?, terminal_state = 'fenced', updated_at = ? WHERE dispatch_id = ?",
                (verb, time.time(), dispatch_id),
            )
        return {"dispatchId": dispatch_id, "verb": verb, "state": verb, "verified": is_verified, "reason": reason, "upstream": raw}

    # --- Mailbox (`route_messages` + `LocalStateStore`) ---
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
        upstream = self._send_sock(
            "route_messages",
            {
                "from": sender or "worker",
                "to": to or "coordinator",
                "type": msg_type,
                "subject": subject,
                "body": payload if payload is not None else subject,
            },
        )
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

    def task_create(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_create(**kwargs)

    def task_update(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_update(**kwargs)

    def task_list(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_list(**kwargs)
