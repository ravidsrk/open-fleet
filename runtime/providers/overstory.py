#!/usr/bin/env python3
"""overstory.py — Overstory (`jayminwest/overstory`, `ov`) RuntimeProvider (#588).

Maps the canonical Runtime Provider Interface (RPI) onto Overstory (`ov` CLI):
  - `worker_start` -> `ov sling <task_id> --capability <"scout" if profile=="ro" else "builder"> --runtime <agent> --json`
    (leverages Overstory's `guard-rules.ts` hook-enforced `ro` for `scout`/`reviewer` and
    worktree-confined `rw` for `builder`).
  - `send_message/check_messages/reply_message` ->
    `ov mail send --type <msg_type> --subject <subject> --body <payload> --json`,
    `ov mail check --agent orchestrator --json`,
    `ov mail reply <id> --body <body> --json` + `LocalStateStore`.
  - `worktree_list/rm` -> `ov worktree list --json` / `ov worktree clean --json`.
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


class OverstoryProvider(RuntimeProvider):
    """RuntimeProvider adapter for Overstory (`ov`)."""

    name = "overstory"

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
        self.call_log: list[Any] = []

    def capabilities(self) -> set[str]:
        return {"cap:core-orchestration", "cap:overstory-mail", "cap:guard-rules"}

    def _default_runner(self, argv: list[str], **kwargs: Any) -> dict[str, Any]:
        proc = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=kwargs.get("timeout", 60))
        if proc.returncode != 0:
            raise ProviderError(
                "overstory_cli_error",
                proc.stderr.strip() or f"ov exited with {proc.returncode}",
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

    def _run(self, argv: list[str], **kwargs: Any) -> dict[str, Any]:
        self.call_log.append(list(argv))
        res = self._runner(list(argv), **kwargs)
        if isinstance(res, dict):
            return res
        return {"result": res}

    # --- Worker Dispatch (`ov sling`) ---
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
        capability: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        cached = self.state.get_or_record_request(retry_request, "worker-start")
        if cached:
            return cached

        check_monotonic_profile(parent_profile, profile)
        cap = capability or ("scout" if profile == "ro" else "builder")
        harness = build_harness_command(agent, profile, worktree, prompt=prompt)

        argv = [
            "ov",
            "sling",
            str(task_id or "adhoc"),
            "--capability",
            cap,
            "--runtime",
            str(agent),
            "--json",
        ]
        raw = self._run(argv)
        dispatch_id = str(raw.get("dispatchId") or raw.get("agentName") or raw.get("id") or f"ov_{uuid.uuid4().hex[:10]}")
        handle = str(raw.get("agentTerminalHandle") or raw.get("tmuxSession") or f"ov:{dispatch_id}")

        effective = {
            "agent": agent,
            "profile": profile,
            "capability": cap,
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
                    terminal_handle, state, terminal_state, backend, launch_effective, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', 'active', 'overstory', ?, ?, ?)
                """,
                (dispatch_id, task_id, run or "default", worktree, agent, profile, handle, json.dumps(effective), now, now),
            )

        res = {
            "state": "ready",
            "dispatchId": dispatch_id,
            "agentTerminalHandle": handle,
            "worktree": worktree,
            "agent": agent,
            "profile": profile,
            "capability": cap,
            "launch": {"effective": effective},
            "upstream": raw,
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        raw = self._run(["ov", "status", "--json"])
        return {"workers": raw.get("agents", raw.get("workers", [])), "upstream": raw}

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        raw = self._run(["ov", "inspect", str(dispatch_id), "--json"])
        return {"dispatchId": dispatch_id, "worker": raw}

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        raw = self._run(["ov", "logs", str(dispatch_id), "--lines", str(limit), "--json"])
        return {"dispatchId": dispatch_id, "source": source, "lines": raw.get("lines", []), "upstream": raw}

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        raw = self._run(["ov", "stop", str(dispatch_id), "--json"])
        with self.state._connect() as conn:
            conn.execute(
                "UPDATE dispatches SET state = ?, terminal_state = 'fenced', updated_at = ? WHERE dispatch_id = ?",
                (verb, time.time(), dispatch_id),
            )
        return {"dispatchId": dispatch_id, "verb": verb, "state": verb, "reason": reason, "upstream": raw}

    # --- Mailbox (`ov mail` + `LocalStateStore`) ---
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
        argv = [
            "ov",
            "mail",
            "send",
            "--type",
            str(msg_type),
            "--subject",
            str(subject),
            "--body",
            str(body),
            "--json",
        ]
        if to:
            argv += ["--to", str(to)]
        upstream = self._run(argv)
        local["upstream"] = upstream
        return local

    def check_messages(
        self,
        *,
        terminal: str | None = None,
        run: str | None = None,
        ack: str | list[str] | None = None,
        mode: str = "unread",
        types: str | None = None,
        fmt: bool = False,
        wait: bool = False,
        timeout_ms: int | None = None,
        retry_request: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        agent_name = terminal or "orchestrator"
        upstream = self._run(["ov", "mail", "check", "--agent", str(agent_name), "--json"])
        local = self.state.check_messages(
            terminal=terminal,
            run=run,
            ack=ack,
            mode=mode,
            types=types,
            fmt=fmt,
            wait=wait,
            timeout_ms=timeout_ms,
            retry_request=retry_request,
        )
        local["upstreamMessages"] = upstream.get("messages", upstream.get("items", []))
        return local

    def reply_message(
        self,
        *,
        msg_id: str,
        body: str,
        run: str | None = None,
        sender: str | None = None,
        retry_request: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        local = self.state.reply_message(msg_id=msg_id, body=body, run=run, sender=sender, retry_request=retry_request)
        upstream = self._run(["ov", "mail", "reply", str(msg_id), "--body", str(body), "--json"])
        local["upstream"] = upstream
        return local

    # --- Worktree operations ---
    def worktree_list(self, *, repo: str | None = None, limit: int | None = None, **kwargs: Any) -> dict[str, Any]:
        raw = self._run(["ov", "worktree", "list", "--json"])
        return {"worktrees": raw.get("worktrees", raw.get("items", [])), "upstream": raw}

    def worktree_rm(self, *, selector: str = "", force: bool = False, **kwargs: Any) -> dict[str, Any]:
        argv = ["ov", "worktree", "clean", "--json"]
        if selector:
            argv += ["--worktree", str(selector)]
        if force:
            argv.append("--force")
        raw = self._run(argv)
        return {"removed": True, "selector": selector, "upstream": raw}

    # --- Task DAG & Gates (`LocalStateStore`) ---
    def task_create(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_create(**kwargs)

    def task_update(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_update(**kwargs)

    def task_list(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_list(**kwargs)

    def ask_human(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.ask_human(**kwargs)

    def request_show(self, request_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.state.request_show(request_id)
