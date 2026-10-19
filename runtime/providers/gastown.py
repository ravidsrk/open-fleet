#!/usr/bin/env python3
"""gastown.py — Gastown (`steveyegge/gastown`, `gt` + `bd` Beads) RuntimeProvider (#583).

Maps the canonical Runtime Provider Interface (RPI) onto Gastown (`gt`) and Beads (`bd`):
  - `task_create/update/list` -> `LocalStateStore` + `bd create --json` / `bd update` / `bd list --json`
  - `worker_start`:
    * Enforces `check_monotonic_profile(parent_profile, profile)`.
    * On `profile == "ro"`: registers a read-only agent alias via
      `gt config agent set <agent>-ro <ro_cmd>` (avoiding Gastown's built-in YOLO agent table)
      and dispatches via `gt sling <task_id> <rig> --agent <agent>-ro --no-merge`.
    * On `profile in ("rw", "danger")`: dispatches via
      `gt sling <task_id> <rig> --agent <agent> --no-merge` (`--no-merge` prevents Gastown's
      Refinery from auto-merging before `verify.py` checks the SHA-bound evidence manifest).
  - `send_message/check_messages` bridges `LocalStateStore` + `gt mail send` /
    `gt mail inbox --unread --json`.
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
    env_get,
)
from .local_state import LocalStateStore


class GastownProvider(RuntimeProvider):
    """RuntimeProvider adapter for Gastown (`gt`) and Beads (`bd`)."""

    name = "gastown"

    def __init__(
        self,
        state: LocalStateStore | None = None,
        runner: Callable[..., Any] | None = None,
        *,
        db_path: str | Path | None = None,
        env: dict[str, str] | None = None,
        rig: str | None = None,
        **kwargs: Any,
    ) -> None:
        self.env = dict(env) if env is not None else None
        self.state = state or LocalStateStore(db_path=db_path, env=self.env)
        self._runner = runner or self._default_runner
        self.default_rig = rig or env_get("OPEN_FLEET_GASTOWN_RIG", "ORCA_GASTOWN_RIG", self.env, "default-rig")
        self.call_log: list[Any] = []

    def capabilities(self) -> set[str]:
        return {"cap:core-orchestration", "cap:beads-dag", "cap:gastown-mail"}

    def _default_runner(self, argv: list[str], **kwargs: Any) -> dict[str, Any]:
        proc = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=kwargs.get("timeout", 60))
        if proc.returncode != 0:
            raise ProviderError(
                "gastown_cli_error",
                proc.stderr.strip() or f"{argv[0]} exited with {proc.returncode}",
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

    # --- Task DAG (`LocalStateStore` + `bd` Beads) ---
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
        argv = ["bd", "create", title or display_name or spec or local["task"]["id"], "--json"]
        if deps:
            argv += ["--deps", ",".join(str(d) for d in deps)]
        bead = self._run(argv)
        local["task"]["bead"] = bead
        return local

    def task_update(
        self,
        *,
        task_id: str,
        status: str,
        result: str | None = None,
        run: str | None = None,
        sender: str | None = None,
        retry_request: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        local = self.state.task_update(
            task_id=task_id,
            status=status,
            result=result,
            run=run,
            sender=sender,
            retry_request=retry_request,
        )
        bead = self._run(["bd", "update", str(task_id), "--status", str(status), "--json"])
        local["task"]["bead"] = bead
        return local

    def task_list(
        self,
        *,
        run: str | None = None,
        sender: str | None = None,
        brief: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        local = self.state.task_list(run=run, sender=sender, brief=brief)
        beads = self._run(["bd", "list", "--json"])
        local["beads"] = beads.get("items", beads.get("beads", []))
        return local

    # --- Worker Dispatch (`gt sling` + read-only alias registration) ---
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
        rig: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        cached = self.state.get_or_record_request(retry_request, "worker-start")
        if cached:
            return cached

        check_monotonic_profile(parent_profile, profile)
        target_rig = rig or self.default_rig
        harness = build_harness_command(agent, profile, worktree, prompt=prompt)

        if profile == "ro":
            agent_alias = f"{agent}-ro"
            self._run(["gt", "config", "agent", "set", agent_alias, harness["command"]])
        else:
            agent_alias = agent

        sling_argv = [
            "gt",
            "sling",
            str(task_id or "adhoc"),
            str(target_rig),
            "--agent",
            agent_alias,
            "--no-merge",
            "--json",
        ]
        raw = self._run(sling_argv)
        dispatch_id = str(raw.get("dispatchId") or raw.get("polecatId") or raw.get("id") or f"gt_{uuid.uuid4().hex[:10]}")
        handle = str(raw.get("agentTerminalHandle") or raw.get("polecat") or f"polecat:{target_rig}/{dispatch_id}")

        effective = {
            "agent": agent,
            "agentAlias": agent_alias,
            "profile": profile,
            "command": harness["command"],
            "argv": harness["argv"],
            "env": harness["env"],
            "profile_flag": harness["profile_flag"],
            "rig": target_rig,
            "noMerge": True,
        }
        now = time.time()
        with self.state._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dispatches(
                    dispatch_id, task_id, run_id, worktree, agent, profile,
                    terminal_handle, state, terminal_state, backend, launch_effective, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', 'active', 'gastown', ?, ?, ?)
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
            "launch": {"effective": effective},
            "upstream": raw,
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        raw = self._run(["gt", "polecat", "list", "--json"])
        return {"workers": raw.get("polecats", raw.get("items", [])), "upstream": raw}

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        raw = self._run(["gt", "polecat", "status", str(dispatch_id), "--json"])
        return {"dispatchId": dispatch_id, "worker": raw}

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        raw = self._run(["gt", "polecat", "logs", str(dispatch_id), "--lines", str(limit), "--json"])
        return {"dispatchId": dispatch_id, "source": source, "lines": raw.get("lines", []), "upstream": raw}

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        raw = self._run(["gt", "polecat", "nuke", str(dispatch_id), "--json"])
        with self.state._connect() as conn:
            conn.execute(
                "UPDATE dispatches SET state = ?, terminal_state = 'fenced', updated_at = ? WHERE dispatch_id = ?",
                (verb, time.time(), dispatch_id),
            )
        return {"dispatchId": dispatch_id, "verb": verb, "state": verb, "reason": reason, "upstream": raw}

    # --- Mailbox (`LocalStateStore` + `gt mail`) ---
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
        recipient = to or "mayor"
        body = payload if payload is not None else subject
        upstream = self._run(
            ["gt", "mail", "send", str(recipient), "--subject", str(subject), "--type", str(msg_type), "--body", str(body), "--json"]
        )
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
        upstream = self._run(["gt", "mail", "inbox", "--unread", "--json"])
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
        local["upstreamInbox"] = upstream.get("messages", upstream.get("items", []))
        return local

    def reply_message(self, *, msg_id: str, body: str, run: str | None = None, sender: str | None = None, retry_request: str | None = None, **kwargs: Any) -> dict[str, Any]:
        local = self.state.reply_message(msg_id=msg_id, body=body, run=run, sender=sender, retry_request=retry_request)
        upstream = self._run(["gt", "mail", "reply", str(msg_id), "--body", str(body), "--json"])
        local["upstream"] = upstream
        return local

    def ask_human(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.ask_human(**kwargs)

    def request_show(self, request_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.state.request_show(request_id)
