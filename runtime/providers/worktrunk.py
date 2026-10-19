#!/usr/bin/env python3
"""worktrunk.py — Worktrunk (`max-sixty/worktrunk`, `wt`) RuntimeProvider (#583).

Maps the canonical Runtime Provider Interface (RPI) onto `wt` (Worktrunk):
  - `worktree_create` -> `wt switch --create <name> --no-cd -y --format=json` +
    `wt step copy-ignored` (CoW reflinks).
  - `worktree_list` -> `wt list --format=json`
  - `worktree_rm` -> `wt remove --reap <selector>`
  - `worker_start` -> enforces `check_monotonic_profile(parent_profile, profile)`,
    provisions worktree via `wt`, launches `build_harness_command(agent, profile, wt_path)`
    via `wt switch -x`, and records state in `LocalStateStore`.
  - `predict_and_merge(branch)` -> wraps `wt merge --format=json` for pre-merge conflict
    prediction and squash/rebase merge.
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


class WorktrunkProvider(RuntimeProvider):
    """RuntimeProvider adapter for Worktrunk (`wt`)."""

    name = "worktrunk"

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
        return {"cap:core-orchestration", "cap:cow-worktree", "cap:conflict-prediction"}

    def _default_runner(self, argv: list[str], **kwargs: Any) -> dict[str, Any]:
        proc = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=kwargs.get("timeout", 60))
        if proc.returncode != 0:
            raise ProviderError(
                "worktrunk_cli_error",
                proc.stderr.strip() or f"wt exited with {proc.returncode}",
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

    # --- Worktree lifecycle ---
    def worktree_create(
        self,
        *,
        name: str = "worker",
        base: str | None = None,
        repo: str | None = None,
        copy_ignored: bool = True,
        **kwargs: Any,
    ) -> dict[str, Any]:
        argv = ["wt", "switch", "--create", str(name), "--no-cd", "-y", "--format=json"]
        if base:
            argv += ["--base", str(base)]
        raw = self._run(argv)
        if copy_ignored:
            self._run(["wt", "step", "copy-ignored"])
        wt_path = raw.get("path") or raw.get("worktree") or f"/tmp/wt/{name}"
        return {
            "worktree": {"name": name, "path": wt_path, "base": base, "copyIgnored": copy_ignored},
            "upstream": raw,
        }

    def worktree_list(self, *, repo: str | None = None, limit: int | None = None, **kwargs: Any) -> dict[str, Any]:
        raw = self._run(["wt", "list", "--format=json"])
        items = raw.get("worktrees", raw.get("items", []))
        if limit is not None and isinstance(items, list):
            items = items[:limit]
        return {"worktrees": items, "upstream": raw}

    def worktree_show(self, *, selector: str = "current", **kwargs: Any) -> dict[str, Any]:
        listed = self.worktree_list()
        for wt in listed.get("worktrees", []):
            if isinstance(wt, dict) and (wt.get("name") == selector or wt.get("branch") == selector or wt.get("path") == selector):
                return {"worktree": wt}
        return {"worktree": {"name": selector, "selector": selector}, "upstream": listed.get("upstream", {})}

    def worktree_rm(self, *, selector: str = "", force: bool = False, **kwargs: Any) -> dict[str, Any]:
        argv = ["wt", "remove", "--reap"]
        if selector:
            argv.append(str(selector))
        if force:
            argv.append("--force")
        raw = self._run(argv)
        return {"removed": True, "selector": selector, "upstream": raw}

    def predict_and_merge(self, branch: str, *, target: str | None = None, **kwargs: Any) -> dict[str, Any]:
        """Run Worktrunk's conflict-predicting merge (`wt merge --format=json`)."""
        argv = ["wt", "merge", str(branch), "--format=json"]
        if target:
            argv += ["--target", str(target)]
        raw = self._run(argv)
        return {
            "merged": bool(raw.get("merged", True)),
            "branch": branch,
            "target": target,
            "conflicts": raw.get("conflicts", []),
            "upstream": raw,
        }

    # --- Worker lifecycle ---
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
        branch_name = name or (f"wt-{task_id}" if task_id else f"wt-{uuid.uuid4().hex[:6]}")
        created = self.worktree_create(name=branch_name)
        wt_path = str(created["worktree"]["path"] if worktree in ("new-child", "") else worktree)

        harness = build_harness_command(agent, profile, wt_path, prompt=prompt)
        exec_argv = ["wt", "switch", branch_name, "--no-cd", "-y", "-x", harness["command"], "--format=json"]
        raw = self._run(exec_argv)

        dispatch_id = str(raw.get("dispatchId") or raw.get("id") or f"wt_dsp_{uuid.uuid4().hex[:10]}")
        handle = str(raw.get("agentTerminalHandle") or f"tmux:{branch_name}")
        effective = {
            "agent": agent,
            "profile": profile,
            "command": harness["command"],
            "argv": harness["argv"],
            "env": harness["env"],
            "profile_flag": harness["profile_flag"],
            "branch": branch_name,
            "worktree": wt_path,
        }
        now = time.time()
        with self.state._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dispatches(
                    dispatch_id, task_id, run_id, worktree, agent, profile,
                    terminal_handle, state, terminal_state, backend, launch_effective, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', 'active', 'worktrunk', ?, ?, ?)
                """,
                (dispatch_id, task_id, run or "default", wt_path, agent, profile, handle, json.dumps(effective), now, now),
            )

        res = {
            "state": "ready",
            "dispatchId": dispatch_id,
            "agentTerminalHandle": handle,
            "worktree": wt_path,
            "branch": branch_name,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective},
            "upstream": raw,
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def worker_list(self, *, run: str | None = None, **kwargs: Any) -> dict[str, Any]:
        with self.state._connect() as conn:
            rows = conn.execute("SELECT * FROM dispatches WHERE backend = 'worktrunk' ORDER BY created_at ASC").fetchall()
        return {"workers": [dict(r) for r in rows]}

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        with self.state._connect() as conn:
            row = conn.execute("SELECT * FROM dispatches WHERE dispatch_id = ?", (dispatch_id,)).fetchone()
        if not row:
            raise ProviderError("dispatch_not_found", f"dispatch {dispatch_id!r} not found")
        return {"dispatchId": dispatch_id, "worker": dict(row)}

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        return {"dispatchId": dispatch_id, "source": source, "lines": []}

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        with self.state._connect() as conn:
            row = conn.execute("SELECT worktree FROM dispatches WHERE dispatch_id = ?", (dispatch_id,)).fetchone()
            conn.execute(
                "UPDATE dispatches SET state = ?, terminal_state = 'fenced', updated_at = ? WHERE dispatch_id = ?",
                (verb, time.time(), dispatch_id),
            )
        if verb in ("release", "abandon") and row and row["worktree"]:
            self.worktree_rm(selector=str(row["worktree"]), force=(verb == "abandon"))
        return {"dispatchId": dispatch_id, "verb": verb, "state": verb, "reason": reason}

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
