#!/usr/bin/env python3
"""superset.py — Superset (`superset-sh/superset`) CLI RuntimeProvider (#582).

Source-verified against superset-sh/superset `packages/cli/src/commands/**` (all flags kebab-case,
`--json` global; host-side workspaces need `--local`):
  - `worktree_list/show/create/rm` -> `superset workspaces list|get|create|delete --local --json`
    (`create` returns `{workspace:{id}}` but no path, so the path comes from
    `workspaces get <id> --local --json` -> `worktreePath`). `delete` is an alias of `archive`,
    which removes the worktree folder WITH any uncommitted changes (only the branch stays), so
    `worktree_rm` first pins the worktree HEAD under `refs/open-fleet/preserved/` and, unless
    `force`, refuses while uncommitted non-hook work remains.
  - `worker_start` (the task spec always reaches the worker):
    * `ro`: NEVER `superset agents create` (its built-in presets carry
      `--dangerously-skip-permissions` / `--dangerously-bypass-approvals-and-sandbox`). Installs the
      deny-hook configs in the real worktree, then runs the COMPLETE ro launch line via
      `superset terminals create --workspace <id> --cwd <path> --command <shell> --local --json`
      (-> `terminalId`). Fails closed when the worktree path cannot be resolved.
    * `rw`: installs deny hooks, then
      `superset agents create --workspace <id> --agent <agent> --prompt <spec> --local --json`
      (-> `sessionId`, which is the agent's terminal id).
    * `danger`: Superset Cloud Sandbox —
      `superset workspaces create --environment <recipe> --name <n> --branch <n> --agent <a>
      --prompt <spec> --json` (no `--local`; `--environment` exists only on `workspaces create`).
  - read/show/kill route by the mechanism stored in `launch_effective`:
    `agents read|explain` (agents.create), `terminals read` + `snapshot` (terminals.create),
    `workspaces get` (cloud); stop/release/abandon -> `superset terminals close` (non-destructive:
    the workspace and its commits stay). `retain` makes no upstream call.
  - `worker_wait` -> `superset agents wait --until settled|idle|blocked|working --timeout <s>`.
  - Task DAG, typed mailbox, and HITL gates delegate to `LocalStateStore`.
"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Callable

from .base import (
    ProviderError,
    RuntimeProvider,
    build_harness_command,
    check_monotonic_profile,
    env_get,
    fence_state,
    normalize_read,
    parse_json_strict,
    require_id,
)
from .local_state import LocalStateStore
from ._external import (
    call_runner,
    foreign_dirty_paths,
    insert_dispatch,
    load_dispatch,
    preserve_worker_head,
    record_fence,
    run_cli_text,
    show_from_row,
)

AGENT_WAIT_UNTIL = ("settled", "idle", "blocked", "working")


def _is_placeholder(worktree: str | None) -> bool:
    return not worktree or worktree.startswith(("new-", "current", "active"))


class SupersetProvider(RuntimeProvider):
    """RuntimeProvider adapter for Superset (`superset` CLI / Desktop local & cloud workspaces)."""

    name = "superset"

    def __init__(
        self,
        state: LocalStateStore | None = None,
        runner: Callable[..., Any] | None = None,
        *,
        db_path: str | Path | None = None,
        env: dict[str, str] | None = None,
        install_hooks: Callable[..., Any] | None = None,
        **kwargs: Any,
    ) -> None:
        self.env = dict(env) if env is not None else None
        self.state = state or LocalStateStore(db_path=db_path, env=self.env)
        self._runner = runner or self._default_runner
        self._install_hooks = install_hooks
        self.call_log: list[Any] = []

    def _default_runner(self, argv: list[str], **kwargs: Any) -> str:
        return run_cli_text(argv, self.name, timeout=int(kwargs.get("timeout", 60)))

    def _run_json(self, argv: list[str], **kwargs: Any) -> Any:
        self.call_log.append(list(argv))
        return parse_json_strict(call_runner(self._runner, argv, self.name, **kwargs), self.name)

    def _hooks(self, wt_path: str, agent: str, profile: str) -> dict[str, str]:
        if self._install_hooks is not None:
            return self._install_hooks(wt_path, agent, profile)
        from .posix import install_worktree_hooks

        return install_worktree_hooks(wt_path, agent, profile)

    # --- Worktree / Workspace operations ---
    def worktree_list(self, *, repo: str | None = None, limit: int | None = None, **kwargs: Any) -> dict[str, Any]:
        argv = ["superset", "workspaces", "list", "--local", "--json"]
        if repo:
            argv += ["--project", str(repo)]
        raw = self._run_json(argv)
        rows = raw if isinstance(raw, list) else (raw.get("workspaces") if isinstance(raw, dict) else None)
        if not isinstance(rows, list):
            raise ProviderError("superset_bad_json", "superset workspaces list returned no workspace array", {"response": raw})
        if limit is not None:
            rows = rows[:limit]
        return {"worktrees": rows, "upstream": raw}

    def worktree_show(self, *, selector: str = "current", **kwargs: Any) -> dict[str, Any]:
        argv = ["superset", "workspaces", "get"]
        if selector and selector != "current":
            argv.append(str(selector))  # omitted -> upstream defaults to $SUPERSET_WORKSPACE_ID
        raw = self._run_json(argv + ["--local", "--json"])
        if not isinstance(raw, dict):
            raise ProviderError("superset_bad_json", "superset workspaces get returned no object", {"response": raw})
        require_id(raw, "id", provider=self.name, what="workspace id")
        return {"worktree": {**raw, "path": raw.get("worktreePath")}, "upstream": raw}

    def _workspace_path(self, workspace_id: str) -> str:
        shown = self.worktree_show(selector=workspace_id)["worktree"]
        path = shown.get("worktreePath")
        if not path or shown.get("worktreeExists") is False:
            raise ProviderError(
                "worktree_unresolved",
                f"superset workspace {workspace_id!r} reports no existing worktreePath",
                {"workspace": shown},
            )
        return str(path)

    def worktree_create(
        self,
        *,
        name: str = "worker",
        base: str | None = None,
        repo: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        project = repo or env_get("OPEN_FLEET_SUPERSET_PROJECT", "ORCA_SUPERSET_PROJECT", self.env, "")
        if not project:
            raise ProviderError(
                "missing_project",
                "superset workspaces create needs a project id (--repo or OPEN_FLEET_SUPERSET_PROJECT)",
            )
        argv = [
            "superset", "workspaces", "create", "--local", "--json",
            "--project", str(project), "--name", str(name), "--branch", str(name),
        ]
        if base:
            argv += ["--base-branch", str(base)]
        raw = self._run_json(argv)
        ws_id = require_id(raw, "workspace.id", "id", provider=self.name, what="workspace id")
        path = self._workspace_path(ws_id)
        return {"worktree": {"id": ws_id, "name": name, "path": path, "base": base}, "upstream": raw}

    def _git(self, argv: list[str]) -> str:
        self.call_log.append(list(argv))
        return call_runner(self._runner, argv, self.name)

    def worktree_rm(self, *, selector: str = "", force: bool = False, **kwargs: Any) -> dict[str, Any]:
        if not selector:
            raise ProviderError("invalid_selector", "superset worktree rm requires an explicit workspace id")
        # `workspaces delete` (= archive) removes the folder with any uncommitted changes and has
        # no --force/--keep-dirty switch: every safety check happens here, before the call.
        shown = self.worktree_show(selector=selector)["worktree"]
        wt_path = shown.get("worktreePath")
        preserved: dict[str, str] | None = None
        dirty: list[str] = []
        if wt_path and shown.get("worktreeExists") is not False:
            preserved = preserve_worker_head(self._git, str(wt_path), f"superset-{selector}")
            dirty = foreign_dirty_paths(self._git, str(wt_path))
            if dirty and not force:
                raise ProviderError(
                    "uncommitted_work",
                    f"superset workspace {selector!r} has uncommitted changes an archive would delete: {', '.join(dirty[:10])}",
                    {"preserved": preserved, "dirty": dirty, "worktree": wt_path},
                )
        elif not force:
            # No folder on disk to check: only an explicit force may archive it.
            raise ProviderError(
                "worktree_unresolved",
                f"superset workspace {selector!r} reports no existing worktreePath; pass --force to archive it anyway",
                {"workspace": shown},
            )
        raw = self._run_json(["superset", "workspaces", "delete", str(selector), "--local", "--json"])
        deleted = raw.get("deleted") if isinstance(raw, dict) else None
        if not isinstance(deleted, list) or str(selector) not in [str(d) for d in deleted]:
            raise ProviderError("superset_delete_failed", f"superset did not delete workspace {selector!r}", {"response": raw})
        return {"removed": True, "selector": selector, "worktree": wt_path, "preserved": preserved,
                "discardedDirty": dirty, "upstream": raw}

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
        repo: str | None = None,
        base: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        cached = self.state.get_or_record_request(retry_request, "worker-start")
        if cached:
            return cached

        check_monotonic_profile(parent_profile, profile)
        task_prompt = self.resolve_task_prompt(task_id, prompt)
        worker_title = name or (f"worker-{task_id}" if task_id else f"worker-{uuid.uuid4().hex[:6]}")

        recipe: str | None = None
        hooks: dict[str, str] | None = None
        harness: dict[str, Any] | None = None
        terminal_id: str | None = None
        upstream: dict[str, Any] = {}
        if profile == "danger":
            recipe = (
                on_env
                or kwargs.get("environment")
                or env_get("OPEN_FLEET_SANDBOX_RECIPE", "ORCA_SANDBOX_RECIPE", self.env, "")
            )
            if not recipe:
                raise ProviderError(
                    "missing_sandbox_recipe",
                    "Superset profile='danger' requires OPEN_FLEET_SANDBOX_RECIPE or ORCA_SANDBOX_RECIPE",
                )
            argv = [
                "superset", "workspaces", "create", "--json",
                "--environment", str(recipe), "--name", worker_title, "--branch", worker_title,
                "--agent", str(agent), "--prompt", task_prompt,
            ]
            raw = self._run_json(argv, timeout=180)
            workspace_id = require_id(raw, "id", "workspace.id", provider=self.name, what="cloud workspace id")
            wt_path: str | None = None  # remote sandbox: no host path exists
            mechanism = "workspaces.create+cloud"
            upstream["workspace"] = raw
        else:
            if _is_placeholder(worktree):
                created = self.worktree_create(name=worker_title, base=base, repo=repo)
                workspace_id = str(created["worktree"]["id"])
                wt_path = str(created["worktree"]["path"])
                upstream["workspace"] = created["upstream"]
            else:
                workspace_id = str(worktree)
                # Fails closed (worktree_unresolved) when Superset cannot name the real path.
                wt_path = self._workspace_path(workspace_id)
            hooks = self._hooks(wt_path, agent, profile)
            if profile == "ro":
                # Superset agent presets inject YOLO flags unconditionally; route ro via a terminal
                # running the COMPLETE ro launch line (prompt included).
                harness = build_harness_command(agent, "ro", wt_path, prompt=task_prompt)
                argv = [
                    "superset", "terminals", "create", "--local", "--json",
                    "--workspace", workspace_id, "--cwd", wt_path, "--command", harness["shell"],
                ]
                raw = self._run_json(argv)
                terminal_id = require_id(raw, "terminalId", provider=self.name, what="terminal id")
                mechanism = "terminals.create"
            elif profile == "rw":
                harness = build_harness_command(agent, "rw", wt_path, prompt=task_prompt)
                argv = [
                    "superset", "agents", "create", "--local", "--json",
                    "--workspace", workspace_id, "--agent", str(agent), "--prompt", task_prompt,
                ]
                raw = self._run_json(argv)
                terminal_id = require_id(raw, "sessionId", provider=self.name, what="agent session id")
                mechanism = "agents.create"
            else:
                raise ProviderError("invalid_profile", f"unknown profile {profile!r}")
            upstream["launch"] = raw

        dispatch_id = f"sup_{terminal_id}" if terminal_id else f"sup_ws_{workspace_id}"
        handle = f"superset:{workspace_id}:{terminal_id}" if terminal_id else f"superset:{workspace_id}"
        effective: dict[str, Any] = {
            "agent": agent,
            "profile": profile,
            "mechanism": mechanism,
            "workspaceId": workspace_id,
            "terminalId": terminal_id,
            "worktree": wt_path,
            "environment": recipe,
            "hooks": hooks,
        }
        if harness is not None:
            effective.update(
                {
                    "command": harness["command"],
                    "shell": harness["shell"] if mechanism == "terminals.create" else None,
                    "argv": harness["argv"] if mechanism == "terminals.create" else None,
                    "env": harness["env"],
                    "profile_flag": harness["profile_flag"],
                }
            )
        if mechanism == "agents.create":
            # Superset's preset decides the real flags; record what that preset is known to carry.
            effective["profile_flag"] = "superset-preset (--dangerously-skip-permissions class)"
        insert_dispatch(
            self.state,
            dispatch_id=dispatch_id,
            task_id=task_id,
            run=run,
            worktree=wt_path,
            agent=agent,
            profile=profile,
            handle=handle,
            backend=self.name,
            effective=effective,
            session_id=terminal_id,
        )
        res = {
            "state": "ready",
            "dispatchId": dispatch_id,
            "agentTerminalHandle": handle,
            "worktree": wt_path,
            "workspaceId": workspace_id,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective, "argv": argv},
            "upstream": upstream,
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def worker_list(
        self,
        *,
        run: str | None = None,
        task: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        raw = self._run_json(["superset", "snapshot", "--json"])
        live: set[str] = set()
        for ws in (raw.get("workspaces") if isinstance(raw, dict) else None) or []:
            terminals = (ws.get("terminals") or []) if isinstance(ws, dict) else []
            live.update(str(t["id"]) for t in terminals if isinstance(t, dict) and t.get("id"))
        with self.state._connect() as conn:
            rows = conn.execute("SELECT * FROM dispatches WHERE backend = ? ORDER BY created_at ASC", (self.name,)).fetchall()
        workers = [
            {
                "dispatchId": r["dispatch_id"],
                "taskId": r["task_id"],
                "state": r["state"],
                "terminalState": r["terminal_state"],
                "agentTerminalHandle": r["terminal_handle"],
                "worktree": r["worktree"],
                "terminalLive": (r["session_id"] in live) if r["session_id"] else None,
            }
            for r in rows
            if (not run or r["run_id"] == run) and (not task or r["task_id"] == task)
        ]
        if limit is not None:
            workers = workers[:limit]
        return {"workers": workers, "snapshot": raw}

    def _target(self, eff: dict[str, Any]) -> list[str]:
        return ["--workspace", str(eff["workspaceId"]), "--terminal", str(eff["terminalId"]), "--local", "--json"]

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        row = load_dispatch(self.state, dispatch_id, self.name)
        eff = row["effective"]
        mech = eff.get("mechanism")
        if mech == "agents.create":
            raw = self._run_json(["superset", "agents", "explain"] + self._target(eff))
            stage = str(raw.get("state") or "unknown") if isinstance(raw, dict) else "unknown"
        elif mech == "terminals.create":
            raw = self._run_json(["superset", "snapshot", "--workspace", str(eff["workspaceId"]), "--json"])
            terms = [
                t
                for ws in (raw.get("workspaces") or [] if isinstance(raw, dict) else [])
                for t in (ws.get("terminals") or [])
                if isinstance(t, dict) and str(t.get("id")) == str(eff["terminalId"])
            ]
            stage = "running" if terms else "terminal-closed"
        else:
            raw = self._run_json(["superset", "workspaces", "get", str(eff["workspaceId"]), "--json"])
            stage = str(raw.get("status") or "unknown") if isinstance(raw, dict) else "unknown"
        return show_from_row(row, stage=stage, raw=raw)

    def worker_read(
        self,
        *,
        dispatch_id: str = "",
        source: str = "transcript",
        limit: int = 50,
        **kwargs: Any,
    ) -> dict[str, Any]:
        row = load_dispatch(self.state, dispatch_id, self.name)
        eff = row["effective"]
        mech = eff.get("mechanism")
        if mech == "agents.create" and source == "transcript":
            raw = self._run_json(["superset", "agents", "read"] + self._target(eff))
            text = raw.get("text") if isinstance(raw, dict) else None
            if not isinstance(text, str):
                raise ProviderError("superset_bad_json", "superset agents read returned no transcript text", {"response": raw})
            out = normalize_read(
                "transcript",
                messages=[{"id": f"{eff['terminalId']}_transcript", "role": "assistant", "blocks": [{"type": "text", "text": text}]}],
            )
            out["upstream"] = raw
            return out
        if mech in ("agents.create", "terminals.create"):
            raw = self._run_json(["superset", "terminals", "read"] + self._target(eff) + ["--max-lines", str(int(limit))])
            text = raw.get("text") if isinstance(raw, dict) else None
            if not isinstance(text, str):
                raise ProviderError("superset_bad_json", "superset terminals read returned no text", {"response": raw})
            out = normalize_read(
                "terminal",
                lines=text.splitlines()[-int(limit):],
                handle=row["terminal_handle"],
                fallback_reason="superset_terminal_has_no_agent_transcript" if source == "transcript" else None,
            )
            out["upstream"] = raw
            return out
        raise ProviderError(
            "unsupported_operation",
            "superset: a cloud-sandbox worker exposes no terminal id to the CLI; read it in Superset",
        )

    def worker_wait(
        self,
        *,
        dispatch_id: str = "",
        until: str = "settled",
        timeout_s: int = 600,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Block on `superset agents wait --until <state>` for an agents.create worker."""
        if until not in AGENT_WAIT_UNTIL:
            raise ProviderError("invalid_condition", f"superset agents wait --until must be one of {AGENT_WAIT_UNTIL}")
        row = load_dispatch(self.state, dispatch_id, self.name)
        eff = row["effective"]
        if eff.get("mechanism") != "agents.create":
            raise ProviderError("unsupported_operation", "superset agents wait applies only to agents.create workers")
        argv = ["superset", "agents", "wait"] + self._target(eff) + ["--until", until, "--timeout", str(int(timeout_s))]
        raw = self._run_json(argv, timeout=int(timeout_s) + 30)
        return {"dispatchId": dispatch_id, "wait": raw}

    def worker_fence(
        self,
        *,
        verb: str,
        dispatch_id: str = "",
        reason: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        fence_state(verb)
        row = load_dispatch(self.state, dispatch_id, self.name)
        eff = row["effective"]
        out: dict[str, Any] = {"dispatchId": dispatch_id, "verb": verb, "reason": reason}
        if verb != "retain":
            if not eff.get("terminalId"):
                raise ProviderError(
                    "unsupported_operation",
                    "superset: a cloud-sandbox worker has no terminal the CLI can close; "
                    "archiving its workspace would destroy unverified work",
                )
            # Closing the terminal stops the worker; the workspace (and its commits) is kept.
            out["upstream"] = self._run_json(["superset", "terminals", "close"] + self._target(eff))
        else:
            out["upstreamCalls"] = []
        new_state, term_state = record_fence(self.state, dispatch_id, verb)
        out.update({"state": new_state, "terminalState": term_state})
        return out
