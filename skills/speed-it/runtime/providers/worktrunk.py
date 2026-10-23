#!/usr/bin/env python3
"""worktrunk.py — Worktrunk (`max-sixty/worktrunk`, `wt`) RuntimeProvider (#583).

Maps the canonical Runtime Provider Interface (RPI) onto `wt` (source-verified against
max-sixty/worktrunk `src/cli/mod.rs`, `src/cli/step.rs`, `src/cli/config.rs`):
  - `worktree_create` -> `wt switch --create <branch> [--base <b>] --no-cd --no-hooks --format=json`
    (JSON `{action, branch, path, ...}`; `path` is required) + `wt step copy-ignored --to <path>`
    so the warm-start copies into the NEW worktree, not the caller's. Never `-y`: it auto-approves
    the repo's own `post-create`/`post-start` hook commands, which would run UNSANDBOXED on the host.
  - `worktree_list/show` -> `wt list --format=json` (schema-2 `{items:[{branch, worktree:{path}}]}`
    or schema-1 bare array).
  - `worktree_rm` -> `wt remove <selector> --reap --foreground --format=json` (selector required).
  - `worker_start` -> provisions (or reuses the given) worktree, installs per-harness deny hooks,
    marks the branch (`wt config state marker set 🤖 --branch=<b>`), then launches the COMPLETE
    harness line DETACHED: `tmux new-session -d -s <branch>-<dispatch> -c <wt> <shell>` (never
    `wt switch -x`, which runs the agent in the foreground under the CLI timeout). The dispatch
    id in the session name keeps two dispatches on one branch from sharing (and killing) a session.
  - `worker_read` -> `tmux capture-pane -p -t <session> -S -<n>` (terminal source).
  - `worker_fence` -> `retain` makes no upstream call; `stop` kills the tmux session;
    `release`/`abandon` are refused while another live dispatch shares the worktree, preserve the
    worker's real HEAD under `refs/open-fleet/preserved/<dispatch>` and check for uncommitted work
    BEFORE the session is killed (a refused release leaves the worker running), then kill, re-pin
    and re-check (recording `stopped` if the re-check refuses), and only then `wt remove <branch>`.
  - `predict_and_merge` -> refuses a dirty worktree (`wt merge` would commit/squash the dirt),
    ALWAYS predicts conflicts (`wt list` `default_branch.merge_conflicts` for the default branch;
    `git merge-tree --write-tree` (exit 1 = conflicts) for an explicit target; an undetermined prediction refuses),
    then `wt merge [target] --branch <b> --no-remove --format=json`.

"""
from __future__ import annotations

import os
import re
import uuid
from pathlib import Path
from typing import Any, Callable

from .base import (
    FENCED_DISPATCH_STATES,
    ProviderError,
    RuntimeProvider,
    build_harness_command,
    check_monotonic_profile,
    fence_state,
    normalize_read,
    parse_json_strict,
    require_id,
)
from ._external import call_runner, foreign_dirty_paths, insert_dispatch, load_dispatch, preserve_worker_head, record_fence, run_cli_text, show_from_row
from .local_state import LocalStateStore

def _is_placeholder_worktree(worktree: str | None) -> bool:
    return not worktree or worktree.startswith(("new-", "current", "active"))


def _tmux_session_name(branch: str) -> str:
    # tmux treats `.` and `:` as target separators; keep the name addressable.
    return re.sub(r"[^A-Za-z0-9_-]", "-", branch) or "wt-worker"


class WorktrunkProvider(RuntimeProvider):
    """RuntimeProvider adapter for Worktrunk (`wt`) with detached tmux worker sessions."""

    name = "worktrunk"

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

    def _run(self, argv: list[str], **kwargs: Any) -> str:
        self.call_log.append(list(argv))
        return call_runner(self._runner, argv, self.name, **kwargs)

    def _run_json(self, argv: list[str], **kwargs: Any) -> Any:
        return parse_json_strict(self._run(argv, **kwargs), self.name)

    def _hooks(self, wt_path: str, agent: str, profile: str) -> dict[str, str]:
        if self._install_hooks is not None:
            return self._install_hooks(wt_path, agent, profile)
        from .posix import install_worktree_hooks

        return install_worktree_hooks(wt_path, agent, profile)

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
        # --no-hooks, never -y: -y would auto-approve repo-defined hook commands on the host.
        argv = ["wt", "switch", "--create", str(name), "--no-cd", "--no-hooks", "--format=json"]
        if base:
            argv += ["--base", str(base)]
        raw = self._run_json(argv)
        wt_path = require_id(raw, "path", provider=self.name, what="worktree path")
        copied: Any = None
        if copy_ignored:
            copied = self._run_json(["wt", "step", "copy-ignored", "--to", wt_path, "--format=json"])
        return {
            "worktree": {
                "name": name,
                "branch": raw.get("branch") or name,
                "path": wt_path,
                "base": base,
                "copyIgnored": copy_ignored,
            },
            "upstream": raw,
            "copyIgnored": copied,
        }

    def _list_items(self) -> tuple[list[dict[str, Any]], Any]:
        raw = self._run_json(["wt", "list", "--format=json"])
        items: list[dict[str, Any]] = []
        source = raw.get("items") if isinstance(raw, dict) else raw
        if not isinstance(source, list):
            raise ProviderError("worktrunk_bad_json", "wt list returned neither an items envelope nor an array", {"response": raw})
        for it in source:
            if not isinstance(it, dict):
                continue
            wt = it.get("worktree") if isinstance(it.get("worktree"), dict) else {}
            path = wt.get("path") or it.get("path")
            if not path:
                continue  # branch-only rows have no worktree
            items.append({"branch": it.get("branch"), "path": path, "raw": it})
        return items, raw

    def worktree_list(self, *, repo: str | None = None, limit: int | None = None, **kwargs: Any) -> dict[str, Any]:
        items, raw = self._list_items()
        if limit is not None:
            items = items[:limit]
        return {"worktrees": [{"branch": i["branch"], "path": i["path"]} for i in items], "upstream": raw}

    def _find_worktree(self, selector: str) -> dict[str, Any]:
        items, _ = self._list_items()
        sel_real = os.path.realpath(selector) if os.path.isabs(selector) else None
        for it in items:
            if it["branch"] == selector or it["path"] == selector or (sel_real and os.path.realpath(it["path"]) == sel_real):
                return it
        raise ProviderError("worktree_not_found", f"worktrunk: no worktree matches {selector!r}")

    def worktree_show(self, *, selector: str = "current", **kwargs: Any) -> dict[str, Any]:
        it = self._find_worktree(selector)
        return {"worktree": {"branch": it["branch"], "path": it["path"]}, "upstream": it["raw"]}

    def worktree_rm(self, *, selector: str = "", force: bool = False, **kwargs: Any) -> dict[str, Any]:
        if not selector:
            # `wt remove` with no target removes the CURRENT worktree — never a default here.
            raise ProviderError("invalid_selector", "worktrunk worktree rm requires an explicit branch or path")
        argv = ["wt", "remove", str(selector), "--reap", "--foreground", "--format=json"]
        if force:
            argv.append("--force")
        raw = self._run_json(argv)
        return {"removed": True, "selector": selector, "upstream": raw}

    def _predict_conflicts(self, item: dict[str, Any], branch: str, target: str | None) -> bool:
        """True/False conflict prediction for merging `branch` into `target` (default branch if None)."""
        if target:
            # `wt list` only simulates the DEFAULT branch; simulate the explicit target the same way.
            try:
                self._run(["git", "-C", str(item["path"]), "merge-tree", "--write-tree", "--name-only", str(target), str(branch)])
                return False
            except ProviderError as exc:
                if exc.data.get("returncode") == 1:  # merge-tree --write-tree: exit 1 == conflicts
                    return True
                raise
        default = item["raw"].get("default_branch")
        predicted = default.get("merge_conflicts") if isinstance(default, dict) else None
        if not isinstance(predicted, bool):
            raise ProviderError(
                "merge_prediction_unavailable",
                f"wt list could not determine whether {branch!r} conflicts with the default branch; refusing to merge blind",
                {"item": item["raw"]},
            )
        return predicted

    def predict_and_merge(self, branch: str, *, target: str | None = None, **kwargs: Any) -> dict[str, Any]:
        """Refuse a dirty worktree or a predicted conflict, else `wt merge` (squash+rebase, keeps the worktree)."""
        items, _ = self._list_items()
        item = next((it for it in items if it["branch"] == branch), None)
        if item is None:
            raise ProviderError("worktree_not_found", f"worktrunk: no worktree for branch {branch!r}; cannot check it before merging")
        # `wt merge` commits (or squash-stages) uncommitted changes by default: never merge dirt.
        dirty = foreign_dirty_paths(self._run, str(item["path"]))
        if dirty:
            raise ProviderError(
                "uncommitted_work",
                f"worktree {item['path']!r} has uncommitted changes wt merge would commit: {', '.join(dirty[:10])}",
                {"dirty": dirty},
            )
        predicted = self._predict_conflicts(item, branch, target)
        if predicted:
            raise ProviderError(
                "merge_conflict_predicted",
                f"{branch!r} is predicted to conflict with {target or 'the default branch'!r}; resolve before merging",
            )
        argv = ["wt", "merge"]
        if target:
            argv.append(str(target))
        argv += ["--branch", str(branch), "--no-remove", "--format=json"]
        raw = self._run_json(argv)
        return {
            "merged": True,
            "branch": branch,
            "target": raw.get("target", target) if isinstance(raw, dict) else target,
            "predictedConflicts": predicted,
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
        base: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        cached = self.state.get_or_record_request(retry_request, "worker-start")
        if cached:
            return cached

        check_monotonic_profile(parent_profile, profile)
        if profile == "danger":
            raise ProviderError("unsupported_profile", "worktrunk launches on the host; PROFILE=danger needs an isolated sandbox")
        task_prompt = self.resolve_task_prompt(task_id, prompt)

        created: dict[str, Any] | None = None
        if _is_placeholder_worktree(worktree):
            branch = name or (f"wt-{task_id}" if task_id else f"wt-{uuid.uuid4().hex[:6]}")
            created = self.worktree_create(name=branch, base=base)
            wt_path = str(created["worktree"]["path"])
            branch = str(created["worktree"]["branch"])
        else:
            found = self._find_worktree(worktree)
            wt_path = str(found["path"])
            branch = str(found["branch"] or "")
            if not branch:
                raise ProviderError("worktree_detached", f"worktree {wt_path!r} has no branch; worktrunk keys workers by branch")

        hooks = self._hooks(wt_path, agent, profile)
        harness = build_harness_command(agent, profile, wt_path, prompt=task_prompt)
        dispatch_id = f"wt_dsp_{uuid.uuid4().hex[:10]}"
        # One session per DISPATCH: two dispatches on one branch must never share (or kill) one.
        session = _tmux_session_name(f"{branch}-{dispatch_id}")
        handle = f"tmux:{session}"

        marker: Any
        try:
            self._run(["wt", "config", "state", "marker", "set", "🤖", f"--branch={branch}"])
            marker = "🤖"
        except ProviderError as exc:  # cosmetic; never blocks the launch
            marker = {"error": exc.code}

        effective = {
            "agent": agent,
            "profile": profile,
            "command": harness["command"],
            "shell": harness["shell"],
            "argv": harness["argv"],
            "env": harness["env"],
            "profile_flag": harness["profile_flag"],
            "branch": branch,
            "worktree": wt_path,
            "tmuxSession": session,
            "mechanism": "tmux.new-session",
            "hooks": hooks,
            "marker": marker,
        }
        # Record before launch so an immediate fence finds the dispatch; roll back on failure.
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
        )
        launch_argv = ["tmux", "new-session", "-d", "-s", session, "-c", wt_path, harness["shell"]]
        try:
            self._run(launch_argv)
        except ProviderError:
            with self.state._connect() as conn:
                conn.execute("DELETE FROM dispatches WHERE dispatch_id = ?", (dispatch_id,))
            raise

        res = {
            "state": "ready",
            "dispatchId": dispatch_id,
            "agentTerminalHandle": handle,
            "worktree": wt_path,
            "branch": branch,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective, "argv": launch_argv},
            "upstream": created["upstream"] if created else None,
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def worker_list(self, *, run: str | None = None, **kwargs: Any) -> dict[str, Any]:
        with self.state._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM dispatches WHERE backend = ? ORDER BY created_at ASC", (self.name,)
            ).fetchall()
        workers = [
            {
                "dispatchId": r["dispatch_id"],
                "taskId": r["task_id"],
                "state": r["state"],
                "terminalState": r["terminal_state"],
                "agentTerminalHandle": r["terminal_handle"],
                "worktree": r["worktree"],
            }
            for r in rows
            if not run or r["run_id"] == run
        ]
        return {"workers": workers}

    def _session_alive(self, session: str) -> bool:
        try:
            self._run(["tmux", "has-session", "-t", f"={session}"])
            return True
        except ProviderError:
            return False

    def _kill_session(self, session: str | None) -> None:
        if session and self._session_alive(session):
            self._run(["tmux", "kill-session", "-t", f"={session}"])

    def _live_sharers(self, dispatch_id: str, wt_path: str) -> list[str]:
        """Other not-yet-fenced dispatches recorded on the same worktree."""
        with self.state._connect() as conn:
            rows = conn.execute(
                "SELECT dispatch_id, worktree, terminal_state FROM dispatches WHERE backend = ? AND dispatch_id != ?",
                (self.name, dispatch_id),
            ).fetchall()
        real = os.path.realpath(wt_path) if wt_path else ""
        return [
            str(r["dispatch_id"])
            for r in rows
            if r["terminal_state"] not in FENCED_DISPATCH_STATES and r["worktree"] and os.path.realpath(r["worktree"]) == real
        ]

    def _check_removable(self, wt_path: str, dispatch_id: str, verb: str) -> dict[str, str]:
        """Pin the worker HEAD; a release refuses while uncommitted non-hook work remains."""
        preserved = preserve_worker_head(self._run, wt_path, dispatch_id)
        dirty = foreign_dirty_paths(self._run, wt_path)
        if dirty and verb == "release":
            raise ProviderError(
                "uncommitted_work",
                f"worktree {wt_path!r} has uncommitted changes a release would lose: {', '.join(dirty[:10])}",
                {"preserved": preserved, "dirty": dirty},
            )
        return preserved

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        row = load_dispatch(self.state, dispatch_id, self.name)
        session = row["effective"].get("tmuxSession")
        alive = self._session_alive(session) if session else False
        return show_from_row(row, stage="running" if alive else "session-exited", raw={"tmuxSession": session, "alive": alive})

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        row = load_dispatch(self.state, dispatch_id, self.name)
        session = row["effective"].get("tmuxSession")
        if not session:
            raise ProviderError("no_terminal", f"dispatch {dispatch_id!r} recorded no tmux session")
        out = self._run(["tmux", "capture-pane", "-p", "-t", f"={session}:", "-S", f"-{int(limit)}"])
        lines = out.splitlines()[-int(limit):] if limit else out.splitlines()
        return normalize_read(
            "terminal",
            lines=lines,
            handle=row["terminal_handle"],
            fallback_reason="worktrunk_has_no_transcript_store" if source == "transcript" else None,
        )

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        fence_state(verb)
        row = load_dispatch(self.state, dispatch_id, self.name)
        eff = row["effective"]
        out: dict[str, Any] = {"dispatchId": dispatch_id, "verb": verb, "reason": reason}
        if verb == "retain":
            new_state, term_state = record_fence(self.state, dispatch_id, verb)
            out.update({"state": new_state, "terminalState": term_state, "upstreamCalls": []})
            return out

        session = eff.get("tmuxSession")
        if verb == "stop":
            self._kill_session(session)
        else:  # release / abandon remove the worktree: every refusal must happen BEFORE the kill
            wt_path = row.get("worktree") or eff.get("worktree") or ""
            sharers = self._live_sharers(dispatch_id, wt_path)
            if sharers:
                raise ProviderError(
                    "worktree_shared",
                    f"worktree {wt_path!r} is still used by live dispatch(es) {', '.join(sharers)}; "
                    f"fence them first — {verb} would remove the worktree under them",
                    {"sharers": sharers},
                )
            self._check_removable(wt_path, dispatch_id, verb)  # refusal leaves the worker running
            self._kill_session(session)
            try:
                # The worker may have committed or written between the check and the kill.
                preserved = self._check_removable(wt_path, dispatch_id, verb)
            except ProviderError:
                record_fence(self.state, dispatch_id, "stop")  # it IS stopped now; the row must say so
                raise
            branch = eff.get("branch") or wt_path
            # --force only removes OUR hook artifacts (release) or the abandoned dirt; HEAD is pinned.
            removed = self.worktree_rm(selector=str(branch), force=True)
            out.update({"preserved": preserved, "removed": removed["upstream"]})
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
