#!/usr/bin/env python3
"""overstory.py — Overstory (`jayminwest/overstory`, `ov`) RuntimeProvider (#588).

Source-verified against jayminwest/overstory `src/index.ts`, `src/commands/{sling,spec,stop,
inspect,worktree,mail}.ts`, `src/agents/hooks-deployer.ts` and `src/runtimes/*.ts`
(every `--json` reply is `{success, command, ...data}`):
  - `worker_start` -> writes the task spec with `ov spec write <task> --body <spec> --json`
    (-> `path`), then `ov sling <task> --capability <cap> --runtime <agent> --name <n>
    --spec <path> --skip-task-check --json` (-> `agentName`, `worktree`, `tmuxSession`).
    PROFILE=ro accepts only the capabilities Overstory deploys write-blocking guards for and that
    cannot spawn writers (`scout`, `reviewer`), and only runtimes whose guards Overstory actually
    enforces (`claude` hooks, `pi` guard extension, `sapling` guards.json) — `codex` always runs
    `--full-auto` (workspace-write) there. PROFILE=danger is refused (no sandbox upstream).
    Open-fleet hooks are NOT installed: they would overwrite Overstory's own guard hooks in
    `.claude/settings.local.json`.
  - `worker_show/read` -> `ov inspect <agent> --json` (`session.state`, `session.worktreePath`,
    `tmuxOutput`); `worker_fence` -> `ov stop <agent> --json` (keeps the worktree); `retain`
    makes no upstream call.
  - `worktree_rm` -> requires an explicit agent/branch/path; pins the agent's real HEAD under
    `refs/open-fleet/preserved/<agent>` and only then `ov stop <agent> --clean-worktree`
    (`ov worktree clean` has no selector and would clean every finished worktree).
  - Mail -> `ov mail send --to --subject --body --type --json`, `ov mail check --agent --json`
    (marks read upstream; `--ack`/`--wait` do not exist there, so ack/wait stay local),
    `ov mail list --to --unread --json` for peek, `ov mail reply <id> --body --json`.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from .base import (
    ProviderError,
    RuntimeProvider,
    check_monotonic_profile,
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
    local_worker_list,
    preserve_worker_head,
    record_fence,
    run_cli_text,
    show_from_row,
)

# hooks-deployer.ts: only these capabilities get Write/Edit blocks AND cannot spawn writers
# (`lead` is non-implementation but spawns builders; coordinator/supervisor/monitor may commit).
RO_CAPABILITIES = ("scout", "reviewer")
# runtimes/registry.ts
OV_RUNTIMES = ("aider", "amp", "claude", "codex", "copilot", "cursor", "gemini", "goose", "opencode", "pi", "sapling")
# Runtimes whose read-only enforcement Overstory implements (claude hooks, pi guards, sapling guards).
RO_ENFORCED_RUNTIMES = ("claude", "pi", "sapling")
# types.ts MailMessageType
OV_MAIL_TYPES = (
    "status", "question", "result", "error", "worker_done", "worker_died", "merge_ready", "merged",
    "merge_failed", "escalation", "health_check", "dispatch", "assign", "decision_gate",
)
# Files Overstory itself deploys into a worktree (overlay + guards) — not the worker's work.
# Exactly what Overstory writes into a worktree (src/runtimes/*.ts instructionPath, hooks
# deployer, pi/sapling guards) — never the user-owned .claude/ or .pi/ directories as a whole.
OV_ARTIFACTS = (
    ".overstory/",
    ".claude/CLAUDE.md",
    ".claude/settings.local.json",
    "AGENTS.md",
    ".pi/extensions/overstory-guard.ts",
    ".sapling/guards.json",
    "SAPLING.md",
    "CONVENTIONS.md",
    ".goosehints",
    "GEMINI.md",
    ".amp/AGENT.md",
    ".cursor/rules/overstory.md",
    ".github/copilot-instructions.md",
)


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

    def _default_runner(self, argv: list[str], **kwargs: Any) -> str:
        return run_cli_text(argv, self.name, timeout=int(kwargs.get("timeout", 120)))

    def _run(self, argv: list[str], **kwargs: Any) -> str:
        self.call_log.append(list(argv))
        return call_runner(self._runner, argv, self.name, **kwargs)

    def _ov(self, argv: list[str], **kwargs: Any) -> dict[str, Any]:
        """Run an `ov ... --json` command; `success: false` or a non-object reply is an error."""
        raw = parse_json_strict(self._run(argv, **kwargs), self.name)
        if not isinstance(raw, dict):
            raise ProviderError("overstory_bad_json", f"{' '.join(argv[:3])} returned no object", {"response": raw})
        if raw.get("success") is False:
            raise ProviderError("overstory_error", str(raw.get("error") or "ov reported failure"), {"response": raw})
        return raw

    # --- Worker Dispatch (`ov spec write` + `ov sling`) ---
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
        if profile == "danger":
            raise ProviderError("unsupported_profile", "overstory runs agents on the host in tmux; PROFILE=danger needs a sandbox")
        if not task_id:
            raise ProviderError("missing_task", "ov sling requires a task id")
        if agent not in OV_RUNTIMES:
            raise ProviderError("unsupported_agent", f"overstory has no runtime {agent!r} (want one of {', '.join(OV_RUNTIMES)})")
        cap = capability or ("scout" if profile == "ro" else "builder")
        if profile == "ro":
            if cap not in RO_CAPABILITIES:
                raise ProviderError(
                    "privilege_escalation",
                    f"overstory capability {cap!r} can write or spawn writers; PROFILE=ro allows only {', '.join(RO_CAPABILITIES)}",
                )
            if agent not in RO_ENFORCED_RUNTIMES:
                raise ProviderError(
                    "unsupported_profile",
                    f"overstory enforces read-only guards only for {', '.join(RO_ENFORCED_RUNTIMES)} runtimes, not {agent!r}",
                )
        if not _is_placeholder(worktree):
            raise ProviderError("unsupported_operation", "ov sling always creates its own worktree; pass --worktree new-child")
        task_prompt = self.resolve_task_prompt(task_id, prompt)

        spec = self._ov(["ov", "spec", "write", str(task_id), "--body", task_prompt, "--json"])
        spec_path = require_id(spec, "path", provider=self.name, what="spec path")
        argv = [
            "ov", "sling", str(task_id),
            "--capability", cap,
            "--runtime", str(agent),
            "--spec", spec_path,
            "--skip-task-check",
            "--json",
        ]
        if name:
            argv[3:3] = ["--name", str(name)]
        raw = self._ov(argv, timeout=300)
        agent_name = require_id(raw, "agentName", provider=self.name, what="agent name")
        wt_path = str(raw.get("worktree") or "")
        if not wt_path:
            raise ProviderError("upstream_no_id", "ov sling reported no worktree", {"response": raw})
        handle = f"ov:{raw.get('tmuxSession') or agent_name}"

        effective = {
            "agent": agent,
            "profile": profile,
            "capability": cap,
            "agentName": agent_name,
            "branch": raw.get("branch"),
            "worktree": wt_path,
            "tmuxSession": raw.get("tmuxSession"),
            "specPath": spec_path,
            "mechanism": "ov.sling",
            "guards": "overstory hooks-deployer" if agent == "claude" else f"overstory {agent} guards",
        }
        insert_dispatch(
            self.state,
            dispatch_id=agent_name,
            task_id=task_id,
            run=run,
            worktree=wt_path,
            agent=agent,
            profile=profile,
            handle=handle,
            backend=self.name,
            effective=effective,
            session_id=raw.get("tmuxSession") or None,
        )
        res = {
            "state": "ready",
            "dispatchId": agent_name,
            "agentTerminalHandle": handle,
            "worktree": wt_path,
            "agent": agent,
            "profile": profile,
            "capability": cap,
            "launch": {"effective": effective, "argv": argv},
            "upstream": {"spec": spec, "sling": raw},
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def worker_list(self, *, run: str | None = None, task: str | None = None, limit: int | None = None, **kwargs: Any) -> dict[str, Any]:
        """OUR dispatch rows; `ov status` only annotates `stage` (it also lists agents we never slung)."""
        raw = self._ov(["ov", "status", "--json"])
        agents = raw.get("agents")
        if not isinstance(agents, list):
            raise ProviderError("overstory_bad_json", "ov status returned no agents array", {"response": raw})
        stages = {
            str(a["agentName"]): str(a.get("state") or "unknown")
            for a in agents
            if isinstance(a, dict) and a.get("agentName")
        }
        return local_worker_list(self.state, self.name, run=run, task=task, limit=limit, stages=stages, upstream=raw)

    def _inspect(self, agent_name: str) -> dict[str, Any]:
        return self._ov(["ov", "inspect", agent_name, "--json"])

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        row = load_dispatch(self.state, dispatch_id, self.name)
        raw = self._inspect(dispatch_id)
        session = raw.get("session") if isinstance(raw.get("session"), dict) else {}
        return show_from_row(row, stage=str(session.get("state") or "unknown"), raw=raw, worktree=session.get("worktreePath"))

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        row = load_dispatch(self.state, dispatch_id, self.name)
        raw = self._inspect(dispatch_id)
        tmux_out = raw.get("tmuxOutput")
        lines = tmux_out.splitlines()[-int(limit):] if isinstance(tmux_out, str) else []
        out = normalize_read(
            "terminal",
            lines=lines,
            handle=row["terminal_handle"],
            fallback_reason="overstory_has_no_transcript_command" if source == "transcript" else None,
        )
        out["recentToolCalls"] = raw.get("recentToolCalls", [])
        return out

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        fence_state(verb)
        load_dispatch(self.state, dispatch_id, self.name)
        out: dict[str, Any] = {"dispatchId": dispatch_id, "verb": verb, "reason": reason}
        if verb == "retain":
            out["upstreamCalls"] = []
        else:
            try:
                out["upstream"] = self._ov(["ov", "stop", dispatch_id, "--json"])
            except ProviderError as exc:
                if "already completed" not in exc.message:
                    raise
                out["upstream"] = {"alreadyCompleted": True}
        new_state, term_state = record_fence(self.state, dispatch_id, verb)
        out.update({"state": new_state, "terminalState": term_state})
        return out

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
        ov_type = "status" if msg_type == "info" else msg_type
        if ov_type not in OV_MAIL_TYPES:
            raise ProviderError("invalid_type", f"overstory mail has no type {msg_type!r} (want {', '.join(OV_MAIL_TYPES)})")
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
            "ov", "mail", "send",
            "--to", str(to or "orchestrator"),
            "--subject", str(subject),
            "--body", str(body),
            "--type", ov_type,
            "--json",
        ]
        if sender:
            argv += ["--from", str(sender)]
        local["upstream"] = self._ov(argv)
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
        if mode == "unread":
            upstream = self._ov(["ov", "mail", "check", "--agent", str(agent_name), "--json"])
        else:
            # `ov mail check` marks everything it returns as read; peek/all must not consume mail.
            argv = ["ov", "mail", "list", "--to", str(agent_name), "--json"]
            if mode == "peek":
                argv.insert(-1, "--unread")
            upstream = self._ov(argv)
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
        local["upstreamMessages"] = upstream.get("messages", [])
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
        try:
            return self.state.reply_message(msg_id=msg_id, body=body, run=run, sender=sender, retry_request=retry_request)
        except ProviderError as exc:
            if exc.code != "message_not_found":
                raise
        # Not a local id: an Overstory mail id from `upstreamMessages`.
        argv = ["ov", "mail", "reply", str(msg_id), "--body", str(body), "--json"]
        if sender:
            argv[-1:-1] = ["--from", str(sender)]
        return {"replied": True, "id": msg_id, "scope": "upstream", "upstream": self._ov(argv)}

    # --- Worktree operations ---
    def worktree_list(self, *, repo: str | None = None, limit: int | None = None, **kwargs: Any) -> dict[str, Any]:
        raw = self._ov(["ov", "worktree", "list", "--json"])
        items = raw.get("worktrees", [])
        if limit is not None:
            items = items[:limit]
        return {"worktrees": items, "upstream": raw}

    def worktree_rm(self, *, selector: str = "", force: bool = False, **kwargs: Any) -> dict[str, Any]:
        if not selector:
            # `ov worktree clean` has no selector: it would remove EVERY finished worktree.
            raise ProviderError("invalid_selector", "overstory worktree rm requires an explicit agent name, branch or path")
        items = self.worktree_list()["worktrees"]
        sel_real = os.path.realpath(selector) if os.path.isabs(selector) else None
        match = next(
            (
                w
                for w in items
                if isinstance(w, dict)
                and (
                    selector in (w.get("agentName"), w.get("branch"), w.get("path"))
                    or (sel_real and w.get("path") and os.path.realpath(str(w["path"])) == sel_real)
                )
            ),
            None,
        )
        if not match or not match.get("agentName"):
            raise ProviderError("worktree_not_found", f"overstory: no agent worktree matches {selector!r}")
        agent_name, wt_path = str(match["agentName"]), str(match.get("path") or "")
        preserved = preserve_worker_head(self._run, wt_path, agent_name)
        dirty = foreign_dirty_paths(self._run, wt_path, OV_ARTIFACTS)
        if dirty and not force:
            raise ProviderError(
                "uncommitted_work",
                f"overstory worktree {wt_path!r} has uncommitted changes removal would lose: {', '.join(dirty[:10])}",
                {"preserved": preserved, "dirty": dirty},
            )
        # HEAD is pinned and no foreign dirt remains (or the caller forced it), so `--force` only
        # discards Overstory's own overlay/guard files that would otherwise block the removal.
        raw = self._ov(["ov", "stop", agent_name, "--clean-worktree", "--force", "--json"])
        return {"removed": bool(raw.get("worktreeRemoved", True)), "selector": selector, "preserved": preserved, "upstream": raw}

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


def _is_placeholder(worktree: str | None) -> bool:
    return not worktree or worktree.startswith(("new-", "current", "active"))
