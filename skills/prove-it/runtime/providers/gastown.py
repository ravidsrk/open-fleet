#!/usr/bin/env python3
"""gastown.py — Gastown (`gastownhall/gastown`, `gt` + `bd` Beads) RuntimeProvider (#583).

Source-verified against gastownhall/gastown `internal/cmd/{sling,polecat,session,peek,mail,
config,molecule_await_signal}.go` and steveyegge/beads `cmd/bd/{create,dep,show,update,list}.go`:
  - `task_create` -> local DAG row + `bd create --title=<t> --description=<spec> --json`; the bead
    id (`id`) is recorded and every dependency is wired with `bd dep add <bead> <dep-bead>`.
  - `task_update` -> `bd update <bead> --status <open|in_progress|blocked|closed> --json`.
  - `worker_start` -> slings the task's BEAD (whose description is the task spec — Gastown polecats
    read it through `gt prime`/`gt hook`) with
    `gt sling <bead> <rig> --agent <alias> --no-merge` (`--no-merge` keeps the Refinery from
    merging before `verify.py`). `gt sling` prints text only (no `--json`), so the polecat is
    parsed from its `Slinging <bead> to <rig>/polecats/<name>` line and the receipt is synthesized
    from `gt polecat status <rig>/<name> --json` (`clone_path`, `session_id`, `state`).
    PROFILE=ro registers a CLI-enforced alias (`gt config agent set <agent>-ro "<ro cmd>"`) and
    adds `--review-only`; the alias is TOWN-wide and the polecat's clone does not exist until
    after the sling, so only a PATH-FREE ro line may become one (claude, codex, gemini) — a line
    that names a directory (`--cwd`, `--data-dir`, `-C`, `--in`, `--dir`, or any path) would
    point every polecat at the wrong tree. PROFILE=danger is refused (polecats run on the host).
  - Polecat names are REUSED: every read/show/fence first re-reads `gt polecat status --json`
    and requires its `issue` to still be the dispatch's bead, else `dispatch_superseded` (the
    name now belongs to another assignment and must not be peeked, stopped, or nuked).
  - `worker_read` -> `gt peek <rig>/<name> -n <limit>` (terminal capture); `worker_show` ->
    `gt polecat status --json`; `worker_list` -> OUR dispatch rows, `stage` annotated from
    `gt polecat list --json` only where the polecat still holds the dispatch's bead.
  - `worker_fence` -> `retain`: no upstream call; `stop`: `gt session stop <rig>/<name>` (keeps the
    worktree); `release`/`abandon`: pin the polecat's real HEAD under
    `refs/open-fleet/preserved/<dispatch>` in its own worktree, then `gt polecat nuke`.
  - Mail bridges `gt mail send/inbox/reply`; `check --wait` blocks on `gt mol step await-signal`.
"""
from __future__ import annotations

import json
import re
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
    local_worker_list,
    preserve_worker_head,
    record_fence,
    run_cli_text,
    show_from_row,
)

# Local DAG status -> Beads built-in status (beads internal/types: open|in_progress|blocked|closed|...).
BEAD_STATUS = {
    "pending": "open",
    "ready": "open",
    "dispatched": "in_progress",
    "completed": "closed",
    "failed": "blocked",
    "blocked": "blocked",
}
# `gt mail send --type` accepts only these (internal/cmd/mail.go).
GT_MAIL_TYPES = ("task", "scavenge", "notification", "reply")

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_SLING_RE = re.compile(r"Slinging\s+\S+\s+to\s+([^\s/]+)/polecats/([A-Za-z0-9_-]+)")
_POLECAT_RE = re.compile(r"(?:Created polecat|Reusing idle polecat):\s+([A-Za-z0-9_-]+)")
# Flags that bind a harness to a directory: an alias carrying one points EVERY polecat there.
_PATH_FLAGS = frozenset({"--cwd", "--data-dir", "-C", "--in", "--dir", "--cd", "--workdir", "--worktree", "--add-dir"})
# Stand-in worktree for building the alias line: if it surfaces in the line, the line embeds a path.
_ALIAS_PROBE_WORKTREE = "/open-fleet-gastown-alias-probe"


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
        install_hooks: Callable[..., Any] | None = None,
        **kwargs: Any,
    ) -> None:
        self.env = dict(env) if env is not None else None
        self.state = state or LocalStateStore(db_path=db_path, env=self.env)
        self._runner = runner or self._default_runner
        self._install_hooks = install_hooks
        self.default_rig = rig or env_get("OPEN_FLEET_GASTOWN_RIG", "ORCA_GASTOWN_RIG", self.env, "")
        self.call_log: list[Any] = []
        with self.state._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS gastown_beads (task_id TEXT PRIMARY KEY, bead_id TEXT NOT NULL)"
            )

    def _default_runner(self, argv: list[str], **kwargs: Any) -> str:
        return run_cli_text(argv, self.name, timeout=int(kwargs.get("timeout", 120)))

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

    # --- Bead bookkeeping ---
    def bead_for(self, task_id: str) -> str | None:
        with self.state._connect() as conn:
            row = conn.execute("SELECT bead_id FROM gastown_beads WHERE task_id = ?", (task_id,)).fetchone()
        return str(row["bead_id"]) if row else None

    def _record_bead(self, task_id: str, bead_id: str) -> None:
        with self.state._connect() as conn:
            conn.execute("INSERT OR REPLACE INTO gastown_beads(task_id, bead_id) VALUES (?, ?)", (task_id, bead_id))

    def _bd_create(self, title: str, description: str) -> tuple[str, Any]:
        raw = self._run_json(["bd", "create", f"--title={title}", f"--description={description}", "--json"])
        bead = raw[0] if isinstance(raw, list) and raw else raw
        return require_id(bead, "id", provider=self.name, what="bead id"), raw

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
        dep_beads: list[str] = []
        for dep in deps or []:
            bead = self.bead_for(str(dep))
            if not bead:
                raise ProviderError("task_not_found", f"dependency {dep!r} has no Gastown bead (create it through this provider)")
            dep_beads.append(bead)
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
        task_id = local["task"]["id"]
        existing = self.bead_for(task_id)
        if existing:  # idempotent retry
            local["task"]["beadId"] = existing
            return local
        try:
            bead_id, raw = self._bd_create(title or display_name or task_id, spec)
            for dep_bead in dep_beads:
                # `bd dep add A B`: A depends on (is blocked by) B.
                self._run(["bd", "dep", "add", bead_id, dep_bead])
        except ProviderError as exc:
            self.state.task_update(task_id=task_id, status="failed", result=f"bd create failed: {exc.message}")
            raise
        self._record_bead(task_id, bead_id)
        local["task"]["beadId"] = bead_id
        local["task"]["bead"] = raw
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
        bead_id = self.bead_for(task_id)
        if bead_id and status in BEAD_STATUS:
            local["task"]["beadId"] = bead_id
            local["task"]["bead"] = self._run_json(["bd", "update", bead_id, "--status", BEAD_STATUS[status], "--json"])
        return local

    def task_show(self, task_id: str) -> dict[str, Any]:
        bead_id = self.bead_for(task_id)
        if not bead_id:
            raise ProviderError("task_not_found", f"task {task_id!r} has no Gastown bead")
        raw = self._run_json(["bd", "show", bead_id, "--json"])
        bead = raw[0] if isinstance(raw, list) and raw else raw
        if not isinstance(bead, dict):
            raise ProviderError("gastown_bad_json", f"bd show {bead_id} returned no bead", {"response": raw})
        return {"taskId": task_id, "beadId": bead_id, "bead": bead}

    def task_list(
        self,
        *,
        run: str | None = None,
        sender: str | None = None,
        brief: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        local = self.state.task_list(run=run, sender=sender, brief=brief)
        beads = self._run_json(["bd", "list", "--json"])
        if isinstance(beads, dict):
            beads = beads.get("issues", [])
        local["beads"] = beads if isinstance(beads, list) else []
        return local

    # --- Worker Dispatch (`gt sling` + read-only alias registration) ---
    def _ro_alias_command(self, agent: str) -> str:
        """The read-only launch line for `gt config agent set` (split by strings.Fields: no quoting).

        The alias is town-wide and registered before the polecat (and its clone) exists, so it
        must be PATH-FREE: any directory it named would be the coordinator's, not the polecat's.
        """
        harness = build_harness_command(agent, "ro", _ALIAS_PROBE_WORKTREE)
        cmd = str(harness["command"])
        tokens = cmd.split()
        path_bound = [
            t for t in tokens
            if t.split("=", 1)[0] in _PATH_FLAGS or "/" in t or _ALIAS_PROBE_WORKTREE in t or t in (".", "..")
        ]
        if path_bound:
            raise ProviderError(
                "unsupported_profile",
                f"gastown: agent {agent!r}'s read-only line binds a directory ({' '.join(path_bound[:3])}); "
                "a town-wide gt agent alias cannot name each polecat's own clone, so it would run in the wrong tree",
            )
        # A token whose quotes do not balance had whitespace inside them: gt would split it.
        shell_meta = any(t in ("&&", "||", ";", "|") for t in tokens) or any(
            t.count('"') % 2 or t.count("'") % 2 for t in tokens
        )
        if not tokens or "=" in tokens[0] or shell_meta or harness["env"].keys() - {
            "OPEN_FLEET_UNIT_WORKTREE",
            "ORCA_UNIT_WORKTREE",
            "OPEN_FLEET_SANDBOX_PROFILE",
            "ORCA_SANDBOX_PROFILE",
        }:
            raise ProviderError(
                "unsupported_profile",
                f"gastown: agent {agent!r} has no read-only launch line expressible as a gt agent alias "
                "(gt splits the command on whitespace; env prefixes and quoting are lost)",
            )
        return cmd

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
        if profile == "danger":
            raise ProviderError("unsupported_profile", "gastown polecats run on the host; PROFILE=danger needs an isolated sandbox")
        target_rig = rig or self.default_rig
        if not target_rig:
            raise ProviderError("missing_rig", "gastown worker-start needs a rig (--rig or OPEN_FLEET_GASTOWN_RIG)")
        task_prompt = self.resolve_task_prompt(task_id, prompt)

        # The bead description IS the assignment a polecat reads; keep it equal to the prompt.
        bead_id = self.bead_for(task_id) if task_id else None
        if not bead_id:
            bead_id, _ = self._bd_create(name or task_id or "open-fleet task", task_prompt)
            if task_id:
                self._record_bead(task_id, bead_id)
        elif task_prompt != self.task_spec(task_id):
            self._run_json(["bd", "update", bead_id, f"--description={task_prompt}", "--json"])

        if profile == "ro":
            agent_alias = f"{agent}-ro"
            ro_cmd = self._ro_alias_command(agent)
            self._run(["gt", "config", "agent", "set", agent_alias, ro_cmd])
        else:
            agent_alias = agent

        sling_argv = ["gt", "sling", bead_id, str(target_rig), "--agent", agent_alias, "--no-merge"]
        if profile == "ro":
            sling_argv.append("--review-only")
        out = _ANSI_RE.sub("", self._run(sling_argv, timeout=300))
        m = _SLING_RE.search(out)
        if m:
            polecat_rig, polecat = m.group(1), m.group(2)
        else:
            m2 = _POLECAT_RE.search(out)
            if not m2:
                raise ProviderError(
                    "upstream_no_id",
                    "gastown: `gt sling` output names no polecat; cannot track the dispatch",
                    {"output": out[-500:]},
                )
            polecat_rig, polecat = str(target_rig), m2.group(1)
        address = f"{polecat_rig}/{polecat}"
        status = self._polecat_status(address)
        clone_path = str(status.get("clone_path") or "")

        hooks: dict[str, str] | None = None
        if clone_path and Path(clone_path).is_dir():
            hooks = self._hooks(clone_path, agent, profile)
        elif profile == "ro":
            # Fail closed: a ro polecat whose worktree cannot be resolved gets no hook config.
            stopped = True
            try:
                self._run(["gt", "session", "stop", address])
            except ProviderError:
                stopped = False
            raise ProviderError(
                "worktree_unresolved",
                f"gastown: polecat {address} reported no usable clone_path; ro session stopped={stopped}",
                {"status": status, "sessionStopped": stopped},
            )

        dispatch_id = f"{address}@{bead_id}"
        handle = f"polecat:{address}"
        effective = {
            "agent": agent,
            "agentAlias": agent_alias,
            "profile": profile,
            "rig": polecat_rig,
            "polecat": polecat,
            "address": address,
            "beadId": bead_id,
            "noMerge": True,
            "reviewOnly": profile == "ro",
            "mechanism": "gt.sling",
            "worktree": clone_path,
            "session": status.get("session_id"),
            "hooks": hooks,
        }
        insert_dispatch(
            self.state,
            dispatch_id=dispatch_id,
            task_id=task_id,
            run=run,
            worktree=clone_path,
            agent=agent,
            profile=profile,
            handle=handle,
            backend=self.name,
            effective=effective,
            session_id=status.get("session_id"),
        )
        res = {
            "state": "ready",
            "dispatchId": dispatch_id,
            "agentTerminalHandle": handle,
            "worktree": clone_path or None,
            "agent": agent,
            "profile": profile,
            "beadId": bead_id,
            "launch": {"effective": effective, "argv": sling_argv},
            "upstream": {"sling": out[-2000:], "status": status},
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def _polecat_status(self, address: str) -> dict[str, Any]:
        raw = self._run_json(["gt", "polecat", "status", address, "--json"])
        if not isinstance(raw, dict):
            raise ProviderError("gastown_bad_json", f"gt polecat status {address} is not an object", {"response": raw})
        return raw

    def _bound_status(self, row: dict[str, Any]) -> dict[str, Any]:
        """`gt polecat status` for a dispatch, refusing if the (reused) polecat moved to other work."""
        eff = row["effective"]
        status = self._polecat_status(eff["address"])
        issue = str(status.get("issue") or "")
        if issue != str(eff.get("beadId") or ""):
            raise ProviderError(
                "dispatch_superseded",
                f"gastown: polecat {eff['address']} now holds {issue or 'no issue'!r}, not this dispatch's bead "
                f"{eff.get('beadId')!r}; refusing to act on another assignment",
                {"dispatchId": row["dispatch_id"], "beadId": eff.get("beadId"), "issue": issue or None},
            )
        return status

    def worker_list(
        self, *, rig: str | None = None, run: str | None = None, task: str | None = None, limit: int | None = None, **kwargs: Any
    ) -> dict[str, Any]:
        target = rig or self.default_rig
        argv = ["gt", "polecat", "list", "--json"] + ([str(target)] if target else ["--all"])
        raw = self._run_json(argv)
        if not isinstance(raw, list):
            raise ProviderError("gastown_bad_json", "gt polecat list returned no polecat array", {"response": raw})
        live = {
            (f"{p.get('rig')}/{p.get('name')}", str(p.get("issue") or "")): str(p.get("state") or "unknown")
            for p in raw
            if isinstance(p, dict)
        }
        with self.state._connect() as conn:
            rows = conn.execute("SELECT dispatch_id, launch_effective FROM dispatches WHERE backend = ?", (self.name,)).fetchall()
        stages: dict[str, str] = {}
        for r in rows:
            try:
                eff = json.loads(r["launch_effective"] or "{}")
            except json.JSONDecodeError:
                eff = {}
            key = (str(eff.get("address")), str(eff.get("beadId") or ""))
            # A polecat name now holding another bead is NOT this dispatch's worker.
            stages[str(r["dispatch_id"])] = live.get(key, "superseded-or-gone")
        return local_worker_list(self.state, self.name, run=run, task=task, limit=limit, stages=stages, upstream=raw)

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        row = load_dispatch(self.state, dispatch_id, self.name)
        status = self._bound_status(row)
        return show_from_row(row, stage=str(status.get("state") or "unknown"), raw=status, worktree=status.get("clone_path"))

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        row = load_dispatch(self.state, dispatch_id, self.name)
        self._bound_status(row)
        out = self._run(["gt", "peek", row["effective"]["address"], "-n", str(int(limit))])
        return normalize_read(
            "terminal",
            lines=out.splitlines(),
            handle=row["terminal_handle"],
            fallback_reason="gastown_exposes_tmux_capture_only" if source == "transcript" else None,
        )

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        fence_state(verb)
        row = load_dispatch(self.state, dispatch_id, self.name)
        address = row["effective"]["address"]
        out: dict[str, Any] = {"dispatchId": dispatch_id, "verb": verb, "reason": reason}
        if verb == "retain":
            new_state, term_state = record_fence(self.state, dispatch_id, verb)
            out.update({"state": new_state, "terminalState": term_state, "upstreamCalls": []})
            return out
        status = self._bound_status(row)  # a reused polecat name is not this dispatch's worker
        if verb == "stop":
            out["upstream"] = self._run(["gt", "session", "stop", address])
        else:
            wt_path = str(status.get("clone_path") or row.get("worktree") or "")
            preserved = preserve_worker_head(self._run, wt_path, dispatch_id)
            dirty = foreign_dirty_paths(self._run, wt_path)
            if dirty and verb == "release":
                raise ProviderError(
                    "uncommitted_work",
                    f"polecat {address} has uncommitted changes a release would lose: {', '.join(dirty[:10])}",
                    {"preserved": preserved, "dirty": dirty},
                )
            # HEAD is pinned in the rig repo's common dir and no foreign dirt remains (or the
            # worker is abandoned), so nuke's unpushed/dirty refusal no longer protects anything.
            out["upstream"] = self._run(["gt", "polecat", "nuke", address, "--force"])
            out["preserved"] = preserved
        new_state, term_state = record_fence(self.state, dispatch_id, verb)
        out.update({"state": new_state, "terminalState": term_state})
        return out

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
        gt_type = msg_type if msg_type in GT_MAIL_TYPES else "notification"
        gt_subject = subject if msg_type in GT_MAIL_TYPES else f"[{msg_type}] {subject}"
        argv = ["gt", "mail", "send", str(recipient), "-s", gt_subject, "-m", str(body), "--type", gt_type]
        if sender:
            argv += ["--from", str(sender)]
        local["upstream"] = {"output": self._run(argv)}
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
        signal: Any = None
        if wait:
            secs = max(1, int((timeout_ms or 60000) / 1000))
            signal = self._run_json(["gt", "mol", "step", "await-signal", "--json", "--timeout", f"{secs}s"], timeout=secs + 30)
        inbox_argv = ["gt", "mail", "inbox", "--json"] + (["--unread"] if mode == "unread" else ["--all"])
        if terminal:
            inbox_argv += ["--address", str(terminal)]
        upstream = parse_json_strict(self._run(inbox_argv), self.name)
        local = self.state.check_messages(
            terminal=terminal,
            run=run,
            ack=ack,
            mode=mode,
            types=types,
            fmt=fmt,
            wait=False,
            timeout_ms=timeout_ms,
            retry_request=retry_request,
        )
        local["upstreamInbox"] = upstream if isinstance(upstream, list) else []
        if signal is not None:
            local["upstreamSignal"] = signal
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
        # Not a local message id: it is a Gastown mail id from `upstreamInbox`.
        out = self._run(["gt", "mail", "reply", str(msg_id), "-m", str(body)])
        return {"replied": True, "id": msg_id, "scope": "upstream", "upstream": {"output": out}}

    def ask_human(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.ask_human(**kwargs)

    def request_show(self, request_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.state.request_show(request_id)
