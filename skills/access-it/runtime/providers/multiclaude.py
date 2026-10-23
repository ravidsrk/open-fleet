#!/usr/bin/env python3
"""multiclaude.py — Multiclaude (`dlorenc/multiclaude`, `~/.multiclaude/daemon.sock`) RuntimeProvider (#589).

Source-verified against `internal/socket`, `internal/daemon/daemon.go`, `internal/hooks`:

  - Wire: one `{"command": ..., "args": {...}}` request and one `{"success", "data", "error"}`
    response per unix-socket connection (`<home>/daemon.sock`; `OPEN_FLEET_MULTICLAUDE_HOME`
    points at the multiclaude root, default `~/.multiclaude`).
  - `worker_start` -> `spawn_agent {repo, name, class:"ephemeral", prompt, task}`. The daemon
    creates `<home>/wts/<repo>/<name>` on `work/<name>`, writes `prompt` to
    `--append-system-prompt-file`, and launches `claude --dangerously-skip-permissions`
    (hardcoded, `daemon.go startAgentWithConfig`). `spawn_agent` never sends the task as a
    message, so the spec is the system prompt AND a kick-off message is queued through the
    daemon's own mailbox (`<home>/messages/<repo>/<name>/<id>.json` + `route_messages`).
  - SAFETY #1: the daemon resolves `claude` with its OWN `PATH` (`exec.LookPath`) and accepts no
    env or command from the caller, so a PATH shim cannot be injected per spawn. The one
    verified injection point is `hooks.CopyConfig`, which copies
    `<home>/repos/<repo>/.multiclaude/hooks.json` to `<worktree>/.claude/settings.json` BEFORE
    claude starts. The adapter writes a per-profile settings document there (ro: deny rules +
    a PreToolUse hook that blocks every write tool and Bash; rw: the open-fleet deny-hook bound
    to the worker worktree), spawns, restores the original file, and verifies the worker's
    `.claude/settings.json` — a missing/different file tears the worker down (fail closed).
  - SAFETY #2: `complete_agent` marks the agent for cleanup and the health check runs
    `git worktree remove --force`. `release` is therefore gated on a DURABLE verification
    produced by `worker_verify(dispatch_id, sha, manifest)`, which re-derives the facts from
    a REQUIRED evidence manifest (worker worktree HEAD == sha, sha is a commit, manifest
    head_sha == sha, manifest base_sha passes `git merge-base --is-ancestor base_sha sha`) and
    is re-checked against the current HEAD at release. A caller `verified=True` flag, or a bare
    `--sha <HEAD>`, is never proof. Release also refuses while the worktree holds uncommitted
    work (`foreign_dirty_paths`): the forced upstream remove would discard it.
  - stop/abandon: the worker's HEAD is pinned (best effort, `preserve_worker_head`), the tmux
    window is killed FIRST and the kill must succeed and be confirmed (`list-windows` no longer
    names it) — otherwise `stop_failed`/`stop_unconfirmed` is raised and nothing is reported
    stopped, because `claude --dangerously-skip-permissions` would keep running orphaned.
    Only then is the agent dropped from daemon state (`remove_agent`), which keeps the worktree.
    retain touches nothing upstream.
"""
from __future__ import annotations

import fcntl
import json
import re
import shlex
import socket
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ._external import (
    ExternalDispatchMixin,
    env_lookup,
    foreign_dirty_paths,
    preserve_worker_head,
    real_worktree,
    run_cli,
)
from .base import (
    ProviderError,
    RuntimeProvider,
    check_monotonic_profile,
    fence_state,
    normalize_read,
    normalize_show,
    require_id,
)
from .local_state import LocalStateStore

RO_DENIED_TOOLS = ["Edit", "Write", "MultiEdit", "NotebookEdit", "Bash"]
RO_HOOK_COMMAND = "echo 'open-fleet PROFILE=ro: write tools and Bash are denied' >&2; exit 2"
DENY_HOOK = Path(__file__).resolve().parent.parent / "scripts" / "deny-hook.sh"
_HEX_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
# multiclaude only ever launches claude (daemon.go startAgentWithConfig).
SUPPORTED_HARNESSES = ("claude",)
# hooks.CopyConfig writes this into every worker worktree; it is ours, not the worker's work.
MC_SETTINGS_ARTIFACT = ".claude/settings.json"
# tmux answers these once the window (and with it its session/server) is gone.
_TMUX_GONE = ("can't find window", "can't find session", "no server running", "session not found", "no such")


def worker_settings(profile: str, worktree: str) -> dict[str, Any]:
    """The `.claude/settings.json` document a multiclaude worker must start with."""
    if profile == "ro":
        return {
            "permissions": {"deny": list(RO_DENIED_TOOLS)},
            "hooks": {"PreToolUse": [{"matcher": "|".join(RO_DENIED_TOOLS),
                                      "hooks": [{"type": "command", "command": RO_HOOK_COMMAND}]}]},
        }
    q = shlex.quote
    cmd = (f"OPEN_FLEET_UNIT_WORKTREE={q(worktree)} ORCA_UNIT_WORKTREE={q(worktree)} "
           f"OPEN_FLEET_SANDBOX_PROFILE={q(profile)} ORCA_SANDBOX_PROFILE={q(profile)} sh {q(str(DENY_HOOK))}")
    return {"hooks": {"PreToolUse": [{"matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit",
                                      "hooks": [{"type": "command", "command": cmd}]}]}}


def merge_settings(ours: dict[str, Any], original: dict[str, Any] | None) -> dict[str, Any]:
    """Ours first; keep the repo's own hooks and deny rules (never drop a stricter rule)."""
    if not isinstance(original, dict):
        return ours
    merged = json.loads(json.dumps(original))
    hooks = merged.setdefault("hooks", {})
    for event, entries in ours.get("hooks", {}).items():
        hooks[event] = list(entries) + [e for e in (hooks.get(event) or []) if e not in entries]
    if "permissions" in ours:
        perms = merged.setdefault("permissions", {})
        deny = list(ours["permissions"].get("deny", []))
        perms["deny"] = deny + [d for d in (perms.get("deny") or []) if d not in deny]
        perms.pop("defaultMode", None)
    return merged


def safe_agent_name(raw: str) -> str:
    name = re.sub(r"[^a-z0-9-]+", "-", raw.lower()).strip("-")[:48]
    if not name:
        raise ProviderError("invalid_name", f"multiclaude: {raw!r} yields no usable agent name")
    return name


class MulticlaudeProvider(ExternalDispatchMixin, RuntimeProvider):
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
        home: str | Path | None = None,
        repo: str | None = None,
        cli_runner: Callable[..., Any] | None = None,
        **kwargs: Any,
    ) -> None:
        self.env = dict(env) if env is not None else None
        self.state = state or LocalStateStore(db_path=db_path, env=self.env)
        self.home = Path(home or env_lookup(self.env, "OPEN_FLEET_MULTICLAUDE_HOME", default=str(Path.home() / ".multiclaude"))).expanduser()
        self.socket_path = str(
            socket_path or env_lookup(self.env, "OPEN_FLEET_MULTICLAUDE_SOCK", "ORCA_MULTICLAUDE_SOCK", default=str(self.home / "daemon.sock"))
        )
        self.repo = repo or env_lookup(self.env, "OPEN_FLEET_MULTICLAUDE_REPO", "ORCA_MULTICLAUDE_REPO")
        self._runner = runner or self._default_runner
        self._cli = cli_runner or (lambda argv: run_cli(argv, provider="multiclaude", timeout=60))
        self.call_log: list[dict[str, Any]] = []
        with self.state._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS multiclaude_verifications (
                    dispatch_id TEXT PRIMARY KEY,
                    sha TEXT NOT NULL,
                    worktree TEXT NOT NULL,
                    manifest TEXT,
                    verified_at REAL NOT NULL
                )
                """
            )

    # --- transport -------------------------------------------------------------------
    def _default_runner(self, msg: dict[str, Any], **kwargs: Any) -> Any:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(kwargs.get("timeout", 60))
                sock.connect(self.socket_path)
                sock.sendall((json.dumps(msg) + "\n").encode("utf-8"))
                chunks: list[bytes] = []
                while True:
                    data = sock.recv(65536)
                    if not data:
                        break
                    chunks.append(data)
        except OSError as exc:
            raise ProviderError("multiclaude_unreachable", f"multiclaude: daemon socket {self.socket_path}: {exc}") from exc
        raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
        if not raw:
            raise ProviderError("multiclaude_empty_output", "multiclaude: daemon closed without a response")
        try:
            return json.loads(raw.splitlines()[0])
        except json.JSONDecodeError as exc:
            raise ProviderError("multiclaude_bad_json", f"multiclaude: daemon response is not JSON: {raw[:200]!r}") from exc

    def _command(self, command: str, args: dict[str, Any] | None = None) -> Any:
        msg: dict[str, Any] = {"command": command}
        if args:
            msg["args"] = args
        self.call_log.append(msg)
        res = self._runner(msg)
        if not isinstance(res, dict) or "success" not in res:
            raise ProviderError("multiclaude_bad_response", f"multiclaude: {command} returned no socket Response", {"response": res})
        if not res.get("success"):
            raise ProviderError("multiclaude_daemon_error", str(res.get("error") or f"{command} failed"), {"command": command})
        return res.get("data")

    def _repo(self, repo: str | None = None) -> str:
        r = repo or self.repo
        if not r:
            raise ProviderError("missing_repo", "multiclaude: set OPEN_FLEET_MULTICLAUDE_REPO to the tracked repository name")
        return r

    def _tmux_target(self, repo: str, window: str) -> str:
        session = env_lookup(self.env, "OPEN_FLEET_MULTICLAUDE_TMUX_SESSION") or "mc-" + re.sub(r"[.: /]", "-", repo)
        return f"{session}:{window}"

    def _git(self, wt: str, *args: str) -> str:
        res = self._cli(["git", "-C", wt, *args])
        return str((res or {}).get("raw") if isinstance(res, dict) else res or "").strip()

    def _cli_text(self, argv: list[str]) -> str:
        """Unstripped stdout (porcelain output is column-sensitive)."""
        res = self._cli(argv)
        if isinstance(res, dict):
            return str(res.get("stdout") if res.get("stdout") is not None else res.get("raw") or "")
        return str(res or "")

    # --- worker dispatch ---------------------------------------------------------------
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
        **kwargs: Any,
    ) -> dict[str, Any]:
        cached = self.state.get_or_record_request(retry_request, "worker-start")
        if cached:
            return cached
        check_monotonic_profile(parent_profile, profile)
        if agent != "claude":
            raise ProviderError("unsupported_agent", f"multiclaude only launches claude (got {agent!r})")
        if profile == "danger":
            raise ProviderError("unsupported_profile", "multiclaude: PROFILE=danger needs a sandbox; multiclaude runs claude on the host")
        if worktree not in ("", "new-child", "new-top-level"):
            raise ProviderError("unsupported_worktree", "multiclaude creates <home>/wts/<repo>/<name> itself; --worktree cannot be honoured")
        repo_name = self._repo(repo)
        agent_name = safe_agent_name(name or f"of-{task_id or uuid.uuid4().hex[:8]}")
        task_prompt = self.resolve_task_prompt(task_id, prompt)
        repo_dir = self.home / "repos" / repo_name
        if not repo_dir.is_dir():
            raise ProviderError("multiclaude_repo_unknown", f"multiclaude: {repo_dir} does not exist (repo not tracked?)")
        expected_wt = str((self.home / "wts" / repo_name / agent_name).resolve())
        hooks_dir = repo_dir / ".multiclaude"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        hooks_file = hooks_dir / "hooks.json"
        system_prompt = (
            "You are an open-fleet worker dispatched by the coordinator. Your assignment:\n\n" + task_prompt
        )

        with open(hooks_dir / ".open-fleet-hooks.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            original_bytes = hooks_file.read_bytes() if hooks_file.is_file() else None
            try:
                original = json.loads(original_bytes) if original_bytes else None
            except json.JSONDecodeError:
                original = None
            settings = merge_settings(worker_settings(profile, expected_wt), original)
            hooks_file.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
            try:
                data = self._command(
                    "spawn_agent",
                    {"repo": repo_name, "name": agent_name, "class": "ephemeral", "prompt": system_prompt, "task": task_prompt[:500]},
                )
            finally:
                if original_bytes is None:
                    hooks_file.unlink(missing_ok=True)
                else:
                    hooks_file.write_bytes(original_bytes)

        wt = real_worktree(require_id(data, "worktree_path", provider="multiclaude", what="worktree_path"))
        try:
            installed = json.loads(Path(wt, ".claude", "settings.json").read_text(encoding="utf-8")) if wt else None
        except (OSError, json.JSONDecodeError):
            installed = None
        if not wt or installed != settings:
            try:
                teardown: dict[str, Any] = self._stop_upstream(repo_name, agent_name, wt)
            except ProviderError as exc:
                teardown = {"error": exc.to_envelope()["error"]}
            raise ProviderError(
                "hooks_not_installed",
                "multiclaude: the worker did not start with the open-fleet .claude/settings.json; it was stopped",
                {"agent": agent_name, "worktree": wt, "teardown": teardown},
            )
        kick = self._deliver(repo_name, agent_name, "Begin the open-fleet assignment in your system prompt now.")

        handle = f"multiclaude:{agent_name}"
        effective = {
            "agent": agent,
            "profile": profile,
            "repo": repo_name,
            "agentName": agent_name,
            "class": "ephemeral",
            "settings": settings,
            "upstreamLaunch": "claude --dangerously-skip-permissions (hardcoded); guarded by .claude/settings.json",
            "kickoffMessage": kick,
        }
        self._record_dispatch(
            dispatch_id=agent_name, task_id=task_id, run=run, worktree=wt, agent=agent,
            profile=profile, handle=handle, effective=effective, session_id=agent_name,
        )
        res = {
            "state": "ready",
            "dispatchId": agent_name,
            "agentTerminalHandle": handle,
            "worktree": wt,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective},
            "upstream": data,
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def _deliver(self, repo: str, to: str, body: str, sender: str = "open-fleet") -> str:
        """Queue a message the multiclaude way (file + `route_messages`)."""
        msg_id = f"msg-{str(uuid.uuid4())[:13]}"
        msg_dir = self.home / "messages" / repo / to
        msg_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        (msg_dir / f"{msg_id}.json").write_text(
            json.dumps({"id": msg_id, "from": sender, "to": to, "timestamp": stamp, "body": body, "status": "pending"}, indent=2),
            encoding="utf-8",
        )
        self._command("route_messages")
        return msg_id

    def _window_gone(self, repo: str, agent_name: str) -> bool:
        session = self._tmux_target(repo, agent_name).rsplit(":", 1)[0]
        try:
            names = self._cli_text(["tmux", "list-windows", "-t", session, "-F", "#{window_name}"])
        except ProviderError as exc:
            return any(m in str(exc.message).lower() for m in _TMUX_GONE)
        return agent_name not in [ln.strip() for ln in names.splitlines()]

    def _stop_upstream(self, repo: str, agent_name: str, worktree: str | None = None) -> dict[str, Any]:
        """Kill the agent's tmux window FIRST (must succeed + be confirmed), then `remove_agent`.

        A failed or unconfirmed kill raises and leaves the daemon state alone: reporting
        "stopped" while `claude --dangerously-skip-permissions` keeps running is the bug.
        """
        out: dict[str, Any] = {}
        wt = real_worktree(worktree)
        if wt:
            try:
                out["preserved"] = preserve_worker_head(lambda argv: self._cli_text(argv), wt, agent_name)
            except ProviderError as exc:
                out["preserved"] = {"error": exc.code, "message": exc.message}
        target = self._tmux_target(repo, agent_name)
        try:
            self._cli(["tmux", "kill-window", "-t", target])
        except ProviderError as exc:
            raise ProviderError(
                "stop_failed",
                f"multiclaude: `tmux kill-window -t {target}` failed ({exc.message}); the agent may still be "
                "running, so it was NOT removed from daemon state or reported stopped",
                {"agent": agent_name, "target": target, "killWindow": exc.code, **out},
            ) from exc
        if not self._window_gone(repo, agent_name):
            raise ProviderError(
                "stop_unconfirmed",
                f"multiclaude: tmux window {target} still exists after kill-window; not reporting it stopped",
                {"agent": agent_name, "target": target, **out},
            )
        out["killWindow"] = True
        out["windowGone"] = True
        out["remove_agent"] = self._command("remove_agent", {"repo": repo, "agent": agent_name})
        return out

    # --- durable verification (release guard) ------------------------------------------
    def _verification(self, dispatch_id: str) -> Any:
        with self.state._connect() as conn:
            return conn.execute("SELECT * FROM multiclaude_verifications WHERE dispatch_id = ?", (dispatch_id,)).fetchone()

    def _resolve_commit(self, wt: str, rev: str, code: str, what: str) -> str:
        try:
            return self._git(wt, "rev-parse", "--verify", f"{rev}^{{commit}}")
        except ProviderError as exc:
            raise ProviderError(code, f"multiclaude: {what} {rev!r} is not a commit in {wt}") from exc

    def worker_verify(self, *, dispatch_id: str = "", sha: str = "", manifest: str | None = None, **kwargs: Any) -> dict[str, Any]:
        """Re-derive the evidence manifest's facts against the worker's real HEAD, then record it durably.

        The manifest is REQUIRED: `--sha <HEAD>` alone proves only that the worker has a HEAD.
        """
        row = self._dispatch_row(dispatch_id)
        wt = real_worktree(row["worktree"])
        if not wt:
            raise ProviderError("worktree_unknown", f"multiclaude: worktree of {dispatch_id!r} is gone or unknown")
        if not _HEX_RE.match(sha or ""):
            raise ProviderError("invalid_sha", f"multiclaude: --sha must be a commit id (got {sha!r})")
        if not manifest:
            raise ProviderError(
                "manifest_required",
                "multiclaude: worker-verify needs --manifest <evidence manifest> (head_sha + base_sha); a bare --sha is not evidence",
                {"dispatchId": dispatch_id},
            )
        mp = Path(manifest).expanduser()
        try:
            doc = json.loads(mp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProviderError("manifest_unreadable", f"multiclaude: cannot read manifest {mp}: {exc}") from exc
        if not isinstance(doc, dict):
            raise ProviderError("manifest_unreadable", f"multiclaude: manifest {mp} is not a JSON object")
        full = self._resolve_commit(wt, sha, "invalid_sha", "--sha")
        head = self._git(wt, "rev-parse", "--verify", "HEAD^{commit}")
        if full != head:
            raise ProviderError("head_mismatch", f"multiclaude: worker HEAD is {head}, not {full}", {"head": head, "sha": full})
        m_head = str(doc.get("head_sha") or "")
        if not _HEX_RE.match(m_head) or self._resolve_commit(wt, m_head, "manifest_mismatch", "manifest head_sha") != full:
            raise ProviderError("manifest_mismatch", f"multiclaude: manifest head_sha {m_head!r} != {full}")
        base = str(doc.get("base_sha") or "")
        if not _HEX_RE.match(base):
            raise ProviderError("manifest_incomplete", f"multiclaude: manifest base_sha {base!r} is missing or not a commit id")
        base_full = self._resolve_commit(wt, base, "not_on_base", "manifest base_sha")
        try:
            self._cli(["git", "-C", wt, "merge-base", "--is-ancestor", base_full, full])
        except ProviderError as exc:
            raise ProviderError("not_on_base", f"multiclaude: base_sha {base_full} is not an ancestor of {full}") from exc
        manifest_path = str(mp.resolve())
        now = time.time()
        with self.state._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO multiclaude_verifications(dispatch_id, sha, worktree, manifest, verified_at) VALUES (?, ?, ?, ?, ?)",
                (dispatch_id, full, wt, manifest_path, now),
            )
            conn.execute("UPDATE dispatches SET head_sha = ?, updated_at = ? WHERE dispatch_id = ?", (full, now, dispatch_id))
        return {"dispatchId": dispatch_id, "verified": True, "verifiedSha": full, "worktree": wt, "manifest": manifest_path}

    def mark_verified(self, dispatch_id: str) -> None:
        raise ProviderError(
            "unsupported_operation",
            "multiclaude: verification is re-derived by worker_verify(dispatch_id, sha, manifest), never asserted",
        )

    # --- observation & fencing --------------------------------------------------------
    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        return self._list_local(run=kwargs.get("run"), task=kwargs.get("task"), limit=kwargs.get("limit"))

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        row = self._dispatch_row(dispatch_id)
        repo = self._effective(row).get("repo") or self._repo()
        agents = self._command("list_agents", {"repo": repo, "rich": True})
        mine = next((a for a in agents or [] if isinstance(a, dict) and a.get("name") == row["session_id"]), None)
        out = normalize_show(
            row["dispatch_id"], row["state"], task_id=row["task_id"], terminal_state=row["terminal_state"],
            handle=row["terminal_handle"], worktree=row["worktree"],
            stage=str((mine or {}).get("status") or ("absent" if mine is None else row["state"])), raw=mine,
        )
        ver = self._verification(dispatch_id)
        out["verification"] = {"sha": ver["sha"], "verifiedAt": ver["verified_at"]} if ver else None
        return out

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        row = self._dispatch_row(dispatch_id)
        repo = self._effective(row).get("repo") or self._repo()
        res = self._cli(["tmux", "capture-pane", "-p", "-J", "-t", self._tmux_target(repo, row["session_id"]), "-S", f"-{int(limit)}"])
        text = str(res.get("stdout") if isinstance(res, dict) else res or "")
        lines = text.splitlines()
        return normalize_read(
            "terminal", lines=lines[-int(limit):] if limit else lines, handle=row["terminal_handle"],
            fallback_reason="multiclaude exposes the tmux pane only" if source == "transcript" else None,
        )

    def worker_fence(
        self,
        *,
        verb: str,
        dispatch_id: str = "",
        reason: str | None = None,
        verified: bool | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        fence_state(verb)
        row = self._dispatch_row(dispatch_id)
        repo = self._effective(row).get("repo") or self._repo()
        agent_name = str(row["session_id"])
        upstream: Any = None
        if verb == "release":
            ver = self._verification(dispatch_id)
            if not ver:
                raise ProviderError(
                    "unverified_release_blocked",
                    f"multiclaude: complete_agent deletes {agent_name!r}'s worktree; run "
                    f"`orchestration worker-verify --dispatch {dispatch_id} --sha <sha>` first "
                    "(a --verified flag is not evidence)",
                    {"dispatchId": dispatch_id, "verifiedFlagIgnored": bool(verified)},
                )
            wt = real_worktree(ver["worktree"])
            head = self._git(wt, "rev-parse", "--verify", "HEAD^{commit}") if wt else ""
            if not wt or head != ver["sha"]:
                raise ProviderError(
                    "verification_stale",
                    f"multiclaude: worker HEAD is {head or 'unknown'} but {ver['sha']} was verified; re-verify before release",
                    {"dispatchId": dispatch_id, "verifiedSha": ver["sha"], "head": head},
                )
            dirty = foreign_dirty_paths(lambda argv: self._cli_text(argv), wt, (MC_SETTINGS_ARTIFACT,))
            if dirty:
                raise ProviderError(
                    "dirty_worktree_release_blocked",
                    f"multiclaude: {wt} has uncommitted work ({', '.join(dirty[:5])}); complete_agent's forced "
                    "worktree remove would discard it — commit it (and re-verify) or retain the worker",
                    {"dispatchId": dispatch_id, "dirty": dirty},
                )
            args = {"repo": repo, "agent": agent_name}
            if reason:
                args["summary"] = reason
            upstream = self._command("complete_agent", args)
        elif verb in ("stop", "abandon"):
            upstream = self._stop_upstream(repo, agent_name, row["worktree"])
        new_state, term_state = self._fence_local(dispatch_id, verb)
        ver = self._verification(dispatch_id)
        return {"dispatchId": dispatch_id, "verb": verb, "state": new_state, "terminalState": term_state,
                "verifiedSha": ver["sha"] if ver else None, "reason": reason, "upstream": upstream}

    # --- Mailbox (multiclaude message files + `route_messages`) ---
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
            subject=subject, msg_type=msg_type, to=to, outcome=outcome, sender=sender,
            payload=payload, run=run, attrs=attrs,
        )
        if to:
            with self.state._connect() as conn:
                row = conn.execute(
                    "SELECT session_id, launch_effective FROM dispatches WHERE backend = ? AND (dispatch_id = ? OR terminal_handle = ?)",
                    (self.name, to, to),
                ).fetchone()
            if row:
                repo = self._effective(row).get("repo") or self._repo()
                body = payload if payload is not None else subject
                local["upstream"] = {"messageId": self._deliver(repo, str(row["session_id"]), f"[{msg_type}] {subject}: {body}")}
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
