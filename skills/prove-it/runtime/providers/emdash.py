#!/usr/bin/env python3
"""emdash.py — Emdash (`generalaction/emdash`, `emdash-workspace-server`) RuntimeProvider (#589).

Source-verified against `apps/workspace-server` + `packages/wire`:

  - Transport is a UNIX socket (`serve --socket-path`, default
    `~/.emdash/workspace-server/run/workspace.sock`; override `OPEN_FLEET_EMDASH_SOCKET`) —
    there is no HTTP listener. Frames are `0x00 | u32be length | UTF-8 JSON`; calls are
    `{kind:"call", id, path, input}`, replies `{kind:"result", id, ok, value|code,message}`,
    and fallible values are `{success, data|error}`. Each connection opens with
    `initialize {protocolVersion, client}` (protocol `12.0.0`, override
    `OPEN_FLEET_EMDASH_PROTOCOL`).
  - `worker_start` -> `tuiAgents.startSession {conversationId, providerId, cwd, sessionId:null,
    model:null, cols, rows, initialPrompt=<task spec>, autoApprove, extraArgs}`. The
    caller-chosen `conversationId` is the ONLY id upstream uses (PTY key, `sendInput`,
    `stop`, the `tuiAgents.output|{conversationId}` topic) — there is no ptyId/streamId.
    The CLI runs interactively in a PTY: emdash builds `[...flags, ...extraArgs, initialPrompt]`
    (`buildStandardCommand`), so the prompt is the positional right after `extraArgs`.
    `PROFILE=ro` passes `--disallowedTools=Edit,...` as ONE `=`-joined token (claude's
    `--disallowedTools` is variadic: a split value would swallow the prompt as a tool name) and
    ends on the fixed-arity `--permission-mode plan` (never `-p`), sets `autoApprove:false`, and
    installs the deny hooks in `cwd` BEFORE the agent starts. `trustWorkspace:true` pre-accepts
    the folder-trust dialog (`runtime.ts` -> `workspaceTrust.ensureTrusted`) so the agent neither
    stalls there nor skips the project-local deny-hook settings.
  - Worktrees: `workspaceRegistry.createWorktree` (needs a registered `repositoryId`, a
    `baseRef`, and a caller-chosen path), `workspaceRegistry.deleteWorktree`,
    `git.repository.listWorktrees`. `deleteWorktree` is ALWAYS `git worktree remove --force`
    upstream (`delete-worktree.ts`: "no dirty/unpushed refusals by design"), so `worktree_rm`
    pins the worktree HEAD under `refs/open-fleet/preserved/` first and, unless `force`,
    refuses while uncommitted work remains.
"""
from __future__ import annotations

import json
import socket
import struct
import uuid
from pathlib import Path
from typing import Any, Callable

from ._external import ExternalDispatchMixin, env_lookup, foreign_dirty_paths, preserve_worker_head, real_worktree, run_cli_text
from .base import (
    ProviderError,
    RuntimeProvider,
    check_monotonic_profile,
    fence_state,
    normalize_read,
)
from .local_state import LocalStateStore
from .posix import install_worktree_hooks

EMDASH_PROTOCOL_VERSION = "12.0.0"
EMDASH_MAX_FRAME = 16 * 1024 * 1024
# PROFILE=ro extraArgs for the claude provider: interactive plan mode, never print mode.
# emdash appends initialPrompt right after extraArgs, and claude's `--disallowedTools` is
# variadic (commander `<tools...>`): `--disallowedTools Edit,...` would eat the prompt as a tool
# name. The `=` form takes exactly one value, and the list ends on a fixed-arity flag.
EMDASH_CLAUDE_RO_ARGS = ["--disallowedTools=Edit,Write,MultiEdit,NotebookEdit", "--permission-mode", "plan"]


def encode_frame(message: dict[str, Any]) -> bytes:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    return b"\x00" + struct.pack(">I", len(body)) + body


def output_topic(conversation_id: str) -> str:
    return "tuiAgents.output|" + json.dumps({"conversationId": conversation_id}, separators=(",", ":"), sort_keys=True)


class EmdashProvider(ExternalDispatchMixin, RuntimeProvider):
    """RuntimeProvider adapter for Emdash (`workspace-server` wire protocol over a unix socket)."""

    name = "emdash"

    def __init__(
        self,
        state: LocalStateStore | None = None,
        runner: Callable[..., Any] | None = None,
        *,
        db_path: str | Path | None = None,
        env: dict[str, str] | None = None,
        socket_path: str | Path | None = None,
        git_runner: Callable[[list[str]], str] | None = None,
        **kwargs: Any,
    ) -> None:
        self.env = dict(env) if env is not None else None
        self.state = state or LocalStateStore(db_path=db_path, env=self.env)
        default_sock = str(Path.home() / ".emdash" / "workspace-server" / "run" / "workspace.sock")
        self.socket_path = str(socket_path or env_lookup(self.env, "OPEN_FLEET_EMDASH_SOCKET", "ORCA_EMDASH_SOCKET", default=default_sock))
        self.protocol_version = env_lookup(self.env, "OPEN_FLEET_EMDASH_PROTOCOL", default=EMDASH_PROTOCOL_VERSION)
        self.repository_id = env_lookup(self.env, "OPEN_FLEET_EMDASH_REPOSITORY_ID")
        self.worktree_root = env_lookup(
            self.env, "OPEN_FLEET_EMDASH_WORKTREE_ROOT", default=str(Path.home() / ".open-fleet" / "emdash-worktrees")
        )
        self._runner = runner or self._default_runner
        self._git = git_runner or (lambda argv: run_cli_text(argv, self.name))
        self.call_log: list[dict[str, Any]] = []
        self._seq = 0
        with self.state._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS emdash_worktrees (workspace_id TEXT PRIMARY KEY, path TEXT NOT NULL)")

    # --- transport -------------------------------------------------------------------
    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ProviderError("emdash_disconnected", "emdash: workspace-server closed the socket mid-frame")
            buf += chunk
        return buf

    def _read_result(self, sock: socket.socket, want_id: str) -> dict[str, Any]:
        while True:
            header = self._recv_exact(sock, 5)
            ftype, length = header[0], struct.unpack(">I", header[1:5])[0]
            if length > EMDASH_MAX_FRAME:
                raise ProviderError("emdash_bad_frame", f"emdash: frame of {length} bytes exceeds 16 MiB")
            payload = self._recv_exact(sock, length)
            if ftype == 0x01:  # blob frame: skip its body
                body_len = struct.unpack(">I", self._recv_exact(sock, 4))[0]
                self._recv_exact(sock, body_len)
                continue
            try:
                msg = json.loads(payload.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise ProviderError("emdash_bad_json", "emdash: unparseable frame from workspace-server") from exc
            if isinstance(msg, dict) and msg.get("kind") == "result" and msg.get("id") == want_id:
                return msg

    def _default_runner(self, message: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        timeout = float(kwargs.get("timeout", 60))
        init = {
            "kind": "call",
            "id": f"init-{uuid.uuid4().hex[:8]}",
            "path": "initialize",
            "input": {"protocolVersion": self.protocol_version, "client": {"id": "open-fleet", "appVersion": self.version()}},
        }
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect(self.socket_path)
                sock.sendall(encode_frame(init))
                init_res = self._read_result(sock, init["id"])
                if not init_res.get("ok"):
                    raise ProviderError("emdash_handshake_failed", str(init_res.get("message") or "initialize refused"), {"result": init_res})
                sock.sendall(encode_frame(message))
                return self._read_result(sock, str(message["id"]))
        except ProviderError:
            raise
        except (OSError, socket.timeout) as exc:
            raise ProviderError("emdash_unreachable", f"emdash: workspace-server socket {self.socket_path}: {exc}") from exc

    def _exchange(self, message: dict[str, Any]) -> Any:
        self.call_log.append(message)
        res = self._runner(message)
        if not isinstance(res, dict):
            raise ProviderError("emdash_bad_response", "emdash: expected a result message object")
        if res.get("kind") == "result":
            if not res.get("ok"):
                raise ProviderError(
                    f"emdash_{str(res.get('code') or 'error').lower()}",
                    str(res.get("message") or "workspace-server call failed"),
                    {"path": message.get("path") or message.get("topic")},
                )
            value = res.get("value")
        else:
            value = res
        if isinstance(value, dict) and "success" in value:
            if not value.get("success"):
                raise ProviderError("emdash_call_failed", str(value.get("error") or "call failed"), {"value": value})
            return value.get("data")
        return value

    def _call(self, path: str, input_: dict[str, Any]) -> Any:
        self._seq += 1
        return self._exchange({"kind": "call", "id": f"of-{self._seq}", "path": path, "input": input_})

    def _snapshot(self, topic: str) -> Any:
        self._seq += 1
        return self._exchange({"kind": "snapshot", "id": f"of-{self._seq}", "topic": topic})

    # --- Worktrees (`workspaceRegistry.*`, `git.repository.listWorktrees`) ---
    def worktree_create(self, *, name: str = "worker", base: str | None = None, repo: str | None = None, **kwargs: Any) -> dict[str, Any]:
        repository_id = repo or self.repository_id
        if not repository_id:
            raise ProviderError("missing_repository", "emdash: createWorktree needs a registered repositoryId (OPEN_FLEET_EMDASH_REPOSITORY_ID)")
        if not base:
            raise ProviderError("missing_base", "emdash: createWorktree needs --base (baseRef)")
        workspace_id = str(uuid.uuid4())
        path = str(Path(self.worktree_root).expanduser() / name)
        record = self._call(
            "workspaceRegistry.createWorktree",
            {"workspaceId": workspace_id, "repositoryId": repository_id, "branch": name, "baseRef": base, "path": path},
        )
        if not isinstance(record, dict) or not record.get("path"):
            raise ProviderError("upstream_no_path", "emdash: createWorktree returned no worktree path", {"response": record})
        ws_id = str(record.get("id") or workspace_id)
        with self.state._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO emdash_worktrees(workspace_id, path) VALUES (?, ?)", (ws_id, str(record["path"]))
            )
        return {"worktree": {"id": ws_id, "name": name, "path": str(record["path"]), "base": base}, "upstream": record}

    def _worktree_path(self, workspace_id: str) -> str | None:
        with self.state._connect() as conn:
            row = conn.execute("SELECT path FROM emdash_worktrees WHERE workspace_id = ?", (workspace_id,)).fetchone()
        return str(row["path"]) if row else None

    def worktree_rm(self, *, selector: str = "", force: bool = False, **kwargs: Any) -> dict[str, Any]:
        if not selector:
            raise ProviderError("missing_worktree", "emdash: worktree rm needs the workspace id")
        # Upstream force-removes unconditionally: every safety check has to happen here, first.
        path = self._worktree_path(selector)
        wt_path = real_worktree(path) if path else None
        if not wt_path:
            raise ProviderError(
                "worktree_unknown",
                f"emdash: workspace {selector!r} has no recorded on-disk worktree; refusing a force-remove "
                "whose HEAD and uncommitted work cannot be checked",
                {"path": path},
            )
        preserved = preserve_worker_head(self._git, wt_path, f"emdash-{selector}")
        dirty = foreign_dirty_paths(self._git, wt_path)
        if dirty and not force:
            raise ProviderError(
                "uncommitted_work",
                f"emdash: worktree {wt_path!r} has uncommitted changes deleteWorktree would destroy: {', '.join(dirty[:10])}",
                {"preserved": preserved, "dirty": dirty},
            )
        raw = self._call("workspaceRegistry.deleteWorktree", {"workspaceId": selector, "deleteBranch": False})
        with self.state._connect() as conn:
            conn.execute("DELETE FROM emdash_worktrees WHERE workspace_id = ?", (selector,))
        return {"removed": True, "selector": selector, "path": wt_path, "preserved": preserved,
                "discardedDirty": dirty, "upstream": raw}

    def worktree_list(self, *, repo: str | None = None, limit: int | None = None, **kwargs: Any) -> dict[str, Any]:
        if not repo:
            raise ProviderError("missing_repository", "emdash: worktree list needs --repo <absolute repository path>")
        raw = self._call("git.repository.listWorktrees", {"repository": str(Path(repo).resolve())})
        items = raw.get("worktrees") if isinstance(raw, dict) else None
        if not isinstance(items, list):
            raise ProviderError("emdash_bad_response", "emdash: listWorktrees returned no worktrees list", {"response": raw})
        return {"worktrees": items[:limit] if limit else items, "upstream": raw}

    # --- Worker dispatch (`tuiAgents.startSession`) ---
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
            raise ProviderError("unsupported_profile", "emdash: PROFILE=danger needs a sandbox; workspace-server runs agents on the host")
        if profile == "ro" and agent != "claude":
            raise ProviderError("unsupported_profile", f"emdash: no verified read-only extraArgs for provider {agent!r} (only claude)")
        task_prompt = self.resolve_task_prompt(task_id, prompt)

        upstream_wt = None
        if worktree in ("", "new-child", "new-top-level"):
            upstream_wt = self.worktree_create(name=name or f"of-{task_id or uuid.uuid4().hex[:8]}", base=base)
            wt_path = real_worktree(upstream_wt["worktree"]["path"])
            if not wt_path:
                raise ProviderError("worktree_unknown", "emdash: createWorktree reported a path that does not exist", upstream_wt)
        else:
            wt_path = real_worktree(worktree)
            if not wt_path:
                raise ProviderError("worktree_unknown", f"emdash: worktree {worktree!r} does not exist")

        hooks = install_worktree_hooks(wt_path, agent, profile)
        auto_approve = profile != "ro"
        extra_args = list(EMDASH_CLAUDE_RO_ARGS) if profile == "ro" else []
        conversation_id = str(uuid.uuid4())
        params: dict[str, Any] = {
            "conversationId": conversation_id,
            "providerId": agent,
            "cwd": wt_path,
            "sessionId": None,
            "model": None,
            "cols": 200,
            "rows": 50,
            "initialPrompt": task_prompt,
            "autoApprove": auto_approve,
            "trustWorkspace": True,
            "extraArgs": extra_args,
        }
        raw = self._call("tuiAgents.startSession", params)
        outcome = raw.get("outcome") if isinstance(raw, dict) else None
        if outcome not in ("started", "attached"):
            raise ProviderError("emdash_start_failed", f"emdash: startSession outcome {outcome!r}", {"response": raw})
        handle = f"emdash:{conversation_id}"
        effective = {
            "agent": agent,
            "profile": profile,
            "providerId": agent,
            "autoApprove": auto_approve,
            "trustWorkspace": True,
            "extraArgs": extra_args,
            "conversationId": conversation_id,
            "outcome": outcome,
            "hooks": hooks,
            "workspace": (upstream_wt or {}).get("worktree"),
        }
        self._record_dispatch(
            dispatch_id=conversation_id, task_id=task_id, run=run, worktree=wt_path, agent=agent,
            profile=profile, handle=handle, effective=effective, session_id=conversation_id,
        )
        res = {
            "state": "ready",
            "dispatchId": conversation_id,
            "agentTerminalHandle": handle,
            "worktree": wt_path,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective},
            "upstream": raw,
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    # --- PTY (`tuiAgents.sendInput`, `tuiAgents.output` snapshot) ---
    @staticmethod
    def _conversation(terminal: str) -> str:
        return terminal.split(":", 1)[1] if terminal.startswith("emdash:") else terminal

    def _output_tail(self, conversation_id: str, limit: int | None) -> tuple[list[str], Any]:
        snap = self._snapshot(output_topic(conversation_id))
        data = snap.get("data") if isinstance(snap, dict) else None
        if not isinstance(data, dict) or not isinstance(data.get("text"), str):
            raise ProviderError("emdash_bad_response", "emdash: output snapshot carried no text", {"snapshot": snap})
        lines = data["text"].splitlines()
        return (lines[-int(limit):] if limit else lines), (snap.get("sequence") if isinstance(snap, dict) else None)

    def terminal_send(self, *, terminal: str = "", text: str = "", enter: bool = True, **kwargs: Any) -> dict[str, Any]:
        cid = self._conversation(terminal)
        data = f"{text}\r" if enter else text
        raw = self._call("tuiAgents.sendInput", {"conversationId": cid, "data": data})
        return {"terminal": terminal, "sent": True, "upstream": raw}

    def terminal_read(self, *, terminal: str = "", cursor: int | None = None, limit: int | None = None, screen: bool = False, **kwargs: Any) -> dict[str, Any]:
        cid = self._conversation(terminal)
        lines, seq = self._output_tail(cid, limit)
        return normalize_read("terminal", lines=lines, cursor=seq, handle=f"emdash:{cid}")

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        row = self._dispatch_row(dispatch_id)
        cid = str(row["session_id"] or row["dispatch_id"])
        lines, seq = self._output_tail(cid, limit)
        return normalize_read(
            "terminal",
            lines=lines,
            cursor=seq,
            handle=row["terminal_handle"],
            fallback_reason="emdash exposes PTY output only" if source == "transcript" else None,
        )

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        fence_state(verb)
        row = self._dispatch_row(dispatch_id)
        cid = str(row["session_id"] or row["dispatch_id"])
        raw = None
        if verb in ("stop", "release"):
            raw = self._call("tuiAgents.stop", {"conversationId": cid})  # resumable; output retained
        elif verb == "abandon":
            raw = self._call("tuiAgents.kill", {"conversationId": cid})
        new_state, term_state = self._fence_local(dispatch_id, verb)
        return {"dispatchId": dispatch_id, "verb": verb, "state": new_state, "terminalState": term_state,
                "reason": reason, "upstream": raw}

    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        return self._list_local(run=kwargs.get("run"), task=kwargs.get("task"), limit=kwargs.get("limit"))

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        return self._show_row(self._dispatch_row(dispatch_id))

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
