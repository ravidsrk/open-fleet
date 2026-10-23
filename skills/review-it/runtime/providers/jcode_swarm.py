#!/usr/bin/env python3
"""jcode_swarm.py — JCode Swarm (`1jehuang/jcode`, `jcode serve` daemon socket) RuntimeProvider (#588).

Source-derived (crates/jcode-protocol/src/wire.rs + wire/events.rs) — there is NO
`jcode api-bridge <op> <json>` CLI and the api-bridge exposes no swarm ops, so this adapter
speaks the daemon's own newline-delimited JSON protocol (`{"type": ..., "id": N, ...}`) on
the `jcode serve` socket (`--socket` / `JCODE_SOCKET`, default `<runtime_dir>/jcode.sock`;
override with `OPEN_FLEET_JCODE_SOCKET`). A connection must `subscribe` first; it attaches
to the coordinator session named by `OPEN_FLEET_JCODE_COORDINATOR_SESSION` (swarm requests
are issued *as* that session).

  - `worker_start` -> `comm_spawn{session_id, working_dir, initial_message=<task spec>,
    spawn_mode:"headless", label}`; the dispatch id is the reply's `new_session_id`.
    A swarm member is always a jcode session (no external harness), so `agent` must be
    `jcode`. `comm_spawn` carries no tool restriction, so `PROFILE=ro` fails closed
    (`unsupported_profile`); `danger` fails closed (no sandbox).
  - `worker_read` -> `comm_read_context{target_session}` (history messages).
  - `worker_show` -> `comm_status{target_session}` and syncs file touches.
  - `worker_fence` stop/abandon/release -> `comm_stop{target_session, force}`; retain is local.
  - `sync_file_touches` -> `debug_command{command:"swarm:touches"}` (daemon needs
    `JCODE_DEBUG_CONTROL=1`). FileTouch has no line fields; the range is parsed from the
    summary exactly like jcode's `parse_file_activity_line_range`, and only a touch whose
    range is unknown is recorded as whole-file.
"""
from __future__ import annotations

import json
import re
import socket
import time
from pathlib import Path
from typing import Any, Callable

from ._external import ExternalDispatchMixin, env_lookup, real_worktree
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

WHOLE_FILE_END = 999999
_WRITE_OPS = {"wrote", "edited", "write", "edit"}


def parse_line_range(summary: Any) -> tuple[int, int] | None:
    """Port of jcode `parse_file_activity_line_range` (server/file_activity.rs)."""
    if not isinstance(summary, str):
        return None
    idx = summary.find("lines ")
    if idx >= 0:
        rest = summary[idx + len("lines "):]
    else:
        idx = summary.find("line ")
        if idx < 0:
            return None
        rest = summary[idx + len("line "):]
    m = re.match(r"(\d+)(?:-(\d*))?", rest)
    if not m:
        return None
    start = int(m.group(1))
    end = int(m.group(2)) if m.group(2) else start
    return (min(start, end), max(start, end))


def default_socket_path(env: dict[str, str] | None) -> str:
    explicit = env_lookup(env, "OPEN_FLEET_JCODE_SOCKET", "ORCA_JCODE_SOCKET", "JCODE_SOCKET")
    if explicit:
        return explicit
    runtime = env_lookup(env, "JCODE_RUNTIME_DIR", "XDG_RUNTIME_DIR")
    return str(Path(runtime) / "jcode.sock") if runtime else ""


class JCodeSwarmProvider(ExternalDispatchMixin, RuntimeProvider):
    """RuntimeProvider adapter for JCode Swarm (`jcode serve` daemon socket)."""

    name = "jcode-swarm"

    def __init__(
        self,
        state: LocalStateStore | None = None,
        runner: Callable[..., Any] | None = None,
        *,
        db_path: str | Path | None = None,
        env: dict[str, str] | None = None,
        socket_path: str | Path | None = None,
        coordinator_session: str | None = None,
        **kwargs: Any,
    ) -> None:
        self.env = dict(env) if env is not None else None
        self.state = state or LocalStateStore(db_path=db_path, env=self.env)
        self.socket_path = str(socket_path or default_socket_path(self.env))
        self.coordinator_session = coordinator_session or env_lookup(
            self.env, "OPEN_FLEET_JCODE_COORDINATOR_SESSION", "ORCA_JCODE_COORDINATOR_SESSION"
        )
        self._runner = runner or self._default_runner
        self.call_log: list[dict[str, Any]] = []
        self._seq = 1
        with self.state._connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS jcode_touch_sync (touch_key TEXT PRIMARY KEY, synced_at REAL NOT NULL)")

    # --- transport -------------------------------------------------------------------
    def _default_runner(self, request: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        if not self.socket_path:
            raise ProviderError("jcode_socket_unknown", "jcode: set OPEN_FLEET_JCODE_SOCKET (or JCODE_SOCKET / JCODE_RUNTIME_DIR)")
        timeout = float(kwargs.get("timeout", 60))
        subscribe = {"type": "subscribe", "id": 1, "target_session_id": self.coordinator_session}
        wd = request.get("working_dir")
        if wd:
            subscribe["working_dir"] = wd
        req_id = int(request.get("id") or 2)
        deadline = time.monotonic() + timeout
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect(self.socket_path)
                sock.sendall((json.dumps(subscribe) + "\n").encode("utf-8"))
                sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
                buf = b""
                while time.monotonic() < deadline:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        if not line.strip():
                            continue
                        try:
                            ev = json.loads(line)
                        except json.JSONDecodeError as exc:
                            raise ProviderError("jcode_bad_json", f"jcode: daemon sent non-JSON line {line[:120]!r}") from exc
                        if isinstance(ev, dict) and ev.get("id") in (1, req_id) and ev.get("type") == "error":
                            raise ProviderError("jcode_daemon_error", str(ev.get("message") or "error"), {"event": ev})
                        if isinstance(ev, dict) and ev.get("id") == req_id and ev.get("type") != "ack":
                            return ev
        except ProviderError:
            raise
        except (OSError, socket.timeout) as exc:
            raise ProviderError("jcode_unreachable", f"jcode: daemon socket {self.socket_path}: {exc}") from exc
        raise ProviderError("jcode_no_reply", f"jcode: no reply to {request.get('type')!r} before the socket closed")

    def _request(self, req_type: str, **fields: Any) -> dict[str, Any]:
        self._seq += 1
        request = {"type": req_type, "id": self._seq, **{k: v for k, v in fields.items() if v is not None}}
        self.call_log.append(request)
        res = self._runner(request)
        if not isinstance(res, dict):
            raise ProviderError("jcode_bad_response", f"jcode: expected an event object for {req_type!r}")
        if res.get("type") == "error":
            raise ProviderError("jcode_daemon_error", str(res.get("message") or "error"), {"event": res})
        return res

    def _coordinator(self) -> str:
        if not self.coordinator_session:
            raise ProviderError(
                "missing_coordinator_session",
                "jcode: swarm requests are issued as a coordinator session; set OPEN_FLEET_JCODE_COORDINATOR_SESSION",
            )
        return self.coordinator_session

    # --- Task DAG (local; jcode plans are proposed by sessions, not by an external client) ---
    def task_create(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_create(**kwargs)

    def task_update(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_update(**kwargs)

    def task_list(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_list(**kwargs)

    # --- Worker dispatch (`comm_spawn`) ---
    def worker_start(
        self,
        *,
        task_id: str = "",
        worktree: str = "new-child",
        agent: str = "jcode",
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
        if agent not in ("jcode", "jcode-swarm"):
            raise ProviderError(
                "unsupported_agent",
                f"jcode-swarm: a swarm member is always a jcode session; agent {agent!r} cannot be launched by comm_spawn",
            )
        if profile != "rw":
            raise ProviderError(
                "unsupported_profile",
                f"jcode-swarm: PROFILE={profile} cannot be enforced — comm_spawn has no tool restriction field "
                "(configure_tools only applies to an attached session after its first turn starts) and no sandbox",
            )
        wt = real_worktree(worktree)
        if not wt:
            raise ProviderError("worktree_required", f"jcode-swarm: jcode does not create worktrees; pass an existing --worktree (got {worktree!r})")
        coord = self._coordinator()
        task_prompt = self.resolve_task_prompt(task_id, prompt)
        reply = self._request(
            "comm_spawn",
            session_id=coord,
            working_dir=wt,
            initial_message=task_prompt,
            spawn_mode="headless",
            label=(name or task_id or None),
            request_nonce=retry_request or None,
        )
        session_id = require_id(reply, "new_session_id", provider="jcode", what="new_session_id")
        handle = f"jcode:{session_id}"
        effective = {
            "agent": "jcode",
            "profile": profile,
            "mechanism": "comm_spawn",
            "spawnMode": "headless",
            "coordinatorSession": coord,
            "sessionId": session_id,
            # jcode reads its PreToolUse hook from JCODE_HOOK_PRE_TOOL in the DAEMON env; no
            # per-worktree file is read, so nothing is written into the worker worktree.
            "hooks": None,
        }
        self._record_dispatch(
            dispatch_id=session_id, task_id=task_id, run=run, worktree=wt, agent="jcode",
            profile=profile, handle=handle, effective=effective, session_id=session_id,
        )
        res = {
            "state": "ready",
            "dispatchId": session_id,
            "agentTerminalHandle": handle,
            "worktree": wt,
            "agent": "jcode",
            "profile": profile,
            "launch": {"effective": effective},
            "upstream": reply,
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    # --- File-touch coordination (`debug_command swarm:touches`) ---
    def sync_file_touches(self, *, run_id: str = "default", **kwargs: Any) -> dict[str, Any]:
        reply = self._request("debug_command", command="swarm:touches", session_id=self.coordinator_session or None)
        if reply.get("ok") is False:
            raise ProviderError("jcode_debug_refused", str(reply.get("output") or "swarm:touches refused"), {"event": reply})
        output = reply.get("output")
        touches = parse_json_strict(output, "jcode", allow_empty=False) if isinstance(output, str) else output
        if not isinstance(touches, list):
            raise ProviderError("jcode_bad_response", "jcode: swarm:touches output is not a JSON list", {"event": reply})
        results: list[dict[str, Any]] = []
        skipped = 0
        for t in touches:
            if not isinstance(t, dict):
                continue
            op = str(t.get("op") or "")
            path = str(t.get("path") or t.get("file_path") or "")
            worker = str(t.get("session_id") or t.get("worker_id") or "")
            if not path or not worker or op.lower() not in _WRITE_OPS:
                skipped += 1
                continue
            if t.get("start_line") is not None:
                start = int(t["start_line"])
                end = int(t.get("end_line") if t.get("end_line") is not None else start)
                known = True
            else:
                rng = parse_line_range(t.get("summary"))
                known = rng is not None
                start, end = rng if rng else (1, WHOLE_FILE_END)
            key = json.dumps([run_id, worker, path, op, t.get("timestamp_unix"), t.get("summary"), start, end])
            with self.state._connect() as conn:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO jcode_touch_sync(touch_key, synced_at) VALUES (?, ?)", (key, time.time())
                )
                fresh = cur.rowcount == 1
            if not fresh:
                skipped += 1
                continue
            rec = self.state.record_file_touch(
                worker_id=worker, file_path=path, start_line=start, end_line=end, op="write", run_id=run_id
            )
            rec["rangeKnown"] = known
            results.append(rec)
        return {"synced": len(results), "skipped": skipped, "results": results, "upstream": reply}

    # --- Mailbox (`comm_message` + `LocalStateStore`) ---
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
        body = payload if payload is not None else subject
        target: str | None = None
        broadcast = to in ("all", "broadcast", "*")
        if to and not broadcast:
            with self.state._connect() as conn:
                row = conn.execute(
                    "SELECT session_id FROM dispatches WHERE backend = ? AND (dispatch_id = ? OR terminal_handle = ?)",
                    (self.name, to, to),
                ).fetchone()
            target = str(row["session_id"]) if row else None
        if broadcast or target:
            local["upstream"] = self._request(
                "comm_message", from_session=self._coordinator(), message=f"[{msg_type}] {subject}\n{body}",
                to_session=target,
            )
        return local

    def check_messages(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.check_messages(**kwargs)

    def reply_message(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.reply_message(**kwargs)

    def ask_human(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.ask_human(**kwargs)

    def request_show(self, request_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.state.request_show(request_id)

    # --- Worker observation & fencing ---
    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        return self._list_local(run=kwargs.get("run"), task=kwargs.get("task"), limit=kwargs.get("limit"))

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        row = self._dispatch_row(dispatch_id)
        status = self._request("comm_status", session_id=self._coordinator(), target_session=str(row["session_id"]))
        out = self._show_row(row, raw=status)
        try:
            out["fileTouches"] = self.sync_file_touches(run_id=row["run_id"] or "default")
        except ProviderError as exc:
            out["fileTouches"] = {"error": exc.to_envelope()["error"]}
        return out

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        row = self._dispatch_row(dispatch_id)
        if source != "transcript":
            raise ProviderError("unsupported_operation", "jcode-swarm: only the session transcript is readable")
        reply = self._request("comm_read_context", session_id=self._coordinator(), target_session=str(row["session_id"]))
        msgs = reply.get("messages")
        if not isinstance(msgs, list):
            raise ProviderError("jcode_bad_response", "jcode: comm_read_context carried no messages", {"event": reply})
        window = msgs[-int(limit):] if limit else msgs
        messages = [
            {"id": f"msg_{i}", "role": str(m.get("role") or "assistant"),
             "blocks": [{"type": "text", "text": str(m.get("content") or "")}]}
            for i, m in enumerate(window) if isinstance(m, dict)
        ]
        return normalize_read("transcript", messages=messages)

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        fence_state(verb)
        row = self._dispatch_row(dispatch_id)
        raw = None
        if verb != "retain":
            raw = self._request(
                "comm_stop", session_id=self._coordinator(), target_session=str(row["session_id"]),
                force=(verb == "abandon") or None,
            )
        new_state, term_state = self._fence_local(dispatch_id, verb)
        return {"dispatchId": dispatch_id, "verb": verb, "state": new_state, "terminalState": term_state,
                "reason": reason, "upstream": raw}


