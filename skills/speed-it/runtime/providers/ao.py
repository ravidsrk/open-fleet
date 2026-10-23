#!/usr/bin/env python3
"""ao.py — Composio Agent Orchestrator (`ComposioHQ/agent-orchestrator`, `ao`) RuntimeProvider (#588).

Source-verified against the Go daemon (`backend/internal/httpd/controllers`): a loopback
HTTP daemon on `127.0.0.1:3001` (`AO_PORT`), base path `/api/v1`.

  - `worker_start` -> `POST /api/v1/sessions` (`SpawnSessionRequest`): `projectId`, `kind`,
    `harness`, `prompt` (the task spec, <= 16 KiB), `approvalMode`, `displayName`,
    `clientRequestId`. The session id is `session.id` in the response; the worktree path is
    NOT in the session JSON (`Metadata` is `json:"-"`) and is read from
    `GET /api/v1/desktop/sessions/{id}/workspace` -> `workspacePath`.
  - AO's permission modes are `default|accept-edits|auto|bypass-permissions`: there is no
    read-only/plan mode and no launch-command override, and the agent starts before its
    worktree is known (so a deny hook cannot precede it). `PROFILE=ro` therefore fails
    closed (`unsupported_profile`); `danger` fails closed too (AO has no sandbox).
  - `worker_read` -> `GET /api/v1/sessions/{id}/conversation` (chat transcript). TUI
    terminal bytes only exist on the `/mux` WebSocket, so terminal reads fail closed.
  - `terminal_send` -> `POST /api/v1/sessions/{id}/send` `{message}`.
  - Fencing: the WORKER's HEAD is pinned with the shared `_external.preserve_worker_head`
    (read in the worker's own worktree, ref read back, git common dir must outlive the
    worktree) under `refs/open-fleet/preserved/<session-id>` (AO itself owns
    `refs/ao/preserved/<id>` for its uncommitted-work stash, so we never write there), then
    `POST /api/v1/sessions/{id}/kill`. `release` REQUIRES the pin (an unresolvable worktree or
    a failed pin aborts the kill); `stop`/`abandon` pin best-effort and kill regardless, so a
    runaway session can always be stopped (the receipt carries `preserveError`). `retain`
    never kills.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

from ._external import ExternalDispatchMixin, http_json, preserve_worker_head, real_worktree, run_cli
from .base import (
    ProviderError,
    RuntimeProvider,
    check_monotonic_profile,
    env_get,
    fence_state,
    normalize_read,
    normalize_show,
    require_id,
)
from .local_state import LocalStateStore
from .posix import install_worktree_hooks

# open-fleet agent name -> AO `harness` enum value (dto.go SpawnSessionRequest.Harness).
AO_HARNESSES = {
    "claude": "claude-code",
    "codex": "codex",
    "opencode": "opencode",
    "crush": "crush",
    "goose": "goose",
    "pi": "pi",
    "omp": "omp",
    "gemini": "gemini",
    "cursor": "cursor",
    "droid": "droid",
    "grok": "grok",
}
# The harnesses worker_start accepts (capabilities.json `supported_harnesses` mirrors this).
SUPPORTED_HARNESSES = tuple(AO_HARNESSES)
AO_PROMPT_MAX_BYTES = 16384
AO_SEND_MAX_CHARS = 4096
# `_external.preserve_worker_head` namespace (shared with the other adapters).
PRESERVED_REF_PREFIX = "refs/open-fleet/preserved/"
_SHA_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")


def safe_ref_component(session_id: str) -> str:
    """A git-ref-safe single path component derived from an AO session id (never a path)."""
    comp = re.sub(r"[^A-Za-z0-9._-]", "-", str(session_id or "")).strip(".-")
    comp = comp.replace("..", "-")
    if comp.endswith(".lock"):
        comp = comp[: -len(".lock")] + "-lock"
    if not comp:
        raise ProviderError("invalid_ref_name", f"session id {session_id!r} yields no usable ref name")
    return comp


class ComposioAOProvider(ExternalDispatchMixin, RuntimeProvider):
    """RuntimeProvider adapter for Composio Agent Orchestrator (`ao`)."""

    name = "ao"

    def __init__(
        self,
        state: LocalStateStore | None = None,
        runner: Callable[..., Any] | None = None,
        *,
        db_path: str | Path | None = None,
        env: dict[str, str] | None = None,
        base_url: str | None = None,
        project: str | None = None,
        **kwargs: Any,
    ) -> None:
        self.env = dict(env) if env is not None else None
        self.state = state or LocalStateStore(db_path=db_path, env=self.env)
        self.base_url = (
            base_url
            or env_get("OPEN_FLEET_AO_URL", "ORCA_AO_URL", self.env, "http://127.0.0.1:3001")
        ).rstrip("/")
        self.project = project or env_get("OPEN_FLEET_AO_PROJECT", "ORCA_AO_PROJECT", self.env, "")
        self._runner = runner or self._default_runner
        self.call_log: list[Any] = []
        self.preserved_refs: dict[str, str] = {}

    def _default_runner(self, call: Any, **kwargs: Any) -> Any:
        timeout = kwargs.get("timeout", 60)
        if isinstance(call, list):
            return run_cli(call, provider="ao", timeout=timeout)
        return http_json(
            self.base_url,
            call.get("method", "GET"),
            call.get("path", "/"),
            call.get("body"),
            provider="ao",
            timeout=timeout,
        )

    def _invoke(self, call: Any, **kwargs: Any) -> dict[str, Any]:
        self.call_log.append(call)
        res = self._runner(call, **kwargs)
        if not isinstance(res, dict):
            raise ProviderError("ao_bad_response", f"ao: expected a JSON object, got {type(res).__name__}")
        return res

    def _session_id(self, row: Any) -> str:
        return str(row["session_id"] or row["dispatch_id"])

    def _resolve_worktree(self, session_id: str, raw: Any = None) -> str | None:
        """Real worker worktree: spawn/session payload when present, else the desktop workspace route."""
        for src in (raw or {}, (raw or {}).get("session") if isinstance(raw, dict) else None):
            if isinstance(src, dict):
                for key in ("workspacePath", "worktreePath"):
                    wt = real_worktree(src.get(key))
                    if wt:
                        return wt
        try:
            ws = self._invoke({"method": "GET", "path": f"/api/v1/desktop/sessions/{session_id}/workspace", "body": None})
        except ProviderError:
            return None
        return real_worktree(ws.get("workspacePath"))

    def _git_head(self, wt: str, rev: str = "HEAD") -> str:
        res = self._invoke(["git", "-C", wt, "rev-parse", "--verify", f"{rev}^{{commit}}"])
        sha = str(res.get("raw") or res.get("stdout") or "").strip()
        if not _SHA_RE.match(sha):
            raise ProviderError("worktree_head_unresolved", f"git rev-parse {rev} in {wt} gave {sha!r}", {"worktree": wt})
        return sha

    def _git_text(self, argv: list[str]) -> str:
        res = self._invoke(argv)
        return str(res.get("raw") if res.get("raw") is not None else res.get("stdout") or "")

    def preserve_worktree_ref(
        self,
        session_id: str,
        head_sha: str | None = None,
        worktree_path: str | None = None,
    ) -> str:
        """Pin the WORKER worktree's HEAD under `refs/open-fleet/preserved/<id>` before teardown.

        Delegates to `_external.preserve_worker_head` (HEAD read in the worker's worktree, ref
        read back, common dir must survive the worktree). When the worktree cannot be resolved
        this raises `worktree_unknown` instead of touching whatever repository the coordinator
        happens to run in. Only the worker's ACTUAL HEAD is ever pinned: a different
        `head_sha` is refused (`preserve_failed`).
        """
        safe_id = safe_ref_component(session_id)
        row = None
        try:
            row = self._dispatch_row(session_id)
        except ProviderError:
            row = None
        wt = real_worktree(worktree_path) or (real_worktree(row["worktree"]) if row is not None else None)
        if not wt and row is not None:
            wt = self._resolve_worktree(self._session_id(row))
            if wt:
                self._patch_dispatch(session_id, worktree=wt)
        if not wt:
            raise ProviderError(
                "worktree_unknown",
                f"ao: cannot resolve the worker worktree of session {session_id!r}; refusing to preserve a ref "
                "from the coordinator's cwd (and refusing teardown)",
                {"sessionId": session_id},
            )
        if head_sha and head_sha != "HEAD":
            want = self._git_head(wt, head_sha)
            if want != self._git_head(wt):
                raise ProviderError("preserve_failed", f"ao: {head_sha!r} is not the worker HEAD in {wt}; only HEAD is preserved")
        pinned = preserve_worker_head(self._git_text, wt, safe_id)
        ref_name = pinned["ref"]
        self.preserved_refs[session_id] = ref_name
        if row is not None:
            self._patch_dispatch(session_id, effective={"preservedRef": ref_name, "preservedSha": pinned["sha"]})
            with self.state._connect() as conn:
                conn.execute("UPDATE dispatches SET head_sha = ? WHERE dispatch_id = ?", (pinned["sha"], session_id))
        return ref_name

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
        project: str | None = None,
        issue: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        cached = self.state.get_or_record_request(retry_request, "worker-start")
        if cached:
            return cached

        check_monotonic_profile(parent_profile, profile)
        if profile != "rw":
            raise ProviderError(
                "unsupported_profile",
                f"ao: PROFILE={profile} cannot be enforced — AO approval modes are default|accept-edits|auto|"
                "bypass-permissions (no read-only/plan mode, no launch override, no sandbox), and the agent starts "
                "before its worktree exists so no deny hook can precede it",
            )
        harness = AO_HARNESSES.get(agent)
        if not harness:
            raise ProviderError("unsupported_agent", f"ao: no AO harness for agent {agent!r} (want {sorted(AO_HARNESSES)})")
        if worktree not in ("", "new-child", "new-top-level"):
            raise ProviderError(
                "unsupported_worktree",
                f"ao: AO creates each session's own worktree; an explicit worktree {worktree!r} cannot be honoured",
            )
        proj = project or self.project
        if not proj:
            raise ProviderError("missing_project", "ao: set OPEN_FLEET_AO_PROJECT (or pass project=) to the AO project id")
        task_prompt = self.resolve_task_prompt(task_id, prompt)
        if len(task_prompt.encode("utf-8")) > AO_PROMPT_MAX_BYTES:
            raise ProviderError("prompt_too_large", f"ao: spawn prompt exceeds AO's {AO_PROMPT_MAX_BYTES}-byte limit")

        body: dict[str, Any] = {
            "projectId": proj,
            "kind": "worker",
            "harness": harness,
            "prompt": task_prompt,
            "approvalMode": "bypass-permissions",
        }
        if name:
            body["displayName"] = name[:100]
        if issue:
            body["issueId"] = issue
        if retry_request:
            body["clientRequestId"] = retry_request[:128]
        raw = self._invoke({"method": "POST", "path": "/api/v1/sessions", "body": body})
        session_id = require_id(raw, "session.id", "id", provider="ao", what="session id")

        wt = self._resolve_worktree(session_id, raw)
        hooks: dict[str, str] | None = None
        if wt:
            hooks = install_worktree_hooks(wt, agent, profile)
        handle = f"ao:{session_id}"
        effective = {
            "agent": agent,
            "harness": harness,
            "profile": profile,
            "project": proj,
            "approvalMode": body["approvalMode"],
            "mechanism": "POST /api/v1/sessions",
            "sessionId": session_id,
            "promptBytes": raw.get("promptBytes"),
            "worktreeResolved": bool(wt),
            "hooks": hooks,
        }
        self._record_dispatch(
            dispatch_id=session_id, task_id=task_id, run=run, worktree=wt or "", agent=agent,
            profile=profile, handle=handle, effective=effective, session_id=session_id,
        )
        res = {
            "state": "ready",
            "dispatchId": session_id,
            "agentTerminalHandle": handle,
            "worktree": wt,
            "agent": agent,
            "profile": profile,
            "launch": {"effective": effective},
            "upstream": raw,
        }
        self.state.save_request(retry_request, "worker-start", "ready", res)
        return res

    def terminal_read(self, **kwargs: Any) -> dict[str, Any]:
        raise ProviderError(
            "unsupported_operation",
            "ao: TUI terminal output is only streamed over the /mux WebSocket; there is no REST output route",
        )

    def terminal_send(self, *, terminal: str = "", text: str = "", enter: bool = True, **kwargs: Any) -> dict[str, Any]:
        session_id = terminal.split(":", 1)[1] if terminal.startswith("ao:") else terminal
        if not text or len(text) > AO_SEND_MAX_CHARS:
            raise ProviderError("invalid_message", f"ao: send message must be 1..{AO_SEND_MAX_CHARS} characters")
        raw = self._invoke({"method": "POST", "path": f"/api/v1/sessions/{session_id}/send", "body": {"message": text}})
        if raw.get("ok") is False:
            raise ProviderError("ao_send_failed", f"ao: send to {session_id!r} was not accepted", {"response": raw})
        return {"terminal": terminal, "sessionId": session_id, "sent": True, "upstream": raw}

    def worker_read(self, *, dispatch_id: str = "", source: str = "transcript", limit: int = 50, **kwargs: Any) -> dict[str, Any]:
        row = self._dispatch_row(dispatch_id)
        if source != "transcript":
            raise ProviderError("unsupported_operation", "ao: terminal bytes are WebSocket-only; read --source transcript")
        sid = self._session_id(row)
        raw = self._invoke({"method": "GET", "path": f"/api/v1/sessions/{sid}/conversation?limit={int(limit)}", "body": None})
        msgs = raw.get("messages")
        if not isinstance(msgs, list):
            raise ProviderError("ao_bad_response", "ao: conversation snapshot carries no messages list", {"response": raw})
        messages = [
            {
                "id": str(m.get("id") or f"msg_{i}"),
                "role": str(m.get("role") or "assistant"),
                "blocks": [{"type": "text", "text": str(m.get("text") or "")}],
            }
            for i, m in enumerate(msgs[-int(limit):] if limit else msgs)
            if isinstance(m, dict)
        ]
        return normalize_read("transcript", messages=messages, cursor=raw.get("latestSequence"))

    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        return self._list_local(run=kwargs.get("run"), task=kwargs.get("task"), limit=kwargs.get("limit"))

    def worker_show(self, *, dispatch_id: str = "", **kwargs: Any) -> dict[str, Any]:
        row = self._dispatch_row(dispatch_id)
        raw = self._invoke({"method": "GET", "path": f"/api/v1/sessions/{self._session_id(row)}", "body": None})
        sess = raw.get("session") if isinstance(raw.get("session"), dict) else raw
        return normalize_show(
            row["dispatch_id"],
            row["state"],
            task_id=row["task_id"],
            terminal_state=row["terminal_state"],
            handle=row["terminal_handle"],
            worktree=row["worktree"],
            stage=str(sess.get("status") or row["state"]),
            raw=raw,
        )

    def worker_fence(self, *, verb: str, dispatch_id: str = "", reason: str | None = None, **kwargs: Any) -> dict[str, Any]:
        fence_state(verb)
        row = self._dispatch_row(dispatch_id)
        sid = self._session_id(row)
        if verb == "retain":
            preserved = None
            try:
                preserved = self.preserve_worktree_ref(dispatch_id)
            except ProviderError as exc:
                if exc.code not in ("worktree_unknown", "preserve_failed"):  # retain destroys nothing
                    raise
            new_state, term_state = self._fence_local(dispatch_id, verb)
            return {"dispatchId": dispatch_id, "verb": verb, "state": new_state, "terminalState": term_state,
                    "preservedRef": preserved, "reason": reason, "upstream": None}
        # release (destructive cleanup) REQUIRES the pin; stop/abandon must always be able to
        # kill a runaway session, so their pin is best-effort and reported.
        preserved_ref: str | None = None
        preserve_error: dict[str, Any] | None = None
        try:
            preserved_ref = self.preserve_worktree_ref(dispatch_id)
        except ProviderError as exc:
            if verb == "release":
                raise
            preserve_error = exc.to_envelope()["error"]
        raw = self._invoke({"method": "POST", "path": f"/api/v1/sessions/{sid}/kill", "body": {}})
        new_state, term_state = self._fence_local(dispatch_id, verb)
        return {
            "dispatchId": dispatch_id,
            "verb": verb,
            "state": new_state,
            "terminalState": term_state,
            "preservedRef": preserved_ref,
            "preserveError": preserve_error,
            "reason": reason,
            "upstream": raw,
        }

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
