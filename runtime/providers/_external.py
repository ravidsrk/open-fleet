#!/usr/bin/env python3
"""_external.py — shared plumbing for the 12 external orchestrator adapters (#582-#584, #588, #589).

Private helpers used by every non-Orca, non-POSIX adapter so they all fail the same way (#591 audit):

  - upstream transport errors (missing binary, timeout, HTTP status, unreachable socket,
    unparseable output) become `ProviderError` (`ok:false`), never a fabricated success;
  - dispatch rows are read back through one place that raises `dispatch_not_found`;
  - fence verbs go through `fence_state` and land on the POSIX state names;
  - worker-show / worker-list receipts use `normalize_show`.
"""
from __future__ import annotations

import contextvars
import functools
import inspect
import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import re
from typing import Callable

from .base import ProviderError, fence_state, normalize_show, parse_json_strict
from .local_state import ACTIVE_REQUEST_PAYLOAD_SHA, LocalStateStore, request_payload_sha256
from .posix import HOOK_ARTIFACTS, populated_gitlinks, run_git


def _run_git(argv: list[str], *, cwd: str | None, env: dict[str, str] | None, timeout: float,
             input: str | None = None) -> subprocess.CompletedProcess:
    """A `git` an adapter runs: COORDINATOR-side git over a worker's worktree (the shared
    `.git/config` and `info/attributes`, the same-uid `~/.gitconfig`), so it runs through
    posix.run_git's custody exactly as posix.py's own git does (W4-01): gitexec's absolute git and
    floor plus PROVIDER_FLOOR, a repository-selecting GIT_* in `env` dropped, `status` and
    `merge-tree --write-tree` run against a coordinator-built git dir whose config declares no
    driver (so a sibling cannot add one mid-call, PR #720 Codex round 3), and any other subcommand
    that could apply an attribute-selected driver (`reset --hard`, `checkout`, `diff`, `add`, ...)
    refused (GitCustodyRefused, an OSError), wherever it runs. A checkout an adapter needs goes
    through posix.checkout_worktree (`read-tree -u --reset` in that git dir), never through here. Output decoded byte-for-byte with os.fsdecode: a `\r`, `\r\n` or non-UTF-8 byte in a
    path comes back as the same path (text mode turned `\r` into `\n`)."""
    proc = run_git(argv[1:], cwd=cwd, env=env, timeout=timeout,
                   input=os.fsencode(input) if input is not None else None)
    return subprocess.CompletedProcess(argv, proc.returncode, os.fsdecode(proc.stdout), os.fsdecode(proc.stderr))

# Files `posix.install_worktree_hooks` writes into a worktree: dirt limited to these paths is
# ours, not the worker's, and never blocks a cleanup that has already preserved HEAD.
HOOK_ARTIFACT_PREFIXES = HOOK_ARTIFACTS

_SHA_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")

PLACEHOLDER_WORKTREES = frozenset({"", "new-child", "new-top-level", "current", "active"})


def real_worktree(path: Any) -> str | None:
    """Absolute path of an existing worktree directory, or None for placeholders/missing dirs."""
    if not isinstance(path, str) or path.strip() in PLACEHOLDER_WORKTREES:
        return None
    p = Path(path).expanduser()
    return str(p.resolve()) if p.is_dir() else None


def run_cli(argv: list[str], *, provider: str, timeout: float = 60, cwd: str | None = None) -> dict[str, Any]:
    """Run an upstream CLI; every failure mode is a ProviderError (never a silent success)."""
    try:
        if argv and argv[0] == "git":
            proc = _run_git(argv, cwd=cwd, env=None, timeout=timeout)
        else:
            proc = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=timeout, cwd=cwd)
    except FileNotFoundError as exc:
        raise ProviderError(f"{provider}_cli_missing", f"{argv[0]!r} not found on PATH", {"argv": argv}) from exc
    except subprocess.TimeoutExpired as exc:
        raise ProviderError(f"{provider}_timeout", f"{argv[0]} timed out after {timeout}s", {"argv": argv}) from exc
    except OSError as exc:
        raise ProviderError(f"{provider}_cli_error", f"{argv[0]} could not be launched: {exc}", {"argv": argv}) from exc
    if proc.returncode != 0:
        raise ProviderError(
            f"{provider}_cli_error",
            (proc.stderr or "").strip() or f"{argv[0]} exited with {proc.returncode}",
            {"argv": argv, "returncode": proc.returncode},
        )
    out = proc.stdout or ""
    return {"stdout": out, "stderr": proc.stderr or "", "returncode": proc.returncode, "raw": out.strip()}


def origin(url: str) -> tuple[str, str, int | None]:
    """(scheme, host, port) of `url`, the unit a redirect may not leave."""
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    return scheme, (parts.hostname or "").lower(), parts.port or {"https": 443, "http": 80}.get(scheme)


def credentialed_request(url: str, data: bytes | None, method: str, plain: dict[str, str],
                         secret: dict[str, str]) -> urllib.request.Request:
    """A Request whose `secret` headers are UNREDIRECTED: urllib copies an ordinary header onto the
    request a 3xx makes, to whatever host its Location names, and never an unredirected one
    (2026-10-27 audit, W5-08's class; runtime/scripts/upstream_probe.py does the same)."""
    req = urllib.request.Request(url, data=data, headers=plain, method=method)
    for key, value in secret.items():
        req.add_unredirected_header(key, value)
    return req


def http_json(
    base_url: str,
    method: str,
    path: str,
    body: Any = None,
    *,
    provider: str,
    timeout: float = 60,
    headers: dict[str, str] | None = None,
    raw_body: bytes | None = None,
    allow_empty: bool = False,
) -> Any:
    """One JSON HTTP exchange; HTTP errors keep their status, bad JSON is an error.

    Every caller header (an adapter's API key rides one) is unredirected, and an answer that ends
    at another origin than `base_url`'s is `<provider>_redirected`, never parsed."""
    url = f"{base_url.rstrip('/')}{path}"
    data = raw_body if raw_body is not None else (json.dumps(body).encode("utf-8") if body is not None else None)
    req = credentialed_request(url, data, method, {"Content-Type": "application/json", "Accept": "application/json"},
                               dict(headers or {}))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if origin(getattr(resp, "url", None) or url) != origin(url):  # where the redirects ended
                raise ProviderError(f"{provider}_redirected", f"{method} {path} was redirected to another origin",
                                    {"path": path})
            text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", errors="replace")
        except Exception:
            detail = ""
        parsed: Any = None
        try:
            parsed = json.loads(detail) if detail.strip() else None
        except json.JSONDecodeError:
            parsed = detail[:500]
        raise ProviderError(
            f"{provider}_http_error",
            f"{method} {path} -> HTTP {exc.code}",
            {"status": exc.code, "response": parsed, "path": path},
        ) from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise ProviderError(f"{provider}_unreachable", f"{method} {url}: {exc}", {"path": path}) from exc
    return parse_json_strict(text, provider, allow_empty=allow_empty)


# Set once a `worker_start` call has handed anything to its runtime (#707 review): from then on a
# worker may exist, so a failure keeps the request's claim. A ContextVar, so concurrent calls on
# one adapter each read their own.
_REACHED_RUNTIME: contextvars.ContextVar[bool] = contextvars.ContextVar("reached_runtime", default=False)
_LAUNCH_CLAIM_CTX: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "launch_claim_ctx", default=None
)


def claim_local_task(
    state: Any,
    task_id: str | None,
    run: str | None = None,
) -> tuple[bool, str | None]:
    """Transition a local task `ready -> dispatched`, enforcing Run ownership (#750 C28, C29)."""
    if state is not None and hasattr(state, "_resolve_caller_run"):
        run = state._resolve_caller_run(run, default_run=None)
    if state is None or not task_id or not hasattr(state, "_connect"):
        return False, run
    now = time.time()
    with state._connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT status, run_id FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            return False, run
        if run is not None and row["run_id"] != run:
            conn.execute("ROLLBACK")
            raise ProviderError(
                "cross_run_access",
                f"task {task_id!r} belongs to run {row['run_id']!r}, not {run!r}",
            )
        if row["status"] != "ready":
            conn.execute("ROLLBACK")
            raise ProviderError(
                "task_not_startable",
                f"task {task_id!r} has status {row['status']!r} (must be 'ready')",
                {"taskId": task_id, "status": row["status"]},
            )
        cur = conn.execute(
            "UPDATE tasks SET status = 'dispatched', updated_at = ? WHERE id = ? AND status = 'ready'",
            (now, task_id),
        )
        if cur.rowcount != 1:
            conn.execute("ROLLBACK")
            raise ProviderError("task_not_startable", f"task {task_id!r} is no longer 'ready'")
        conn.execute("COMMIT")
        return True, str(row["run_id"] or "default")


def release_local_task(state: Any, task_id: str | None) -> None:
    """Restore a claimed local task to `ready` when upstream launch fails before recording (#750 C29)."""
    if state is None or not task_id or not hasattr(state, "_connect"):
        return
    with state._connect() as conn:
        conn.execute(
            "UPDATE tasks SET status = 'ready', updated_at = ? WHERE id = ? AND status = 'dispatched'",
            (time.time(), task_id),
        )


def _ensure_ctx_task_claimed() -> None:
    ctx = _LAUNCH_CLAIM_CTX.get()
    if ctx is not None and not ctx.get("checked"):
        ctx["checked"] = True
        claimed, eff_run = claim_local_task(ctx.get("state"), ctx.get("task_id"), ctx.get("run"))
        ctx["claimed"] = claimed
        ctx["effective_run"] = eff_run


def _marking_runtime_contact(runner):
    """`runner` that claims the local task and records the runtime was reached."""

    @functools.wraps(runner)
    def marked(*args, **kwargs):
        _ensure_ctx_task_claimed()
        ctx = _LAUNCH_CLAIM_CTX.get()
        before = _REACHED_RUNTIME.get()
        if not before and ctx is not None:
            st = ctx.get("state")
            req_id = ctx.get("retry_request")
            if req_id and st is not None and hasattr(st, "mark_request_contacted"):
                st.mark_request_contacted(
                    req_id,
                    contacted=True,
                    task_id=ctx.get("task_id") if ctx.get("claimed") else None,
                )
        _REACHED_RUNTIME.set(True)
        try:
            return runner(*args, **kwargs)
        except FileNotFoundError:
            _REACHED_RUNTIME.set(before)
            if not before and ctx is not None:
                st = ctx.get("state")
                req_id = ctx.get("retry_request")
                if req_id and st is not None and hasattr(st, "mark_request_contacted"):
                    st.mark_request_contacted(req_id, contacted=False)
            raise
        except ProviderError as exc:
            if exc.code.endswith(("_not_configured", "_cli_missing")):
                _REACHED_RUNTIME.set(before)
                if not before and ctx is not None:
                    st = ctx.get("state")
                    req_id = ctx.get("retry_request")
                    if req_id and st is not None and hasattr(st, "mark_request_contacted"):
                        st.mark_request_contacted(req_id, contacted=False)
            raise

    marked._marks_runtime_contact = True
    return marked


def ensure_runner_marks_contact(provider: Any) -> contextvars.Token[bool]:
    """Ensure `provider._runner` records runtime contact and return a fresh `_REACHED_RUNTIME` token."""
    runner = getattr(provider, "_runner", None)
    if callable(runner) and getattr(runner, "_marks_runtime_contact", False) is not True:
        provider._runner = _marking_runtime_contact(runner)
    return _REACHED_RUNTIME.set(not callable(runner))


def runtime_was_reached() -> bool:
    """Whether the current call has handed anything to its upstream runtime."""
    return bool(_REACHED_RUNTIME.get())


def release_claim_on_failure(worker_start):
    """Decorator for an adapter's `worker_start`: a `--retry-request` claim this call took is
    released when the call fails BEFORE it reached the runtime, so a retry acts instead of reading
    the pending marker for PENDING_STALE_S (PR #707 review: a refusal before any launch left a
    long-running coordinator locked out of the id for ten minutes). Every adapter reaches its
    runtime through `self._runner`; once that is called a worker may have started (`ov sling` ran
    and its reply was lost or malformed), so the claim stays until the launch is checked or
    stopped, and a retry gets the pending marker, never a second worker (#707 review). Only this
    process's own pending claim is released; a completed row, or another caller's claim, never is."""

    @functools.wraps(worker_start)
    def wrapper(self, *args, **kwargs):
        retry_request = kwargs.get("retry_request")
        try:
            bound = inspect.signature(worker_start).bind_partial(self, *args, **kwargs)
            bound.apply_defaults()
            payload_args = {
                k: v for k, v in bound.arguments.items() if k not in ("self", "retry_request", "kwargs")
            }
            if "kwargs" in bound.arguments and isinstance(bound.arguments["kwargs"], dict):
                payload_args.update(bound.arguments["kwargs"])
        except (TypeError, ValueError):
            payload_args = {k: v for k, v in kwargs.items() if k != "retry_request"}
        payload_sha = request_payload_sha256(payload_args)
        state_obj = getattr(self, "state", None)
        resolved_run = payload_args.get("run")
        if state_obj is not None and hasattr(state_obj, "_resolve_caller_run"):
            resolved_run = state_obj._resolve_caller_run(resolved_run, default_run=None)
            tid = payload_args.get("task_id")
            if tid and hasattr(state_obj, "_connect"):
                with state_obj._connect() as conn:
                    t_row = conn.execute("SELECT run_id FROM tasks WHERE id = ?", (tid,)).fetchone()
                if t_row is not None and resolved_run is not None and t_row["run_id"] != resolved_run:
                    raise ProviderError(
                        "cross_run_access",
                        f"task {tid!r} belongs to run {t_row['run_id']!r}, not {resolved_run!r}",
                    )
        runner = getattr(self, "_runner", None)
        if callable(runner) and getattr(runner, "_marks_runtime_contact", False) is not True:
            self._runner = _marking_runtime_contact(runner)
        # An adapter with no `_runner` cannot say whether it launched: its claim is kept.
        token = _REACHED_RUNTIME.set(not callable(runner))
        sha_token = ACTIVE_REQUEST_PAYLOAD_SHA.set(payload_sha)
        claim_ctx = {
            "state": state_obj,
            "task_id": payload_args.get("task_id"),
            "run": resolved_run,
            "retry_request": retry_request,
            "checked": False,
            "claimed": False,
            "effective_run": resolved_run,
            "recorded": False,
        }
        ctx_token = _LAUNCH_CLAIM_CTX.set(claim_ctx)
        try:
            return worker_start(self, *args, **kwargs)
        except BaseException:
            if claim_ctx.get("claimed") and not claim_ctx.get("recorded") and not _REACHED_RUNTIME.get():
                release_local_task(claim_ctx.get("state"), claim_ctx.get("task_id"))
            if retry_request and state_obj is not None:
                row = state_obj.request_row(retry_request)
                if row and row.get("state") == "pending" and not row.get("response_json"):
                    if not _REACHED_RUNTIME.get():
                        if int(row.get("claim_pid") or 0) == os.getpid():
                            state_obj.release_request(retry_request)
                    elif hasattr(state_obj, "mark_request_contacted") and (
                        int(row.get("contacted_runtime") or 0) != 0
                        or int(row.get("claim_pid") or 0) == os.getpid()
                    ):
                        state_obj.mark_request_contacted(
                            retry_request,
                            contacted=True,
                            task_id=claim_ctx.get("task_id") if claim_ctx.get("claimed") else None,
                            settled_ambiguous=True,
                        )
            raise
        finally:
            _LAUNCH_CLAIM_CTX.reset(ctx_token)
            ACTIVE_REQUEST_PAYLOAD_SHA.reset(sha_token)
            _REACHED_RUNTIME.reset(token)

    return wrapper


class ExternalDispatchMixin:
    """Local dispatch bookkeeping shared by the external adapters (expects `self.state`, `self.name`)."""

    name: str
    state: Any

    def _dispatch_row(self, dispatch_id: str) -> Any:
        if not dispatch_id:
            raise ProviderError("dispatch_not_found", "no --dispatch id given")
        bound = (
            self.state._resolve_caller_run(None, default_run=None)
            if hasattr(self.state, "_resolve_caller_run")
            else None
        )
        with self.state._connect() as conn:
            row = conn.execute(
                "SELECT * FROM dispatches WHERE dispatch_id = ? AND backend = ?",
                (dispatch_id, self.name),
            ).fetchone()
        if not row:
            raise ProviderError("dispatch_not_found", f"{self.name}: dispatch {dispatch_id!r} not found")
        row_run = str(row["run_id"] or "default")
        if bound and row_run != bound:
            raise ProviderError(
                "cross_run_access",
                f"dispatch {dispatch_id!r} belongs to run {row_run!r}, not {bound!r}",
            )
        return row

    @staticmethod
    def _effective(row: Any) -> dict[str, Any]:
        try:
            eff = json.loads(row["launch_effective"] or "{}")
        except (json.JSONDecodeError, TypeError):
            eff = {}
        return eff if isinstance(eff, dict) else {}

    def _record_dispatch(
        self,
        *,
        dispatch_id: str,
        task_id: str,
        run: str | None,
        worktree: str,
        agent: str,
        profile: str,
        handle: str,
        effective: dict[str, Any],
        session_id: str | None = None,
    ) -> None:
        insert_dispatch(
            self.state,
            dispatch_id=dispatch_id,
            task_id=task_id,
            run=run,
            worktree=worktree,
            agent=agent,
            profile=profile,
            handle=handle,
            backend=self.name,
            effective=effective,
            session_id=session_id or dispatch_id,
        )

    def _patch_dispatch(self, dispatch_id: str, *, worktree: str | None = None, effective: dict[str, Any] | None = None) -> None:
        row = self._dispatch_row(dispatch_id)
        eff = self._effective(row)
        if effective:
            eff.update(effective)
        with self.state._connect() as conn:
            conn.execute(
                "UPDATE dispatches SET worktree = ?, launch_effective = ?, updated_at = ? WHERE dispatch_id = ?",
                (worktree if worktree is not None else row["worktree"], json.dumps(eff), time.time(), dispatch_id),
            )

    def _fence_local(self, dispatch_id: str, verb: str) -> tuple[str, str]:
        new_state, term_state = fence_state(verb)
        with self.state._connect() as conn:
            conn.execute(
                "UPDATE dispatches SET state = ?, terminal_state = ?, updated_at = ? WHERE dispatch_id = ?",
                (new_state, term_state, time.time(), dispatch_id),
            )
        return new_state, term_state

    def _show_row(self, row: Any, *, state: str | None = None, raw: Any = None, worktree: str | None = None) -> dict[str, Any]:
        return normalize_show(
            row["dispatch_id"],
            state or row["state"],
            task_id=row["task_id"],
            terminal_state=row["terminal_state"],
            handle=row["terminal_handle"],
            worktree=worktree if worktree is not None else row["worktree"],
            raw=raw,
        )

    def _list_local(
        self,
        *,
        run: str | None = None,
        task: str | None = None,
        terminal_state: str | None = None,
        include_remote: bool = False,
        limit: int | None = None,
        cursor: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return local_worker_list(
            self.state,
            self.name,
            run=run,
            task=task,
            terminal_state=terminal_state,
            include_remote=include_remote,
            limit=limit,
            cursor=cursor,
        )


def env_flag(value: str | None) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def env_lookup(env: dict[str, str] | None, *names: str, default: str = "") -> str:
    source = os.environ if env is None else env
    for n in names:
        v = (source.get(n) or "").strip()
        if v:
            return v
    return default


# --------------------------------------------------------------------------------------
# CLI-text adapters (gastown / overstory / superset / t3code / worktrunk)
# --------------------------------------------------------------------------------------
def run_cli_text(
    argv: list[str],
    provider: str,
    *,
    timeout: int = 60,
    env: dict[str, str] | None = None,
    input: str | None = None,  # same name as subprocess.run's keyword
) -> str:
    """Run an upstream CLI; any launch failure, timeout, or non-zero exit is a ProviderError."""
    try:
        if argv and argv[0] == "git":
            proc = _run_git(argv, cwd=None, env=env, timeout=timeout, input=input)
        else:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
                env=env,
                **({"input": input} if input is not None else {}),
            )
    except FileNotFoundError as exc:
        raise ProviderError(f"{provider}_cli_missing", f"{argv[0]!r} is not installed or not on PATH", {"argv": argv}) from exc
    except subprocess.TimeoutExpired as exc:
        raise ProviderError(f"{provider}_cli_timeout", f"{argv[0]} did not finish within {timeout}s", {"argv": argv}) from exc
    except OSError as exc:
        raise ProviderError(f"{provider}_cli_error", f"{argv[0]} could not be launched: {exc}", {"argv": argv}) from exc
    if proc.returncode != 0:
        raise ProviderError(
            f"{provider}_cli_error",
            (proc.stderr or "").strip() or (proc.stdout or "").strip()[:500] or f"{argv[0]} exited with {proc.returncode}",
            {"argv": argv, "returncode": proc.returncode},
        )
    return proc.stdout or ""


def coerce_output(res: Any) -> str:
    """Injected runners may return text, or a dict/list standing in for JSON stdout."""
    if res is None:
        return ""
    if isinstance(res, (dict, list)):
        return json.dumps(res)
    return str(res)


def call_runner(runner: Callable[..., Any], argv: list[str], provider: str, **kwargs: Any) -> str:
    """Invoke `runner` and wrap raw launch errors (FileNotFoundError/TimeoutExpired) as ProviderError."""
    try:
        return coerce_output(runner(list(argv), **kwargs))
    except ProviderError:
        raise
    except FileNotFoundError as exc:
        raise ProviderError(f"{provider}_cli_missing", f"{argv[0]!r} is not installed or not on PATH", {"argv": argv}) from exc
    except subprocess.TimeoutExpired as exc:
        raise ProviderError(f"{provider}_cli_timeout", f"{argv[0]} timed out", {"argv": argv}) from exc
    except OSError as exc:
        raise ProviderError(f"{provider}_cli_error", f"{argv[0]} could not be launched: {exc}", {"argv": argv}) from exc


def ref_safe(text: str) -> str:
    """Reduce `text` to characters that are always legal inside one git ref component."""
    cleaned = re.sub(r"[^A-Za-z0-9._/-]", "-", text).strip("/.")
    cleaned = re.sub(r"\.\.+", ".", cleaned)
    cleaned = re.sub(r"/+", "/", cleaned)
    return cleaned or "dispatch"


def preserve_worker_head(run: Callable[[list[str]], str], worktree: str, dispatch_id: str) -> dict[str, str]:
    """Pin the worker's ACTUAL HEAD (read in its own worktree) under refs/open-fleet/preserved/.

    Raises `preserve_failed` unless the ref verifiably equals that HEAD and lives in a git
    directory that survives removal of the worktree (a linked worktree's common dir).
    """
    if not worktree or not os.path.isabs(worktree):
        raise ProviderError("preserve_failed", f"worker worktree {worktree!r} is unknown; refusing destructive cleanup")
    head = run(["git", "-C", worktree, "rev-parse", "--verify", "HEAD"]).strip()
    if not _SHA_RE.match(head):
        raise ProviderError("preserve_failed", f"could not resolve HEAD in {worktree!r}: {head[:80]!r}")
    ref = f"refs/open-fleet/preserved/{ref_safe(dispatch_id)}"
    run(["git", "-C", worktree, "update-ref", ref, head])
    pinned = run(["git", "-C", worktree, "rev-parse", "--verify", ref]).strip()
    if pinned != head:
        raise ProviderError("preserve_failed", f"{ref} resolves to {pinned!r}, not the worker HEAD {head}")
    common = run(["git", "-C", worktree, "rev-parse", "--path-format=absolute", "--git-common-dir"]).strip()
    wt_real = os.path.realpath(worktree)
    common_real = os.path.realpath(common) if common else ""
    if not common_real or common_real == wt_real or common_real.startswith(wt_real.rstrip("/") + "/"):
        raise ProviderError(
            "preserve_failed",
            f"git dir {common!r} lives inside the worktree being removed; {ref} would not survive cleanup",
        )
    return {"ref": ref, "sha": head, "commonDir": common}


def _artifact_match(path: str, entry: str) -> bool:
    """`entry` ending in "/" covers that directory's contents; otherwise an EXACT file match.

    A prefix test let `AGENTS.md` hide `AGENTS.md.backup` and `.claude/` hide a user's own
    commands, so an unforced removal discarded them (#592 review).
    """
    if entry.endswith("/"):
        return path == entry.rstrip("/") or path.startswith(entry)
    return path == entry


def foreign_dirty_paths(
    run: Callable[[list[str]], str],
    worktree: str,
    extra_ignored: tuple[str, ...] = (),
) -> list[str]:
    """Uncommitted paths in `worktree` that are NOT open-fleet hook artifacts (work a removal would lose).

    `-z`: every path raw, NUL-terminated, a rename's source in the field after its destination.
    The line form C-quoted a path holding a newline and printed `x -> AGENTS.md` unquoted, which
    the ` -> ` split read as the artifact `AGENTS.md`, so a user's unsaved file counted as clean
    (PR #720 Codex round 2).

    A checked-out submodule always counts (posix.populated_gitlinks): the custody's `status` never
    looks inside one, because git inspects it with a child git that drops the env floor and reads
    the submodule's own config, whose clean filter ran as the coordinator (PR #720 Codex round 3)."""
    out = run(["git", "-C", worktree, "status", "--porcelain", "-z", "--untracked-files=all"])
    staged = run(["git", "-C", worktree, "ls-files", "-s", "-z"])
    ignored = HOOK_ARTIFACT_PREFIXES + tuple(extra_ignored)
    dirty: list[str] = []
    fields = out.split("\0")
    i = 0
    while i < len(fields):
        entry = fields[i]
        i += 1
        if len(entry) < 4:
            continue
        status, path = entry[:2], entry[3:]
        if "R" in status or "C" in status:
            i += 1  # the rename/copy source: the destination is what a removal would lose
        if not any(_artifact_match(path, p) for p in ignored):
            dirty.append(path)
    for path in populated_gitlinks(staged, worktree):
        if path not in dirty and not any(_artifact_match(path, p) for p in ignored):
            dirty.append(path)
    return dirty


def insert_dispatch(
    state: LocalStateStore,
    *,
    dispatch_id: str,
    task_id: str,
    run: str | None,
    worktree: str | None,
    agent: str,
    profile: str,
    handle: str,
    backend: str,
    effective: dict[str, Any],
    session_id: str | None = None,
) -> None:
    _ensure_ctx_task_claimed()
    ctx = _LAUNCH_CLAIM_CTX.get()
    effective_run = (
        state._resolve_caller_run(run, default_run=None)
        if hasattr(state, "_resolve_caller_run")
        else run
    )
    if ctx is not None:
        ctx["recorded"] = True
        if effective_run is None and ctx.get("effective_run"):
            effective_run = ctx["effective_run"]
    now = time.time()
    with state._connect() as conn:
        if effective_run is None and task_id:
            t_row = conn.execute("SELECT run_id FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if t_row and t_row["run_id"]:
                effective_run = str(t_row["run_id"])
        conn.execute(
            """
            INSERT OR REPLACE INTO dispatches(
                dispatch_id, task_id, run_id, worktree, agent, profile, terminal_handle, state,
                terminal_state, backend, launch_effective, session_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', 'active', ?, ?, ?, ?, ?)
            """,
            (
                dispatch_id,
                task_id or "",
                effective_run or "default",
                worktree or "",
                agent,
                profile,
                handle,
                backend,
                json.dumps(effective),
                session_id,
                now,
                now,
            ),
        )


def resolve_worker_list_run(
    state: LocalStateStore,
    run: str | None,
    *,
    include_remote: bool = False,
) -> str | None:
    eff_run = state._resolve_caller_run(run, default_run=None) if hasattr(state, "_resolve_caller_run") else run
    if include_remote and hasattr(state, "_worker_bound_run") and state._worker_bound_run():
        raise ProviderError("cross_run_access", "launched worker cannot list unfiltered remote workers across runs")
    return eff_run


def load_dispatch(state: LocalStateStore, dispatch_id: str, backend: str) -> dict[str, Any]:
    """The locally recorded dispatch for `backend`, with `launch_effective` decoded."""
    if not dispatch_id:
        raise ProviderError("dispatch_not_found", "no dispatch id given")
    bound = state._resolve_caller_run(None, default_run=None) if hasattr(state, "_resolve_caller_run") else None
    with state._connect() as conn:
        row = conn.execute(
            "SELECT * FROM dispatches WHERE dispatch_id = ? AND backend = ?",
            (dispatch_id, backend),
        ).fetchone()
    if not row:
        raise ProviderError("dispatch_not_found", f"{backend}: dispatch {dispatch_id!r} not found")
    rec = dict(row)
    row_run = str(rec.get("run_id") or "default")
    if bound and row_run != bound:
        raise ProviderError(
            "cross_run_access",
            f"dispatch {dispatch_id!r} belongs to run {row_run!r}, not {bound!r}",
        )
    try:
        rec["effective"] = json.loads(rec.get("launch_effective") or "{}")
    except json.JSONDecodeError:
        rec["effective"] = {}
    return rec


def record_fence(state: LocalStateStore, dispatch_id: str, verb: str) -> tuple[str, str]:
    """Store the posix fence state names (`stopped|abandoned|released|retained`)."""
    new_state, term_state = fence_state(verb)
    with state._connect() as conn:
        conn.execute(
            "UPDATE dispatches SET state = ?, terminal_state = ?, updated_at = ? WHERE dispatch_id = ?",
            (new_state, term_state, time.time(), dispatch_id),
        )
    return new_state, term_state


def show_from_row(row: dict[str, Any], *, stage: str | None = None, raw: Any = None, worktree: str | None = None) -> dict[str, Any]:
    return normalize_show(
        row["dispatch_id"],
        row["state"],
        task_id=row.get("task_id") or None,
        terminal_state=row.get("terminal_state"),
        handle=row.get("terminal_handle"),
        worktree=worktree if worktree is not None else (row.get("worktree") or None),
        stage=stage,
        raw=raw,
    )


def _filter_upstream_records(upstream: Any, page_rows: list[dict[str, Any]]) -> Any:
    """Filter raw upstream records to the dispatches returned in `page_rows` (#750 C37)."""
    if upstream is None:
        return None
    page_ids = {str(r.get("dispatch_id") or "") for r in page_rows if r.get("dispatch_id")}
    session_ids = {str(r.get("session_id") or "") for r in page_rows if r.get("session_id")}
    addresses: set[tuple[str, str]] = set()
    workspace_ids: set[str] = set()
    thread_ids: set[str] = set()
    for r in page_rows:
        try:
            eff = json.loads(r.get("launch_effective") or "{}")
        except (json.JSONDecodeError, TypeError):
            eff = {}
        if isinstance(eff, dict):
            if eff.get("address"):
                addresses.add((str(eff.get("address")), str(eff.get("beadId") or "")))
            if eff.get("workspaceId"):
                workspace_ids.add(str(eff.get("workspaceId")))
            if eff.get("threadId"):
                thread_ids.add(str(eff.get("threadId")))
    if isinstance(upstream, list):
        return [
            p
            for p in upstream
            if isinstance(p, dict)
            and (
                (f"{p.get('rig')}/{p.get('name')}", str(p.get("issue") or "")) in addresses
                or str(p.get("id") or "") in page_ids
                or str(p.get("name") or "") in page_ids
            )
        ]
    if isinstance(upstream, dict):
        out = dict(upstream)
        if isinstance(out.get("items"), list):
            out["items"] = [
                it for it in out["items"] if isinstance(it, dict) and str(it.get("id") or "") in page_ids
            ]
        if isinstance(out.get("agents"), list):
            out["agents"] = [
                a for a in out["agents"] if isinstance(a, dict) and str(a.get("agentName") or "") in page_ids
            ]
        if isinstance(out.get("threads"), list):
            valid_threads = page_ids | session_ids | thread_ids
            out["threads"] = [
                t for t in out["threads"] if isinstance(t, dict) and str(t.get("threadId") or "") in valid_threads
            ]
        if isinstance(out.get("workspaces"), list):
            filtered_ws = []
            for ws in out["workspaces"]:
                if not isinstance(ws, dict):
                    continue
                ws_id = str(ws.get("id") or "")
                terms = [
                    t
                    for t in (ws.get("terminals") or [])
                    if isinstance(t, dict) and str(t.get("id") or "") in session_ids
                ]
                if ws_id in workspace_ids or terms:
                    ws_copy = dict(ws)
                    if "terminals" in ws_copy:
                        ws_copy["terminals"] = terms
                    filtered_ws.append(ws_copy)
            out["workspaces"] = filtered_ws
        return out
    return upstream


def local_worker_list(
    state: LocalStateStore,
    backend: str,
    *,
    run: str | None = None,
    task: str | None = None,
    terminal_state: str | None = None,
    include_remote: bool = False,
    limit: int | None = None,
    cursor: str | None = None,
    stages: dict[str, str] | None = None,
    upstream: Any = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """A worker-list receipt built from OUR dispatch rows (the shape `worker_ops.format_list` reads).

    Upstream listings name workers open-fleet never dispatched (and reused slots); they may only
    annotate a row's `stage` (keyed by dispatch id), never become rows themselves.
    """
    run = resolve_worker_list_run(state, run, include_remote=bool(include_remote))
    q = "SELECT * FROM dispatches WHERE backend = ?"
    params: list[Any] = [backend]
    if run:
        q += " AND run_id = ?"
        params.append(run)
    if task:
        q += " AND task_id = ?"
        params.append(task)
    if terminal_state:
        q += " AND terminal_state = ?"
        params.append(terminal_state)
    q += " ORDER BY created_at ASC, dispatch_id ASC"
    with state._connect() as conn:
        rows = [dict(r) for r in conn.execute(q, params).fetchall()]
    start_idx = 0
    if cursor is not None and str(cursor) != "":
        s_cur = str(cursor)
        if s_cur.isascii() and s_cur.isdigit():
            start_idx = int(s_cur)
        else:
            for idx, r in enumerate(rows):
                if r.get("dispatch_id") == s_cur:
                    start_idx = idx + 1
                    break
    total = len(rows)
    if limit is not None and int(limit) > 0:
        lim = int(limit)
        page_rows = rows[start_idx : start_idx + lim]
        next_cursor = str(start_idx + lim) if (start_idx + lim) < total else None
    else:
        page_rows = rows[start_idx:]
        next_cursor = None
    stages = stages or {}
    workers = [show_from_row(r, stage=stages.get(str(r["dispatch_id"])))["worker"] for r in page_rows]
    out: dict[str, Any] = {"workers": workers, "scope": {"source": backend}, "page": {"nextCursor": next_cursor}}
    if upstream is not None:
        out["upstream"] = upstream if include_remote else _filter_upstream_records(upstream, page_rows)
    return out
