#!/usr/bin/env python3
"""posix.py — Zero-Daemon Native POSIX Worktree RuntimeProvider (`OPEN_FLEET_RUNTIME=posix`).

Runs `open-fleet` missions standalone on any Linux/macOS host or CI container without requiring
an external orchestrator daemon (`stablyai/orca`), combining:
  - `LocalStateStore` (SQLite WAL Run, Task DAG, Typed Mailbox, HITL Gates, File-Touch Conflicts)
  - `git worktree` / `wtree.sh` worktree isolation
  - `tmux`, `cmux` (`manaflow-ai/cmux` with `kqueue` `cmux wait-for`), or detached `setsid`
    process groups
  - Verified 9-harness launch table (`claude`, `codex`, `opencode`, `omp`, `pi`, `jcode`, `goose`,
    `hermes`, `crush`) across `PROFILE=ro|rw|danger`
  - Automatic per-worktree `PreToolUse` hook installation (`deny-hook.sh`)
  - Overstory-style synthetic `worker_died` guarantee on process exit without terminal mail (#590).
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import signal
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
    env_get,
)
from .local_state import LocalStateStore

OMP_PI_BRIDGE_TS = """// Auto-generated open-fleet PreToolUse bridge for oh-my-pi (omp) and pi-mono (pi)
import { spawnSync } from "node:child_process";

export default function registerOpenFleetDenyBridge(pi: any) {
  const hookPath = process.env.OPEN_FLEET_DENY_HOOK || process.env.ORCA_DENY_HOOK_PATH || "";
  pi.on("tool_call", async (event: any) => {
    if (!hookPath) {
      return { block: true, reason: "OPEN_FLEET_DENY_HOOK is not configured (fail-closed)" };
    }
    const payload = JSON.stringify({
      tool_name: event.toolName || event.name || "unknown",
      tool_input: event.input || event.args || {},
    });
    const res = spawnSync("sh", [hookPath], {
      input: payload,
      encoding: "utf-8",
      env: process.env,
    });
    if (res.status !== 0) {
      return { block: true, reason: (res.stderr || res.stdout || "blocked by deny-hook.sh").trim() };
    }
    const rawOut = (res.stdout || "").trim();
    if (!rawOut) return undefined;
    try {
      const parsed = JSON.parse(rawOut);
      const decision = parsed.decision || parsed.hookSpecificOutput?.permissionDecision;
      if (decision === "deny" || decision === "block" || decision === "ask") {
        const reason = parsed.reason || parsed.hookSpecificOutput?.permissionDecisionReason || "blocked by deny-hook.sh";
        return { block: true, reason };
      }
    } catch (err: any) {
      return { block: true, reason: String(err?.message || err || "invalid deny-hook JSON") };
    }
    return undefined;
  });
}
"""

OPENCODE_PLUGIN_TS = """// Auto-generated open-fleet PreToolUse plugin for anomalyco/opencode
import { spawnSync } from "node:child_process";

export const OpenFleetDenyPlugin = async (ctx: any) => {
  const hookPath = process.env.OPEN_FLEET_DENY_HOOK || process.env.ORCA_DENY_HOOK_PATH || "";
  if (!ctx?.tool?.hook) return;
  ctx.tool.hook("execute.before", async (call: any) => {
    if (!hookPath) {
      throw new Error("OPEN_FLEET_DENY_HOOK is not configured (fail-closed)");
    }
    const payload = JSON.stringify({
      tool_name: call.name || call.tool || "unknown",
      tool_input: call.args || call.input || {},
    });
    const res = spawnSync("sh", [hookPath], {
      input: payload,
      encoding: "utf-8",
      env: process.env,
    });
    if (res.status !== 0) {
      throw new Error((res.stderr || res.stdout || "blocked by deny-hook.sh").trim());
    }
    try {
      const parsed = JSON.parse(res.stdout || "{}");
      const decision = parsed.decision || parsed.hookSpecificOutput?.permissionDecision;
      if (decision === "deny" || decision === "block" || decision === "ask") {
        throw new Error(parsed.reason || parsed.hookSpecificOutput?.permissionDecisionReason || "blocked by deny-hook.sh");
      }
    } catch (err: any) {
      if (err instanceof Error && err.message) throw err;
    }
  });
};
export default OpenFleetDenyPlugin;
"""

CRUSH_RO_DISABLED_TOOLS = [
    "bash",
    "write",
    "edit",
    "multiedit",
    "download",
    "lsp_rename",
    "lsp_replace_symbol",
    "agent",
    "agentic_fetch",
    "job_kill",
    "job_output",
]


def install_worktree_hooks(
    worktree_path: str | Path,
    agent: str,
    profile: str,
    *,
    deny_hook_path: str | None = None,
) -> dict[str, str]:
    """Install per-worktree `PreToolUse` hook configs and bridges for all supported harnesses."""
    wt = Path(worktree_path).resolve()
    wt.mkdir(parents=True, exist_ok=True)
    root_dir = Path(__file__).resolve().parent.parent
    hook = deny_hook_path or str(root_dir / "scripts" / "deny-hook.sh")
    cmd_str = f'OPEN_FLEET_UNIT_WORKTREE="{wt}" ORCA_UNIT_WORKTREE="{wt}" sh "{hook}"'
    installed: dict[str, str] = {}

    # 1. Claude Code (.claude/settings.local.json)
    claude_dir = wt / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    claude_settings = claude_dir / "settings.local.json"
    claude_doc = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit",
                    "hooks": [{"type": "command", "command": cmd_str}],
                }
            ]
        }
    }
    claude_settings.write_text(json.dumps(claude_doc, indent=2) + "\n", encoding="utf-8")
    installed["claude"] = str(claude_settings)

    # 2. OpenAI Codex (.codex/hooks.json)
    codex_dir = wt / ".codex"
    codex_dir.mkdir(parents=True, exist_ok=True)
    codex_hooks = codex_dir / "hooks.json"
    codex_doc = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": ".*",
                    "hooks": [{"type": "command", "command": cmd_str}],
                }
            ]
        }
    }
    codex_hooks.write_text(json.dumps(codex_doc, indent=2) + "\n", encoding="utf-8")
    installed["codex"] = str(codex_hooks)

    # 3. OpenHands (.openhands/hooks.json)
    oh_dir = wt / ".openhands"
    oh_dir.mkdir(parents=True, exist_ok=True)
    oh_hooks = oh_dir / "hooks.json"
    oh_hooks.write_text(json.dumps(codex_doc, indent=2) + "\n", encoding="utf-8")
    installed["openhands"] = str(oh_hooks)

    # 4. AAIF Goose (.agents/plugins/orca-deny-hook/hooks/hooks.json)
    goose_dir = wt / ".agents" / "plugins" / "orca-deny-hook" / "hooks"
    goose_dir.mkdir(parents=True, exist_ok=True)
    goose_hooks = goose_dir / "hooks.json"
    goose_doc = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": ".*",
                    "hooks": [{"type": "command", "command": cmd_str, "on_failure": "block"}],
                }
            ]
        }
    }
    goose_hooks.write_text(json.dumps(goose_doc, indent=2) + "\n", encoding="utf-8")
    installed["goose"] = str(goose_hooks)

    # 5. OpenCode (.opencode/plugin/orca-deny-hook.ts)
    oc_dir = wt / ".opencode" / "plugin"
    oc_dir.mkdir(parents=True, exist_ok=True)
    oc_plugin = oc_dir / "orca-deny-hook.ts"
    oc_plugin.write_text(OPENCODE_PLUGIN_TS, encoding="utf-8")
    installed["opencode"] = str(oc_plugin)

    # 6. Oh-My-Pi (omp) & Pi-Mono (pi) (.open-fleet/bridges/omp_pi_deny_bridge.ts)
    bridge_dir = wt / ".open-fleet" / "bridges"
    bridge_dir.mkdir(parents=True, exist_ok=True)
    bridge_ts = bridge_dir / "omp_pi_deny_bridge.ts"
    bridge_ts.write_text(OMP_PI_BRIDGE_TS, encoding="utf-8")
    installed["omp"] = str(bridge_ts)
    installed["pi"] = str(bridge_ts)

    # 7. Charmbracelet Crush (<data-dir>/crush.json)
    crush_ro_dir = wt / ".crush-orca-ro"
    crush_ro_dir.mkdir(parents=True, exist_ok=True)
    (crush_ro_dir / "crush.json").write_text(
        json.dumps({"options": {"disabled_tools": CRUSH_RO_DISABLED_TOOLS}}, indent=2) + "\n",
        encoding="utf-8",
    )
    crush_rw_dir = wt / ".crush"
    crush_rw_dir.mkdir(parents=True, exist_ok=True)
    (crush_rw_dir / "crush.json").write_text(
        json.dumps(codex_doc, indent=2) + "\n",
        encoding="utf-8",
    )
    installed["crush"] = str((crush_ro_dir if profile == "ro" else crush_rw_dir) / "crush.json")

    return installed


class PosixWorktreeProvider(RuntimeProvider):
    """Zero-daemon POSIX worktree provider supporting `tmux`, `cmux`, and `setsid` backends."""

    name = "posix"

    def __init__(
        self,
        *,
        state: LocalStateStore | None = None,
        repo_root: str | Path | None = None,
        backend: str | None = None,
        runner: Callable[..., Any] | None = None,
        env: dict[str, str] | None = None,
    ):
        self.env = dict(os.environ if env is None else env)
        self.state = state or LocalStateStore(env=self.env)
        self.repo_root = Path(
            repo_root
            or self.env.get("OPEN_FLEET_REPO_ROOT")
            or env_get("OPEN_FLEET_CLI_CWD", "ORCA_CLI_CWD", self.env, os.getcwd())
        ).resolve()
        self.runner = runner
        self.backend = self._resolve_backend(backend)

    def _resolve_backend(self, requested: str | None = None) -> str:
        req = (
            requested
            or self.env.get("OPEN_FLEET_POSIX_BACKEND")
            or self.env.get("OPEN_FLEET_POSIX_MUX")
            or self.env.get("ORCA_POSIX_BACKEND")
            or self.env.get("ORCA_POSIX_MUX")
            or "auto"
        ).lower()
        if req in ("tmux", "cmux", "setsid", "dry-run"):
            return req
        if self.env.get("CMUX_SOCKET_PATH") and shutil.which("cmux"):
            return "cmux"
        if shutil.which("tmux"):
            return "tmux"
        return "setsid"

    def capabilities(self) -> set[str]:
        return {
            "cap:core-orchestration",
            "cap:sandbox-vm",
            "cap:session-search",
            "cap:browser",
            "cap:mobile-emulator",
            "cap:issue-tracker",
            "cap:scheduler",
        }

    # --- Task DAG & Mailbox delegate directly to LocalStateStore ---
    def task_create(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_create(**kwargs)

    def task_update(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_update(**kwargs)

    def task_list(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_list(**kwargs)

    def request_show(self, request_id: str) -> dict[str, Any]:
        return self.state.request_show(request_id)

    def send_message(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.send_message(**kwargs)

    def check_messages(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.check_messages(**kwargs)

    def reply_message(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.reply_message(**kwargs)

    def ask_human(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.ask_human(**kwargs)

    # --- Worktree Isolation ---
    def _worktree_base_dir(self) -> Path:
        base = self.state.db_path.parent / "worktrees"
        base.mkdir(parents=True, exist_ok=True)
        return base

    def worktree_create(self, name: str, base: str | None = None, repo: str | None = None) -> dict[str, Any]:
        root = Path(repo).resolve() if repo else self.repo_root
        slug = "".join(c if c.isalnum() or c in "._-" else "-" for c in name).strip("-") or f"wt-{uuid.uuid4().hex[:6]}"
        wt_path = self._worktree_base_dir() / slug
        branch = f"fleet/{slug}"
        if not wt_path.exists():
            git_dir = root / ".git"
            if git_dir.exists():
                subprocess.run(
                    ["git", "-C", str(root), "worktree", "prune"],
                    capture_output=True,
                    text=True,
                )
                cmd = ["git", "-C", str(root), "worktree", "add", "-B", branch, str(wt_path)]
                if base:
                    cmd.append(base)
                proc = subprocess.run(cmd, capture_output=True, text=True)
                if proc.returncode != 0:
                    raise ProviderError(
                        "worktree_create_failed",
                        (proc.stderr or proc.stdout or f"git worktree add failed for {slug}").strip(),
                    )
            else:
                wt_path.mkdir(parents=True, exist_ok=True)
        wt_id = f"{root.name}::{wt_path}"
        return {
            "worktree": {
                "id": wt_id,
                "displayName": slug,
                "path": str(wt_path),
                "branch": branch,
            }
        }

    def worktree_list(self, repo: str | None = None, limit: int | None = None) -> dict[str, Any]:
        root = Path(repo).resolve() if repo else self.repo_root
        rows: list[dict[str, Any]] = []
        if (root / ".git").exists():
            proc = subprocess.run(
                ["git", "-C", str(root), "worktree", "list", "--porcelain"],
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                current_path = None
                for line in proc.stdout.splitlines():
                    if line.startswith("worktree "):
                        current_path = line.split(" ", 1)[1].strip()
                        rows.append(
                            {
                                "id": f"{root.name}::{current_path}",
                                "displayName": Path(current_path).name,
                                "path": current_path,
                            }
                        )
        for child in sorted(self._worktree_base_dir().iterdir()):
            if child.is_dir() and not any(r.get("path") == str(child) for r in rows):
                rows.append(
                    {
                        "id": f"{root.name}::{child}",
                        "displayName": child.name,
                        "path": str(child),
                    }
                )
        truncated = False
        if limit and len(rows) > limit:
            rows = rows[:limit]
            truncated = True
        return {"worktrees": rows, "truncated": truncated}

    def worktree_show(self, selector: str) -> dict[str, Any]:
        if selector in ("active", "current"):
            wt_path = str(self.repo_root)
        elif selector.startswith("path:"):
            wt_path = selector.split(":", 1)[1]
        elif "::" in selector:
            wt_path = selector.split("::", 1)[1]
        elif ":" in selector:
            wt_path = str(self._worktree_base_dir() / selector.split(":", 1)[1])
        else:
            wt_path = selector
        p = Path(wt_path)
        return {
            "worktree": {
                "id": f"{self.repo_root.name}::{p}",
                "displayName": p.name or "worktree",
                "path": str(p),
            }
        }

    def worktree_rm(self, selector: str, force: bool = False) -> dict[str, Any]:
        shown = self.worktree_show(selector)["worktree"]
        wt_path = Path(shown["path"])
        if (self.repo_root / ".git").exists() and wt_path.exists():
            cmd = ["git", "-C", str(self.repo_root), "worktree", "remove"]
            if force:
                cmd.append("--force")
            cmd.append(str(wt_path))
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0 and not force:
                raise ProviderError(
                    "worktree_dirty",
                    (proc.stderr or proc.stdout or f"git worktree remove refused dirty worktree {wt_path}").strip(),
                )
        if wt_path.exists() and wt_path != self.repo_root:
            shutil.rmtree(wt_path, ignore_errors=True)
        return {"removed": True, "id": shown["id"]}

    # --- Worker Lifecycle ---
    def _resolve_worktree_path(self, worktree_sel: str, name: str | None) -> str:
        if worktree_sel in ("new-child", "new-top-level"):
            created = self.worktree_create(name or f"worker-{uuid.uuid4().hex[:6]}")
            return created["worktree"]["path"]
        if worktree_sel in ("current", "active"):
            return str(self.repo_root)
        if worktree_sel.startswith("path:"):
            return worktree_sel.split(":", 1)[1]
        if "::" in worktree_sel:
            return worktree_sel.split("::", 1)[1]
        return worktree_sel

    def _spawn_process(
        self,
        *,
        dispatch_id: str,
        term_handle: str,
        wt_path: str,
        command: str,
        env_vars: dict[str, str],
        lane_dir: Path,
        run_id: str,
    ) -> dict[str, Any]:
        log_file = lane_dir / "events.jsonl"
        log_file.touch()
        merged_env = {**self.env, **env_vars}

        if self.runner is not None:
            res = self.runner(
                command=command,
                worktree=wt_path,
                env=merged_env,
                backend=self.backend,
                dispatch_id=dispatch_id,
                term_handle=term_handle,
                log_file=str(log_file),
            )
            return res if isinstance(res, dict) else {"pid": 0, "backend": self.backend}

        if self.backend == "dry-run":
            log_file.write_text(json.dumps({"type": "turn_started", "dispatchId": dispatch_id}) + "\n", encoding="utf-8")
            return {"pid": 99999, "backend": "dry-run"}

        chan = f"orca-done-{dispatch_id}"
        monitor_py = f"""
import json, os, subprocess, sys
sys.path.insert(0, {repr(str(Path(__file__).resolve().parent.parent))})
from providers.local_state import LocalStateStore

log_path = {repr(str(log_file))}
with open(log_path, "a", encoding="utf-8") as lf:
    lf.write(json.dumps({{"type": "turn_started", "dispatchId": {repr(dispatch_id)}}}) + "\\n")
    lf.flush()
    proc = subprocess.Popen(
        {repr(command)},
        shell=True,
        cwd={repr(wt_path)},
        stdout=lf,
        stderr=subprocess.STDOUT,
    )
    rc = proc.wait()

store = LocalStateStore(db_path={repr(str(self.state.db_path))})
tail = ""
try:
    with open(log_path, "r", encoding="utf-8", errors="replace") as rf:
        tail = rf.read()[-500:]
except Exception:
    pass
store.ensure_terminal_or_died(
    dispatch_id={repr(dispatch_id)},
    worker_handle={repr(term_handle)},
    exit_code=rc,
    last_tail=tail,
    run_id={repr(run_id)},
)
if {repr(self.backend)} == "cmux":
    subprocess.run(["cmux", "wait-for", "-S", {repr(chan)}], capture_output=True)
"""
        runner_script = lane_dir / "run_worker.py"
        runner_script.write_text(monitor_py, encoding="utf-8")
        py_bin = os.environ.get("PYTHON", "python3")
        wrapped_monitor = f"{shlex.quote(py_bin)} {shlex.quote(str(runner_script))}"

        if self.backend == "cmux":
            proc = subprocess.run(
                ["cmux", "new-workspace", "--cwd", wt_path, "--command", wrapped_monitor],
                capture_output=True,
                text=True,
                env=merged_env,
            )
            if proc.returncode == 0:
                return {"pid": 0, "backend": "cmux", "channel": chan}

        if self.backend == "tmux":
            sess_name = f"openfleet-{term_handle}"
            proc = subprocess.run(
                ["tmux", "new-session", "-d", "-s", sess_name, "-c", wt_path, wrapped_monitor],
                capture_output=True,
                text=True,
                env=merged_env,
            )
            if proc.returncode == 0:
                return {"pid": 0, "backend": "tmux", "session": sess_name}

        proc = subprocess.Popen(
            [py_bin, str(runner_script)],
            cwd=wt_path,
            env=merged_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return {"pid": proc.pid, "backend": "setsid"}

    def worker_start(
        self,
        *,
        task_id: str,
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
    ) -> dict[str, Any]:
        check_monotonic_profile(parent_profile, profile)
        sandbox_recipe = on_env or env_get("OPEN_FLEET_SANDBOX_RECIPE", "ORCA_SANDBOX_RECIPE", self.env, "")
        if profile == "danger" and not sandbox_recipe:
            raise ProviderError(
                "danger_requires_sandbox",
                "profile='danger' requires --on <env> or OPEN_FLEET_SANDBOX_RECIPE isolated sandbox placement",
            )
        cached = self.state.get_or_record_request(retry_request, "worker-start")
        if cached:
            return cached

        run_id = run or "default"
        with self.state._connect() as conn:
            t_row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if not t_row:
                raise ProviderError("task_not_found", f"task {task_id!r} not found")
            if t_row["status"] != "ready":
                raise ProviderError(
                    "task_not_startable",
                    f"task {task_id!r} has status {t_row['status']!r} (must be 'ready')",
                )
            spec_text = prompt if prompt is not None else t_row["spec"]

        wt_path = self._resolve_worktree_path(worktree, name or task_id)
        Path(wt_path).mkdir(parents=True, exist_ok=True)
        dispatch_id = f"disp_{uuid.uuid4().hex[:10]}"
        term_handle = f"term_{uuid.uuid4().hex[:8]}"
        lane_dir = self.state.db_path.parent / "lanes" / dispatch_id
        lane_dir.mkdir(parents=True, exist_ok=True)

        hooks_map = install_worktree_hooks(wt_path, agent, profile)
        hook_script = str(Path(__file__).resolve().parent.parent / "scripts" / "deny-hook.sh")
        launch = build_harness_command(
            agent=agent,
            profile=profile,
            worktree=wt_path,
            prompt=spec_text,
            bridge_dir=str(Path(wt_path) / ".open-fleet" / "bridges"),
        )
        full_command = " ".join(shlex.quote(str(a)) for a in launch["argv"])
        if profile == "danger" and sandbox_recipe:
            extra_mounts = ""
            if (Path(wt_path) / ".git").is_file():
                gp = subprocess.run(
                    ["git", "-C", wt_path, "rev-parse", "--git-common-dir"],
                    capture_output=True,
                    text=True,
                )
                if gp.returncode == 0 and gp.stdout.strip():
                    common_dir = str((Path(wt_path) / gp.stdout.strip()).resolve())
                    extra_mounts = f"-v {shlex.quote(common_dir)}:{shlex.quote(common_dir)} "
            full_command = (
                f"docker run --rm -w {shlex.quote(wt_path)} "
                f"-v {shlex.quote(wt_path)}:{shlex.quote(wt_path)} "
                f"{extra_mounts}"
                f"{shlex.quote(sandbox_recipe)} sh -c {shlex.quote(full_command)}"
            )

        env_vars = {
            **launch["env"],
            "OPEN_FLEET_DENY_HOOK": hook_script,
            "ORCA_DENY_HOOK_PATH": hook_script,
            "OPEN_FLEET_DISPATCH_ID": dispatch_id,
            "ORCA_DISPATCH_ID": dispatch_id,
            "OPEN_FLEET_WORKER_ID": dispatch_id,
            "ORCA_WORKER_ID": dispatch_id,
            "OPEN_FLEET_RUN_ID": run_id,
            "ORCA_RUN_ID": run_id,
            "ORCA_TERMINAL_HANDLE": term_handle,
            "OPEN_FLEET_TERMINAL_HANDLE": term_handle,
            "OPEN_FLEET_STATE_DB": str(self.state.db_path),
            "ORCA_FLEET_STATE_DB": str(self.state.db_path),
        }

        now = time.time()
        eff_json = json.dumps(
            {
                "agent": agent,
                "args": launch["profile_flag"],
                "command": full_command,
                "hooks": hooks_map.get(agent, ""),
                "sandbox": sandbox_recipe if profile == "danger" else "",
            },
            sort_keys=True,
        )
        # Claim task and insert dispatch/terminal BEFORE spawning so concurrent callers
        # or fast-exiting workers always find the dispatch record (#591 review).
        with self.state._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE tasks SET status = 'dispatched', updated_at = ? WHERE id = ? AND status = 'ready'",
                (now, task_id),
            )
            if cur.rowcount != 1:
                conn.execute("ROLLBACK")
                raise ProviderError("task_not_startable", f"task {task_id!r} was already claimed concurrently")
            conn.execute(
                """
                INSERT INTO terminals(handle, worktree, title, command, pid, backend, log_path, state, created_at)
                VALUES (?, ?, ?, ?, 0, ?, ?, 'running', ?)
                """,
                (
                    term_handle,
                    wt_path,
                    name or task_id,
                    full_command,
                    self.backend,
                    str(lane_dir / "events.jsonl"),
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, profile, terminal_handle, state, terminal_state, pid, backend, launch_effective, lane_dir, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', 'active', 0, ?, ?, ?, ?, ?)
                """,
                (
                    dispatch_id,
                    task_id,
                    run_id,
                    wt_path,
                    agent,
                    profile,
                    term_handle,
                    self.backend,
                    eff_json,
                    str(lane_dir),
                    now,
                    now,
                ),
            )
            conn.execute("COMMIT")

        try:
            spawn_info = self._spawn_process(
                dispatch_id=dispatch_id,
                term_handle=term_handle,
                wt_path=wt_path,
                command=full_command,
                env_vars=env_vars,
                lane_dir=lane_dir,
                run_id=run_id,
            )
        except Exception:
            with self.state._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("UPDATE tasks SET status = 'ready', updated_at = ? WHERE id = ?", (time.time(), task_id))
                conn.execute("DELETE FROM dispatches WHERE dispatch_id = ?", (dispatch_id,))
                conn.execute("DELETE FROM terminals WHERE handle = ?", (term_handle,))
                conn.execute("COMMIT")
            raise

        with self.state._connect() as conn:
            conn.execute(
                "UPDATE terminals SET pid = ?, backend = ? WHERE handle = ?",
                (spawn_info.get("pid", 0), spawn_info.get("backend", self.backend), term_handle),
            )
            conn.execute(
                "UPDATE dispatches SET pid = ?, backend = ?, updated_at = ? WHERE dispatch_id = ?",
                (spawn_info.get("pid", 0), spawn_info.get("backend", self.backend), time.time(), dispatch_id),
            )

        res = {
            "state": "ready",
            "dispatchId": dispatch_id,
            "agentTerminalHandle": term_handle,
            "effects": [{"kind": "terminal", "role": "agent", "id": term_handle}],
            "launch": {
                "effective": {
                    "agent": agent,
                    "args": launch["profile_flag"],
                    "command": launch["command"],
                }
            },
            "worker": {
                "dispatchId": dispatch_id,
                "taskId": task_id,
                "state": "ready",
                "terminalState": "active",
                "agentTerminalHandle": term_handle,
                "worktree": wt_path,
            },
        }
        self.state.save_request(retry_request, "worker-start", "completed", res)
        return res

    def worker_list(
        self,
        *,
        run: str | None = None,
        task: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        with self.state._connect() as conn:
            q = "SELECT * FROM dispatches WHERE 1=1"
            params: list[Any] = []
            if run:
                q += " AND run_id = ?"
                params.append(run)
            if task:
                q += " AND task_id = ?"
                params.append(task)
            q += " ORDER BY created_at DESC"
            if limit:
                q += f" LIMIT {int(limit)}"
            rows = conn.execute(q, params).fetchall()
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
        ]
        return {"workers": workers, "scope": {"source": "posix"}, "page": {"nextCursor": None}}

    def worker_show(self, dispatch_id: str) -> dict[str, Any]:
        with self.state._connect() as conn:
            r = conn.execute("SELECT * FROM dispatches WHERE dispatch_id = ?", (dispatch_id,)).fetchone()
            if not r:
                raise ProviderError("dispatch_not_found", f"dispatch {dispatch_id!r} not found")
        return {
            "worker": {
                "dispatchId": r["dispatch_id"],
                "taskId": r["task_id"],
                "state": r["state"],
                "terminalState": r["terminal_state"],
                "agentTerminalHandle": r["terminal_handle"],
                "worktree": r["worktree"],
            }
        }

    def worker_read(self, dispatch_id: str, source: str = "transcript", limit: int = 50) -> dict[str, Any]:
        with self.state._connect() as conn:
            r = conn.execute("SELECT * FROM dispatches WHERE dispatch_id = ?", (dispatch_id,)).fetchone()
            if not r:
                raise ProviderError("dispatch_not_found", f"dispatch {dispatch_id!r} not found")
        log_file = Path(r["lane_dir"]) / "events.jsonl" if r["lane_dir"] else None
        lines: list[str] = []
        if log_file and log_file.is_file():
            lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
        if source == "transcript":
            items = [
                {
                    "id": f"item_{i}",
                    "role": "assistant",
                    "blocks": [{"type": "text", "text": ln}],
                }
                for i, ln in enumerate(lines or ["(no transcript lines yet)"])
            ]
            return {"source": "transcript", "transcript": {"items": items, "truncated": False}}
        return {"source": "terminal", "terminal": {"handle": r["terminal_handle"], "tail": lines}}

    def worker_fence(self, verb: str, dispatch_id: str, reason: str | None = None) -> dict[str, Any]:
        state_map = {
            "stop": ("stopped", "stopped"),
            "abandon": ("abandoned", "abandoned"),
            "release": ("released", "released"),
            "retain": ("retained", "retained"),
        }
        if verb not in state_map:
            raise ProviderError("invalid_verb", f"unknown worker fence verb {verb!r}")
        new_state, term_state = state_map[verb]
        with self.state._connect() as conn:
            r = conn.execute("SELECT * FROM dispatches WHERE dispatch_id = ?", (dispatch_id,)).fetchone()
            if not r:
                raise ProviderError("dispatch_not_found", f"dispatch {dispatch_id!r} not found")
            if verb in ("stop", "abandon", "release"):
                backend = r["backend"] or self.backend
                handle = r["terminal_handle"]
                if backend == "tmux" and handle:
                    subprocess.run(
                        ["tmux", "kill-session", "-t", f"openfleet-{handle}"],
                        capture_output=True,
                        text=True,
                    )
                elif backend == "cmux" and handle:
                    subprocess.run(
                        ["cmux", "close-workspace", "--workspace", handle],
                        capture_output=True,
                        text=True,
                    )
                if r["pid"] and r["pid"] > 0:
                    try:
                        os.killpg(int(r["pid"]), signal.SIGTERM)
                    except OSError:
                        pass
                if handle:
                    conn.execute("UPDATE terminals SET state = ? WHERE handle = ?", (term_state, handle))
            conn.execute(
                "UPDATE dispatches SET state = ?, terminal_state = ?, updated_at = ? WHERE dispatch_id = ?",
                (new_state, term_state, time.time(), dispatch_id),
            )
        return {"dispatchId": dispatch_id, "state": new_state, "terminalState": term_state}

    # --- Custom-Argv Terminal Operations (`terminal create/wait/read/list/show/send` + `dispatch --inject`) ---
    def terminal_create(
        self,
        worktree: str | None = None,
        title: str | None = None,
        command: str | None = None,
        shell: str | None = None,
        focus: bool = False,
    ) -> dict[str, Any]:
        wt_path = self._resolve_worktree_path(worktree or "current", title)
        Path(wt_path).mkdir(parents=True, exist_ok=True)
        handle = f"term_{uuid.uuid4().hex[:8]}"
        lane_dir = self.state.db_path.parent / "terminals" / handle
        lane_dir.mkdir(parents=True, exist_ok=True)
        log_file = lane_dir / "events.jsonl"
        log_file.write_text(json.dumps({"type": "tui_idle", "handle": handle}) + "\n", encoding="utf-8")
        pid = 0
        if command:
            spawn = self._spawn_process(
                dispatch_id=f"unsupervised_{handle}",
                term_handle=handle,
                wt_path=wt_path,
                command=command,
                env_vars={"ORCA_TERMINAL_HANDLE": handle, "OPEN_FLEET_TERMINAL_HANDLE": handle},
                lane_dir=lane_dir,
                run_id="default",
            )
            pid = spawn.get("pid", 0)
        with self.state._connect() as conn:
            conn.execute(
                """
                INSERT INTO terminals(handle, worktree, title, command, shell, pid, backend, log_path, state, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?)
                """,
                (handle, wt_path, title or handle, command or "", shell or "/bin/sh", pid, self.backend, str(log_file), time.time()),
            )
        return {"terminal": {"handle": handle, "id": handle, "title": title or handle, "worktree": wt_path}}

    def terminal_wait(self, terminal: str, condition: str = "tui-idle", timeout_ms: int = 90000) -> dict[str, Any]:
        with self.state._connect() as conn:
            r = conn.execute("SELECT * FROM terminals WHERE handle = ?", (terminal,)).fetchone()
            if not r:
                raise ProviderError("terminal_not_found", f"terminal {terminal!r} not found")
        if r["state"] != "running":
            raise ProviderError("terminal_not_running", f"terminal {terminal!r} is in state {r['state']!r}")
        normalized_cond = condition.replace("-", "_")
        satisfied = False
        if r["log_path"] and Path(r["log_path"]).is_file():
            content = Path(r["log_path"]).read_text(encoding="utf-8", errors="replace")
            if normalized_cond in content or condition in content or "tui_idle" in content or "turn_started" in content:
                satisfied = True
        if not satisfied:
            raise ProviderError("terminal_wait_timeout", f"terminal {terminal!r} did not reach {condition!r}")
        return {"wait": {"satisfied": True, "condition": condition, "terminal": terminal}}

    def terminal_read(
        self,
        terminal: str,
        cursor: int | None = None,
        limit: int | None = None,
        screen: bool = False,
    ) -> dict[str, Any]:
        with self.state._connect() as conn:
            r = conn.execute("SELECT * FROM terminals WHERE handle = ?", (terminal,)).fetchone()
            if not r:
                raise ProviderError("terminal_not_found", f"terminal {terminal!r} not found")
        lines: list[str] = []
        if r["log_path"] and Path(r["log_path"]).is_file():
            lines = Path(r["log_path"]).read_text(encoding="utf-8", errors="replace").splitlines()
        if limit:
            lines = lines[-int(limit):]
        return {"terminal": {"handle": terminal, "tail": lines, "cursor": len(lines)}}

    def terminal_list(
        self,
        worktree: str | None = None,
        limit: int | None = None,
        include_visual_layouts: bool = False,
    ) -> dict[str, Any]:
        with self.state._connect() as conn:
            rows = conn.execute("SELECT * FROM terminals ORDER BY created_at DESC").fetchall()
        terms = [
            {
                "handle": r["handle"],
                "title": r["title"],
                "worktree": r["worktree"],
                "state": r["state"],
            }
            for r in rows
        ]
        if limit:
            terms = terms[: int(limit)]
        return {"terminals": terms}

    def terminal_show(self, terminal: str) -> dict[str, Any]:
        with self.state._connect() as conn:
            r = conn.execute("SELECT * FROM terminals WHERE handle = ?", (terminal,)).fetchone()
            if not r:
                raise ProviderError("terminal_not_found", f"terminal {terminal!r} not found")
        return {
            "terminal": {
                "handle": r["handle"],
                "title": r["title"],
                "worktree": r["worktree"],
                "state": r["state"],
            }
        }

    def _deliver_terminal_input(self, term_row: Any, text: str, enter: bool = True) -> None:
        if term_row["state"] != "running":
            raise ProviderError("terminal_not_running", f"terminal {term_row['handle']!r} is not running")
        handle = term_row["handle"]
        backend = term_row["backend"] or self.backend
        payload = text + ("\n" if enter else "")
        if self.runner is not None:
            self.runner(
                action="terminal_send",
                term_handle=handle,
                backend=backend,
                text=payload,
                worktree=term_row["worktree"],
            )
        elif backend == "tmux":
            sess_name = f"openfleet-{handle}"
            cmd = ["tmux", "send-keys", "-t", sess_name, text]
            if enter:
                cmd.append("Enter")
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                raise ProviderError("terminal_send_failed", (proc.stderr or "tmux send-keys failed").strip())
        elif backend == "cmux":
            proc = subprocess.run(
                ["cmux", "send", "--workspace", handle, payload],
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                raise ProviderError("terminal_send_failed", (proc.stderr or "cmux send failed").strip())
        elif backend == "setsid" and int(term_row["pid"] or 0) > 0:
            try:
                os.kill(int(term_row["pid"]), 0)
            except OSError as exc:
                raise ProviderError("terminal_not_running", f"process {term_row['pid']} is not running: {exc}") from exc
        if term_row["worktree"]:
            inbox_dir = Path(term_row["worktree"]) / ".open-fleet"
            inbox_dir.mkdir(parents=True, exist_ok=True)
            with open(inbox_dir / "inbox.jsonl", "a", encoding="utf-8") as inf:
                inf.write(json.dumps({"handle": handle, "text": text, "ts": time.time()}) + "\n")
        if term_row["log_path"]:
            with open(term_row["log_path"], "a", encoding="utf-8") as lf:
                lf.write(payload)

    def terminal_send(self, terminal: str, text: str, enter: bool = True) -> dict[str, Any]:
        with self.state._connect() as conn:
            r = conn.execute("SELECT * FROM terminals WHERE handle = ?", (terminal,)).fetchone()
            if not r:
                raise ProviderError("terminal_not_found", f"terminal {terminal!r} not found")
        self._deliver_terminal_input(r, text, enter=enter)
        req_id = f"req_{uuid.uuid4().hex[:10]}"
        return {"send": {"accepted": True, "prompt": {"requestId": req_id, "stages": ["input_accepted", "turn_started"]}}}

    def dispatch_inject(
        self,
        task_id: str,
        to_handle: str,
        run: str | None = None,
        sender: str | None = None,
    ) -> dict[str, Any]:
        req_id = f"req_{uuid.uuid4().hex[:10]}"
        with self.state._connect() as conn:
            t_row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if not t_row:
                raise ProviderError("task_not_found", f"task {task_id!r} not found")
            term_row = conn.execute("SELECT * FROM terminals WHERE handle = ?", (to_handle,)).fetchone()
            if not term_row:
                raise ProviderError("inject_rejected", f"terminal {to_handle!r} not found")
        injected_line = json.dumps({"type": "injected_prompt", "taskId": task_id, "spec": t_row["spec"]})
        self._deliver_terminal_input(term_row, injected_line, enter=True)
        with self.state._connect() as conn:
            conn.execute("UPDATE tasks SET status = 'dispatched', updated_at = ? WHERE id = ?", (time.time(), task_id))
        return {
            "injected": True,
            "prompt": {
                "requestId": req_id,
                "stages": ["input_accepted", "turn_started"],
            },
        }
