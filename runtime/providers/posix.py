#!/usr/bin/env python3
"""posix.py — Zero-Daemon Native POSIX Worktree RuntimeProvider (`OPEN_FLEET_RUNTIME=posix`).

Runs `open-fleet` missions standalone on any Linux/macOS host or CI container without requiring
an external orchestrator daemon (`stablyai/orca`), combining:
  - `LocalStateStore` (SQLite WAL Run, Task DAG, Typed Mailbox, HITL Gates, File-Touch Conflicts)
  - `git worktree` / `wtree.sh` worktree isolation
  - `tmux`, `cmux` (`manaflow-ai/cmux` with `kqueue` `cmux wait-for`), or detached `setsid`
    process groups
  - The verified CLI-harness launch table (`base.SUPPORTED_HARNESSES`), for the harnesses
    `capabilities.json` lists for posix, across `PROFILE=ro|rw|danger` (`hermes` refuses `danger`)
  - Automatic per-worktree `PreToolUse` hook installation (`deny-hook.sh`)
  - Overstory-style synthetic `worker_died` guarantee on process exit without terminal mail (#590).
  - Crash-recoverable worker launch: a launch intent persisted before the first external side
    effect, settled by recorded identity after a coordinator crash (#597, docs/runtimes.md).
"""
from __future__ import annotations

import contextlib
import fcntl
import fnmatch
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from .base import (
    FENCED_DISPATCH_STATES,
    ProviderError,
    RuntimeProvider,
    build_harness_command,
    check_env_keys,
    check_monotonic_profile,
    env_get,
    fence_state,
    normalize_read,
    normalize_show,
)
from .local_state import LocalStateStore
from .transcript import final_answer

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


RUNTIME_DIR = Path(__file__).resolve().parent.parent
OPEN_FLEET_ROOT = RUNTIME_DIR.parent
CANONICAL_DENY_HOOK = RUNTIME_DIR / "scripts" / "deny-hook.sh"


def _load_gitexec():
    """runtime/scripts/gitexec.py: the one git resolution rule and hardened environment (W4-01)."""
    spec = importlib.util.spec_from_file_location("open_fleet_posix_gitexec", RUNTIME_DIR / "scripts" / "gitexec.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gitexec = _load_gitexec()
SANDBOX_GIT_MOUNT = "/open-fleet/sandbox.git"
# Per-worktree guard artifacts install_worktree_hooks writes. They are excluded from git (never
# land in a PR) and deny-hook.sh refuses edits to them (a worker cannot disarm its own guard).
# Entries ending in "/" are directories open-fleet owns outright; every other entry is one
# exact generated FILE. A user directory (.codex/, .crush/, .claude/) is never exempted
# wholesale: excluded files are silently deleted by `git worktree remove` (#592 review).
HOOK_ARTIFACTS = (
    ".open-fleet/",
    ".crush-orca-ro/",
    ".hermes-open-fleet/",
    ".claude/settings.local.json",
    ".codex/hooks.json",
    ".openhands/hooks.json",
    ".agents/plugins/orca-deny-hook/hooks/hooks.json",
    ".opencode/plugin/orca-deny-hook.ts",
    ".crush/crush.json",
)


# Every file install_worktree_hooks writes, relative to the worktree.
GUARD_FILES = (
    ".claude/settings.local.json",
    ".codex/hooks.json",
    ".openhands/hooks.json",
    ".agents/plugins/orca-deny-hook/hooks/hooks.json",
    ".opencode/plugin/orca-deny-hook.ts",
    ".open-fleet/bridges/omp_pi_deny_bridge.ts",
    ".crush-orca-ro/crush.json",
    ".crush/crush.json",
)


def _refuse_guard_links(wt: Path) -> None:
    """A worktree's content is the worker's: a commit can carry `.claude`, or a guard file itself,
    as a symbolic link, and each guard write would follow it out of the worktree. No component of
    any guard path may be a link (PR #653 review sweep)."""
    for rel in GUARD_FILES:
        path = wt
        for part in Path(rel).parts:
            path = path / part
            if path.is_symlink():
                raise ProviderError("worktree_guard_link",
                                    f"{path} is a symbolic link: the worktree guard is never written through one",
                                    {"path": str(path)})


def _exclude_hook_artifacts(wt: Path) -> None:
    """Append HOOK_ARTIFACTS to the worktree's `info/exclude` (shared by all linked worktrees)."""
    proc = _git(["rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=wt, timeout=15)
    if proc.returncode != 0 or not _line(proc.stdout):
        return
    info = Path(_line(proc.stdout)) / "info"
    info.mkdir(parents=True, exist_ok=True)
    exclude = info / "exclude"
    have = exclude.read_text(encoding="utf-8").splitlines() if exclude.is_file() else []
    missing = [a for a in HOOK_ARTIFACTS if a not in have]
    if missing:
        with open(exclude, "a", encoding="utf-8") as fh:
            if have and have[-1] != "":
                fh.write("\n")
            fh.write("# open-fleet worker guard artifacts (install_worktree_hooks)\n")
            fh.write("\n".join(missing) + "\n")


# Settings keys a harness reads that would switch the guard off or steer it: never merged in
# from a document already at a guard path (2026-10-26 review).
_GUARD_STEERING_PREFIXES = ("ORCA_", "OPEN_FLEET_")
# Env that steers which shell runs the guard command (a bare `sh`) or what that shell loads: a
# kept `PATH` naming a planted `sh` ran it instead of deny-hook.sh (#707 review). The same keys
# deny-hook.sh --verify-settings refuses as STEERING; a test keeps the two lists in step.
_SHELL_STEERING_KEYS = frozenset((
    "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
    "ENV", "BASH_ENV", "SHELLOPTS", "CDPATH", "IFS", "SHELL",
))


def _steers_the_guard(key: Any) -> bool:
    return str(key) in _SHELL_STEERING_KEYS or str(key).startswith(_GUARD_STEERING_PREFIXES)


def _runs_a_command(value: Any) -> bool:
    """True when a settings value names something the harness executes itself: a hook, a status
    line, an LSP or MCP server — any object, at any depth, carrying a `command`."""
    if isinstance(value, dict):
        return "command" in value or any(_runs_a_command(v) for v in value.values())
    if isinstance(value, list):
        return any(_runs_a_command(v) for v in value)
    return False


def _merge_hook_doc(path: Path, ours: dict[str, Any]) -> dict[str, Any]:
    """`ours` laid over the JSON object already at `path` (2026-10-26 review).

    The guard used to REPLACE the file: a repository's checked-in `.crush/crush.json` or
    `.codex/hooks.json`, or an operator's `.claude/settings.local.json` in a reused worktree, lost
    every other key it carried. Now its plain settings survive, and what could disarm the guard
    or run beside it is dropped: `disableAllHooks`, `env` entries that steer the hook
    (ORCA_*/OPEN_FLEET_*) or the shell that runs it (`_SHELL_STEERING_KEYS`), every hook already
    there, and every setting that names a command (#707 review: a kept repository hook ran beside
    the guard, never through it, and Codex launches with --dangerously-bypass-hook-trust). The
    `hooks` written are ours alone. A file that is unreadable or not a JSON object is replaced
    outright.
    """
    try:
        have = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ours
    if not isinstance(have, dict):
        return ours
    merged: dict[str, Any] = {k: v for k, v in have.items()
                              if k not in ("disableAllHooks", "hooks") and not _runs_a_command(v)}
    env = merged.get("env")
    if isinstance(env, dict):
        merged["env"] = {k: v for k, v in env.items() if not _steers_the_guard(k)}
    merged["hooks"] = {event: list(entries) for event, entries in ours.get("hooks", {}).items()}
    for key, value in ours.items():
        if key != "hooks":
            merged[key] = value
    return merged


def _write_guard_doc(path: Path, ours: dict[str, Any]) -> None:
    path.write_text(json.dumps(_merge_hook_doc(path, ours), indent=2) + "\n", encoding="utf-8")


def install_worktree_hooks(
    worktree_path: str | Path,
    agent: str,
    profile: str,
    *,
    deny_hook_path: str | None = None,
) -> dict[str, str]:
    """Install per-worktree `PreToolUse` hook configs and bridges for all supported harnesses.

    A JSON config already at a guard path is merged, not replaced (`_merge_hook_doc`).
    The hook itself is NEVER copied into the worktree: configs point at the canonical
    `runtime/scripts/deny-hook.sh` outside the unit's write boundary, so a worker cannot edit
    its own guard, and the hook's `$0`-relative lookup of `local_state.py` (file-touch
    recording) keeps working. Inside a Docker sandbox the runtime dir is bind-mounted read-only
    at the same path. Non-Claude harnesses get `ORCA_HOOK_STRICT_EXIT=1`: they fail OPEN on an
    `ask` decision, so the hook must answer exit 2 instead (#577).
    """
    wt = Path(worktree_path).resolve()
    wt.mkdir(parents=True, exist_ok=True)
    _refuse_guard_links(wt)
    hook = deny_hook_path or str(CANONICAL_DENY_HOOK)
    # shlex-quoted: a path carrying `$`, a backtick or `"` must never expand in the hook shell.
    qwt, qhook = shlex.quote(str(wt)), shlex.quote(hook)
    boundary = f"OPEN_FLEET_UNIT_WORKTREE={qwt} ORCA_UNIT_WORKTREE={qwt}"
    if profile == "ro":
        boundary += " OPEN_FLEET_HOOK_READONLY=1 ORCA_HOOK_READONLY=1"
    cmd_str = f"{boundary} sh {qhook}"
    strict_cmd = f"{boundary} ORCA_HOOK_STRICT_EXIT=1 sh {qhook}"
    installed: dict[str, str] = {"deny_hook": hook}

    # 1. Claude Code (.claude/settings.local.json) — honours `ask` natively.
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
    _write_guard_doc(claude_settings, claude_doc)
    installed["claude"] = str(claude_settings)

    strict_doc = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": ".*",
                    "hooks": [{"type": "command", "command": strict_cmd}],
                }
            ]
        }
    }
    # 2. OpenAI Codex (.codex/hooks.json)
    codex_dir = wt / ".codex"
    codex_dir.mkdir(parents=True, exist_ok=True)
    codex_hooks = codex_dir / "hooks.json"
    _write_guard_doc(codex_hooks, strict_doc)
    installed["codex"] = str(codex_hooks)

    # 3. OpenHands (.openhands/hooks.json)
    oh_dir = wt / ".openhands"
    oh_dir.mkdir(parents=True, exist_ok=True)
    oh_hooks = oh_dir / "hooks.json"
    _write_guard_doc(oh_hooks, strict_doc)
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
                    "hooks": [{"type": "command", "command": strict_cmd, "on_failure": "block"}],
                }
            ]
        }
    }
    _write_guard_doc(goose_hooks, goose_doc)
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
    _write_guard_doc(crush_rw_dir / "crush.json", strict_doc)
    installed["crush"] = str((crush_ro_dir if profile == "ro" else crush_rw_dir) / "crush.json")

    _exclude_hook_artifacts(wt)
    return installed


# Harnesses whose deny-hook registration install_worktree_hooks writes as a settings FILE the
# hook can re-verify by name (hermes/jcode wire theirs through env, not a file, so they are not
# here). The key is both the hooks_map key and the deny-hook.sh --harness name.
_GUARD_VERIFIABLE_HARNESSES = ("claude", "codex", "openhands", "goose", "opencode", "omp", "pi",
                               "crush")


def verify_installed_guard(wt_path: str | Path, agent: str, profile: str,
                           hooks_map: dict[str, str], hook_script: str | None = None,
                           verifier: str | None = None) -> None:
    """Prove the deny-hook registration this worktree just received is armed, BEFORE the agent
    process starts (W4-06). The previous story verified a guard only in the coordinator's
    pre-launch gate, which a `new-child` spawn cannot reach (no worktree, no settings file yet);
    the real enforcement point is here, where the registration is installed and the launch is
    about to run. Runs `deny-hook.sh --verify-settings <registration> --harness <agent>
    --boundary <wt>`: the file must exist, name the hook that will load, pin the boundary and
    answer a live deny probe. Raise ProviderError('deny_hook_unverified') on any failure so the
    caller aborts the launch and no agent starts. Scoped to the file-registration harnesses; a
    `danger` worker (sandbox is its boundary), harnesses with no settings-file registration, and
    crush `ro` (its installed file is a disabled-tools restriction, not a hook registration) are
    left to their own mechanisms. The probe runs under the env worker_start gives the agent: the
    opencode/omp/pi bridges read the hook path and boundary from it, so that IS what loads.
    `verifier` names the deny-hook.sh that RUNS the check when it should not be the registered
    hook itself (the openhands provider passes this repo's own copy, so a stand-in hook that
    answers --verify-settings with exit 0 is refused for its bytes, not trusted to grade itself)."""
    if profile == "danger" or agent not in _GUARD_VERIFIABLE_HARNESSES:
        return
    if agent == "crush" and profile == "ro":
        return
    registration = hooks_map.get(agent)
    if not registration:
        return
    hook = hook_script or hooks_map.get("deny_hook") or str(CANONICAL_DENY_HOOK)
    launch_env = {**os.environ, "OPEN_FLEET_DENY_HOOK": str(hook), "ORCA_DENY_HOOK_PATH": str(hook),
                  "OPEN_FLEET_UNIT_WORKTREE": str(wt_path), "ORCA_UNIT_WORKTREE": str(wt_path),
                  "OPEN_FLEET_SANDBOX_PROFILE": profile, "ORCA_SANDBOX_PROFILE": profile}
    vs_args = ["sh", str(verifier or hook), "--verify-settings", str(registration), "--harness", agent,
               "--boundary", str(wt_path)]
    if profile == "ro":
        launch_env["OPEN_FLEET_HOOK_READONLY"] = "1"
        launch_env["ORCA_HOOK_READONLY"] = "1"
        vs_args.append("--readonly")
    proc = subprocess.run(
        vs_args,
        capture_output=True, text=True, timeout=60, env=launch_env,
    )
    if proc.returncode != 0:
        raise ProviderError(
            "deny_hook_unverified",
            f"the deny-hook registration installed for {agent} at {registration} is not armed, so "
            f"the agent is not started (W4-06): {(proc.stderr or proc.stdout).strip()[:300]}",
        )


# Fleet-custody secrets a worker never receives: the dispatch signing seeds (it could sign its
# own dispatches) and the coordinator's orchestrator/cloud credentials (2026-10-26 review). The
# rest of the coordinator's environment still reaches the worker — harness credentials and proxy
# settings live there and no allowlist of them is known — so an operator names anything else to
# strip in OPEN_FLEET_WORKER_ENV_DENY (`ORCA_WORKER_ENV_DENY`): comma- or space-separated names or
# fnmatch globs, e.g. `GH_TOKEN,AWS_*`. Applied to the spawn env, the mux server's env and, in the
# monitor, to the env it inherited from an already-running server.
WORKER_ENV_DENYLIST = frozenset({
    "OPEN_FLEET_SIGNING_SEED", "ORCA_DISPATCH_SIGNING_SEED",
    "ORCA_CLOUD_AUTH_TOKEN",
    "OPEN_FLEET_PAPERCLIP_API_KEY", "ORCA_PAPERCLIP_API_KEY",
    "OPEN_FLEET_OPENHANDS_SESSION_API_KEY", "ORCA_OPENHANDS_SESSION_API_KEY",
    "OPEN_FLEET_OPENHANDS_LLM_API_KEY", "ORCA_OPENHANDS_LLM_API_KEY",
})


def worker_env_deny_patterns(env: dict[str, str]) -> list[str]:
    """The built-in denylist plus the operator's OPEN_FLEET_WORKER_ENV_DENY patterns, sorted."""
    extra = env_get("OPEN_FLEET_WORKER_ENV_DENY", "ORCA_WORKER_ENV_DENY", env, "")
    names = {p for p in re.split(r"[,\s]+", extra) if p}
    return sorted(WORKER_ENV_DENYLIST | names)


def strip_denied_env(mapping: dict[str, str], patterns: list[str]) -> dict[str, str]:
    """`mapping` without every key that a pattern names (exact name or fnmatch glob)."""
    return {k: v for k, v in mapping.items() if not any(fnmatch.fnmatchcase(k, p) for p in patterns)}
HERMES_HOOK_MATCHER = "terminal|write_file|patch|execute_code|process"

# A PROFILE=ro launch strips every tool that could send mail (#596): no shell to run send_msg.py,
# and codex's read-only sandbox and hermes' /dev/null write root deny the state-DB write besides.
# So a ro assignment names a completion LINE, and the exit monitor, which already holds the
# dispatch's identity and the state DB, relays it as that worker's worker_done. The line binds the
# dispatch id, which exists only once worker_start runs: no spec text, echoed instruction or
# other dispatch's output can speak for this one. The worker gains no tool and no writable path.
RO_DONE_MARK = "OPEN_FLEET_WORKER_DONE"
_RO_DONE_RE = re.compile(r"^\W*" + RO_DONE_MARK + r"\s+(\S+)\s+(succeeded|failed)\W*$")


def ro_completion_footer(dispatch_id: str) -> str:
    """The instruction worker_start appends to a ro worker's assignment. No line of it is itself
    a completion line, so a harness that echoes its prompt cannot complete the dispatch."""
    return (
        "\n\n---\nopen-fleet: this read-only dispatch has no tool to send mail. When you finish, make "
        f"the last line of your final answer the marker {RO_DONE_MARK} {dispatch_id} <outcome>, with "
        "<outcome> replaced by succeeded or failed; the runtime relays it to the coordinator as "
        "your worker_done."
    )


def ro_completion_outcome(transcript: str, dispatch_id: str, agent: str) -> str | None:
    """The outcome on the completion line that ENDS `agent`'s final answer for `dispatch_id`.

    Only the final answer counts, read with first_run.py's per-harness reader (transcript.py),
    and only its last line that carries a word: the footer asks for exactly that line. A marker
    rehearsed in reasoning, quoted from a tool result, echoed from the prompt, or said earlier in
    the answer is not the worker's completion (#596 review); for jcode and plain-text launches,
    whose answer carries every turn's text, the last line is what tells the two apart. A closing
    fence after the line carries no word, so it does not hide it. None: no completion line.
    """
    answer = final_answer(agent, transcript.splitlines())
    last = next((ln for ln in reversed(answer.splitlines()) if re.search(r"\w", ln)), "")
    m = _RO_DONE_RE.match(last.strip())
    if m and m.group(1).strip("`'\"*") == dispatch_id:
        return m.group(2)
    return None


def relay_ro_completion(
    store: LocalStateStore,
    *,
    dispatch_id: str,
    worker_handle: str,
    agent: str,
    run_id: str,
    log_path: str | Path,
    head_sha: str = "",
) -> dict[str, Any] | None:
    """Relay the completion line a ro worker's final answer ends with, as its worker_done (#596).

    The exit monitor's one reader, which recovery also uses when a monitor recorded its exit and
    died before relaying. relay_worker_done is one idempotent transaction, so a worker is never
    reported twice. None: no readable transcript, or no completion line in it.
    """
    try:
        text = Path(log_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    outcome = ro_completion_outcome(text, dispatch_id, agent)
    if not outcome:
        return None
    return store.relay_worker_done(dispatch_id=dispatch_id, worker_handle=worker_handle, outcome=outcome,
                                   run_id=run_id, head_sha=head_sha)


# The committed boundaries of a `worker_start`, in the order it crosses them (#597). The spec —
# what is durable after each and what a restarted coordinator does — is docs/runtimes.md.
LAUNCH_BOUNDARIES = (
    "intent_claimed",
    "worktree_created",
    "registered",
    "monitor_spawned",
    "published",
    "receipted",
)
LAUNCH_FINAL_OUTCOMES = ("completed", "failed")


class _IntentLease:
    """An exclusive `flock` the coordinator launching an intent holds until it finishes (#597).

    The kernel releases it when the holder dies, however it dies, so a free lock on an OPEN intent
    (same host) proves its owner is gone; that is what lets recovery act without guessing from a
    pid that may have been reused. The fd is non-inheritable: no spawned process keeps it.
    """

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.held = False
        self.fd: int | None = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)

    def try_acquire(self) -> bool:
        if self.fd is None:
            return False
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        self.held = True
        return True

    def release(self, *, unlink: bool) -> None:
        if self.fd is None:
            return
        if unlink and self.held:
            # Only the holder's own bookkeeping, never a lock someone else holds (a takeover's
            # lease, #597 review): an undeletable lock file is harmless (an open intent is
            # judged by acquiring the lock, never by the file's presence).
            with contextlib.suppress(OSError):
                self.path.unlink()
        os.close(self.fd)
        self.fd = None


def _launch_payload_sha256(fields: dict[str, Any]) -> str:
    """The request payload a `--retry-request` id binds (#597): same id + other payload = mismatch."""
    return hashlib.sha256(json.dumps(fields, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _worktree_slug(name: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "-" for c in name).strip("-")


def _col(row: Any, key: str) -> Any:
    """`row[key]`, or None for a row (or hand-built dict) that predates the column."""
    return row[key] if key in row.keys() else None


def _pid_runs_monitor(pid: int, lane: Path) -> bool:
    """Whether `pid` is alive AND still the monitor of `lane` (a reused pid is not, #597)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    marker = os.path.join(lane.name, "run_worker.py")
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        raw = None
    if raw is not None:
        # Linux: the argv without a `ps` fork per sweep. Empty for a zombie or a kernel thread.
        return marker in raw.replace(b"\0", b" ").decode("utf-8", "replace")
    try:
        proc = subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return True  # no `ps` here: the pid is alive, which is all that can be known
    cmd = proc.stdout.strip()
    # A reaped or zombie pid prints nothing / "<defunct>"; the monitor's argv names its script.
    return proc.returncode == 0 and marker in cmd


def _cwd_under(cwd: str, wanted: list[str]) -> bool:
    return any(cwd == r or cwd.startswith(r.rstrip("/") + "/") for r in wanted)


def _group_members_under(pgid: int, roots: tuple[Path, ...]) -> list[int] | None:
    """Live pids in process group `pgid` whose cwd lies under one of `roots`.

    The monitor leads its own session, and the agent (with its `sh -c` wrapper) runs in that
    group with the worktree as cwd, so after `kill -9` of the monitor alone these are the worker
    it left behind. Read from /proc, or with `ps` and `lsof` where there is none (macOS, #707
    review). None: neither can be read, so membership and cwd are unknown.
    """
    wanted = [os.path.realpath(str(r)) for r in roots if r]
    try:
        entries = [e for e in Path("/proc").iterdir() if e.name.isdigit()]
    except OSError:
        return _ps_group_members_under(pgid, wanted)
    out: list[int] = []
    for entry in entries:
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[-1].split()
            if fields[0] == "Z" or int(fields[2]) != pgid:
                continue
            cwd = os.readlink(entry / "cwd")
        except (OSError, ValueError, IndexError):
            continue
        if _cwd_under(cwd, wanted):
            out.append(int(entry.name))
    return out


def _ps_group_members_under(pgid: int, wanted: list[str]) -> list[int] | None:
    """`_group_members_under` on a host with no /proc: `ps` lists the group, `lsof` reads each
    member's cwd. None when either tool is missing or fails, as with no /proc before."""
    try:
        ps = subprocess.run(["ps", "-A", "-o", "pid=,pgid=,stat="], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    if ps.returncode != 0:
        return None
    out: list[int] = []
    for line in ps.stdout.splitlines():
        fields = line.split()
        if len(fields) < 3 or not fields[0].isdigit() or fields[1] != str(pgid) or fields[2].startswith("Z"):
            continue
        try:
            lsof = subprocess.run(["lsof", "-a", "-p", fields[0], "-d", "cwd", "-Fn"],
                                  capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            return None
        # `-Fn` prints one `n<path>` line per file; a member that exited meanwhile prints none.
        cwd = next((ln[1:] for ln in lsof.stdout.splitlines() if ln.startswith("n")), "")
        if cwd and _cwd_under(cwd, wanted):
            out.append(int(fields[0]))
    return out


def _hermes_interpreter(env: dict[str, str]) -> list[str] | None:
    """The Python the installed `hermes` launcher runs on (it always has PyYAML: Hermes needs it)."""
    exe = shutil.which("hermes", path=env.get("PATH"))
    if not exe:
        return None
    try:
        with open(exe, "rb") as fh:
            first = fh.readline(512).decode("utf-8", "replace").strip()
    except OSError:
        return None
    if not first.startswith("#!"):
        return None
    argv = shlex.split(first[2:])
    if argv and os.path.basename(argv[0]) == "env":
        argv = [a for a in argv[1:] if not a.startswith("-")]
    if not argv or "python" not in os.path.basename(argv[0]):
        return None
    return argv


def _load_hermes_config(user_cfg: Path, env: dict[str, str]) -> dict[str, Any]:
    """Parse the user's Hermes config.yaml without making PyYAML a hard coordinator dependency.

    Order: an empty/absent file needs no parser; then PyYAML in this interpreter; then the
    interpreter Hermes itself runs on. With none available the launch is REFUSED — never
    started with the user's config dropped or the hook missing.
    """
    text = user_cfg.read_text(encoding="utf-8") if user_cfg.is_file() else ""
    if not text.strip():
        return {}
    loaded: Any = None
    try:
        import yaml

        loaded = yaml.safe_load(text)
    except ImportError:
        interp = _hermes_interpreter(env)
        if interp is None:
            raise ProviderError(
                "hermes_hooks_unavailable",
                "cannot parse the user's Hermes config.yaml (no PyYAML here and no Python `hermes` launcher "
                "to borrow one from); refusing an unguarded launch",
            ) from None
        proc = subprocess.run(
            [*interp, "-I", "-c", "import json,sys,yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1], encoding='utf-8'))))", str(user_cfg)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            raise ProviderError(
                "hermes_hooks_unavailable",
                f"could not parse {user_cfg} with Hermes' own interpreter: {(proc.stderr or proc.stdout).strip()[:200]}",
            )
        loaded = json.loads(proc.stdout or "null")
    loaded = loaded or {}
    if not isinstance(loaded, dict):
        raise ProviderError("hermes_hooks_unavailable", f"{user_cfg} is not a YAML mapping")
    return loaded


def tmux_send_keys_argv(ref: str, text: str) -> list[str]:
    """argv for sending `text` LITERALLY to tmux pane `ref`. `--` ends tmux's options so a
    `-`-leading payload (`-R`, `--help`) is the text, never a flag: `tmux send-keys -l -R` parsed
    the text as -R (reset terminal), exited 0, and the send was recorded as accepted with nothing
    delivered (W2-01)."""
    return ["tmux", "send-keys", "-t", ref, "-l", "--", text]


def prepare_hermes_home(lane_dir: Path, wt_path: str, hook: str, env: dict[str, str]) -> dict[str, str]:
    """A per-dispatch HERMES_HOME (outside the worktree) whose config carries our deny hook.

    Hermes loads `pre_tool_call` hooks only from `$HERMES_HOME/config.yaml`, runs the command
    WITHOUT a shell, blocks only on exit 2 (or `{"decision":"block"}`), and fails OPEN unless
    `fail_closed: true` (NousResearch/hermes-agent agent/shell_hooks.py). The user's own home
    is mirrored by symlink (auth, .env, skills…) except config.yaml, which is the user's config
    merged with the hook; the worker can neither edit it nor its allowlist. The merged config is
    written as JSON — valid YAML that every YAML loader reads — so no YAML emitter is needed.
    """
    src_raw = (env.get("HERMES_HOME") or "").strip()
    src = Path(os.path.expanduser(src_raw)) if src_raw else Path.home() / ".hermes"
    cfg = _load_hermes_config(src / "config.yaml", env)
    home = Path(lane_dir) / "hermes-home"
    home.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        for entry in src.iterdir():
            if entry.name in ("config.yaml", "shell-hooks-allowlist.json"):
                continue
            link = home / entry.name
            if not link.exists() and not link.is_symlink():
                link.symlink_to(entry)
    hooks = cfg.get("hooks") if isinstance(cfg.get("hooks"), dict) else {}
    pre = [h for h in (hooks.get("pre_tool_call") or []) if isinstance(h, dict)]
    pre.insert(
        0,
        {
            "matcher": HERMES_HOOK_MATCHER,
            "command": f"env ORCA_HOOK_STRICT_EXIT=1 OPEN_FLEET_UNIT_WORKTREE={shlex.quote(wt_path)} "
            f"ORCA_UNIT_WORKTREE={shlex.quote(wt_path)} sh {shlex.quote(hook)}",
            "timeout": 60,
            "fail_closed": True,
        },
    )
    hooks["pre_tool_call"] = pre
    cfg["hooks"] = hooks
    out = home / "config.yaml"
    out.write_text(json.dumps(cfg, indent=2, default=str) + "\n", encoding="utf-8")
    os.chmod(out, 0o600)
    return {"HERMES_HOME": str(home), "HERMES_ACCEPT_HOOKS": "1", "HERMES_SAFE_MODE": "0"}


# Variables that choose the repository, worktree, index, object store or attribute source a git
# call reads, or that inject config, templates or git's own helper programs (gitexec.SELECTOR_ENV,
# shared with the read-side tools' custody). Handed to a provider's git in a caller-supplied env,
# they pointed the call at a repository the custody never looked at, and its smudge filter ran
# (PR #720 Codex round 2): `-C`/cwd/`--git-dir`/`--work-tree` is the only way a provider names its
# repository.
GIT_SELECTOR_ENV = gitexec.SELECTOR_ENV


def git_call_base(env: dict[str, str] | None) -> dict[str, str]:
    """The env a provider git call starts from (os.environ when None) with GIT_SELECTOR_ENV and
    every GIT_CONFIG_KEY_n/VALUE_n removed: the one base every step of a custody call (its
    repository lookups, the driver listing, the git itself) runs under, so all resolve the same
    repository. Used by run_git and checkout_worktree."""
    return {k: v for k, v in (os.environ if env is None else env).items()
            if k not in GIT_SELECTOR_ENV and not k.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))}


def git_location(args: list[str], cwd: str | Path | None) -> tuple[str, str | None]:
    """`(repo, git_dir)` git runs in for the arguments `args` (everything after the program name):
    their leading `-C <dir>` options (each relative to the one before, from the launch cwd), or a
    `--git-dir`, else the launch cwd itself. Shared with the adapters' launcher
    (_external._run_git)."""
    repo, git_dir, i = str(cwd or os.getcwd()), None, 0
    while i < len(args):
        tok = args[i]
        if tok in ("-C", "-c", "--git-dir", "--work-tree") and i + 1 < len(args):
            if tok == "-C":
                repo = os.path.join(repo, args[i + 1])
            elif tok == "--git-dir":
                git_dir = args[i + 1]
            i += 2
        elif tok.startswith("--git-dir="):
            git_dir, i = tok.split("=", 1)[1], i + 1
        elif tok.startswith("-"):
            i += 1
        else:
            break
    return repo, (os.path.join(repo, git_dir) if git_dir else None)


# ---------------------------------------------------------------------------------------------
# Coordinator git custody (W4-01; PR #720 Codex round 3)
# ---------------------------------------------------------------------------------------------
# The custody's fixed command keys (core.alternateRefsCommand, submodule recursion, signature
# verification, auto-maintenance), the transport/lazy-fetch environment no config can outrank, the
# data-only core.* settings a custody call carries, the extensions it honours and its refusal all
# live in runtime/scripts/gitexec.py since the W4 custody sweep, shared with the read-side tools
# (floor_guard, diff_scope, hint_provenance, verify's negative control). The transport is pinned by
# PROVIDER_FLOOR_ENV (GIT_ALLOW_PROTOCOL), not a `protocol.*.allow` config pair, because a worker's
# SPECIFIC `protocol.ssh.allow=always` beats a generic `protocol.allow=never` (PR #720 Codex round 4).
PROVIDER_FLOOR: tuple[tuple[str, str], ...] = gitexec.CUSTODY_FLOOR
PROVIDER_FLOOR_ENV: dict[str, str] = gitexec.CUSTODY_ENV
_CUSTODY_CORE_KEYS: tuple[str, ...] = gitexec.CUSTODY_CORE_KEYS
_HONOURABLE_EXTENSIONS: frozenset[bytes] = gitexec.HONOURABLE_EXTENSIONS
GitCustodyRefused = gitexec.GitCustodyRefused


# `-c` keys a caller may put on a direct call: the sandbox sync's ownership and transport belts.
_LEAD_CONFIG_KEYS = frozenset({"safe.directory", "protocol.file.allow"})


def _split_git_args(args: list[str]) -> tuple[list[str], str, list[str]]:
    """`(global options, subcommand, its arguments)`; an unknown global option is refused."""
    i = 0
    while i < len(args):
        tok = args[i]
        if tok in ("-C", "--git-dir", "--work-tree") and i + 1 < len(args):
            i += 2
        elif tok == "-c" and i + 1 < len(args):
            if args[i + 1].split("=", 1)[0].lower() not in _LEAD_CONFIG_KEYS:
                raise GitCustodyRefused(f"git custody: refusing `-c {args[i + 1]}`")
            i += 2
        elif tok.startswith(("--git-dir=", "--work-tree=")) or tok == "--no-optional-locks":
            i += 1
        elif tok.startswith("-"):
            raise GitCustodyRefused(f"git custody: refusing the global option {tok!r}")
        else:
            return args[:i], tok, args[i + 1:]
    raise GitCustodyRefused("git custody: no subcommand")


def _options(rest: list[str]) -> tuple[list[str], list[str]]:
    """`(options, positionals)` of a subcommand's arguments; everything after `--` is positional."""
    opts: list[str] = []
    pos: list[str] = []
    for i, tok in enumerate(rest):
        if tok == "--":
            return opts, pos + rest[i + 1:]
        (opts if tok.startswith("-") and tok != "-" else pos).append(tok)
    return opts, pos


def _only(opts: list[str], allowed: frozenset[str], prefixes: tuple[str, ...] = ()) -> bool:
    return all(o in allowed or (prefixes and o.startswith(prefixes)) for o in opts)


# Subcommands that read or write objects, refs or config and never a working-tree file's content,
# so no attribute-selected driver (filter, textconv, external diff, merge driver) can apply.
_REF_PLUMBING = frozenset({"rev-parse", "symbolic-ref", "update-ref", "merge-base", "show-ref", "for-each-ref"})
_STATUS_OPTS = frozenset({"--porcelain", "--porcelain=v1", "-z", "--short", "-s", "--untracked-files=all",
                          "--untracked-files=normal", "--untracked-files=no", "-uall", "-unormal", "-uno"})


def _custody_kind(sub: str, rest: list[str]) -> str:
    """How the custody runs `git <sub> <rest>`: "direct" (it applies no attribute-selected driver),
    "status" / "merge-tree" (run against a coordinator-built git dir), or refused. A checkout is
    never run here: checkout_worktree does it, anchored to the provider's own repository."""
    opts, pos = _options(rest)
    kind = ""
    if sub in _REF_PLUMBING:
        kind = "direct"
    elif sub == "fetch":
        # From an absolute path only: a remote NAME brings `remote.<name>.uploadpack`, a program the
        # shared config names (git never reads a remote named by a path starting with `/`).
        if pos[:1] and pos[0].startswith("/") and _only(opts, frozenset({"--quiet", "-q", "--no-tags", "--no-write-fetch-head",
                                                                         "--no-recurse-submodules", "--no-auto-maintenance"})):
            kind = "direct"
    elif sub == "clone":
        # From an absolute path, checking nothing out; `--upload-pack`/`--template`/`--recurse-submodules` refused.
        if pos[:1] and pos[0].startswith("/") and _only(opts, frozenset({"--bare", "--mirror", "--no-checkout", "-n",
                                                                         "--no-local", "--quiet", "-q"})):
            kind = "direct" if {"--bare", "--mirror", "--no-checkout", "-n"} & set(opts) else ""
    elif sub == "remote":
        kind = "direct" if pos[:1] in (["remove"], ["rm"]) and not opts else ""
    elif sub == "config":
        kind = "direct" if _only(opts, frozenset({"--get", "--unset", "--list", "-l", "-z", "--null", "--name-only"})) else ""
    elif sub == "worktree":
        action = pos[0] if pos else ""
        if action in ("list", "prune"):
            kind = "direct"
        elif action == "add" and "--no-checkout" in opts:  # checkout_worktree runs the checkout
            kind = "direct" if _only(opts, frozenset({"--no-checkout", "-b", "--detach", "-q", "--quiet"})) else ""
        elif action == "remove" and _only(opts, frozenset({"--force", "-f"})) and opts:
            kind = "direct"  # only forced: an unforced remove runs `status` in the worktree
    elif sub == "read-tree":
        kind = "direct" if _only(opts, frozenset({"--empty"})) else ""  # no -u/-m/--reset/-i: no worktree, zero stat
    elif sub == "ls-files":
        kind = "direct" if _only(opts, frozenset({"-s", "--stage", "-z", "-o", "--others", "--exclude-standard",
                                                  "--full-name", "--cached", "-c"})) else ""
    elif sub == "log":
        kind = "direct" if _only(opts, frozenset({"-n", "-z", "--end-of-options", "--no-show-signature"}),
                                 ("--format=", "--pretty=", "--max-count=", "-1", "-2", "-3", "-4", "-5",
                                  "-6", "-7", "-8", "-9")) else ""
    elif sub == "reset":
        if "--soft" in opts and _only(opts, frozenset({"--soft", "-q", "--quiet"})):
            kind = "direct"  # moves HEAD only: reads no working-tree file
    elif sub == "status":
        kind = "status" if not pos and _only(opts, _STATUS_OPTS) else ""
    elif sub == "merge-tree":
        if "--write-tree" in opts and len(pos) == 2 and _only(opts, frozenset({"--write-tree", "--name-only", "-z",
                                                                               "--messages", "--no-messages"})):
            kind = "merge-tree"
    if not kind:
        raise GitCustodyRefused(
            f"git custody: refusing `git {sub} {' '.join(rest)}`: it could run a filter, diff or merge "
            "driver the repository names, and the coordinator runs no such command")
    return kind


def _direct(args: list[str], cwd: str | Path | None, base: dict[str, str], timeout: float,
            input: bytes | None = None, extra_blanks: list[tuple[str, str]] = []) -> subprocess.CompletedProcess:
    """One git child: gitexec's absolute git and floor plus PROVIDER_FLOOR (config) and
    PROVIDER_FLOOR_ENV (environment the floor sets that no config can outrank); stdin closed; output
    captured as BYTES (never decoded here: a `\\r` or a non-UTF-8 byte in a path survives). The
    drivers the config declares where it runs are blanked too, a belt for the direct commands
    (which apply none) and empty for a custody git dir (which declares none). `extra_blanks` adds
    the custody call's data-only `core.*` fidelity pairs (_custody_settings)."""
    repo, git_dir = git_location(args, cwd)
    blanks = [*gitexec.driver_blanks(repo, git_dir=git_dir, base=base), *PROVIDER_FLOOR, *extra_blanks]
    feed: dict[str, Any] = {"input": input} if input is not None else {"stdin": subprocess.DEVNULL}
    env = gitexec.env(base, blanks=blanks)
    env.update(PROVIDER_FLOOR_ENV)
    return subprocess.run(gitexec.argv(*args), cwd=cwd, capture_output=True, env=env, timeout=timeout, **feed)


def _line(out: str | bytes) -> Any:
    """One value git printed: its trailing newline removed and nothing else (a path may end in a
    space, `\\r` or `\\t`, which `.strip()` would cut)."""
    return out[:-1] if out[-1:] in ("\n", b"\n") else out


def _rev_parse(lead: list[str], cwd: str | Path | None, base: dict[str, str], timeout: float, *args: str) -> str | None:
    proc = _direct([*lead, "rev-parse", *args], cwd, base, timeout)
    return os.fsdecode(_line(proc.stdout)) if proc.returncode == 0 and proc.stdout else None


_c_quote = gitexec._c_quote
_read_regular = gitexec._read_regular
_copy_regular = gitexec._copy_regular
_custody_git_dir = gitexec.custody_git_dir


def _custody_settings(lead: list[str], cwd: str | Path | None, base: dict[str, str], timeout: float) -> list[tuple[str, str]]:
    """gitexec.custody_settings for the repository `lead`/`cwd` names, read through `_direct`: the
    data-only `core.*` pairs a custody call carries, after refusing an `extensions.*` the custody
    git dir cannot honour (a partial clone above all; PR #720 Codex round 4)."""
    return gitexec.custody_settings(lambda args: _direct([*lead, *args], cwd, base, timeout))


def _custody_attributes(lead: list[str], cwd: str | Path | None, base: dict[str, str], timeout: float,
                        top: str) -> bytes | None:
    """gitexec.custody_attributes for the repository `lead`/`cwd` names: the CONTENT of its own
    core.attributesFile (read only as a bounded regular file, never blocking), carried as data so a
    custody `status`/`read-tree` normalises as the repository does; anything else refuses."""
    return gitexec.custody_attributes(lambda args: _direct([*lead, *args], cwd, base, timeout), top)


def _repo_facts(lead: list[str], cwd: str | Path | None, base: dict[str, str], timeout: float) -> dict[str, str | None]:
    return gitexec.custody_facts(lambda args: _direct([*lead, *args], cwd, base, timeout))


def registered_admin_dir(common: str, wt: str | Path) -> str:
    """The one admin entry under `<common>/worktrees/` whose `gitdir` back-pointer (written by
    `git worktree add`) names `<wt>/.git`: the repository's own record of a linked worktree, found
    from the repository the provider names, never through the worktree's own `.git` pointer (the
    worker's to rewrite, W4-08). None or several is a refusal."""
    want = os.path.realpath(os.path.join(str(wt), ".git"))
    base = os.path.join(common, "worktrees")
    found = []
    for name in sorted(os.listdir(base)) if os.path.isdir(base) else []:
        entry = os.path.join(base, name)
        if os.path.islink(entry) or not os.path.isdir(entry):
            continue
        try:
            back = _read_regular(os.path.join(entry, "gitdir"))
        except GitCustodyRefused:
            continue  # not a record git wrote; it cannot vouch for anything
        if back is not None and os.path.realpath(os.fsdecode(_line(back[0]))) == want:
            found.append(entry)
    if len(found) != 1:
        raise GitCustodyRefused(f"git custody: {len(found)} admin entries in {base!r} record {str(wt)!r}")
    return found[0]


def _install_index(src: str, gitdir: str) -> None:
    """Replace `<gitdir>/index` with `src` under git's own `index.lock` protocol, mtime kept."""
    got = _read_regular(src)
    if got is None:
        raise GitCustodyRefused("git custody: the checkout wrote no index")
    lock = os.path.join(gitdir, "index.lock")
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o666)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(got[0])
        os.utime(lock, ns=(got[1].st_atime_ns, got[1].st_mtime_ns))
        os.replace(lock, os.path.join(gitdir, "index"))
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(lock)
        raise


def run_git(args: list[str], *, cwd: str | Path | None = None, env: dict[str, str] | None = None,
            timeout: float = 120, input: bytes | None = None) -> subprocess.CompletedProcess:
    """Every coordinator-side git the providers run (posix `_git`, the adapters' run_cli/run_cli_text),
    and the only way they run one (W4-01). Output is BYTES; decode with os.fsdecode.

    The coordinator runs git over a repository a worker writes: linked worktrees share one
    `.git/config` and `info/attributes`, and the same-uid `~/.gitconfig` is the worker's too. A
    fixed command key (core.hooksPath, core.fsmonitor, diff.external, PROVIDER_FLOOR's) is
    overridden atomically on git's command line. A name-indexed driver (`filter.<n>.*`,
    `diff.<n>.*`, `merge.<n>.driver`) cannot be: listing the declared names and blanking them
    leaves a window in which a sibling adds a new one (PR #720 Codex round 3). So no command that
    could apply such a driver ever reads the repository's config:

    - direct: plumbing that reads no working-tree content (`_custody_kind`), run as is;
    - `status`, `merge-tree --write-tree`: run against `_custody_git_dir` (the repository's
      objects and index, a config the coordinator wrote); same output, nothing written back;
    - a checkout: checkout_worktree only;
    - anything else (`commit`, `checkout`, `reset --hard`, `diff`, `add`, ...): GitCustodyRefused,
      never run.

    A non-direct command carries NO leading `-c`, including the `safe.directory` /
    `protocol.file.allow` pairs `_split_git_args` lets a direct call pass: the custody runs its
    `status`/`read-tree`/`merge-tree` against the dir it builds, with its own settings, so a caller
    `-c` there is refused. No caller passes one today (the sandbox sync's `-c` pairs ride only its
    direct `rev-parse`/`fetch`/`update-ref`).

    The env the call is handed loses every repository-selecting GIT_* variable (git_call_base)."""
    base = git_call_base(env)
    lead, sub, rest = _split_git_args(list(args))
    kind = _custody_kind(sub, rest)
    if kind == "direct":
        return _direct(list(args), cwd, base, timeout, input)
    if any(tok == "-c" for tok in lead):
        raise GitCustodyRefused(f"git custody: refusing `-c` on the non-direct `git {sub}`")
    facts = _repo_facts(lead, cwd, base, timeout)
    opts, pos = _options(rest)
    if kind == "merge-tree":
        shas = []
        for rev in pos:
            sha = _rev_parse(lead, cwd, base, timeout, "--verify", "-q", "--end-of-options", f"{rev}^{{commit}}")
            if not sha:
                return subprocess.CompletedProcess(args, 128, b"", os.fsencode(f"fatal: {rev!r} is not a commit\n"))
            shas.append(sha)
        _custody_settings(lead, cwd, base, timeout)  # refuse an extension the custody dir cannot honour
        attrs = _custody_attributes(lead, cwd, base, timeout, facts["top"] or git_location(lead, cwd)[0])
        with _custody_git_dir(str(facts["common"]), str(facts["format"]), None, None, attributes=attrs) as gd:
            proc = _direct(["--git-dir", gd, "merge-tree", *opts, *shas], None, base, timeout)
        return subprocess.CompletedProcess(args, proc.returncode, proc.stdout, proc.stderr)
    named = next((lead[i + 1] for i, tok in enumerate(lead[:-1]) if tok == "--work-tree"), None)
    named = os.path.join(git_location(lead, cwd)[0], named) if named else git_location(lead, cwd)[0]
    if not facts["top"] or os.path.realpath(str(facts["top"])) != os.path.realpath(named):
        # The work tree the call names, never one config (`core.worktree`) redirects it to.
        raise GitCustodyRefused(f"git custody: `git {sub}` runs at the top of the work tree it names ({named!r})")
    settings = _custody_settings(lead, cwd, base, timeout)
    attrs = _custody_attributes(lead, cwd, base, timeout, str(facts["top"]))
    with _custody_git_dir(str(facts["common"]), str(facts["format"]), facts["head"], str(facts["gitdir"]),
                          attributes=attrs) as gd:
        # `dirty`: a submodule's recorded commit is compared, its work tree never inspected (that
        # inspection is a child git without the floor, under the submodule's own config).
        proc = _direct(["--git-dir", gd, "--work-tree", str(facts["top"]), "--no-optional-locks", "status",
                        *opts, "--ignore-submodules=dirty"], facts["top"], base, timeout, extra_blanks=settings)
    return subprocess.CompletedProcess(args, proc.returncode, proc.stdout, proc.stderr)


def checkout_worktree(root: str | Path, wt: str | Path, branch: str, *, timeout: float = 120) -> subprocess.CompletedProcess:
    """The checkout a `git worktree add --no-checkout` left out, done by the custody (W4-01): the
    tracked files of `refs/heads/<branch>` written into `wt` and its index installed, as the
    `reset --hard` git would run there, but by `read-tree -u --reset` against `_custody_git_dir`,
    so no filter, hook or driver of any name runs, and none a sibling adds mid-call (PR #720
    Codex round 3). Committed bytes: an LFS or git-crypt file is checked out as its stored pointer
    or ciphertext. Anchored to `root`, the repository the provider names: the common dir, the
    commit and the admin entry (registered_admin_dir) all come from there, never from the new
    worktree's `.git` pointer. Output is bytes; raises GitCustodyRefused (an OSError) when
    anything does not resolve."""
    base = git_call_base(None)
    at_root = ["-C", str(root)]
    common = _rev_parse(at_root, None, base, timeout, "--path-format=absolute", "--git-common-dir")
    fmt = _rev_parse(at_root, None, base, timeout, "--show-object-format")
    head = _rev_parse(at_root, None, base, timeout, "--verify", "-q", "--end-of-options", f"refs/heads/{branch}^{{commit}}")
    if not (common and fmt and head):
        raise GitCustodyRefused(f"git custody: cannot resolve refs/heads/{branch} in {str(root)!r}")
    if os.path.islink(str(wt)) or not os.path.isdir(str(wt)):
        raise GitCustodyRefused(f"git custody: {str(wt)!r} is not a directory to check out into")
    admin = registered_admin_dir(common, wt)
    settings = _custody_settings(at_root, None, base, timeout)
    attrs = _custody_attributes(at_root, None, base, timeout, str(wt))
    with _custody_git_dir(common, fmt, head, admin, attributes=attrs) as gd:
        proc = _direct(["--git-dir", gd, "--work-tree", str(wt), "read-tree", "-u", "--reset", head],
                       str(wt), base, timeout, extra_blanks=settings)
        if proc.returncode == 0:
            _install_index(os.path.join(gd, "index"), admin)
    return proc


def _git(
    args: list[str],
    *,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess:
    """Every git the provider runs, and the only way it runs one: run_git's custody (W4-01), its
    output decoded byte-for-byte (os.fsdecode: a `\\r`, `\\r\\n` or non-UTF-8 byte in a path comes
    back as the same path). A refused or unrunnable call is exit 127 with the reason; gitexec's git
    absent at import is exit 127 too, never a PATH re-resolution."""
    full = [*(["-C", str(cwd)] if cwd else []), *args]
    try:
        proc = run_git(full, env=env, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(full, 127, "", str(exc))
    return subprocess.CompletedProcess(full, proc.returncode, os.fsdecode(proc.stdout), os.fsdecode(proc.stderr))


def _parse_worktree_list(out: str) -> list[tuple[str, str]]:
    """`[(path, branch ref or "")]` from `git worktree list --porcelain -z`: NUL-terminated
    `attribute value` fields, a worktree per `worktree <path>` field, paths raw (never quoted)."""
    entries: list[tuple[str, str]] = []
    for field in out.split("\0"):
        if field.startswith("worktree "):
            entries.append((field[len("worktree "):], ""))
        elif field.startswith("branch ") and entries:
            entries[-1] = (entries[-1][0], field[len("branch "):])
    return entries


def populated_gitlinks(stage_listing: str, worktree: str) -> list[str]:
    """Paths of the submodules (index mode 160000, from `ls-files -s -z`) that are checked out in
    `worktree`, i.e. hold a `.git`. The custody never looks inside one (that is a child git without
    the floor, under the submodule's own config), so a caller counts each as uncommitted work."""
    out = []
    for entry in stage_listing.split("\0"):
        meta, tab, path = entry.partition("\t")
        if tab and meta.startswith("160000 ") and os.path.lexists(os.path.join(worktree, path, ".git")):
            out.append(path)
    return out


def _git_ok(args: list[str], what: str, **kw: Any) -> str:
    proc = _git(args, **kw)
    if proc.returncode != 0:
        raise ProviderError("sandbox_git_failed", f"{what}: {(proc.stderr or proc.stdout or 'git failed').strip()[:300]}")
    return _line(proc.stdout)


def prepare_sandbox_git(wt_path: str, lane_dir: Path) -> dict[str, str]:
    """Build a container-private git dir for a `danger` worker (#591 review issues 1 & "cannot commit").

    The host worktree's `.git` pointer and the host repository are NEVER mounted writable: the
    container gets a bare clone (reachable objects only, `--no-local` so no hardlinks/alternates,
    no host config or hooks) at SANDBOX_GIT_MOUNT with `GIT_DIR`/`GIT_WORK_TREE` pointing at it,
    with HEAD/branch and index matching the worktree. After the container exits, the host-side
    monitor calls `sync_sandbox_git` to bring the worker's commits back.
    """
    wt = Path(wt_path).resolve()
    if not (wt / ".git").is_file():
        raise ProviderError(
            "danger_requires_linked_worktree",
            f"profile='danger' needs a disposable linked git worktree (got {wt}); use --worktree new-child",
        )
    common = Path(_git_ok(["rev-parse", "--path-format=absolute", "--git-common-dir"], "resolve git common dir", cwd=wt))
    wt_gitdir = _git_ok(["rev-parse", "--absolute-git-dir"], "resolve worktree git dir", cwd=wt)
    head = _git_ok(["rev-parse", "--verify", "HEAD^{commit}"], "resolve worktree HEAD", cwd=wt)
    branch_proc = _git(["symbolic-ref", "-q", "HEAD"], cwd=wt)
    branch = branch_proc.stdout.strip() if branch_proc.returncode == 0 else ""
    object_format = _git(["rev-parse", "--show-object-format"], cwd=wt).stdout.strip() or "sha1"
    sandbox = Path(lane_dir) / "sandbox.git"
    if sandbox.exists():
        shutil.rmtree(sandbox)
    _git_ok(["clone", "--bare", "--no-local", "--quiet", str(common), str(sandbox)], "clone sandbox git dir")
    sb = ["--git-dir", str(sandbox)]
    _git(sb + ["remote", "remove", "origin"])
    _git_ok(sb + ["config", "core.bare", "false"], "configure sandbox git dir")
    if branch:
        _git_ok(sb + ["update-ref", branch, head], "pin sandbox branch")
        _git_ok(sb + ["symbolic-ref", "HEAD", branch], "point sandbox HEAD at branch")
    else:
        _git_ok(sb + ["update-ref", "--no-deref", "HEAD", head], "pin sandbox detached HEAD")
    # Index = HEAD; the worktree's uncommitted edits stay as working-tree modifications. A plain
    # `read-tree` (no -m/-u) touches no worktree file and writes zero stat data, so writing it runs
    # no clean filter. The coordinator never refreshes it: a refresh re-hashes worktree files
    # through whatever filter the config names. The worker's own first `git status`, inside the
    # container, refreshes it (W4-01, PR #720 Codex round 3).
    _git_ok(sb + ["--work-tree", str(wt), "read-tree", "HEAD"], "seed sandbox index")
    meta = {
        "sandbox_git": str(sandbox),
        "common_dir": str(common),
        "wt_gitdir": wt_gitdir,
        "worktree": str(wt),
        "branch": branch,
        "base_head": head,
        "object_format": object_format,
    }
    (Path(lane_dir) / "sandbox_git.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return meta


def _sanitize_sandbox_git(meta: dict[str, str]) -> None:
    """Strip anything the untrusted container could have planted before host git reads it.

    Refuses outright if ANY entry in the sandbox git dir is a symlink: a bare repository never
    needs one, and following one would let the container aim a host-side write (config) or
    delete (rmtree) at an arbitrary host path. A nested `.git` is removed because upload-pack
    resolves `<path>/.git` BEFORE `<path>` — a decoy repo there would choose what is fetched.
    """
    sandbox = Path(meta["sandbox_git"])
    if sandbox.is_symlink() or not sandbox.is_dir():
        raise ProviderError("sandbox_git_tampered", f"sandbox git dir {sandbox} is missing or a symlink")
    for dirpath, dirnames, filenames in os.walk(sandbox, followlinks=False):
        for name in dirnames + filenames:
            if os.path.islink(os.path.join(dirpath, name)):
                raise ProviderError(
                    "sandbox_git_tampered",
                    f"sandbox git dir contains a symlink ({os.path.relpath(os.path.join(dirpath, name), sandbox)}); refusing to sync",
                )
    for sub in (".git", "hooks", "commondir", "gitdir", "objects/info/alternates", "objects/info/http-alternates", "info/attributes"):
        target = sandbox / sub
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()
    fmt = meta.get("object_format") or "sha1"
    cfg = "[core]\n\trepositoryformatversion = {v}\n\tbare = true\n".format(v=1 if fmt != "sha1" else 0)
    if fmt != "sha1":
        cfg += f"[extensions]\n\tobjectformat = {fmt}\n"
    cfg_path = sandbox / "config"
    if cfg_path.exists():
        cfg_path.unlink()
    fd = os.open(cfg_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(cfg)


def sync_sandbox_git(meta: dict[str, str], dispatch_id: str) -> dict[str, Any]:
    """Host-side: fetch a finished sandbox's HEAD back into the host repository.

    Always records `refs/open-fleet/sandbox/<dispatch>` (the coordinator verifies that SHA); the
    worker's branch is only fast-forwarded, never rewritten, and the host worktree's index is
    reset to the new HEAD (`read-tree`, zero stat data) so `git status` there reflects it. A
    non-fast-forward (the worker rewrote history) leaves the branch untouched and reports
    `nonFastForward`. The fetch runs only the local file transport (PROVIDER_FLOOR), so a
    shared-config `url.<base>.insteadOf` that rewrites the sandbox path fails the sync closed.
    """
    _sanitize_sandbox_git(meta)
    sandbox = meta["sandbox_git"]
    safe = ["-c", f"safe.directory={sandbox}", "-c", "protocol.file.allow=always"]
    new_head = _git_ok(safe + ["--git-dir", sandbox, "rev-parse", "--verify", "HEAD^{commit}"], "read sandbox HEAD")
    ref = f"refs/open-fleet/sandbox/{dispatch_id}"
    common = meta["common_dir"]
    _git_ok(
        safe + ["--git-dir", common, "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", sandbox, f"+HEAD:{ref}"],
        "fetch sandbox commits",
    )
    fetched = _git_ok(["--git-dir", common, "rev-parse", "--verify", f"{ref}^{{commit}}"], "read fetched sandbox ref")
    if fetched != new_head:
        _git(["--git-dir", common, "update-ref", "-d", ref])
        raise ProviderError(
            "sandbox_git_tampered",
            f"fetched {fetched} but the sandbox HEAD is {new_head}; refusing to record a ref the coordinator would verify",
        )
    res: dict[str, Any] = {"head": new_head, "sandboxRef": ref, "branchUpdated": False, "nonFastForward": False}
    branch = meta.get("branch") or ""
    if not branch:
        return res
    old = _git_ok(["--git-dir", common, "rev-parse", "--verify", branch], "read host branch")
    if old == new_head:
        return res
    if _git(["--git-dir", common, "merge-base", "--is-ancestor", old, new_head]).returncode != 0:
        res["nonFastForward"] = True
        return res
    _git_ok(["--git-dir", common, "update-ref", branch, new_head, old], "fast-forward host branch")
    # Explicit git dir: never trust the (container-writable) worktree's `.git` pointer. The index
    # becomes the new HEAD by a plain `read-tree`: zero stat data, no worktree file read, so no
    # clean filter the SHARED config names can run (a mixed `reset` refreshed through one, W4-01).
    # Best-effort: a failure leaves the index stale, and the worker's next `git status` shows it.
    _git(["--git-dir", meta["wt_gitdir"], "read-tree", new_head])
    res["branchUpdated"] = True
    return res


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
        start = Path(
            repo_root
            or self.env.get("OPEN_FLEET_REPO_ROOT")
            or env_get("OPEN_FLEET_CLI_CWD", "ORCA_CLI_CWD", self.env, os.getcwd())
        ).resolve()
        if repo_root is None and not self.env.get("OPEN_FLEET_REPO_ROOT"):
            # Invoked from a subdirectory: the repository is the git top-level, not the cwd.
            top = _git(["rev-parse", "--show-toplevel"], cwd=start) if start.is_dir() else None
            if top is not None and top.returncode == 0 and _line(top.stdout):
                start = Path(_line(top.stdout)).resolve()
        self.repo_root = start
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

    # --- Task DAG & Mailbox delegate directly to LocalStateStore ---
    def task_create(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_create(**kwargs)

    def task_update(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_update(**kwargs)

    def task_list(self, **kwargs: Any) -> dict[str, Any]:
        return self.state.task_list(**kwargs)

    def request_show(self, request_id: str) -> dict[str, Any]:
        return self.state.request_show(request_id)

    def send_message(self, *, retry_request: str | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.state.send_message(retry_request=retry_request, **kwargs)

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

    def _is_disposable(self, path: Path) -> bool:
        """True only for paths this provider created under its own worktree base dir."""
        base = self._worktree_base_dir().resolve()
        try:
            rel = path.resolve().relative_to(base)
        except ValueError:
            return False
        return bool(rel.parts)

    def worktree_create(self, name: str, base: str | None = None, repo: str | None = None) -> dict[str, Any]:
        root = Path(repo).resolve() if repo else self.repo_root
        slug = _worktree_slug(name) or f"wt-{uuid.uuid4().hex[:6]}"
        wt_path = self._worktree_base_dir() / slug
        branch = f"fleet/{slug}"
        is_git = (root / ".git").exists()
        if wt_path.exists():
            if is_git:
                # A reused directory must really be a worktree of this repository, not a stale
                # leftover that would launch a worker without the project files.
                top = _git(["rev-parse", "--show-toplevel"], cwd=wt_path)
                common = _git(["rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=wt_path)
                root_common = _git(["rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=root)
                if (
                    top.returncode != 0
                    or Path(_line(top.stdout)).resolve() != wt_path.resolve()
                    or _line(common.stdout) != _line(root_common.stdout)
                ):
                    raise ProviderError(
                        "worktree_create_failed",
                        f"{wt_path} exists but is not a worktree of {root}; remove it or choose another name",
                    )
        elif is_git:
            _git(["worktree", "prune"], cwd=root)
            exists = _git(["rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"], cwd=root).returncode == 0
            # `--` ends the options: a `--base` that starts with `-` is a commit-ish, never a flag (W2-04).
            if exists:
                # Never `-B`: resetting an existing branch silently discards its unmerged commits.
                cmd = ["worktree", "add", "--no-checkout", "--", str(wt_path), branch]
            else:
                cmd = ["worktree", "add", "--no-checkout", "-b", branch, "--", str(wt_path)] + ([base] if base else [])
            proc = _git(cmd, cwd=root)
            if proc.returncode != 0:
                raise ProviderError(
                    "worktree_create_failed",
                    (proc.stderr or proc.stdout or f"git worktree add failed for {slug}").strip(),
                )
            # The checkout `worktree add` would run (its `reset --hard`) is checkout_worktree's:
            # `read-tree -u --reset` against a git dir the coordinator built (the shared objects, a
            # config with no driver), the index installed into the admin entry the repository
            # records for this path. Committed bytes; no filter, hook or driver of any name (W4-01).
            try:
                done = checkout_worktree(root, wt_path, branch)
                why = None if done.returncode == 0 else os.fsdecode(done.stderr or done.stdout).strip()
            except (OSError, subprocess.SubprocessError) as exc:
                why = str(exc)
            if why is not None:
                _git(["worktree", "remove", "--force", "--", str(wt_path)], cwd=root)
                raise ProviderError("worktree_create_failed", why or f"checkout of {slug} failed")
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
            proc = _git(["worktree", "list", "--porcelain", "-z"], cwd=root)
            if proc.returncode == 0:
                for current_path, branch in _parse_worktree_list(proc.stdout):
                    row = {"id": f"{root.name}::{current_path}", "displayName": Path(current_path).name,
                           "path": current_path}
                    if branch:
                        row["branch"] = branch.removeprefix("refs/heads/")
                    rows.append(row)
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

    @staticmethod
    def _linked_worktrees(root: Path) -> set[Path]:
        """Resolved paths of `root`'s LINKED worktrees, from the repository's own admin entries
        (`worktree list`; the first entry is the main checkout); empty for a root with no `.git`.
        A list git cannot produce (a malformed shared config makes it die; a git older than 2.36
        has no `-z`) is a refusal, never "none registered": that answer sent a registered worktree
        with a deleted pointer to rmtree, its admin entry left behind (W4-08, PR #720 review).
        `-z` because without it a path holding a newline or another character git quotes came back
        split or quoted, matched nothing, and read as unregistered (PR #720 Codex round 2)."""
        if not (root / ".git").exists():
            return set()
        proc = _git(["worktree", "list", "--porcelain", "-z"], cwd=root)
        if proc.returncode != 0:
            raise ProviderError(
                "worktree_list_unreadable",
                f"cannot read {root}'s worktree list, so whether the target is a registered worktree "
                f"is unknown; refusing to remove anything: {(proc.stderr or proc.stdout).strip()[:300]}",
            )
        return {Path(path).resolve() for path, _ in _parse_worktree_list(proc.stdout)[1:]}

    @staticmethod
    def _refuse_unclean(wt_path: Path, common: str) -> None:
        """`worktree_dirty` unless `wt_path` is clean the way git's own `worktree remove` check
        reads it: no populated submodule (git refuses those outright), and an empty `status` with
        untracked files. Both run against the worktree's admin entry as the repository records it
        (its `gitdir` back-pointer), never discovered through the tree's own `.git` pointer."""
        try:
            admin = registered_admin_dir(common, wt_path)
        except GitCustodyRefused as exc:
            raise ProviderError("worktree_rm_failed", f"cannot tell whether {wt_path} is clean: {exc}") from exc
        where = ["--git-dir", admin, "--work-tree", str(wt_path)]
        staged = _git([*where, "ls-files", "-s", "-z"])
        status = _git([*where, "status", "--porcelain", "-z", "--untracked-files=all"])
        for proc in (staged, status):
            if proc.returncode != 0:
                raise ProviderError("worktree_rm_failed", f"cannot read {wt_path}'s state: {(proc.stderr or proc.stdout).strip()[:300]}")
        if populated_gitlinks(staged.stdout, str(wt_path)):
            raise ProviderError("worktree_dirty", f"{wt_path}: working trees containing submodules cannot be moved or removed")
        if status.stdout:
            raise ProviderError("worktree_dirty", f"'{wt_path}' contains modified or untracked files, use --force to delete it")

    def worktree_rm(self, selector: str, force: bool = False) -> dict[str, Any]:
        if not selector:
            raise ProviderError("invalid_argument", "worktree rm needs a worktree selector")
        shown = self.worktree_show(selector)["worktree"]
        wt_path = Path(shown["path"]).resolve()
        worker_run = self.state._worker_bound_run()
        if worker_run:
            with self.state._connect() as conn:
                owned_wt = conn.execute(
                    "SELECT 1 FROM dispatches WHERE worktree = ? AND run_id = ? LIMIT 1",
                    (str(wt_path), worker_run),
                ).fetchone()
            if owned_wt is None:
                raise ProviderError(
                    "cross_run_access",
                    f"launched worker in run {worker_run!r} cannot remove worktree {wt_path!r} outside its run",
                )
        repo_root = self.repo_root.resolve()
        common = _line(_git(["rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=repo_root).stdout)
        protected = {repo_root, Path.home().resolve(), Path("/").resolve()}
        if common:
            protected.add(Path(common).resolve())
            protected.add(Path(common).resolve().parent)
        if wt_path in protected or any(wt_path == p or p.is_relative_to(wt_path) for p in protected if p != Path("/")):
            raise ProviderError("worktree_protected", f"refusing to remove {wt_path}: it is (or contains) the main checkout")
        if not wt_path.exists():
            return {"removed": False, "id": shown["id"], "reason": "absent"}
        # W4-08: whether this is a linked worktree is the REPOSITORY's record, read once from its
        # own admin entries — never the `.git` pointer inside the tree, which the worker rewrites
        # at will (deleted, it steered a forced removal onto the rmtree branch below and left the
        # admin entry and branch registered to a tree that was gone). A registered worktree is
        # git's to remove: `worktree remove` checks that pointer against its own admin entry and
        # refuses a missing or foreign one. Anything unregistered takes the plain-directory branch.
        is_linked = wt_path in self._linked_worktrees(repo_root)
        if is_linked:
            if not force:
                self._refuse_unclean(wt_path, common)
            # Always `--force` to git: an unforced `worktree remove` runs its own clean check as a
            # `status` child under the repository's config, so the check above (run_git's custody
            # `status`, no driver of any name) is the one that decides. git still refuses a locked
            # worktree and a pointer that does not match its admin entry (W4-01, W4-08).
            proc = _git(["worktree", "remove", "--force", "--", str(wt_path)], cwd=repo_root)
            if proc.returncode != 0:
                # Never fall back to rmtree: git refused for a reason (dirty tree, main worktree,
                # locked) and deleting anyway discards the unit's unsaved work (#591 review).
                raise ProviderError(
                    "worktree_dirty" if not force else "worktree_rm_failed",
                    (proc.stderr or proc.stdout or f"git worktree remove refused {wt_path}").strip(),
                )
            return {"removed": True, "id": shown["id"]}
        if not self._is_disposable(wt_path):
            raise ProviderError("worktree_protected", f"refusing to delete {wt_path}: not a worktree this provider created")
        if (wt_path / ".git").exists():
            raise ProviderError("worktree_protected", f"refusing to delete {wt_path}: it holds its own git repository")
        if any(wt_path.iterdir()) and not force:
            raise ProviderError("worktree_dirty", f"{wt_path} is not empty; pass --force to delete it")
        shutil.rmtree(wt_path)
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
        supervised: bool = True,
        sandbox_meta: dict[str, str] | None = None,
        ro_relay: str = "",
    ) -> dict[str, Any]:
        log_file = lane_dir / "events.jsonl"
        log_file.touch(mode=0o600)  # the worker's whole transcript: tool output can carry secrets
        # Fleet custody secrets never reach a worker (it could sign its own dispatches), nor
        # does anything the operator named in OPEN_FLEET_WORKER_ENV_DENY.
        deny = worker_env_deny_patterns(self.env)
        merged_env = strip_denied_env({**self.env, **env_vars}, deny)

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
        # The worker's launch environment travels IN the monitor script: a tmux/cmux server that
        # is already running ignores the client's environment, which silently dropped the hook
        # path and the ro safety settings (#591 review). Only the explicit launch vars are
        # written (mode 0600) — never the coordinator's whole environment. PATH is one of them:
        # without it the agent resolved on the multiplexer server's PATH (or one its shell rc
        # rewrote) and a stale server ran a different `claude` (2026-10-23 review, P1-11).
        launch_env = {"PATH": merged_env.get("PATH") or os.defpath, **env_vars}
        env_file = lane_dir / "worker_env.json"
        env_file.write_text(json.dumps(launch_env, sort_keys=True), encoding="utf-8")
        os.chmod(env_file, 0o600)
        # A multiplexer server this spawn starts keeps its client's env for EVERY later
        # session: hand it the coordinator's env only, never this worker's launch vars, which
        # would otherwise leak into the next worker launched into that server (P1-11).
        mux_env = strip_denied_env(self.env, deny)
        monitor_py = f"""
import fnmatch, json, os, subprocess, sys, time
sys.path.insert(0, {repr(str(RUNTIME_DIR))})
from providers.local_state import LocalStateStore

DISPATCH = {repr(dispatch_id)}
SUPERVISED = {supervised!r}
RO_RELAY = {ro_relay!r}
SANDBOX_META = {repr(json.dumps(sandbox_meta) if sandbox_meta else "")}
log_path = {repr(str(log_file))}
store = LocalStateStore(db_path={repr(str(self.state.db_path))})
with open({repr(str(env_file))}, encoding="utf-8") as ef:
    worker_env = {{**os.environ, **json.load(ef)}}
# A tmux/cmux server started with fleet custody secrets hands them to this monitor's
# environment: strip them from the FINAL worker env too, not only the client's (#592).
for _pattern in {deny!r}:
    for _k in [k for k in worker_env if fnmatch.fnmatchcase(k, _pattern)]:
        worker_env.pop(_k, None)

def _log(obj):
    with open(log_path, "a", encoding="utf-8") as lf:
        lf.write(json.dumps(obj) + "\\n")

# Launch gate: a dispatch fenced while it was starting never runs its agent (#591 review), and
# it is a compare-and-set, so ONE monitor ever runs it: a late monitor from a dead coordinator's
# launcher loses to the one recovery adopted, or to recovery abandoning the dispatch (#597).
# A fence before any claim closes the gate for good: a later retain never reopens it.
MONITOR_PID = os.getpid()
if SUPERVISED and not store.claim_monitor(DISPATCH, MONITOR_PID):
    _log({{"type": "launch_refused", "dispatchId": DISPATCH, "reason": store.gate_refusal(DISPATCH)}})
    sys.exit(0)

with open(log_path, "a", encoding="utf-8") as lf:
    lf.write(json.dumps({{"type": "turn_started", "dispatchId": DISPATCH, "monitorPid": MONITOR_PID}}) + "\\n")
    lf.flush()
    proc = subprocess.Popen(
        {repr(command)},
        shell=True,
        cwd={repr(wt_path)},
        env=worker_env,
        stdout=lf,
        stderr=subprocess.STDOUT,
    )
    rc = proc.wait()

head = ""
if SANDBOX_META:
    # The worker's commits live only in the sandbox git dir until this sync copies them
    # back: a stop (tmux SIGHUP, killpg SIGTERM) must not cut it short (#592 review).
    import signal
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        from providers.posix import sync_sandbox_git
        synced = sync_sandbox_git(json.loads(SANDBOX_META), DISPATCH)
        head = synced.get("head", "")
        _log({{"type": "sandbox_git_synced", **synced}})
    except Exception as exc:
        _log({{"type": "sandbox_git_sync_failed", "error": str(exc)[:500]}})
else:
    try:
        # The provider's own git (gitexec's absolute git and floor, W4-01), never a bare `git`.
        from providers.posix import _git
        head = _git(["rev-parse", "HEAD"], cwd={repr(wt_path)}, timeout=15).stdout.strip()
    except Exception:
        head = ""
try:
    with open({repr(str(lane_dir / "exit.json"))}, "w", encoding="utf-8") as xf:
        json.dump({{"rc": rc, "ts": time.time(), "headSha": head, "monitorPid": MONITOR_PID}}, xf)
except OSError:
    pass
tail = ""
try:
    with open(log_path, "r", encoding="utf-8", errors="replace") as rf:
        tail = rf.read()[-500:]
except Exception:
    pass
if SUPERVISED and RO_RELAY and rc == 0:
    # A ro worker has no tool to send mail; its completion line rides its own output (#596).
    # A crash (rc != 0) stays a death whatever it printed.
    try:
        from providers.posix import relay_ro_completion
        relay_ro_completion(store, dispatch_id=DISPATCH, worker_handle={repr(term_handle)}, agent=RO_RELAY,
                            run_id={repr(run_id)}, log_path=log_path, head_sha=head)
    except Exception as exc:
        _log({{"type": "ro_relay_failed", "dispatchId": DISPATCH, "error": str(exc)[:500]}})
with store._connect() as conn:
    conn.execute("UPDATE terminals SET state = 'exited' WHERE handle = ? AND state = 'running'", ({repr(term_handle)},))
    # Release the gate BEFORE the final state write (exit.json above already records the run;
    # monitor_started_at keeps proving a monitor ran). Its last write stays the dispatch state.
    conn.execute("UPDATE dispatches SET monitor_pid = 0 WHERE dispatch_id = ? AND monitor_pid = ?", (DISPATCH, MONITOR_PID))
    bound = conn.execute(
        "SELECT dispatch_id, run_id FROM dispatches WHERE terminal_handle = ? AND dispatch_id != ? AND state IN ('ready', 'running')",
        ({repr(term_handle)}, DISPATCH),
    ).fetchall()
if SUPERVISED:
    store.ensure_terminal_or_died(
        dispatch_id=DISPATCH,
        worker_handle={repr(term_handle)},
        exit_code=rc,
        last_tail=tail,
        worktree_head_sha=head,
        run_id={repr(run_id)},
    )
for row in bound:
    # Work injected into this terminal dies with it (dispatch --inject, #591 re-review).
    store.ensure_terminal_or_died(
        dispatch_id=row["dispatch_id"],
        worker_handle={repr(term_handle)},
        exit_code=rc,
        last_tail=tail,
        worktree_head_sha=head,
        run_id=row["run_id"],
    )
if {repr(self.backend)} == "cmux":
    subprocess.run(["cmux", "wait-for", "-S", {repr(chan)}], capture_output=True)
"""
        runner_script = lane_dir / "run_worker.py"
        runner_script.write_text(monitor_py, encoding="utf-8")
        os.chmod(runner_script, 0o600)
        py_bin = os.environ.get("PYTHON", "python3")
        # The monitor interpreter is resolved here too, not by the server's shell (P1-11).
        py_bin = shutil.which(py_bin, path=launch_env["PATH"]) or py_bin
        # `-I`: never import from the (worker-writable) cwd or honour PYTHON* env.
        wrapped_monitor = f"{shlex.quote(py_bin)} -I {shlex.quote(str(runner_script))}"

        if self.backend == "cmux":
            proc = subprocess.run(
                ["cmux", "new-workspace", "--cwd", wt_path, "--command", wrapped_monitor],
                capture_output=True,
                text=True,
                env=mux_env,
            )
            if proc.returncode != 0:
                raise ProviderError("spawn_failed", (proc.stderr or proc.stdout or "cmux new-workspace failed").strip())
            ref = _parse_cmux_workspace_ref(proc.stdout)
            if not ref:
                raise ProviderError("spawn_failed", f"cmux new-workspace returned no workspace id: {proc.stdout[:200]!r}")
            return {"pid": 0, "backend": "cmux", "channel": chan, "backendRef": ref}

        if self.backend == "tmux":
            sess_name = f"openfleet-{term_handle}"
            proc = subprocess.run(
                ["tmux", "new-session", "-d", "-s", sess_name, "-c", wt_path, wrapped_monitor],
                capture_output=True,
                text=True,
                env=mux_env,
            )
            if proc.returncode != 0:
                raise ProviderError("spawn_failed", (proc.stderr or proc.stdout or "tmux new-session failed").strip())
            pane = subprocess.run(
                ["tmux", "display-message", "-p", "-t", sess_name, "#{pane_pid}"],
                capture_output=True,
                text=True,
            )
            pane_pid = int(pane.stdout.strip()) if pane.returncode == 0 and pane.stdout.strip().isdigit() else 0
            return {"pid": pane_pid, "backend": "tmux", "session": sess_name, "backendRef": sess_name}

        # Double-fork: a short-lived launcher starts the monitor in its own session and exits,
        # so the monitor is reparented to init (reaped on exit, never a zombie of the caller).
        launcher = (
            "import subprocess, sys\n"
            "p = subprocess.Popen(sys.argv[1:], start_new_session=True, stdin=subprocess.DEVNULL,"
            " stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "print(p.pid, flush=True)\n"
        )
        proc = subprocess.run(
            [py_bin, "-I", "-c", launcher, py_bin, "-I", str(runner_script)],
            cwd=str(lane_dir),
            env=merged_env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        pid_text = proc.stdout.strip()
        if proc.returncode != 0 or not pid_text.isdigit():
            raise ProviderError("spawn_failed", (proc.stderr or proc.stdout or "setsid launch failed").strip()[:300])
        return {"pid": int(pid_text), "backend": "setsid"}

    def _docker_command(
        self,
        *,
        image: str,
        wt_path: str,
        inner: str,
        env: dict[str, str],
        dispatch_id: str,
        sandbox_meta: dict[str, str],
    ) -> tuple[str, str]:
        # `-e K=v` is a word in a `sh -c` line: a key that is not a shell identifier is refused (W2-02).
        check_env_keys(env)
        container = f"openfleet-{dispatch_id}"
        user = self.env.get("OPEN_FLEET_SANDBOX_USER")
        if user is None:
            user = f"{os.getuid()}:{os.getgid()}"
        runtime_dir = str(RUNTIME_DIR)
        mounts = [
            f"-v {shlex.quote(wt_path)}:{shlex.quote(wt_path)}",
            # The worktree's `.git` pointer is read-only: the container cannot redirect host git.
            f"-v {shlex.quote(str(Path(wt_path) / '.git'))}:{shlex.quote(str(Path(wt_path) / '.git'))}:ro",
            f"-v {shlex.quote(sandbox_meta['sandbox_git'])}:{SANDBOX_GIT_MOUNT}",
            # The guard lives outside the worktree and is read-only inside the sandbox.
            f"-v {shlex.quote(runtime_dir)}:{shlex.quote(runtime_dir)}:ro",
        ]
        env_flags = " ".join(f"-e {k}={shlex.quote(str(v))}" for k, v in sorted(env.items()))
        flags = (
            f"docker run --rm --init --name {container} -w {shlex.quote(wt_path)} "
            "--cap-drop ALL --security-opt no-new-privileges --pids-limit 512 "
            + (f"--user {shlex.quote(user)} " if user else "")
        )
        cmd = f"{flags}{' '.join(mounts)} {env_flags} {shlex.quote(image)} sh -c {shlex.quote(inner)}"
        return cmd, container

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
        effort: str | None = None,
    ) -> dict[str, Any]:
        check_monotonic_profile(parent_profile, profile)
        sandbox_recipe = on_env or env_get("OPEN_FLEET_SANDBOX_RECIPE", "ORCA_SANDBOX_RECIPE", self.env, "")
        if profile == "danger" and not sandbox_recipe:
            raise ProviderError(
                "danger_requires_sandbox",
                "profile='danger' requires --on <env> or OPEN_FLEET_SANDBOX_RECIPE isolated sandbox placement",
            )
        if profile == "danger" and worktree in ("current", "active"):
            raise ProviderError(
                "danger_requires_linked_worktree",
                "profile='danger' never runs in the main checkout; use --worktree new-child",
            )
        eff_run = self.state._resolve_caller_run(run, default_run=None)
        with self.state._connect() as conn:
            t_pre = conn.execute("SELECT run_id FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if t_pre is not None and eff_run is not None and t_pre["run_id"] != eff_run:
            raise ProviderError(
                "cross_run_access",
                f"task {task_id!r} belongs to run {t_pre['run_id']!r}, not {eff_run!r}",
            )
        payload_sha = _launch_payload_sha256(
            {
                "task": task_id,
                "worktree": worktree,
                "agent": agent,
                "name": name,
                "run": run,
                "profile": profile,
                "parentProfile": parent_profile or "",
                "prompt": prompt,
                "effort": effort,
                "sandbox": sandbox_recipe if profile == "danger" else "",
                "retryOf": retry_of,
            }
        )
        if retry_request:
            replay = self._replay_worker_start(retry_request, payload_sha, eff_run=eff_run)
            if replay is not None:
                return replay

        # A dead coordinator's unfinished launch of THIS task is settled before a new claim (#597).
        self._reconcile_dead_intents(task_id=task_id, run_id=eff_run)
        with self.state._connect() as conn:
            t_row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not t_row:
            raise ProviderError("task_not_found", f"task {task_id!r} not found")
        if eff_run is not None and t_row["run_id"] != eff_run:
            raise ProviderError(
                "cross_run_access",
                f"task {task_id!r} belongs to run {t_row['run_id']!r}, not {eff_run!r}",
            )
        run_id = t_row["run_id"] or "default"
        if t_row["status"] != "ready":
            raise self._not_startable(task_id, t_row["status"])
        spec_text = self.resolve_task_prompt(task_id, prompt if prompt is not None else t_row["spec"])

        intent_id = f"li_{uuid.uuid4().hex[:12]}"
        lease = _IntentLease(self._intent_lock_path(intent_id))
        if not lease.try_acquire():
            lease.release(unlink=False)
            raise ProviderError("launch_lease_unavailable", f"could not lock {lease.path}")
        try:
            return self._launch(
                intent_id=intent_id,
                payload_sha=payload_sha,
                task_id=task_id,
                run_id=run_id,
                worktree=worktree,
                agent=agent,
                name=name,
                retry_request=retry_request,
                profile=profile,
                effort=effort,
                spec_text=spec_text,
                sandbox_recipe=sandbox_recipe,
            )
        finally:
            # Released however this call ends. An intent still open afterwards (an unexpected
            # error) is then provably ownerless, and recovery settles it.
            lease.release(unlink=True)

    def _launch(
        self,
        *,
        intent_id: str,
        payload_sha: str,
        task_id: str,
        run_id: str,
        worktree: str,
        agent: str,
        name: str | None,
        retry_request: str | None,
        profile: str,
        effort: str | None,
        spec_text: str,
        sandbox_recipe: str,
    ) -> dict[str, Any]:
        """The six committed launch boundaries (LAUNCH_BOUNDARIES), in order (#597).

        Every commit after the first checks this coordinator's owner token in the same
        transaction: a coordinator that was taken over (`launch-reconcile --takeover`) stops
        at its next commit (`launch_fenced`) and leaves everything to the new owner.
        """
        token = uuid.uuid4().hex
        dispatch_id = f"disp_{uuid.uuid4().hex[:10]}"
        term_handle = f"term_{uuid.uuid4().hex[:8]}"
        # A ro worker's only completion channel (#596) is relayed by the exit monitor, so the
        # footer promises it only where one runs: never on dry-run or an injected runner.
        relay_ro = profile == "ro" and self.runner is None and self.backend != "dry-run"
        if relay_ro:
            spec_text += ro_completion_footer(dispatch_id)
        lane_dir = self.state.db_path.parent / "lanes" / dispatch_id
        wt_name, planned_wt = self._plan_worktree(worktree, name or task_id)
        info: dict[str, Any] = {
            "intentId": intent_id,
            "requestId": retry_request,
            "taskId": task_id,
            "runId": run_id,
            "dispatchId": dispatch_id,
            "terminalHandle": term_handle,
            "laneDir": str(lane_dir),
            "worktree": planned_wt,
        }
        now = time.time()
        # 1. Intent + claim (+ the pending request) in ONE transaction, before any external side
        # effect: a losing concurrent caller touches no worktree, and a crash after this commit
        # leaves an intent naming everything this launch is about to create.
        raced = False
        with self.state._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if retry_request and conn.execute("SELECT 1 FROM requests WHERE request_id = ?", (retry_request,)).fetchone():
                conn.execute("ROLLBACK")
                raced = True
            else:
                cur = conn.execute(
                    "UPDATE tasks SET status = 'dispatched', updated_at = ? WHERE id = ? AND status = 'ready'",
                    (now, task_id),
                )
                if cur.rowcount != 1:
                    conn.execute("ROLLBACK")
                    raise ProviderError("task_not_startable", f"task {task_id!r} was already claimed concurrently")
                conn.execute(
                    """
                    INSERT INTO launch_intents(intent_id, request_id, payload_sha256, task_id, run_id, dispatch_id, terminal_handle,
                        lane_dir, worktree, backend, phase, owner_token, owner_pid, owner_host, epoch, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'claimed', ?, ?, ?, 1, ?, ?)
                    """,
                    (
                        intent_id, retry_request, payload_sha, task_id, run_id, dispatch_id, term_handle,
                        str(lane_dir), planned_wt, self.backend, token, os.getpid(), socket.gethostname(), now, now,
                    ),
                )
                if retry_request:
                    conn.execute(
                        "INSERT INTO requests(request_id, method, state, response_json, created_at, payload_sha256, intent_id, caller_scope) "
                        "VALUES (?, 'worker-start', 'pending', NULL, ?, ?, ?, ?)",
                        (retry_request, now, payload_sha, intent_id, self.state._caller_request_scope()),
                    )
                conn.execute("COMMIT")
        if raced:
            # The same request id is being (or was) launched by another call: its outcome, never a second launch.
            bound_raced = self.state._resolve_caller_run(None, default_run=None)
            return self._replay_worker_start(str(retry_request), payload_sha, eff_run=bound_raced) or {}
        self._boundary("intent_claimed", info)

        try:
            wt_path = str(Path(self._resolve_worktree_path(worktree, wt_name)).resolve())
            if wt_path != planned_wt:
                raise ProviderError(
                    "worktree_create_failed",
                    f"created {wt_path} but the launch intent recorded {planned_wt}; refusing a worktree recovery could not name",
                )
            Path(wt_path).mkdir(parents=True, exist_ok=True)
            lane_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            sandbox_meta: dict[str, str] | None = None
            if profile == "danger":
                if not self._is_disposable(Path(wt_path)):
                    raise ProviderError(
                        "danger_requires_linked_worktree",
                        f"profile='danger' only runs in a disposable worktree this provider created (got {wt_path})",
                    )
                sandbox_meta = prepare_sandbox_git(wt_path, lane_dir)
            hooks_map = install_worktree_hooks(wt_path, agent, profile)
            hook_script = hooks_map["deny_hook"]
            harness_env: dict[str, str] = {}
            if agent == "hermes":
                if profile == "danger":
                    raise ProviderError(
                        "unsupported_profile",
                        "hermes keeps its hook config in HERMES_HOME, which a danger sandbox cannot see; use another harness",
                    )
                harness_env = prepare_hermes_home(lane_dir, wt_path, hook_script, self.env)
            launch = build_harness_command(
                agent=agent,
                profile=profile,
                worktree=wt_path,
                prompt=spec_text,
                effort=effort or "xhigh",
                deny_hook_path=hook_script,
                bridge_dir=str(Path(wt_path) / ".open-fleet" / "bridges"),
            )
            # The guard is installed; prove it is armed before the agent starts (W4-06). A
            # new-child spawn cannot be verified in the coordinator's pre-launch gate (no
            # worktree yet), so enforcement lives here, at the installation point.
            verify_installed_guard(wt_path, agent, profile, hooks_map, hook_script)
        except BaseException as exc:
            self._abort_launch(intent_id, token, exc, task_id=task_id, dispatch_id=dispatch_id, term_handle=term_handle)
            raise
        info["worktree"] = wt_path
        self._boundary("worktree_created", info)

        identity_env = {
            **harness_env,
            "OPEN_FLEET_DENY_HOOK": hook_script,
            "ORCA_DENY_HOOK_PATH": hook_script,
            "OPEN_FLEET_UNIT_WORKTREE": wt_path,
            "ORCA_UNIT_WORKTREE": wt_path,
            "OPEN_FLEET_DISPATCH_ID": dispatch_id,
            "ORCA_DISPATCH_ID": dispatch_id,
            "OPEN_FLEET_WORKER_ID": dispatch_id,
            "ORCA_WORKER_ID": dispatch_id,
            "OPEN_FLEET_RUN_ID": run_id,
            "ORCA_RUN_ID": run_id,
            "ORCA_TERMINAL_HANDLE": term_handle,
            "OPEN_FLEET_TERMINAL_HANDLE": term_handle,
            # The child's own profile becomes the ceiling for anything it spawns (#590).
            "OPEN_FLEET_PARENT_PROFILE": profile,
            "ORCA_PARENT_PROFILE": profile,
            "OPEN_FLEET_ROOT": str(OPEN_FLEET_ROOT),
            **({"OPEN_FLEET_HOOK_READONLY": "1", "ORCA_HOOK_READONLY": "1"} if profile == "ro" else {}),
        }
        full_command = " ".join(shlex.quote(str(a)) for a in launch["argv"])
        container = ""
        if profile == "danger" and sandbox_meta is not None:
            # The state DB is deliberately NOT exposed to the sandbox (it could forge mail).
            container_env = {
                **launch["env"],
                **identity_env,
                "GIT_DIR": SANDBOX_GIT_MOUNT,
                "GIT_WORK_TREE": wt_path,
            }
            container_env.pop("OPEN_FLEET_ROOT", None)
            full_command, container = self._docker_command(
                image=sandbox_recipe,
                wt_path=wt_path,
                inner=full_command,
                env=container_env,
                dispatch_id=dispatch_id,
                sandbox_meta=sandbox_meta,
            )
        env_vars = {
            **launch["env"],
            **identity_env,
            "OPEN_FLEET_STATE_DB": str(self.state.db_path),
        }

        eff_json = json.dumps(
            {
                "agent": agent,
                "args": launch["profile_flag"],
                "command": full_command,
                "hooks": hooks_map.get(agent, ""),
                "sandbox": sandbox_recipe if profile == "danger" else "",
                "container": container,
            },
            sort_keys=True,
        )
        # 2. Insert dispatch/terminal BEFORE spawning so fast-exiting workers and a concurrent
        # fence always find the dispatch record (#591 review); the intent's phase moves with them.
        with self.state._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._check_owner(conn, intent_id, token)
            conn.execute(
                """
                INSERT INTO terminals(handle, worktree, title, command, pid, backend, log_path, state, created_at)
                VALUES (?, ?, ?, ?, 0, ?, ?, 'running', ?)
                """,
                (term_handle, wt_path, name or task_id, full_command, self.backend, str(lane_dir / "events.jsonl"), now),
            )
            conn.execute(
                """
                INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, profile, terminal_handle, state, terminal_state, pid, backend, launch_effective, lane_dir, created_at, updated_at, intent_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', 'active', 0, ?, ?, ?, ?, ?, ?)
                """,
                (dispatch_id, task_id, run_id, wt_path, agent, profile, term_handle, self.backend, eff_json, str(lane_dir), now, now, intent_id),
            )
            conn.execute(
                "UPDATE launch_intents SET phase = 'registered', worktree = ?, backend = ?, updated_at = ? WHERE intent_id = ?",
                (wt_path, self.backend, time.time(), intent_id),
            )
            conn.execute("COMMIT")
        self._boundary("registered", info)

        tmux_ref = f"openfleet-{term_handle}" if self.backend == "tmux" else None
        try:
            self._assert_owner(intent_id, token)  # a taken-over coordinator never spawns
            spawn_info = self._spawn_process(
                dispatch_id=dispatch_id,
                term_handle=term_handle,
                wt_path=wt_path,
                command=full_command,
                env_vars=env_vars,
                lane_dir=lane_dir,
                run_id=run_id,
                sandbox_meta=sandbox_meta,
                ro_relay=agent if relay_ro else "",  # whose final answer the monitor reads
            )
        except BaseException as exc:
            if isinstance(exc, ProviderError) and exc.code == "launch_fenced":
                raise
            # The monitor may already be running (e.g. cmux id parse / launcher timeout /
            # Ctrl-C after tmux started): withdraw the dispatch FIRST so its launch gate
            # refuses, tear down whatever started, then hand the task back. A monitor that
            # already passed the gate is stopped by the pid it recorded there (#597).
            monitor_pid = self._abort_launch(intent_id, token, exc, task_id=task_id, dispatch_id=dispatch_id, term_handle=term_handle)
            if monitor_pid is not None:
                self._terminate_backend(self.backend, term_handle, monitor_pid, backend_ref=tmux_ref, container=container)
            raise
        info["pid"] = int(spawn_info.get("pid", 0) or 0)
        self._boundary("monitor_spawned", info)

        spawn_pid = int(spawn_info.get("pid", 0) or 0)
        spawn_backend = spawn_info.get("backend", self.backend)
        backend_ref = spawn_info.get("backendRef") or ""
        fenced_state: str | None = None
        with self.state._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._check_owner(conn, intent_id, token)
            cur_disp = conn.execute("SELECT state FROM dispatches WHERE dispatch_id = ?", (dispatch_id,)).fetchone()
            if not cur_disp or cur_disp["state"] in FENCED_DISPATCH_STATES:
                fenced_state = cur_disp["state"] if cur_disp else "deleted"
            conn.execute(
                "UPDATE terminals SET pid = ?, backend = ?, backend_ref = ? WHERE handle = ?",
                (spawn_pid, spawn_backend, backend_ref, term_handle),
            )
            conn.execute(
                "UPDATE dispatches SET pid = ?, backend = ?, backend_ref = ?, updated_at = ? WHERE dispatch_id = ?",
                (spawn_pid, spawn_backend, backend_ref, time.time(), dispatch_id),
            )
            conn.execute(
                "UPDATE launch_intents SET phase = 'published', backend = ?, updated_at = ? WHERE intent_id = ?",
                (spawn_backend, time.time(), intent_id),
            )
            conn.execute("COMMIT")
        self._boundary("published", info)
        if fenced_state is not None:
            # Fenced while starting: the generated monitor's launch gate refuses to run the
            # agent, and anything that did start is torn down here.
            self._terminate_backend(spawn_backend, term_handle, spawn_pid, backend_ref=backend_ref, container=container)
            err = ProviderError(
                "dispatch_fenced",
                f"dispatch {dispatch_id!r} was fenced ({fenced_state}) during startup",
            )
            self._finalize_launch(
                intent_id,
                token,
                outcome="failed",
                receipt={"state": "failed", "dispatchId": dispatch_id, "error": {"code": err.code, "message": err.message}},
                request_state="failed",
                response=self._failed_response(retry_request, dispatch_id, err),
                release=(task_id, dispatch_id),
            )
            raise err

        res = self._start_receipt(
            dispatch_id=dispatch_id,
            task_id=task_id,
            term_handle=term_handle,
            wt_path=wt_path,
            # What actually ran — not the short human label (#591 review).
            effective={"agent": agent, "args": launch["profile_flag"], "command": full_command},
        )
        # 6. The request's receipt and the intent's outcome, in one owner-checked transaction.
        self._finalize_launch(
            intent_id, token, outcome="completed", receipt=res, request_state="completed", response=res, phase="receipted"
        )
        self._boundary("receipted", info)
        return res

    @staticmethod
    def _start_receipt(
        *,
        dispatch_id: str,
        task_id: str,
        term_handle: str,
        wt_path: str,
        effective: dict[str, Any],
        worker_state: str = "ready",
        terminal_state: str = "active",
    ) -> dict[str, Any]:
        return {
            "state": "ready",
            "dispatchId": dispatch_id,
            "agentTerminalHandle": term_handle,
            "effects": [{"kind": "terminal", "role": "agent", "id": term_handle}],
            "launch": {"effective": {k: effective.get(k) for k in ("agent", "args", "command")}},
            "worker": {
                "dispatchId": dispatch_id,
                "taskId": task_id,
                "state": worker_state,
                "terminalState": terminal_state,
                "agentTerminalHandle": term_handle,
                "worktree": wt_path,
            },
        }

    # --- #597: crash-recoverable launch (spec: docs/runtimes.md "posix launch crash recovery") ---
    # Observer called right after each committed launch boundary (LAUNCH_BOUNDARIES) with the
    # launch's recorded identity. Crash-injection tests SIGKILL a coordinator from it; nothing
    # in the provider depends on it.
    on_launch_boundary: Callable[[str, dict[str, Any]], None] | None = None

    def _boundary(self, stage: str, info: dict[str, Any]) -> None:
        if self.on_launch_boundary is not None:
            self.on_launch_boundary(stage, dict(info))

    def _intent_lock_path(self, intent_id: str) -> Path:
        return self.state.db_path.parent / "intents" / f"{intent_id}.lock"

    def _recovery_lock_path(self, intent_id: str) -> Path:
        return self.state.db_path.parent / "intents" / f"{intent_id}.recovery.lock"

    def _plan_worktree(self, worktree_sel: str, name: str) -> tuple[str, str]:
        """The worktree name and path a launch uses, chosen ONCE, before its intent is recorded.

        A name that sanitizes to nothing (`---`) gets `worktree_create`'s random fallback here,
        not later: the intent records that path, and the launch creates exactly it (the name is
        already a slug, so `worktree_create` keeps it, and its branch `fleet/<name>` with it).
        Otherwise a coordinator that died before registering left recovery an empty worktree
        path, unable to name or pin the worktree it had created (#597 review).
        """
        if worktree_sel in ("new-child", "new-top-level"):
            slug = _worktree_slug(name) or f"wt-{uuid.uuid4().hex[:6]}"
            return slug, str((self._worktree_base_dir() / slug).resolve())
        return name, str(Path(self._resolve_worktree_path(worktree_sel, name)).resolve())

    @staticmethod
    def _check_owner(conn: Any, intent_id: str, token: str) -> None:
        """Inside an open transaction: roll back and refuse a write by a coordinator that was taken over."""
        row = conn.execute("SELECT owner_token, epoch FROM launch_intents WHERE intent_id = ?", (intent_id,)).fetchone()
        if row is None or row["owner_token"] != token:
            conn.execute("ROLLBACK")
            raise ProviderError(
                "launch_fenced",
                f"launch intent {intent_id!r} was taken over by another coordinator; this one stops and leaves it to the new owner",
                {"intentId": intent_id, "epoch": row["epoch"] if row else None},
            )

    def _assert_owner(self, intent_id: str, token: str) -> None:
        with self.state._connect() as conn:
            conn.execute("BEGIN")
            self._check_owner(conn, intent_id, token)
            conn.execute("COMMIT")

    @staticmethod
    def _release_task_claim(conn: Any, task_id: str, dispatch_id: str) -> None:
        """Hand a claimed task back to `ready`, unless another live dispatch of it exists."""
        conn.execute(
            "UPDATE tasks SET status = 'ready', updated_at = ? WHERE id = ? AND status = 'dispatched' "
            "AND NOT EXISTS (SELECT 1 FROM dispatches WHERE task_id = ? AND dispatch_id != ? "
            "AND state IN ('ready', 'running', 'retained'))",
            (time.time(), task_id, task_id, dispatch_id),
        )

    @staticmethod
    def _failed_response(request_id: str | None, dispatch_id: str, err: ProviderError, data: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "state": "failed",
            "requestId": request_id,
            "dispatchId": dispatch_id,
            "error": {"code": err.code, "message": err.message, "data": {**err.data, **(data or {})}},
        }

    def _finalize_launch(
        self,
        intent_id: str,
        token: str,
        *,
        outcome: str | None,
        receipt: dict[str, Any],
        request_state: str,
        response: dict[str, Any],
        release: tuple[str, str] | None = None,
        phase: str | None = None,
    ) -> str | None:
        """Owner-checked: the intent's outcome, its request's state and (optionally) the task
        claim's release, in ONE transaction. Returns the task's status after it."""
        with self.state._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._check_owner(conn, intent_id, token)
            it = conn.execute("SELECT request_id, task_id FROM launch_intents WHERE intent_id = ?", (intent_id,)).fetchone()
            if release is not None:
                self._release_task_claim(conn, *release)
            t = conn.execute("SELECT status FROM tasks WHERE id = ?", (it["task_id"],)).fetchone()
            task_after = t["status"] if t else None
            if isinstance(receipt.get("task"), dict):
                receipt["task"]["after"] = task_after
            conn.execute(
                "UPDATE launch_intents SET outcome = ?, phase = COALESCE(?, phase), receipt_json = ?, updated_at = ? WHERE intent_id = ?",
                (outcome, phase, json.dumps(receipt, sort_keys=True, default=str), time.time(), intent_id),
            )
            if it["request_id"]:
                conn.execute(
                    "UPDATE requests SET state = ?, response_json = ? WHERE request_id = ?",
                    (request_state, json.dumps(response, sort_keys=True, default=str), it["request_id"]),
                )
            conn.execute("COMMIT")
        return task_after

    def _abort_launch(
        self,
        intent_id: str,
        token: str,
        exc: BaseException,
        *,
        task_id: str,
        dispatch_id: str,
        term_handle: str,
    ) -> int | None:
        """An in-process failure: withdraw what this attempt registered, hand the task back and
        record the request `failed`, only while this coordinator still owns the intent.

        Returns the pid a monitor recorded at the launch gate (0 when none passed it), or None
        when the intent was taken over: the new owner settles it, so nothing is touched here.
        """
        err = exc if isinstance(exc, ProviderError) else ProviderError("launch_aborted", f"{type(exc).__name__}: {exc}"[:300])
        try:
            with self.state._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                self._check_owner(conn, intent_id, token)
                d = conn.execute("SELECT monitor_pid FROM dispatches WHERE dispatch_id = ?", (dispatch_id,)).fetchone()
                monitor_pid = int((d["monitor_pid"] if d else 0) or 0)
                conn.execute(
                    "UPDATE tasks SET status = 'ready', updated_at = ? WHERE id = ? AND status = 'dispatched'",
                    (time.time(), task_id),
                )
                conn.execute("DELETE FROM dispatches WHERE dispatch_id = ?", (dispatch_id,))
                conn.execute("DELETE FROM terminals WHERE handle = ?", (term_handle,))
                receipt = {"state": "failed", "dispatchId": dispatch_id, "withdrawn": True, "error": {"code": err.code, "message": err.message}}
                req = conn.execute("SELECT request_id FROM launch_intents WHERE intent_id = ?", (intent_id,)).fetchone()
                conn.execute(
                    "UPDATE launch_intents SET outcome = 'failed', receipt_json = ?, updated_at = ? WHERE intent_id = ?",
                    (json.dumps(receipt, sort_keys=True), time.time(), intent_id),
                )
                if req and req["request_id"]:
                    conn.execute(
                        "UPDATE requests SET state = 'failed', response_json = ? WHERE request_id = ?",
                        (json.dumps(self._failed_response(req["request_id"], dispatch_id, err), sort_keys=True, default=str), req["request_id"]),
                    )
                conn.execute("COMMIT")
        except ProviderError as fenced:
            if fenced.code != "launch_fenced":
                raise
            return None
        return monitor_pid

    def _not_startable(self, task_id: str, status: str) -> ProviderError:
        """`task_not_startable`, naming the open launch that holds the task (if any) and how to settle it."""
        data: dict[str, Any] = {}
        held = self.state.open_launch_intents(task_id)
        if held:
            it = held[-1]
            data = {
                "openLaunch": {
                    "intentId": it["intent_id"],
                    "dispatchId": it["dispatch_id"],
                    "phase": it["phase"],
                    "outcome": it["outcome"],
                    "ownerPid": it["owner_pid"],
                    "ownerHost": it["owner_host"],
                },
                "nextSteps": [
                    f"orchestration launch-reconcile --intent {it['intent_id']} (settles it once its coordinator is gone)",
                    f"add --takeover only when coordinator pid {it['owner_pid']} on {it['owner_host']} is wedged: it fences that writer",
                ],
            }
        return ProviderError("task_not_startable", f"task {task_id!r} has status {status!r} (must be 'ready')", data)

    def _replay_worker_start(
        self, request_id: str, payload_sha: str, *, eff_run: str | None = None
    ) -> dict[str, Any] | None:
        """A retried `--retry-request`: the recorded outcome, never a second launch (#597)."""
        row = self.state.request_row(request_id)
        if row is None:
            return None
        it_pre = self.state.launch_intent(row["intent_id"]) if row.get("intent_id") else None
        if eff_run is not None and it_pre is not None:
            it_run = str(it_pre["run_id"] or "default")
            if it_run != eff_run:
                raise ProviderError(
                    "cross_run_access",
                    f"task {it_pre['task_id']!r} belongs to run {it_run!r}, not {eff_run!r}",
                )
        caller_scope = self.state._caller_request_scope()
        if row.get("caller_scope") and row["caller_scope"] != caller_scope:
            if eff_run is not None and row["caller_scope"].startswith("worker:") and not row["caller_scope"].startswith(f"worker:{eff_run}:"):
                raise ProviderError(
                    "cross_run_access",
                    f"retry-request {request_id!r} belongs to another run's worker scope",
                    {"requestId": request_id},
                )
            raise ProviderError(
                "request_mismatch",
                f"retry-request {request_id!r} belongs to a different caller scope; use a new request id",
                {"requestId": request_id},
            )
        if row["method"] != "worker-start":
            raise ProviderError("request_mismatch", f"retry-request {request_id!r} bound to {row['method']}, not worker-start")
        self.state.check_request_payload(request_id, row.get("payload_sha256"), payload_sha)
        if row["state"] == "pending" and row.get("intent_id"):
            recovery = self._reconcile_intent(row["intent_id"], takeover=False)
            row = self.state.request_row(request_id) or row
            if row["state"] == "pending":
                stage = "launch_recovery" if recovery.get("resolution") == "cleanup_pending" else "launch_in_progress"
                return self._unknown_response(recovery, stage=stage)
        response = json.loads(row["response_json"]) if row.get("response_json") else {}
        if row["state"] == "failed":
            err = response.get("error") or {}
            raise ProviderError(
                err.get("code") or "launch_failed",
                err.get("message") or f"request {request_id!r} failed",
                {**(err.get("data") or {}), "requestId": request_id, "replayed": True},
            )
        return response or {"state": row["state"], "requestId": request_id}

    @staticmethod
    def _unknown_response(recovery: dict[str, Any], *, stage: str) -> dict[str, Any]:
        did = recovery.get("dispatchId")
        return {
            "state": "outcome_unknown",
            "stage": stage,
            "requestId": recovery.get("requestId"),
            "dispatchId": did,
            "nextCommands": [
                f"orchestration worker-show --dispatch {did} --json",
                f"orchestration launch-reconcile --intent {recovery.get('intentId')} --json",
            ],
            "recovery": recovery,
        }

    def launch_reconcile(
        self,
        *,
        intent: str | None = None,
        request: str | None = None,
        takeover: bool = False,
    ) -> dict[str, Any]:
        """Settle launches a dead coordinator left open; `takeover` also fences a LIVE one (#597)."""
        bound = self.state._resolve_caller_run(None, default_run=None)
        if request:
            row = self.state.request_row(request)
            if row is None:
                raise ProviderError("request_not_found", f"request {request!r} not found")
            if not row.get("intent_id"):
                raise ProviderError("invalid_argument", f"request {request!r} names no launch intent")
            if intent and intent != row["intent_id"]:
                raise ProviderError("invalid_argument", f"request {request!r} names intent {row['intent_id']!r}, not {intent!r}")
            intent = row["intent_id"]
        if intent:
            it_chk = self.state.launch_intent(intent)
            if it_chk is not None and bound is not None:
                it_run = str(it_chk["run_id"] or "default")
                if it_run != bound:
                    raise ProviderError(
                        "cross_run_access",
                        f"launch intent {intent!r} belongs to run {it_run!r}, not {bound!r}",
                    )
            ids = [intent]
        else:
            ids = [
                r["intent_id"]
                for r in self.state.open_launch_intents()
                if bound is None or str(r["run_id"] or "default") == bound
            ]
        receipts = [self._reconcile_intent(i, takeover=takeover) for i in ids]
        return {"reconciled": receipts, "count": len(receipts)}

    def _reconcile_dead_intents(self, task_id: str | None = None, *, run_id: str | None = None) -> None:
        """Settle every open launch on this host whose coordinator is provably gone.

        An `unknown` launch is left to an explicit `launch-reconcile`: it waits on an inspection,
        and re-deciding it on every poll would only rewrite the same receipt.
        """
        host = socket.gethostname()
        for it in self.state.open_launch_intents(task_id):
            if run_id is not None and str(it["run_id"] or "default") != run_id:
                continue
            if it["owner_host"] != host or it["outcome"] == "unknown":
                continue
            try:
                self._reconcile_intent(it["intent_id"], takeover=False)
            except ProviderError as exc:
                if exc.code != "launch_fenced":  # another reconciler won the takeover race
                    raise

    def _recovery_receipt(self, it: dict[str, Any], *, resolution: str, previous: dict[str, Any], **extra: Any) -> dict[str, Any]:
        out: dict[str, Any] = {
            "kind": "launch_recovery",
            "intentId": it["intent_id"],
            "requestId": it["request_id"],
            "runId": it["run_id"],
            "taskId": it["task_id"],
            "dispatchId": it["dispatch_id"],
            "terminalHandle": it["terminal_handle"],
            "worktree": it["worktree"],
            "phase": it["phase"],
            "resolution": resolution,
            "owner": {"previous": previous, "epoch": it["epoch"]},
            "completionInferred": False,
            "reconciledAt": time.time(),
        }
        out.update(extra)
        return out

    def _reconcile_intent(self, intent_id: str, *, takeover: bool) -> dict[str, Any]:
        it = self.state.launch_intent(intent_id)
        if it is None:
            raise ProviderError("intent_not_found", f"launch intent {intent_id!r} not found")
        previous = {"pid": it["owner_pid"], "host": it["owner_host"], "epoch": it["epoch"], "alive": None}
        if it["outcome"] in LAUNCH_FINAL_OUTCOMES:
            return self._recovery_receipt(
                it, resolution="already_settled", previous=previous, outcome=it["outcome"], settled=json.loads(it["receipt_json"] or "{}")
            )
        lease = _IntentLease(self._intent_lock_path(intent_id))
        recovery: _IntentLease | None = None
        final = False
        try:
            owner_gone = lease.try_acquire()
            same_host = it["owner_host"] == socket.gethostname()
            previous["alive"] = (not owner_gone) if same_host else None
            if not takeover and not (owner_gone and same_host):
                # Never act for a coordinator that may still be launching: report, change nothing.
                who = f"coordinator pid {it['owner_pid']} on {it['owner_host']}"
                return self._recovery_receipt(
                    it,
                    resolution="pending" if same_host else "unknown",
                    previous=previous,
                    requestState="pending",
                    nextSteps=[
                        f"{who} still holds this launch: wait for its receipt (request-show / worker-show)"
                        if same_host
                        else f"{who} cannot be checked from this host: inspect there",
                        f"only if it is wedged: orchestration launch-reconcile --intent {intent_id} --takeover (fences that writer)",
                    ],
                )
            # One settler at a time, a takeover included (#597 review). A takeover cannot hold the
            # launch lease (its live owner does, and drops it the moment it stops, letting a poll's
            # reconcile in beside the takeover), so every settler first holds the recovery lock.
            recovery = _IntentLease(self._recovery_lock_path(intent_id))
            if not recovery.try_acquire():
                return self._recovery_receipt(
                    it,
                    resolution="pending",
                    previous=previous,
                    requestState="pending",
                    nextSteps=["another reconciler is settling this launch now: wait for its receipt (request-show / worker-show)"],
                )
            token = uuid.uuid4().hex
            with self.state._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "UPDATE launch_intents SET owner_token = ?, owner_pid = ?, owner_host = ?, epoch = epoch + 1, updated_at = ? "
                    "WHERE intent_id = ? AND owner_token = ? AND (outcome IS NULL OR outcome = 'unknown')",
                    (token, os.getpid(), socket.gethostname(), time.time(), intent_id, it["owner_token"]),
                )
                conn.execute("COMMIT")
            if cur.rowcount != 1:
                fresh = self.state.launch_intent(intent_id) or it
                settled = fresh["outcome"] in LAUNCH_FINAL_OUTCOMES
                return self._recovery_receipt(fresh, resolution="already_settled" if settled else "pending", previous=previous)
            receipt = self._settle_intent(self.state.launch_intent(intent_id) or it, token, previous, takeover=takeover and not owner_gone)
            final = receipt["resolution"] not in ("unknown", "cleanup_pending")
            return receipt
        finally:
            if recovery is not None:
                recovery.release(unlink=final)
            lease.release(unlink=final)

    def _settle_intent(self, it: dict[str, Any], token: str, previous: dict[str, Any], *, takeover: bool) -> dict[str, Any]:
        """Decide an open launch by its recorded identity: adopt, roll back, or report unknown.

        It never respawns, never deletes a worktree or branch, and never marks anything
        completed: that is the worker's own terminal mail (`ensure_terminal_or_died`).
        """
        intent_id, task_id, disp_id, handle = it["intent_id"], it["task_id"], it["dispatch_id"], it["terminal_handle"]
        lane = Path(it["lane_dir"])
        exit_file = lane / "exit.json"
        processes: list[dict[str, Any]] = [{"role": "coordinator", **previous, "action": "fenced"}]
        cleanup: list[dict[str, Any]] = []
        refs: list[dict[str, Any]] = []
        with self.state._connect() as conn:
            t = conn.execute("SELECT status FROM tasks WHERE id = ?", (task_id,)).fetchone()
        task_before = t["status"] if t else None
        d = self._dispatch_row(disp_id)
        disp_before = d["state"] if d else None
        resolution = ""
        err: ProviderError | None = None
        release = False
        if d is None:
            # Phase `claimed`: with no dispatch row, no monitor can ever pass this launch's gate.
            resolution, release = "failed", True
            err = ProviderError(
                "launch_interrupted",
                "the coordinator stopped after claiming the task and before registering a dispatch; nothing was launched",
            )
        elif d["state"] in FENCED_DISPATCH_STATES:
            # An operator fenced it while it was starting: finish that fence, as the live path would.
            mon = self._monitor_process(d, lane)
            never_ran = self._gate_proves_never_ran(d)
            if never_ran:
                mon["gate"] = "closed"
            if mon["alive"] is False or (never_ran and mon["alive"] is None):
                # Confirmed dead, or a gate closed before any claim (no monitor ever ran and none
                # can): no exit.json can ever come, and waiting the sync grace for one stalled
                # recovery (#597). Salvage as for any vanished monitor (container removal, then
                # the sync) with its unknown exit; only the mux session is left to close.
                vanished = self._report_vanished(d)
                mon["action"] = "refused_at_gate" if never_ran else "reported_dead"
                if vanished.get("orphans"):
                    mon["orphans"] = vanished["orphans"]
                mon["termination"] = self._terminate_backend(d["backend"] or self.backend, handle, 0, backend_ref=d["backend_ref"])
                self._record_salvage(vanished.get("salvage"), mon, refs, cleanup)
                if vanished.get("retry"):
                    resolution = "cleanup_pending"  # its container may still run: keep the task claimed
            else:
                mon["action"] = "terminated"
                mon["termination"] = self._terminate_backend(
                    d["backend"] or self.backend,
                    handle,
                    int(mon.get("pid") or 0) if mon.get("alive") else 0,
                    backend_ref=d["backend_ref"],
                    container=self._dispatch_container(d),
                    # A live process under a closed gate is a refused monitor: it never syncs.
                    lane_dir=None if never_ran else d["lane_dir"],
                )
            processes.append(mon)
            if not resolution:
                resolution, release = "failed", True
                err = ProviderError("dispatch_fenced", f"dispatch {disp_id!r} was fenced ({d['state']}) during startup")
        else:
            gated = bool(_col(d, "monitor_started_at")) or exit_file.is_file() or d["state"] not in ("ready", "retained")
            if it["phase"] == "registered" and not gated:
                if self.runner is not None:
                    resolution = "unknown"  # an injected runner's process is invisible here
                elif self.state.abandon_unlaunched(disp_id):
                    # Won against the gate: no monitor ever runs this dispatch. Close a mux
                    # session the dead launch may have opened; its monitor refuses anyway.
                    backend = d["backend"] or self.backend
                    term = self._terminate_backend(
                        backend, handle, 0, backend_ref=d["backend_ref"] or (f"openfleet-{handle}" if backend == "tmux" else None)
                    )
                    processes.append({"role": "monitor", "pid": None, "alive": False, "action": "refused_at_gate", "termination": term})
                    cleanup.append({"kind": "dispatch", "target": disp_id, "action": "abandoned", "why": "kept for its identity; a late monitor is refused at the launch gate"})
                    resolution, release = "failed", True
                    err = ProviderError(
                        "launch_interrupted",
                        "the coordinator stopped before any monitor claimed the launch gate; the dispatch is abandoned and nothing ran",
                    )
                else:
                    d = self._dispatch_row(disp_id) or d  # a monitor claimed the gate first: adopt it
            if not resolution:
                mon = self._monitor_process(d, lane)
                recorded = None
                if not mon["alive"] and d["state"] not in ("died", "completed") and exit_file.is_file():
                    # Its monitor recorded the exit, then died before settling it (#597 review).
                    recorded = self._settle_recorded_exit(d)
                if mon["alive"]:
                    self._publish_adopted(d, mon)
                    mon["action"], resolution = "adopted", "live"
                elif d["state"] in ("died", "completed"):
                    mon["action"], resolution = "none", "exited"  # its own monitor already settled the dispatch
                elif recorded is not None:
                    mon["action"], mon["exit"], resolution = "settled_recorded_exit", recorded, "exited"
                elif mon["alive"] is False:
                    vanished = self._report_vanished(d)
                    if vanished.get("retry"):
                        # Its sandbox cleanup or sync failed: not dead yet, and recovery stays open (#597 review).
                        mon["action"], resolution = "cleanup_pending", "cleanup_pending"
                    else:
                        mon["action"], resolution = "reported_dead", "exited"
                    if vanished.get("orphans"):
                        mon["orphans"] = vanished["orphans"]
                    self._record_salvage(vanished.get("salvage"), mon, refs, cleanup)
                else:
                    resolution = "unknown"
                processes.append(mon)

        wt = (d["worktree"] if d else None) or it["worktree"]
        pinned = self._preserve_head(wt, disp_id)
        if pinned:
            refs.insert(0, pinned)
        if wt:
            exists = Path(wt).is_dir()
            cleanup.append(
                {
                    "kind": "worktree",
                    "target": wt,
                    "action": "kept" if exists else "absent",
                    "why": "recovery never deletes a worktree or a branch" if exists else "never created",
                }
            )
        if lane.is_dir():
            cleanup.append({"kind": "lane", "target": str(lane), "action": "kept", "why": "logs, exit.json and this receipt"})
        d_after = self._dispatch_row(disp_id)
        request_state = {"live": "completed", "exited": "completed", "failed": "failed", "cleanup_pending": "pending"}.get(
            resolution, "unknown"
        )
        # `cleanup_pending` leaves the outcome NULL: an open intent that every poll reconciles again.
        outcome = {"completed": "completed", "failed": "failed", "pending": None}.get(request_state, "unknown")
        if resolution == "live":
            steps = ["the worker is live: supervise it (check --wait, worker-show); never start a second worker for this task"]
        elif resolution == "exited":
            steps = ["the worker already exited: read its terminal mail or its worker_died escalation (check) before any retry-of"]
        elif resolution == "failed":
            steps = ["nothing runs for this attempt and the task is back to ready: start a new attempt with a NEW --retry-request"]
        elif resolution == "cleanup_pending" and d_after is not None and d_after["state"] in FENCED_DISPATCH_STATES:
            steps = [
                f"it is {d_after['state']} and its monitor is dead, but removing its container or syncing its commits failed: "
                "worker-list, worker-show and launch-reconcile retry both, and only then hand the task back",
            ]
        elif resolution == "cleanup_pending":
            steps = [
                "its monitor vanished and removing its container or syncing its commits failed: worker-list, worker-show "
                "and launch-reconcile retry both, and only then report its worker_died",
                f"to give up instead: orchestration worker-abandon --dispatch {disp_id} (its sandbox git dir stays in {lane})",
            ]
        else:
            steps = [
                f"inspect: orchestration worker-show --dispatch {disp_id}",
                "then worker-stop or worker-abandon explicitly; never respawn beside it",
            ]
        receipt = self._recovery_receipt(
            self.state.launch_intent(intent_id) or it,
            resolution=resolution,
            previous=previous,
            requestState=request_state,
            takeover=takeover,
            processes=processes,
            preservedRefs=refs,
            task={"id": task_id, "before": task_before, "after": task_before},
            dispatch={"id": disp_id, "before": disp_before, "after": d_after["state"] if d_after else None},
            cleanup=cleanup,
            nextSteps=steps,
        )
        if err is not None:
            receipt["error"] = {"code": err.code, "message": err.message}
        if request_state == "completed" and d_after is not None:
            try:
                eff = json.loads(d_after["launch_effective"] or "{}")
            except json.JSONDecodeError:
                eff = {}
            response = self._start_receipt(
                dispatch_id=disp_id,
                task_id=task_id,
                term_handle=handle,
                wt_path=d_after["worktree"],
                effective=eff,
                worker_state=d_after["state"],
                terminal_state=d_after["terminal_state"],
            )
            response["recovery"] = receipt
        elif request_state == "failed" and err is not None:
            response = self._failed_response(it["request_id"], disp_id, err, {"nextSteps": steps, "recovery": receipt})
        else:
            response = self._unknown_response(receipt, stage="launch_recovery")
        self._finalize_launch(
            intent_id,
            token,
            outcome=outcome,
            receipt=receipt,
            request_state=request_state,
            response=response,
            release=(task_id, disp_id) if release else None,
        )
        if lane.is_dir():
            (lane / "recovery.json").write_text(json.dumps(receipt, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
        return receipt

    def _gate_proves_never_ran(self, d: Any) -> bool:
        """Whether the launch gate proves no monitor ever ran this dispatch and none ever can (#597).

        A fence before any claim closed the gate for good, and a `worker-start` dispatch (it
        carries an intent) runs its worker only after its monitor passes that gate. An injected
        runner or an injected dispatch starts work without the gate, so the gate proves nothing there.
        """
        return (
            d is not None
            and self.runner is None
            and _col(d, "intent_id") is not None
            and _col(d, "gate_closed_at") is not None
            and _col(d, "monitor_started_at") is None
        )

    @staticmethod
    def _record_salvage(
        salvage: dict[str, Any] | None, mon: dict[str, Any], refs: list[dict[str, Any]], cleanup: list[dict[str, Any]]
    ) -> None:
        """What `_salvage_sandbox` did, in the recovery receipt: the synced ref and every cleanup step."""
        if not salvage:
            return
        if salvage.get("sandboxRef"):
            refs.append({"ref": salvage["sandboxRef"], "sha": salvage.get("head"), "source": "sandbox"})
        if salvage.get("container"):
            box = salvage["container"]
            cleanup.append(
                {"kind": "container", "target": box["name"], "action": box["action"], "rc": box["rc"]}
                | ({"error": box["error"]} if box.get("error") else {})
            )
        if salvage.get("sync") in ("deferred", "failed", "refused"):
            cleanup.append(
                {"kind": "sandbox_sync", "target": salvage["sandboxGit"], "action": salvage["sync"]}
                | ({"error": salvage["error"]} if salvage.get("error") else {})
            )
        if salvage.get("error"):
            mon["salvageError"] = salvage["error"]

    def _dispatch_row(self, dispatch_id: str) -> Any:
        rows = self._dispatch_rows("WHERE dispatch_id = ?", (dispatch_id,))
        return rows[0] if rows else None

    @staticmethod
    def _dispatch_container(row: Any) -> str:
        try:
            return json.loads(row["launch_effective"] or "{}").get("container") or ""
        except json.JSONDecodeError:
            return ""

    def _monitor_process(self, d: Any, lane: Path) -> dict[str, Any]:
        """The monitor a dispatch recorded, and whether THAT process (not a pid reuse) is alive."""
        backend = d["backend"] or self.backend
        pid = int(_col(d, "monitor_pid") or 0) or int(d["pid"] or 0)
        out: dict[str, Any] = {"role": "monitor", "pid": pid or None, "backend": backend, "backendRef": d["backend_ref"] or None}
        container = self._dispatch_container(d)
        if container:
            out["container"] = container
        if self.runner is not None or backend == "dry-run":
            out["alive"] = None
        elif backend == "tmux":
            ref = d["backend_ref"] or f"openfleet-{d['terminal_handle']}"
            out["backendRef"] = ref
            try:
                out["alive"] = subprocess.run(["tmux", "has-session", "-t", ref], capture_output=True, timeout=15).returncode == 0
            except (OSError, subprocess.SubprocessError):
                out["alive"] = None  # no tmux to ask: cannot tell
        elif pid > 0:
            out["alive"] = _pid_runs_monitor(pid, lane)
        else:
            out["alive"] = None
        return out

    def _publish_adopted(self, d: Any, mon: dict[str, Any]) -> None:
        """Publish what the dead coordinator never did: the adopted monitor's pid (and tmux session)."""
        pid = int(mon.get("pid") or 0)
        ref = mon.get("backendRef") or ""
        with self.state._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE dispatches SET pid = CASE WHEN COALESCE(pid, 0) = 0 THEN ? ELSE pid END, "
                "backend_ref = COALESCE(NULLIF(backend_ref, ''), ?), updated_at = ? WHERE dispatch_id = ?",
                (pid, ref, time.time(), d["dispatch_id"]),
            )
            conn.execute(
                "UPDATE terminals SET pid = CASE WHEN COALESCE(pid, 0) = 0 THEN ? ELSE pid END, "
                "backend_ref = COALESCE(NULLIF(backend_ref, ''), ?) WHERE handle = ?",
                (pid, ref, d["terminal_handle"]),
            )
            conn.execute("COMMIT")

    @staticmethod
    def _preserve_head(wt: str | None, dispatch_id: str) -> dict[str, Any] | None:
        """Pin the worktree's HEAD at `refs/open-fleet/preserved/<dispatch>` (shared by every linked worktree)."""
        if not wt or not (Path(wt) / ".git").exists():
            return None
        ref = f"refs/open-fleet/preserved/{dispatch_id}"
        head = _git(["rev-parse", "--verify", "HEAD^{commit}"], cwd=wt)
        if head.returncode != 0:
            return {"ref": ref, "error": (head.stderr or "no HEAD").strip()[:200]}
        sha = head.stdout.strip()
        upd = _git(["update-ref", ref, sha], cwd=wt)
        pinned: dict[str, Any] = {"ref": ref, "sha": sha, "source": "worktree", "worktree": wt}
        if upd.returncode != 0:
            pinned["error"] = (upd.stderr or "update-ref failed").strip()[:200]
        return pinned

    def _salvage_sandbox(self, r: Any) -> dict[str, Any] | None:
        """A `danger` worker's commits live only in its lane's private git dir until its monitor
        syncs them. When that monitor vanished, stop the container, then sync them here (#597).

        `retry` marks a salvage that must run again (#597 review): a container not confirmed gone
        (the sync waits for that, since a live container could still write the git dir) or a sync
        that failed in git or the filesystem. A sandbox refused as tampered, or whose metadata is
        unreadable, can never sync: that is final, and the receipt records it.
        """
        lane = r["lane_dir"]
        meta_path = Path(lane) / "sandbox_git.json" if lane else None
        if meta_path is None or not meta_path.is_file():
            return None
        out: dict[str, Any] = {"sandboxGit": str(Path(lane) / "sandbox.git")}
        container = self._dispatch_container(r)
        if container:
            try:
                proc = subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True, env=self.env, timeout=120)
            except (OSError, subprocess.SubprocessError) as exc:
                box: dict[str, Any] = {"name": container, "rc": None, "action": "removal_failed", "error": str(exc)[:200]}
            else:
                said = (proc.stderr or proc.stdout or "").strip()
                if proc.returncode == 0:
                    box = {"name": container, "rc": 0, "action": "removed"}
                elif "no such container" in said.lower():
                    box = {"name": container, "rc": proc.returncode, "action": "absent"}  # an older CLI's `rm -f`
                else:
                    box = {"name": container, "rc": proc.returncode, "action": "removal_failed", "error": said[:200] or "docker rm failed"}
            out["container"] = box
            if box["action"] == "removal_failed":
                out["sync"], out["retry"] = "deferred", True
                return out
        try:
            out.update(sync_sandbox_git(json.loads(meta_path.read_text(encoding="utf-8")), r["dispatch_id"]))
            out["sync"] = "synced"
        except ProviderError as exc:
            out["error"] = str(exc)[:300]
            out["sync"], out["retry"] = ("refused", False) if exc.code == "sandbox_git_tampered" else ("failed", True)
        except ValueError as exc:
            out["error"], out["sync"], out["retry"] = str(exc)[:300], "refused", False
        except OSError as exc:
            out["error"], out["sync"], out["retry"] = str(exc)[:300], "failed", True
        return out

    def _settle_recorded_exit(self, r: Any) -> dict[str, Any] | None:
        """Finish what a monitor that died after writing `exit.json` never did (#597 review).

        The monitor records the exit and only THEN settles the dispatch, so a death between the
        two left it `ready` with no `worker_died`. The recorded exit code and head settle it through
        `ensure_terminal_or_died` (atomic: a monitor still finishing and this call never both
        report), so completion is still only ever the worker's own mail. None: no readable record.
        """
        lane = Path(r["lane_dir"]) if r["lane_dir"] else None
        if lane is None:
            return None
        try:
            rec = json.loads((lane / "exit.json").read_text(encoding="utf-8"))
            rc = int(rec["rc"])
        except (OSError, ValueError, TypeError, KeyError):
            return None
        head = str(rec.get("headSha") or "")
        if r["state"] == "retained":
            reported = self.state.terminal_report(
                dispatch_id=r["dispatch_id"], worker_handle=r["terminal_handle"], run_id=r["run_id"]
            )
            if reported:
                # Its monitor DID settle it (that is the mail), and the coordinator retained it
                # afterwards: settling again rewrote the retain to `completed`, a `died` one
                # included, on the next show or list (#596 review of #641). Retain stays final.
                return {"exitCode": rc, "headSha": head, "died": {"syntheticDied": False, "retained": reported}}
        tail = ""
        with contextlib.suppress(OSError):
            tail = (lane / "events.jsonl").read_text(encoding="utf-8", errors="replace")[-500:]
        if rc == 0 and _col(r, "profile") == "ro":
            # The monitor relays a ro worker's completion line AFTER exit.json; one that died in
            # between must not turn a printed `failed` into worker_died (exit=0) (#596 review). Same
            # reader as the monitor's; idempotent, so a monitor that did relay is never doubled.
            self._relay_recorded_completion(r, lane, head)
        with self.state._connect() as conn:
            conn.execute("UPDATE terminals SET state = 'exited' WHERE handle = ? AND state = 'running'", (r["terminal_handle"],))
        died = self.state.ensure_terminal_or_died(
            dispatch_id=r["dispatch_id"],
            worker_handle=r["terminal_handle"],
            exit_code=rc,
            last_tail=tail,
            worktree_head_sha=head,
            run_id=r["run_id"],
        )
        return {"exitCode": rc, "headSha": head, "died": died}

    def _relay_recorded_completion(self, r: Any, lane: Path, head: str) -> dict[str, Any] | None:
        """relay_ro_completion over a dead monitor's recorded transcript; a failure is logged, never
        raised, so the exit still settles (as worker_died when no line could be read)."""
        try:
            return relay_ro_completion(
                self.state,
                dispatch_id=r["dispatch_id"],
                worker_handle=r["terminal_handle"],
                agent=str(_col(r, "agent") or ""),
                run_id=r["run_id"],
                log_path=lane / "events.jsonl",
                head_sha=head,
            )
        except (ProviderError, sqlite3.Error, OSError) as exc:
            with contextlib.suppress(OSError), open(lane / "events.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"type": "ro_relay_failed", "dispatchId": r["dispatch_id"],
                                     "error": str(exc)[:500], "by": "recovery"}) + "\n")
            return None

    def _report_vanished(self, r: Any) -> dict[str, Any]:
        """A monitor that died without reporting: salvage a sandbox's commits, then `worker_died`.

        Not while the salvage must run again (#597 review): a `worker_died` invites a retry beside
        a container that may still run, with a head that lacks the sandbox's commits. The dispatch
        stays live instead, so the next liveness sweep or reconcile retries the salvage.
        """
        # The agent it left behind is stopped FIRST, so the head recorded below is final.
        orphans = self._stop_orphaned_group(r)
        salvage = self._salvage_sandbox(r)
        if salvage and salvage.get("retry"):
            return {"salvage": salvage, "died": None, "headSha": "", "retry": True, "orphans": orphans}
        head = (salvage or {}).get("head") or ""
        if not head and r["worktree"]:
            head = _git(["rev-parse", "HEAD"], cwd=r["worktree"]).stdout.strip()
        died = self.state.ensure_terminal_or_died(
            dispatch_id=r["dispatch_id"],
            worker_handle=r["terminal_handle"],
            exit_code=-1,
            last_tail="(monitor process vanished without reporting an exit)",
            worktree_head_sha=head,
            run_id=r["run_id"],
        )
        return {"salvage": salvage, "died": died, "headSha": head, "orphans": orphans}

    def _terminate_backend(
        self,
        backend: str,
        handle: str | None,
        pid: int,
        *,
        backend_ref: str | None = None,
        container: str | None = None,
        lane_dir: str | None = None,
        grace_s: float = 3.0,
    ) -> dict[str, Any]:
        """Stop a worker for real: container, process group (SIGTERM → SIGKILL), mux session.

        A sandboxed worker's commits exist only in its private git dir until the host-side
        monitor runs `sync_sandbox_git` after `docker run` returns. So the agent (container)
        is stopped FIRST, the monitor is given time to finish that sync (it ignores
        SIGTERM/SIGHUP while syncing), and only then is the monitor's group killed (#592).
        """
        report: dict[str, Any] = {"backend": backend}
        if container:
            proc = subprocess.run(["docker", "rm", "-f", container], capture_output=True, text=True, env=self.env)
            report["container"] = {"name": container, "rc": proc.returncode}
            if lane_dir:
                exit_file = Path(lane_dir) / "exit.json"
                try:
                    sync_grace = float(self.env.get("OPEN_FLEET_SANDBOX_SYNC_GRACE_S") or 120)
                except ValueError:
                    sync_grace = 120.0
                deadline = time.time() + sync_grace
                while time.time() < deadline and not exit_file.is_file():
                    if pid and pid > 0:
                        try:
                            os.killpg(int(pid), 0)
                        except OSError:
                            break
                    time.sleep(0.1)
                try:
                    report["sandboxSync"] = json.loads(exit_file.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    report["sandboxSync"] = {"error": "monitor did not report a finished sync"}
        if pid and pid > 0:
            try:
                os.killpg(int(pid), signal.SIGTERM)
                deadline = time.time() + grace_s
                while time.time() < deadline:
                    try:
                        os.killpg(int(pid), 0)
                    except OSError:
                        break
                    time.sleep(0.05)
                else:
                    os.killpg(int(pid), signal.SIGKILL)
                report["pidGroup"] = "terminated"
            except OSError:
                report["pidGroup"] = "absent"
        if backend == "tmux" and handle:
            proc = subprocess.run(
                ["tmux", "kill-session", "-t", backend_ref or f"openfleet-{handle}"],
                capture_output=True,
                text=True,
            )
            report["tmux"] = proc.returncode
        elif backend == "cmux" and (backend_ref or handle):
            proc = subprocess.run(
                ["cmux", "close-workspace", "--workspace", backend_ref or str(handle)],
                capture_output=True,
                text=True,
            )
            report["cmux"] = proc.returncode
        return report

    def _backend_alive(self, row: Any) -> bool | None:
        """Liveness of a dispatch's process (None = cannot tell, e.g. dry-run / injected runner)."""
        backend = row["backend"] or self.backend
        # A monitor that passed the launch gate recorded its pid there even when the coordinator
        # died before publishing one (#597).
        pid = int(row["pid"] or 0) or int(_col(row, "monitor_pid") or 0)
        if self.runner is not None or backend == "dry-run":
            return None
        if pid <= 0 and not row["backend_ref"]:
            return None  # inserted before spawn and not launched yet: starting, not dead
        if backend == "tmux":
            ref = row["backend_ref"] or f"openfleet-{row['terminal_handle']}"
            return subprocess.run(["tmux", "has-session", "-t", ref], capture_output=True).returncode == 0
        if pid > 0:
            lane = Path(_col(row, "lane_dir")) if _col(row, "lane_dir") else None
            if lane is not None and (lane / "run_worker.py").is_file():
                # A worker_start dispatch: alive means THIS lane's monitor still runs under that
                # pid. `kill -0` alone said "alive" forever once the kernel reused the pid of a
                # monitor that died without reporting, and the dispatch was never swept
                # (2026-10-26 review). An injected dispatch has no monitor script to name.
                return _pid_runs_monitor(pid, lane)
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return False
            except PermissionError:
                return True
            try:
                stat = Path(f"/proc/{pid}/stat").read_text()
                if stat.rsplit(")", 1)[-1].split()[0] == "Z":
                    return False
            except (OSError, IndexError):
                pass
            return True
        return None

    def _stop_orphaned_group(self, r: Any, *, grace_s: float = 3.0) -> dict[str, Any] | None:
        """Stop the worker a vanished monitor left running in its process group (2026-10-26 review).

        The monitor leads the group its agent runs in, so `kill -9` of the monitor alone left the
        agent writing the worktree while the sweep reported the dispatch died, and a later stop
        skipped termination as "already finished". Only a group with a live member whose cwd is
        this dispatch's worktree or lane is signalled: a group id the kernel handed to someone
        else fails that check and is left alone. None: nothing was signalled (no recorded pid, a
        backend that holds no local group, an injected runner, a group already gone, or one not
        provably this worker's — on a host where neither /proc nor `ps`/`lsof` can be read, that
        is every group).
        """
        if self.runner is not None or (r["backend"] or self.backend) not in ("setsid", "tmux"):
            return None
        pgid = int(r["pid"] or 0) or int(_col(r, "monitor_pid") or 0)
        if pgid <= 0:
            return None
        try:
            os.killpg(pgid, 0)
        except OSError:
            return None  # gone, or not ours to signal
        # None (no /proc, ps or lsof) or [] (no member works in this worktree or lane): not provably this
        # worker's group, so it is left alone and nothing is reported.
        members = _group_members_under(pgid, tuple(Path(p) for p in (r["worktree"], r["lane_dir"]) if p))
        if not members:
            return None
        out: dict[str, Any] = {"pgid": pgid, "members": members}
        try:
            os.killpg(pgid, signal.SIGTERM)
            deadline = time.time() + grace_s
            while time.time() < deadline:
                try:
                    os.killpg(pgid, 0)
                except OSError:
                    break
                time.sleep(0.05)
            else:
                os.killpg(pgid, signal.SIGKILL)
            out["action"] = "terminated"
        except OSError:
            out["action"] = "absent"
        if r["lane_dir"]:
            with contextlib.suppress(OSError), open(Path(r["lane_dir"]) / "events.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"type": "orphaned_worker_stopped", "dispatchId": r["dispatch_id"], **out}) + "\n")
        return out

    def _sweep_liveness(self, rows: list[Any]) -> None:
        """A dispatch whose monitor was killed (-9) never reports; detect it and emit worker_died."""
        for r in rows:
            if r["state"] not in ("ready", "running", "retained") or r["task_id"] is None:
                continue
            if self._backend_alive(r) is not False:
                continue
            # A monitor that died between recording its exit and settling it is settled from the
            # record; skipping it left the dispatch live forever (#597 review).
            exit_file = Path(r["lane_dir"] or "/nonexistent") / "exit.json"
            if not exit_file.is_file() or self._settle_recorded_exit(r) is None:
                self._report_vanished(r)

    def _dispatch_rows(self, where: str = "", params: tuple[Any, ...] = ()) -> list[Any]:
        with self.state._connect() as conn:
            return conn.execute(f"SELECT * FROM dispatches {where}", params).fetchall()

    def worker_list(
        self,
        *,
        run: str | None = None,
        task: str | None = None,
        terminal_state: str | None = None,
        include_remote: bool = False,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        run = self.state._resolve_caller_run(run, default_run=None)
        if include_remote and self.state._worker_bound_run():
            raise ProviderError("cross_run_access", "launched worker cannot list unfiltered remote workers across runs")
        q = "WHERE 1=1"
        params: list[Any] = []
        if run:
            q += " AND run_id = ?"
            params.append(run)
        if task:
            q += " AND task_id = ?"
            params.append(task)
        q += " ORDER BY created_at DESC, dispatch_id DESC"
        self._reconcile_dead_intents(run_id=run)
        self._sweep_liveness(self._dispatch_rows(q, tuple(params)))
        rows = self._dispatch_rows(q, tuple(params))
        if terminal_state:
            rows = [r for r in rows if r["terminal_state"] == terminal_state]
        start_idx = 0
        if cursor is not None and str(cursor) != "":
            s_cur = str(cursor)
            if s_cur.isdigit():
                start_idx = int(s_cur)
            else:
                for idx, r in enumerate(rows):
                    if r["dispatch_id"] == s_cur:
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
        workers = [
            {
                "dispatchId": r["dispatch_id"],
                "taskId": r["task_id"],
                "state": r["state"],
                "terminalState": r["terminal_state"],
                "agentTerminalHandle": r["terminal_handle"],
                "worktree": r["worktree"],
            }
            for r in page_rows
        ]
        return {"workers": workers, "scope": {"source": "posix"}, "page": {"nextCursor": next_cursor}}

    def worker_show(self, dispatch_id: str) -> dict[str, Any]:
        bound = self.state._resolve_caller_run(None, default_run=None)
        self._reconcile_dead_intents(run_id=bound)
        rows = self._dispatch_rows("WHERE dispatch_id = ?", (dispatch_id,))
        if not rows:
            raise ProviderError("dispatch_not_found", f"dispatch {dispatch_id!r} not found")
        row_run = str(rows[0]["run_id"] or "default")
        if bound and row_run != bound:
            raise ProviderError("cross_run_access", f"dispatch {dispatch_id!r} belongs to run {row_run!r}, not {bound!r}")
        self._sweep_liveness(rows)
        r = self._dispatch_rows("WHERE dispatch_id = ?", (dispatch_id,))[0]
        return normalize_show(
            r["dispatch_id"],
            r["state"],
            task_id=r["task_id"],
            terminal_state=r["terminal_state"],
            handle=r["terminal_handle"],
            worktree=r["worktree"],
        )

    @staticmethod
    def _parse_nonneg_int(val: Any, name: str) -> int:
        if isinstance(val, bool):
            raise ProviderError("invalid_argument", f"{name} must be a non-negative integer, got {val!r}")
        if isinstance(val, int):
            if val < 0:
                raise ProviderError("invalid_argument", f"{name} must be a non-negative integer, got {val!r}")
            return val
        if isinstance(val, str):
            s = val.strip()
            if s.isdigit():
                return int(s)
        raise ProviderError("invalid_argument", f"{name} must be a non-negative integer, got {val!r}")

    def worker_read(
        self,
        dispatch_id: str,
        source: str = "transcript",
        limit: int = 50,
        cursor: str | int | None = None,
    ) -> dict[str, Any]:
        bound = self.state._resolve_caller_run(None, default_run=None)
        rows = self._dispatch_rows("WHERE dispatch_id = ?", (dispatch_id,))
        if not rows:
            raise ProviderError("dispatch_not_found", f"dispatch {dispatch_id!r} not found")
        r = rows[0]
        row_run = str(r["run_id"] or "default")
        if bound and row_run != bound:
            raise ProviderError("cross_run_access", f"dispatch {dispatch_id!r} belongs to run {row_run!r}, not {bound!r}")
        log_file = Path(r["lane_dir"]) / "events.jsonl" if r["lane_dir"] else None
        all_lines: list[str] = []
        if log_file and log_file.is_file():
            all_lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
        total = len(all_lines)
        if cursor is not None and str(cursor) != "":
            cur_idx = self._parse_nonneg_int(cursor, "cursor")
            after = all_lines[cur_idx:]
            if limit is not None:
                lim = self._parse_nonneg_int(limit, "limit")
                lines = after[:lim]
                truncated = len(after) > lim
            else:
                lines = after
                truncated = False
            next_cursor = cur_idx + len(lines)
        else:
            if limit is not None:
                lim = self._parse_nonneg_int(limit, "limit")
                truncated = total > lim
                lines = all_lines[-lim:] if lim > 0 else []
            else:
                lines = all_lines
                truncated = False
            next_cursor = total
        if source == "transcript":
            return normalize_read("transcript", lines=lines, cursor=next_cursor, truncated=truncated)
        return normalize_read(
            "terminal",
            lines=lines,
            cursor=next_cursor,
            truncated=truncated,
            handle=r["terminal_handle"],
        )

    @staticmethod
    def _purge_private_inbox(worktree: str | None) -> None:
        if not worktree:
            return
        with contextlib.suppress(OSError):
            inbox_dir = Path(worktree) / ".open-fleet"
            if inbox_dir.is_symlink():
                return
            inbox_file = inbox_dir / "inbox.jsonl"
            if inbox_file.exists() or inbox_file.is_symlink():
                inbox_file.unlink(missing_ok=True)
            if inbox_dir.is_dir() and not any(inbox_dir.iterdir()):
                inbox_dir.rmdir()

    def worker_fence(
        self,
        verb: str,
        dispatch_id: str,
        reason: str | None = None,
        retry_request: str | None = None,
    ) -> dict[str, Any]:
        bound = self.state._resolve_caller_run(None, default_run=None)
        if bound:
            rows_chk = self._dispatch_rows("WHERE dispatch_id = ?", (dispatch_id,))
            if rows_chk:
                row_run = str(rows_chk[0]["run_id"] or "default")
                if row_run != bound:
                    raise ProviderError(
                        "cross_run_access",
                        f"dispatch {dispatch_id!r} belongs to run {row_run!r}, not {bound!r}",
                    )
        payload_sha = _launch_payload_sha256({"verb": verb, "dispatch_id": dispatch_id, "reason": reason})
        method = f"worker-{verb}"
        cached = self.state.get_or_record_request(retry_request, method, payload_sha)
        if cached:
            return cached
        try:
            new_state, term_state = fence_state(verb)
            with self.state._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                r = conn.execute("SELECT * FROM dispatches WHERE dispatch_id = ?", (dispatch_id,)).fetchone()
                if not r:
                    conn.execute("ROLLBACK")
                    raise ProviderError("dispatch_not_found", f"dispatch {dispatch_id!r} not found")
                handle = r["terminal_handle"]
                if verb != "retain" and handle:
                    conn.execute("UPDATE terminals SET state = ? WHERE handle = ?", (term_state, handle))
                conn.execute(
                    "UPDATE dispatches SET state = ?, terminal_state = ?, updated_at = ? WHERE dispatch_id = ?",
                    (new_state, term_state, time.time(), dispatch_id),
                )
                if verb != "retain":
                    # A fence before any monitor claimed closes the launch gate for good, in the
                    # same transaction: a later retain rewrites the state for inspection, but a
                    # late monitor from a dead coordinator's launcher never runs under it (#597).
                    conn.execute(
                        "UPDATE dispatches SET gate_closed_at = COALESCE(gate_closed_at, ?) "
                        "WHERE dispatch_id = ? AND monitor_started_at IS NULL",
                        (time.time(), dispatch_id),
                    )
                gated = conn.execute("SELECT * FROM dispatches WHERE dispatch_id = ?", (dispatch_id,)).fetchone()
                conn.execute("COMMIT")
            if verb != "retain":
                self._purge_private_inbox(r["worktree"])
            never_ran = self._gate_proves_never_ran(gated)
            out: dict[str, Any] = {"dispatchId": dispatch_id, "state": new_state, "terminalState": term_state}
            finished = r["state"] in ("completed", "died", *FENCED_DISPATCH_STATES) or (
                bool(r["lane_dir"]) and (Path(r["lane_dir"]) / "exit.json").is_file()
            )
            if verb != "retain" and finished:
                # Already exited: its pid may belong to an unrelated process group by now, so only
                # a group proven to be this worker's (a vanished monitor's agent) is still stopped.
                out["termination"] = {"skipped": "dispatch already finished"}
                orphans = self._stop_orphaned_group(r)
                if orphans:
                    out["termination"]["orphans"] = orphans
            elif verb != "retain":
                # Record first (the launch gate and the post-spawn check read it), then tear down.
                container = ""
                try:
                    container = json.loads(r["launch_effective"] or "{}").get("container") or ""
                except json.JSONDecodeError:
                    container = ""
                out["termination"] = self._terminate_backend(
                    r["backend"] or self.backend,
                    handle,
                    # No published pid (its coordinator died first): the gate-recorded one (#597).
                    int(r["pid"] or 0) or int(_col(r, "monitor_pid") or 0),
                    backend_ref=r["backend_ref"],
                    container=container,
                    # A gate closed before any claim: no monitor ran or can, so no sync is coming (#597).
                    lane_dir=None if never_ran else r["lane_dir"],
                )
                if never_ran:
                    out["termination"]["gate"] = "closed"
            self.state.save_request(retry_request, method, "completed", out, payload_sha)
            return out
        except BaseException:
            self.state.release_request(retry_request)
            raise

    def vm_recipe_doctor(self, recipe_id: str) -> dict[str, Any]:
        """Probe the Docker sandbox a `danger` worker would launch into (`--on <image>`)."""
        checks: list[dict[str, Any]] = []
        failures: list[str] = []
        docker = shutil.which("docker", path=self.env.get("PATH"))
        checks.append({"id": "docker-cli", "status": "pass" if docker else "fail"})
        if not docker:
            failures.append("docker CLI not on PATH")
        else:
            proc = subprocess.run(["docker", "image", "inspect", recipe_id], capture_output=True, text=True, env=self.env)
            ok = proc.returncode == 0
            checks.append({"id": "image-present", "status": "pass" if ok else "fail"})
            if not ok:
                failures.append(f"image {recipe_id!r} not present: {(proc.stderr or '').strip()[:160]}")
        checks.append({"id": "isolation-flags", "status": "pass"})
        user = self.env.get("OPEN_FLEET_SANDBOX_USER")
        return {
            "recipeId": recipe_id,
            "backend": "docker",
            "ok": not failures,
            "checks": checks,
            "isolation": {
                "capDrop": ["ALL"],
                "noNewPrivileges": True,
                "pidsLimit": 512,
                "privileged": False,
                "network": "bridge",
                "user": user if user is not None else f"{os.getuid()}:{os.getgid()}",
            },
            "mounts": [
                {"source": "<worktree>", "target": "<worktree>", "mode": "rw"},
                {"source": "<worktree>/.git", "target": "<worktree>/.git", "mode": "ro"},
                {"source": "<lane>/sandbox.git", "target": SANDBOX_GIT_MOUNT, "mode": "rw"},
                {"source": str(RUNTIME_DIR), "target": str(RUNTIME_DIR), "mode": "ro"},
            ],
            # --rm container + private git dir; credentials are never mounted; the recipe IS the
            # image `worker_start --on <recipe>` binds before launch.
            "ephemeral": True,
            "credential_mounts": [],
            "prelaunch_placement_bound": True,
            "failures": failures,
            "warnings": [],
        }

    # --- Custom-Argv Terminal Operations (`terminal create/wait/read/list/show/send` + `dispatch --inject`) ---
    def terminal_create(
        self,
        worktree: str | None = None,
        title: str | None = None,
        command: str | None = None,
        shell: str | None = None,
        focus: bool = False,
    ) -> dict[str, Any]:
        worker_run = self.state._worker_bound_run()
        if worker_run:
            raise ProviderError(
                "cross_run_access",
                f"launched worker in run {worker_run!r} cannot create unsupervised terminals",
            )
        wt_path = self._resolve_worktree_path(worktree or "current", title)
        Path(wt_path).mkdir(parents=True, exist_ok=True)
        handle = f"term_{uuid.uuid4().hex[:8]}"
        lane_dir = self.state.db_path.parent / "terminals" / handle
        lane_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        log_file = lane_dir / "events.jsonl"
        log_file.touch(mode=0o600)
        # Row first: the process can never be orphaned by a failed insert (#578 audit).
        with self.state._connect() as conn:
            conn.execute(
                """
                INSERT INTO terminals(handle, worktree, title, command, shell, pid, backend, log_path, state, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    handle,
                    wt_path,
                    title or handle,
                    command or "",
                    shell or "/bin/sh",
                    0,
                    self.backend,
                    str(log_file),
                    "running" if command else "idle",
                    time.time(),
                ),
            )
        if command:
            try:
                spawn = self._spawn_process(
                    dispatch_id=f"unsupervised_{handle}",
                    term_handle=handle,
                    wt_path=wt_path,
                    command=command,
                    env_vars={"ORCA_TERMINAL_HANDLE": handle, "OPEN_FLEET_TERMINAL_HANDLE": handle},
                    lane_dir=lane_dir,
                    run_id="default",
                    supervised=False,
                )
            except BaseException:
                with self.state._connect() as conn:
                    conn.execute("UPDATE terminals SET state = 'failed' WHERE handle = ?", (handle,))
                raise
            with self.state._connect() as conn:
                conn.execute(
                    "UPDATE terminals SET pid = ?, backend = ?, backend_ref = ? WHERE handle = ?",
                    (int(spawn.get("pid", 0) or 0), spawn.get("backend", self.backend), spawn.get("backendRef") or "", handle),
                )
        return {"terminal": {"handle": handle, "id": handle, "title": title or handle, "worktree": wt_path}}

    def _terminal_row(self, terminal: str) -> Any:
        bound = self.state._resolve_caller_run(None, default_run=None)
        with self.state._connect() as conn:
            r = conn.execute("SELECT * FROM terminals WHERE handle = ?", (terminal,)).fetchone()
            foreign = (
                conn.execute(
                    "SELECT run_id FROM dispatches WHERE terminal_handle = ? AND run_id != ? LIMIT 1",
                    (terminal, bound),
                ).fetchone()
                if bound
                else None
            )
            owned = (
                conn.execute(
                    "SELECT 1 FROM dispatches WHERE terminal_handle = ? AND run_id = ? LIMIT 1",
                    (terminal, bound),
                ).fetchone()
                if bound
                else True
            )
        if foreign:
            raise ProviderError(
                "cross_run_access",
                f"terminal {terminal!r} is bound to run {foreign['run_id']!r}, not {bound!r}",
            )
        if bound and not owned:
            raise ProviderError(
                "cross_run_access",
                f"launched worker in run {bound!r} cannot access unregistered terminal {terminal!r}",
            )
        if not r:
            raise ProviderError("terminal_not_found", f"terminal {terminal!r} not found")
        return r

    def _screen(self, r: Any) -> str | None:
        backend = r["backend"] or self.backend
        if self.runner is not None:
            return None
        if backend == "tmux":
            ref = r["backend_ref"] or f"openfleet-{r['handle']}"
            proc = subprocess.run(["tmux", "capture-pane", "-p", "-t", ref], capture_output=True, text=True)
            return proc.stdout if proc.returncode == 0 else None
        if backend == "cmux" and r["backend_ref"]:
            proc = subprocess.run(["cmux", "read-screen", "--workspace", r["backend_ref"]], capture_output=True, text=True)
            return proc.stdout if proc.returncode == 0 else None
        return None

    def terminal_wait(self, terminal: str, condition: str = "tui-idle", timeout_ms: int = 90000) -> dict[str, Any]:
        """Poll REAL terminal state until `condition` holds or `timeout_ms` passes.

        `exit`: the process is gone. `tui-idle`: the screen (tmux/cmux) or output log stopped
        changing for 1s while the process is alive. Any other condition: that marker appears in
        output written AFTER the wait began. Nothing is pre-written to satisfy a wait.
        """
        r = self._terminal_row(terminal)
        normalized = condition.replace("_", "-")
        deadline = time.time() + max(0, int(timeout_ms)) / 1000.0
        log_path = Path(r["log_path"]) if r["log_path"] else None
        start_size = log_path.stat().st_size if log_path and log_path.is_file() else 0
        last_snapshot: Any = object()
        stable_since = time.time()
        while True:
            r = self._terminal_row(terminal)
            alive = r["state"] == "running"
            if normalized == "exit":
                if not alive:
                    return {"wait": {"satisfied": True, "condition": condition, "terminal": terminal}}
            else:
                if not alive:
                    raise ProviderError("terminal_not_running", f"terminal {terminal!r} is in state {r['state']!r}")
                screen = self._screen(r)
                content = ""
                if log_path and log_path.is_file():
                    content = log_path.read_bytes()[start_size:].decode("utf-8", errors="replace")
                if normalized == "tui-idle":
                    snapshot = screen if screen is not None else (log_path.stat().st_size if log_path and log_path.is_file() else 0)
                    if snapshot != last_snapshot:
                        last_snapshot = snapshot
                        stable_since = time.time()
                    elif time.time() - stable_since >= 1.0 and (self.backend == "dry-run" or screen is not None or content):
                        return {"wait": {"satisfied": True, "condition": condition, "terminal": terminal}}
                elif condition in content or normalized in content or condition in (screen or ""):
                    return {"wait": {"satisfied": True, "condition": condition, "terminal": terminal}}
            if time.time() >= deadline:
                raise ProviderError("terminal_wait_timeout", f"terminal {terminal!r} did not reach {condition!r}")
            time.sleep(0.1)

    def terminal_read(
        self,
        terminal: str,
        cursor: int | str | None = None,
        limit: int | None = None,
        screen: bool = False,
    ) -> dict[str, Any]:
        r = self._terminal_row(terminal)
        all_lines: list[str] = []
        src = "stream"
        if screen:
            text = self._screen(r)
            if text is not None:
                all_lines = text.splitlines()
                src = "screen"
            else:
                src = "screen-unavailable"
        if not all_lines and r["log_path"] and Path(r["log_path"]).is_file():
            all_lines = Path(r["log_path"]).read_text(encoding="utf-8", errors="replace").splitlines()
        total = len(all_lines)
        if cursor is not None and str(cursor) != "":
            cur_idx = self._parse_nonneg_int(cursor, "cursor")
            after = all_lines[cur_idx:]
            if limit is not None:
                lim = self._parse_nonneg_int(limit, "limit")
                lines = after[:lim]
                truncated = len(after) > lim
            else:
                lines = after
                truncated = False
            next_cursor = cur_idx + len(lines)
        else:
            if limit is not None:
                lim = self._parse_nonneg_int(limit, "limit")
                truncated = total > lim
                lines = all_lines[-lim:] if lim > 0 else []
            else:
                lines = all_lines
                truncated = False
            next_cursor = total
        return {
            "terminal": {
                "handle": terminal,
                "tail": lines,
                "cursor": next_cursor,
                "truncated": truncated,
                "source": src,
            },
            "source": src,
            "cursor": next_cursor,
            "truncated": truncated,
        }

    def terminal_list(
        self,
        worktree: str | None = None,
        limit: int | None = None,
        include_visual_layouts: bool = False,
    ) -> dict[str, Any]:
        bound = self.state._resolve_caller_run(None, default_run=None)
        with self.state._connect() as conn:
            rows = conn.execute("SELECT * FROM terminals ORDER BY created_at DESC").fetchall()
            foreign_handles = (
                {
                    str(fr["terminal_handle"])
                    for fr in conn.execute(
                        "SELECT DISTINCT terminal_handle FROM dispatches WHERE terminal_handle != '' AND run_id != ?",
                        (bound,),
                    ).fetchall()
                }
                if bound
                else set()
            )
            owned_handles = (
                {
                    str(orow["terminal_handle"])
                    for orow in conn.execute(
                        "SELECT DISTINCT terminal_handle FROM dispatches WHERE terminal_handle != '' AND run_id = ?",
                        (bound,),
                    ).fetchall()
                }
                if bound
                else None
            )
        terms = [
            {
                "handle": r["handle"],
                "title": r["title"],
                "worktree": r["worktree"],
                "state": r["state"],
            }
            for r in rows
            if r["handle"] not in foreign_handles
            and (owned_handles is None or r["handle"] in owned_handles)
            and (not worktree or r["worktree"] == worktree)
        ]
        truncated = False
        if limit and len(terms) > int(limit):
            terms = terms[: int(limit)]
            truncated = True
        return {"terminals": terms, "truncated": truncated}

    def terminal_show(self, terminal: str) -> dict[str, Any]:
        r = self._terminal_row(terminal)
        return {
            "terminal": {
                "handle": r["handle"],
                "title": r["title"],
                "worktree": r["worktree"],
                "state": r["state"],
            }
        }

    @staticmethod
    def _write_private_append(path: Path, data: str) -> None:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if path.is_symlink():
            return
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | nofollow, 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
                return
            os.fchmod(fd, 0o600)
            os.write(fd, data.encode("utf-8"))
        finally:
            os.close(fd)

    def _deliver_terminal_input(self, term_row: Any, text: str, enter: bool = True) -> bool:
        """Deliver `text` to a live terminal. Returns True once the transport ACCEPTED it.

        Raises (nothing accepted) when the terminal is not running or the backend has no input
        channel: a detached `setsid` process has no stdin, so pretending to deliver there is the
        false success the #591 review flagged. Bookkeeping after acceptance is best-effort.
        """
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
            ref = term_row["backend_ref"] or f"openfleet-{handle}"
            proc = subprocess.run(tmux_send_keys_argv(ref, text), capture_output=True, text=True)
            if proc.returncode == 0 and enter:
                proc = subprocess.run(["tmux", "send-keys", "-t", ref, "Enter"], capture_output=True, text=True)
            if proc.returncode != 0:
                raise ProviderError("terminal_send_failed", (proc.stderr or "tmux send-keys failed").strip())
        elif backend == "cmux":
            if not term_row["backend_ref"]:
                raise ProviderError("terminal_send_failed", f"terminal {handle!r} has no cmux workspace id")
            # The text is cmux's last positional, so a `-`-leading one rides after `--` (W2-01).
            # Only then: cmux's `--` handling is UNVERIFIED here (no cmux on the audit host), and
            # every other payload keeps the argv it has always had.
            end_opts = ["--"] if payload.startswith("-") else []
            proc = subprocess.run(
                ["cmux", "send", "--workspace", term_row["backend_ref"], *end_opts, payload],
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                raise ProviderError("terminal_send_failed", (proc.stderr or "cmux send failed").strip())
        elif backend != "dry-run":
            raise ProviderError(
                "unsupported_operation",
                f"terminal {handle!r} runs on backend {backend!r}, which has no input channel; use tmux or cmux",
            )
        # Accepted. Everything below is bookkeeping and must not undo the delivery.
        try:
            if term_row["worktree"]:
                wt = Path(term_row["worktree"])
                if wt.is_dir() and not wt.is_symlink() and wt.stat().st_uid == os.getuid():
                    inbox_dir = wt / ".open-fleet"
                    if not inbox_dir.is_symlink():
                        inbox_dir.mkdir(mode=0o700, exist_ok=True)
                        if inbox_dir.is_dir() and not inbox_dir.is_symlink() and inbox_dir.stat().st_uid == os.getuid():
                            os.chmod(inbox_dir, 0o700)
                            self._write_private_append(
                                inbox_dir / "inbox.jsonl",
                                json.dumps({"handle": handle, "text": text, "ts": time.time()}) + "\n",
                            )
            if backend == "dry-run" and term_row["log_path"]:
                self._write_private_append(Path(term_row["log_path"]), payload)
        except OSError:
            pass
        return True

    def terminal_send(
        self,
        terminal: str,
        text: str,
        enter: bool = True,
        run: str | None = None,
    ) -> dict[str, Any]:
        eff_run = self.state._resolve_caller_run(run, default_run=None)
        if eff_run is not None:
            with self.state._connect() as conn:
                disp = conn.execute(
                    "SELECT run_id FROM dispatches WHERE terminal_handle = ? ORDER BY created_at DESC LIMIT 1",
                    (terminal,),
                ).fetchone()
            if disp and disp["run_id"] != eff_run:
                raise ProviderError(
                    "cross_run_access",
                    f"terminal {terminal!r} is bound to run {disp['run_id']!r}, not {eff_run!r}",
                )
        r = self._terminal_row(terminal)
        self._deliver_terminal_input(r, text, enter=enter)
        req_id = f"req_{uuid.uuid4().hex[:10]}"
        stages = ["input_accepted"] if (r["backend"] or self.backend) != "dry-run" else ["input_accepted", "simulated"]
        return {"send": {"accepted": True, "prompt": {"requestId": req_id, "stages": stages}}}

    def dispatch_inject(
        self,
        task_id: str,
        to_handle: str,
        run: str | None = None,
        sender: str | None = None,
    ) -> dict[str, Any]:
        worker_run = self.state._worker_bound_run()
        eff_run = self.state._resolve_caller_run(run, default_run=None)
        req_id = f"req_{uuid.uuid4().hex[:10]}"
        dispatch_id = f"disp_{uuid.uuid4().hex[:10]}"
        now = time.time()
        with self.state._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            t_row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if not t_row:
                conn.execute("ROLLBACK")
                raise ProviderError("task_not_found", f"task {task_id!r} not found")
            if eff_run is not None and t_row["run_id"] != eff_run:
                conn.execute("ROLLBACK")
                raise ProviderError(
                    "cross_run_access",
                    f"task {task_id!r} belongs to run {t_row['run_id']!r}, not {eff_run!r}",
                )
            effective_run = t_row["run_id"] or "default"
            term_row = conn.execute("SELECT * FROM terminals WHERE handle = ?", (to_handle,)).fetchone()
            if not term_row:
                conn.execute("ROLLBACK")
                raise ProviderError("inject_rejected", f"terminal {to_handle!r} not found")
            bound_disp = conn.execute(
                "SELECT run_id FROM dispatches WHERE terminal_handle = ? AND run_id != ? LIMIT 1",
                (to_handle, effective_run),
            ).fetchone()
            if bound_disp:
                conn.execute("ROLLBACK")
                raise ProviderError(
                    "cross_run_access",
                    f"terminal {to_handle!r} is bound to run {bound_disp['run_id']!r}, not {effective_run!r}",
                )
            if worker_run:
                owned_disp = conn.execute(
                    "SELECT 1 FROM dispatches WHERE terminal_handle = ? AND run_id = ? LIMIT 1",
                    (to_handle, effective_run),
                ).fetchone()
                if owned_disp is None:
                    conn.execute("ROLLBACK")
                    raise ProviderError(
                        "cross_run_access",
                        f"launched worker in run {worker_run!r} cannot inject into unregistered terminal {to_handle!r}",
                    )
            cur = conn.execute(
                "UPDATE tasks SET status = 'dispatched', updated_at = ? WHERE id = ? AND status = 'ready'",
                (now, task_id),
            )
            if cur.rowcount != 1:
                conn.execute("ROLLBACK")
                raise ProviderError("task_not_startable", f"task {task_id!r} has status {t_row['status']!r} (must be 'ready')")
            # Injected work is a real dispatch: it shows in worker-list and its crash is linkable.
            conn.execute(
                """
                INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, profile, terminal_handle, state, terminal_state, pid, backend, backend_ref, launch_effective, lane_dir, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'custom', ?, ?, 'ready', 'active', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dispatch_id,
                    task_id,
                    effective_run,
                    term_row["worktree"] or "",
                    self.env.get("OPEN_FLEET_SANDBOX_PROFILE") or "ro",
                    to_handle,
                    int(term_row["pid"] or 0),
                    term_row["backend"] or self.backend,
                    term_row["backend_ref"] or "",
                    json.dumps({"agent": "custom", "command": term_row["command"] or "", "inject": True}),
                    str(Path(term_row["log_path"]).parent) if term_row["log_path"] else "",
                    now,
                    now,
                ),
            )
            conn.execute("COMMIT")
        injected_line = json.dumps({"type": "injected_prompt", "taskId": task_id, "spec": t_row["spec"]})
        try:
            self._deliver_terminal_input(term_row, injected_line, enter=True)
        except BaseException:
            # Nothing was accepted: give the task back and drop the dispatch.
            with self.state._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "UPDATE tasks SET status = 'ready', updated_at = ? WHERE id = ? AND status = 'dispatched'",
                    (time.time(), task_id),
                )
                conn.execute("DELETE FROM dispatches WHERE dispatch_id = ?", (dispatch_id,))
                conn.execute("COMMIT")
            raise
        return {
            "injected": True,
            "dispatchId": dispatch_id,
            "prompt": {
                "requestId": req_id,
                "stages": ["input_accepted"],
            },
        }


def _parse_cmux_workspace_ref(out: str) -> str:
    """Extract the workspace id `cmux new-workspace` printed (JSON or `OK <id>` text)."""
    text = (out or "").strip()
    if not text:
        return ""
    try:
        doc = json.loads(text)
        if isinstance(doc, dict):
            for key in ("workspace_id", "workspaceId", "id", "ref", "workspace"):
                val = doc.get(key)
                if isinstance(val, (str, int)) and str(val).strip():
                    return str(val)
                if isinstance(val, dict) and val.get("id"):
                    return str(val["id"])
    except json.JSONDecodeError:
        pass
    for tok in text.replace(",", " ").split():
        if tok.upper() == "OK":
            continue
        return tok.strip()
    return ""
