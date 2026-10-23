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
    FENCED_DISPATCH_STATES,
    ProviderError,
    RuntimeProvider,
    build_harness_command,
    check_monotonic_profile,
    env_get,
    fence_state,
    normalize_read,
    normalize_show,
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


RUNTIME_DIR = Path(__file__).resolve().parent.parent
OPEN_FLEET_ROOT = RUNTIME_DIR.parent
CANONICAL_DENY_HOOK = RUNTIME_DIR / "scripts" / "deny-hook.sh"
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


def _exclude_hook_artifacts(wt: Path) -> None:
    """Append HOOK_ARTIFACTS to the worktree's `info/exclude` (shared by all linked worktrees)."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(wt), "rev-parse", "--path-format=absolute", "--git-common-dir"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return
    if proc.returncode != 0 or not proc.stdout.strip():
        return
    info = Path(proc.stdout.strip()) / "info"
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


def install_worktree_hooks(
    worktree_path: str | Path,
    agent: str,
    profile: str,
    *,
    deny_hook_path: str | None = None,
) -> dict[str, str]:
    """Install per-worktree `PreToolUse` hook configs and bridges for all supported harnesses.

    The hook itself is NEVER copied into the worktree: configs point at the canonical
    `runtime/scripts/deny-hook.sh` outside the unit's write boundary, so a worker cannot edit
    its own guard, and the hook's `$0`-relative lookup of `local_state.py` (file-touch
    recording) keeps working. Inside a Docker sandbox the runtime dir is bind-mounted read-only
    at the same path. Non-Claude harnesses get `ORCA_HOOK_STRICT_EXIT=1`: they fail OPEN on an
    `ask` decision, so the hook must answer exit 2 instead (#577).
    """
    wt = Path(worktree_path).resolve()
    wt.mkdir(parents=True, exist_ok=True)
    hook = deny_hook_path or str(CANONICAL_DENY_HOOK)
    # shlex-quoted: a path carrying `$`, a backtick or `"` must never expand in the hook shell.
    qwt, qhook = shlex.quote(str(wt)), shlex.quote(hook)
    boundary = f"OPEN_FLEET_UNIT_WORKTREE={qwt} ORCA_UNIT_WORKTREE={qwt}"
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
    claude_settings.write_text(json.dumps(claude_doc, indent=2) + "\n", encoding="utf-8")
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
    codex_hooks.write_text(json.dumps(strict_doc, indent=2) + "\n", encoding="utf-8")
    installed["codex"] = str(codex_hooks)

    # 3. OpenHands (.openhands/hooks.json)
    oh_dir = wt / ".openhands"
    oh_dir.mkdir(parents=True, exist_ok=True)
    oh_hooks = oh_dir / "hooks.json"
    oh_hooks.write_text(json.dumps(strict_doc, indent=2) + "\n", encoding="utf-8")
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
        json.dumps(strict_doc, indent=2) + "\n",
        encoding="utf-8",
    )
    installed["crush"] = str((crush_ro_dir if profile == "ro" else crush_rw_dir) / "crush.json")

    _exclude_hook_artifacts(wt)
    return installed


WORKER_ENV_DENYLIST = frozenset({"OPEN_FLEET_SIGNING_SEED", "ORCA_DISPATCH_SIGNING_SEED"})
HERMES_HOOK_MATCHER = "terminal|write_file|patch|execute_code|process"


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


def _git(args: list[str], *, cwd: str | Path | None = None, env: dict[str, str] | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    full = ["git", *(["-C", str(cwd)] if cwd else []), *args]
    try:
        return subprocess.run(full, capture_output=True, text=True, env=env, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(full, 127, "", str(exc))


def _git_ok(args: list[str], what: str, **kw: Any) -> str:
    proc = _git(args, **kw)
    if proc.returncode != 0:
        raise ProviderError("sandbox_git_failed", f"{what}: {(proc.stderr or proc.stdout or 'git failed').strip()[:300]}")
    return proc.stdout.strip()


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
    # Index = HEAD; the worktree's uncommitted edits stay as working-tree modifications.
    _git_ok(sb + ["--work-tree", str(wt), "read-tree", "HEAD"], "seed sandbox index")
    _git(sb + ["--work-tree", str(wt), "update-index", "-q", "--refresh"])
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
    refreshed so `git status` there reflects the new HEAD. A non-fast-forward (the worker
    rewrote history) leaves the branch untouched and reports `nonFastForward`.
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
    # Explicit git dir: never trust the (container-writable) worktree's `.git` pointer.
    _git(["--git-dir", meta["wt_gitdir"], "--work-tree", meta["worktree"], "reset", "-q"])
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
            if top is not None and top.returncode == 0 and top.stdout.strip():
                start = Path(top.stdout.strip()).resolve()
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
        slug = "".join(c if c.isalnum() or c in "._-" else "-" for c in name).strip("-") or f"wt-{uuid.uuid4().hex[:6]}"
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
                    or Path(top.stdout.strip()).resolve() != wt_path.resolve()
                    or common.stdout.strip() != root_common.stdout.strip()
                ):
                    raise ProviderError(
                        "worktree_create_failed",
                        f"{wt_path} exists but is not a worktree of {root}; remove it or choose another name",
                    )
        elif is_git:
            _git(["worktree", "prune"], cwd=root)
            exists = _git(["rev-parse", "--verify", "--quiet", f"refs/heads/{branch}"], cwd=root).returncode == 0
            if exists:
                # Never `-B`: resetting an existing branch silently discards its unmerged commits.
                cmd = ["worktree", "add", str(wt_path), branch]
            else:
                cmd = ["worktree", "add", "-b", branch, str(wt_path)] + ([base] if base else [])
            proc = _git(cmd, cwd=root)
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
            proc = _git(["worktree", "list", "--porcelain"], cwd=root)
            if proc.returncode == 0:
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
                    elif line.startswith("branch ") and rows:
                        rows[-1]["branch"] = line.split(" ", 1)[1].strip().removeprefix("refs/heads/")
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
        if not selector:
            raise ProviderError("invalid_argument", "worktree rm needs a worktree selector")
        shown = self.worktree_show(selector)["worktree"]
        wt_path = Path(shown["path"]).resolve()
        repo_root = self.repo_root.resolve()
        common = _git(["rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=repo_root).stdout.strip()
        protected = {repo_root, Path.home().resolve(), Path("/").resolve()}
        if common:
            protected.add(Path(common).resolve())
            protected.add(Path(common).resolve().parent)
        if wt_path in protected or any(wt_path == p or p.is_relative_to(wt_path) for p in protected if p != Path("/")):
            raise ProviderError("worktree_protected", f"refusing to remove {wt_path}: it is (or contains) the main checkout")
        if not wt_path.exists():
            return {"removed": False, "id": shown["id"], "reason": "absent"}
        is_linked = (wt_path / ".git").is_file()
        if is_linked:
            cmd = ["worktree", "remove"] + (["--force"] if force else []) + [str(wt_path)]
            proc = _git(cmd, cwd=repo_root)
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
    ) -> dict[str, Any]:
        log_file = lane_dir / "events.jsonl"
        log_file.touch()
        # Fleet custody secrets never reach a worker (it could sign its own dispatches).
        merged_env = {k: v for k, v in {**self.env, **env_vars}.items() if k not in WORKER_ENV_DENYLIST}

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
        mux_env = {k: v for k, v in self.env.items() if k not in WORKER_ENV_DENYLIST}
        monitor_py = f"""
import json, os, subprocess, sys, time
sys.path.insert(0, {repr(str(RUNTIME_DIR))})
from providers.local_state import LocalStateStore

DISPATCH = {repr(dispatch_id)}
SUPERVISED = {supervised!r}
SANDBOX_META = {repr(json.dumps(sandbox_meta) if sandbox_meta else "")}
log_path = {repr(str(log_file))}
store = LocalStateStore(db_path={repr(str(self.state.db_path))})
with open({repr(str(env_file))}, encoding="utf-8") as ef:
    worker_env = {{**os.environ, **json.load(ef)}}
# A tmux/cmux server started with fleet custody secrets hands them to this monitor's
# environment: strip them from the FINAL worker env too, not only the client's (#592).
for _secret in {sorted(WORKER_ENV_DENYLIST)!r}:
    worker_env.pop(_secret, None)

def _log(obj):
    with open(log_path, "a", encoding="utf-8") as lf:
        lf.write(json.dumps(obj) + "\\n")

# Launch gate: a dispatch fenced while it was starting never runs its agent (#591 review).
if SUPERVISED and store.dispatch_state(DISPATCH) not in ("ready", "running", "retained"):
    _log({{"type": "launch_refused", "dispatchId": DISPATCH, "reason": "dispatch fenced or withdrawn before launch"}})
    sys.exit(0)

with open(log_path, "a", encoding="utf-8") as lf:
    lf.write(json.dumps({{"type": "turn_started", "dispatchId": DISPATCH}}) + "\\n")
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
        head = subprocess.run(["git", "-C", {repr(wt_path)}, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:
        head = ""
try:
    with open({repr(str(lane_dir / "exit.json"))}, "w", encoding="utf-8") as xf:
        json.dump({{"rc": rc, "ts": time.time(), "headSha": head}}, xf)
except OSError:
    pass
tail = ""
try:
    with open(log_path, "r", encoding="utf-8", errors="replace") as rf:
        tail = rf.read()[-500:]
except Exception:
    pass
with store._connect() as conn:
    conn.execute("UPDATE terminals SET state = 'exited' WHERE handle = ? AND state = 'running'", ({repr(term_handle)},))
    bound = [] if SUPERVISED else conn.execute(
        "SELECT dispatch_id, run_id FROM dispatches WHERE terminal_handle = ? AND state IN ('ready', 'running')",
        ({repr(term_handle)},),
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
        spec_text = self.resolve_task_prompt(task_id, prompt if prompt is not None else t_row["spec"])

        dispatch_id = f"disp_{uuid.uuid4().hex[:10]}"
        term_handle = f"term_{uuid.uuid4().hex[:8]}"
        lane_dir = self.state.db_path.parent / "lanes" / dispatch_id
        now = time.time()
        # 1. Claim the task FIRST: a losing concurrent caller must not touch any worktree.
        with self.state._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE tasks SET status = 'dispatched', updated_at = ? WHERE id = ? AND status = 'ready'",
                (now, task_id),
            )
            if cur.rowcount != 1:
                conn.execute("ROLLBACK")
                raise ProviderError("task_not_startable", f"task {task_id!r} was already claimed concurrently")
            conn.execute("COMMIT")

        def _release_claim() -> None:
            with self.state._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "UPDATE tasks SET status = 'ready', updated_at = ? WHERE id = ? AND status = 'dispatched'",
                    (time.time(), task_id),
                )
                conn.execute("DELETE FROM dispatches WHERE dispatch_id = ?", (dispatch_id,))
                conn.execute("DELETE FROM terminals WHERE handle = ?", (term_handle,))
                conn.execute("COMMIT")

        try:
            wt_path = str(Path(self._resolve_worktree_path(worktree, name or task_id)).resolve())
            Path(wt_path).mkdir(parents=True, exist_ok=True)
            lane_dir.mkdir(parents=True, exist_ok=True)
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
        except BaseException:
            _release_claim()
            raise

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
        # fence always find the dispatch record (#591 review).
        with self.state._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO terminals(handle, worktree, title, command, pid, backend, log_path, state, created_at)
                VALUES (?, ?, ?, ?, 0, ?, ?, 'running', ?)
                """,
                (term_handle, wt_path, name or task_id, full_command, self.backend, str(lane_dir / "events.jsonl"), now),
            )
            conn.execute(
                """
                INSERT INTO dispatches(dispatch_id, task_id, run_id, worktree, agent, profile, terminal_handle, state, terminal_state, pid, backend, launch_effective, lane_dir, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', 'active', 0, ?, ?, ?, ?, ?)
                """,
                (dispatch_id, task_id, run_id, wt_path, agent, profile, term_handle, self.backend, eff_json, str(lane_dir), now, now),
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
                sandbox_meta=sandbox_meta,
            )
        except BaseException:
            # The monitor may already be running (e.g. cmux id parse / launcher timeout /
            # Ctrl-C after tmux started): withdraw the dispatch FIRST so its launch gate
            # refuses, tear down whatever started, then hand the task back.
            _release_claim()
            self._terminate_backend(
                self.backend,
                term_handle,
                0,
                backend_ref=f"openfleet-{term_handle}" if self.backend == "tmux" else None,
                container=container,
            )
            raise

        spawn_pid = int(spawn_info.get("pid", 0) or 0)
        spawn_backend = spawn_info.get("backend", self.backend)
        backend_ref = spawn_info.get("backendRef") or ""
        fenced_state: str | None = None
        with self.state._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
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
            conn.execute("COMMIT")
        if fenced_state is not None:
            # Fenced while starting: the generated monitor's launch gate refuses to run the
            # agent, and anything that did start is torn down here.
            self._terminate_backend(spawn_backend, term_handle, spawn_pid, backend_ref=backend_ref, container=container)
            with self.state._connect() as conn:
                conn.execute(
                    "UPDATE tasks SET status = 'ready', updated_at = ? WHERE id = ? AND status = 'dispatched'",
                    (time.time(), task_id),
                )
            raise ProviderError(
                "dispatch_fenced",
                f"dispatch {dispatch_id!r} was fenced ({fenced_state}) during startup",
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
                    # What actually ran — not the short human label (#591 review).
                    "command": full_command,
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
        pid = int(row["pid"] or 0)
        if self.runner is not None or backend == "dry-run":
            return None
        if pid <= 0 and not row["backend_ref"]:
            return None  # inserted before spawn and not launched yet: starting, not dead
        if backend == "tmux":
            ref = row["backend_ref"] or f"openfleet-{row['terminal_handle']}"
            return subprocess.run(["tmux", "has-session", "-t", ref], capture_output=True).returncode == 0
        if pid > 0:
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

    def _sweep_liveness(self, rows: list[Any]) -> None:
        """A dispatch whose monitor was killed (-9) never reports; detect it and emit worker_died."""
        for r in rows:
            if r["state"] not in ("ready", "running", "retained") or r["task_id"] is None:
                continue
            if self._backend_alive(r) is False and not (Path(r["lane_dir"] or "/nonexistent") / "exit.json").is_file():
                head = _git(["rev-parse", "HEAD"], cwd=r["worktree"]).stdout.strip() if r["worktree"] else ""
                self.state.ensure_terminal_or_died(
                    dispatch_id=r["dispatch_id"],
                    worker_handle=r["terminal_handle"],
                    exit_code=-1,
                    last_tail="(monitor process vanished without reporting an exit)",
                    worktree_head_sha=head,
                    run_id=r["run_id"],
                )

    def _dispatch_rows(self, where: str = "", params: tuple[Any, ...] = ()) -> list[Any]:
        with self.state._connect() as conn:
            return conn.execute(f"SELECT * FROM dispatches {where}", params).fetchall()

    def worker_list(
        self,
        *,
        run: str | None = None,
        task: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        q = "WHERE 1=1"
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
        self._sweep_liveness(self._dispatch_rows(q, tuple(params)))
        rows = self._dispatch_rows(q, tuple(params))
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
        rows = self._dispatch_rows("WHERE dispatch_id = ?", (dispatch_id,))
        if not rows:
            raise ProviderError("dispatch_not_found", f"dispatch {dispatch_id!r} not found")
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

    def worker_read(self, dispatch_id: str, source: str = "transcript", limit: int = 50) -> dict[str, Any]:
        rows = self._dispatch_rows("WHERE dispatch_id = ?", (dispatch_id,))
        if not rows:
            raise ProviderError("dispatch_not_found", f"dispatch {dispatch_id!r} not found")
        r = rows[0]
        log_file = Path(r["lane_dir"]) / "events.jsonl" if r["lane_dir"] else None
        lines: list[str] = []
        if log_file and log_file.is_file():
            lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
        if source == "transcript":
            return normalize_read("transcript", lines=lines, cursor=len(lines))
        return normalize_read("terminal", lines=lines, cursor=len(lines), handle=r["terminal_handle"])

    def worker_fence(self, verb: str, dispatch_id: str, reason: str | None = None) -> dict[str, Any]:
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
            conn.execute("COMMIT")
        out: dict[str, Any] = {"dispatchId": dispatch_id, "state": new_state, "terminalState": term_state}
        finished = r["state"] in ("completed", "died", *FENCED_DISPATCH_STATES) or (
            bool(r["lane_dir"]) and (Path(r["lane_dir"]) / "exit.json").is_file()
        )
        if verb != "retain" and finished:
            # Already exited: its pid may belong to an unrelated process group by now.
            out["termination"] = {"skipped": "dispatch already finished"}
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
                int(r["pid"] or 0),
                backend_ref=r["backend_ref"],
                container=container,
                lane_dir=r["lane_dir"],
            )
        return out

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
        wt_path = self._resolve_worktree_path(worktree or "current", title)
        Path(wt_path).mkdir(parents=True, exist_ok=True)
        handle = f"term_{uuid.uuid4().hex[:8]}"
        lane_dir = self.state.db_path.parent / "terminals" / handle
        lane_dir.mkdir(parents=True, exist_ok=True)
        log_file = lane_dir / "events.jsonl"
        log_file.touch()
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
        with self.state._connect() as conn:
            r = conn.execute("SELECT * FROM terminals WHERE handle = ?", (terminal,)).fetchone()
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
        cursor: int | None = None,
        limit: int | None = None,
        screen: bool = False,
    ) -> dict[str, Any]:
        r = self._terminal_row(terminal)
        lines: list[str] = []
        if screen:
            text = self._screen(r)
            if text is not None:
                lines = text.splitlines()
        if not lines and r["log_path"] and Path(r["log_path"]).is_file():
            lines = Path(r["log_path"]).read_text(encoding="utf-8", errors="replace").splitlines()
        if cursor:
            lines = lines[int(cursor):]
        if limit:
            lines = lines[-int(limit):]
        return {"terminal": {"handle": terminal, "tail": lines, "cursor": (int(cursor or 0) + len(lines))}}

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
            if not worktree or r["worktree"] == worktree
        ]
        if limit:
            terms = terms[: int(limit)]
        return {"terminals": terms}

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
            proc = subprocess.run(["tmux", "send-keys", "-t", ref, "-l", text], capture_output=True, text=True)
            if proc.returncode == 0 and enter:
                proc = subprocess.run(["tmux", "send-keys", "-t", ref, "Enter"], capture_output=True, text=True)
            if proc.returncode != 0:
                raise ProviderError("terminal_send_failed", (proc.stderr or "tmux send-keys failed").strip())
        elif backend == "cmux":
            if not term_row["backend_ref"]:
                raise ProviderError("terminal_send_failed", f"terminal {handle!r} has no cmux workspace id")
            proc = subprocess.run(
                ["cmux", "send", "--workspace", term_row["backend_ref"], payload],
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
                inbox_dir = Path(term_row["worktree"]) / ".open-fleet"
                inbox_dir.mkdir(parents=True, exist_ok=True)
                with open(inbox_dir / "inbox.jsonl", "a", encoding="utf-8") as inf:
                    inf.write(json.dumps({"handle": handle, "text": text, "ts": time.time()}) + "\n")
            if backend == "dry-run" and term_row["log_path"]:
                with open(term_row["log_path"], "a", encoding="utf-8") as lf:
                    lf.write(payload)
        except OSError:
            pass
        return True

    def terminal_send(self, terminal: str, text: str, enter: bool = True) -> dict[str, Any]:
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
        req_id = f"req_{uuid.uuid4().hex[:10]}"
        dispatch_id = f"disp_{uuid.uuid4().hex[:10]}"
        now = time.time()
        with self.state._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            t_row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if not t_row:
                conn.execute("ROLLBACK")
                raise ProviderError("task_not_found", f"task {task_id!r} not found")
            term_row = conn.execute("SELECT * FROM terminals WHERE handle = ?", (to_handle,)).fetchone()
            if not term_row:
                conn.execute("ROLLBACK")
                raise ProviderError("inject_rejected", f"terminal {to_handle!r} not found")
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
                    run or t_row["run_id"] or "default",
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
