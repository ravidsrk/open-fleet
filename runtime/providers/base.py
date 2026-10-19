#!/usr/bin/env python3
"""base.py — Runtime Provider Interface (RPI) base contract and 9-harness launch table.

Defines the canonical `RuntimeProvider` interface, `ProviderError` exception, monotonic
privilege narrowing (`ro < rw < danger`), and the verified 9-harness launch table
(`claude`, `codex`, `opencode`, `omp`, `pi`, `jcode`, `goose`, `hermes`, `crush`) used by
`open-fleet` (and backward-compatible `orca-fleet` callers) across all 15 supported
orchestrator runtimes.
"""
from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Any

PROFILE_RANK = {"ro": 0, "rw": 1, "danger": 2}

SUPPORTED_PROVIDERS = (
    "orca",
    "posix",
    "overstory",
    "t3code",
    "ao",
    "superset",
    "gastown",
    "worktrunk",
    "jcode-swarm",
    "emdash",
    "vibe-kanban",
    "paperclip",
    "multiclaude",
    "openhands",
)

SUPPORTED_HARNESSES = (
    "claude",
    "codex",
    "opencode",
    "omp",
    "pi",
    "jcode",
    "goose",
    "hermes",
    "crush",
    "gemini",
    "cursor",
    "antigravity",
    "grok",
    "droid",
)


def env_get(primary: str, legacy: str, env: dict[str, str] | None = None, default: str = "") -> str:
    """Read `OPEN_FLEET_*` primary env var with fallback to legacy `ORCA_*`."""
    source = os.environ if env is None else env
    val = (source.get(primary) or "").strip()
    if val:
        return val
    return (source.get(legacy) or default).strip()


def check_monotonic_profile(parent_profile: str | None, requested_profile: str) -> str:
    """Enforce monotonic privilege narrowing (`ro < rw < danger`).

    A parent running under `ro` can never spawn a child with `rw` or `danger`.
    """
    if requested_profile not in PROFILE_RANK:
        raise ProviderError("invalid_profile", f"unknown profile {requested_profile!r} (want ro|rw|danger)")
    if not parent_profile:
        return requested_profile
    parent_clean = parent_profile.strip()
    if not parent_clean:
        return requested_profile
    if parent_clean not in PROFILE_RANK:
        raise ProviderError("invalid_profile", f"unknown parent profile {parent_clean!r} (want ro|rw|danger)")
    if PROFILE_RANK[requested_profile] > PROFILE_RANK[parent_clean]:
        raise ProviderError(
            "privilege_escalation",
            f"monotonic privilege violation: parent profile '{parent_clean}' cannot dispatch "
            f"higher-privilege child profile '{requested_profile}' (order: ro < rw < danger)",
        )
    return requested_profile


class ProviderError(Exception):
    """Structured error raised by a RuntimeProvider method."""

    def __init__(self, code: str, message: str = "", data: dict[str, Any] | None = None):
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        self.data = data or {}

    def to_envelope(self) -> dict[str, Any]:
        err: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data:
            err["data"] = self.data
        return {"ok": False, "error": err}


def build_harness_command(
    agent: str,
    profile: str,
    worktree: str,
    prompt: str | None = None,
    *,
    effort: str = "xhigh",
    deny_hook_path: str | None = None,
    bridge_dir: str | None = None,
    data_dir: str | None = None,
) -> dict[str, Any]:
    """Build the verified CLI command, argv, env, and profile_flag for any of the 9 CLI harnesses.

    Source-audited across all cloned harnesses to avoid silent permission bypasses:
      - `pi` has no `--cwd` flag and no built-in permission prompt (requires `cd` + `--exclude-tools` on `ro`).
      - `jcode --profile minimal` still includes `bash,write,edit,replace,apply_patch` (requires explicit `--disabled-tools`).
      - `crush run` calls `AutoApproveSession` unconditionally (requires `<data-dir>/crush.json` `disabled_tools` on `ro`).
      - `hermes` bundles read and write tools in `file` (requires `HERMES_WRITE_SAFE_ROOT=/dev/null` on `ro`).
      - `omp -p` with `--approval-mode always-ask` fails closed on any non-read tool in print mode.
    """
    if profile not in PROFILE_RANK:
        raise ProviderError("invalid_profile", f"unknown profile {profile!r}")
    wt = os.path.abspath(worktree) if worktree and not worktree.startswith(("new-", "current", "active")) else (worktree or ".")
    root_dir = Path(__file__).resolve().parent.parent
    hook_path = deny_hook_path or str(root_dir / "scripts" / "deny-hook.sh")
    bridges = Path(bridge_dir) if bridge_dir else (Path(__file__).resolve().parent / "bridges")
    omp_bridge = str(bridges / "omp_pi_deny_bridge.ts")
    prompt_str = prompt or ""

    env: dict[str, str] = {
        "OPEN_FLEET_UNIT_WORKTREE": wt,
        "ORCA_UNIT_WORKTREE": wt,
        "OPEN_FLEET_SANDBOX_PROFILE": profile,
        "ORCA_SANDBOX_PROFILE": profile,
    }

    if agent == "claude":
        if profile == "ro":
            flag = "--permission-mode plan"
            argv = ["claude", "-p", "--permission-mode", "plan",
                    "--disallowedTools", "Edit,Write,MultiEdit,NotebookEdit",
                    "--output-format", "stream-json", "--verbose"]
            if prompt_str:
                argv.append(prompt_str)
            cmd = "claude --permission-mode plan"
        else:
            flag = "--dangerously-skip-permissions"
            argv = ["claude", "-p", "--dangerously-skip-permissions",
                    "--output-format", "stream-json", "--verbose"]
            if prompt_str:
                argv.append(prompt_str)
            cmd = "claude --dangerously-skip-permissions"
        return {"agent": agent, "profile": profile, "argv": argv, "command": cmd, "env": env, "profile_flag": flag}

    if agent == "codex":
        cx_eff = f'model_reasoning_effort="{effort}"'
        if profile == "ro":
            flag = "--sandbox read-only"
            argv = ["codex", "exec", "--json", "-C", wt, "--sandbox", "read-only",
                    "-c", 'approval_policy="never"', "-c", cx_eff,
                    "--dangerously-bypass-hook-trust"]
            if prompt_str:
                argv.append(prompt_str)
            cmd = f"codex --sandbox read-only -c {cx_eff}"
        else:
            flag = "--dangerously-bypass-approvals-and-sandbox"
            argv = ["codex", "exec", "--json", "-C", wt,
                    "--dangerously-bypass-approvals-and-sandbox", "-c", cx_eff,
                    "--dangerously-bypass-hook-trust"]
            if prompt_str:
                argv.append(prompt_str)
            cmd = f"codex --dangerously-bypass-approvals-and-sandbox -c {cx_eff}"
        return {"agent": agent, "profile": profile, "argv": argv, "command": cmd, "env": env, "profile_flag": flag}

    if agent == "opencode":
        if profile == "ro":
            cfg = json.dumps({"permission": {"*": "allow", "edit": "deny", "bash": "deny", "external_directory": "deny"}})
            env["OPENCODE_CONFIG_CONTENT"] = cfg
            flag = "edit:deny,bash:deny"
            argv = ["opencode", "run", "--standalone", "--format", "json", "--dir", wt]
            if prompt_str:
                argv.append(prompt_str)
            cmd = f"OPENCODE_CONFIG_CONTENT={shlex.quote(cfg)} opencode run --standalone --format json --dir {shlex.quote(wt)}"
        else:
            cfg = json.dumps({"permission": {"*": "allow", "external_directory": "deny"}})
            env["OPENCODE_CONFIG_CONTENT"] = cfg
            flag = "--auto --standalone"
            argv = ["opencode", "run", "--auto", "--standalone", "--format", "json", "--dir", wt]
            if prompt_str:
                argv.append(prompt_str)
            cmd = f"OPENCODE_CONFIG_CONTENT={shlex.quote(cfg)} opencode run --auto --standalone --format json --dir {shlex.quote(wt)}"
        return {"agent": agent, "profile": profile, "argv": argv, "command": cmd, "env": env, "profile_flag": flag}

    if agent == "omp":
        env["PI_NO_TITLE"] = "1"
        if profile == "ro":
            flag = "--approval-mode always-ask"
            argv = ["omp", "-p", "--mode", "json", "--cwd", wt, "--no-session", "--no-lsp",
                    "--tools", "read,grep,glob,find,ast_grep", "--approval-mode", "always-ask"]
            if prompt_str:
                argv.append(prompt_str)
            cmd = f"PI_NO_TITLE=1 omp -p --mode json --cwd {shlex.quote(wt)} --no-session --no-lsp --tools read,grep,glob,find,ast_grep --approval-mode always-ask"
        else:
            flag = "--yolo"
            argv = ["omp", "-p", "--mode", "json", "--cwd", wt, "--yolo",
                    "--trusted-extension", omp_bridge]
            if prompt_str:
                argv.append(prompt_str)
            cmd = f"PI_NO_TITLE=1 omp -p --mode json --cwd {shlex.quote(wt)} --yolo --trusted-extension {shlex.quote(omp_bridge)}"
        return {"agent": agent, "profile": profile, "argv": argv, "command": cmd, "env": env, "profile_flag": flag}

    if agent == "pi":
        if profile == "ro":
            flag = "--exclude-tools bash,powershell,write,edit,codemode,mcp__*"
            argv = ["pi", "-p", "--mode", "json", "--no-session", "--no-mcp", "-ne", "-na",
                    "--tools", "read,grep,find,ls",
                    "--exclude-tools", "bash,powershell,write,edit,codemode,mcp__*"]
            if prompt_str:
                argv.append(prompt_str)
            cmd = f"cd {shlex.quote(wt)} && pi -p --mode json --no-session --no-mcp -ne -na --tools read,grep,find,ls --exclude-tools 'bash,powershell,write,edit,codemode,mcp__*'"
        else:
            flag = "--tools read,bash,edit,write,grep,find,ls"
            argv = ["pi", "-p", "--mode", "json", "-e", omp_bridge,
                    "--tools", "read,bash,edit,write,grep,find,ls"]
            if prompt_str:
                argv.append(prompt_str)
            cmd = f"cd {shlex.quote(wt)} && pi -p --mode json -e {shlex.quote(omp_bridge)} --tools read,bash,edit,write,grep,find,ls"
        return {"agent": agent, "profile": profile, "argv": argv, "command": cmd, "env": env, "profile_flag": flag}

    if agent == "jcode":
        env["JCODE_HOOK_PRE_TOOL"] = hook_path
        if profile == "ro":
            flag = "--disabled-tools bash,write,edit,replace,apply_patch,swarm,selfdev,desktop_selfdev,bg,codemode,mcp"
            argv = ["jcode", "-C", wt, "--no-update", "-q",
                    "--tools", "read,agentgrep,ls,session_search,conversation_search,memory,web_search",
                    "--disabled-tools", "bash,write,edit,replace,apply_patch,swarm,selfdev,desktop_selfdev,bg,codemode,mcp",
                    "run", prompt_str or "inspect", "--ndjson"]
            cmd = (f"JCODE_HOOK_PRE_TOOL={shlex.quote(hook_path)} jcode -C {shlex.quote(wt)} --no-update -q "
                   f"--tools read,agentgrep,ls,session_search,conversation_search,memory,web_search "
                   f"{flag} run")
        else:
            flag = "--disabled-tools selfdev,desktop_selfdev"
            argv = ["jcode", "-C", wt, "--no-update", "-q",
                    "--disabled-tools", "selfdev,desktop_selfdev",
                    "run", prompt_str or "execute", "--ndjson"]
            cmd = f"JCODE_HOOK_PRE_TOOL={shlex.quote(hook_path)} jcode -C {shlex.quote(wt)} --no-update -q {flag} run"
        return {"agent": agent, "profile": profile, "argv": argv, "command": cmd, "env": env, "profile_flag": flag}

    if agent == "goose":
        env["GOOSE_MODE"] = "auto"
        if profile == "ro":
            flag = "--with-builtin analyze"
            argv = ["goose", "run", "--output-format", "stream-json", "--no-profile", "--with-builtin", "analyze"]
            if prompt_str:
                argv += ["-t", prompt_str]
            cmd = "GOOSE_MODE=auto goose run --output-format stream-json --no-profile --with-builtin analyze"
        else:
            flag = "--with-builtin developer"
            argv = ["goose", "run", "--output-format", "stream-json", "--no-profile", "--with-builtin", "developer"]
            if prompt_str:
                argv += ["-t", prompt_str]
            cmd = "GOOSE_MODE=auto goose run --output-format stream-json --no-profile --with-builtin developer"
        return {"agent": agent, "profile": profile, "argv": argv, "command": cmd, "env": env, "profile_flag": flag}

    if agent == "hermes":
        if profile == "ro":
            env["HERMES_WRITE_SAFE_ROOT"] = "/dev/null"
            flag = "--toolsets file,web,session_search"
            argv = ["hermes", "--in", wt, "--accept-hooks", "chat", "--oneshot", "-Q",
                    "--toolsets", "file,web,session_search", "-q", prompt_str or "inspect"]
            cmd = f"HERMES_WRITE_SAFE_ROOT=/dev/null hermes --in {shlex.quote(wt)} --accept-hooks chat --oneshot -Q --toolsets file,web,session_search"
        else:
            env["HERMES_WRITE_SAFE_ROOT"] = wt
            flag = "--yolo --toolsets coding"
            argv = ["hermes", "--in", wt, "--yolo", "--accept-hooks", "chat", "--oneshot", "-Q",
                    "--toolsets", "coding", "-q", prompt_str or "execute"]
            cmd = f"HERMES_WRITE_SAFE_ROOT={shlex.quote(wt)} hermes --in {shlex.quote(wt)} --yolo --accept-hooks chat --oneshot -Q --toolsets coding"
        return {"agent": agent, "profile": profile, "argv": argv, "command": cmd, "env": env, "profile_flag": flag}

    if agent == "crush":
        c_data = data_dir or os.path.join(wt, ".crush-orca-ro" if profile == "ro" else ".crush")
        if profile == "ro":
            flag = "disabled_tools:bash,write,edit,multiedit"
            argv = ["crush", "--cwd", wt, "--data-dir", c_data, "run", "-q", prompt_str or "inspect"]
            cmd = f"crush --cwd {shlex.quote(wt)} --data-dir {shlex.quote(c_data)} run -q"
        else:
            flag = "--yolo"
            argv = ["crush", "--cwd", wt, "--data-dir", c_data, "--yolo", "run", "-q", prompt_str or "execute"]
            cmd = f"crush --cwd {shlex.quote(wt)} --data-dir {shlex.quote(c_data)} --yolo run -q"
        return {"agent": agent, "profile": profile, "argv": argv, "command": cmd, "env": env, "profile_flag": flag}

    if agent == "gemini":
        flag = "--approval-mode plan" if profile == "ro" else "--yolo"
        cmd = f"gemini {flag}"
        return {"agent": agent, "profile": profile, "argv": cmd.split(), "command": cmd, "env": env, "profile_flag": flag}

    if agent in ("cursor", "antigravity", "grok", "droid"):
        if profile == "ro":
            raise ProviderError("unsupported_profile", f"agent {agent!r} has no verified PROFILE=ro launch flag")
        flag_map = {
            "cursor": ("cursor --yolo", "--yolo"),
            "antigravity": ("agy --dangerously-skip-permissions", "--dangerously-skip-permissions"),
            "grok": ("grok --permission-mode bypassPermissions", "--permission-mode bypassPermissions"),
            "droid": ("droid --auto high", "--auto high"),
        }
        cmd, flag = flag_map[agent]
        return {"agent": agent, "profile": profile, "argv": cmd.split(), "command": cmd, "env": env, "profile_flag": flag}

    raise ProviderError("unknown_agent", f"unknown agent {agent!r}")


def _parse_flag_map(tokens: list[str]) -> tuple[list[str], dict[str, Any]]:
    """Parse CLI flag tokens (`--key val` or boolean `--flag`) into `(positionals, flags)`."""
    pos: list[str] = []
    flags: dict[str, Any] = {}
    BOOL_FLAGS = {
        "--brief", "--wait", "--format", "--unread", "--peek", "--all",
        "--screen", "--focus", "--include-visual-layouts", "--fresh",
        "--debug", "--inject", "--json", "--force",
    }
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--json":
            i += 1
            continue
        if tok in BOOL_FLAGS:
            flags[tok.lstrip("-")] = True
            i += 1
            continue
        if tok.startswith("--"):
            key = tok.lstrip("-")
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("--"):
                val = tokens[i + 1]
                if key in flags:
                    if isinstance(flags[key], list):
                        flags[key].append(val)
                    else:
                        flags[key] = [flags[key], val]
                else:
                    flags[key] = val
                i += 2
            else:
                flags[key] = True
                i += 1
        else:
            pos.append(tok)
            i += 1
    return pos, flags


class RuntimeProvider:
    """Base class for all `open-fleet` Runtime Provider Interface (RPI) adapters."""

    name: str = "base"

    def capabilities(self) -> set[str]:
        return {"cap:core-orchestration"}

    def dispatch(self, argv: list[str], *, timeout: int = 120, env: dict[str, str] | None = None) -> dict[str, Any]:
        """Route a canonical CLI `argv` list to the corresponding typed provider method."""
        clean = [a for a in argv if a != "--json"]
        if not clean:
            return self.status()
        head = clean[0]
        if head in ("--version", "version"):
            return {"version": self.version()}
        if head == "status":
            return self.status()
        if head == "search":
            pos, flags = _parse_flag_map(clean[1:])
            query = flags.get("query") or (pos[0] if pos else "")
            return self.search(
                query=str(query),
                scope=flags.get("scope"),
                limit=int(flags["limit"]) if "limit" in flags else 20,
                cursor=flags.get("cursor"),
                agent=flags.get("agent"),
                path=flags.get("path"),
                since=flags.get("since"),
                sort=flags.get("sort"),
            )
        if head == "vm" and len(clean) >= 3 and clean[1] == "recipe" and clean[2] == "doctor":
            pos, flags = _parse_flag_map(clean[3:])
            recipe_id = pos[0] if pos else ""
            return self.vm_recipe_doctor(recipe_id)
        if head == "worktree" and len(clean) >= 2:
            sub = clean[1]
            pos, flags = _parse_flag_map(clean[2:])
            if sub == "list":
                return self.worktree_list(
                    repo=flags.get("repo"),
                    limit=int(flags["limit"]) if "limit" in flags else None,
                )
            if sub == "show":
                return self.worktree_show(selector=flags.get("worktree") or (pos[0] if pos else "current"))
            if sub == "create":
                return self.worktree_create(
                    name=flags.get("name") or (pos[0] if pos else "worker"),
                    base=flags.get("base"),
                    repo=flags.get("repo"),
                )
            if sub in ("rm", "remove", "delete"):
                return self.worktree_rm(
                    selector=flags.get("worktree") or (pos[0] if pos else ""),
                    force=bool(flags.get("force")),
                )
        if head == "terminal" and len(clean) >= 2:
            sub = clean[1]
            pos, flags = _parse_flag_map(clean[2:])
            if sub == "create":
                return self.terminal_create(
                    worktree=flags.get("worktree"),
                    title=flags.get("title"),
                    command=flags.get("command"),
                    shell=flags.get("shell"),
                    focus=bool(flags.get("focus")),
                )
            if sub == "read":
                return self.terminal_read(
                    terminal=flags.get("terminal") or (pos[0] if pos else ""),
                    cursor=int(flags["cursor"]) if "cursor" in flags else None,
                    limit=int(flags["limit"]) if "limit" in flags else None,
                    screen=bool(flags.get("screen")),
                )
            if sub == "list":
                return self.terminal_list(
                    worktree=flags.get("worktree"),
                    limit=int(flags["limit"]) if "limit" in flags else None,
                    include_visual_layouts=bool(flags.get("include-visual-layouts")),
                )
            if sub == "show":
                return self.terminal_show(terminal=flags.get("terminal") or (pos[0] if pos else ""))
            if sub == "wait":
                return self.terminal_wait(
                    terminal=flags.get("terminal") or (pos[0] if pos else ""),
                    condition=flags.get("for", "tui-idle"),
                    timeout_ms=int(flags.get("timeout-ms", 90000)),
                )
            if sub == "send":
                return self.terminal_send(
                    terminal=flags.get("terminal") or (pos[0] if pos else ""),
                    text=flags.get("text", ""),
                    enter=not bool(flags.get("no-enter")),
                )
        if head == "orchestration" and len(clean) >= 2:
            sub = clean[1]
            pos, flags = _parse_flag_map(clean[2:])
            if sub == "task-create":
                deps_raw = flags.get("deps")
                deps = json.loads(deps_raw) if isinstance(deps_raw, str) else (deps_raw or [])
                return self.task_create(
                    spec=flags.get("spec", ""),
                    title=flags.get("task-title"),
                    display_name=flags.get("display-name"),
                    deps=deps,
                    parent=flags.get("parent"),
                    run=flags.get("run"),
                    sender=flags.get("from"),
                    retry_request=flags.get("retry-request"),
                )
            if sub == "task-update":
                return self.task_update(
                    task_id=flags.get("id", ""),
                    status=flags.get("status", ""),
                    result=flags.get("result"),
                    run=flags.get("run"),
                    sender=flags.get("from"),
                    retry_request=flags.get("retry-request"),
                )
            if sub == "task-list":
                return self.task_list(
                    run=flags.get("run"),
                    sender=flags.get("from"),
                    brief=bool(flags.get("brief")),
                )
            if sub == "worker-start":
                raw_prof = flags.get("profile") or env_get(
                    "OPEN_FLEET_SANDBOX_PROFILE",
                    "ORCA_SANDBOX_PROFILE",
                    env,
                    os.environ.get("PROFILE", "rw"),
                )
                raw_parent = flags.get("parent-profile") or env_get(
                    "OPEN_FLEET_PARENT_PROFILE",
                    "ORCA_PARENT_PROFILE",
                    env,
                    "",
                )
                kw: dict[str, Any] = {
                    "task_id": flags.get("task", ""),
                    "worktree": flags.get("worktree", "new-child"),
                    "agent": flags.get("agent", "claude"),
                    "name": flags.get("name"),
                    "run": flags.get("run"),
                    "sender": flags.get("from"),
                    "timeout_ms": int(flags["timeout-ms"]) if "timeout-ms" in flags else None,
                    "on_env": flags.get("on"),
                    "retry_of": flags.get("retry-of"),
                    "retry_request": flags.get("retry-request"),
                    "profile": str(raw_prof),
                    "parent_profile": str(raw_parent),
                }
                if "prompt" in flags:
                    kw["prompt"] = str(flags["prompt"])
                return self.worker_start(**kw)
            if sub == "worker-list":
                return self.worker_list(
                    run=flags.get("run"),
                    task=flags.get("task"),
                    limit=int(flags["limit"]) if "limit" in flags else None,
                    cursor=flags.get("cursor"),
                )
            if sub == "worker-show":
                return self.worker_show(dispatch_id=flags.get("dispatch", ""))
            if sub == "worker-read":
                return self.worker_read(
                    dispatch_id=flags.get("dispatch", ""),
                    source="transcript" if flags.get("transcript") else ("terminal" if flags.get("terminal") else flags.get("source", "transcript")),
                    limit=int(flags.get("limit", 50)),
                )
            if sub in ("worker-stop", "worker-abandon", "worker-release", "worker-retain"):
                verb = sub.split("-", 1)[1]
                fence_kw: dict[str, Any] = {
                    "verb": verb,
                    "dispatch_id": flags.get("dispatch", ""),
                    "reason": flags.get("reason"),
                }
                if "verified" in flags:
                    fence_kw["verified"] = flags["verified"] is True or str(flags["verified"]).lower() in ("1", "true", "yes")
                return self.worker_fence(**fence_kw)
            if sub == "dispatch":
                return self.dispatch_inject(
                    task_id=flags.get("task", ""),
                    to_handle=flags.get("to", ""),
                    run=flags.get("run"),
                    sender=flags.get("from"),
                )
            if sub == "request-show":
                return self.request_show(request_id=flags.get("request", ""))
            if sub == "send":
                reserved = {"subject", "type", "to", "outcome", "from", "payload", "run", "environment", "pairing-code"}
                attrs = {k: v for k, v in flags.items() if k not in reserved}
                return self.send_message(
                    subject=flags.get("subject", ""),
                    msg_type=flags.get("type", "info"),
                    to=flags.get("to"),
                    outcome=flags.get("outcome"),
                    sender=flags.get("from"),
                    payload=flags.get("payload"),
                    run=flags.get("run"),
                    attrs=attrs,
                )
            if sub == "check":
                mode = "all" if flags.get("all") else ("peek" if flags.get("peek") else "unread")
                return self.check_messages(
                    terminal=flags.get("terminal"),
                    run=flags.get("run"),
                    ack=flags.get("ack"),
                    mode=mode,
                    types=flags.get("types"),
                    fmt=bool(flags.get("format")),
                    wait=bool(flags.get("wait")),
                    timeout_ms=int(flags["timeout-ms"]) if "timeout-ms" in flags else None,
                    retry_request=flags.get("retry-request"),
                )
            if sub == "reply":
                return self.reply_message(
                    msg_id=flags.get("id", ""),
                    body=flags.get("body", ""),
                    run=flags.get("run"),
                    sender=flags.get("from"),
                    retry_request=flags.get("retry-request"),
                )
            if sub == "ask":
                return self.ask_human(
                    question=flags.get("question"),
                    resume=flags.get("resume"),
                    to=flags.get("to"),
                    run=flags.get("run"),
                    options=flags.get("options"),
                    timeout_ms=int(flags["timeout-ms"]) if "timeout-ms" in flags else None,
                    sender=flags.get("from"),
                    retry_request=flags.get("retry-request"),
                )
        raise ProviderError("unsupported_command", f"provider '{self.name}' does not support argv: {clean!r}")

    def version(self) -> str:
        pins = Path(__file__).resolve().parent.parent / "pins.json"
        try:
            return json.loads(pins.read_text(encoding="utf-8"))["orca"]["version"]
        except Exception:
            return "v1.4.229"

    def status(self) -> dict[str, Any]:
        return {"ready": True, "provider": self.name, "version": self.version()}

    def _unsupported(self, method: str, kwargs: dict[str, Any]) -> dict[str, Any]:
        raise ProviderError(
            "unsupported_operation",
            f"provider '{self.name}' does not support '{method}' (args={sorted(kwargs.keys())})",
        )

    def task_create(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("task_create", kwargs)

    def task_update(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("task_update", kwargs)

    def task_list(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("task_list", kwargs)

    def worker_start(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("worker_start", kwargs)

    def worker_list(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("worker_list", kwargs)

    def worker_show(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("worker_show", kwargs)

    def worker_read(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("worker_read", kwargs)

    def worker_fence(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("worker_fence", kwargs)

    def dispatch_inject(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("dispatch_inject", kwargs)

    def request_show(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("request_show", kwargs)

    def send_message(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("send_message", kwargs)

    def check_messages(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("check_messages", kwargs)

    def reply_message(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("reply_message", kwargs)

    def ask_human(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("ask_human", kwargs)

    def worktree_list(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("worktree_list", kwargs)

    def worktree_show(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("worktree_show", kwargs)

    def worktree_create(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("worktree_create", kwargs)

    def worktree_rm(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("worktree_rm", kwargs)

    def terminal_create(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("terminal_create", kwargs)

    def terminal_read(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("terminal_read", kwargs)

    def terminal_list(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("terminal_list", kwargs)

    def terminal_show(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("terminal_show", kwargs)

    def terminal_wait(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("terminal_wait", kwargs)

    def terminal_send(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("terminal_send", kwargs)

    def search(self, **kwargs: Any) -> dict[str, Any]:
        return self._unsupported("search", kwargs)

    def vm_recipe_doctor(self, recipe_id: str) -> dict[str, Any]:
        return {
            "recipeId": recipe_id,
            "ok": True,
            "summary": {"failures": 0, "warnings": 0},
            "checks": [{"id": "sandbox-ready", "status": "pass"}],
        }
