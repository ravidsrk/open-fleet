"""Zero-friction doctor diagnostics, host setup, atomic JSON hook merging, and MCP config generation."""

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from open_fleet import catalog_version, find_catalog_root
from open_fleet.catalog import load_pins, load_quarantine

HOST_PROFILES: dict[str, dict[str, Any]] = {
    "claude": {
        "label": "Claude Code",
        "skills_rel": ".claude/skills",
        "settings_rel": ".claude/settings.json",
        "mcp_rel": ".claude.json",
        "supports_hooks": True,
        "invocation": "/review-it or natural language",
    },
    "codex": {
        "label": "OpenAI Codex CLI",
        "skills_rel": ".codex/skills",
        "settings_rel": None,
        "mcp_rel": ".codex/config.toml",
        "supports_hooks": False,
        "invocation": "$review-it or natural language",
    },
    "gemini": {
        "label": "Gemini CLI",
        "skills_rel": ".gemini/skills",
        "settings_rel": ".gemini/settings.json",
        "mcp_rel": ".gemini/settings.json",
        "supports_hooks": False,
        "invocation": "natural language (avoid /plan; invoke map-it by name)",
    },
    "opencode": {
        "label": "OpenCode",
        "skills_rel": ".config/opencode/skills",
        "settings_rel": None,
        "mcp_rel": ".config/opencode/opencode.json",
        "supports_hooks": False,
        "invocation": "/review-it or natural language",
    },
    "antigravity": {
        "label": "Antigravity (agy)",
        "skills_rel": ".gemini/antigravity-cli/skills",
        "settings_rel": None,
        "mcp_rel": ".gemini/antigravity-cli/mcp_config.json",
        "supports_hooks": False,
        "invocation": "/review-it or natural language",
    },
    "cursor": {
        "label": "Cursor",
        "skills_rel": ".cursor/skills",
        "settings_rel": None,
        "mcp_rel": ".cursor/mcp.json",
        "supports_hooks": False,
        "invocation": "MCP tools + skills",
    },
}

DETECTED_HARNESS_BINS: tuple[tuple[str, str], ...] = (
    ("claude", "claude"),
    ("codex", "codex"),
    ("gemini", "gemini"),
    ("opencode", "opencode"),
    ("omp", "omp"),
    ("pi", "pi"),
    ("jcode", "jcode"),
    ("goose", "goose"),
    ("hermes", "hermes"),
    ("crush", "crush"),
    ("cursor", "cursor"),
    ("antigravity", "agy"),
    ("grok", "grok"),
    ("droid", "droid"),
)


def _which(binary: str, path_env: str | None) -> str | None:
    return shutil.which(binary, path=path_env)


def _orca_binary_name(system: str | None = None, env: dict[str, str] | None = None) -> str:
    src = os.environ if env is None else env
    explicit = (src.get("ORCA_CLI_COMMAND") or "").strip()
    if explicit:
        return explicit
    plat = (system or platform.system()).lower()
    if plat == "linux":
        return "orca-ide"
    return "orca"


def _resolve_runtime(requested: str | None, env: dict[str, str] | None = None) -> dict[str, Any]:
    src = os.environ if env is None else env
    path_env = src.get("PATH")
    raw = (requested or src.get("OPEN_FLEET_RUNTIME") or src.get("ORCA_FLEET_RUNTIME") or "").strip().lower()
    orca_bin = _orca_binary_name(env=src)
    orca_found = _which(orca_bin, path_env)
    if not raw:
        recommended = "orca" if orca_found else "posix"
        return {
            "configured": "(unset -> legacy default: orca)",
            "effective_legacy": "orca",
            "effective_auto": recommended,
            "orca_binary": orca_bin,
            "orca_found": orca_found,
            "recommend_export": None if orca_found else "export OPEN_FLEET_RUNTIME=auto",
        }
    if raw == "auto":
        effective = "orca" if orca_found else "posix"
        return {
            "configured": "auto",
            "effective_legacy": effective,
            "effective_auto": effective,
            "orca_binary": orca_bin,
            "orca_found": orca_found,
            "recommend_export": None,
        }
    return {
        "configured": raw,
        "effective_legacy": raw,
        "effective_auto": raw,
        "orca_binary": orca_bin,
        "orca_found": orca_found,
        "recommend_export": None,
    }


def _check_claude_hooks(settings_path: Path, root: Path) -> dict[str, Any]:
    gate_path = str((root / "runtime" / "scripts" / "verify-gate.sh").resolve())
    if not settings_path.is_file():
        return {"exists": False, "wired": False, "stop_wired": False, "task_wired": False, "plugin_enabled": False}
    try:
        data = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"exists": True, "wired": False, "stop_wired": False, "task_wired": False, "plugin_enabled": False, "error": "invalid JSON"}
    hooks = data.get("hooks") if isinstance(data, dict) else {}
    stop_wired = False
    task_wired = False
    if isinstance(hooks, dict):
        for event_name, target_flag in (("Stop", "stop"), ("TaskCompleted", "task")):
            entries = hooks.get(event_name)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                inner = entry.get("hooks") if isinstance(entry, dict) else None
                if not isinstance(inner, list):
                    continue
                for hook in inner:
                    cmd = str(hook.get("command") or "") if isinstance(hook, dict) else ""
                    if "verify-gate.sh" in cmd:
                        if target_flag == "stop":
                            stop_wired = True
                        else:
                            task_wired = True
    enabled_plugins = data.get("enabledPlugins") if isinstance(data, dict) else {}
    plugin_enabled = bool(isinstance(enabled_plugins, dict) and enabled_plugins.get("open-fleet@open-fleet"))
    return {
        "exists": True,
        "path": str(settings_path),
        "gate_path": gate_path,
        "wired": stop_wired and task_wired,
        "stop_wired": stop_wired,
        "task_wired": task_wired,
        "plugin_enabled": plugin_enabled,
    }


def _check_symlinks(skills_dir: Path, root: Path) -> dict[str, Any]:
    expected = sorted(
        d.name
        for d in (root / "skills").iterdir()
        if d.is_dir() and not d.name.startswith((".", "_")) and (d / "SKILL.md").is_file()
    )
    linked: list[str] = []
    other_clone: list[str] = []
    real_dirs: list[str] = []
    missing: list[str] = []
    for name in expected:
        dst = skills_dir / name
        if dst.is_symlink():
            if dst.resolve() == (root / "skills" / name).resolve():
                linked.append(name)
            else:
                other_clone.append(name)
        elif dst.exists():
            real_dirs.append(name)
        else:
            missing.append(name)
    return {
        "skills_dir": str(skills_dir),
        "total": len(expected),
        "linked": len(linked),
        "other_clone": other_clone,
        "real_dirs": real_dirs,
        "missing_count": len(missing),
        "complete": len(linked) == len(expected) and len(expected) > 0,
    }


def doctor(
    root: Path | None = None,
    *,
    runtime: str | None = None,
    home: Path | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run an actionable diagnostic of environment, runtimes, harnesses, hooks, pins, and next steps."""
    base = (root or find_catalog_root()).resolve()
    src = os.environ if env is None else env
    path_env = src.get("PATH")
    home_dir = (home or Path(src.get("HOME") or Path.home())).expanduser().resolve()

    checks: list[dict[str, Any]] = []
    next_actions: list[str] = []

    py_ok = sys.version_info >= (3, 11)
    checks.append({
        "id": "python",
        "status": "ok" if py_ok else "fail",
        "detail": f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} (requires >=3.11, stdlib only)",
    })

    git_bin = _which("git", path_env)
    shallow = False
    if git_bin:
        try:
            proc = subprocess.run(
                [git_bin, "-C", str(base), "rev-parse", "--is-shallow-repository"],
                capture_output=True,
                text=True,
                timeout=10,
                env={**src, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
            )
            shallow = proc.returncode == 0 and proc.stdout.strip() == "true"
        except (OSError, subprocess.SubprocessError):
            shallow = False
    checks.append({
        "id": "git",
        "status": "fail" if not git_bin else ("warn" if shallow else "ok"),
        "detail": "git missing from PATH" if not git_bin else ("shallow clone (run `git fetch --unshallow`)" if shallow else f"{git_bin} (full history)"),
    })
    if shallow:
        next_actions.append(f"git -C {base} fetch --unshallow")

    rt = _resolve_runtime(runtime, src)
    rt_status = "ok" if rt["effective_auto"] == "posix" or rt["orca_found"] else "warn"
    if rt["configured"].startswith("(unset") and not rt["orca_found"]:
        rt_status = "warn"
        next_actions.append("export OPEN_FLEET_RUNTIME=auto   # uses Orca when installed, standalone posix otherwise")
    checks.append({
        "id": "runtime",
        "status": rt_status,
        "detail": f"configured={rt['configured']} · auto_effective={rt['effective_auto']} · orca={'found' if rt['orca_found'] else 'not installed'}",
    })

    gate_script = base / "runtime" / "scripts" / "verify-gate.sh"
    gate_exec = gate_script.is_file() and os.access(gate_script, os.X_OK)
    checks.append({
        "id": "verify-gate-script",
        "status": "ok" if gate_exec else "fail",
        "detail": f"{gate_script} ({'executable' if gate_exec else 'missing execute bit'})",
    })

    quarantine = load_quarantine(base)
    q_count = len(quarantine.get("quarantined") or [])
    checks.append({
        "id": "quarantine",
        "status": "fail" if not quarantine["valid"] else ("warn" if q_count else "ok"),
        "detail": quarantine["error"] if not quarantine["valid"] else f"{q_count} quarantined component(s)",
    })

    harnesses = []
    for name, binary in DETECTED_HARNESS_BINS:
        found = _which(binary, path_env)
        harnesses.append({"name": name, "binary": binary, "installed": bool(found), "path": found or ""})
    installed_harnesses = [h["name"] for h in harnesses if h["installed"]]
    checks.append({
        "id": "harnesses",
        "status": "ok" if installed_harnesses else "warn",
        "detail": f"detected: {', '.join(installed_harnesses)}" if installed_harnesses else "no coding-agent CLI found on PATH (inert first-run & verifier still work)",
    })

    extras = {tool: bool(_which(tool, path_env)) for tool in ("gh", "tmux", "docker", "ruff", "uv")}
    checks.append({
        "id": "tooling",
        "status": "ok" if extras["gh"] else "warn",
        "detail": " · ".join(f"{k}={'yes' if v else 'no'}" for k, v in extras.items()),
    })

    claude_skills = _check_symlinks(home_dir / ".claude" / "skills", base)
    claude_hooks = _check_claude_hooks(home_dir / ".claude" / "settings.json", base)
    stacked = claude_skills["linked"] > 0 and claude_hooks["plugin_enabled"]
    if stacked:
        checks.append({
            "id": "claude-install",
            "status": "fail",
            "detail": "STACKED INSTALL: both symlinked ~/.claude/skills and open-fleet@open-fleet plugin are active (causes duplicate skills & double hook runs)",
        })
        next_actions.append("open-fleet setup --host claude --uninstall   # remove stacked symlinks & manual hook block")
    elif claude_skills["complete"] and claude_hooks["wired"]:
        checks.append({"id": "claude-install", "status": "ok", "detail": f"symlink install complete ({claude_skills['linked']} missions) + completion gate wired"})
    elif claude_hooks["plugin_enabled"]:
        checks.append({"id": "claude-install", "status": "ok", "detail": "Claude Code plugin enabled (hooks wired via plugin)"})
    elif claude_skills["linked"] > 0 and not claude_hooks["wired"]:
        checks.append({"id": "claude-install", "status": "warn", "detail": f"{claude_skills['linked']}/{claude_skills['total']} skills linked, completion gate NOT wired in ~/.claude/settings.json"})
        next_actions.append("open-fleet setup --host claude --wire-hooks --wire-mcp")
    else:
        checks.append({"id": "claude-install", "status": "info", "detail": "not yet installed into ~/.claude/skills (run `open-fleet setup --host claude --wire-hooks --wire-mcp`)"})
        next_actions.append("open-fleet setup --host claude --wire-hooks --wire-mcp")

    overall = "fail" if any(c["status"] == "fail" for c in checks) else ("warn" if any(c["status"] == "warn" for c in checks) else "ok")
    return {
        "version": catalog_version(base),
        "root": str(base),
        "platform": f"{platform.system()} {platform.machine()}",
        "overall": overall,
        "runtime": rt,
        "checks": checks,
        "harnesses": harnesses,
        "tooling": extras,
        "claude": {"skills": claude_skills, "hooks": claude_hooks, "stacked": stacked},
        "pins": load_pins(base),
        "next_actions": next_actions,
    }


def build_mcp_config(
    host: str,
    root: Path | None = None,
    *,
    runtime: str = "auto",
) -> dict[str, Any]:
    """Build copy-ready MCP server registration snippet for any supported coding-agent host."""
    base = (root or find_catalog_root()).resolve()
    py = sys.executable or "python3"
    server_entry = {
        "command": py,
        "args": ["-m", "open_fleet.mcp_server", "--root", str(base)],
        "env": {
            "OPEN_FLEET_ROOT": str(base),
            "OPEN_FLEET_RUNTIME": runtime,
        },
    }
    if host == "codex":
        toml_lines = [
            "[mcp_servers.open-fleet]",
            f'command = "{py}"',
            f'args = ["-m", "open_fleet.mcp_server", "--root", "{base}"]',
            "",
            "[mcp_servers.open-fleet.env]",
            f'OPEN_FLEET_ROOT = "{base}"',
            f'OPEN_FLEET_RUNTIME = "{runtime}"',
        ]
        return {"host": host, "format": "toml", "config_path": "~/.codex/config.toml", "content": "\n".join(toml_lines) + "\n", "server": server_entry}
    if host == "opencode":
        doc = {
            "mcp": {
                "open-fleet": {
                    "type": "local",
                    "command": [py, "-m", "open_fleet.mcp_server", "--root", str(base)],
                    "environment": {
                        "OPEN_FLEET_ROOT": str(base),
                        "OPEN_FLEET_RUNTIME": runtime,
                    },
                }
            }
        }
        return {"host": host, "format": "json", "config_path": "~/.config/opencode/opencode.json", "content": json.dumps(doc, indent=2) + "\n", "json": doc, "server": server_entry}
    profile = HOST_PROFILES.get(host, HOST_PROFILES["claude"])
    doc = {"mcpServers": {"open-fleet": server_entry}}
    return {
        "host": host,
        "format": "json",
        "config_path": f"~/{profile['mcp_rel']}",
        "content": json.dumps(doc, indent=2) + "\n",
        "json": doc,
        "server": server_entry,
    }


def merge_claude_hooks(
    existing: dict[str, Any],
    root: Path,
    *,
    remove: bool = False,
) -> tuple[dict[str, Any], bool]:
    """Non-destructively add or remove open-fleet's Stop/TaskCompleted verify-gate hooks."""
    gate = str((root / "runtime" / "scripts" / "verify-gate.sh").resolve())
    result = json.loads(json.dumps(existing)) if isinstance(existing, dict) else {}
    hooks = result.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}

    desired = {
        "Stop": {
            "hooks": [{"type": "command", "command": f"{gate} --event stop", "timeout": 120}]
        },
        "TaskCompleted": {
            "hooks": [{"type": "command", "command": f"{gate} --event task", "timeout": 120}]
        },
    }

    changed = False
    for event_name, target_entry in desired.items():
        current = hooks.get(event_name)
        entries = list(current) if isinstance(current, list) else []
        filtered = []
        removed_any = False
        for entry in entries:
            inner = entry.get("hooks") if isinstance(entry, dict) else None
            is_open_fleet = isinstance(inner, list) and any(
                isinstance(h, dict) and "verify-gate.sh" in str(h.get("command") or "") for h in inner
            )
            if is_open_fleet:
                removed_any = True
                continue
            filtered.append(entry)
        if remove:
            if removed_any:
                changed = True
            if filtered:
                hooks[event_name] = filtered
            elif event_name in hooks:
                del hooks[event_name]
        else:
            filtered.append(target_entry)
            if filtered != entries:
                changed = True
            hooks[event_name] = filtered

    if hooks:
        result["hooks"] = hooks
    elif "hooks" in result:
        del result["hooks"]
    return result, changed


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
        os.replace(tmp_name, path)
    except BaseException:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise


def setup_host(
    host: str = "claude",
    *,
    root: Path | None = None,
    home: Path | None = None,
    skills_dir: Path | None = None,
    runtime: str = "auto",
    wire_hooks: bool = False,
    wire_mcp: bool = False,
    force: bool = False,
    uninstall: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Install/uninstall symlinks, wire completion hooks atomically, and emit or write MCP config."""
    if host not in HOST_PROFILES:
        raise ValueError(f"unsupported host {host!r}; choose from {', '.join(sorted(HOST_PROFILES))}")
    base = (root or find_catalog_root()).resolve()
    home_dir = (home or Path.home()).expanduser().resolve()
    profile = HOST_PROFILES[host]
    target_skills = (skills_dir or (home_dir / profile["skills_rel"])).expanduser().resolve()

    missions = sorted(
        d.name
        for d in (base / "skills").iterdir()
        if d.is_dir() and not d.name.startswith((".", "_")) and (d / "SKILL.md").is_file()
    )
    actions: list[str] = []
    warnings: list[str] = []

    if host == "claude" and not uninstall:
        settings_path = home_dir / profile["settings_rel"]
        hooks_state = _check_claude_hooks(settings_path, base)
        if hooks_state.get("plugin_enabled") and not force:
            raise RuntimeError(
                "Claude Code plugin open-fleet@open-fleet is enabled in ~/.claude/settings.json; "
                "do not stack symlink installs with the plugin (disable plugin or pass --force)"
            )

    if uninstall:
        removed = 0
        for name in missions:
            link = target_skills / name
            if link.is_symlink() and (link.resolve() == (base / "skills" / name).resolve() or force):
                actions.append(f"unlink {link}")
                if not dry_run:
                    link.unlink()
                removed += 1
        if host == "claude" and profile["settings_rel"]:
            settings_path = home_dir / profile["settings_rel"]
            if settings_path.is_file():
                existing = json.loads(settings_path.read_text(encoding="utf-8"))
                updated, changed = merge_claude_hooks(existing, base, remove=True)
                if changed:
                    actions.append(f"remove verify-gate.sh hooks from {settings_path}")
                    if not dry_run:
                        _atomic_write_json(settings_path, updated)
        return {
            "host": host,
            "mode": "uninstall",
            "dry_run": dry_run,
            "skills_dir": str(target_skills),
            "missions_affected": removed,
            "actions": actions,
            "warnings": warnings,
        }

    # Pre-check destinations before modifying anything (fail closed on conflicts).
    for name in missions:
        dst = target_skills / name
        src = (base / "skills" / name).resolve()
        if dst.exists() and not dst.is_symlink():
            raise RuntimeError(f"{dst} exists and is a real directory; remove it before linking")
        if dst.is_symlink() and dst.exists() and dst.resolve() != src and not force:
            raise RuntimeError(f"{dst} already points to {dst.resolve()}; pass --force to repoint")

    if not dry_run:
        target_skills.mkdir(parents=True, exist_ok=True)
    linked = 0
    for name in missions:
        src = (base / "skills" / name).resolve()
        dst = target_skills / name
        actions.append(f"symlink {dst} -> {src}")
        if not dry_run:
            if dst.is_symlink():
                dst.unlink()
            dst.symlink_to(src)
        linked += 1

    hooks_result = None
    if wire_hooks:
        if profile["supports_hooks"] and profile["settings_rel"]:
            settings_path = home_dir / profile["settings_rel"]
            existing = {}
            if settings_path.is_file():
                existing = json.loads(settings_path.read_text(encoding="utf-8"))
            updated, changed = merge_claude_hooks(existing, base, remove=False)
            actions.append(f"merge verify-gate.sh hooks into {settings_path}")
            if not dry_run and changed:
                _atomic_write_json(settings_path, updated)
            hooks_result = {"path": str(settings_path), "changed": changed, "preview": updated.get("hooks")}
        else:
            warnings.append(f"{host} does not use Claude Code Stop/TaskCompleted hooks; use MCP tools or invoke verify.py per phase")

    mcp_cfg = build_mcp_config(host, base, runtime=runtime)
    mcp_written = False
    if wire_mcp and mcp_cfg["format"] == "json":
        mcp_path = home_dir / profile["mcp_rel"]
        existing_mcp = {}
        if mcp_path.is_file():
            existing_mcp = json.loads(mcp_path.read_text(encoding="utf-8"))
        if not isinstance(existing_mcp, dict):
            raise RuntimeError(f"{mcp_path} is not a JSON object")
        if host == "opencode":
            mcp_block = dict(existing_mcp.get("mcp") or {})
            mcp_block["open-fleet"] = mcp_cfg["json"]["mcp"]["open-fleet"]
            existing_mcp["mcp"] = mcp_block
        else:
            servers = dict(existing_mcp.get("mcpServers") or {})
            servers["open-fleet"] = mcp_cfg["server"]
            existing_mcp["mcpServers"] = servers
        actions.append(f"register open-fleet MCP server in {mcp_path}")
        if not dry_run:
            _atomic_write_json(mcp_path, existing_mcp)
        mcp_written = True
    elif wire_mcp and mcp_cfg["format"] == "toml":
        warnings.append(f"append the generated TOML snippet to ~/{profile['mcp_rel']} (TOML auto-merge skipped to preserve comments)")

    return {
        "host": host,
        "mode": "install",
        "dry_run": dry_run,
        "skills_dir": str(target_skills),
        "missions_affected": linked,
        "hooks": hooks_result,
        "mcp": {**mcp_cfg, "written": mcp_written},
        "actions": actions,
        "warnings": warnings,
    }
