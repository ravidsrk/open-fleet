#!/usr/bin/env python3
"""orca_cli.py — resolve the Orca CLI command name the way upstream documents it (#510).

Every fleet script that talks to Orca resolves the executable through this module, so one
rule holds everywhere. The order is upstream's own, from `skill-stubs/_shared/cli-resolution.md`
in stablyai/orca:

  1. `ORCA_CLI_COMMAND` when set. Orca exports it inside the sessions it manages (structured
     worker sessions, managed WSL sessions), and the test suite points it at a stub.
  2. `orca-dev` when `ORCA_DEV_REPO_ROOT` is set — a dev checkout's launcher.
  3. `orca-ide` on Linux, WSL included. Orca's Linux executable, `.deb` and `.rpm` are all
     `orca-ide` by construction (`src/main/cli/bundled-cli-launcher-path.ts`
     LINUX_CLI_COMMAND_NAME). Bare `orca` on a Linux host outside an Orca terminal normally
     resolves to the GNOME Orca screen reader at /usr/bin/orca and starts speech on the
     user's machine — upstream's stated reason, not folklore.
  4. `orca` everywhere else (macOS, Windows).

Resolution never consults PATH: the name is a policy decision, and a missing executable is
reported by the caller (or by `--path` below), never silently swapped for another build.

Usage:
  python3 orca_cli.py            # print the resolved command name
  python3 orca_cli.py --path     # print the resolved absolute path; exit 1 when not on PATH
Library:
  from orca_cli import resolve, run_json
  argv = [resolve(), "orchestration", "check", "--json"]
  result = run_json(["orchestration", "check"], timeout=120, error=Failed)

`run_json` is the one envelope reader the *_ops.py / send_msg / hitl_ask / check_reply /
search_sessions wrappers share (it was copy-pasted into each): run `<cli> ARGV --json`,
parse the envelope, raise the caller's own exception class on an unrunnable CLI,
unreadable or non-object JSON, or an `error` (top level or inside `result`), and return
the `result` object (`{}` when absent). `nonzero` keeps each caller's exit-status rule:
"strict" (a nonzero exit with no error envelope fails), "no-receipt" (fails only when
there is no result either), "ignore" (the envelope alone decides).

Exit: 0 printed · 1 (`--path`) the resolved command is not on PATH · 2 usage.
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys

from pathlib import Path

LINUX_COMMAND = "orca-ide"
DEFAULT_COMMAND = "orca"
DEV_COMMAND = "orca-dev"

_PROVIDER_DOMAINS = frozenset({
    "orchestration", "worktree", "terminal", "vm",
    "search", "environment", "linear", "jira", "reference",
})


def _active_non_orca_runtime(env=None) -> str:
    """The explicitly selected non-Orca runtime, or '' for the Orca CLI path.

    An explicit `OPEN_FLEET_RUNTIME` wins over an inherited `ORCA_CLI_COMMAND` (Orca exports that
    inside its own sessions, which used to silently override `OPEN_FLEET_RUNTIME=posix`, #578
    audit). The CLI-command override only decides WHICH Orca binary runs.
    """
    env = os.environ if env is None else env
    rt = (env.get("OPEN_FLEET_RUNTIME") or env.get("ORCA_FLEET_RUNTIME") or "").strip().lower()
    if rt and rt != "orca":
        return rt
    return ""


def _validate_runtime(env=None):
    """Return an error string when the selected runtime is unknown, else None."""
    rt = _active_non_orca_runtime(env)
    if not rt:
        return None
    providers = _load_providers()
    try:
        providers.active_provider_name(os.environ if env is None else env)
    except providers.ProviderError as exc:
        return exc.message
    return None


def _load_providers():
    root = str(Path(__file__).resolve().parent.parent.parent)
    if root not in sys.path:
        sys.path.insert(0, root)
    from runtime import providers
    return providers


def resolve(env=None, system=None) -> str:
    """The command name to execute, per the order in the module docstring.

    `env` and `system` are injectable for tests; production callers pass nothing.
    """
    env = os.environ if env is None else env
    configured = (env.get("OPEN_FLEET_CLI_COMMAND") or env.get("ORCA_CLI_COMMAND") or "").strip()
    if configured:
        return configured
    if _active_non_orca_runtime(env):
        return str(Path(__file__).resolve())
    if (env.get("ORCA_DEV_REPO_ROOT") or "").strip():
        return DEV_COMMAND
    system = platform.system() if system is None else system
    if system == "Linux":
        return LINUX_COMMAND
    return DEFAULT_COMMAND


def run_json(argv, *, timeout, error, nonzero="strict"):
    """Run `<resolved cli> *argv --json`; return the envelope's result object or raise `error`."""
    if _active_non_orca_runtime():
        providers = _load_providers()
        try:
            clean = [a for a in argv if a != "--json"]
            res = providers.get_provider().dispatch(clean, timeout=timeout)
            return res if isinstance(res, dict) else {}
        except providers.ProviderError as exc:
            raise error(f"orca refused: {exc.code}")
        except Exception as exc:
            raise error(f"could not run orca: {exc}")
    try:
        proc = subprocess.run([resolve(), *argv, "--json"],
                              capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise error(f"could not run orca: {exc}")
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise error(f"orca returned unreadable JSON (exit {proc.returncode})")
    if not isinstance(doc, dict):
        raise error("orca returned a non-object envelope")
    result = doc.get("result") if isinstance(doc.get("result"), dict) else {}
    err = doc.get("error") or result.get("error")
    if err:
        code = err.get("code") if isinstance(err, dict) else err
        raise error(f"orca refused: {code}")
    if nonzero == "strict" and proc.returncode != 0:
        raise error(f"orca exited {proc.returncode} with no error envelope")
    if nonzero == "no-receipt" and not result and proc.returncode != 0:
        raise error(f"orca exited {proc.returncode} with no receipt")
    return result


def _pinned_version() -> str:
    pins_path = Path(__file__).resolve().parent.parent / "pins.json"
    try:
        data = json.loads(pins_path.read_text(encoding="utf-8"))
        return (data.get("orca") or {}).get("version") or "v1.4.229"
    except Exception:
        return "v1.4.229"


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    bad_runtime = _validate_runtime()
    if bad_runtime:
        print(f"orca_cli: {bad_runtime}", file=sys.stderr)
        return 2
    if argv == []:
        print(resolve())
        return 0
    if argv == ["--path"]:
        name = resolve()
        found = (name if (os.path.isabs(name) and os.path.isfile(name) and os.access(name, os.X_OK))
                 else shutil.which(name))
        if not found:
            print(f"orca_cli: `{name}` is not on PATH", file=sys.stderr)
            return 1
        print(found)
        return 0
    if argv == ["--version"]:
        print(f"open-fleet-rpi {_pinned_version()}")
        return 0
    if argv and argv[0] in _PROVIDER_DOMAINS:
        providers = _load_providers()
        clean = [a for a in argv if a != "--json"]
        try:
            res = providers.get_provider().dispatch(clean)
            print(json.dumps({"ok": True, "result": res}))
            return 0
        except providers.ProviderError as exc:
            print(json.dumps(exc.to_envelope()))
            return 1
        except Exception as exc:
            print(json.dumps({"ok": False, "error": {"code": "runtime_error", "message": str(exc)}}))
            return 1
    print("usage: orca_cli.py [--path]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

