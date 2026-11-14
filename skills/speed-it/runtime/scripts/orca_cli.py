#!/usr/bin/env python3
"""orca_cli.py — resolve the Orca CLI command name the way upstream documents it (#510).

Every fleet script that talks to Orca resolves the executable through this module, so one
rule holds everywhere. The order is upstream's own, from `skill-stubs/_shared/cli-resolution.md`
in stablyai/orca:

  1. `OPEN_FLEET_CLI_COMMAND`, else `ORCA_CLI_COMMAND`, when set. Orca exports the latter inside
     the sessions it manages (structured worker sessions, managed WSL sessions), and the test
     suite points it at a stub. It must name ONE executable — a bare name or an absolute path,
     never a command line, an option, a cwd-relative path or an invisible character — or
     resolution refuses by name. One policy for every resolver: runtime/providers/orca.py's
     resolve_orca_binary delegates to resolve_orca here, upstream_probe reads the same override.
  2. `orca-dev` when `ORCA_DEV_REPO_ROOT` is set — a dev checkout's launcher.
  3. `orca-ide` on Linux, WSL included. Orca's Linux executable, `.deb` and `.rpm` are all
     `orca-ide` by construction (`src/main/cli/bundled-cli-launcher-path.ts`
     LINUX_CLI_COMMAND_NAME). Bare `orca` on a Linux host outside an Orca terminal normally
     resolves to the GNOME Orca screen reader at /usr/bin/orca and starts speech on the
     user's machine — upstream's stated reason, not folklore.
  4. `orca` everywhere else (macOS, Windows).

Resolution never consults PATH: the name is a policy decision, and a missing executable is
reported by the caller (`run_json` names a configured command that is not on PATH, `--path`
below any), never silently swapped for another build. Under OPEN_FLEET_RUNTIME=auto the registry
(active_provider_name) decides whether Orca answers at all, so the two never disagree.

Usage:
  python3 orca_cli.py            # print the resolved command name
  python3 orca_cli.py --path     # print the resolved absolute path; exit 1 when not on PATH
  python3 orca_cli.py --version  # print `open-fleet-rpi <runtime/pins.json orca.version>`
                                 # (`unknown` when the pin cannot be read)
  python3 orca_cli.py <domain> ARGS...
      # hand `<domain> ARGS` (minus --json) to the active runtime provider's dispatch and print
      # a JSON envelope ({"ok": true, "result": ...} or the error); <domain> is orchestration,
      # worktree, terminal, vm, search, environment, linear, jira or reference
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

Exit: 0 printed · 1 (`--path`) the resolved command is not on PATH, or a `<domain>` dispatch
failed (its error envelope is still printed on stdout) · 2 usage, a configured CLI command that
is not one executable, or an unknown OPEN_FLEET_RUNTIME (else legacy ORCA_FLEET_RUNTIME) value,
checked first whatever the arguments.
"""
import sys

# W3-01: `python3 <dir>/<script>.py` puts <dir> at sys.path[0], AHEAD of the stdlib, so a committed
# sibling named like a stdlib module (json.py, hashlib.py) would BE that module here, and no
# toolchain hash binds it. Drop that entry before any other import (`from __future__` imports too,
# which is why this file has none); `os` is read from sys.modules, loaded at start-up, never
# imported. `python3 -I` does the same from outside; this holds when a caller forgets it.
if (__name__ == "__main__" and not getattr(sys.flags, "safe_path", False) and sys.path
        and ("os" not in sys.modules or sys.modules["os"].path.realpath(sys.path[0])
             == sys.modules["os"].path.dirname(sys.modules["os"].path.realpath(__file__)))):
    del sys.path[0]

import json
import os
import platform
import shutil
import subprocess
import unicodedata

from pathlib import Path

LINUX_COMMAND = "orca-ide"
DEFAULT_COMMAND = "orca"
DEV_COMMAND = "orca-dev"
CLI_COMMAND_RULE = "it must name one executable, without arguments"

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
    # W3-01 (PR #719 re-attack): the repo ROOT never goes on sys.path — there, a root-level file
    # named like a stdlib module (`typing.py`, `traceback.py`) answered imports the package makes
    # while it loads. The `runtime` package is registered by path: a module whose __path__ is a
    # plain list naming this repository's runtime/, so only `runtime.*` resolves there.
    if "runtime" not in sys.modules:
        package = type(sys)("runtime")  # a plain module object; nothing imported to make it
        package.__path__ = [str(Path(__file__).resolve().parent.parent.parent / "runtime")]
        sys.modules["runtime"] = package
    from runtime import providers
    return providers


class CliCommandError(ValueError):
    """A configured CLI command (OPEN_FLEET_CLI_COMMAND / ORCA_CLI_COMMAND) that is not one executable."""


# Unicode categories a command name must never hold: controls (C0 and C1), format characters
# (bidi overrides, zero-width), line/paragraph separators, surrogates, private use, unassigned.
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn"})


def cli_command_problem(value, var, which=None):
    """Why `value`, read from the env var `var`, cannot be the CLI command; None when it can.

    ONE policy for every resolver (upstream_probe.resolve_cli calls this too, W4-15/W2-03): the
    value becomes argv[0] of every fleet call, so it names one executable — a bare name found
    on PATH, or an absolute path — never a command line (`python3 /tmp/orca.py` died as an
    opaque errno), an option (`-x`), a path relative to whatever cwd the caller has, or a
    control, format or separator character (C0, C1, bidi and other Cf, line/paragraph separators,
    surrogates, private or unassigned code points). `which` (shutil.which) adds the on-PATH check;
    without it only the shape is judged, because resolve() never consults PATH. The value is
    shown repr()-quoted.
    """
    if any(unicodedata.category(c) in _INVISIBLE_CATEGORIES for c in value):
        why = "holds a control, format or separator character"
    elif value.startswith("-"):
        why = "is option-shaped"
    elif not os.path.isabs(value) and any(c.isspace() for c in value):
        why = "is a command line, not one executable"
    elif not os.path.isabs(value) and "/" in value:
        why = "is a relative path"
    elif which is not None and which(value) is None:
        why = "is not on PATH"
    else:
        return None
    return f"{var}={value!r} {why} ({CLI_COMMAND_RULE})"


def configured_command(env):
    """(var, value) of the CLI-command override in force, or ("", "") when none is set:
    OPEN_FLEET_CLI_COMMAND, else ORCA_CLI_COMMAND (a blank value is unset). The one precedence
    for every resolver: resolve_orca (which runtime/providers/orca.py's resolve_orca_binary
    delegates to) and upstream_probe.resolve_cli read the override through this too."""
    for var in ("OPEN_FLEET_CLI_COMMAND", "ORCA_CLI_COMMAND"):
        value = (env.get(var) or "").strip(" \t\r\n\v\f")  # ASCII only: a C1 NEL or NBSP is judged, not trimmed
        if value:
            return var, value
    return "", ""


def resolve_orca(env=None, system=None) -> str:
    """The ORCA CLI itself, never this module's shim: the validated override, else orca-dev under
    ORCA_DEV_REPO_ROOT, else the platform's name. The one resolution of the Orca binary;
    runtime/providers/orca.py:resolve_orca_binary (the Orca provider, `auto`, preflight,
    install.sh) delegates here. A configured command that is not one executable raises
    CliCommandError (cli_command_problem)."""
    env = os.environ if env is None else env
    var, configured = configured_command(env)
    if configured:
        problem = cli_command_problem(configured, var)
        if problem:
            raise CliCommandError(problem)
        return configured
    if (env.get("ORCA_DEV_REPO_ROOT") or "").strip():
        return DEV_COMMAND
    system = platform.system() if system is None else system
    if system == "Linux":
        return LINUX_COMMAND
    return DEFAULT_COMMAND


def resolve(env=None, system=None) -> str:
    """The command name to execute, per the order in the module docstring.

    `env` and `system` are injectable for tests; production callers pass nothing. On Orca it is
    resolve_orca. Under OPEN_FLEET_RUNTIME=auto the registry decides (active_provider_name: the
    Orca binary only when it is on PATH), so this never names an Orca binary the registry
    rejected; under an explicit non-Orca runtime a configured override still wins (a test stub,
    an operator's wrapper), else this module's own shim answers.
    """
    env = os.environ if env is None else env
    runtime = _active_non_orca_runtime(env)
    if runtime == "auto":
        if _load_providers().active_provider_name(env, system) == "orca":
            return resolve_orca(env, system)
        return str(Path(__file__).resolve())
    if runtime and not configured_command(env)[1]:
        return str(Path(__file__).resolve())
    return resolve_orca(env, system)


def _inert(value) -> str:
    """Any text in a message every tool prints to the coordinator's terminal (a runtime's error
    code, an exception's text, a configured value): non-printable characters (controls,
    newlines, bidi) escaped, so it stays one inert line (W4-11; Codex round 3)."""
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in str(value))


def run_json(argv, *, timeout, error, nonzero="strict"):
    """Run `<resolved cli> *argv --json`; return the envelope's result object or raise `error`."""
    if _active_non_orca_runtime():
        providers = _load_providers()
        try:
            clean = [a for a in argv if a != "--json"]
            res = providers.get_provider().dispatch(clean, timeout=timeout)
            return res if isinstance(res, dict) else {}
        except providers.ProviderError as exc:
            raise error(f"orca refused: {_inert(exc.code)}")
        except Exception as exc:
            raise error(f"could not run orca: {_inert(exc)}")
    try:
        cli = resolve()
    except CliCommandError as exc:
        raise error(f"could not run orca: {_inert(exc)}")
    var, configured = configured_command(os.environ)
    problem = cli_command_problem(configured, var, shutil.which) if configured else None
    if problem:
        raise error(f"could not run orca: {_inert(problem)}")
    try:
        proc = subprocess.run([cli, *argv, "--json"],
                              capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise error(f"could not run orca: {_inert(exc)}")
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
        # The code is the runtime's text and every tool prints this line to the coordinator's
        # terminal: anything non-printable (controls, newlines, bidi) is escaped (W4-11).
        raise error(f"orca refused: {_inert(code)}")
    if nonzero == "strict" and proc.returncode != 0:
        raise error(f"orca exited {proc.returncode} with no error envelope")
    if nonzero == "no-receipt" and not result and proc.returncode != 0:
        raise error(f"orca exited {proc.returncode} with no receipt")
    return result


def _pinned_version() -> str:
    """The Orca version runtime/pins.json pins, or "unknown" when the pin cannot be read: a
    literal fallback here reported a stale pin as current once the file moved on
    (2026-10-26 review); "unknown" lets spawn_worker.sh's drift NOTE fire instead."""
    pins_path = Path(__file__).resolve().parent.parent / "pins.json"
    try:
        data = json.loads(pins_path.read_text(encoding="utf-8"))
        return (data.get("orca") or {}).get("version") or "unknown"
    except (OSError, ValueError, AttributeError):
        return "unknown"


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    bad_runtime = _validate_runtime()
    if bad_runtime:
        print(f"orca_cli: {_inert(bad_runtime)}", file=sys.stderr)
        return 2
    if argv in ([], ["--path"]):
        try:
            name = resolve()
        except CliCommandError as exc:
            print(f"orca_cli: {_inert(exc)}", file=sys.stderr)
            return 2
    if argv == []:
        print(name)
        return 0
    if argv == ["--path"]:
        found = (name if (os.path.isabs(name) and os.path.isfile(name) and os.access(name, os.X_OK))
                 else shutil.which(name))
        if not found:
            print(f"orca_cli: `{_inert(name)}` is not on PATH", file=sys.stderr)
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
    print("usage: orca_cli.py [--path | --version | <domain> ARGS...]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

