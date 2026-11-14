#!/usr/bin/env python3
"""terminal_ops.py — terminal create/read + read-only list/show (S9/S18).

Upstream argv (pinned specs/core.ts, handlers/terminal.ts):

* ``create [--worktree …] [--title …] [--command …] [--shell …] [--focus]`` —
  --shell ∈ cmd.exe|powershell.exe|pwsh.exe|wsl.exe|bash.exe|git-bash (a host
  that cannot apply it refuses rather than spawning its default).
* ``read [--terminal …] [--cursor n] [--limit n] [--screen]`` — --cursor is a
  non-negative integer; --screen and --cursor are mutually exclusive (a screen
  read is the current frame, with no history to page). The receipt carries
  source: stream|screen|screen-unavailable, and an ABSENT source on a --screen
  read means an older host dropped the unknown param and answered the other
  question — upstream refuses with incompatible_runtime, and this wrapper
  fails closed the same way instead of certifying accumulated output as the
  rendered screen. screen-unavailable is degraded (accumulated output stood
  in), likewise never certified.
* ``list [--worktree …] [--limit n] [--include-visual-layouts]`` and
  ``show [--terminal …]`` — read-only inventory: ROWS/HANDLE lines.

Mutating verbs (close/rename/set-pane-title/split/switch/stop/send/wait) are
PARKED (lifecycle-risk: this tool takes no process or PTY action) and stay out;
`set-pane-title` joined them at v1.4.238 (terminal-set-pane-title.ts).

Exit: 0 ok · 1 runtime/refusal/receipt/evidence failure · 2 usage.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import orca_cli
except ImportError:  # loaded by file path (tests): the resolver sits beside this script
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import orca_cli
from pm import _off_column_0
from pm import _visible_line as _line

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_REFUSED = 2

SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "wsl.exe", "bash.exe",
          "git-bash")
MAX_SAFE_INT = 9007199254740991


class Refused(Exception):
    """Usage/validation refusal: exit 2, nothing was invoked."""


class Failed(Exception):
    """The runtime refused, the receipt is unreadable, or the evidence does
    not certify: exit 1."""


def _nonempty(value, flag):
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise Refused(f"{flag} needs a non-empty value")
    return value


def _positive_int(raw, flag):
    if not isinstance(raw, str) or not raw.isdigit():
        raise Refused(f"{flag} must be a positive integer, got {raw!r}")
    value = int(raw)
    if value < 1 or value > MAX_SAFE_INT:
        raise Refused(f"{flag} must be a positive integer, got {raw!r}")
    return raw


def _non_negative_int(raw, flag):
    if not isinstance(raw, str) or not raw.isdigit():
        raise Refused(f"{flag} must be a non-negative integer, got {raw!r}")
    return raw


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="terminal_ops.py",
        description="Terminal create/read + read-only list/show.")
    subs = parser.add_subparsers(dest="command", required=True)
    create = subs.add_parser("create", help="create a terminal")
    create.add_argument("--worktree", default=None)
    create.add_argument("--title", default=None)
    # dest: --command would otherwise overwrite the subparsers' dest="command".
    create.add_argument("--command", dest="launch_command", default=None)
    create.add_argument("--shell", default=None)
    create.add_argument("--focus", action="store_true")
    read = subs.add_parser("read", help="read bounded terminal output")
    read.add_argument("--terminal", default=None)
    read.add_argument("--cursor", default=None)
    read.add_argument("--limit", default=None)
    read.add_argument("--screen", action="store_true")
    wlist = subs.add_parser("list", help="list live terminals")
    wlist.add_argument("--worktree", default=None)
    wlist.add_argument("--limit", default=None)
    wlist.add_argument("--include-visual-layouts", action="store_true")
    show = subs.add_parser("show", help="show terminal metadata + preview")
    show.add_argument("--terminal", default=None)
    return parser.parse_args(argv)


def build_argv(ns):
    cmd = ns.command
    if cmd == "create":
        argv = ["terminal", "create"]
        if _nonempty(ns.worktree, "--worktree") is not None:
            argv += ["--worktree", ns.worktree]
        if _nonempty(ns.title, "--title") is not None:
            argv += ["--title", ns.title]
        if _nonempty(ns.launch_command, "--command") is not None:
            argv += ["--command", ns.launch_command]
        if ns.shell is not None:
            if ns.shell not in SHELLS:
                raise Refused(f"--shell must be one of {','.join(SHELLS)}, "
                              f"got {ns.shell!r}")
            argv += ["--shell", ns.shell]
        if ns.focus:
            argv += ["--focus"]
        return argv
    if cmd == "read":
        if ns.screen and ns.cursor is not None:
            raise Refused("--screen reads the current rendered screen, which "
                          "has no cursor to page from — use --cursor without "
                          "--screen")
        argv = ["terminal", "read"]
        if _nonempty(ns.terminal, "--terminal") is not None:
            argv += ["--terminal", ns.terminal]
        if ns.cursor is not None:
            argv += ["--cursor", _non_negative_int(ns.cursor, "--cursor")]
        if ns.limit is not None:
            argv += ["--limit", _positive_int(ns.limit, "--limit")]
        if ns.screen:
            argv += ["--screen"]
        return argv
    if cmd == "list":
        argv = ["terminal", "list"]
        if _nonempty(ns.worktree, "--worktree") is not None:
            argv += ["--worktree", ns.worktree]
        if ns.limit is not None:
            argv += ["--limit", _positive_int(ns.limit, "--limit")]
        if ns.include_visual_layouts:
            argv += ["--include-visual-layouts"]
        return argv
    argv = ["terminal", "show"]
    if _nonempty(ns.terminal, "--terminal") is not None:
        argv += ["--terminal", ns.terminal]
    return argv


def format_create(result):
    if not isinstance(result, dict):
        raise Failed("terminal create receipt is not an object")
    term = result.get("terminal") if isinstance(result.get("terminal"),
                                                dict) else {}
    handle = term.get("handle") or result.get("handle")
    if not handle:
        raise Failed("terminal create returned no handle")
    return [f"HANDLE={_line(handle)}"]


def format_read(result, want_screen=False):
    if not isinstance(result, dict):
        raise Failed("terminal read receipt is not an object")
    term = result.get("terminal") if isinstance(result.get("terminal"),
                                                dict) else result
    source = term.get("source") if isinstance(term, dict) else None
    if want_screen:
        # Mirrors the handler: absent source = an older host answered the
        # stream question; screen-unavailable = accumulated output stood in.
        # Neither is the rendered screen; neither is certified.
        if source is None:
            raise Failed("older host: --screen was asked but the receipt "
                         "carries no source, so this is accumulated output, "
                         "not the rendered screen")
        if source == "screen-unavailable":
            raise Failed("screen-unavailable: no screen could be rendered and "
                         "accumulated output was returned instead")
        if source != "screen":
            raise Failed(f"--screen asked but the receipt source is {source!r}")
    if source is None:
        source = "unknown"
    tail = term.get("tail") if isinstance(term, dict) else None
    if not isinstance(tail, list):
        raise Failed("terminal read receipt names no tail")
    lines = [f"SOURCE={_line(source)}",
             f"TRUNCATED={'yes' if term.get('truncated') else 'no'}",
             "--- tail"]
    # One item, one line — and off column 0 when it starts like this receipt's own lines
    # (Codex round 2, swept: a pane printing `SOURCE=transcript` forged the field).
    lines.extend(_off_column_0(_line(line)) for line in tail)
    return lines


def format_list(result):
    if not isinstance(result, dict):
        raise Failed("terminal list receipt is not an object")
    terminals = result.get("terminals")
    if not isinstance(terminals, list):
        raise Failed("terminal list receipt names no terminals")
    lines = [f"ROWS={len(terminals)}",
             f"TRUNCATED={'yes' if result.get('truncated') else 'no'}"]
    for row in terminals:
        if not isinstance(row, dict):
            continue
        lines.append(_off_column_0(f"{_line(row.get('handle') or '?')} "
                                   f"{_line(row.get('title') or '?')}"))
    return lines


def format_show(result):
    if not isinstance(result, dict):
        raise Failed("terminal show receipt is not an object")
    term = result.get("terminal")
    if not isinstance(term, dict) or not term.get("handle"):
        raise Failed("terminal show receipt names no terminal")
    return [f"HANDLE={_line(term.get('handle'))}",
            f"TITLE={_line(term.get('title') or 'none')}"]


def run_orca(argv):
    return orca_cli.run_json(argv, timeout=120, error=Failed)


def main(argv=None):
    try:
        ns = parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return exc.code
    try:
        result = run_orca(build_argv(ns))
        if ns.command == "create":
            lines = format_create(result)
        elif ns.command == "read":
            lines = format_read(result, want_screen=ns.screen)
        elif ns.command == "list":
            lines = format_list(result)
        else:
            lines = format_show(result)
        print("\n".join(lines))
        return EXIT_OK
    except Refused as exc:
        print(f"terminal_ops: REFUSED: {_line(exc)}", file=sys.stderr)  # one inert line (Codex round 3)
        return EXIT_REFUSED
    except Failed as exc:
        print(f"terminal_ops: FAILED: {_line(exc)}", file=sys.stderr)  # one inert line (Codex round 3)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
