#!/usr/bin/env python3
"""worktree_ops.py — worktree list/show with selector validation (S10).

Upstream argv (pinned specs/core.ts, cli/selectors.ts):

* ``list [--repo <selector>] [--limit n]``
* ``show --worktree <selector>``

A selector is ``active``|``current`` or one of the documented prefixed forms —
identity:|id:|name:|branch:|issue:|path:|folder:|worktree: — with a non-empty
remainder (selectors.ts). Anything else refuses with exit 2 before any orca
call: a bare path must be spelled ``path:<abs>`` (cwd-relative guesses resolve
against the wrong machine over the SSH relay), and an unknown prefix is a
typo the runtime would bill a lookup to explain. Argv is a list, never a
shell string.

Exit: 0 ok · 1 runtime/refusal/receipt failure · 2 usage.
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
from pm import _visible

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_REFUSED = 2

SHORTCUTS = ("active", "current")
PREFIXES = ("identity:", "id:", "name:", "branch:", "issue:", "path:",
            "folder:", "worktree:")
MAX_SAFE_INT = 9007199254740991


class Refused(Exception):
    """Usage/validation refusal: exit 2, nothing was invoked."""


class Failed(Exception):
    """The runtime refused or the receipt is unreadable: exit 1."""


def validate_selector(value):
    if value in SHORTCUTS:
        return value
    if isinstance(value, str):
        for prefix in PREFIXES:
            if value.startswith(prefix) and len(value) > len(prefix):
                return value
    raise Refused(
        f"worktree selector must be active|current or "
        f"{'|'.join(PREFIXES)}<value>, got {value!r} — spell a bare path as "
        f"path:<absolute-path>")


def _positive_int(raw, flag):
    if not isinstance(raw, str) or not raw.isdigit():
        raise Refused(f"{flag} must be a positive integer, got {raw!r}")
    value = int(raw)
    if value < 1 or value > MAX_SAFE_INT:
        raise Refused(f"{flag} must be a positive integer, got {raw!r}")
    return raw


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="worktree_ops.py",
        description="Worktree list/show with selector validation.")
    subs = parser.add_subparsers(dest="command", required=True)
    wlist = subs.add_parser("list", help="list Orca-managed worktrees")
    wlist.add_argument("--repo", default=None)
    wlist.add_argument("--limit", default=None)
    show = subs.add_parser("show", help="show one worktree")
    show.add_argument("--worktree", required=True)
    return parser.parse_args(argv)


def build_argv(ns):
    if ns.command == "list":
        argv = ["worktree", "list"]
        if ns.repo is not None:
            if not ns.repo:
                raise Refused("--repo needs a non-empty value")
            argv += ["--repo", ns.repo]
        if ns.limit is not None:
            argv += ["--limit", _positive_int(ns.limit, "--limit")]
        return argv
    return ["worktree", "show", "--worktree",
            validate_selector(ns.worktree)]


def format_list(result):
    if not isinstance(result, dict):
        raise Failed("worktree list receipt is not an object")
    rows = result.get("worktrees")
    if not isinstance(rows, list):
        raise Failed("worktree list receipt names no worktrees")
    lines = [f"ROWS={len(rows)}",
             f"TRUNCATED={'yes' if result.get('truncated') else 'no'}"]
    for row in rows:
        if not isinstance(row, dict):
            continue
        lines.append(f"{_visible(row.get('id') or '?')} "
                     f"{_visible(row.get('displayName') or '?')}")
    return lines


def format_show(result):
    if not isinstance(result, dict):
        raise Failed("worktree show receipt is not an object")
    row = result.get("worktree")
    if not isinstance(row, dict) or not row.get("id"):
        raise Failed("worktree show receipt names no worktree")
    return [f"ID={_visible(row.get('id'))}",
            f"NAME={_visible(row.get('displayName') or 'none')}"]


def run_orca(argv):
    return orca_cli.run_json(argv, timeout=120, error=Failed)


def main(argv=None):
    try:
        ns = parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return exc.code
    try:
        result = run_orca(build_argv(ns))
        lines = format_list(result) if ns.command == "list" \
            else format_show(result)
        print("\n".join(lines))
        return EXIT_OK
    except Refused as exc:
        print(f"worktree_ops: REFUSED: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except Failed as exc:
        print(f"worktree_ops: FAILED: {exc}", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
