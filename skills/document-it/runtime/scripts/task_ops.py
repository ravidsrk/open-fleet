#!/usr/bin/env python3
"""task_ops.py — fail-closed task-create / task-update lifecycle flags (S2).

Upstream argv (pinned specs/orchestration.ts, handlers/orchestration/task-handlers.ts):

* ``task-create --spec <text> [--task-title …] [--display-name …] [--deps <json_array>]
  [--parent …] [--run …] [--from …] [--retry-request …]``
* ``task-update --id … --status <status> [--result <json>] [--run …] [--from …]
  [--retry-request …]`` with status ∈ pending|ready|dispatched|completed|failed|blocked.

Every flag is validated before any orca call: empty ids/specs, an unknown
status, and malformed --deps/--result JSON refuse with exit 2 and zero side
effects. Receipts parse fail-closed: an error envelope or a receipt without
``result.task{id, status}`` is exit 1, never a claimed transition. Argv is a
list, never a shell string: validated or refused, never interpolated.

Exit: 0 transitioned/created · 1 runtime/refusal/receipt failure · 2 usage.
"""
import argparse
import json
import os
import sys

try:
    import orca_cli
except ImportError:  # loaded by file path (tests): the resolver sits beside this script
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import orca_cli

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_REFUSED = 2

STATUSES = ("pending", "ready", "dispatched", "completed", "failed", "blocked")


class Refused(Exception):
    """Usage/validation refusal: exit 2, nothing was invoked."""


class Failed(Exception):
    """The runtime refused or the receipt is unreadable: exit 1."""


def _nonempty(value, flag):
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise Refused(f"{flag} needs a non-empty value")
    return value


def _json_array_of_strings(raw, flag):
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        raise Refused(f"{flag} must be a JSON array of task-id strings")
    if not isinstance(parsed, list) or not all(isinstance(x, str) for x in parsed):
        raise Refused(f"{flag} must be a JSON array of task-id strings")
    return raw


def _json_value(raw, flag):
    try:
        json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        raise Refused(f"{flag} must be JSON")
    return raw


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="task_ops.py",
        description="Fail-closed task-create / task-update lifecycle flags.")
    subs = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--run", default=None)
    common.add_argument("--from", dest="sender", default=None)
    common.add_argument("--retry-request", default=None)
    create = subs.add_parser("create", parents=[common],
                             help="create a task (spec required)")
    create.add_argument("--spec", required=True)
    create.add_argument("--task-title", default=None)
    create.add_argument("--display-name", default=None)
    create.add_argument("--deps", default=None)
    create.add_argument("--parent", default=None)
    update = subs.add_parser("update", parents=[common],
                             help="move a task to a status")
    update.add_argument("--id", dest="task_id", required=True)
    update.add_argument("--status", required=True)
    update.add_argument("--result", default=None)
    return parser.parse_args(argv)


def _scope_flags(ns):
    out = []
    if _nonempty(ns.run, "--run") is not None:
        out += ["--run", ns.run]
    if _nonempty(ns.sender, "--from") is not None:
        out += ["--from", ns.sender]
    if _nonempty(ns.retry_request, "--retry-request") is not None:
        out += ["--retry-request", ns.retry_request]
    return out


def build_create_argv(ns):
    spec = _nonempty(ns.spec, "--spec")
    argv = ["orchestration", "task-create", "--spec", spec]
    if _nonempty(ns.task_title, "--task-title") is not None:
        argv += ["--task-title", ns.task_title]
    if _nonempty(ns.display_name, "--display-name") is not None:
        argv += ["--display-name", ns.display_name]
    if ns.deps is not None:
        argv += ["--deps", _json_array_of_strings(ns.deps, "--deps")]
    if _nonempty(ns.parent, "--parent") is not None:
        argv += ["--parent", ns.parent]
    return argv + _scope_flags(ns)


def build_update_argv(ns):
    task_id = _nonempty(ns.task_id, "--id")
    if ns.status not in STATUSES:
        raise Refused(f"--status must be one of {','.join(STATUSES)}, "
                      f"got {ns.status!r}")
    argv = ["orchestration", "task-update", "--id", task_id,
            "--status", ns.status]
    if ns.result is not None:
        argv += ["--result", _json_value(ns.result, "--result")]
    return argv + _scope_flags(ns)


def run_orca(argv):
    """Run orca with --json; return the result object or raise Failed."""
    return orca_cli.run_json(argv, timeout=120, error=Failed)


def main(argv=None):
    try:
        ns = parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return exc.code
    try:
        if ns.command == "create":
            argv = build_create_argv(ns)
            verb, label = "create", "CREATED"
        else:
            argv = build_update_argv(ns)
            verb, label = "update", "UPDATED"
        result = run_orca(argv)
        task = result.get("task") if isinstance(result, dict) else None
        tid = task.get("id") if isinstance(task, dict) else None
        status = task.get("status") if isinstance(task, dict) else None
        if not tid or not status:
            raise Failed(f"task-{verb} receipt names no task id/status")
        print(f"{label}={tid} STATUS={status}")
        return EXIT_OK
    except Refused as exc:
        print(f"task_ops: REFUSED: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except Failed as exc:
        print(f"task_ops: FAILED: {exc}", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
