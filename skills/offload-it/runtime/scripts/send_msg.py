#!/usr/bin/env python3
"""send_msg.py — orchestration send with the handler's rules + sender assertion (S11).

Upstream argv (pinned specs/orchestration.ts, handlers/orchestration/
message-send-handler.ts + terminal-identity.ts). The handler's own gates are
enforced client-side, before any orca call (exit 2, zero side effects):

* --type ∈ status|dispatch|worker_done|merge_ready|escalation|handoff|
  decision_gate|question|heartbeat.
* worker_done REQUIRES --outcome succeeded|failed; --outcome rides NOTHING else.
* worker_done|heartbeat never target a group address (no --to @…): exact-Dispatch
  signals belong to one Dispatch.
* worker_done|heartbeat never run identity-less: without --from AND without
  ORCA_TERMINAL_HANDLE the lifecycle sender is refused (focus is not lifecycle
  authority). An explicit --from that disagrees with ORCA_TERMINAL_HANDLE is
  refused — naming the sender is an identity claim, and a wrong one speaks as
  a sibling worker. Otherwise --from defaults to the env handle.

--payload must be JSON. Everything else rides through nonempty-checked. Argv is
a list, never a shell string. Live delivery is PARKED (needs-human: send a
worker_done from a live dispatch and confirm the relay receipt + settlement).

Exit: 0 sent · 1 runtime/refusal/receipt failure · 2 usage.
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

TYPES = ("status", "dispatch", "worker_done", "merge_ready", "escalation",
         "handoff", "decision_gate", "question", "heartbeat")
OUTCOMES = ("succeeded", "failed")
LIFECYCLE = ("worker_done", "heartbeat")

PASSTHROUGH = ("to", "run", "body", "priority", "thread_id", "task_id",
               "dispatch_id", "files_modified", "report_path", "phase",
               "retry_request", "dispatch_capability")


def flag_of(attr):
    return "--" + attr.replace("_", "-")


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


def resolve_from(explicit, env):
    ambient = env.get("ORCA_TERMINAL_HANDLE", "")
    if explicit is not None:
        _nonempty(explicit, "--from")
        if ambient and explicit != ambient:
            raise Refused(f"--from '{explicit}' disagrees with "
                          f"ORCA_TERMINAL_HANDLE='{ambient}' — passing another "
                          f"pane's handle would speak as that worker")
        return explicit
    return ambient or None


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="send_msg.py",
        description="Fail-closed orchestration send.")
    parser.add_argument("--subject", required=True)
    parser.add_argument("--to", default=None)
    parser.add_argument("--run", default=None)
    parser.add_argument("--from", dest="sender", default=None)
    parser.add_argument("--body", default=None)
    parser.add_argument("--type", dest="msg_type", default=None)
    parser.add_argument("--priority", default=None)
    parser.add_argument("--thread-id", dest="thread_id", default=None)
    parser.add_argument("--payload", default=None)
    parser.add_argument("--task-id", dest="task_id", default=None)
    parser.add_argument("--dispatch-id", dest="dispatch_id", default=None)
    parser.add_argument("--outcome", default=None)
    parser.add_argument("--files-modified", dest="files_modified", default=None)
    parser.add_argument("--report-path", dest="report_path", default=None)
    parser.add_argument("--phase", default=None)
    parser.add_argument("--retry-request", dest="retry_request", default=None)
    parser.add_argument("--dispatch-capability", dest="dispatch_capability",
                        default=None)
    return parser.parse_args(argv)


def build_argv(ns, env):
    subject = _nonempty(ns.subject, "--subject")
    argv = ["orchestration", "send", "--subject", subject]
    mtype = ns.msg_type
    if mtype is not None:
        if mtype not in TYPES:
            raise Refused(f"--type must be one of {','.join(TYPES)}, "
                          f"got {mtype!r}")
        argv += ["--type", mtype]
    to = _nonempty(ns.to, "--to")
    if to is not None:
        if mtype in LIFECYCLE and to.startswith("@"):
            raise Refused(f"{mtype} messages belong to one exact Dispatch "
                          f"and cannot target a group address")
        argv += ["--to", to]
    outcome = ns.outcome
    if mtype != "worker_done" and outcome is not None:
        raise Refused("--outcome is only valid with --type worker_done")
    if mtype == "worker_done":
        if outcome not in OUTCOMES:
            raise Refused("--type worker_done requires --outcome "
                          f"succeeded|failed, got {outcome!r}")
        argv += ["--outcome", outcome]
    sender = resolve_from(ns.sender, env)
    if mtype in LIFECYCLE and sender is None:
        raise Refused(f"--type {mtype} needs a sender identity: pass --from "
                      f"with your own terminal's handle, or run inside a live "
                      f"Orca terminal with ORCA_TERMINAL_HANDLE set")
    if sender is not None:
        argv += ["--from", sender]
    for attr in PASSTHROUGH:
        if attr in ("to",):
            continue  # handled above (group rule runs first)
        value = _nonempty(getattr(ns, attr), flag_of(attr))
        if value is not None:
            argv += [flag_of(attr), value]
    if ns.payload is not None:
        try:
            json.loads(ns.payload)
        except (json.JSONDecodeError, TypeError):
            raise Refused("--payload must be JSON")
        argv += ["--payload", ns.payload]
    return argv


def run_orca(argv):
    return orca_cli.run_json(argv, timeout=180, error=Failed)


def format_send(result):
    if not isinstance(result, dict):
        raise Failed("send receipt is not an object")
    relay = result.get("relay") if isinstance(result.get("relay"),
                                              dict) else {}
    return [f"MESSAGE_ID={relay.get('messageId') or 'unknown'}"]


def main(argv=None, env=None):
    try:
        ns = parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return exc.code
    env = os.environ if env is None else env
    try:
        result = run_orca(build_argv(ns, env))
        print("\n".join(format_send(result)))
        return EXIT_OK
    except Refused as exc:
        print(f"send_msg: REFUSED: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except Failed as exc:
        print(f"send_msg: FAILED: {exc}", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
