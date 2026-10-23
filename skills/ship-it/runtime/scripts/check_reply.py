#!/usr/bin/env python3
"""check_reply.py — fail-closed orchestration check / reply invoker (S3).

Upstream argv (pinned specs/orchestration.ts, handlers/orchestration/
message-check-handler.ts):

* ``check [--terminal …] [--run …] [--ack …] [--unread|--peek|--all] [--types …]
  [--format] [--wait] [--timeout-ms …] [--retry-request …]`` — at most ONE read
  mode (the handler refuses more: older runtimes strip unknown peek and a
  --unread --peek combo would mark-read destructively).
* ``reply --id … --body … [--run …] [--from …] [--retry-request …]``.

--types members come from the orchestration message keyset (send spec note);
--timeout-ms is a positive int. --from defaults to ORCA_TERMINAL_HANDLE, and an
explicit --from that disagrees with it is refused — naming the sender is an
identity claim, and a wrong one speaks as a sibling (terminal-identity.ts).

A clean receipt is the verdict: --wait timing out (timedOut) is exit 0 with
TIMED_OUT=yes, not a failure. Argv is a list, never a shell string.

Exit: 0 checked/replied · 1 runtime/refusal/receipt failure · 2 usage.
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

TYPES = ("status", "dispatch", "worker_done", "merge_ready", "escalation",
         "handoff", "decision_gate", "question", "heartbeat")
MAX_SAFE_INT = 9007199254740991


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


def _positive_int(raw, flag):
    if not isinstance(raw, str) or not raw.isdigit():
        raise Refused(f"{flag} must be a positive integer, got {raw!r}")
    value = int(raw)
    if value < 1 or value > MAX_SAFE_INT:
        raise Refused(f"{flag} must be a positive integer, got {raw!r}")
    return raw


def resolve_from(explicit, env=None):
    """--from wins; else ORCA_TERMINAL_HANDLE; a disagreement is refused."""
    env = os.environ if env is None else env
    ambient = env.get("ORCA_TERMINAL_HANDLE", "")
    if explicit is not None:
        _nonempty(explicit, "--from")
        if ambient and explicit != ambient:
            raise Refused(f"--from '{explicit}' disagrees with "
                          f"ORCA_TERMINAL_HANDLE='{ambient}' — passing another "
                          f"pane's handle would act on its mailbox")
        return explicit
    return ambient or None


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="check_reply.py",
        description="Fail-closed orchestration check / reply invoker.")
    subs = parser.add_subparsers(dest="command", required=True)
    check = subs.add_parser("check", help="check a terminal's messages")
    check.add_argument("--terminal", default=None)
    check.add_argument("--run", default=None)
    check.add_argument("--ack", default=None)
    check.add_argument("--unread", action="store_true")
    check.add_argument("--peek", action="store_true")
    check.add_argument("--all", dest="all_msgs", action="store_true")
    check.add_argument("--types", default=None)
    check.add_argument("--format", action="store_true")
    check.add_argument("--wait", action="store_true")
    check.add_argument("--timeout-ms", default=None)
    check.add_argument("--retry-request", default=None)
    reply = subs.add_parser("reply", help="reply to one message")
    reply.add_argument("--id", dest="msg_id", required=True)
    reply.add_argument("--body", required=True)
    reply.add_argument("--run", default=None)
    reply.add_argument("--from", dest="sender", default=None)
    reply.add_argument("--retry-request", default=None)
    return parser.parse_args(argv)


def build_check_argv(ns):
    modes = [m for m, on in (("--unread", ns.unread), ("--peek", ns.peek),
                             ("--all", ns.all_msgs)) if on]
    if len(modes) > 1:
        raise Refused("choose at most one message read mode: "
                      "--unread, --peek, or --all")
    argv = ["orchestration", "check"]
    if _nonempty(ns.terminal, "--terminal") is not None:
        argv += ["--terminal", ns.terminal]
    if _nonempty(ns.run, "--run") is not None:
        argv += ["--run", ns.run]
    if _nonempty(ns.ack, "--ack") is not None:
        argv += ["--ack", ns.ack]
    argv += modes
    if ns.types is not None:
        members = ns.types.split(",")
        unknown = [m for m in members if m not in TYPES]
        if unknown or not members or any(not m for m in members):
            raise Refused(f"--types members must be in {','.join(TYPES)}, "
                          f"got {ns.types!r}")
        argv += ["--types", ns.types]
    if ns.format:
        argv += ["--format"]
    if ns.wait:
        argv += ["--wait"]
    if ns.timeout_ms is not None:
        argv += ["--timeout-ms", _positive_int(ns.timeout_ms, "--timeout-ms")]
    if _nonempty(ns.retry_request, "--retry-request") is not None:
        argv += ["--retry-request", ns.retry_request]
    return argv


def build_reply_argv(ns, env=None):
    msg_id = _nonempty(ns.msg_id, "--id")
    body = _nonempty(ns.body, "--body")
    argv = ["orchestration", "reply", "--id", msg_id, "--body", body]
    if _nonempty(ns.run, "--run") is not None:
        argv += ["--run", ns.run]
    sender = resolve_from(ns.sender, env)
    if sender is not None:
        argv += ["--from", sender]
    if _nonempty(ns.retry_request, "--retry-request") is not None:
        argv += ["--retry-request", ns.retry_request]
    return argv


def run_orca(argv):
    return orca_cli.run_json(argv, timeout=300, error=Failed, nonzero="no-receipt")


BODY_LIMIT = 2000


def _bounded(text, limit=BODY_LIMIT):
    text = text if isinstance(text, str) else ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[truncated {len(text) - limit} chars]"


def format_messages(messages):
    """One block per message; returns (lines, skipped_non_dicts)."""
    lines, skipped = [], 0
    for m in messages:
        if not isinstance(m, dict):
            skipped += 1
            continue
        lines.append(f"--- {_visible(m.get('id', '?'))} "
                     f"({_visible(m.get('type', '?'))}) "
                     f"from {_visible(m.get('from_handle', '?'))}")
        lines.append(f"SUBJ: {_visible(m.get('subject', '?'))}")
        lines.append(_bounded(_visible(m.get("body", ""))))
    return lines, skipped


def main(argv=None, env=None):
    try:
        ns = parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return exc.code
    try:
        if ns.command == "check":
            result = run_orca(build_check_argv(ns))
            messages = result.get("messages")
            count = result.get("count")
            if not isinstance(messages, list) or not isinstance(count, int):
                raise Failed("check receipt names no messages/count")
            delivery = result.get("deliveryId") or "none"
            timed_out = "yes" if result.get("timedOut") is True else "no"
            print(f"COUNT={count} DELIVERY={delivery} TIMED_OUT={timed_out}")
            body, skipped = format_messages(messages)
            for line in body:
                print(line)
            if skipped:
                print(f"check_reply: WARN: skipped {skipped} malformed "
                      f"message(s)", file=sys.stderr)
        else:
            result = run_orca(build_reply_argv(ns, env))
            reported = result.get("messageId") or result.get("id") or "unknown"
            print(f"REPLIED={reported} FOR={ns.msg_id}")
        return EXIT_OK
    except Refused as exc:
        print(f"check_reply: REFUSED: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except Failed as exc:
        print(f"check_reply: FAILED: {exc}", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
