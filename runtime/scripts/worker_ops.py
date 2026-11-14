#!/usr/bin/env python3
"""worker_ops.py — fail-closed worker lifecycle verbs (S5/S6/S7/S8/S21).

Upstream argv (pinned specs/orchestration-worker-specs.ts +
handlers/orchestration/worker-*.ts):

* ``show --dispatch …`` — minimal consumption of the fleet verdict:
  projection.nextAction.argv beside liveness, and observation.agentWait with
  absent-vs-null semantics (absent = never evaluated, never "not waiting").
* ``read --dispatch … [--source auto|transcript|terminal] [--cursor …] [--limit …]``
  — --source transcript CERTIFIES transcript evidence: a receipt whose
  effective source is not transcript is an evidence failure (exit 1), because
  auto falls back to labeled terminal output and the label is not the source.
* ``stop|abandon --dispatch … [--retry-request …]`` — scripted fencing: the
  receipt state is printed and stop_unknown is a failure, never a claim.
* ``release|retain --dispatch … [--retry-request …]`` — reclaim: release_unknown
  is the only failing state (retained/pending/already-released are settled
  answers, mirroring the handler).
* ``list [--run …] [--terminal-state …] [--include-remote] [--cursor …]
  [--limit 1-100]`` — watchdog enumeration: machine-readable ROWS/SCOPE lines,
  newest first, with the opaque page cursor passed back unchanged.

Validation refuses with exit 2 before any orca call; argv is a list, never a
shell string. Live worker behavior is PARKED (needs-human: run each verb
against a live dispatch and compare STATE/SOURCE lines to worker-show).

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
from pm import _indent_continuations, _off_column_0, _visible
from pm import _visible_line as _line

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_REFUSED = 2

SOURCES = ("auto", "transcript", "terminal")
LIST_STATES = ("active", "reclaimable", "retained", "release_pending",
               "release_unknown", "released")
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


def _required(value, flag):
    if not isinstance(value, str) or not value:
        raise Refused(f"{flag} needs a non-empty value")
    return value


def _positive_int(raw, flag, upper=MAX_SAFE_INT):
    if not isinstance(raw, str) or not raw.isdigit():
        raise Refused(f"{flag} must be a positive integer, got {raw!r}")
    value = int(raw)
    if value < 1 or value > upper:
        if upper == MAX_SAFE_INT:
            raise Refused(f"{flag} must be a positive integer, got {raw!r}")
        raise Refused(f"{flag} must be 1-{upper}, got {raw!r}")
    return raw


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="worker_ops.py",
        description="Fail-closed worker lifecycle verbs.")
    subs = parser.add_subparsers(dest="command", required=True)
    dispatch = argparse.ArgumentParser(add_help=False)
    dispatch.add_argument("--dispatch", required=True, help="the dispatch id (worker-list ROWS, spawn receipt)")
    retry = argparse.ArgumentParser(add_help=False)
    retry.add_argument("--retry-request", default=None,
                       help="idempotency key: resend the same value to retry one request safely")

    subs.add_parser("show", parents=[dispatch],
                    help="inspect one dispatch (verdict + wait + next action)")
    read = subs.add_parser("read", parents=[dispatch],
                           help="read bounded worker output")
    read.add_argument("--source", default="auto", help="auto | transcript | terminal; transcript "
                      "CERTIFIES: a receipt from any other source is an evidence failure (exit 1)")
    read.add_argument("--cursor", default=None, help="opaque page cursor from the previous read, passed back unchanged")
    read.add_argument("--limit", default=None, help="max entries, 1-100 (default: the host's)")
    for verb in ("stop", "abandon", "release", "retain"):
        subs.add_parser(verb, parents=[dispatch, retry],
                        help=f"worker-{verb} one dispatch")
    wlist = subs.add_parser("list", help="enumerate worker terminal accounting")
    wlist.add_argument("--run", default=None, help="only this Run's workers")
    wlist.add_argument("--terminal-state", default=None,
                       help="filter: " + " | ".join(LIST_STATES))
    wlist.add_argument("--include-remote", action="store_true",
                       help="read remote workers too; without it they render unverifiable")
    wlist.add_argument("--cursor", default=None, help="opaque page cursor from the previous list, passed back unchanged")
    wlist.add_argument("--limit", default=None, help="rows per page, a positive integer")
    return parser.parse_args(argv)


def build_argv(ns):
    cmd = ns.command
    if cmd == "list":
        argv = ["orchestration", "worker-list"]
        if _nonempty(ns.run, "--run") is not None:
            argv += ["--run", ns.run]
        if ns.terminal_state is not None:
            if ns.terminal_state not in LIST_STATES:
                raise Refused("--terminal-state must be one of "
                              f"{','.join(LIST_STATES)}, "
                              f"got {ns.terminal_state!r}")
            argv += ["--terminal-state", ns.terminal_state]
        if ns.include_remote:
            argv += ["--include-remote"]
        if _nonempty(ns.cursor, "--cursor") is not None:
            argv += ["--cursor", ns.cursor]
        if ns.limit is not None:
            argv += ["--limit", _positive_int(ns.limit, "--limit", 100)]
        return argv
    dispatch = _required(ns.dispatch, "--dispatch")
    if cmd == "show":
        return ["orchestration", "worker-show", "--dispatch", dispatch]
    if cmd == "read":
        if ns.source not in SOURCES:
            raise Refused(f"--source must be one of {','.join(SOURCES)}, "
                          f"got {ns.source!r}")
        argv = ["orchestration", "worker-read", "--dispatch", dispatch,
               "--source", ns.source]
        if _nonempty(ns.cursor, "--cursor") is not None:
            argv += ["--cursor", ns.cursor]
        if ns.limit is not None:
            argv += ["--limit", _positive_int(ns.limit, "--limit")]
        return argv
    argv = [f"orchestration", f"worker-{cmd}", "--dispatch", dispatch]
    if _nonempty(ns.retry_request, "--retry-request") is not None:
        argv += ["--retry-request", ns.retry_request]
    return argv


def format_show(result):
    """Minimal worker-show consumption: verdict + wait + next action."""
    if not isinstance(result, dict):
        raise Failed("worker-show receipt is not an object")
    dispatch = result.get("dispatch") or {}
    worker = result.get("worker") or {}
    lines = [f"DISPATCH={_line(dispatch.get('id') or 'unknown')}",
             f"STATE={_line(worker.get('state') or 'unknown')}",
             f"STAGE={_line(worker.get('stage') or 'unknown')}"]
    projection = result.get("projection")
    if isinstance(projection, dict):
        liveness = projection.get("liveness") or {}
        nxt = projection.get("nextAction") or {}
        argv = nxt.get("argv")
        lines.append(f"PROJECTION_VERDICT={_line(liveness.get('verdict') or 'unknown')}")
        lines.append("NEXT_ACTION=" + (" ".join(_line(a) for a in argv) if argv else "none"))
    else:
        lines += ["PROJECTION_VERDICT=absent", "NEXT_ACTION=absent"]
    observation = result.get("observation")
    # Absent observation (or absent key) = never evaluated = unknown; an
    # evaluated null = none. Mirrors the handler's three-way print.
    if not isinstance(observation, dict) or "agentWait" not in observation:
        lines.append("AGENT_WAIT=unknown")
    elif observation["agentWait"]:
        wait = observation["agentWait"]
        lines.append(f"AGENT_WAIT=waiting:{_line(wait.get('source') or '?')}:"
                     f"{_line(wait.get('reason') or 'interactive prompt')}")
    else:
        lines.append("AGENT_WAIT=none")
    return lines


BODY_LIMIT = 2000


def _bounded(text, limit=BODY_LIMIT):
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[truncated {len(text) - limit} chars]"


def format_read(result, want="auto"):
    """worker-read receipt; want=transcript certifies transcript evidence."""
    if not isinstance(result, dict):
        raise Failed("worker-read receipt is not an object")
    source = result.get("source")
    if source not in ("transcript", "terminal"):
        raise Failed("worker-read receipt names no effective source")
    if want == "transcript" and source != "transcript":
        raise Failed(f"--source transcript asked but the effective source is "
                     f"{source} (fallback "
                     f"{_line(result.get('fallbackReason') or 'unknown')}): refusing "
                     f"to certify terminal output as transcript evidence")
    cur = result.get("cursor")
    cur_text = "none" if cur is None or cur == "" else str(cur)
    page_obj = result.get("transcript") if isinstance(result.get("transcript"), dict) else None
    term_obj = result.get("terminal") if isinstance(result.get("terminal"), dict) else None
    trunc = bool(
        result.get("truncated")
        or (page_obj.get("truncated") or page_obj.get("limited") if page_obj else False)
        or (term_obj.get("truncated") if term_obj else False)
    )
    lines = [f"SOURCE={source}",
             f"CURSOR={_line(cur_text)}",
             f"TRUNCATED={'true' if trunc else 'false'}"]
    fallback = result.get("fallbackReason")
    if fallback:
        lines.append(f"FALLBACK={_line(fallback)}")
    if source == "transcript":
        page = result.get("transcript")
        messages = page.get("messages") if isinstance(page, dict) else None
        if not isinstance(messages, list):
            raise Failed("worker-read receipt names no transcript messages")
        for m in messages:
            if not isinstance(m, dict):
                lines.append("--- ? (?)")
                lines.append("(unreadable message skipped)")
                continue
            lines.append(f"--- {_line(m.get('id', '?'))} "
                         f"({_line(m.get('role', '?'))})")
            text = "\n".join(
                b.get("text", "") for b in m.get("blocks", [])
                if isinstance(b, dict) and b.get("type") == "text"
                and isinstance(b.get("text"), str))
            # A body keeps its lines, indented off column 0, so it cannot pass for a header.
            lines.append(_indent_continuations(_bounded(_visible(text if text else "(no text blocks)")),
                                               ("--- ",)))
    else:
        term = result.get("terminal")
        tail = term.get("tail") if isinstance(term, dict) else None
        if not isinstance(tail, list):
            raise Failed("worker-read receipt names no terminal tail")
        lines.append("--- tail")
        # One item, one line — and off column 0 when it starts like this receipt's own lines
        # (Codex round 2, swept: a pane printing `SOURCE=transcript` forged the field).
        lines.extend(_off_column_0(_line(line)) for line in tail)
    return lines


def format_fence(result, unknown):
    if not isinstance(result, dict):
        raise Failed("fencing receipt is not an object")
    state = result.get("state")
    if not state:
        raise Failed("fencing receipt names no state")
    if unknown is not None and state == unknown:
        raise Failed(f"the runtime reports {unknown}: unproven, inspect")
    return [f"DISPATCH={_line(result.get('dispatchId') or 'unknown')}",
            f"STATE={_line(state)}"]


def format_list(result):
    if not isinstance(result, dict):
        raise Failed("worker-list receipt is not an object")
    workers = result.get("workers")
    if not isinstance(workers, list):
        raise Failed("worker-list receipt names no workers")
    scope = result.get("scope") or {}
    page = result.get("page") or {}
    nxt = page.get("nextCursor")
    nxt_text = "none" if nxt is None or nxt == "" else str(nxt)
    lines = [f"ROWS={len(workers)}",
             f"SCOPE={_line(scope.get('source') or 'unknown')}",
             f"NEXT_CURSOR={_line(nxt_text)}"]
    for row in workers:
        if not isinstance(row, dict):
            continue
        lines.append(_off_column_0(f"{_line(row.get('dispatchId') or '?')} "
                                   f"{_line(row.get('taskId') or '?')} "
                                   f"{_line(row.get('terminalState') or '?')}"))
    return lines


# The handler exits 1 only on these; abandon names no failing state upstream
# (worker-terminal-handlers.ts prints whatever state the receipt carries).
UNKNOWN_BY_VERB = {"stop": "stop_unknown", "abandon": None,
                   "release": "release_unknown", "retain": "release_unknown"}


def run_orca(argv):
    return orca_cli.run_json(argv, timeout=120, error=Failed)


def main(argv=None):
    try:
        ns = parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return exc.code
    try:
        argv = build_argv(ns)
        result = run_orca(argv)
        if ns.command == "show":
            lines = format_show(result)
        elif ns.command == "read":
            lines = format_read(result, want=ns.source)
        elif ns.command == "list":
            lines = format_list(result)
        else:
            lines = format_fence(result, UNKNOWN_BY_VERB[ns.command])
        print("\n".join(lines))
        return EXIT_OK
    except Refused as exc:
        print(f"worker_ops: REFUSED: {_line(exc)}", file=sys.stderr)  # one inert line (Codex round 3)
        return EXIT_REFUSED
    except Failed as exc:
        print(f"worker_ops: FAILED: {_line(exc)}", file=sys.stderr)  # one inert line (Codex round 3)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
