#!/usr/bin/env python3
"""hitl_ask.py — durable `orchestration ask` for the hitl loop (S4).

Upstream argv (pinned specs/orchestration.ts, handlers/orchestration/
question-handler.ts, shared/orchestration-ask-timeout.ts):

* ``ask (--question <text> | --resume <message_id>) [--to <run:id>] [--run …]
  [--options <csv>] [--timeout-ms 1..1800000] [--from …] [--retry-request …]``
* exactly ONE of --question/--resume; --options only for a new question;
  the default budget is 600000ms and the clamp ceiling is 1800000ms.

The hitl template calls this as ``hitl_ask.py --question …`` when HITL_ASK=1
(HITL_ASK_HELPER overrides the helper path); every other knob has a flag and
an env fallback (HITL_RESUME, HITL_ASK_TIMEOUT_MS, HITL_ASK_OPTIONS,
HITL_ASK_TO, HITL_ASK_FROM, HITL_ASK_RUN), the flag winning. --from defaults
to ORCA_TERMINAL_HANDLE and refuses a disagreement (identity claim).

Answers print VERBATIM on stdout (the template captures them); timeouts exit
1 with HITL_RESUME=<id> and the rerun command on stderr, so a timed-out
question is resumed, never lost or re-asked. Argv is a list, never shell.

Exit: 0 answered · 1 timeout/runtime/receipt failure · 2 usage.
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

ASK_MAX_TIMEOUT_MS = 1800000


class Refused(Exception):
    """Usage/validation refusal: exit 2, nothing was invoked."""


class Failed(Exception):
    """Timeout, runtime refusal, or unreadable receipt: exit 1."""


def _nonempty(value, flag):
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise Refused(f"{flag} needs a non-empty value")
    return value


def _timeout(raw, flag="--timeout-ms"):
    if not isinstance(raw, str) or not raw.isdigit():
        raise Refused(f"{flag} must be 1-{ASK_MAX_TIMEOUT_MS}, got {raw!r}")
    value = int(raw)
    if value < 1 or value > ASK_MAX_TIMEOUT_MS:
        raise Refused(f"{flag} must be 1-{ASK_MAX_TIMEOUT_MS}, got {raw!r}")
    return raw


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="hitl_ask.py",
        description="Durable orchestration ask for the hitl loop.")
    parser.add_argument("--question", default=None)
    parser.add_argument("--resume", default=None)
    parser.add_argument("--to", default=None)
    parser.add_argument("--run", default=None)
    parser.add_argument("--options", default=None)
    parser.add_argument("--timeout-ms", default=None)
    parser.add_argument("--from", dest="sender", default=None)
    parser.add_argument("--retry-request", default=None)
    return parser.parse_args(argv)


def _pick(flag_value, env, name):
    """Flag wins; else the env fallback; else None."""
    if flag_value is not None:
        return flag_value
    return env.get(name) or None


def resolve_from(explicit, env):
    ambient = env.get("ORCA_TERMINAL_HANDLE", "")
    if explicit is not None:
        _nonempty(explicit, "--from")
        if ambient and explicit != ambient:
            raise Refused(f"--from '{explicit}' disagrees with "
                          f"ORCA_TERMINAL_HANDLE='{ambient}'")
        return explicit
    return ambient or None


def build_argv(ns, env):
    question = _nonempty(ns.question, "--question") \
        if ns.question is not None else None
    resume = _nonempty(_pick(ns.resume, env, "HITL_RESUME"), "--resume")
    if (question is None) == (resume is None):
        raise Refused("choose exactly one of --question or --resume "
                      "(HITL_RESUME counts as --resume)")
    argv = ["orchestration", "ask"]
    if question is not None:
        argv += ["--question", question]
    else:
        argv += ["--resume", resume]
    to = _nonempty(_pick(ns.to, env, "HITL_ASK_TO"), "--to")
    if to is not None:
        argv += ["--to", to]
    run = _nonempty(_pick(ns.run, env, "HITL_ASK_RUN"), "--run")
    if run is not None:
        argv += ["--run", run]
    options = _pick(ns.options, env, "HITL_ASK_OPTIONS")
    if options is not None:
        if question is None:
            raise Refused("--options is only valid when creating a new "
                          "question (not with --resume)")
        argv += ["--options", _nonempty(options, "--options")]
    timeout = _pick(ns.timeout_ms, env, "HITL_ASK_TIMEOUT_MS")
    if timeout is not None:
        argv += ["--timeout-ms", _timeout(timeout)]
    sender = resolve_from(_pick(ns.sender, env, "HITL_ASK_FROM"), env)
    if sender is not None:
        argv += ["--from", sender]
    retry = _nonempty(ns.retry_request, "--retry-request")
    if retry is not None:
        argv += ["--retry-request", retry]
    return argv


def run_orca(argv):
    return orca_cli.run_json(argv, timeout=1900, error=Failed, nonzero="ignore")


def main(argv=None, env=None):
    try:
        ns = parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return exc.code
    env = os.environ if env is None else env
    try:
        result = run_orca(build_argv(ns, env))
        answer = result.get("answer")
        if answer is not None:
            # Verbatim: the template captures this as the human's observation.
            print(answer if isinstance(answer, str) else json.dumps(answer))
            return EXIT_OK
        if result.get("timedOut") is True:
            mid = result.get("messageId") or "none"
            print(f"hitl_ask: HITL_ASK_TIMEOUT=yes HITL_RESUME={mid} — the "
                  f"question is still pending; resume it, do not re-ask it"
                  + (f": hitl_ask.py --resume {mid}" if mid != "none" else ""),
                  file=sys.stderr)
            return EXIT_FAILED
        raise Failed("ask answered null without timing out")
    except Refused as exc:
        print(f"hitl_ask: REFUSED: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except Failed as exc:
        print(f"hitl_ask: FAILED: {exc}", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
