#!/usr/bin/env sh
# deny-hook.sh — PreToolUse guard for read-write workers (Bash, Edit, Write).
#
# The Never list and the worktree boundary are doctrine (runtime/sandbox-policy.md,
# playbooks/risk-review.md). Doctrine sits above the model; this sits below it.
# A read-write worker runs with the host's permission prompts turned down, so the
# only thing between an improvised `rm -rf ~` and the disk is a hook.
#
# Reads the PreToolUse event JSON on stdin and writes ONE decision object on
# stdout in the shape the host honors:
#
#   {"hookSpecificOutput":{"hookEventName":"PreToolUse",
#     "permissionDecision":"deny|ask","permissionDecisionReason":"…"}}
#
# The nesting is load-bearing: a top-level permissionDecision is ignored, which
# is how a deny silently becomes an allow. Every field is JSON-encoded by
# python3 — never printf-interpolated, since a path carrying a quote produces
# malformed JSON and a malformed decision is no decision at all.
#
# POLARITY IS FAIL-CLOSED. Unparseable stdin, absent stdin, or no JSON parser on
# PATH all DENY. A boundary that fails open is not a boundary. Allow is the only
# decision this hook makes silently (exit 0, no output).
#
# HIGH tier (deny, never ask) for Bash. Every segment of a compound command is
# judged on its own, with env/VAR= prefixes stripped first, so a refused shape
# is refused wherever it sits rather than only in first position (#297). Still
# string matching: a segment whose target comes from a variable or a subshell is
# beyond it, and the Never list is the net for those. The refused shapes:
#   1. recursive delete whose every target is /, ~, $HOME or /*, or any
#      recursive delete carrying --no-preserve-root
#   2. force-push to the default branch, including the +main refspec form that
#      needs no flag at all — and deleting it outright, which carries no flag
#      either: `:main`, `git push -d`, `git push --delete` (#297). An effective
#      --force-with-lease exempts even the default branch (the lease pins the
#      remote head); the rule above reads unconditional, so say so here (#382).
#   3. `git push --force` / `-f` on any target without an effective lease — and
#      an effective explicit global force even with one, since Git documents
#      that it disables the --force-with-lease checks
#   4. `orca orchestration reset` — one command that discards a whole fleet's
#      dispatch state
#   5. an off-repo write (`gh pr|issue|release <write-verb>`, or `gh api` with
#      a write method/field) with no egress receipt immediately &&-preceding
#      it in the same command (`egress.py write … &&`). Judged in the payload
#      reader, the only place the joining operators survive: a receipt joined
#      by || or ; proves nothing (the send runs even when the receipt failed),
#      and one receipt covers exactly one send. The receipt is free and
#      mechanical, so there is no legitimate unreceipted form to ask about;
#      the denial names the governed path. Doctrine:
#      merge-serialization.md (#368), enforced here since #561. Plain
#      `git push` is out of scope (branch pushes are evidenced by PR head
#      SHAs, and the force rules above already govern their dangerous forms).
#   6. `git push --mirror` / `--prune` — they delete remote refs they never name.
#      Push long options are matched by git's unambiguous-prefix rule (--del).
# Git global options between `git` and the subcommand (-C, -c, --git-dir and
# kin) are stripped before any of this is judged — `git -C /x push --force` is
# the push it names (#297). A deletion that spares the default branch asks
# rather than denies: re-pushing the ref recovers it, and recovery is a human
# call — except under a redirected repository (-C, --git-dir, GIT_DIR=), where
# the default is resolved in the hook's own cwd and the ref cannot be shown
# recoverable, so any remote-ref deletion denies (#321 review).
# --force-with-lease is deliberately NOT matched as a force-push — but a
# lease does not pardon a deletion (judged first) or an effective explicit
# global force, which Git documents as disabling the lease checks.
#
# Never list (ask, per runtime/sandbox-policy.md): live-prod mutation, credential
# provisioning, destructive database or infrastructure teardown, unpinned remote
# code execution, publishing, and history-discarding local git. These are "ask"
# rather than "deny" because each has a legitimate form the human can authorize
# in the moment; the HIGH tier has none.
#
# Worktree boundary: when ORCA_UNIT_WORKTREE is set, a write outside it is DENIED.
# It covers the Edit/Write/MultiEdit file_path and NotebookEdit's notebook_path
# — the one write tool that spells the field differently (#297) — and, since a
# worker that can run a shell can spell the same write as `echo pwned >
# /etc/cron.d/x`, a Bash redirect or `tee` destination naming an ABSOLUTE path. Both go
# through one resolver, which follows the whole symlink chain, so an in-boundary
# name pointing out is judged by where it ends up however many links that takes.
#
# What the Bash half does NOT cover, and says so at the block itself: a relative
# target (the hook is not told the worker's cwd, and the segment before it may
# have been a `cd`, so judging one would be guessing), a `cp`/`mv`/`dd of=`
# destination, a path built from a variable, and an interpreter writing through
# its own API. The disposable sandbox is the boundary for those. The process's
# own standard streams and /dev/null are allowed by name — not by a /dev/ prefix,
# which would waive `> /dev/sda` along with them.
#
# A payload that parses but names no file_path (a non-file tool) is allowed. When
# the variable is unset the boundary is not enforced — an unset boundary is a
# configuration choice, and this hook says so rather than guessing one.
#
# Exit codes: always 0. The DECISION is the output, not the status — a non-zero
# exit from a hook is a hook error, which the host treats differently from a deny.
#
# How to wire — and what does NOT wire it. Nothing in this repository registers
# this hook, and this header used to say the dispatcher did (PR #277 review, P2).
# It cannot, on either lane spawn_worker.sh has: the supervised `worker-start`
# lane takes its launch args from the HOST's agentDefaultArgs, not from any
# command this repo builds, and an env var exported here does not cross the Orca
# daemon into the worker's process. A hook nobody registers is doctrine wearing a
# script's file extension, which is the thing this catalog exists to refuse.
#
# So you wire it, per host, and `deny-hook.sh --settings <worktree>` prints the
# exact block: a PreToolUse matcher over Bash|Edit|Write|NotebookEdit|MultiEdit
# plus ORCA_UNIT_WORKTREE=<the unit's own worktree>, which gives the freeze
# boundary for free. Merge it into the settings file the worker's agent reads.
#
# State the boundary honestly when you do: this runs INSIDE the worker's session,
# so it is defense-in-depth against an improvised command, the same advisory
# status the completion gate carries — not a soundness boundary against a worker
# that sets out to defeat it. The soundness boundary is the disposable sandbox
# for the danger lane.
set -eu

usage() {
  cat <<'USAGE'
deny-hook.sh — PreToolUse deny/ask guard for read-write workers.

Usage: deny-hook.sh [--help] [--settings <worktree>]
  Reads a PreToolUse event JSON object on stdin; writes a decision object on
  stdout when the action is denied or must be asked, nothing when it is allowed.
  --settings <worktree> prints the settings.json block that registers this hook
  for one worker, with the boundary path resolved. Nothing registers it for you.

Environment:
  ORCA_UNIT_WORKTREE  when set, a write outside this directory is denied: the
                      Edit/Write/MultiEdit file_path or NotebookEdit
                      notebook_path, and a Bash redirect or tee destination
                      naming an absolute path.

Exit: always 0 (the decision is the output). Fail-closed: unparseable input denies.
USAGE
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then usage; exit 0; fi

# --settings <worktree>: print the registration block, boundary resolved. This is
# the whole answer to "how do I turn this on" — there is no dispatcher step that
# does it for you, and saying so in a --help is cheaper than a doc nobody reads.
if [ "${1:-}" = "--settings" ]; then
  if [ -z "${2:-}" ]; then
    echo "deny-hook.sh --settings needs the worker's worktree path" >&2
    exit 2
  fi
  _wt=$(cd "$2" 2>/dev/null && pwd -P) || {
    echo "deny-hook.sh --settings: '$2' is not a directory" >&2
    exit 2
  }
  _self=$(cd "$(dirname -- "$0")" && pwd -P)/$(basename -- "$0")
  # Serialized, never interpolated: a POSIX path may legally contain a quote, a
  # backslash or a control character, and pasting one into a hand-built JSON
  # string yields either invalid JSON or a DIFFERENT path — a boundary silently
  # set somewhere else is worse than no boundary (PR #277 review, P2). Same
  # json.dumps the decision path below already uses.
  python3 -c 'import json,sys; print(json.dumps({
      "env": {"ORCA_UNIT_WORKTREE": sys.argv[1]},
      "hooks": {"PreToolUse": [{
          "matcher": "Bash|Edit|Write|NotebookEdit|MultiEdit",
          "hooks": [{"type": "command", "command": sys.argv[2]}],
      }]},
  }, indent=2))' "$_wt" "$_self" || {
    echo "deny-hook.sh --settings: python3 is required to emit valid JSON" >&2
    exit 2
  }
  exit 0
fi
if [ "${1:-}" = "--verify-settings" ]; then
  # Is the guard actually armed in the named settings file? Parse the real
  # registration (PreToolUse entry, tool matcher, command, boundary env),
  # then run the REGISTERED command — not this copy — under its configured
  # environment against three probes: a root delete and an
  # outside-the-boundary write must deny; a plain `ls` must not (a hook that
  # denies everything is armed like a brick). spawn_worker.sh calls this so
  # "wired" is verified, not assumed (#562).
  if [ -z "${2:-}" ]; then
    echo "deny-hook.sh --verify-settings needs the settings file path" >&2
    exit 2
  fi
  python3 - "$2" <<'PYEOF'
import json
import os
import re
import subprocess
import sys
from pathlib import Path

path = Path(sys.argv[1])


def refuse(reason):
    print(f"deny-hook: NOT ARMED in {path}: {reason}", file=sys.stderr)
    return 2


try:
    raw_text = path.read_text(encoding="utf-8")
except (OSError, UnicodeDecodeError) as err:
    sys.exit(refuse(f"settings unreadable ({err})"))

env = dict(os.environ)


def boundary_for(command):
    m = re.search(
        r"(?:OPEN_FLEET_UNIT_WORKTREE|ORCA_UNIT_WORKTREE)=(\"[^\"]*\"|'[^']*'|\S+)",
        command,
    )
    if m:
        return m.group(1).strip("\"'")
    return env.get("OPEN_FLEET_UNIT_WORKTREE") or env.get("ORCA_UNIT_WORKTREE") or ""


commands = {}
if path.suffix in (".ts", ".js"):
    if "deny-hook.sh" not in raw_text or (
        "tool.execute.before" not in raw_text and "PreToolUse" not in raw_text
    ):
        sys.exit(refuse("plugin does not wire deny-hook.sh on tool.execute.before"))
    m_cmd = re.search(
        r"((?:(?:OPEN_FLEET_UNIT_WORKTREE|ORCA_UNIT_WORKTREE)=\S+\s+)?(?:sh\s+)?[^\s\"'`]+deny-hook\.sh)",
        raw_text,
    )
    if not m_cmd:
        sys.exit(refuse("could not extract deny-hook.sh command from plugin"))
    cmd_str = m_cmd.group(1).strip("\"'`")
    m_wt = re.search(
        r"(?:OPEN_FLEET_UNIT_WORKTREE|ORCA_UNIT_WORKTREE)\s*[:=]\s*[\"']([^\"']+)[\"']",
        raw_text,
    )
    if m_wt and not boundary_for(cmd_str):
        env["ORCA_UNIT_WORKTREE"] = m_wt.group(1)
    commands = {"Bash": cmd_str, "Edit": cmd_str}
else:
    try:
        settings = json.loads(raw_text)
    except ValueError as err:
        sys.exit(refuse(f"settings unreadable ({err})"))
    if not isinstance(settings, dict):
        sys.exit(refuse("settings must be a JSON object"))

    def covers(matcher, tool):
        matcher = str(matcher)
        if matcher.strip() == "*":
            return True
        candidates = (
            ("Bash", "bash", "shell", "terminal", "exec_command")
            if tool == "Bash"
            else ("Edit", "edit", "Write", "write", "apply_patch", "file_editor", "replace", "write_file")
        )
        try:
            return any(re.fullmatch(matcher, cand) is not None for cand in candidates)
        except re.error:
            return False

    hooks_obj = settings.get("hooks") if isinstance(settings.get("hooks"), dict) else settings
    entries = (hooks_obj.get("PreToolUse") if isinstance(hooks_obj, dict) else None) or []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        hook_list = entry.get("hooks") if isinstance(entry.get("hooks"), list) else [entry]
        for hook in hook_list:
            if not (isinstance(hook, dict)
                    and hook.get("type", "command") == "command"
                    and "deny-hook.sh" in str(hook.get("command", ""))):
                continue
            matcher_val = entry.get("matcher", "")
            for tool in ("Bash", "Edit"):
                if tool not in commands and covers(matcher_val, tool):
                    commands[tool] = str(hook["command"])
    missing = [tool for tool in ("Bash", "Edit") if tool not in commands]
    if missing:
        sys.exit(refuse(
            "no PreToolUse registration of deny-hook.sh covers "
            + " and ".join(missing)
            + " (a mention elsewhere in the file is not a registration)"))

    registered_env = settings.get("env") or {}
    if not isinstance(registered_env, dict):
        sys.exit(refuse("settings env is not an object"))
    env.update({str(k): str(v) for k, v in registered_env.items()})

for tool, command in sorted(commands.items()):
    boundary = boundary_for(command)
    if not boundary or not Path(boundary).is_dir():
        sys.exit(refuse(
            f"no usable ORCA_UNIT_WORKTREE for the {tool} registration "
            "(settings env or an inline assignment) — the worktree boundary "
            "the registration exists to enforce is off"))


def probe(command, tool_name, tool_input):
    payload = json.dumps({"hook_event_name": "PreToolUse",
                          "tool_name": tool_name, "tool_input": tool_input})
    r = subprocess.run(["sh", "-c", command], input=payload,
                       capture_output=True, text=True, env=env,
                       cwd=boundary_for(command), timeout=60)
    if not r.stdout.strip():
        return "allow" if r.returncode == 0 else "deny"
    try:
        return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"]
    except (ValueError, KeyError, TypeError):
        return f"unparsable:{r.stdout[:60]!r}"


if probe(commands["Bash"], "Bash", {"command": "rm -rf /"}) != "deny":
    sys.exit(refuse("registered command did not deny 'rm -rf /'"))
bash_outside = str(Path(boundary_for(commands["Bash"])).parent
                   / "outside-the-boundary.probe")
if probe(commands["Bash"], "Bash",
         {"command": f"echo x > {bash_outside}"}) != "deny":
    sys.exit(refuse(
        "registered Bash command did not deny a shell redirect outside "
        "its configured ORCA_UNIT_WORKTREE — the write boundary is not live"))
outside = str(Path(boundary_for(commands["Edit"])).parent
              / "outside-the-boundary.probe")
if probe(commands["Edit"], "Edit", {"file_path": outside}) != "deny":
    sys.exit(refuse(
        "registered command did not deny a write outside its configured "
        "ORCA_UNIT_WORKTREE — registered, but the boundary is not live"))
if probe(commands["Bash"], "Bash", {"command": "ls"}) == "deny":
    sys.exit(refuse("registered command denies even a plain 'ls' — armed "
                    "like a brick, not a guard"))
print(f"deny-hook: armed in {path} ({commands['Bash']})")
PYEOF
  exit $?
fi
if [ $# -gt 0 ]; then
  printf 'deny-hook.sh: unexpected argument: %s\n' "$1" >&2
  usage >&2
  exit 2
fi

UNIT_WORKTREE=${OPEN_FLEET_UNIT_WORKTREE:-${ORCA_UNIT_WORKTREE:-}}
if [ -n "${OPEN_FLEET_EGRESS_LEDGER:-}" ] && [ -z "${ORCA_EGRESS_LEDGER:-}" ]; then
  export ORCA_EGRESS_LEDGER="$OPEN_FLEET_EGRESS_LEDGER"
fi

# One decision object, with the reason JSON-encoded via argv (never interpolated).
decide() {
  _dec=$1
  _reason=$2
  if [ "$_dec" = "ask" ]; then
    if [ "${CODEX_CI:-0}" != "0" ] && [ -n "${CODEX_CI:-}" ]; then _dec="deny"; fi
    if [ "${CODEX_SANDBOX:-0}" != "0" ] && [ -n "${CODEX_SANDBOX:-}" ]; then _dec="deny"; fi
    if [ "${OPEN_FLEET_HEADLESS_STRICT:-0}" != "0" ] && [ -n "${OPEN_FLEET_HEADLESS_STRICT:-}" ]; then _dec="deny"; fi
    if [ "${ORCA_HOOK_STRICT_EXIT:-0}" != "0" ] && [ -n "${ORCA_HOOK_STRICT_EXIT:-}" ]; then _dec="deny"; fi
  fi
  _top_dec=$_dec
  if [ "$_dec" = "deny" ] && [ -n "${GOOSE_MODE:-}" ] && [ "${GOOSE_MODE:-0}" != "0" ]; then
    _top_dec="block"
  fi
  python3 -c 'import json,sys; print(json.dumps({"decision":sys.argv[3],"reason":sys.argv[2],"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":sys.argv[1],"permissionDecisionReason":sys.argv[2]}}))' "$_dec" "$_reason" "$_top_dec" 2>/dev/null || \
    printf '{"decision":"%s","reason":"denied by policy","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"%s","permissionDecisionReason":"denied by policy"}}\n' "$_top_dec" "$_dec"
  if [ "$_dec" = "deny" ]; then
    if [ -n "${JCODE_HOOK_TOOL_NAME:-}" ] || [ "${ORCA_HOOK_STRICT_EXIT:-0}" = "1" ] || [ "${OPEN_FLEET_HOOK_EXIT2:-0}" = "1" ]; then
      printf '%s\n' "$_reason" >&2
      exit 2
    fi
  fi
}

PAYLOAD=$(cat 2>/dev/null || true)

# Extract tool_name, tool_input.command and tool_input.file_path as three lines.
# A parse failure (or no python3) exits non-zero here and DENIES below.
FIELDS=$(printf '%s' "$PAYLOAD" | python3 -c 'import json,os,re,shlex,sys
d = json.loads(sys.stdin.read())
if not isinstance(d, dict):
    raise SystemExit(1)
raw_tool = d.get("tool_name") or d.get("tool") or os.environ.get("JCODE_HOOK_TOOL_NAME") or ""
ti = d.get("tool_input")
if isinstance(ti, str):
    try:
        parsed_ti = json.loads(ti)
        ti = parsed_ti if isinstance(parsed_ti, dict) else {"patch": ti, "input": ti}
    except Exception:
        ti = {"patch": ti, "input": ti}
elif not isinstance(ti, dict):
    if "tool_name" not in d and "tool" not in d and os.environ.get("JCODE_HOOK_TOOL_NAME"):
        ti = d
    elif isinstance(d.get("input"), dict):
        ti = d.get("input")
    else:
        ti = {}
def s(v):
    return v.replace("\n", " ") if isinstance(v, str) else ""
def r(v):
    # The command as the shell sees it, newlines intact. `segments` needs them:
    # a newline separates two commands, and it is also the only thing that ENDS
    # a # comment. Pre-mapping it to `;` erased that boundary, so a comment had
    # no end to find (PR #325 review, P1).
    return v.replace("\r", "\n") if isinstance(v, str) else ""
def c(v):
    # The as-written Never-list pass reads this off a single line of the field
    # protocol, which cannot carry an embedded newline. In a shell a newline
    # SEPARATES two commands exactly as `;` does; flattening it to a space glued
    # them into one nonsense segment that matched nothing, so a two-line payload
    # walked straight past the HIGH tier (#297). Map it to the separator it
    # actually is. The splitter reads `r` instead and needs no such compromise.
    return r(v).replace("\n", " ; ")


# NOTE: this whole program is the argument of a single-quoted sh string, so it may not contain
# an apostrophe anywhere — not in code, not in a comment. SQ/DQ are how a quote character is
# named here. A stray one ends the sh string and the payload reader dies, which fails closed and
# refuses every tool call.
SQ = chr(39)
DQ = chr(34)
# What a shell splits words on. NOT str.isspace(): Python calls NBSP and friends
# whitespace, a shell does not, and a word boundary the shell never saw is one this
# parser must not invent either (PR #325 review, P1).
BLANKS = chr(32) + chr(9)


def _norm_join(sep_chars):
    # The join before a segment, reduced to what rule 5 (egress receipts)
    # needs: "&&" runs the next command only if the previous one succeeded;
    # every other separator run (||, ;, |, &, newline, mixes) runs it
    # regardless, so a receipt joined that way proves nothing about the send.
    core = sep_chars.replace(chr(10), "")
    if not core:
        return "start"
    return "&&" if core == "&&" else "seq"


def _split(cmd):
    """Split a shell line into (join, segment) pairs, QUOTE-AWARE.

    join is the operator run before the segment: "start" for the first,
    "&&" when the shell runs it only on the previous success, "seq" for
    every other separator. segments() below is this walk with the joins
    dropped, byte-identical to what it always returned.

    This was a sed pass over the raw text, and a separator inside a quoted string split there
    too. The header called that safe, reasoning that splitting only ever makes MORE segments and
    every segment is judged. That reasoning was wrong: the split leaves the rest of the quoted
    value glued to the FRONT of the next segment, and every HIGH-tier rule is anchored at ^.
    X=<dq>a&b<dq> git push --force origin main became `b<dq> git push --force origin main`, which
    begins with neither git nor anything else the tier knows, and was allowed (PR #308 review,
    P1). Same for ; and | inside a value.

    Quoting is parsed here rather than in sh because a POSIX shell cannot do it without eval, and
    python3 is already load-bearing above: no parser, no decision, and this whole script denies.
    Redirect operators are consumed whole so their | and & are never read as separators.

    A # that OPENS A WORD opens a comment, which runs to the end of its line. Nothing recognized
    them, so `git status # dont modify anything` was tokenized as shell: the apostrophe in the
    comment opened a quote that never closed, shlex raised, and the payload reader hard-DENIED a
    read-only command (PR #325 review, P1). Word position is what decides it, exactly as in a
    shell: after a redirect operator `>#f` names a file, and un-seeing that word would lose a
    write target, which is the one direction this parser must never fail in.
    """
    segs, cur = [], []
    cur_join, sep_run = "start", ""
    i, n, quote = 0, len(cmd), ""
    word_start = True
    while i < n:
        ch = cmd[i]
        # A backslash-newline is a line continuation. The shell REMOVES it -- inside double
        # quotes as well as outside -- and the text on either side is one word. Keeping it opened
        # two holes (PR #325 review, P1): the newline rode into a word and broke the one-line
        # record protocol below, forging a C record that reset tee enforcement so the write
        # target after it went unchecked; and counting it as a word boundary made
        # echo a\<newline>#b a comment, swallowing the command after it. Removing it here leaves
        # word_start untouched, which is the point: a continuation neither opens nor closes a
        # word. Single quotes take no escapes, so it is literal there.
        if ch == "\\" and quote != SQ and i + 1 < n and cmd[i + 1] == "\n":
            i += 2
            continue
        if quote:
            # A literal newline inside a quoted word is data, not a boundary. It cannot travel on
            # the one-line record protocol below, so it rides as a space: a value, still one word.
            sep_run = ""
            cur.append(" " if ch == "\n" else ch)
            if ch == "\\" and quote == DQ and i + 1 < n:
                cur.append(cmd[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
            word_start = False
            i += 1
            continue
        if ch == SQ or ch == DQ:
            quote = ch
            sep_run = ""
            cur.append(ch)
            word_start = False
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            sep_run = ""
            cur.append(ch)
            cur.append(cmd[i + 1])
            word_start = False   # an escaped character is a word character
            i += 2
            continue
        if ch == "#" and word_start:
            while i < n and cmd[i] != "\n":
                i += 1
            continue   # the newline itself falls through to the separator case below
        if ch in "<>" or (ch == "&" and i + 1 < n and cmd[i + 1] == ">"):
            j = i + 1
            while j < n and cmd[j] in "<>|&":
                j += 1
            sep_run = ""
            cur.append(cmd[i:j])
            word_start = False
            i = j
            continue
        # && and || need no case of their own: the second character lands on a separator too, and
        # the empty segment between them is dropped below. Measured, not assumed — a mutant
        # removing a special case for them changed no decision, so there is no special case.
        # A newline is a separator too, and the one that ends a comment.
        if ch in ";|&\n":
            if cur:
                segs.append((cur_join, "".join(cur)))
                cur = []
            sep_run += ch
            cur_join = _norm_join(sep_run)
            word_start = True
            i += 1
            continue
        # Blanks BETWEEN segments (after an operator, before the next word —
        # or before the newline that ends a trailing comment) must not erase
        # the pending join: `receipt && # note` <newline> `send` is still
        # &&-joined (PR #567 review, P2).
        if ch not in BLANKS or "".join(cur).strip():
            sep_run = ""
        cur.append(ch)
        word_start = ch in BLANKS
        i += 1
    if cur:
        segs.append((cur_join, "".join(cur)))
    return [(join, seg) for join, seg in segs if seg.strip()]


def segments(cmd):
    return [seg for _join, seg in _split(cmd)]


def policy_word(word):
    # This is an internal comparison word, NEVER shell code. Encode whitespace,
    # quotes and escapes so shell word splitting cannot turn one operand into
    # flags/refspecs. Literal command/option words lose their shell quoting.
    return "".join("\\%03o" % ord(ch) if ch.isspace() or ch in (SQ, DQ, "\\")
                   else ch for ch in word) or "\\000"


def shell_tokens(seg):
    # Keep operator identity BEFORE quote removal: quoted/escaped > is data.
    # A descriptor is optional and may have several digits. After an operator,
    # however, the next word is its target: in 10>&1>file, 1 is not another fd.
    ops = r"(?:&>>|&>|>>|>\||>&|<>|<<<|<<-|<<|<&|>|<)"
    i, target = 0, False
    while i < len(seg):
        if seg[i] in BLANKS:
            i += 1
            continue
        op = re.match(ops if target else r"[0-9]*" + ops, seg[i:])
        if op:
            yield "redirect", op[0].lstrip("0123456789")
            i += len(op[0])
            target = True
            continue
        start, quote = i, ""
        while i < len(seg):
            ch = seg[i]
            if ch == "\\" and quote != SQ:
                i += 2
                continue
            if quote:
                if ch == quote:
                    quote = ""
            elif ch in (SQ, DQ):
                quote = ch
            elif ch in BLANKS or ch in "<>&":
                break
            i += 1
        if i == start:
            raise ValueError("unexpected operator")
        yield "word", shlex.split(seg[start:i])[0]
        target = False


def record(kind, value):
    # One record, one line. A value carrying a newline forges the NEXT record, and a forged
    # C line resets tee enforcement so the write target after it is never checked (PR #325
    # review, P1). segments() makes this unreachable -- an unquoted newline separates, a
    # quoted one rides as a space, a continuation is removed -- so anything arriving here
    # means that reasoning is wrong somewhere, and dying is the fail-closed answer.
    if "\n" in value or "\r" in value:
        raise ValueError("a record value cannot contain a newline")
    print(kind + " " + value)


if raw_tool in ("Bash", "bash", "shell", "terminal", "exec_command"):
    norm_tool = "Bash"
elif raw_tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
    norm_tool = raw_tool
elif raw_tool in ("write", "edit", "multiedit", "replace", "write_file", "apply_patch", "patch"):
    norm_tool = "Edit"
elif raw_tool == "file_editor":
    fe_cmd = str(ti.get("command") or "").strip().lower()
    norm_tool = "Read" if fe_cmd == "view" else "Edit"
else:
    norm_tool = str(raw_tool)

cmd_val = ti.get("command") if (norm_tool == "Bash" and isinstance(ti.get("command"), str)) else (ti.get("cmd") if isinstance(ti.get("cmd"), str) else (ti.get("command") if norm_tool == "Bash" else ""))
raw_command = r(cmd_val)
command = c(raw_command)

target_paths = []
for _k in ("file_path", "notebook_path", "path", "filePath"):
    _v = ti.get(_k)
    if isinstance(_v, str) and _v:
        target_paths.append(_v)
if isinstance(ti.get("edits"), list):
    for _ed in ti.get("edits"):
        if isinstance(_ed, dict):
            for _k in ("file_path", "path", "filePath"):
                _v = _ed.get(_k)
                if isinstance(_v, str) and _v:
                    target_paths.append(_v)
_patch_blobs = []
for _pk in ("patch", "diff"):
    if isinstance(ti.get(_pk), str):
        _patch_blobs.append(ti.get(_pk))
if raw_tool in ("apply_patch", "patch"):
    for _pk in ("input", "content", "command", "cmd"):
        if isinstance(ti.get(_pk), str):
            _patch_blobs.append(ti.get(_pk))
    if isinstance(d.get("patch"), str):
        _patch_blobs.append(d.get("patch"))
for _pv in _patch_blobs:
    for _pln in _pv.splitlines():
        _m = re.match(r"^\*\*\* (?:Add|Update|Delete) File:\s*(.+)$", _pln)
        if not _m:
            _m = re.match(r"^\*\*\* Move to:\s*(.+)$", _pln)
        if not _m:
            _m = re.match(r"^(?:\+\+\+|---) (?:[ab]/)?([^\t\r\n]+)", _pln)
        if _m:
            _cand = _m.group(1).strip()
            if _cand and _cand != "/dev/null":
                target_paths.append(_cand)
print(s(norm_tool))
print(command)
print(s(target_paths[0] if target_paths else ""))
for _extra_p in target_paths[1:]:
    record("F", s(_extra_p))
# Line 4 onward: C = comparison command, W = write target, A = literal argument,
# E = an off-repo write with no egress receipt arming it (rule 5, judged here
# because only this side of the protocol still knows the joining operators).
# Paths stay decoded on their own lines; comparison words cannot split operands.
SEND_VERBS = {"create", "merge", "comment", "review", "close", "reopen", "edit",
              "delete", "upload", "ready", "pin", "unpin", "lock", "unlock", "transfer"}


# Wrapper words strip_prefix peels on the shell side (env/sudo-style
# laundering). Rule 5 moved into this reader, so the peeling must come with
# it — `env gh issue close`, `command gh release create`, `sudo -n gh …`
# are the same sends (PR #567 review, P1). env/nice/time/nohup also peel
# their own option runs (`env -i gh …` is the canonical form).
_WRAPPERS = {"command", "builtin"}
_WRAPPER_OPERANDS = {
    # -S/--split-string is handled in _peel_wrapper, not here: its operand
    # IS the command, so treating it as a skippable operand would promote
    # the arguments of that command to the head (PR #567 review, P1).
    "env": {"-u", "--unset", "-a", "--argv0", "-C", "--chdir"},
    "nice": {"-n", "--adjustment"},
    "time": {"-o", "--output", "-f", "--format"},
    "nohup": set(),
}
_SUDO_OPERAND_FLAGS = ("-u", "-U", "-g", "-h", "-p", "-C", "-T", "-R", "-t")


def _split_env_string(text):
    # GNU env -S word splitting, to head-finding fidelity: blanks separate,
    # `\_` is a SEPARATOR (not a literal underscore), other `\x` is a literal
    # x, single/double quotes group (and vanish). A plain .split() kept
    # `ignore\_--version` as one word, hiding --version inside what read as
    # a -W value, so a version print armed a send (PR #567 review, P1).
    words, cur, quote = [], [], ""
    started = False  # a quote opens a word even if it adds no characters:
    # `""` is an empty argument env preserves and python consumes (P1).
    i = 0

    def flush():
        nonlocal cur, started
        if started:
            words.append("".join(cur))
            cur, started = [], False

    while i < len(text):
        ch = text[i]
        if quote:
            if ch == quote:
                quote = ""
            else:
                cur.append(ch)
            i += 1
            continue
        if ch in (SQ, DQ):
            quote = ch
            started = True
        elif ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "_":
                flush()
            else:
                cur.append(nxt)
                started = True
            i += 2
            continue
        elif ch in " \t":
            flush()
        else:
            cur.append(ch)
            started = True
        i += 1
    flush()
    return words


def _peel_wrapper(ws, operand_flags, is_env=False):
    # ws[0] is env/nice/time/nohup: peel it and its options. Help/version
    # means nothing runs — return the words as they stand.
    original = ws
    ws = ws[1:]
    while ws:
        word = ws[0]
        if word in ("-V", "--help", "--version"):
            return original
        if word == "--":
            return ws[1:]
        if is_env and word in ("-S", "--split-string") and len(ws) > 1:
            # The operand IS the command line env runs: its words take the
            # head, the words after it become their arguments.
            return _split_env_string(ws[1]) + ws[2:]
        if is_env and word.startswith("-S") and len(word) > 2:
            return _split_env_string(word[2:]) + ws[1:]
        if word in operand_flags and len(ws) > 1:
            ws = ws[2:]
        elif word.startswith("-"):
            ws = ws[1:]  # a lone "-" is env spelling of -i; no command is "-"
        else:
            return ws
    return ws


def _peel_sudo(ws):
    # ws[0] is sudo: peel it, stacked sudos, and the sudo option run —
    # the same shapes strip_prefix handles (`sudo -n`, `sudo --`,
    # `sudo -u root`, `sudo --user=root`). A help/version option stops the
    # peel cold: sudo prints and exits 0 running nothing, so the words keep
    # their sudo head and neither arm a receipt nor read as the send.
    original = ws
    ws = ws[1:]
    while ws:
        word = ws[0]
        if word in ("-V", "--help", "--version"):
            return original
        if word == "sudo":
            ws = ws[1:]
        elif word == "--":
            return ws[1:]
        elif word.startswith("--") and "=" in word:
            ws = ws[1:]
        elif word in _SUDO_OPERAND_FLAGS and len(ws) > 1:
            ws = ws[2:]
        elif word.startswith("-") and word != "-":
            ws = ws[1:]
        else:
            return ws
    return ws


def _plain_words(args, peel_bang=True):
    ws = list(args)
    while ws:
        # Group/subshell openers and negation name no command: `{ gh …; }`,
        # `(gh …)`, `! gh …` run the same command (PR #567 review, P1).
        # Peel the opener word, or the opener character glued to it. The
        # receipt check passes peel_bang=False: `!` inverts exit status, so
        # a negated writer that FAILS reads as success to `&&` — it proves
        # nothing was recorded and must never arm a send (P1).
        openers = ("{", "(", "!") if peel_bang else ("{", "(")
        if ws[0] in openers:
            ws = ws[1:]
        elif ws[0][:1] in openers and len(ws[0]) > 1:
            ws = [ws[0][1:]] + ws[1:]
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", ws[0], re.DOTALL):
            ws = ws[1:]
        elif ws[0] == "sudo":
            peeled = _peel_sudo(ws)
            if peeled == ws:
                return ws  # help/version stop: judge the words as they stand
            ws = peeled
        elif ws[0] in _WRAPPER_OPERANDS:
            peeled = _peel_wrapper(ws, _WRAPPER_OPERANDS[ws[0]],
                                   is_env=ws[0] == "env")
            if peeled == ws:
                return ws
            ws = peeled
        elif ws[0] in _WRAPPERS:
            ws = ws[1:]
        else:
            return ws
    return ws


def _is_receipt(args):
    # The receipt writer must be the command being run — egress.py as the
    # executable, or as the script a python invocation runs. Merely
    # MENTIONING it (`echo egress.py write`) records nothing and arms
    # nothing (PR #567 review, P1).
    ws = _plain_words(args, peel_bang=False)
    def is_egress(word):
        return word == "egress.py" or word.endswith("/egress.py")

    if len(ws) >= 2 and is_egress(ws[0]) and ws[1] == "write":
        return True
    # python3 [options] … egress.py write: versioned interpreters
    # (python3.12) and interpreter options before the script still run the
    # writer (PR #567 review, P2). The options are ALLOWLISTED to ones that
    # proceed to the script — --version/-h print and exit 0 without running
    # it, so skipping unknown dash-words would arm a send on a no-op (P1).
    if ws and re.fullmatch(r"python(3(\.\d+)?)?", ws[0].rsplit("/", 1)[-1]):
        i = 1
        while i < len(ws):
            word = ws[i]
            if word == "--":
                i += 1
                break
            if word in ("-W", "-X"):
                i += 2
            elif re.fullmatch(r"-[WX].+", word, re.DOTALL):
                i += 1
            elif re.fullmatch(r"-[uEIsSvqBObdi]+", word):
                i += 1
            else:
                break
        return i < len(ws) and not ws[i].startswith("-") \
            and i + 1 < len(ws) and is_egress(ws[i]) and ws[i + 1] == "write"
    return False


def _is_send(args):
    ws = _plain_words(args)
    if not ws or not (ws[0] == "gh" or ws[0].endswith("/gh")):
        return False
    rest = ws[1:]
    if len(rest) >= 2 and rest[0] in ("pr", "issue", "release"):
        return rest[1] in SEND_VERBS
    if rest and rest[0] == "api":
        method, fields, i = None, False, 1
        while i < len(rest):
            word = rest[i]
            if word in ("-X", "--method") and i + 1 < len(rest):
                method = rest[i + 1].upper()
                i += 2
                continue
            if word.startswith("--method="):
                method = word.split("=", 1)[1].upper()
            elif word.startswith("-X") and len(word) > 2:
                method = word[2:].upper()
            elif word in ("-f", "-F", "--field", "--raw-field", "--input") \
                    or word.startswith(("--field=", "--raw-field=", "--input=")) \
                    or (len(word) > 2 and word[:2] in ("-f", "-F")):
                # Attached short forms (-ftitle=x) supply fields too, and so
                # imply POST with no explicit method (PR #567 review, P1).
                fields = True
            i += 1
        # An explicit method wins: --method GET with -f filters is a read.
        # Fields imply POST only when no method was supplied (gh semantics).
        if method is not None:
            return method in ("POST", "PUT", "PATCH", "DELETE")
        return fields
    return False


_seg_args = []
for _join, seg in _split(raw_command):
    args, writes, pending = [], [], None
    for kind, value in shell_tokens(seg):
        if kind == "redirect":
            pending = value
        elif pending:
            if pending in (">", ">>", ">|", ">&", "&>", "&>>", "<>"):
                writes.append(value)
            pending = None
        else:
            args.append(value)
    _seg_args.append((_join, args))
    record("C", " ".join(policy_word(word) for word in args))
    for path in writes:
        record("W", path)
    for word in args:
        record("A", word)

_armed = False
for _join, _args in _seg_args:
    if _is_receipt(_args):
        _armed = True
        continue
    if _is_send(_args):
        if not (_armed and _join == "&&"):
            record("E", "unreceipted")
            break
        _armed = False  # one receipt covers exactly one send
        continue
    _armed = False  # any other segment consumes the arming
' 2>/dev/null) || {
  decide deny "deny-hook: the tool payload could not be parsed. Fail-closed: an unreadable payload is refused, never allowed."
  exit 0
}

# Rule 5 verdict, computed in the payload reader (the only place the joining
# operators survive): an E record means an off-repo write in this command has
# no egress receipt immediately &&-preceding it.
if printf '%s\n' "$FIELDS" | grep -q '^E '; then
  decide deny "deny-hook[HIGH]: off-repo write without its egress receipt. Precede the send in the same command — egress.py write … && <this gh command> — so what left the machine is on the hash-chained record (merge-serialization.md, #368). The receipt comes first: the send may be the last thing this process does. One receipt covers exactly one send, and only on the success path (&&)."
  exit 0
fi

# --- path resolution ---------------------------------------------------------
# The boundary check is a string prefix, so the path it compares has to be a
# REAL absolute path. It previously was not: when a write named a parent that
# did not exist yet, the fallback pasted the raw (un-normalized) parent onto
# $PWD, so `../outside/new/file` became `/worktree/../outside/new` — which
# prefix-matches `/worktree/` and was ALLOWED while the write landed outside
# (PR #277 review, P2).
#
# lexical_abs collapses `.` and `..` with no filesystem access, so it is safe on
# a tail that does not exist yet. resolve_dir resolves the deepest EXISTING
# ancestor physically first (that is what catches symlinks, which a lexical pass
# cannot), then collapses the remaining tail against it — components that do not
# exist cannot be symlinks, so collapsing them lexically is sound.
lexical_abs() {
  _p=$1
  case "$_p" in /*) : ;; *) _p="$(pwd -P)/$_p" ;; esac
  _out=""
  _oldifs=$IFS
  IFS='/'
  for _seg in $_p; do
    case "$_seg" in
      ''|.) : ;;
      ..) _out=${_out%/*} ;;
      *) _out="$_out/$_seg" ;;
    esac
  done
  IFS=$_oldifs
  printf '%s' "${_out:-/}"
}

resolve_dir() {
  _d=$1
  [ -n "$_d" ] || return 0
  case "$_d" in /*) : ;; *) _d="$(pwd -P)/$_d" ;; esac
  _tail=""
  while [ ! -d "$_d" ]; do
    _parent=$(dirname -- "$_d")
    [ "$_parent" = "$_d" ] && break
    _tail="$(basename -- "$_d")${_tail:+/}$_tail"
    _d=$_parent
  done
  _real=$(cd "$_d" 2>/dev/null && pwd -P) || _real=$_d
  [ -n "$_tail" ] && _real="$_real/$_tail"
  lexical_abs "$_real"
}

# resolve_target sets RESOLVED to the physical directory the final component of
# $1 actually lives in, following the WHOLE symlink chain. Resolving a single hop
# denied `wt/link -> /outside/f` and allowed `wt/a -> wt/b -> /outside/f` — the
# same escape with one more link in it, and the attacker picks the number of
# links (#297). Bounded, so a cycle cannot spin here; exhausting the bound is a
# refusal, not a pass. It sets a global rather than printing one because a
# command substitution would run the refusal below in a subshell, where `exit`
# exits the substitution and the hook carries on to allow.
resolve_target() {
  _base=$(basename -- "$1")
  RESOLVED=$(resolve_dir "$(dirname -- "$1")")
  _hops=0
  while [ -n "$RESOLVED" ] && [ -L "$RESOLVED/$_base" ]; do
    _hops=$((_hops + 1))
    if [ "$_hops" -gt 32 ]; then
      decide deny "deny-hook: the write target is a symlink chain over 32 links deep, or a cycle. Fail-closed."
      exit 0
    fi
    _tgt=$(readlink "$RESOLVED/$_base" 2>/dev/null || printf '')
    [ -n "$_tgt" ] || break
    case "$_tgt" in
      /*) RESOLVED=$(resolve_dir "$(dirname -- "$_tgt")") ;;
      *)  RESOLVED=$(resolve_dir "$RESOLVED/$(dirname -- "$_tgt")") ;;
    esac
    _base=$(basename -- "$_tgt")
  done
}

TOOL=$(printf '%s\n' "$FIELDS" | sed -n '1p')
CMD=$(printf '%s\n' "$FIELDS" | sed -n '2p')
FILE=$(printf '%s\n' "$FIELDS" | sed -n '3p')

case "$TOOL" in
  Edit|Write|NotebookEdit|MultiEdit)
    [ -n "$FILE" ] || exit 0
    if [ -n "${UNIT_WORKTREE:-}" ]; then
      BOUND=$(cd "$UNIT_WORKTREE" 2>/dev/null && pwd -P) || BOUND=""
      if [ -z "$BOUND" ]; then
        decide deny "deny-hook: ORCA_UNIT_WORKTREE is set but does not resolve to a directory. Fail-closed."
        exit 0
      fi
      # Judged by where the final component actually points, not by its own name.
      check_edit_target() {
        resolve_target "$1"
        REAL=$RESOLVED
        if [ -z "$REAL" ]; then
          decide deny "deny-hook: the write target could not be resolved to an absolute path. Fail-closed."
          exit 0
        fi
        case "$REAL/" in
          "$BOUND"/*) return 0 ;;
          *) decide deny "deny-hook: this worker may only write inside its own worktree. The target resolves outside the unit boundary."
             exit 0 ;;
        esac
      }
      check_edit_target "$FILE"
      while IFS= read -r _FREC; do
        case "$_FREC" in
          'F '*) check_edit_target "${_FREC#F }" ;;
        esac
      done <<EOF
$(printf '%s\n' "$FIELDS" | sed -n '4,$p')
EOF
    fi
    if [ -n "${OPEN_FLEET_STATE_DB:-${ORCA_FLEET_STATE_DB:-}}" ]; then
      python3 - "$0" "$TOOL" "$FILE" "$FIELDS" <<'PYTOUCH' 2>/dev/null || true
import importlib, os, sys
from pathlib import Path
db_path = os.environ.get("OPEN_FLEET_STATE_DB") or os.environ.get("ORCA_FLEET_STATE_DB")
repo_root = Path(sys.argv[1]).resolve().parent.parent.parent
if db_path and (repo_root / "runtime" / "providers" / "local_state.py").is_file():
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    mod = importlib.import_module("runtime.providers.local_state")
    store = mod.LocalStateStore(db_path)
    worker_id = (
        os.environ.get("OPEN_FLEET_WORKER_ID")
        or os.environ.get("ORCA_WORKER_ID")
        or os.environ.get("OPEN_FLEET_DISPATCH_ID")
        or os.environ.get("ORCA_DISPATCH_ID")
        or os.environ.get("OPEN_FLEET_TERMINAL_HANDLE")
        or os.environ.get("ORCA_TERMINAL_HANDLE")
        or "worker"
    )
    run_id = os.environ.get("OPEN_FLEET_RUN_ID") or os.environ.get("ORCA_RUN_ID") or "default"
    op = sys.argv[2].lower()
    paths = [sys.argv[3]]
    for ln in sys.argv[4].splitlines()[3:]:
        if ln.startswith("F "):
            paths.append(ln[2:])
    seen = set()
    for p in paths:
        if p and p not in seen:
            seen.add(p)
            store.record_file_touch(worker_id=worker_id, file_path=p, op=op, run_id=run_id)
PYTOUCH
    fi
    exit 0
    ;;
  Bash) : ;;
  *) exit 0 ;;
esac

[ -n "$CMD" ] || exit 0

# --- HIGH tier (deny) --------------------------------------------------------
# Each SEGMENT of the command line is judged on its own. This block used to run only when the
# command contained no ';', '&&', '||' or '|', and the header claimed a compound command "falls
# through to the Never-list ask". It did not — it was ALLOWED, silently. `cd /x && rm
# --no-preserve-root -rf /` and `env FOO=1 rm --no-preserve-root -rf /` both passed, so putting
# anything at all in front of a refused command defeated the entire tier (#297).
#
# This is still string matching and still cannot resolve what a command DOES: a segment whose
# target comes from a variable or a subshell is beyond it, and the Never list below is the net for
# those. What it buys is that the refused shapes are refused wherever they sit.
#
# The split IS quote-aware (see `segments` in the payload reader), so `git commit -m "oops; rm -rf
# /"` is one segment naming `git commit`, and `rm -rf "/;x"` is one segment whose only target is a
# file literally called `/;x`. An earlier cut split on the raw text and argued that was safe
# because splitting only ever makes MORE segments. It is not: the split leaves the rest of the
# quoted value glued to the FRONT of the next segment, and every rule here is anchored at `^`.
FULL_CMD=$CMD
has() { printf '%s' "$CMD" | grep -qE "$1" 2>/dev/null; }

# Canonicalise the executable spelling of the FIRST word: an absolute or
# relative path, a leading backslash, or surrounding quotes name the same
# command as the bare word. Every rule below anchors on bare names (`rm`,
# `git`, `tee`), so `/bin/rm -rf /` and `/usr/bin/git push --force` walked
# past rules that denied the bare spellings (full-review probe). An
# assignment word is never touched — its VALUE may contain slashes
# (`FOO=/a/b git …`) and basename-cutting it would eat the prefix run.
canon_first() {
  _cf=$1
  case "$_cf" in \\*) _cf=${_cf#\\} ;; esac
  _t=${_cf%% *}
  case "$_t" in
    [A-Za-z_]*=*) printf '%s' "$_cf"; return ;;
    */*|\\*|\"*|\'*) : ;;
    *) printf '%s' "$_cf"; return ;;
  esac
  _u=$_t
  _u=${_u#\\}; _u=${_u#\"}; _u=${_u%\"}; _u=${_u#\'}; _u=${_u%\'}
  _b=${_u##*/}
  [ -n "$_b" ] || { printf '%s' "$_cf"; return; }
  case "$_cf" in
    *\ *) printf '%s %s' "$_b" "${_cf#* }" ;;
    *)    printf '%s' "$_b" ;;
  esac
}

# Drop env/sudo-style prefixes so a refused command cannot be laundered by putting something
# harmless in front of it. `sudo` is peeled but REATTACHED — the rules below match `sudo`
# themselves — because an assignment under it (`sudo GIT_DIR=x git push -d`) otherwise hid
# the whole command from every anchored pattern (PR #321 review).
strip_prefix() {
  _c=$(canon_first "$1")
  _pre=""
  case "$_c" in
    sudo\ *)
      _pre="sudo "; _c=${_c#sudo }
      # sudo's own option run must peel too, or `sudo -n tee`, `sudo -- tee`,
      # `sudo -u root tee`, and stacked `sudo sudo tee` launder the reattached
      # prefix the tee boundary matches (PR #387 security review).
      while : ; do
        case "$_c" in
          sudo\ *)                _c=${_c#sudo } ;;              # stacked sudo
          --\ *)                  _c=${_c#-- }; break ;;         # options end here
          --*=*\ *)               _c=${_c#* } ;;                 # --user=root
          -[uUghpUCTRt]\ *\ *\ *) _c=${_c#* }; _c=${_c#* } ;;    # flag + separate operand
          -*\ *)                  _c=${_c#* } ;;                 # bare flags: -n -E -A -k…
          *) break ;;
        esac
      done ;;
  esac
  while : ; do
    _c=$(canon_first "$_c")
    case "$_c" in
      env\ *)     _c=${_c#env } ;;
      nohup\ *)   _c=${_c#nohup } ;;
      nice\ *)    _c=${_c#nice } ;;  # `nice tee` is the same write (#387 review)
      time\ *)    _c=${_c#time } ;;
      command\ *) _c=${_c#command } ;;
      builtin\ *) _c=${_c#builtin } ;;
      \ *)        _c=${_c# } ;;
      # A NAME=value prefix only IS a prefix when the `=` lives in the FIRST
      # token — a glob cannot confine it there (`*` crosses spaces), so the
      # inner case re-checks the first token alone. An `=` further right is an
      # option operand — `git -c a=b push -f`, `git --git-dir=/x push` — and
      # letting this arm fire there ate `git ` and freed the options after it
      # (#297). A quoted value cuts at its closing quote, not the first space
      # (PR #308 review, P1); an ESCAPED quote inside stays beyond it.
      [A-Za-z_]*=*[!\ ]*\ *)
        case "${_c%% *}" in
          [A-Za-z_]*=*) _c=$(skip_tok "$_c") ;;
          *) break ;;
        esac ;;
      *) break ;;
    esac
  done
  printf '%s%s' "$_pre" "$_c"
}

# git's global options sit between `git` and the subcommand, and every rule here
# anchors the subcommand to the word `git`: `git -C /x push --force`,
# `git -c a=b push -f`, `git --git-dir=/x push --force` all named refused pushes
# and were ALLOWED (#297). Strip the leading option run — an option that takes
# a separate operand drops the operand too, and a quoted operand is cut at its
# closing quote, not the next space. Glued forms need no arm: git rejects
# `-C/x` and `-ca=b` itself. An option this does not know ends the run and the
# segment is judged as written — a future global option still evades, which is
# the same string-matching limit the tier already states above.
strip_git_opts() {
  case "$1" in
    git\ *)       _pre="";      _rest=${1#git } ;;
    sudo\ git\ *) _pre="sudo "; _rest=${1#sudo git } ;;
    *)            printf '%s' "$1"; return ;;
  esac
  while : ; do
    case "$_rest" in
      # Options taking a separate operand: drop the option, then the operand.
      -C\ *|-c\ *|--git-dir\ *|--work-tree\ *|--namespace\ *|--config-env\ *)
        _rest=${_rest#* }
        _rest=$(skip_tok "$_rest") ;;
      # Immediate-exit options print and stop — `git --html-path push --force`
      # never pushes at all, and stripping the option would judge tokens git
      # ignores (PR #321 review). Empty the rest so the segment normalizes to a
      # bare `git`. `--exec-path` is here, not in the operand arm: git's own
      # `[=path]` is optional-and-inline, so a separate token after it is just
      # more ignored text.
      --html-path|--html-path\ *|--man-path|--man-path\ *|--info-path|--info-path\ *|\
      --exec-path|--exec-path\ *|--version|--version\ *|--help|--help\ *|-h|-h\ *)
        _rest=""; break ;;
      # Inline `--opt=value`: drop `name=` then the whole word — the value may
      # quote only its middle (`=/srv/dir" one"`), so it goes through skip_tok
      # like any other operand (PR #321 review, P1).
      --git-dir=*|--work-tree=*|--namespace=*|--exec-path=*|--config-env=*)
        _rest=${_rest#*=}
        _rest=$(skip_tok "$_rest") ;;
      # Valueless flags drop one token each.
      -p\ *|-P\ *|--paginate\ *|--no-pager\ *|--bare\ *|--no-replace-objects\ *|--no-advice\ *|\
      --literal-pathspecs\ *|--glob-pathspecs\ *|--noglob-pathspecs\ *|--icase-pathspecs\ *|\
      --no-optional-locks\ *)
        _rest=${_rest#* } ;;
      *) break ;;
    esac
  done
  printf '%sgit %s' "$_pre" "$_rest"
}

# Collapse every whitespace run to one space and trim the ends. The prefix and
# option arms match single literal spaces, so `git -C␣␣/x` or a tab after `-C`
# left the options in place and the refused push unmatched (PR #321 review).
# Collapsing a quoted value's interior is harmless — rules never inspect a
# value, only the command around it.
norm_ws() {
  _n=$(printf '%s' "$1" | tr -s '[:space:]' ' ')
  _n=${_n# }; _n=${_n% }
  printf '%s' "$_n"
}

# Remove the first shell WORD from $1 and print what follows. A word may quote
# only part of itself — `--git-dir=/srv/dir" one"` is one word — and a `\x`
# escape binds anywhere, including `\ ` for a space (#321 review) — so scanning
# must skip quoted spans and escaped chars wherever they sit. An unclosed
# quote eats to end: that mangles the line, it cannot free a refused command.
skip_tok() {
  _w=$1
  while : ; do
    _p=$_w
    case "$_w" in
      \"*)
        _w=${_w#\"}
        while : ; do
          _i=$_w
          _q=${_w%%[\\\"]*}
          _w=${_w#"$_q"}
          case "$_w" in
            \"*) _w=${_w#\"}; break ;;
            \\*) _w=${_w#\\?} ;;
            *)   break ;;
          esac
          [ "$_w" = "$_i" ] && break
        done ;;
      \'*)    _w=${_w#\'}; _w=${_w#*\'} ;;
      *)      _h=${_w%%[\\\'\" ]*}; _w=${_w#"$_h"}
              case "$_w" in \\*) _w=${_w#\\?} ;; esac ;;
    esac
    [ "$_w" = "$_p" ] && break
    case "$_w" in \ *) break ;; esac
  done
  printf '%s' "${_w# }"
}

# `-C`, `--git-dir`, `--work-tree`, and GIT_DIR=/GIT_WORK_TREE= point a command
# at a DIFFERENT repository, but DEFAULT_BRANCH below is resolved in the hook's
# own working directory — so under a redirect nothing here can prove which ref
# the target repo calls its default (#321 review). Detected on the raw segment,
# before the options were stripped away. An env var only redirects when it sits
# in the leading assignment run — `feature/GIT_DIR=config` is a ref name, not
# a redirect (#321 review) — and the option run ends at `git` itself.
git_redirected() {
  _r=$1
  while : ; do
    _r=$(canon_first "$_r")
    case "$_r" in
      \ *)          _r=${_r# } ;;
      env\ *)       _r=${_r#env } ;;
      sudo\ *)      _r=${_r#sudo } ;;
      command\ *)   _r=${_r#command } ;;
      builtin\ *)   _r=${_r#builtin } ;;
      nohup\ *)     _r=${_r#nohup } ;;
      time\ *)      _r=${_r#time } ;;
      GIT_DIR=*|GIT_WORK_TREE=*) return 0 ;;
      # Any other assignment advances past its token — but only when the `=`
      # lives in the FIRST token, as in strip_prefix: `git --git-dir=/x` also
      # contains `=`+space and letting this arm fire there ate `git ` (#321
      # review). A trailing token with no space after fails the arm outright,
      # so the loop cannot spin on it; a quoted value cuts at its closing
      # quote, not the first space inside.
      [A-Za-z_]*=*\ *)
        case "${_r%% *}" in
          [A-Za-z_]*=*) _r=$(skip_tok "$_r") ;;
          *) break ;;
        esac ;;
      *) break ;;
    esac
  done
  case "$_r" in git\ *) _r=${_r#git } ;; *) return 1 ;; esac
  # Only git's LEADING global-option run can redirect — a `-C` sitting inside a
  # `-c` operand value is text, not an option, so the run is walked and every
  # operand skipped rather than substring-matched (#321 review).
  while : ; do
    case "$_r" in
      -C\ *|-C|--git-dir\ *|--git-dir|--work-tree\ *|--work-tree|\
      --git-dir=*|--git-dir=*\ *|--work-tree=*|--work-tree=*\ *)
        return 0 ;;
      -c\ *|-c|--namespace\ *|--namespace|--config-env\ *|--config-env)
        _r=${_r#* }
        _r=$(skip_tok "$_r") ;;
      --namespace=*|--config-env=*|--exec-path=*)
        _r=${_r#*=}
        _r=$(skip_tok "$_r") ;;
      -p|-p\ *|-P|-P\ *|--paginate|--paginate\ *|--no-pager|--no-pager\ *|\
      --bare|--bare\ *|--no-replace-objects|--no-replace-objects\ *|\
      --no-advice|--no-advice\ *|--literal-pathspecs|--literal-pathspecs\ *|\
      --glob-pathspecs|--glob-pathspecs\ *|--noglob-pathspecs|--noglob-pathspecs\ *|\
      --icase-pathspecs|--icase-pathspecs\ *|--no-optional-locks|--no-optional-locks\ *)
        _r=${_r#* } ;;
      *) return 1 ;;
    esac
  done
}

# Normalize push options only after the command/global-option run was resolved.
# Operand-taking options consume the rest of a short cluster or the next word;
# `-vof` carries push-option `f`, whereas `-vf` forces. Operand text must never
# supply a force flag, a lease, or a deleted ref to the HIGH tier.
#
# Long options are canonicalized first. Git accepts any unambiguous prefix of a
# long option (parse-options): `--del`, `--mi`, `--pru`, `--force-w` and
# `--no-force-w` are --delete, --mirror, --prune, --force-with-lease and
# --no-force-with-lease, so `git push origin --del main` used to pass because
# only full spellings were matched. LONG is git-push 2.43's long-option table;
# an exact name wins, a unique prefix expands, and an AMBIGUOUS prefix (which
# git itself rejects) keeps every destructive meaning it could carry but never
# grants a lease — a newer git that adds an option can only make it ambiguous.
push_policy() {
  python3 -c 'import sys
LONG = {"verbose": 0, "quiet": 0, "repo": 1, "all": 0, "branches": 0,
        "mirror": 0, "delete": 0, "tags": 0, "dry-run": 0, "porcelain": 0,
        "force": 0, "force-with-lease": 0, "force-if-includes": 0,
        "recurse-submodules": 1, "thin": 0, "receive-pack": 1, "exec": 1,
        "set-upstream": 0, "progress": 0, "prune": 0, "no-verify": -1,
        "verify": -1, "follow-tags": 0, "signed": 0, "atomic": 0,
        "push-option": 1, "ipv4": -1, "ipv6": -1}
NAMES = set(LONG) | {"no-" + n for n, kind in LONG.items() if kind >= 0}
OPERAND = ("-o", "--push-option", "--receive-pack", "--exec", "--repo",
           "--recurse-submodules")
DANGER = ("delete", "mirror", "prune", "force", "no-force-with-lease")
def canon(word):
    name, eq, value = word[2:].partition("=")
    if name in NAMES:
        return [word]
    hits = [n for n in NAMES if n.startswith(name)] if name else []
    if len(hits) == 1:
        return ["--" + hits[0] + eq + value]
    return [word] + ["--" + n for n in DANGER if n in hits]
words = sys.argv[1].split()
out, skip, options = [], False, True
lease, force = False, False
for raw in words:
    if skip:
        skip = False
        continue
    if raw == "--":
        options = False
        out.append(raw)
        continue
    expanded = canon(raw) if options and raw.startswith("--") else [raw]
    for word in expanded:
        if options and word in OPERAND:
            skip = True
            continue
        elif word in ("--force", "--no-force", "-f"):
            # The literal word still reaches the HIGH-tier text below; the ordered
            # bit only decides whether a lease may still exempt the push.
            if options:
                force = word != "--no-force"
        elif word == "--no-force-with-lease":
            if options:
                lease = False
            else:
                out.append("--lease-operand")
            continue
        elif word == "--force-with-lease" or word.startswith("--force-with-lease="):
            if options:
                lease = True
            else:
                # An operand grants no lease but keeps its position: after --, the
                # deletion loops skip the word after -o/--repo, and dropping this
                # one would hand them the deleted ref instead.
                out.append("--lease-operand")
            continue
        elif options and word.startswith("-") and not word.startswith("--"):
            cluster = word[1:]
            for i, flag in enumerate(cluster):
                if flag == "o":
                    skip = i == len(cluster) - 1
                    break
                if flag not in "vqnfdu46":
                    out.append(word)
                    break
                if flag == "f":
                    force = True
                out.append("-" + flag)
            continue
        out.append(word)
# Emit only the effective lease; canceled leases and operands after -- cannot
# grant the HIGH-tier exemption. Explicit global force disables lease checks
# (git-push 2.55), so an effective one replaces the lease marker. --no-force
# clears that bit in command-line order but never removes a literal force word:
# an unleased push keeps the trigger it had before E5, which only adds denials.
if force:
    out.append("--force")
elif lease:
    out.append("--force-with-lease")
print(" ".join(out))' "$1"
}

# The C records carry PRE-SPLIT, word-normalized commands from the payload reader above. They
# are split there because splitting is quote-aware and a POSIX shell cannot parse quoting without
# eval: a separator inside a quoted value used to split too, leaving the rest of the value glued
# to the FRONT of the next segment, and every rule below is anchored at `^`. `X="a&b" git push
# --force origin main` became `b" git push --force origin main` and was allowed (PR #308 review,
# P1). Selecting only C records keeps literal path/argument records out of the HIGH tier.
# Loading the commands into positional parameters keeps the loop out of a subshell, so a
# `decide deny` inside it still exits the script.
_SEGS=$(printf '%s\n' "$FIELDS" | sed -n '4,$s/^C //p')
_OLDIFS=$IFS
IFS='
'
set -f
# shellcheck disable=SC2086
set -- $_SEGS
set +f
IFS=$_OLDIFS

for _SEG in "$@"; do
  _SEG_N=$(norm_ws "$_SEG")
  CMD=$(strip_git_opts "$(strip_prefix "$_SEG_N")")
  [ -n "$(printf '%s' "$CMD" | tr -d '[:space:]')" ] || continue
  # 1. Recursive delete of a root-class target, or --no-preserve-root anywhere.
  if has '^[[:space:]]*(sudo[[:space:]]+)?rm[[:space:]]' \
    && has '(^|[[:space:]])(-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)([[:space:]]|$)'; then
    if has '(^|[[:space:]])--no-preserve-root([[:space:]]|$)'; then
      decide deny "deny-hook[HIGH]: rm --no-preserve-root is refused. No task authorizes disabling the root guard."
      exit 0
    fi
    ROOTY=0; SAFE=0
    set -f
    for TOK in $CMD; do
      TOK=${TOK#\"}; TOK=${TOK%\"}; TOK=${TOK#\'}; TOK=${TOK%\'}
      case "$TOK" in
        sudo|rm|-*|--|[0-9]'>'*|'>'*|'<'*|'&') continue ;;
        '/'|'//'|'/*'|'~'|'~/'|'$HOME'|'$HOME/'|'${HOME}'|'${HOME}/') ROOTY=1 ;;
        *) SAFE=1 ;;
      esac
    done
    set +f
    if [ "$ROOTY" -eq 1 ] && [ "$SAFE" -eq 0 ]; then
      decide deny "deny-hook[HIGH]: recursive delete of / or the home directory is refused. Delete a named path inside the unit worktree instead."
      exit 0
    fi
  fi

  # 2/3. Force-push and deletion. An effective lease guards concurrent updates; a
  # deletion recovers nothing, so it is judged FIRST and no lease pardons it:
  # `git push origin :main`, `-d` and `--delete` carry no force flag at all and
  # sailed under both force rules (#297).
  if has '^[[:space:]]*(sudo[[:space:]]+)?git[[:space:]]+push([[:space:]]|$)'; then
    CMD=$(push_policy "$CMD")
    # --mirror force-updates AND deletes every remote ref the local repo lacks;
    # --prune deletes every remote ref its refspecs no longer map — either can
    # remove the default branch without naming it, so no text here can show
    # which refs go. Neither had any rule, so `git push --mirror` passed.
    if has '(^|[[:space:]])--(mirror|prune)($|[[:space:]])'; then
      decide deny "deny-hook[HIGH]: git push --mirror/--prune is refused. It deletes or rewrites remote refs it never names, the default branch among them; push named refs instead."
      exit 0
    fi
    DEFAULT_BRANCH=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's|^refs/remotes/origin/||' || true)
    if [ -z "$DEFAULT_BRANCH" ]; then
      if git show-ref --verify -q refs/remotes/origin/main 2>/dev/null; then DEFAULT_BRANCH="main"
      elif git show-ref --verify -q refs/remotes/origin/master 2>/dev/null; then DEFAULT_BRANCH="master"
      fi
    fi

    # `-d`/`--delete` take their refs positionally; a `:dst` or `+:dst` refspec
    # names the deleted ref in the token itself. A bare `:` or `+:` is the
    # matching-branches push — an empty dst is not a deletion. `refs/heads/` is
    # stripped before comparing: `git push origin :refs/heads/main` deletes the
    # same ref `:main` does (#321 review).
    _DEL=0; _DEL_FLAG=0; _DEL_DEFAULT=0; _SKIP=0
    set -f
    for TOK in $CMD; do
      TOK=${TOK#\"}; TOK=${TOK%\"}; TOK=${TOK#\'}; TOK=${TOK%\'}
      # `-o`/`--push-option`, `--receive-pack`, `--repo` consume the next token —
      # its content is an option string, never a refspec: `-o :x` is not a
      # deletion of x (#321 review).
      [ "$_SKIP" -eq 1 ] && _SKIP=0 && continue
      case "$TOK" in
        -o|--push-option|--receive-pack|--exec|--repo) _SKIP=1 ;;
        -d|--delete) _DEL=1; _DEL_FLAG=1 ;;
        +:*|:*) _dst=${TOK#+}; _dst=${_dst#:}; _dst=${_dst#refs/heads/}
                [ -n "$_dst" ] || continue
                _DEL=1
                [ -n "$DEFAULT_BRANCH" ] && [ "$_dst" = "$DEFAULT_BRANCH" ] && _DEL_DEFAULT=1 ;;
      esac
    done
    set +f
    if [ "$_DEL" -eq 1 ] && git_redirected "$_SEG_N"; then
      # The push targets another repository while DEFAULT_BRANCH was resolved
      # in this one's cwd — the deleted ref cannot be shown recoverable, and
      # ask is the wrong answer for maybe-the-default. Deny.
      decide deny "deny-hook[HIGH]: deleting a remote ref under a redirected repository (-C/--git-dir/GIT_DIR) is refused — the hook cannot verify the target repo's default branch."
      exit 0
    fi
    if [ "$_DEL_FLAG" -eq 1 ] && [ -n "$DEFAULT_BRANCH" ]; then
      # The flag form names its refs among the positionals: a bare token equal
      # to the default branch — qualified or not (`--delete origin
      # refs/heads/main` is the same delete, #321 review) — is the ref being
      # deleted. A remote literally named after it earns a deny rather than a
      # silent delete — that is the error to err toward.
      _SKIP=0
      set -f
      for TOK in $CMD; do
        TOK=${TOK#\"}; TOK=${TOK%\"}; TOK=${TOK#\'}; TOK=${TOK%\'}
        [ "$_SKIP" -eq 1 ] && _SKIP=0 && continue
        case "$TOK" in
          -o|--push-option|--receive-pack|--exec|--repo) _SKIP=1; continue ;;
          git|push|sudo|-*) continue ;;
        esac
        TOK=${TOK#refs/heads/}
        [ "$TOK" = "$DEFAULT_BRANCH" ] && _DEL_DEFAULT=1 && break
      done
      set +f
    fi
    if [ "$_DEL_DEFAULT" -eq 1 ]; then
      decide deny "deny-hook[HIGH]: deleting the default branch is refused. The ref everyone else builds on is not a worker's to remove."
      exit 0
    fi
    if [ "$_DEL" -eq 1 ]; then
      decide ask "deny-hook[NEVER-LIST]: Deleting a remote ref. Per runtime/sandbox-policy.md this needs a recorded human grant before it runs."
      exit 0
    fi

    if ! has '(^|[[:space:]])--force-with-lease($|[[:space:]])'; then
      HAS_FORCE=0
      has '(^|[[:space:]])(-f|--force)($|[[:space:]])' && HAS_FORCE=1
      has '(^|[[:space:]])\+[^[:space:]]' && HAS_FORCE=1
      if [ "$HAS_FORCE" -eq 1 ]; then
        TARGETS_DEFAULT=0
        if [ -n "$DEFAULT_BRANCH" ]; then
          set -f
          for TOK in $CMD; do
            TOK=${TOK#\"}; TOK=${TOK%\"}; TOK=${TOK#\'}; TOK=${TOK%\'}
            case "$TOK" in git|push|sudo|-*) continue ;; esac
            REF=${TOK#+}; REF=${REF##*:}
            [ "$REF" = "$DEFAULT_BRANCH" ] && TARGETS_DEFAULT=1 && break
          done
          set +f
        fi
        if [ "$TARGETS_DEFAULT" -eq 1 ]; then
          decide deny "deny-hook[HIGH]: force-push to the default branch is refused. It rewrites the history everyone else builds on."
        else
          decide deny "deny-hook[HIGH]: unleased or explicit global force is refused. Use --force-with-lease without -f/--force so a concurrent push cannot be silently discarded."
        fi
        exit 0
      fi
    fi
  fi

  # 4. Fleet-wide orchestration reset.
  if has '^[[:space:]]*(sudo[[:space:]]+)?orca(-ide)?[[:space:]]+orchestration[[:space:]]+reset([[:space:]]|$)'; then
    decide deny "deny-hook[HIGH]: 'orca orchestration reset' discards the whole fleet's dispatch state. A worker never resets the orchestration it runs inside."
    exit 0
  fi
done

# --- worktree boundary for Bash writes ---------------------------------------
# The boundary used to be applied only to an Edit/Write payload, so a bounded
# worker could write anywhere it liked by spelling the write as a shell line:
# `echo pwned > /etc/cron.d/x` was ALLOWED (#297). A redirect and a `tee`
# destination are the two file writes in a shell line that can be read off the
# text without knowing what the command does, so those are the two this covers.
#
# ABSOLUTE targets only. A relative target resolves against a working directory
# this hook cannot know — the host does not hand it the worker's cwd, and the
# segment before it may have been a `cd` — so judging one would be guessing, and
# a boundary that guesses at half its cases is worse than one that says what it
# covers. Deliberately NOT covered: `cp`/`mv`/`install` destinations, `dd of=`,
# an interpreter writing through its own API, a path built from a variable, and
# every relative path. The disposable sandbox is the boundary for those; this is
# defense in depth, the same advisory status the rest of this hook carries.
if [ -n "${UNIT_WORKTREE:-}" ]; then
  BOUND=$(cd "$UNIT_WORKTREE" 2>/dev/null && pwd -P) || BOUND=""
  if [ -z "$BOUND" ]; then
    decide deny "deny-hook: ORCA_UNIT_WORKTREE is set but does not resolve to a directory. Fail-closed."
    exit 0
  fi

  bounded_write() {
    _t=$1
    case "$_t" in /*) : ;; *) return 0 ;; esac
    # The process's own standard streams and the bit bucket. `make > /dev/null`
    # is the most common redirect there is and writes nothing anyone can read;
    # refusing it would make the boundary a thing workers route around. Named
    # one by one, not as a /dev/ prefix — `> /dev/sda` IS an escape.
    case "$_t" in
      /dev/null|/dev/zero|/dev/full|/dev/tty|/dev/stdout|/dev/stderr|/dev/stdin|/dev/fd/*)
        return 0 ;;
    esac
    resolve_target "$_t"
    [ -n "$RESOLVED" ] || return 0
    case "$RESOLVED/" in "$BOUND"/*) return 0 ;; esac
    decide deny "deny-hook: this worker may only write inside its own worktree. A shell redirect or tee destination names an absolute path outside the unit boundary."
    exit 0
  }

  # Consume typed records without splitting paths on whitespace. The here-doc
  # keeps this loop in the main shell so a refusal exits the entire hook.
  _TEE=0
  while IFS= read -r _RECORD; do
    case "$_RECORD" in
      'C '*) _TEE=0
             # sudo is peeled and REATTACHED by strip_prefix so the sudo-matching rules
             # still fire — match `sudo tee` here too, or the reattach hides the one
             # write shape this boundary exists to catch (#351).
             case "$(strip_prefix "${_RECORD#C }")" in tee|tee\ *|sudo\ tee|sudo\ tee\ *) _TEE=1 ;; esac ;;
      'W '*) bounded_write "${_RECORD#W }" ;;
      'A '*) if [ "$_TEE" -eq 1 ]; then bounded_write "${_RECORD#A }"; fi ;;
    esac
  done <<EOF
$(printf '%s\n' "$FIELDS" | sed -n '4,$p')
EOF
fi
# --- Never list (ask) --------------------------------------------------------
ask() { decide ask "deny-hook[NEVER-LIST]: $1 Per runtime/sandbox-policy.md this needs a recorded human grant before it runs."; exit 0; }

never_list() {
  has '(^|[[:space:]])rm[[:space:]]+(-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)' && ask "Recursive delete."
  has '(DROP|TRUNCATE)[[:space:]]+(TABLE|DATABASE|SCHEMA)' && ask "Destructive database statement."
  has '(^|[[:space:]])(kubectl|helm)[[:space:]]+(delete|uninstall)' && ask "Cluster resource teardown."
  has '(^|[[:space:]])terraform[[:space:]]+(destroy|apply)' && ask "Infrastructure mutation."
  has '(^|[[:space:]])(aws|gcloud|az)[[:space:]]+[a-z0-9-]+[[:space:]]+(delete|rm|destroy|terminate)' && ask "Cloud resource deletion."
  has '(^|[[:space:]])docker[[:space:]]+(system[[:space:]]+prune|rm[[:space:]]+-f|volume[[:space:]]+rm)' && ask "Container or volume destruction."
  has 'curl[^|]*\|[[:space:]]*(ba|z|d|k)?sh' && ask "Piping a remote script into a shell."
  has '(^|[[:space:]])(npm|pnpm|yarn|cargo|gem|twine)[[:space:]]+publish' && ask "Publishing a package."
  has '(^|[[:space:]])git[[:space:]]+reset[[:space:]]+--hard' && ask "Discarding uncommitted work."
  has '(^|[[:space:]])git[[:space:]]+(checkout|restore)[[:space:]]+\.' && ask "Discarding every local change."
  has '(^|[[:space:]])gh[[:space:]]+secret[[:space:]]+(set|delete)' && ask "Writing or removing a repository secret."
  has '(^|[[:space:]])(aws[[:space:]]+iam|gcloud[[:space:]]+iam)[[:space:]]+.*(create|add)' && ask "Provisioning a credential or identity."
  has '(^|[[:space:]])git[[:space:]]+push[^|;]*(prod|production|release)' && ask "Pushing to a production ref."
  # Every rule above is `has && ask` — when nothing matches the function's
  # status is the last has's failure, and set -e reads a failing CALL as a
  # failing command. Returning 0 keeps "nothing to ask" from exiting nonzero.
  :
}

# The list judges the line twice. As WRITTEN first, because rules like curl|sh
# match on the `|` that sits BETWEEN segments — a normalized join replaces the
# separators with `;` and would unsee the shape the rule exists to catch. Then
# over the same normalized segments the HIGH tier judged — prefixes and git
# global options stripped — so `git -C /x reset --hard` asks what `git reset
# --hard` asks (#297). A line the split somehow emptied falls back to raw.
CMD=$FULL_CMD
never_list
CMD=
for _SEG in "$@"; do
  _n=$(strip_git_opts "$(strip_prefix "$(norm_ws "$_SEG")")")
  CMD=${CMD:+$CMD ; }$_n
done
[ -z "$CMD" ] || never_list

exit 0
