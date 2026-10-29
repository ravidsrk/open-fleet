#!/usr/bin/env sh
# wtree.sh — print a working-tree CONTENT fingerprint (a git tree hash).
#
# Ported from gstack `bin/gstack-wtree` (MIT, garrytan/gstack v1.84.1) — the mechanism is theirs,
# the POSIX-sh spelling and the fail-closed exit are ours. See
# docs/research/2026-09-10-upstream-audit/gstack.md §4.2.
#
# Builds a TEMP index, stages the full working tree into it (`git add -A`, so .gitignore'd scratch
# stays out and UNTRACKED source is included), and prints `git write-tree` of that index. Why this
# and not `git rev-parse HEAD^{tree}`:
#
#   - committing identical content does NOT change the fingerprint, so a record made on a dirty
#     tree stays valid once that exact content is committed;
#   - an untracked new source file DOES change it, so "tests passed" cannot stay fresh after a new
#     file appears;
#   - rebase / amend / squash that preserve content do not change it.
#
# The REAL repo index is never touched. Seeding the temp index by COPYING the real one preserves the
# stat cache, so `git add -A` only re-hashes files whose stat changed. gstack's #2687 hardening is
# kept verbatim in spirit: a copy is stamped "now", which defeats git's racy-index protection and
# can hide a same-second rewrite, so the copy gets the original's times back (from the fstat of the
# descriptor it was read from) — and if that FAILS we fall through to the slower `read-tree HEAD`
# seed rather than trusting a stale stat cache.
#
# Staging runs in GIT CUSTODY (W4 custody sweep): against a git dir this script builds in a temp
# dir, whose config it writes and which defines no filter or diff driver, over the repository's
# objects (read through `objects/info/alternates`) and work tree. The blobs `add -A` writes and the
# tree `write-tree` writes land in that dir's own object store and are removed with it, so the
# repository's store is never written.
#
# IGNORED FILES ARE OUT BY CONTRACT, and that is a stated limit, not an oversight. The consumer
# (verify.py check_commands, evidence-manifest.md) compares this value to `<head_sha>^{tree}`, a
# commit's tree, and an ignored file can never be in one: hashing ignored files in would make every
# record STALE, and would re-hash node_modules/ and build output on every run. The cost: a run whose
# outcome depended on ignored content (.env, a stale build artifact, a file hidden by a local
# .git/info/exclude or global core.excludesFile) still fingerprints as the committed tree. This
# value binds a run to COMMITTABLE content only; the coordinator's clean-env re-run at head_sha is
# what catches a pass that leaned on anything else.
#
# Usage:
#   wtree.sh [repo-dir]                            # default: the current directory
#   wtree.sh predict-merge <base> <branch> [repo]  # 3-way merge conflict prediction in memory
# Exit 1 outside a git repo, or in a repo with no commits and no usable index — callers MUST treat
# a non-zero exit as "no fingerprint" and fail closed, never as an empty one.
# Exit 1 too when the repository cannot be staged in custody: an `extensions.*` the custody git dir
# cannot honour (a partial clone above all), a common git dir whose path an alternates file cannot
# name (a newline or `"` in it), an `info/exclude`, `info/attributes`, `shallow` or
# `info/sparse-checkout` that is not a regular file of at most 16 MiB, an index or shared index
# that is not one of at most 1 GiB, or a repository-scope `core.attributesFile` that is not one of
# at most 1 MiB, where git would read it; no python3 that resolves to an absolute path (it does
# those reads); or a gitlink path holding a newline; and when the exit-3 check below cannot run
# (its diff-index or check-attr fails).
# Exit 3, with the reason on stderr, when a path staged differently from HEAD is selected by a
# filter driver a config DECLARES — the repository's, or a global/system file, which on a one-uid
# host the worker can write as well (#629, PR #649 review, W4-02). No filter ever runs here: the
# command is the worker's to name, and staging reads no config the worker can write, so not even
# one added while this script runs is defined there (W4 custody sweep). But without it, a smudged file's bytes cannot be mapped back to
# the committed clean blob, so for that path the comparison is genuinely unverifiable — touching
# an unchanged expanded file would otherwise fingerprint it as different from HEAD and a good run
# would read as STALE. Exit 3 says so instead of printing a misleading value. An untouched file is
# never re-hashed (the stat cache holds), so a clean checkout still fingerprints normally (Git LFS
# included). The coordinator's clean-env re-run at head_sha remains the authority for such a unit.
set -eu

if [ "${1:-}" = "predict-merge" ]; then
  if [ $# -lt 3 ]; then
    echo "usage: wtree.sh predict-merge <base> <branch> [repo-dir]" >&2
    exit 2
  fi
  _BASE="$2"
  _BRANCH="$3"
  _REPO="${4:-.}"
  exec python3 -I "$(dirname -- "$0")/diff_scope.py" --repo "$_REPO" --predict-merge "$_BASE" "$_BRANCH"
fi
if [ "${2:-}" = "predict-merge" ]; then
  if [ $# -lt 4 ]; then
    echo "usage: wtree.sh <repo-dir> predict-merge <base> <branch>" >&2
    exit 2
  fi
  exec python3 -I "$(dirname -- "$0")/diff_scope.py" --repo "$1" --predict-merge "$3" "$4"
fi

# #629: this script runs git over a repo it does not own (evidence-run.py, verify.py predict-merge
# both point it at a worker's worktree), so close the config command channels before any git
# call. Set at command-line precedence (GIT_CONFIG_COUNT), which overrides the repo's own
# .git/config: core.fsmonitor (a program git runs on `add`/`status`), core.hooksPath (every hook),
# and the ext:: transport; plus replacement objects and grafts off, so a planted refs/replace or
# .git/info/grafts cannot change the tree this fingerprints. A filter a config declares is
# blanked below and never runs (exit 3 covers what that costs). W4-02: global and system config
# are off as well, as in gitexec.py. On a one-uid host ~/.gitconfig is the worker's to write, and
# a global clean filter both ran here and CHOSE the fingerprint (it mapped a tampered file back to
# its committed blob, so verify graded a tree no test saw as FRESH). `safe.directory=*` stands in
# for the one legitimate use of the dropped global file, as gitexec's does. A global
# core.excludesFile is dropped with it, so an untracked file only it hid now counts (fails STALE).
# W4-07: the environment pointers that outrank `-C` (GIT_DIR, GIT_WORK_TREE, GIT_COMMON_DIR,
# GIT_INDEX_FILE, the object directories, GIT_ATTR_SOURCE) and the inherited config channels that
# outrank or blind this belt (GIT_CONFIG_PARAMETERS is read after the GIT_CONFIG_COUNT pairs;
# GIT_CONFIG is the one file `git config --list` reads) are the caller's, never the fingerprint's.
# And git is resolved ONCE, to an absolute path (gitexec.py's rule), not per call against PATH.
# GIT_EXEC_PATH names the directory git runs its own helper programs from, GIT_TEMPLATE_DIR what an
# init copies and GIT_NAMESPACE the refs a call sees: the caller's too, never the fingerprint's.
# GIT_NO_LAZY_FETCH=1 and GIT_ALLOW_PROTOCOL=file (gitexec.py CUSTODY_ENV): a planted promisor
# remote cannot make a read of a missing object fetch, so no `uploadpack`, credential helper or
# ssh command it names runs.
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_ATTR_SOURCE GIT_EXTERNAL_DIFF GIT_CONFIG GIT_CONFIG_PARAMETERS \
  GIT_EXEC_PATH GIT_TEMPLATE_DIR GIT_NAMESPACE
GIT_NO_LAZY_FETCH=1
GIT_ALLOW_PROTOCOL=file
# GIT_ATTR_NOSYSTEM=1: the system attributes file ($(prefix)/etc/gitattributes, which a per-user
# install leaves the worker's to write) is never opened (Codex, round 3); attributes come from the
# work tree, the copied info/attributes and CUSTODY's own core.attributesFile only.
GIT_ATTR_NOSYSTEM=1
export GIT_NO_LAZY_FETCH GIT_ALLOW_PROTOCOL GIT_ATTR_NOSYSTEM
GIT=$(command -v git 2>/dev/null) || GIT=
case "$GIT" in
  /*) ;;
  *) echo "wtree: no git on PATH that resolves to an absolute path; no fingerprint" >&2; exit 1 ;;
esac
# python3 -I does the reads sh cannot do safely: every file copied into CUSTODY below is opened
# without blocking and without following a final symlink (Codex, round 5, P2). Resolved once, as git.
PY=$(command -v python3 2>/dev/null) || PY=
case "$PY" in
  /*) ;;
  *) echo "wtree: no python3 on PATH that resolves to an absolute path; no fingerprint" >&2; exit 1 ;;
esac
# The caller's own global/system view, kept for ONE read below: the driver NAMES those files
# declare, so a changed path one selects is reported unverifiable (exit 3), never staged raw.
_CALLER_GLOBAL=${GIT_CONFIG_GLOBAL-}; _CALLER_GLOBAL_SET=${GIT_CONFIG_GLOBAL+1}
_CALLER_NOSYSTEM=${GIT_CONFIG_NOSYSTEM-}; _CALLER_NOSYSTEM_SET=${GIT_CONFIG_NOSYSTEM+1}
GIT_TERMINAL_PROMPT=0
GIT_NO_REPLACE_OBJECTS=1
GIT_GRAFT_FILE=/dev/null
GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_NOSYSTEM=1
GIT_CONFIG_COUNT=4
GIT_CONFIG_KEY_0=core.fsmonitor;   GIT_CONFIG_VALUE_0=false
GIT_CONFIG_KEY_1=core.hooksPath;   GIT_CONFIG_VALUE_1=/dev/null
GIT_CONFIG_KEY_2=protocol.ext.allow; GIT_CONFIG_VALUE_2=never
GIT_CONFIG_KEY_3=safe.directory;   GIT_CONFIG_VALUE_3='*'
export GIT_TERMINAL_PROMPT GIT_NO_REPLACE_OBJECTS GIT_GRAFT_FILE GIT_CONFIG_COUNT
export GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM
export GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 GIT_CONFIG_KEY_1 GIT_CONFIG_VALUE_1
export GIT_CONFIG_KEY_2 GIT_CONFIG_VALUE_2 GIT_CONFIG_KEY_3 GIT_CONFIG_VALUE_3
# No git call (nor any hook or filter one runs) may read this script's stdin: an inherited pipe
# that never closes would block the fingerprint, and the gate behind it, forever (#629).
exec </dev/null

# Bytes, not text, from here on: paths and config keys are handled under LC_ALL=C (see below).
LC_ALL=C
export LC_ALL
NL='
'
TAB=$(printf '\t')
# Codex, round 5 (P1): `$(...)` strips EVERY trailing newline, so `TOP=$(git rev-parse
# --show-toplevel)` for a repository at /tmp/repo<NL> named /tmp/repo, and the fingerprint printed
# THAT repository's tree. exact_out runs a command and leaves its stdout in `_out` with only the ONE
# newline git ends a value with removed and every other byte kept (a sentinel printed after the
# output takes the strip); a command that fails, or output that does not end in that newline, is a
# failure. Every path git hands this script (the toplevel, the git dir, the common dir, the index)
# and every core.* value carried below is read this way. No other command substitution here can
# lose a byte to the strip: `command -v` output must be absolute, so it ends in the command's name;
# mktemp's ends in its random suffix; the rest are object ids, a format name, counts or messages.
exact_out() {
  _out=$("$@" 2>/dev/null && printf x) || return 1
  _out=${_out%x}
  case "$_out" in
    *"$NL") _out=${_out%"$NL"} ;;
    *) return 1 ;;
  esac
}

TARGET="${1:-.}"
exact_out "$GIT" -C "$TARGET" rev-parse --show-toplevel || exit 1
TOP=$_out
# An empty TOP would make every `-C "$TOP"` below run in the caller's directory instead.
case "$TOP" in
  /*) ;;
  *) exit 1 ;;
esac

# #629: `git add -A` below materialises worktree content, running a repo-config clean/smudge
# filter a .gitattributes selects. The command comes only from a declared filter.<n>.* key, and
# -c cannot wildcard the <n>, so read the declared names and blank each. A filter runs only for a
# file whose stat changed since the index, so a clean checkout re-stages nothing and this never
# alters the fingerprint; it bites only on a currently-dirty filtered file (uncommitted anyway).
# The names are BYTES (PR #649 review): git accepts 0xff, an invalid UTF-8 sequence, `.` or `=` in
# one, and an attribute selects that exact name. So the keys are handled under LC_ALL=C (a UTF-8
# `tr` aborts at the first invalid byte and drops every key after it), split on newline with
# globbing off, and collected as GIT_CONFIG_KEY_n/VALUE_n pairs: an env pair keeps key and value
# apart, where `-c <key>=` splits a name holding `=` at its first `=` and blanks another key.
# The pairs are POSITIONAL `NAME=value` arguments that `env "$@" "$GIT" ...` applies to each call
# that can run a filter: env(1) splits each one at its first `=` (the variable name holds none),
# so the key's bytes reach git intact and no shell text is ever built from them and re-parsed.
# The listing alone reads the CALLER's global/system view (W4-02): every git call that stages
# content runs with those files off, so a driver they declare never runs, but its NAME is
# collected with the repository's — DECLARED keeps every blanked filter name, one per line, for
# the exit-3 check after staging, whichever scope (`--show-scope`) declared it.
DECLARED=
# PR #649 review (PRRT_kwDOTWxN9c6vzAIE): an unreadable driver list must stop the fingerprint,
# never run with nothing blanked. `$(git ... | tr ...)` reported tr's exit status and hid git's,
# so the listing goes to a temp file and git's own status decides. git answers an empty but valid
# config with exit 0 and no output; anything else — a non-zero exit (128 for an unreadable or
# malformed config), output that is not NUL-terminated, a scope without its key — is "no
# fingerprint", exit 1 with the reason on stderr.
set --
_n=$GIT_CONFIG_COUNT
CFG=$(mktemp "${TMPDIR:-/tmp}/orca-wtree-cfg-XXXXXX") || exit 1
trap 'rm -f "$CFG"' EXIT INT TERM
if ! (
  if [ -n "$_CALLER_GLOBAL_SET" ]; then GIT_CONFIG_GLOBAL=$_CALLER_GLOBAL; export GIT_CONFIG_GLOBAL
  else unset GIT_CONFIG_GLOBAL; fi
  if [ -n "$_CALLER_NOSYSTEM_SET" ]; then GIT_CONFIG_NOSYSTEM=$_CALLER_NOSYSTEM; export GIT_CONFIG_NOSYSTEM
  else unset GIT_CONFIG_NOSYSTEM; fi
  exec "$GIT" -C "$TOP" config --list --show-scope -z --name-only
) >"$CFG" 2>/dev/null; then
  echo "wtree: cannot read $TOP's config, so its filter drivers cannot be neutralised; no fingerprint (#629)" >&2
  exit 1
fi
if [ -s "$CFG" ] && [ "$(tail -c 1 "$CFG" | od -An -tx1 | tr -d ' \n')" != 00 ]; then
  echo "wtree: $TOP's config listing is not NUL-terminated keys; no fingerprint (#629)" >&2
  exit 1
fi
BLANK_KEYS=$(tr '\0' '\n' <"$CFG")
rm -f "$CFG"
OLDIFS=$IFS
IFS=$NL
set -f
_scope=
for _k in $BLANK_KEYS; do
  if [ -z "$_scope" ]; then
    _scope=$_k
    continue
  fi
  _scope=
  case "$_k" in
    filter.*.*)
      # A filter is neutralised WHOLE: commands blank AND required=false, since git dies on a
      # required filter that runs nothing — blanked, or with no command declared (PR #649).
      # Repeats for a name's other keys are harmless (same pairs, last one wins).
      _d=${_k#filter.}
      _d=${_d%.*}
      DECLARED="$DECLARED$_d$NL"
      for _v in clean smudge process required; do
        _val=
        [ "$_v" = required ] && _val=false
        set -- "$@" "GIT_CONFIG_KEY_$_n=filter.$_d.$_v" "GIT_CONFIG_VALUE_$_n=$_val"
        _n=$((_n + 1))
      done ;;
    diff.*.textconv|diff.*.command)
      set -- "$@" "GIT_CONFIG_KEY_$_n=$_k" "GIT_CONFIG_VALUE_$_n="
      _n=$((_n + 1)) ;;
  esac
done
set +f
IFS=$OLDIFS
if [ -n "$_scope" ]; then
  echo "wtree: $TOP's config listing has a scope without its key; no fingerprint (#629)" >&2
  exit 1
fi

# W4 custody sweep: the listing above and `add -A` below are two git calls, and `add -A` used to
# read the repository's config again — a filter a still-running worker declared in between ran
# here unblanked (and, mapping a tampered file back to its committed blob, chose the fingerprint).
# So everything that stages or hashes content runs against CUSTODY, a git dir built here (the
# shared custody of runtime/scripts/gitexec.py, custody_git_dir, spelled in sh): its own config
# (format only, no driver of any kind), HEAD at the repository's HEAD commit, the repository's
# objects as a read-only alternate, and regular-file copies of what git reads there: the common
# `info/exclude` and `shallow`, and the per-worktree `info/sparse-checkout` and split-index
# `sharedindex.*`. The work tree is the repository's own (`--work-tree "$TOP"`). The pairs listed
# above still ride as a belt; the repository's data-only core.* settings (line endings, file modes,
# name folding, stat fields, sparse flags) ride too, read here by `config --get`, so a checkout
# still fingerprints as its committed tree. `core.excludesFile` is NOT carried: honouring a file
# the worker names could hide an untracked file, so it counts (fails STALE) instead.
# Both read byte-exact (exact_out, above): a stripped trailing newline named another directory.
exact_out "$GIT" -C "$TOP" rev-parse --absolute-git-dir || exit 1
_gitdir=$_out
exact_out "$GIT" -C "$TOP" rev-parse --path-format=absolute --git-common-dir || exit 1
_common=$_out
case "$_gitdir" in
  /*) ;;
  *) echo "wtree: $TOP's git dir is not absolute; no fingerprint" >&2; exit 1 ;;
esac
_format=$("$GIT" -C "$TOP" rev-parse --show-object-format 2>/dev/null) || exit 1
case "$_format" in
  sha1) _rfv=0 ;;
  sha256) _rfv=1 ;;
  *) echo "wtree: unknown object format '$_format'; no fingerprint" >&2; exit 1 ;;
esac
case "$_common" in
  /*"$NL"*|*'"'*) echo "wtree: cannot name $TOP's object store in an alternates file; no fingerprint" >&2; exit 1 ;;
  /*) ;;
  *) echo "wtree: $TOP's common git dir is not absolute; no fingerprint" >&2; exit 1 ;;
esac
# Any extensions.* the custody dir cannot reproduce is refused, never guessed (a partial clone's
# missing objects, above all). `config --get-regexp` exits 1 when there is none.
_rc=0
_ext=$("$GIT" -C "$TOP" config --name-only --get-regexp '^extensions\.' 2>/dev/null) || _rc=$?
if [ "$_rc" -ne 0 ] && [ "$_rc" -ne 1 ]; then
  echo "wtree: cannot read $TOP's extensions; no fingerprint" >&2
  exit 1
fi
OLDIFS=$IFS
IFS=$NL
set -f
for _k in $_ext; do
  case "$_k" in
    extensions.objectformat|extensions.compatobjectformat|extensions.worktreeconfig) ;;
    extensions.refstorage|extensions.relativeworktrees) ;;
    *) echo "wtree: $TOP declares $_k, which the custody git dir cannot honour; no fingerprint" >&2
       exit 1 ;;
  esac
done
set +f
IFS=$OLDIFS
for _k in filemode symlinks ignorecase precomposeunicode protecthfs protectntfs sparsecheckout \
    sparsecheckoutcone autocrlf eol safecrlf checkroundtripencoding checkstat trustctime; do
  exact_out "$GIT" -C "$TOP" config --get "core.$_k" || continue
  set -- "$@" "GIT_CONFIG_KEY_$_n=core.$_k" "GIT_CONFIG_VALUE_$_n=$_out"
  _n=$((_n + 1))
done
_head=$("$GIT" -C "$TOP" rev-parse -q --verify 'HEAD^{commit}' 2>/dev/null) || _head=

CUSTODY=$(mktemp -d "${TMPDIR:-/tmp}/orca-wtree-git-XXXXXX") || exit 1
trap 'rm -rf "$CUSTODY"' EXIT INT TERM

# core.attributesFile (Codex on this branch, P1): a repository-scope one is attribute DATA like
# info/attributes — dropped, a clean CRLF checkout an `eol=crlf` line there steers, once touched,
# staged unnormalised and read STALE. Its CONTENT is carried: the path as git expands it
# (`--type=path`; a relative one is the work tree top's, where git reads it), read as every custody
# copy below is read (a regular file of at most 1 MiB here), into a file CUSTODY's own
# core.attributesFile names — the same lowest precedence, below .gitattributes and info/attributes.
# A FIFO, device, directory, symlink or larger file is no fingerprint (exit 1), never silently
# dropped; a missing file or an empty value is no attributes, as for git. The reader takes the path
# from git's NUL-terminated output in a file: a `$(...)` would strip a trailing newline from it and
# read another file (Codex, round 3). CUSTODY's file is named ALWAYS, empty when the repository
# names none, so git never opens its default user attributes file ($XDG_CONFIG_HOME/git/attributes
# or ~/.config/git/attributes, the worker's to write on a one-uid host — a FIFO there hung
# staging), and GIT_ATTR_NOSYSTEM=1 (above) keeps the system file shut.
: >"$CUSTODY/attributes" || exit 1
_rc=0
"$GIT" -C "$TOP" config --type=path -z --get core.attributesFile >"$CUSTODY/wtree-attributes-path" \
  2>/dev/null || _rc=$?
_aflen=$(wc -c <"$CUSTODY/wtree-attributes-path" | tr -d ' \t') || exit 1
_attrs=
if [ "$_rc" -eq 0 ] && [ "$_aflen" -gt 1 ]; then
  _attrs=$CUSTODY/wtree-attributes-path
elif [ "$_rc" -eq 0 ] && [ "$_aflen" -ne 1 ]; then
  echo "wtree: $TOP's core.attributesFile listing is not one NUL-terminated value; no fingerprint" >&2
  exit 1
elif [ "$_rc" -ne 0 ] && [ "$_rc" -ne 1 ]; then
  echo "wtree: cannot read $TOP's core.attributesFile; no fingerprint" >&2
  exit 1
fi
set -- "$@" "GIT_CONFIG_KEY_$_n=core.attributesFile" "GIT_CONFIG_VALUE_$_n=$CUSTODY/attributes"
_n=$((_n + 1))
set -- "$@" "GIT_CONFIG_COUNT=$_n"
mkdir "$CUSTODY/refs" "$CUSTODY/refs/heads" "$CUSTODY/refs/tags" "$CUSTODY/info" \
  "$CUSTODY/objects" "$CUSTODY/objects/info" || exit 1
printf '[core]\n\trepositoryformatversion = %s\n\tbare = true\n' "$_rfv" >"$CUSTODY/config" || exit 1
if [ "$_format" = sha256 ]; then
  printf '[extensions]\n\tobjectformat = sha256\n' >>"$CUSTODY/config" || exit 1
fi
if [ -n "$_head" ]; then
  printf '%s\n' "$_head" >"$CUSTODY/HEAD" || exit 1
else
  printf 'ref: refs/heads/open-fleet-unborn\n' >"$CUSTODY/HEAD" || exit 1
fi
printf '%s/objects\n' "$_common" >"$CUSTODY/objects/info/alternates" || exit 1

# Resolve the REAL index path BEFORE exporting GIT_INDEX_FILE: with the variable set,
# `rev-parse --git-path index` returns the temp index itself and the stat-cache seed self-copies.
REAL_INDEX=
if exact_out "$GIT" -C "$TOP" rev-parse --git-path index; then
  REAL_INDEX=$_out
fi
case "$REAL_INDEX" in
  ""|/*) ;;
  *) REAL_INDEX="$TOP/$REAL_INDEX" ;;
esac

TMPIDX=$(mktemp "${TMPDIR:-/tmp}/orca-wtree-XXXXXX") || exit 1
trap 'rm -f "$TMPIDX"; rm -rf "$CUSTODY"' EXIT INT TERM

# What git reads from the repository's git dir is COPIED into CUSTODY: the common `info/exclude`,
# `info/attributes` and `shallow`, the per-worktree `info/sparse-checkout` and split-index
# `sharedindex.*`, the core.attributesFile content (above), and the real index into TMPIDX (the
# stat-cache seed). info/attributes is DATA (Codex on this branch, P1): `text`/`eol`/
# `working-tree-encoding`/`ident` are built-in conversions, so without it a clean CRLF checkout of
# an `eol=crlf` path, once touched, staged as CRLF and read STALE; a `filter=`/`diff=` it selects
# names a driver CUSTODY's config never defines. Each file is opened ONCE (Codex, round 5, P2): a
# type check by path and then `cp` by path again let a still-running worker swap in a FIFO between
# the two (cp's open hung the gate) or a symlink (cp followed it). So python3 -I opens it without
# following a final symlink and without blocking, checks the type and size with fstat on that
# descriptor, and copies from that descriptor, never more than the cap: a regular file of at most
# 16 MiB (the data files) or 1 GiB (the index and each shared index). Anything else — a FIFO,
# socket, device, directory, symlink, larger or still-growing file — is no fingerprint (exit 1),
# never followed or skipped; an absent file is skipped, as git skips it. Each copy gets its
# original's atime/mtime from that same fstat. The reader prints `seeded` once the index is copied
# with its times; an absent index, or times that cannot be restored, seed from HEAD instead.
if ! _seeded=$("$PY" -I -c '
import os, stat, sys
MIB = 1 << 20
DATA, INDEX, ATTRIBUTES = (16 * MIB, b"16 MiB"), (1024 * MIB, b"1 GiB"), (MIB, b"1 MiB")
FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
         | getattr(os, "O_NOCTTY", 0))
top, common, gitdir, custody, index, tmpidx, pathfile = map(os.fsencode, sys.argv[1:8])


class Refused(Exception):
    pass


def copy(src, dst, cap):
    """src into dst from ONE descriptor: opened without following a final symlink or blocking, read
    only if fstat on it shows a regular file of at most cap bytes, and never past cap + 1 bytes (a
    file that grows past it is refused too). Its stat, or None if src is absent, as for git."""
    try:
        fd = os.open(src, FLAGS)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError:
        raise Refused(src, cap)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > cap[0]:
            raise Refused(src, cap)
        left = cap[0] + 1
        with open(dst, "wb") as out:
            while left > 0:
                chunk = os.read(fd, min(left, MIB))
                if not chunk:
                    break
                out.write(chunk)
                left -= len(chunk)
        if left <= 0:
            raise Refused(src, cap)
    finally:
        os.close(fd)
    return st


def stamp(dst, st):
    os.utime(dst, ns=(st.st_atime_ns, st.st_mtime_ns))


def main():
    if pathfile:
        with open(pathfile, "rb") as fh:
            raw = fh.read()
        src = raw[:-1]
        named = top + b"\x27s core.attributesFile"
        if not raw.endswith(b"\0") or b"\0" in src:
            raise Refused(named, ATTRIBUTES)
        try:
            copy(src if src.startswith(b"/") else top + b"/" + src, custody + b"/attributes", ATTRIBUTES)
        except Refused:
            raise Refused(named, ATTRIBUTES) from None
    for base, rel in ((common, b"info/exclude"), (common, b"info/attributes"), (common, b"shallow"),
                      (gitdir, b"info/sparse-checkout")):
        st = copy(base + b"/" + rel, custody + b"/" + rel, DATA)
        if st is not None:
            stamp(custody + b"/" + rel, st)
    for name in sorted(os.listdir(gitdir)):
        if name.startswith(b"sharedindex."):
            st = copy(gitdir + b"/" + name, custody + b"/" + name, INDEX)
            if st is not None:
                stamp(custody + b"/" + name, st)
    st = copy(index, tmpidx, INDEX) if index else None
    if st is not None:
        try:
            stamp(tmpidx, st)
        except OSError:
            return
        sys.stdout.write("seeded\n")


try:
    main()
except Refused as exc:
    what, cap = exc.args
    sys.stderr.buffer.write(b"wtree: " + what + b" is not a regular file of at most " + cap[1]
                            + b"; no fingerprint\n")
    sys.exit(1)
except OSError as exc:
    sys.stderr.write("wtree: cannot copy what git reads into custody (%s); no fingerprint\n" % exc)
    sys.exit(1)
' "$TOP" "$_common" "$_gitdir" "$CUSTODY" "$REAL_INDEX" "$TMPIDX" "$_attrs"); then
  exit 1
fi
GIT_INDEX_FILE="$TMPIDX"
export GIT_INDEX_FILE

seed_from_head() {
  rm -f "$TMPIDX" 2>/dev/null || true
  "$GIT" -C "$TOP" --git-dir="$CUSTODY" --work-tree="$TOP" read-tree HEAD 2>/dev/null || return 1
}

if [ "$_seeded" != seeded ]; then
  seed_from_head || exit 1
fi

# Gitlinks (Codex on PR #724, P1). For a gitlink whose submodule is checked out, `add` asks whether
# the submodule is dirty by starting a child `git status` INSIDE it, under the submodule's own
# config and attributes — which CUSTODY never sees, so a filter planted there ran here. `add` has
# no option against it and ignores the config that would set one. So every gitlink whose path is a
# directory is kept out of `add -A` (an exclude pathspec) and refreshed with `update-index`, which
# reads the submodule's HEAD from its refs in-process (a moved submodule still changes the
# fingerprint) and starts no child. The index is listed NUL-separated; a gitlink path holding a
# newline (or \001, which stands in for one below) is refused, never guessed. An untracked nested
# repository is added by `add -A` as a gitlink, the same in-process way.
SOH=$(printf '\001')
"$GIT" -C "$TOP" --git-dir="$CUSTODY" --work-tree="$TOP" ls-files -s -z >"$CUSTODY/wtree-ls" 2>/dev/null || exit 1
: >"$CUSTODY/wtree-gitlinks"
printf ':/\000' >"$CUSTODY/wtree-pathspec"
if ! tr '\0\n' '\n\001' <"$CUSTODY/wtree-ls" | {
  while IFS= read -r _rec; do
    case "$_rec" in
      ("160000 "*) ;;
      (*) continue ;;
    esac
    case "$_rec" in
      (*"$SOH"*) exit 1 ;;
    esac
    _p=${_rec#*"$TAB"}
    if [ ! -L "$TOP/$_p" ] && [ -d "$TOP/$_p" ]; then
      printf '%s\000' "$_p" >>"$CUSTODY/wtree-gitlinks"
      printf ':(exclude,literal)%s\000' "$_p" >>"$CUSTODY/wtree-pathspec"
    fi
  done
}; then
  echo "wtree: a gitlink path in $TOP's index holds a newline; no fingerprint" >&2
  exit 1
fi
if [ -s "$CUSTODY/wtree-gitlinks" ]; then
  env "$@" "$GIT" -C "$TOP" --git-dir="$CUSTODY" --work-tree="$TOP" add -A \
    --pathspec-from-file="$CUSTODY/wtree-pathspec" --pathspec-file-nul 2>/dev/null || exit 1
  env "$@" "$GIT" -C "$TOP" --git-dir="$CUSTODY" --work-tree="$TOP" update-index -z --stdin \
    <"$CUSTODY/wtree-gitlinks" 2>/dev/null || exit 1
else
  env "$@" "$GIT" -C "$TOP" --git-dir="$CUSTODY" --work-tree="$TOP" add -A 2>/dev/null || exit 1
fi
# write-tree too: a racily-clean index entry (its mtime equals the temp index's, which `touch -r`
# above makes likely) is re-hashed here, which would re-run a clean filter — so it runs in custody
# with the blanks (#629), as `add -A` does.
TREE=$(env "$@" "$GIT" -C "$TOP" --git-dir="$CUSTODY" --work-tree="$TOP" write-tree 2>/dev/null) || exit 1

# Exit 3 (see the header): a path staged differently from HEAD that a declared driver filters.
# `diff-index --cached` compares the temp index to HEAD's tree and `check-attr` reads the
# attributes, both in custody, which holds every attribute source the repository's own git reads
# (the work tree's .gitattributes, the copied info/attributes, the carried core.attributesFile)
# and never opens a file the worker names; neither runs any command. A driver declared only after the listing is not in DECLARED: it never ran, so its path
# was hashed from its raw bytes and the fingerprint states that content, as for any changed file.
# check-attr -z prints `path NUL filter NUL value NUL`: NUL and newline
# are swapped so each field is one line (a newline inside a path becomes a NUL that `read` drops,
# which keeps every third line the value). A value is never a path, and holds no whitespace.
# Each git's own status decides (Codex on this branch, P2): a pipeline reported only its last
# reader's, so a diff-index or check-attr that failed left HIT empty and the TREE was printed as
# if nothing were filtered. Both write to files first; either failing is "no fingerprint".
if [ -n "$DECLARED" ]; then
  HEAD_TREE=$("$GIT" -C "$TOP" rev-parse -q --verify 'HEAD^{tree}' 2>/dev/null) \
    || HEAD_TREE=$("$GIT" -C "$TOP" hash-object -t tree /dev/null)
  if ! env "$@" "$GIT" -C "$TOP" --git-dir="$CUSTODY" --work-tree="$TOP" diff-index --cached \
      --ignore-submodules=dirty --no-ext-diff -z --name-only --no-renames --diff-filter=AMT \
      "$HEAD_TREE" -- >"$CUSTODY/wtree-changed" 2>/dev/null; then
    echo "wtree: cannot list the paths staged differently from HEAD; no fingerprint" >&2
    exit 1
  fi
  if ! env "$@" "$GIT" -C "$TOP" --git-dir="$CUSTODY" --work-tree="$TOP" check-attr --stdin -z filter \
      <"$CUSTODY/wtree-changed" >"$CUSTODY/wtree-attrs" 2>/dev/null; then
    echo "wtree: cannot read the filter attributes of the changed paths; no fingerprint" >&2
    exit 1
  fi
  HIT=$(tr '\0\n' '\n\0' <"$CUSTODY/wtree-attrs" \
        | { _i=0; _path=
            while IFS= read -r _f; do
              # `(pattern)`: a bare `pattern)` inside $( ) trips bash 3.2's parser (macOS /bin/sh).
              case $((_i % 3)) in
                (0) _path=$_f ;;
                (2) case "$NL$DECLARED" in
                      (*"$NL$_f$NL"*) printf '%s%s%s\n' "$_f" "$TAB" "$_path"; break ;;
                    esac ;;
              esac
              _i=$((_i + 1))
            done; })
  if [ -n "$HIT" ]; then
    printf 'wtree: %s: filtered by declared driver %s and staged differently from HEAD; its content cannot be compared to the committed tree without running repository-supplied commands, so no fingerprint (#629)\n' \
      "${HIT#*"$TAB"}" "${HIT%%"$TAB"*}" >&2
    exit 3
  fi
fi
printf '%s\n' "$TREE"
