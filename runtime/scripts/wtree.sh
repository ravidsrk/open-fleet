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
# kept verbatim in spirit: `cp` stamps the copy "now", which defeats git's racy-index protection and
# can hide a same-second rewrite, so `touch -r` restores the original mtime — and if that touch
# FAILS we fall through to the slower `read-tree HEAD` seed rather than trusting a stale stat cache.
#
# Staged blobs land in the object store as unreachable objects and are gc'd like stash churn (so the
# CONTENT of untracked, non-ignored files enters .git/objects until gc — the same property
# `git stash -u` has).
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
set -eu

if [ "${1:-}" = "predict-merge" ]; then
  if [ $# -lt 3 ]; then
    echo "usage: wtree.sh predict-merge <base> <branch> [repo-dir]" >&2
    exit 2
  fi
  _BASE="$2"
  _BRANCH="$3"
  _REPO="${4:-.}"
  exec python3 "$(dirname -- "$0")/diff_scope.py" --repo "$_REPO" --predict-merge "$_BASE" "$_BRANCH"
fi
if [ "${2:-}" = "predict-merge" ]; then
  if [ $# -lt 4 ]; then
    echo "usage: wtree.sh <repo-dir> predict-merge <base> <branch>" >&2
    exit 2
  fi
  exec python3 "$(dirname -- "$0")/diff_scope.py" --repo "$1" --predict-merge "$3" "$4"
fi

TARGET="${1:-.}"
TOP=$(git -C "$TARGET" rev-parse --show-toplevel 2>/dev/null) || exit 1

# Resolve the REAL index path BEFORE exporting GIT_INDEX_FILE: with the variable set,
# `rev-parse --git-path index` returns the temp index itself and the stat-cache seed self-copies.
REAL_INDEX=$(git -C "$TOP" rev-parse --git-path index 2>/dev/null || true)
case "$REAL_INDEX" in
  ""|/*) ;;
  *) REAL_INDEX="$TOP/$REAL_INDEX" ;;
esac

TMPIDX=$(mktemp "${TMPDIR:-/tmp}/orca-wtree-XXXXXX") || exit 1
trap 'rm -f "$TMPIDX"' EXIT INT TERM
GIT_INDEX_FILE="$TMPIDX"
export GIT_INDEX_FILE

seed_from_head() {
  rm -f "$TMPIDX" 2>/dev/null || true
  git -C "$TOP" read-tree HEAD 2>/dev/null || return 1
}

if [ -n "$REAL_INDEX" ] && [ -f "$REAL_INDEX" ] && cp "$REAL_INDEX" "$TMPIDX" 2>/dev/null; then
  if ! touch -r "$REAL_INDEX" "$TMPIDX" 2>/dev/null; then
    seed_from_head || exit 1
  fi
else
  seed_from_head || exit 1
fi

git -C "$TOP" add -A 2>/dev/null || exit 1
git -C "$TOP" write-tree 2>/dev/null || exit 1
