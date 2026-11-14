#!/usr/bin/env sh
# verify-gate.sh — the completion-gate entrypoint for Claude Code Stop / TaskCompleted hooks.
#
# Wires the independent verifier (verify.py) to the native hook surface so a unit CANNOT be
# marked done until its evidence manifest passes. `TaskCompleted` exit 2 blocks completion and
# returns feedback; `Stop` exit 2 refuses the turn end. This is the plugin-hook packaging of
# evidence-manifest.md section 2 — the gate mechanism is native, its CONTENT (independent
# re-derivation + negative control + frozen denominator) is the differentiator.
#
# FAIL CLOSED: if no manifest is named, the unit is NOT verifiable, so the gate blocks (exit 2),
# never passes by default. Same for a verifier that errors.
#
# Inputs (env). CRITICAL: these are trustworthy only when they originate OFF the graded worker.
# On the native Stop/TaskCompleted hook the gate runs IN the worker's session, so the worker can set
# them — there the gate is ADVISORY (defense-in-depth), not a soundness boundary. The SOUND guarantee
# holds on CI / MCP-Task / SDK-subprocess surfaces where the coordinator, not the worker, sets the env.
# Set ORCA_PROVENANCE=ci|mcp|sdk|dispatch on those surfaces to assert off-worker origin (else a NOTE
# is emitted). See docs/verify-gate.md#trust-boundary. (Signed/out-of-band binding is tracked separately.)
#   ORCA_MANIFEST         path to the unit's evidence manifest JSON (required)
#   ORCA_CONTRACT_SOURCE  authoritative frozen contract `path@ref` (required for scope soundness)
#   ORCA_CONTRACT_DIGEST  authoritative sha256 of that contract (required for scope soundness)
#   ORCA_REPO             owner/name for the independent review lookup. REQUIRED on the sound
#                         surfaces (ORCA_PROVENANCE set) — verify.py fails the review leg closed
#                         without it there; on the native lane it is inferred from origin and
#                         recorded as ADVISORY (origin is worker-writable; h409 F-2)
#   ORCA_BASE             integration base branch, for the ancestry check (optional)
#   ORCA_SYMBOL           a unit symbol to grep on the base (optional)
#   ORCA_UNIT_CLASS       mutation | report-only | planning, from dispatch (optional; missing => mutation)
#   ORCA_UNIT_LANE        A | B | 0, from dispatch (optional; forwarded as --lane)
#   ORCA_PROVENANCE       ci|mcp|sdk|dispatch — asserts the env came from OFF the worker (optional)
#   ORCA_NC_COMMAND       forwarded as --nc-command: the AUTHORITATIVE criterion-bound command the
#                         control must turn RED, supplied out of band the way the contract is.
#                         REQUIRED whenever ORCA_EXECUTE_NC is set (#279) — there is no fallback.
#                         The manifest and the `commands[]` ledger are both written by the graded
#                         worker, so neither can authorise the other; a unit never nominates the
#                         command that proves it.
#   ORCA_EXECUTE_NC       forwarded as --execute-nc: verify.py EXECUTES the negative control in a
#                         throwaway worktree at head_sha (RED under the control, green at clean head).
#                         REQUIRED whenever ORCA_NO_GH or ORCA_LIGHTING=dark-eligible is set — those
#                         lanes waive the review, leaving the control as the only oracle (#256).
# Without ORCA_CONTRACT_SOURCE/DIGEST the verifier fail-closes on scope (a manifest cannot certify
# its own denominator), so the gate blocks — as it should.
#
# Aliases: every input above also reads as OPEN_FLEET_<same suffix> (ORCA_MANIFEST also as
# OPEN_FLEET_GATE_MANIFEST / OPEN_FLEET_MANIFEST) — the neutral family docs/runtimes.md names.
# Either spelling may set an input; when two spellings are set and DISAGREE the gate BLOCKS
# (exit 2) instead of letting one silently win. The alias used to take precedence unannounced,
# so an inherited OPEN_FLEET_UNIT_CLASS or OPEN_FLEET_NO_GH overrode the coordinator's ORCA_*
# value — a class downgrade or a review waiver nobody set where they looked (2026-10-23 review, P3).
#
#   ORCA_GATE_TIMEOUT_S   seconds the verifier may run before the gate stops it and BLOCKS
#                         (default 2100; keep it below the host hook timeout, 2400 in hooks.json)
# Switch inputs (ORCA_NO_GH, ORCA_EXECUTE_NC) are read as values: on = 1|true|yes|on, off = unset,
# empty, 0|false|no|off; any other spelling BLOCKS.
#
# Exit: 0 = verified (allow) · 2 = a required invariant failed OR nothing to verify (BLOCK).
# Enterprise note: `allowManagedHooksOnly` can disable plugin hooks — see docs/verify-gate.md
# for the MCP-Task / CI / SDK-subprocess fallbacks that run the SAME verify.py.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# git and python3 are resolved ONCE, to absolute paths, the way verify.py pins its authorities
# (h409 R2): every later use runs that path, never a bare name a later PATH entry could shadow.
_abs() { case "$1" in /*) printf '%s\n' "$1" ;; "") : ;; *) printf '%s/%s\n' "$(pwd)" "$1" ;; esac; }
GIT_BIN=$(_abs "$(command -v git 2>/dev/null || true)")
PY_BIN=$(_abs "$(command -v python3 2>/dev/null || true)")
EVENT=""
if [ "${1:-}" = "--event" ]; then
  EVENT="${2:-}"
  [ -n "$EVENT" ] || { echo "verify-gate: --event needs a value" >&2; exit 2; }  # usage is 2, never a bare set -eu exit 1 (#382)
  shift 2
fi
# _pick NAME VALUE [NAME VALUE]... — the one value the named variables agree on (empty when none
# is set), or a BLOCK when two of them are set to different values. Each value is passed beside
# its name, so nothing is looked up by a constructed name.
_pick() {
  _val="" _from=""
  while [ "$#" -ge 2 ]; do
    _name=$1 _cur=$2
    shift 2
    [ -n "$_cur" ] || continue
    if [ -z "$_from" ]; then
      _val=$_cur _from=$_name
    elif [ "$_cur" != "$_val" ]; then
      echo "verify-gate: $_from and $_name are both set and disagree — BLOCKING (fail-closed: one" \
           "spelling must not silently override the other; set one)" >&2
      return 2
    fi
  done
  printf '%s' "$_val"
}
MANIFEST=$(_pick OPEN_FLEET_GATE_MANIFEST "${OPEN_FLEET_GATE_MANIFEST:-}" OPEN_FLEET_MANIFEST "${OPEN_FLEET_MANIFEST:-}" ORCA_MANIFEST "${ORCA_MANIFEST:-}") || exit 2
[ -n "$MANIFEST" ] || MANIFEST="${1:-}"
CONTRACT_SOURCE=$(_pick OPEN_FLEET_CONTRACT_SOURCE "${OPEN_FLEET_CONTRACT_SOURCE:-}" ORCA_CONTRACT_SOURCE "${ORCA_CONTRACT_SOURCE:-}") || exit 2
CONTRACT_DIGEST=$(_pick OPEN_FLEET_CONTRACT_DIGEST "${OPEN_FLEET_CONTRACT_DIGEST:-}" ORCA_CONTRACT_DIGEST "${ORCA_CONTRACT_DIGEST:-}") || exit 2
REPO=$(_pick OPEN_FLEET_REPO "${OPEN_FLEET_REPO:-}" ORCA_REPO "${ORCA_REPO:-}") || exit 2
BASE=$(_pick OPEN_FLEET_BASE "${OPEN_FLEET_BASE:-}" ORCA_BASE "${ORCA_BASE:-}") || exit 2
SYMBOL=$(_pick OPEN_FLEET_SYMBOL "${OPEN_FLEET_SYMBOL:-}" ORCA_SYMBOL "${ORCA_SYMBOL:-}") || exit 2
UNIT_CLASS=$(_pick OPEN_FLEET_UNIT_CLASS "${OPEN_FLEET_UNIT_CLASS:-}" ORCA_UNIT_CLASS "${ORCA_UNIT_CLASS:-}") || exit 2
NO_GH=$(_pick OPEN_FLEET_NO_GH "${OPEN_FLEET_NO_GH:-}" ORCA_NO_GH "${ORCA_NO_GH:-}") || exit 2
LIGHTING=$(_pick OPEN_FLEET_LIGHTING "${OPEN_FLEET_LIGHTING:-}" ORCA_LIGHTING "${ORCA_LIGHTING:-}") || exit 2
UNIT_LANE=$(_pick OPEN_FLEET_UNIT_LANE "${OPEN_FLEET_UNIT_LANE:-}" ORCA_UNIT_LANE "${ORCA_UNIT_LANE:-}") || exit 2
RECORD=$(_pick OPEN_FLEET_DISPATCH_RECORD "${OPEN_FLEET_DISPATCH_RECORD:-}" ORCA_DISPATCH_RECORD "${ORCA_DISPATCH_RECORD:-}") || exit 2
PUBKEY=$(_pick OPEN_FLEET_DISPATCH_PUBKEY "${OPEN_FLEET_DISPATCH_PUBKEY:-}" ORCA_DISPATCH_PUBKEY "${ORCA_DISPATCH_PUBKEY:-}") || exit 2
EXECUTE_NC=$(_pick OPEN_FLEET_EXECUTE_NC "${OPEN_FLEET_EXECUTE_NC:-}" ORCA_EXECUTE_NC "${ORCA_EXECUTE_NC:-}") || exit 2
# A lane switch is read as a VALUE, never as mere non-emptiness: `ORCA_NO_GH=false` used to switch
# the review waiver ON (2026-10-26 review). on: 1|true|yes|on; off: unset, empty, 0|false|no|off;
# anything else BLOCKS — a misspelled switch must not silently pick a lane.
_switch() {
  case "$2" in
    ""|0|[Ff][Aa][Ll][Ss][Ee]|[Nn][Oo]|[Oo][Ff][Ff]) : ;;
    1|[Tt][Rr][Uu][Ee]|[Yy][Ee][Ss]|[Oo][Nn]) printf '1' ;;
    *) echo "verify-gate: $1='$2' is not a switch value (on: 1|true|yes|on; off: unset|0|false|no|off) — BLOCKING (fail-closed)" >&2
       return 2 ;;
  esac
}
NO_GH=$(_switch NO_GH "$NO_GH") || exit 2
EXECUTE_NC=$(_switch EXECUTE_NC "$EXECUTE_NC") || exit 2
GATE_TIMEOUT=$(_pick OPEN_FLEET_GATE_TIMEOUT_S "${OPEN_FLEET_GATE_TIMEOUT_S:-}" ORCA_GATE_TIMEOUT_S "${ORCA_GATE_TIMEOUT_S:-}") || exit 2
[ -n "$GATE_TIMEOUT" ] || GATE_TIMEOUT=2100
case "$GATE_TIMEOUT" in
  ""|*[!0-9]*|0) echo "verify-gate: ORCA_GATE_TIMEOUT_S='$GATE_TIMEOUT' is not a positive integer of seconds — BLOCKING (fail-closed)" >&2; exit 2 ;;
esac
NC_COMMAND=$(_pick OPEN_FLEET_NC_COMMAND "${OPEN_FLEET_NC_COMMAND:-}" ORCA_NC_COMMAND "${ORCA_NC_COMMAND:-}") || exit 2
PROVENANCE=$(_pick OPEN_FLEET_PROVENANCE "${OPEN_FLEET_PROVENANCE:-}" ORCA_PROVENANCE "${ORCA_PROVENANCE:-}") || exit 2
# #135 key SOURCE: an injected ORCA_DISPATCH_PUBKEY (off-worker orchestrator) else the committed
# opt-in pin .orca/dispatch-pubkey — preferring the reviewed remote blob, falling back to the working
# tree — so a repo that follows the docs actually gets the check to RUN.
# Discovered in the TARGET repo — the toplevel of the cwd the gate runs in — because that is where
# verify.py reads the relative `.orca/dispatch-pubkey[@ref]` it is handed. Probing the plugin root
# ($HERE/../..) found a pin verify.py then looked for in another repo, and missed the target's own.
# A CI-shaped clone (actions/checkout) carries no refs/remotes/origin/HEAD, so the blob read used
# to miss and the gate fell through to the WORKING TREE — the PR's own checkout, where a worker
# replaces the pin with its own key and self-signs the record (2026-10-26 review). The blob is
# now also read at refs/remotes/origin/<BASE> when a base is named, and on a lane claiming
# soundness (ORCA_PROVENANCE set) the working-tree pin is never used: with no reviewed blob the
# key stays undiscovered, which verify.py reads as half-configured and refuses.
# W3-02 (2026-10-27 audit, P1): the ref is origin/HEAD's FULL target, and only a remote-tracking
# one counts. `symbolic-ref --short` printed the target's short form, so a worker that pointed
# origin/HEAD at its own LOCAL branch had the gate read `.orca/dispatch-pubkey@<that branch>` — a
# key it committed — and its self-signed record verified. A short name is also shadowable by a
# local tag or branch of the same spelling; the full refs/remotes/… name is not.
# W3-08: a fresh actions/checkout tree carries neither origin/HEAD nor origin/<BASE>, so with the
# working tree refused every sound CI run blocked as half-configured. Two ref-backed sources exist
# there: refs/remotes/origin/$GITHUB_BASE_REF when the step fetched the base, and the PR's base
# COMMIT from the runner's own event payload — an object id, which nothing can move. (The commit
# must be present: fetch-depth 0, or `git fetch origin <base sha>`; absent, nothing is read.)
_gh_pr_base() {
  [ "${GITHUB_ACTIONS:-}" = "true" ] && [ -n "$PY_BIN" ] && [ -f "${GITHUB_EVENT_PATH:-}" ] || return 1
  _sha=$("$PY_BIN" -I -c 'import json, sys
try:
    print(json.load(open(sys.argv[1], encoding="utf-8"))["pull_request"]["base"]["sha"])
except Exception:
    pass' "$GITHUB_EVENT_PATH" 2>/dev/null) || return 1
  case "$_sha" in ""|*[!0-9a-f]*) return 1 ;; esac
  [ "${#_sha}" -eq 40 ] || [ "${#_sha}" -eq 64 ] || return 1
  printf '%s' "$_sha"
}
# _dgit — git in the target repo for key DISCOVERY, with replacement objects and grafts off (the
# object-identity floor verify.py and gitexec.py read under): `git replace <reviewed> <other>`
# made `cat-file -e <ref>:.orca/dispatch-pubkey` see a pin the reviewed commit does not carry.
_dgit() { GIT_NO_REPLACE_OBJECTS=1 GIT_GRAFT_FILE=/dev/null "$GIT_BIN" -C "$TOP" "$@"; }
# _remote_target REF — REF followed through any symbolic chain to its FINAL target, printed only
# when every hop is a remote-tracking ref that EXISTS under exactly its name (W3-07: the rule
# gitexec.remote_tracking_commit holds for decisions.py, gate-batch.py, run_report.py and
# verify.py, mirrored here in sh). A refs/remotes/… NAME proves nothing: it can be a symbolic ref
# to a local branch the worker moves (PR #719 review), and with the remote-tracking ref ABSENT,
# `cat-file -e refs/remotes/origin/HEAD:…` expands the name to the LOCAL branch
# refs/heads/refs/remotes/origin/HEAD (Codex review) — so each hop is looked up in one
# `for-each-ref refs/remotes/` listing, by exact name, and never handed to git to expand; a
# revision suffix (origin/$BASE = main~1, @{1}) is no ref name at all. The listing's %(symref) is
# the chain's recursively resolved END, which hid a local bridge (origin/HEAD -> refs/heads/bridge
# -> refs/remotes/origin/<old key>; Codex review round 2), so each symbolic hop is read on its own
# with `symbolic-ref --no-recurse` (git 2.39+; where it cannot be, the name is refused). verify.py resolves what it
# is handed again, once, under the same rule, to the commit it reads the key at. Remote-tracking
# means "what this clone's fetch wrote" — the coordinator's or the CI runner's on a sound lane; on
# a worker's own machine any ref is the worker's to write, which is why that lane stays advisory.
_remote_target() {
  _rt_refs=$(_dgit for-each-ref --format='%(refname) %(symref)' refs/remotes/ 2>/dev/null) || _rt_refs=
  _t=$1
  _rt_hops=0
  while :; do
    case "$_t" in
      refs/remotes/?*) ;;
      *) echo "verify-gate: NOTE — $1 points at '$_t', which is not a remote-tracking ref; no key is read there (a local branch is the graded worker's to move)." >&2
         return 1 ;;
    esac
    if ! "$GIT_BIN" check-ref-format "$_t" 2>/dev/null; then
      echo "verify-gate: NOTE — '$_t' is not a valid ref name (a revision suffix such as ~1 or @{1} names an older commit, not a ref); no key is read there." >&2
      return 1
    fi
    _rt_entry=$(printf '%s\n' "$_rt_refs" | while read -r _rt_name _rt_sym; do
      if [ "$_rt_name" = "$_t" ]; then printf '=%s' "$_rt_sym"; break; fi
    done)
    if [ -z "$_rt_entry" ]; then
      # $1 itself absent is the ordinary CI shape (no origin/HEAD): nothing to say. A hop that
      # names an absent ref is said, since git would have expanded it to a local branch.
      [ "$_t" = "$1" ] || echo "verify-gate: NOTE — $1 points at '$_t', and no remote-tracking ref of exactly that name exists; no key is read there (git's ref-name expansion to refs/heads/$_t is never followed)." >&2
      return 1
    fi
    _rt_entry=${_rt_entry#=}
    [ -n "$_rt_entry" ] || break
    # Non-empty: $_t is symbolic. Its NEXT hop, not the chain's end the listing shows.
    if ! _rt_entry=$(_dgit symbolic-ref -q --no-recurse "$_t" 2>/dev/null) || [ -z "$_rt_entry" ]; then
      echo "verify-gate: NOTE — $1 reaches the symbolic ref '$_t', whose chain cannot be read one hop at a time here (symbolic-ref --no-recurse needs Git 2.39+); no key is read there." >&2
      return 1
    fi
    _rt_hops=$((_rt_hops + 1))
    if [ "$_rt_hops" -gt 5 ]; then
      echo "verify-gate: NOTE — $1 is a symbolic-ref chain longer than 5 hops; no key is read there." >&2
      return 1
    fi
    _t=$_rt_entry
  done
  printf '%s' "$_t"
}
KEY_BASE="$BASE"
[ -n "$KEY_BASE" ] || [ "${GITHUB_ACTIONS:-}" != "true" ] || KEY_BASE="${GITHUB_BASE_REF:-}"
if [ -z "$PUBKEY" ] && [ -n "$GIT_BIN" ]; then
  TOP="$("$GIT_BIN" rev-parse --show-toplevel 2>/dev/null || true)"
  if [ -n "$TOP" ]; then
    PR_BASE="$(_gh_pr_base || true)"
    DEF_REF="$(_remote_target refs/remotes/origin/HEAD || true)"
    BASE_REF=""
    [ -z "$KEY_BASE" ] || BASE_REF="$(_remote_target "refs/remotes/origin/$KEY_BASE" || true)"
    if [ -n "$DEF_REF" ] && _dgit cat-file -e "$DEF_REF:.orca/dispatch-pubkey" 2>/dev/null; then
      PUBKEY=".orca/dispatch-pubkey@$DEF_REF"
    elif [ -n "$BASE_REF" ] && _dgit cat-file -e "$BASE_REF:.orca/dispatch-pubkey" 2>/dev/null; then
      PUBKEY=".orca/dispatch-pubkey@$BASE_REF"
    elif [ -n "$PR_BASE" ] && _dgit cat-file -e "$PR_BASE:.orca/dispatch-pubkey" 2>/dev/null; then
      PUBKEY=".orca/dispatch-pubkey@$PR_BASE"
    elif [ -f "$TOP/.orca/dispatch-pubkey" ]; then
      if [ -n "$PROVENANCE" ]; then
        echo "verify-gate: NOTE — .orca/dispatch-pubkey exists only in the working tree, which the graded worker writes; a lane claiming soundness (ORCA_PROVENANCE=$PROVENANCE) does not read a key from there. Pin it on the default or base branch, or inject ORCA_DISPATCH_PUBKEY off-worker." >&2
      else
        PUBKEY=".orca/dispatch-pubkey"
      fi
    fi
  fi
fi
# This does NOT make the native in-session path sound: the worker controls ORCA_PROVENANCE, any env
# key, and `origin`/local refs, so no in-session key is trustworthy (the #112 result). The record's
# real value is OFF-WORKER — CI/MCP/SDK or an auditor re-runs verify.py with the coordinator's REAL
# key and detects any substitution. Soundness is a property of WHERE this runs (see the note below).

if [ -z "$MANIFEST" ]; then
  # Stop fires on EVERY turn end; a turn with no unit in progress (manifest unset) has nothing to
  # verify — allow it. TaskCompleted with no manifest is a mis-dispatch — fail closed.
  if [ "$EVENT" = "stop" ]; then
    echo "verify-gate: Stop with no unit in progress (ORCA_MANIFEST unset) — nothing to verify, allowing" >&2
    exit 0
  fi
  echo "verify-gate: no evidence manifest (ORCA_MANIFEST unset) — BLOCKING (fail-closed)" >&2
  exit 2
elif [ ! -f "$MANIFEST" ]; then
  # A NAMED manifest that does not exist means an active unit's evidence is missing (deleted, mistyped,
  # or unavailable) — never allow the turn to end on it, even on Stop.
  echo "verify-gate: evidence manifest named but missing: $MANIFEST — BLOCKING (fail-closed)" >&2
  exit 2
fi

set -- --manifest "$MANIFEST"
[ -n "$CONTRACT_SOURCE" ] && set -- "$@" --contract-source "$CONTRACT_SOURCE"
[ -n "$CONTRACT_DIGEST" ] && set -- "$@" --contract-digest "$CONTRACT_DIGEST"
[ -n "$REPO" ] && set -- "$@" --repo "$REPO"
[ -n "$BASE" ] && set -- "$@" --base "$BASE"
[ -n "$SYMBOL" ] && set -- "$@" --symbol "$SYMBOL"
[ -n "$UNIT_CLASS" ] && set -- "$@" --unit-class "$UNIT_CLASS"
[ -n "$NO_GH" ] && set -- "$@" --no-gh
[ -n "$LIGHTING" ] && set -- "$@" --lighting "$LIGHTING"
[ -n "$UNIT_LANE" ] && set -- "$@" --lane "$UNIT_LANE"
[ -n "$RECORD" ] && set -- "$@" --dispatch-record "$RECORD"
[ -n "$PUBKEY" ] && set -- "$@" --dispatch-pubkey "$PUBKEY"
[ -n "$EXECUTE_NC" ] && set -- "$@" --execute-nc
[ -n "$NC_COMMAND" ] && set -- "$@" --nc-command "$NC_COMMAND"
# h409 F-1/F-2: verify.py learns the lane too, so a sound lane's review authority (an explicit
# repo, a gh outside any worker-writable location) is REQUIRED there, not merely noted here.
[ -n "$PROVENANCE" ] && set -- "$@" --provenance "$PROVENANCE"

# #279: say it here rather than let the operator read it out of verify.py's invariant list. The
# refusal itself is verify.py's — this is a signpost, never the check.
if [ -n "$EXECUTE_NC" ] && [ -z "$NC_COMMAND" ]; then
  echo "verify-gate: NOTE — ORCA_EXECUTE_NC is set without ORCA_NC_COMMAND. The executed control" \
       "needs the criterion-bound command from OFF the worker; the manifest cannot supply it." >&2
fi

# Trust boundary (#112, #135): soundness is a property of the EXECUTION CONTEXT, not of an env var the
# worker can set. A signed dispatch record is verified (defense-in-depth in-session; a real boundary
# only off-worker with a trusted key).
case "$PROVENANCE" in
  ci|mcp|sdk|dispatch) : ;;  # off-worker context sets the env AND the key — sound; record is auditable
  *) echo "verify-gate: NOTE — native in-session hook is ADVISORY: the worker controls ORCA_* (incl." \
          "ORCA_PROVENANCE and any dispatch key) and every ref in its clone — refs/remotes/* too, so" \
          "a remote-tracking or commit key pin is trustworthy only where the worker cannot write" \
          "refs (the coordinator's own fetch, a CI checkout) — so nothing here is a soundness boundary. A signed" \
          "ORCA_DISPATCH_RECORD is verified, but is a boundary only OFF-WORKER — CI/MCP/SDK or an" \
          "auditor re-running verify.py with the coordinator's real key — docs/verify-gate.md#trust-boundary." >&2 ;;
esac

# Any nonzero from verify.py (2 = invariant failed, 1 = usage/dep) is a BLOCK: an un-runnable or
# failing verifier is never a green light. Capture the REAL exit in the else branch — `$?` after a
# bare `fi` is the if-statement's status (0 when the condition fails with no else), not verify.py's.
if [ -z "$PY_BIN" ]; then
  echo "verify-gate: python3 not on PATH — cannot run the verifier, BLOCKING (fail-closed)" >&2
  exit 2
fi
# Claude Code cancels a command hook at its timeout (600 s by default) and DISCARDS its output, and
# on Stop / TaskCompleted only exit 2 blocks — so a verifier still replaying the negative control
# (up to 3 × 600 s) when the host gave up let the turn end: fail-OPEN. The gate therefore bounds
# the verifier itself, below the host's limit (hooks/hooks.json and the snippet set 2400 s): at
# the deadline the verifier is stopped and the gate BLOCKS (2026-10-26 review).
# -I (W3-01): without it the interpreter puts $HERE at sys.path[0], ahead of the stdlib, and a
# committed runtime/scripts/json.py became the verifier's `json` — a RED verdict turned GREEN,
# bound by no toolchain hash. verify.py drops that entry itself too; -I also keeps PYTHON* env
# and the user site out of the verdict.
"$PY_BIN" -I "$HERE/verify.py" "$@" &
_vpid=$!
_waited=0
while kill -0 "$_vpid" 2>/dev/null; do
  if [ "$_waited" -ge "$GATE_TIMEOUT" ]; then
    kill "$_vpid" 2>/dev/null || true
    sleep 1
    kill -9 "$_vpid" 2>/dev/null || true
    wait "$_vpid" 2>/dev/null || true
    echo "verify-gate: the verifier ran past ${GATE_TIMEOUT}s (ORCA_GATE_TIMEOUT_S) and was stopped — BLOCKING (fail-closed: a verdict that never arrived is not a pass; the host would have discarded a timed-out hook and let the turn end)" >&2
    exit 2
  fi
  sleep 1
  _waited=$((_waited + 1))
done
rc=0
wait "$_vpid" || rc=$?
[ "$rc" -eq 0 ] && exit 0
echo "verify-gate: verifier returned $rc — BLOCKING completion" >&2
exit 2
