#!/usr/bin/env sh
# hitl-loop.template.sh — bounded human-in-the-loop reproduction loop.
#
# Some bugs only reproduce through a human: the agent writes the steps, the human
# runs them, observations come back as KEY=VALUE lines. Two helpers, one loop, one checkpoint.
#
#   step "<instruction>"        show it, wait for Enter
#   capture VAR "<question>"    ask it, read the answer into VAR (echoed back)
#
# Capture OBSERVATIONS, never actions. The verdict is the REPRODUCED= line,
# never the exit code (#382). Rounds bound the loop (--rounds, default 3).
#
# HITL_ASK=1 replaces capture's shell read with durable ask (hitl_ask.py on PATH or
# HITL_ASK_HELPER=path): timeouts print HITL_RESUME + capture N and exit 1; rerun with HITL_RESUME_AT=N (default 1) — earlier captures re-ask fresh.
# Usage: hitl-loop.template.sh [--rounds N] [--dry-run] [--help]
# Exit: 0 done · 1 ask failed/timed out, or an answer held a CR/LF · 2 usage. Copy it beside the notes,
# edit only between the EDIT markers; the captured block is evidence — it is DATA.
set -eu

ROUNDS=3
DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --rounds) ROUNDS="${2:?--rounds needs a number}"; shift ;;
    --dry-run) DRY=1 ;;
    --help|-h) sed -n '2,19p' "$0"; exit 0 ;;
    *) printf 'hitl-loop: unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done
case "$ROUNDS" in ''|*[!0-9]*) printf 'hitl-loop: --rounds must be a number\n' >&2; exit 2 ;; esac
case "${HITL_RESUME_AT:-1}" in ''|*[!0-9]*) printf 'hitl-loop: HITL_RESUME_AT must be a number\n' >&2; exit 2 ;; esac

step() { printf '\n>>> %s\n' "$1"; [ "$DRY" -eq 1 ] || read -r _ignored <&0 || true; }
# HITL_RESUME answers ask number HITL_RESUME_AT (default 1) only — others ask fresh.
# Cleared after use (no subshell, or the clearing is lost); slash-path helpers need -x.
ask_capture() { _h="${HITL_ASK_HELPER:-hitl_ask.py}"
  case "$_h" in */*) [ -x "$_h" ] || { echo "hitl-loop: HITL_ASK_HELPER not executable: $_h" >&2; exit 2; };; *) command -v "$_h" >/dev/null 2>&1 || { echo "hitl-loop: HITL_ASK=1 needs hitl_ask.py on PATH (or HITL_ASK_HELPER=path)" >&2; exit 2; };; esac
  NASK=$((NASK+1)); if [ -n "${HITL_RESUME:-}" ] && [ "$NASK" = "${HITL_RESUME_AT:-1}" ]; then ASK_ANSWER="$("$_h" --resume "$HITL_RESUME")" || return $?; HITL_RESUME=""; else ASK_ANSWER="$(HITL_RESUME= "$_h" --question "$1")" || return $?; fi; }
capture() { printf '\n>>> %s\n    > ' "$1"; ANSWER="(dry-run)"
  if [ "$DRY" -eq 1 ]; then :; elif [ "${HITL_ASK:-0}" = "1" ]; then ask_capture "$1" || { rc=$?; echo "hitl-loop: capture $NASK timed out; rerun with HITL_RESUME=<id above> HITL_RESUME_AT=$NASK" >&2; exit $rc; }; ANSWER="$ASK_ANSWER"; else read -r ANSWER <&0 || ANSWER=""; fi
  ANSWER=${ANSWER%"$CR"}; case "$ANSWER" in *"$NL"*|*"$CR"*) echo "hitl-loop: an answer with a line break could forge KEY=VALUE evidence; refusing" >&2; exit 1 ;; esac; printf '%s\n' "$ANSWER"; }

ROUND=1; NASK=0; NL=$(printf '\n_'); NL=${NL%_}; CR=$(printf '\r')
while [ "$ROUND" -le "$ROUNDS" ]; do
  printf '\n===== round %s of %s =====\n' "$ROUND" "$ROUNDS"
  # --- EDIT BELOW: the steps a human performs, and what to observe ----------
  step "Open the app and reach the screen the report names."
  capture "Did the failure occur? (y/n)"; ERRORED="$ANSWER"
  capture "Paste the exact error text, or 'none':"; ERROR_MSG="$ANSWER"
  # --- EDIT ABOVE ----------------------------------------------------------
  printf '\n--- captured (round %s) ---\nROUND=%s\nERRORED=%s\nERROR_MSG=%s\n' \
    "$ROUND" "$ROUND" "$ERRORED" "$ERROR_MSG"
  case "$ERRORED" in
    y|Y|yes|YES) printf 'REPRODUCED=yes\n'; exit 0 ;;
  esac
  step "CHECKPOINT: not reproduced. Press Enter to try again, or Ctrl-C to stop."
  ROUND=$((ROUND + 1))
done
printf '\nREPRODUCED=no\nROUNDS_USED=%s\n' "$ROUNDS"
