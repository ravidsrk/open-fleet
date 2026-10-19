#!/usr/bin/env bash
# spawn_worker.sh — fail-closed Orca worker dispatch for fleet coordinators. (v5)
#
# Base v5 contract (2026-09-10 upstream re-pin), source-witnessed at v1.4.199. The custom-lane
# recovery correction below uses the Orca 1.4.200 receipt and source witness (release E2).
# Re-witnessed at v1.4.203 (pin-it #416, 2026-09-16 — docs/runs/2026-09-16-pin-it-416/): YOLO map,
# release contract, readiness turn-start, refusal codes, keepalive shape — all hold at the build commit.
#   - supervised lane = `worker-start` (compose: worktree + agent terminal + readiness + dispatch).
#     READINESS SEMANTIC: at v1.4.199 `ready` means the preamble WRITE WAS ACCEPTED, not that the
#     agent started a turn (`local-worker-start.ts:263` marks the dispatch ready straight after the
#     accepted write). v1.4.200 flipped this to a positive `turn_started`, returning
#     `state: outcome_unknown` otherwise — which is why exit 4 exists below. Readiness per agent
#     is source-witnessed at v1.4.199
#     (`local-worker-start.ts:243-263`); live probe owed — pin-it.
#   - typed refusals: branch on `error.code`, NEVER on stderr text, and print `error.data.nextSteps`
#     verbatim — that array is the runtime's own recovery text
#     (`orchestration-dispatch-refusal-contract.ts:8`,
#     `orchestration/recovery-and-cleanup:96-108`).
#   - `state: outcome_unknown` is NOT a failure: it is an unproven outcome. Exit 4, print the
#     receipt's `nextCommands`, and INSPECT — never respawn (respawning beside a live pane is the
#     dual-writer class) (`worker-start-receipt.ts:48,60-68`).
#   - Exit 5 = LAUNCHED_UNUSABLE: the start succeeded, so a worker IS live, but `launch.effective`
#     does not prove the PROFILE's flag was applied — it lacks the flag, or the host omitted the
#     field entirely. Not a failure (something started) and not unknown (we know it did): STOP the
#     worker, never respawn beside it, then fix the host (sandbox-policy.md:16-20).
#   - custom-argv lane = `terminal create` + `dispatch --inject`. The inject ALREADY SUBMITS the
#     preamble (`dispatch-methods.ts:155-165` calls `sendTerminalAgentPrompt`) and `--json` returns
#     `result.prompt{requestId, stages}`, stages drawn from `input_accepted | turn_started`
#     (`src/shared/runtime-terminal-contracts.ts:221-225`). v4's blind re-Enter/heartbeat loop is DELETED:
#     the guide's rule is "never resend on silence"
#     (`orchestration/recovery-and-cleanup:92-94`). Without `turn_started`, report UNPROVEN and
#     retain the injection receipt. Orca 1.4.200 rejects a terminal-send retry of a dispatch
#     request as `request_mismatch`: durable mutation identity binds the METHOD and payload
#     (`orchestration-mutation-executor.ts:65-80`). `dispatch-show --preamble` regenerates a
#     preview without the original capability; it is not the accepted payload. Even the original
#     text from `dispatch --return-preamble` cannot change the method bound to that request ID.
#     There is no supported cross-method wait-submit replay here; inspect without resending.
#   - `terminal wait` result is READ: `wait.satisfied:false` is an unsatisfied condition. The CLI
#     also sets exit 1 for it (`terminal.ts:125-129` at v1.4.203), so v4 failed closed BY ACCIDENT; v5 reads
#     the field, so a host that sets only one of the two still fails closed.
#   - PROFILE=ro NEVER takes worker-start: launch args come from the host's `agentDefaultArgs`
#     profile setting, whose migrated default IS the YOLO map (`tui-agent-launch-defaults.ts:10`
#     re-exports `YOLO_TUI_AGENT_ARGS` as `DEFAULT_TUI_AGENT_ARGS`), so a default host would
#     silently upgrade a read-only reviewer to a bypass one. A host set to manual mode has `''`
#     instead — the rationale is host-dependent, not universal. `agentDefaultArgs` is
#     source-witnessed at v1.4.203 (`tui-agent-launch-defaults.ts:10`); live probe owed — pin-it.
#   - `launch.effective` from the worker-start receipt is printed when present: never claim a model,
#     effort, or permission flag from the REQUESTED arguments alone
#     (`orchestration/coordinator-loop:23-36`).
#   - fail-closed: any failed step exits nonzero with a SPAWN=FAILED diagnostic line on stderr
#   - respects the task DAG: never forces `ready`; `--mark-ready` is an explicit opt-in and
#     only applies when every declared dep is already completed
#   - least-privilege launch profiles: PROFILE=ro|rw|danger; danger is refused until authoritative
#     prelaunch placement binding to the validated disposable sandbox is supported.
#   - distinct exit codes so coordinators can react:
#       0  dispatched — supervised: state=ready; custom-argv: `turn_started` observed
#       1  a spawn/dispatch step failed (includes the refusal code `runtime_error`)
#       2  usage or policy refusal (bad args, task not ready, unmet deps, danger without opt-in,
#          and EVERY typed refusal code: task_not_found, task_not_startable, inject_rejected,
#          nested_worker_depth_exceeded, consumer_fenced, dispatch_inactive)
#       3  (custom-argv lane only) preamble accepted but the turn is UNPROVEN — `input_accepted`
#          with no `turn_started`. Inspect with `orca terminal read --terminal <h> --screen`;
#          NEVER respawn on this, and never send another Enter.
#       4  supervised state=outcome_unknown — the start neither proved nor disproved the worker.
#          Run the receipt's nextCommands (worker-show / worker-abandon); inspect, never respawn.
#
# Usage:
#   SP=<dir> [PROFILE=rw] spawn_worker.sh [options] (<task_id> <worktree_selector> | --spec <text> <worktree_selector>) <title> [agent] [effort]
#   agent ∈ claude|codex|cursor|gemini|grok|droid|opencode|omp|pi|antigravity (default claude)
# Options:
#   --mark-ready               opt-in: mark a pending task ready when deps are complete
#   --timeout-ms <n>           worker-start timeout, positive int (supervised lane only)
#   --run <id> --from <handle> Run/sender binding for task-list, task-update,
#                              task-create, worker-start, and dispatch --inject
#   --retry-of <dispatch_id>   retry a failed dispatch (needs --task; refused with --spec)
#   --retry-request <id>       durable mutation id for worker-start ONLY (one id, one
#                              mutation), plus request-show triage of an unknown outcome
#   --on <saved-environment>   worker server for worker-start (refused with current/
#                              new-child selectors; live use PARKED — needs a paired server)
#   --environment <e> --pairing-code <c>
#                              GLOBAL routing: ride every orca call. A flag that disagrees
#                              with ambient ORCA_ENVIRONMENT/ORCA_PAIRING_CODE is refused.
#                              --host is REFUSED here: it is an unknown flag on orchestration
#                              verbs upstream (args.ts), valid only on worktree create et al.
#   --cli-cwd <abs-dir>        exported as ORCA_CLI_CWD (SSH-relay cwd override); absolute
#                              directory, refused on ambient disagreement. Live PARKED.
#   --task-brief               pass --brief on the spawn-time task-list read. --task-status
#                              / --task-ready are REFUSED: a filtered view cannot verify deps.
#   --spec <text> [--task-title <t>] [--deps <json_array>] [--parent <id>]
#                              create the task first (task-create), then run the normal
#                              verified path with the created id. The fleet DAG check needs
#                              the id upfront, so --spec is never passed to worker-start.
#                              --task-title/--deps/--parent without --spec are refused.
# Prints:  SCRATCH=<per-attempt receipt directory>, then
#          supervised: HANDLE=<h> READY=<state>, DISPATCH=<id>, and LAUNCH_EFFECTIVE=<json> when the
#          receipt carries it.  custom-argv lane: HANDLE=<h> STAGES=<csv>
#
# Agent × profile coverage (flags are Orca's own autonomous "yolo" args from
# `tui-agent-permissions.ts:6-33`, so workers never block on a prompt; anything else fails closed
# and needs WORKER_CMD):
#   claude/codex/gemini → ro + rw + danger
#   cursor              → rw + danger (`tui-agent-permissions.ts` maps cursor to `--yolo`;
#                         ro → WORKER_CMD). `--model` is accepted at the PIN for claude, codex,
#                         cursor, antigravity, muse (since v1.4.215, 52a1e2875b #22383), and —
#                         new in the 215→224 range — omp and opencode: their catalogs gained
#                         supportsWorkerLaunchPreferences + launchArgs (opencode additionally
#                         requires an existing worktree and a TUI that can verify the selection,
#                         worker-launch-preferences.ts:73-86 at v1.4.224). gemini/grok carry
#                         catalogs WITHOUT the flag, and pi/droid/kilo carry NO catalog at all,
#                         so those reject --model ("does not support launch-time model
#                         selection", worker-launch-preferences.ts). --effort requires --model
#                         plus a catalog effort option for that model, and both are passed only
#                         when the user named a model; this script omits both so the worker
#                         inherits the configured default.
#   antigravity         → rw + danger. `--agent antigravity`; the binary is `agy`
#                         (`tui-agent-config.ts` detectCmd) plus
#                         `--dangerously-skip-permissions`. ro → WORKER_CMD
#   grok                → rw + danger (Orca has no read-only mode for grok)
#   droid               → rw + danger (Orca appends `--auto high`); ro → WORKER_CMD
#   opencode/omp/pi     → WORKER_CMD. opencode AND kilo are actively STRIPPED of
#                         `--dangerously-skip-permissions` (`tui-agent-launch-defaults.ts:5-8`);
#                         kilo stays off this roster for the same reason opencode fails closed.
# rw and danger use the SAME non-blocking flag; danger only adds the ALLOW_DANGER gate + the
# ephemeral-sandbox requirement (sandbox-policy.md). worker-start's `--effort` requires `--model`
# (a provider model id the fleet does not pin) — the validated `effort` arg applies on the
# override lane's launch command; the supervised path takes the agent's configured default.
#
# NOTE: <worktree_selector> is a RAW orca selector. A worktree id is the composite
#   `<repoId>::<worktreePath>` from `worktree create --json` — pass `path:/abs/worktree/path`
#   (unambiguous) or that full id. See runtime/dispatch-lifecycle.md.
#
# Env:
#   SP                        parent dir for retained per-attempt JSON artifacts (default: cwd)
#   PROFILE                   ro | rw (default) | danger — worker permission profile
#   ORCA_COORD_ALLOW_AUTONOMOUS_WRITE  must be 1 for PROFILE=rw (accept autonomous bypass workers)
#   ORCA_DENY_HOOK_SETTINGS   settings file registering deny-hook.sh for workers; named →
#                             verified armed (registration + live deny probe) or the spawn
#                             refuses; unset → spawn proceeds with an UNVERIFIED warning
#   ORCA_COORD_ALLOW_DANGER   must be 1 for PROFILE=danger (implies the above + ephemeral sandbox)
#   ORCA_SANDBOX_RECIPE       PROFILE=danger only: the orca-per-workspace-env recipe id the lane
#                             runs in. Required — the opt-in above is intent, this is evidence.
#   ORCA_SANDBOX_DOCTOR       PROFILE=danger only, and an OUTPUT path since #283: where this
#                             script WRITES the `vm recipe doctor <id>` transcript it
#                             ran itself, for the lane ledger. Optional; an unwritable path is a
#                             refusal. It is no longer an input — a transcript the caller names is
#                             not evidence (/etc/passwd passed the old grep).
#   WORKER_CMD                full launch command for ANY agent (the generic override; its
#                             read-only/write semantics become YOUR assertion). Legacy
#                             CLAUDE_CMD / CODEX_CMD still work for those two. Any override
#                             requires ORCA_COORD_ALLOW_CMD_OVERRIDE=1 (it bypasses the profile).
#   SETTLE_SECS               TUI settle delay (default 20 seconds) — custom-argv lane.
set -Eeuo pipefail  # -E: ERR trap fires inside functions (orca_json) too
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"  # sibling scripts (sandbox_doctor.py)
# The CLI command name, resolved the way upstream documents it (#510): ORCA_CLI_COMMAND when set,
# else orca-dev in a dev checkout, else orca-ide on Linux (bare `orca` there is the GNOME screen
# reader), else orca. One resolver for every fleet script: runtime/scripts/orca_cli.py.
ORCA_BIN="$(python3 "$HERE/orca_cli.py")"

step=parse-args
task="?"
trap 'rc=$?; echo "SPAWN=FAILED task=${task} step=${step} rc=${rc}" >&2; exit "${rc}"' ERR

# orca_json <outfile> <orca-args...> — run orca with --json, fail on nonzero exit
# OR on an exit-0 error envelope ({"error": ...}); fail-closed for every step.
orca_json() {
  local out="$1"; shift
  "$ORCA_BIN" "$@" --json > "$out"
  python3 - "$out" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
err = None
if isinstance(d, dict):
    err = d.get("error")
    res = d.get("result")
    if not err and isinstance(res, dict):
        err = res.get("error")
if err:
    print(f"orca error envelope: {err}", file=sys.stderr)
    raise SystemExit(1)
PY
}

MARK_READY=0
TASK_BRIEF=0
TASK_READY_FILTER=0
TASK_STATUS_FILTER=""
SPEC_GIVEN=0; SPEC=""
TITLE_GIVEN=0; TASK_TITLE=""
DEPS_GIVEN=0; DEPS=""
PARENT_GIVEN=0; PARENT=""
TIMEOUT_GIVEN=0; TIMEOUT_MS=""
RUN_GIVEN=0; RUN_ID=""
FROM_GIVEN=0; FROM_HANDLE=""
RETRY_OF_GIVEN=0; RETRY_OF=""
RETRY_REQ_GIVEN=0; RETRY_REQUEST=""
ON_GIVEN=0; ON_ENV=""
ENV_GIVEN=0; ROUTE_ENV=""
PAIRING_GIVEN=0; ROUTE_PAIRING=""
CWD_GIVEN=0; CLI_CWD=""
HOST_GIVEN=0; HOST_FLAG=""
PARENT_PROFILE_GIVEN=0; PARENT_PROFILE=""
args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --mark-ready) MARK_READY=1; shift ;;
    --task-brief) TASK_BRIEF=1; shift ;;
    --task-ready) TASK_READY_FILTER=1; shift ;;
    --timeout-ms|--run|--from|--retry-of|--retry-request|--on|--environment|--pairing-code|--cli-cwd|--task-status|--spec|--task-title|--deps|--parent|--host|--parent-profile)
      flag="$1"
      if [ $# -lt 2 ]; then
        echo "SPAWN=REFUSED task=? ${flag} needs a value" >&2
        exit 2
      fi
      case "$flag" in
        --timeout-ms) TIMEOUT_GIVEN=1; TIMEOUT_MS="$2" ;;
        --run) RUN_GIVEN=1; RUN_ID="$2" ;;
        --from) FROM_GIVEN=1; FROM_HANDLE="$2" ;;
        --retry-of) RETRY_OF_GIVEN=1; RETRY_OF="$2" ;;
        --retry-request) RETRY_REQ_GIVEN=1; RETRY_REQUEST="$2" ;;
        --on) ON_GIVEN=1; ON_ENV="$2" ;;
        --environment) ENV_GIVEN=1; ROUTE_ENV="$2" ;;
        --pairing-code) PAIRING_GIVEN=1; ROUTE_PAIRING="$2" ;;
        --cli-cwd) CWD_GIVEN=1; CLI_CWD="$2" ;;
        --task-status) TASK_STATUS_FILTER="$2" ;;
        --spec) SPEC_GIVEN=1; SPEC="$2" ;;
        --task-title) TITLE_GIVEN=1; TASK_TITLE="$2" ;;
        --deps) DEPS_GIVEN=1; DEPS="$2" ;;
        --parent) PARENT_GIVEN=1; PARENT="$2" ;;
        --host) HOST_GIVEN=1; HOST_FLAG="$2" ;;
        --parent-profile) PARENT_PROFILE_GIVEN=1; PARENT_PROFILE="$2" ;;
      esac
      shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
spawn_usage() {
  echo "usage: [PROFILE=ro|rw|danger] spawn_worker.sh [options] (<task_id> <worktree_selector> | --spec <text> <worktree_selector>) <title> [agent] [effort]" >&2
  exit 2
}
# Tentative positional read so refusals below name the task; the STRICT count check follows
# validation, so a bad FLAG refuses as a flag error (SPAWN=REFUSED) even when miscounting
# positionals is what the bad flag caused. Inline creation (--spec) has no positional task id:
# positionals are <worktree_selector> <title> [agent] [effort], and the created id fills
# `task` at the task-create step, before any verification reads it.
if [ "$SPEC_GIVEN" = "1" ]; then
  task=""; sel="${args[0]:-}"; title="${args[1]:-}"; agent="${args[2]:-claude}"; effort="${args[3]:-xhigh}"
else
  task="${args[0]:-}"; sel="${args[1]:-}"; title="${args[2]:-}"; agent="${args[3]:-claude}"; effort="${args[4]:-xhigh}"
fi
# Every new flag is validated HERE, before scratch allocation or any orca call: a refusal
# below must leave zero side effects (the tests assert an empty orca call log).
tname="${task:-?}"
if [ "$SPEC_GIVEN" = "1" ] && [ -z "$SPEC" ]; then
  echo "SPAWN=REFUSED task=${tname} --spec needs a non-empty spec" >&2
  exit 2
fi
if [ "$TITLE_GIVEN" = "1" ] && [ -z "$TASK_TITLE" ]; then
  echo "SPAWN=REFUSED task=${tname} --task-title needs a non-empty value" >&2
  exit 2
fi
if [ "$PARENT_GIVEN" = "1" ] && [ -z "$PARENT" ]; then
  echo "SPAWN=REFUSED task=${tname} --parent needs a non-empty task id" >&2
  exit 2
fi
if { [ "$TITLE_GIVEN" = "1" ] || [ "$DEPS_GIVEN" = "1" ] || [ "$PARENT_GIVEN" = "1" ]; } && [ "$SPEC_GIVEN" != "1" ]; then
  echo "SPAWN=REFUSED task=${tname} --task-title/--deps/--parent need --spec (without it they would be silently dropped)" >&2
  exit 2
fi
if [ "$DEPS_GIVEN" = "1" ]; then
  if ! printf '%s' "$DEPS" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if isinstance(d,list) and all(isinstance(x,str) for x in d) else 1)' 2>/dev/null; then
    echo "SPAWN=REFUSED task=${tname} --deps must be a JSON array of task-id strings" >&2
    exit 2
  fi
fi
if [ "$RETRY_OF_GIVEN" = "1" ] && [ "$SPEC_GIVEN" = "1" ]; then
  echo "SPAWN=REFUSED task=${tname} --retry-of needs --task naming the failed task (--spec creates a new one)" >&2
  exit 2
fi
if [ "$TIMEOUT_GIVEN" = "1" ]; then
  # Digits, ≤15 chars (fits int64 with room), and ≥1 — the shell spelling of
  # upstream getOptionalPositiveIntegerValueFlag.
  TIMEOUT_OK=""
  case "$TIMEOUT_MS" in
    ""|*[!0-9]*) : ;;
    *)
      if [ "${#TIMEOUT_MS}" -le 15 ] && [ "$TIMEOUT_MS" -ge 1 ] 2>/dev/null; then
        TIMEOUT_OK=1
      fi ;;
  esac
  if [ -z "$TIMEOUT_OK" ]; then
    echo "SPAWN=REFUSED task=${tname} --timeout-ms must be a positive integer, got '${TIMEOUT_MS}'" >&2
    exit 2
  fi
fi
for pair in "RUN_GIVEN:$RUN_ID:--run" "FROM_GIVEN:$FROM_HANDLE:--from" \
            "RETRY_OF_GIVEN:$RETRY_OF:--retry-of" "RETRY_REQ_GIVEN:$RETRY_REQUEST:--retry-request" \
            "ON_GIVEN:$ON_ENV:--on" "ENV_GIVEN:$ROUTE_ENV:--environment" \
            "PAIRING_GIVEN:$ROUTE_PAIRING:--pairing-code"; do
  flagvar="${pair%%:*}"; rest="${pair#*:}"; val="${rest%%:*}"; name="${rest##*:}"
  given="${!flagvar}"
  if [ "$given" = "1" ] && [ -z "$val" ]; then
    echo "SPAWN=REFUSED task=${tname} ${name} needs a non-empty value" >&2
    exit 2
  fi
done
if [ "$ENV_GIVEN" = "1" ] && [ -n "${ORCA_ENVIRONMENT:-}" ] && [ "$ROUTE_ENV" != "$ORCA_ENVIRONMENT" ]; then
  echo "SPAWN=REFUSED task=${tname} --environment '${ROUTE_ENV}' disagrees with ambient ORCA_ENVIRONMENT='${ORCA_ENVIRONMENT}' — silently retargeting a dispatch to another server is the bug class; unset one" >&2
  exit 2
fi
if [ "$PAIRING_GIVEN" = "1" ] && [ -n "${ORCA_PAIRING_CODE:-}" ] && [ "$ROUTE_PAIRING" != "$ORCA_PAIRING_CODE" ]; then
  echo "SPAWN=REFUSED task=${tname} --pairing-code disagrees with ambient ORCA_PAIRING_CODE — unset one" >&2
  exit 2
fi
if [ "$FROM_GIVEN" = "1" ] && [ -n "${ORCA_TERMINAL_HANDLE:-}" ] && [ "$FROM_HANDLE" != "$ORCA_TERMINAL_HANDLE" ]; then
  echo "SPAWN=REFUSED task=${tname} --from '${FROM_HANDLE}' disagrees with ambient ORCA_TERMINAL_HANDLE='${ORCA_TERMINAL_HANDLE}' — naming the sender is an identity claim; a wrong handle binds work to a sibling worker, so unset one" >&2
  exit 2
fi
if [ "$HOST_GIVEN" = "1" ]; then
  echo "SPAWN=REFUSED task=${tname} --host is not valid on orchestration verbs (upstream rejects it as an unknown flag; it is allowed only on worktree create / project / automations) — route this spawn with --environment/--pairing-code, or place the worker with --on" >&2
  exit 2
fi
if [ "$CWD_GIVEN" = "1" ]; then
  if [ -n "${ORCA_CLI_CWD:-}" ] && [ "$CLI_CWD" != "$ORCA_CLI_CWD" ]; then
    echo "SPAWN=REFUSED task=${tname} --cli-cwd '${CLI_CWD}' disagrees with ambient ORCA_CLI_CWD='${ORCA_CLI_CWD}' — unset one" >&2
    exit 2
  fi
  case "$CLI_CWD" in
    /*) [ -d "$CLI_CWD" ] || {
      echo "SPAWN=REFUSED task=${tname} --cli-cwd '${CLI_CWD}' is not a directory" >&2
      exit 2
    } ;;
    *)
      echo "SPAWN=REFUSED task=${tname} --cli-cwd must be absolute, got '${CLI_CWD}'" >&2
      exit 2 ;;
  esac
  ORCA_CLI_CWD="$CLI_CWD"
  export ORCA_CLI_CWD
fi
if [ -n "$TASK_STATUS_FILTER" ] || [ "$TASK_READY_FILTER" = "1" ]; then
  echo "SPAWN=REFUSED task=${tname} --task-status/--task-ready are refused on the spawn path: the DAG check must see deps in every status, and a filtered task-list cannot prove them" >&2
  exit 2
fi
if [ "$ON_GIVEN" = "1" ]; then
  case "$sel" in
    current|new-child)
      echo "SPAWN=REFUSED task=${tname} --on names a remote worker server, and remote current/new-child are invalid upstream — discover an exact remote selector or use new-top-level" >&2
      exit 2 ;;
  esac
fi
if [ "$SPEC_GIVEN" = "1" ]; then
  if [ "${#args[@]}" -lt 2 ] || [ "${#args[@]}" -gt 4 ]; then spawn_usage; fi
else
  if [ "${#args[@]}" -lt 3 ] || [ "${#args[@]}" -gt 5 ]; then spawn_usage; fi
fi
# `effort` is interpolated into the codex reasoning-effort flag (below), so an unvalidated
# value would be injected verbatim into the launch command string. Validate it against the
# known reasoning-effort keyset, fail CLOSED like `agent`/`PROFILE` — never interpolate an
# arbitrary string. Non-codex agents ignore effort entirely, so a bad value is only a risk
# on the codex path, but we reject early and uniformly. The keyset is the codex one —
# CODEX_EFFORT_CHOICES (agent-session-option-catalog-claude-codex.ts:183-191): the pinned
# catalog runs minimal..ultra, and effort feeds ONLY `-c model_reasoning_effort=` there.
case "$effort" in
  minimal|low|medium|high|xhigh|max|ultra) : ;;
  *)
    echo "SPAWN=REFUSED task=${tname} invalid effort '${effort}' (want minimal|low|medium|high|xhigh|max|ultra)" >&2
    exit 2
    ;;
esac
# Known Orca roster. claude/codex/gemini have Orca-verified flags for all three profiles;
# cursor, grok, droid, and antigravity have a verified WRITE flag (rw/danger) but no read-only mode in Orca's map;
# opencode/omp/pi have no Orca autonomous launch flag at all (droid's `--auto high`
# covers rw/danger — coverage table above; droid ro still needs WORKER_CMD). Any
# (agent, profile) without a verified flag fails CLOSED and must be supplied via
# WORKER_CMD (below).
# `kilo` is deliberately ABSENT for the same reason opencode fails closed: Orca STRIPS
# `--dangerously-skip-permissions` from both (`tui-agent-launch-defaults.ts:5-8` at v1.4.203).
case "$agent" in
  claude|codex|cursor|gemini|grok|droid|opencode|omp|pi|antigravity|jcode|goose|hermes|crush) : ;;
  *)
    echo "SPAWN=REFUSED task=${task} unknown agent '${agent}' (want claude|codex|cursor|gemini|grok|droid|opencode|omp|pi|antigravity|jcode|goose|hermes|crush)" >&2
    exit 2
    ;;
esac
if [ "$PARENT_PROFILE_GIVEN" = "1" ] && [ -z "$PARENT_PROFILE" ]; then
  echo "SPAWN=REFUSED task=${tname} --parent-profile needs a non-empty value" >&2
  exit 2
fi
# Validated-flag argv. ROUTE_ARGS are GLOBAL (--environment/--pairing-code ride every orca
# call); SCOPE_ARGS (--run/--from) ride only the orchestration verbs whose specs allow them —
# request-show, the terminal verbs, and vm doctor would reject them as unknown flags (args.ts).
# WS_ARGS ride worker-start only: --retry-request is one mutation's durable id, and spreading
# one id across task-update + worker-start would bind two mutations to one identity.
ROUTE_ARGS=()
if [ "$ENV_GIVEN" = "1" ]; then ROUTE_ARGS+=(--environment "$ROUTE_ENV"); fi
if [ "$PAIRING_GIVEN" = "1" ]; then ROUTE_ARGS+=(--pairing-code "$ROUTE_PAIRING"); fi
SCOPE_ARGS=()
if [ "$RUN_GIVEN" = "1" ]; then SCOPE_ARGS+=(--run "$RUN_ID"); fi
if [ "$FROM_GIVEN" = "1" ]; then SCOPE_ARGS+=(--from "$FROM_HANDLE"); fi
WS_ARGS=()
if [ "$TIMEOUT_GIVEN" = "1" ]; then WS_ARGS+=(--timeout-ms "$TIMEOUT_MS"); fi
if [ "$ON_GIVEN" = "1" ]; then WS_ARGS+=(--on "$ON_ENV"); fi
if [ "$RETRY_OF_GIVEN" = "1" ]; then WS_ARGS+=(--retry-of "$RETRY_OF"); fi
if [ "$RETRY_REQ_GIVEN" = "1" ]; then WS_ARGS+=(--retry-request "$RETRY_REQUEST"); fi
SP="${SP:-$(pwd)}"
PROFILE="${PROFILE:-rw}"
SETTLE_SECS="${SETTLE_SECS:-20}"
ACTIVE_RUNTIME="${OPEN_FLEET_RUNTIME:-${ORCA_FLEET_RUNTIME:-orca}}"
if [ -n "$ACTIVE_RUNTIME" ] && [ "$ACTIVE_RUNTIME" != "orca" ]; then
  WS_ARGS+=(--profile "$PROFILE")
  if [ -n "${PARENT_PROFILE:-${OPEN_FLEET_PARENT_PROFILE:-${ORCA_PARENT_PROFILE:-}}}" ]; then
    WS_ARGS+=(--parent-profile "${PARENT_PROFILE:-${OPEN_FLEET_PARENT_PROFILE:-${ORCA_PARENT_PROFILE:-}}}")
  fi
fi
# Keep a readable worktree/receipt label with a checksum to distinguish squashed titles (#44).
# This is NOT attempt identity: identical titles, retries, and checksum collisions are possible.
# Actual scratch isolation is the atomic directory allocation below, independent of this label.
title_hash=$(printf '%s' "$title" | cksum | cut -d' ' -f1)
safe_title="$(printf '%s' "$title" | tr -c 'A-Za-z0-9._-' '-')-${title_hash}"

# Self-test hook: compute the two hardened values and exit before any orchestration side
# effect. Lets the contract test assert effort-validation and title disambiguation without
# a live runtime. Placed after both computations so it exercises the real code paths.
if [ -n "${SW_SELFTEST:-}" ]; then
  printf 'safe_title=%s\neffort=%s\n' "$safe_title" "$effort"
  exit 0
fi

# --- runtime pin drift ---------------------------------------------------------
# runtime/pins.json records the Orca the catalog was witnessed against, and NOTHING
# compared it to the binary actually on PATH (#301). The pin is the thing pin-it
# exists to maintain, and every behaviour this script depends on — the YOLO flag
# map, the receipt shape, worker-start's own arg handling — was read off that
# version's source. Drift does not make them wrong; it makes them unwitnessed.
#
# A NOTE, not a refusal: an upstream release is not a safety failure, and refusing
# every spawn on a version bump would make the catalog unusable the day Orca ships.
# It names both versions. A PATH that LAGS the pin (the witness host's version or any
# older release, e.g. the previous pin) gets update-the-app advice — re-running a
# completed pin is never the fix. A PATH AHEAD of the pin is fresh drift and arms
# pin-it, the mission that re-witnesses.
# ver_lt A B: true when dotted version A is older than B. Both sides are v-prefix
# tolerant; a non-numeric component fails the comparison toward "not older", which
# routes to the pin-it lane — the safe default for a version the check cannot read.
ver_lt() {
  _a=${1#v}; _b=${2#v}
  while [ -n "$_a" ] || [ -n "$_b" ]; do
    _pa=${_a%%.*}; _pb=${_b%%.*}
    case $_a in *.*) _a=${_a#*.};; *) _a=;; esac
    case $_b in *.*) _b=${_b#*.};; *) _b=;; esac
    _pa=${_pa:-0}; _pb=${_pb:-0}
    if [ "$_pa" -lt "$_pb" ] 2>/dev/null; then return 0; fi
    if [ "$_pa" -gt "$_pb" ] 2>/dev/null; then return 1; fi
  done
  return 1
}
pin_version=$(python3 - "$HERE/../pins.json" <<'PIN'
import json, sys
try:
    with open(sys.argv[1]) as fh:
        print((json.load(fh).get("orca") or {}).get("version") or "")
except Exception:
    print("")
PIN
)
witness_binary=$(python3 - "$HERE/../pins.json" <<'PIN'
import json, sys
try:
    with open(sys.argv[1]) as fh:
        print((json.load(fh).get("orca") or {}).get("witness_binary") or "")
except Exception:
    print("")
PIN
)
if [ -n "$pin_version" ] && command -v "$ORCA_BIN" >/dev/null 2>&1; then
  # `orca --version` is not source-witnessed as to its exact wording, so take the
  # first version-shaped token anywhere in its output rather than the whole line.
  installed=$("$ORCA_BIN" --version 2>/dev/null | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)
  if [ -z "$installed" ]; then
    # Not silence. "Nothing noticed the drift" is the defect this check exists to
    # fix, and a check that quietly stops working is that defect wearing a fix.
    echo "SPAWN=NOTE task=${task} could not read a version from \`${ORCA_BIN} --version\`, so drift from runtime/pins.json (${pin_version}) could not be checked at all. If the output format changed, the check needs re-witnessing — pin-it (#301)." >&2
  elif [ "${installed#v}" != "${pin_version#v}" ]; then
    if [ -n "$witness_binary" ] && ver_lt "$installed" "$pin_version"; then
      # PATH lags a completed pin (the witness host's version or any older release,
      # e.g. the previous pin): the honest advice is to update the app, never to
      # re-run the pin.
      echo "SPAWN=NOTE task=${task} Orca on PATH is ${installed} but runtime/pins.json was witnessed against ${pin_version} from ${witness_binary} — the app update is owed: update Orca to ${pin_version} and this note clears. Do NOT re-run pin-it; it already completed for ${pin_version} (#301)." >&2
    else
      # PATH runs something NEWER than the pin (or the pin record predates witness
      # artifacts): fresh drift.
      echo "SPAWN=NOTE task=${task} Orca on PATH is ${installed}, runtime/pins.json was witnessed against ${pin_version}. Every behaviour this script relies on was read off the PINNED version's source, so the difference is unwitnessed, not known-wrong: run pin-it to re-witness before trusting the launch map or the receipt shape (#301)." >&2
    fi
  fi
fi

step=resolve-profile
case "$PROFILE" in ro|rw|danger) : ;; *)
  echo "SPAWN=REFUSED task=${task} unknown PROFILE='$PROFILE' (want ro|rw|danger)" >&2; exit 2 ;;
esac
eff_parent_profile="${PARENT_PROFILE:-${OPEN_FLEET_PARENT_PROFILE:-${ORCA_PARENT_PROFILE:-}}}"
if [ -n "$eff_parent_profile" ]; then
  case "$eff_parent_profile" in
    ro) _pr=0 ;;
    rw) _pr=1 ;;
    danger) _pr=2 ;;
    *)
      echo "SPAWN=REFUSED task=${task} unknown parent profile '${eff_parent_profile}' (want ro|rw|danger)" >&2
      exit 2 ;;
  esac
  case "$PROFILE" in
    ro) _cr=0 ;;
    rw) _cr=1 ;;
    danger) _cr=2 ;;
  esac
  if [ "$_cr" -gt "$_pr" ]; then
    echo "SPAWN=REFUSED task=${task} monotonic privilege narrowing violation: child PROFILE=${PROFILE} exceeds parent profile '${eff_parent_profile}' (ro < rw < danger)" >&2
    exit 2
  fi
fi
# rw and danger launch fully-autonomous (permission-bypass) write workers — non-blocking by
# design, but a real capability grant. They are FAIL-CLOSED behind an explicit opt-in so a
# bare/accidental invocation never spawns a bypass worker silently. ro (read-only) needs none.
#   rw     → ORCA_COORD_ALLOW_AUTONOMOUS_WRITE=1  (accept: no per-command prompts; safety is the
#            isolated worktree + build-blind review + PR gate + testnet/staging rails)
#   danger → ORCA_COORD_ALLOW_DANGER=1            (implies the above AND the ephemeral-sandbox
#            requirement — see sandbox-policy.md; use for destructive / exploit work)
ALLOW_RW="${OPEN_FLEET_COORD_ALLOW_AUTONOMOUS_WRITE:-${ORCA_COORD_ALLOW_AUTONOMOUS_WRITE:-0}}"
if [ "$PROFILE" = "rw" ] && [ "$ALLOW_RW" != "1" ]; then
  echo "SPAWN=REFUSED task=${task} PROFILE=rw launches an autonomous permission-bypass worker — set ORCA_COORD_ALLOW_AUTONOMOUS_WRITE=1 to accept (worktree + review + PR gate are the safety layer, not per-command prompts)" >&2
  exit 2
fi
if [ "$PROFILE" = "danger" ]; then
  # A boolean is not evidence of a sandbox — and neither is A FILE THE CALLER NAMES. Until #283
  # this block read a transcript from ORCA_SANDBOX_DOCTOR and grepped it for the recipe id and for
  # "fail"/"warn". Both halves were broken, in opposite directions:
  #   ORCA_SANDBOX_RECIPE=root ORCA_SANDBOX_DOCTOR=/etc/passwd spawned a danger worker — the passwd
  #     file mentions "root" and carries neither word;
  #   a REAL doctor transcript carrying `"failures": []` was REFUSED, because "fail" matched.
  # So the evidence is PRODUCED here rather than accepted here: this script runs the doctor and
  # reads its verdict. ORCA_SANDBOX_DOCTOR is now an OUTPUT path — where the transcript is WRITTEN
  # for the lane ledger — not an input anyone is trusted to supply.
  ALLOW_DANGER="${OPEN_FLEET_COORD_ALLOW_DANGER:-${ORCA_COORD_ALLOW_DANGER:-0}}"
  if [ "$ALLOW_DANGER" != "1" ]; then
    echo "SPAWN=REFUSED task=${task} PROFILE=danger requires ORCA_COORD_ALLOW_DANGER=1 AND an ephemeral sandbox (sandbox-policy.md)" >&2
    exit 2
  fi
  recipe="${OPEN_FLEET_SANDBOX_RECIPE:-${ORCA_SANDBOX_RECIPE:-}}"
  case "$recipe" in
    "" )
      echo "SPAWN=REFUSED task=${task} PROFILE=danger requires ORCA_SANDBOX_RECIPE=<orca-per-workspace-env recipe id> — the flag alone is not evidence of an ephemeral sandbox (sandbox-policy.md)" >&2
      exit 2 ;;
    *[!A-Za-z0-9._-]* | ?|?? )
      echo "SPAWN=REFUSED task=${task} ORCA_SANDBOX_RECIPE='${recipe}' is not a recipe id (want 3+ chars of [A-Za-z0-9._-])" >&2
      exit 2 ;;
  esac
  if ! command -v "$ORCA_BIN" >/dev/null 2>&1; then
    echo "SPAWN=REFUSED task=${task} PROFILE=danger needs \`${ORCA_BIN}\` on PATH to run \`vm recipe doctor ${recipe}\` — a sandbox cannot be certified without the runtime that provides it (#283)" >&2
    exit 2
  fi
  step=sandbox-doctor
  doctor_out="$(mktemp)"
  doctor_rc=0
  # --json rides on every CLI command via GLOBAL_FLAGS (cli-argument-boundary.ts:2), and
  # `src/cli/specs/vm.ts:10` spreads them into doctor's allowedFlags — the old comment's claim
  # that vm.ts "lists only [--repo-path] [--provision|--connect]" misread the spec. Ask for JSON
  # and keep the plain-form fallback for old hosts that predate it. Source-witnessed, not
  # binary-witnessed — the same limitation pins.json records for itself; re-witness on the next
  # pin-it wave.
  # NOT --provision. The refusal below is unconditional: no doctor verdict, clear or not, can
  # authorize this lane, so bringing a VM up buys nothing and bills for it (#335 review). The
  # health check itself is cheap and stays, because what it proves — and what it does NOT prove
  # about placement — is the whole point of the refusal. `--provision` goes back when placement
  # binding exists for it to gate; `vm.ts:6-9` documents the bare form as valid.
  "$ORCA_BIN" vm recipe doctor "$recipe" ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} --json > "$doctor_out" 2>&1 || doctor_rc=$?
  if [ "$doctor_rc" -ne 0 ] && grep -qiE "unknown (option|flag|argument)|unrecognized|invalid option" "$doctor_out"; then
    doctor_rc=0
    "$ORCA_BIN" vm recipe doctor "$recipe" ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} > "$doctor_out" 2>&1 || doctor_rc=$?
  fi
  if [ "$doctor_rc" -ne 0 ]; then
    echo "SPAWN=REFUSED task=${task} \`${ORCA_BIN} vm recipe doctor ${recipe}\` exited ${doctor_rc} — the sandbox did not come up clean: $(head -c 300 "$doctor_out" | tr '\n' ' ')" >&2
    rm -f "$doctor_out"
    exit 2
  fi
  if ! python3 "$HERE/sandbox_doctor.py" "$doctor_out" "$recipe" 2>/dev/null; then
    echo "SPAWN=REFUSED task=${task} recipe doctor for '${recipe}' is not clear — sandbox-policy.md: clear means no fail AND no warn (ok:true alone proves nothing): $(python3 "$HERE/sandbox_doctor.py" "$doctor_out" "$recipe" 2>&1 >/dev/null | head -c 200)" >&2
    rm -f "$doctor_out"
    exit 2
  fi
  # The transcript is OURS now; record it where the lane ledger wants it.
  DOCTOR_DEST="${OPEN_FLEET_SANDBOX_DOCTOR:-${ORCA_SANDBOX_DOCTOR:-}}"
  if [ -n "$DOCTOR_DEST" ]; then
    if ! cp "$doctor_out" "$DOCTOR_DEST" 2>/dev/null; then
      echo "SPAWN=REFUSED task=${task} could not write the doctor transcript to ORCA_SANDBOX_DOCTOR='${DOCTOR_DEST}' — the lane ledger record is part of the danger contract (sandbox-policy.md)" >&2
      rm -f "$doctor_out"
      exit 2
    fi
  fi
  rm -f "$doctor_out"
  echo "SPAWN=NOTE task=${task} sandbox recipe='${recipe}' doctored clear by this script (#283)" >&2
  # Doctor proves recipe health, not this selector's execution placement (R1). The documented
  # probe can clean up its instance; worker-start --on names a saved server, not that instance.
  # Neither supported launch lane binds the validated disposable environment BEFORE launch.
  # Fail closed here, before task mutation or either launch, including command overrides.
  # A receipt inspected after launch is too late; do not invent placement fields or trust a path.
  echo "SPAWN=REFUSED task=${task} PROFILE=danger has no supported authoritative placement binding for worktree='${sel}' to the validated disposable sandbox. A clear doctor is insufficient. Implement and validate prelaunch placement binding before enabling danger; use PROFILE=ro or PROFILE=rw only for work authorized for those profiles." >&2
  exit 2
fi

# Per-agent × profile launch command. Autonomy is the WHOLE POINT: a worker that blocks on a
# permission prompt kills the run. So the write tiers use each agent's fully-autonomous
# ("yolo") flag — the exact flag Orca itself appends by DEFAULT (src/shared/tui-agent-
# permissions.ts YOLO_TUI_AGENT_ARGS / YOLO_TUI_AGENT_ENV; re-witness the map after an Orca
# upgrade — pin-it). NOT the sandboxed modes (acceptEdits / workspace-write / auto_edit), which
# still prompt on shell + network and would block a build worker running tests or `npm install`.
#
# ro    = read-only, non-blocking (it cannot mutate, so nothing to approve) — for review/audit.
# rw    = autonomous write, non-blocking — the DEFAULT. Safety is the isolated worktree +
#         build-blind review + PR gate + no-merge-to-default-without-human, NOT per-command
#         prompts (per the coordinator prompt library's "no per-action permission prompts").
# danger= the SAME autonomous flag as rw, but gated (ORCA_COORD_ALLOW_DANGER) and required to run
#         in an ephemeral per-workspace sandbox (sandbox-policy.md) for destructive / exploit work.
# An (agent, tier) with no Orca-verified flag stays empty → fail-closed to WORKER_CMD below.
# Only the ro entries ever become argv (the custom-argv lane below). A write-tier entry is the
# verified-flag gate: rw without an override launches through worker-start on the host's own
# args (checked against profile_flag), an override replaces it, and danger is refused above.
cmd_default=""
_cx_effort="-c model_reasoning_effort=\"$effort\""
case "$agent:$PROFILE" in
  claude:ro)                 cmd_default="claude --permission-mode plan" ;;
  claude:rw|claude:danger)   cmd_default="claude --dangerously-skip-permissions" ;;
  codex:ro)                  cmd_default="codex --sandbox read-only $_cx_effort" ;;
  codex:rw|codex:danger)     cmd_default="codex --dangerously-bypass-approvals-and-sandbox $_cx_effort" ;;
  gemini:ro)                 cmd_default="gemini --approval-mode plan" ;;
  gemini:rw|gemini:danger)   cmd_default="gemini --yolo" ;;
  cursor:rw|cursor:danger)   cmd_default="cursor --yolo" ;;
  antigravity:rw|antigravity:danger) cmd_default="agy --dangerously-skip-permissions" ;;
  grok:rw|grok:danger)       cmd_default="grok --permission-mode bypassPermissions" ;;
  droid:rw|droid:danger)     cmd_default="droid --auto high" ;;
  jcode:ro)                  cmd_default="jcode --no-session --disabled-tools write,edit,multiedit,patch,apply_patch,bash,shell,terminal" ;;
  jcode:rw|jcode:danger)     cmd_default="jcode --no-session" ;;
  goose:ro)                  cmd_default="GOOSE_MODE=chat goose run --no-session" ;;
  goose:rw|goose:danger)     cmd_default="GOOSE_MODE=auto goose run --no-session" ;;
  hermes:ro)                 cmd_default="hermes chat --Continue" ;;
  hermes:rw|hermes:danger)   cmd_default="hermes chat --yolo" ;;
  crush:ro)                  cmd_default="crush run --quiet" ;;
  crush:rw|crush:danger)     cmd_default="crush run --yolo" ;;
  # Non-Orca RPI providers support opencode, omp, and pi natively without Orca's launch-arg stripping:
  opencode:ro)               if [ "$ACTIVE_RUNTIME" != "orca" ]; then cmd_default='OPENCODE_PERMISSION={"edit":"deny","bash":"deny"} opencode run'; fi ;;
  opencode:rw|opencode:danger) if [ "$ACTIVE_RUNTIME" != "orca" ]; then cmd_default='OPENCODE_PERMISSION={"edit":"allow","bash":"allow"} opencode run'; fi ;;
  omp:ro)                    if [ "$ACTIVE_RUNTIME" != "orca" ]; then cmd_default="omp --tools read,grep,find,ls --no-session"; fi ;;
  omp:rw|omp:danger)         if [ "$ACTIVE_RUNTIME" != "orca" ]; then cmd_default="omp --no-session"; fi ;;
  pi:ro)                     if [ "$ACTIVE_RUNTIME" != "orca" ]; then cmd_default="pi --tools read,grep,find,ls --no-session"; fi ;;
  pi:rw|pi:danger)           if [ "$ACTIVE_RUNTIME" != "orca" ]; then cmd_default="pi --no-session"; fi ;;
esac

# Generalized launch override: WORKER_CMD (any agent) or the legacy CLAUDE_CMD/CODEX_CMD.
# An override replaces the profile's command entirely, so an inherited env var with bypass
# flags would silently defeat PROFILE=ro — it needs its own opt-in, mirroring the danger guard.
override=""
case "$agent" in
  claude) override="${CLAUDE_CMD:-${WORKER_CMD:-}}" ;;
  codex)  override="${CODEX_CMD:-${WORKER_CMD:-}}" ;;
  *)      override="${WORKER_CMD:-}" ;;
esac
ALLOW_OVERRIDE="${OPEN_FLEET_COORD_ALLOW_CMD_OVERRIDE:-${ORCA_COORD_ALLOW_CMD_OVERRIDE:-0}}"
if [ -n "$override" ]; then
  if [ "$ALLOW_OVERRIDE" != "1" ]; then
    echo "SPAWN=REFUSED task=${task} launch override set without ORCA_COORD_ALLOW_CMD_OVERRIDE=1 (it would bypass PROFILE=$PROFILE)" >&2
    exit 2
  fi
  cmd="$override"
elif [ -n "$cmd_default" ]; then
  cmd="$cmd_default"
else
  echo "SPAWN=REFUSED task=${tname} agent '${agent}' has no verified PROFILE=$PROFILE launch flag — supply WORKER_CMD='<cmd>' with ORCA_COORD_ALLOW_CMD_OVERRIDE=1 (its read-only/write semantics are then your assertion)" >&2
  exit 2
fi

# worker-start-only flags on the custom-argv lane (overrides + PROFILE=ro) would be silently
# dropped — no worker-start runs there. Refuse rather than mislead. (--run/--from/--spec
# stay: dispatch --inject and task-create accept them.)
if [ -n "$override" ] || [ "$PROFILE" = "ro" ]; then
  if [ "$TIMEOUT_GIVEN" = "1" ]; then
    echo "SPAWN=REFUSED task=${tname} --timeout-ms is a worker-start flag, and this spawn takes the custom-argv lane (override or PROFILE=ro) where no worker-start runs" >&2
    exit 2
  fi
  if [ "$ON_GIVEN" = "1" ]; then
    echo "SPAWN=REFUSED task=${tname} --on is a worker-start flag, and this spawn takes the custom-argv lane (override or PROFILE=ro) where no worker-start runs" >&2
    exit 2
  fi
  if [ "$RETRY_OF_GIVEN" = "1" ]; then
    echo "SPAWN=REFUSED task=${tname} --retry-of is a worker-start flag, and this spawn takes the custom-argv lane (override or PROFILE=ro) where no worker-start runs" >&2
    exit 2
  fi
  if [ "$RETRY_REQ_GIVEN" = "1" ]; then
    echo "SPAWN=REFUSED task=${tname} --retry-request is a worker-start flag, and this spawn takes the custom-argv lane (override or PROFILE=ro) where no worker-start runs" >&2
    exit 2
  fi
fi

# Deny-hook arming (#562): the rw safety story names the PreToolUse guard, but
# nothing checked it was actually wired into the worker's settings — the claim
# was doctrinal. When the operator names the wired settings file, verify
# fail-closed: it must register deny-hook.sh AND the hook must answer a deny
# probe. Unnamed, proceed but say UNVERIFIED out loud; never claim a guard
# nobody checked. ro needs no guard (no write surface to bound); a ro-profile
# WORKER_CMD override keeps its own semantics behind its own opt-in.
if [ "$PROFILE" != "ro" ]; then
  step=deny-hook-arming
  DENY_HOOK_SETTINGS="${OPEN_FLEET_DENY_HOOK_SETTINGS:-${ORCA_DENY_HOOK_SETTINGS:-}}"
  if [ -n "$DENY_HOOK_SETTINGS" ]; then
    # The hook verifies its own registration: parses the settings, then runs
    # the REGISTERED command (not this repo's copy) under its configured env
    # against deny/allow probes. A mention of the filename is not arming.
    if ! _arming=$(sh "$HERE/deny-hook.sh" --verify-settings "$DENY_HOOK_SETTINGS" 2>&1); then
      echo "SPAWN=REFUSED task=${task} deny-hook not armed: ${_arming} — wire it (deny-hook.sh --settings <worktree>) or unset ORCA_DENY_HOOK_SETTINGS to proceed UNVERIFIED" >&2
      exit 2
    fi
  else
    echo "spawn_worker: WARNING deny-hook arming UNVERIFIED for PROFILE=${PROFILE} (ORCA_DENY_HOOK_SETTINGS unset) — worktree + review are the safety layer for this spawn" >&2
  fi
fi

# Allocate atomically for every attempt, including identical task/title retries (R13).
# All lane artifacts use this private directory; retain it even on failure for inspection.
# Allocation failure exits through ERR before task mutation or launch, never reuses a directory.
step=allocate-scratch
SP="$(mktemp -d "$SP/spawn-XXXXXX")"
printf 'SCRATCH=%s\n' "$SP"

# --- inline creation: --spec creates the task, then the normal verified path runs ---
if [ "$SPEC_GIVEN" = "1" ]; then
  step=task-create
  tc="$SP/tc-$safe_title.json"
  create_args=(--spec "$SPEC")
  if [ "$TITLE_GIVEN" = "1" ]; then create_args+=(--task-title "$TASK_TITLE"); fi
  if [ "$DEPS_GIVEN" = "1" ]; then create_args+=(--deps "$DEPS"); fi
  if [ "$PARENT_GIVEN" = "1" ]; then create_args+=(--parent "$PARENT"); fi
  orca_json "$tc" orchestration task-create ${create_args[@]+"${create_args[@]}"} ${SCOPE_ARGS[@]+"${SCOPE_ARGS[@]}"} ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"}
  task=$(python3 - "$tc" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    d = {}
r = d.get("result") if isinstance(d, dict) else None
tid = (r.get("task") or {}).get("id") if isinstance(r, dict) else None
if not tid or not isinstance(tid, str):
    print("task-create returned no task id", file=sys.stderr)
    raise SystemExit(1)
print(tid)
PY
)
  tname="$task"
fi

# --- verify task readiness against the DAG (never force ready) ---------------
step=verify-task-ready
tl="$SP/tl-$safe_title.json"
brief_args=()
if [ "$TASK_BRIEF" = "1" ]; then brief_args=(--brief); fi
orca_json "$tl" orchestration task-list ${SCOPE_ARGS[@]+"${SCOPE_ARGS[@]}"} ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} ${brief_args[@]+"${brief_args[@]}"}
tl_out=$(python3 - "$tl" "$task" <<'PY'
import json, sys


def emit(status, unmet):
    """unmet on line 1, status on line 2 — the shell reads lines, never words."""
    print(unmet)
    print(str(status).replace("\n", " ").replace("\r", " "))
    raise SystemExit(0)


path, tid = sys.argv[1], sys.argv[2]
d = json.load(open(path))
r = d.get("result", d)
tasks = r.get("tasks") if isinstance(r, dict) else r
tasks = tasks or []
by = {t.get("id"): t for t in tasks}
t = by.get(tid)
if not t:
    emit("not-found", 0)
deps = t.get("deps")
if deps is None:
    deps = []  # absent deps is the ONLY value that legitimately means "no deps"
elif isinstance(deps, str):
    try:
        deps = json.loads(deps)  # "" and garbage both fail here -> refusal below
    except Exception:
        deps = None
if not isinstance(deps, list):
    # Corrupt/unreadable dependency metadata ("", 0, {}, bad JSON) must fail
    # CLOSED, not count as "no deps".
    emit(t.get("status", "unknown"), -1)
unmet = sum(1 for dep in deps if (by.get(dep) or {}).get("status") != "completed")
emit(t.get("status", "unknown"), unmet)
PY
)
# unmet first, status second, one per line. `read -r status unmet` word-split them, so a
# status whose FIRST WORD is a dispatchable one was dispatched: `ready for review` read as
# `ready` (#298). unmet is an int and cannot carry a space; status can, so it
# gets a line to itself and nothing splits it.
unmet=$(printf '%s\n' "$tl_out" | sed -n '1p')
status=$(printf '%s\n' "$tl_out" | sed -n '2p')

# The DAG check runs for `ready` too: `ready` is a status anyone can set with task-update, and
# a ready task whose deps are still open dispatched straight past the gate pending had to clear.
case "$status" in
  ready)
    if [ "$unmet" = "-1" ]; then
      echo "SPAWN=REFUSED task=${task} deps metadata unreadable — failing closed rather than assuming no deps" >&2
      exit 2
    fi
    if [ "$unmet" != "0" ]; then
      echo "SPAWN=REFUSED task=${task} status=ready unmet_deps=${unmet} — dispatching would bypass the DAG" >&2
      exit 2
    fi
    ;;
  pending)
    if [ "$MARK_READY" != "1" ]; then
      echo "SPAWN=REFUSED task=${task} status=pending — pass --mark-ready only for tasks whose deps are complete" >&2
      exit 2
    fi
    if [ "$unmet" = "-1" ]; then
      echo "SPAWN=REFUSED task=${task} deps metadata unreadable — failing closed rather than assuming no deps" >&2
      exit 2
    fi
    if [ "$unmet" != "0" ]; then
      echo "SPAWN=REFUSED task=${task} status=pending unmet_deps=${unmet} — dispatching would bypass the DAG" >&2
      exit 2
    fi
    step=mark-ready
    orca_json "$SP/tu-$safe_title.json" orchestration task-update --id "$task" --status ready ${SCOPE_ARGS[@]+"${SCOPE_ARGS[@]}"} ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"}
    ;;
  not-found)
    echo "SPAWN=REFUSED task=${task} not found in task-list" >&2
    exit 2
    ;;
  *)
    echo "SPAWN=REFUSED task=${task} status=${status} — only ready (or opt-in pending) tasks can be dispatched" >&2
    exit 2
    ;;
esac

# --- spawn lanes ---------------------------------------------------------------
# Lane selection:
#   override set (WORKER_CMD/legacy)      → custom-argv lane (opt-in checked above)
#   PROFILE=ro                            → custom-argv lane with the profile's ro command. A
#                                           worker-start launch takes its args from the host's
#                                           `agentDefaultArgs` setting, whose migrated default IS
#                                           the YOLO map, so on a default host it would silently
#                                           turn a read-only reviewer into a permission-bypass one.
#                                           ro NEVER takes worker-start. (Host-dependent: a
#                                           manual-mode host has `''` — probe owed, pin-it.)
#   PROFILE=rw|danger, no override        → supervised worker-start lane
step=spawn
ws="$SP/ws-$safe_title.json"
if [ -z "$override" ] && [ "$PROFILE" != "ro" ]; then
  # The supervised path: one call composes worktree + agent terminal + readiness + dispatch.
  # Creation flags (--name et al.) are REJECTED for current/existing worktrees — pass --name only
  # when the selector asks for a new worktree.
  name_args=()
  case "$sel" in
    new-child|new-top-level) name_args=(--name "$safe_title") ;;
  esac
  # The call's own exit status is NOT the verdict: a typed refusal, a hard failure, and an
  # UNPROVEN outcome (state: outcome_unknown) all exit nonzero. The receipt is the verdict.
  ws_rc=0
  "$ORCA_BIN" orchestration worker-start --task "$task" --worktree "$sel" ${name_args[@]+"${name_args[@]}"} --agent "$agent" ${SCOPE_ARGS[@]+"${SCOPE_ARGS[@]}"} ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} ${WS_ARGS[@]+"${WS_ARGS[@]}"} --json > "$ws" 2>&1 || ws_rc=$?

  # The flag the requested PROFILE implies, read back out of the map above so the two cannot
  # drift: worker-start takes its args from the HOST, so this is what the host must have used.
  profile_flag=""
  case "$agent" in
    claude|antigravity) profile_flag="--dangerously-skip-permissions" ;;
    codex)  profile_flag="--dangerously-bypass-approvals-and-sandbox" ;;
    gemini|cursor|omp|crush) profile_flag="--yolo" ;;
    hermes) profile_flag="--yolo --toolsets coding" ;;
    grok)   profile_flag="--permission-mode bypassPermissions" ;;
    droid)  profile_flag="--auto high" ;;
    jcode)  profile_flag="--disabled-tools selfdev,desktop_selfdev" ;;
    goose)  profile_flag="--with-builtin developer" ;;
    opencode) profile_flag="--auto --standalone" ;;
    pi)     profile_flag="--tools read,bash,edit,write,grep,find,ls" ;;
  esac

  step=read-start-receipt
  # Line 1 is the machine verdict; the remaining stdout lines are the caller-facing receipt
  # fields. nextSteps / nextCommands go to stderr verbatim — they are the runtime's own
  # recovery text, not ours to paraphrase.
  ws_out=$(python3 - "$ws" "$profile_flag" <<'PY'
import json, sys

# Every typed preflight refusal is a POLICY/usage answer, not a transport failure: the
# coordinator must branch, not retry. runtime_error is the documented catch-all and is the
# one code that stays a failure ("do not retry unchanged").
# Anchored per code, because they do NOT share one definition — dispatch-lifecycle.md used to
# cite all six at the contract file, which declares the first three (#302), verified against the
# pinned v1.4.203 tree:
#   task_not_found / task_not_startable / inject_rejected
#                                 orchestration-dispatch-refusal-contract.ts:8
#   nested_worker_depth_exceeded  nested-worker-depth.ts:13
#   dispatch_inactive             dispatch-capability.ts:18
#   consumer_fenced               role-mailbox-delivery.ts:52, decision-gate-store.ts:49
#   runtime_error (NOT policy)    cli-error.ts:117
POLICY_CODES = {
    "task_not_found", "task_not_startable", "inject_rejected",
    "nested_worker_depth_exceeded", "consumer_fenced", "dispatch_inactive",
}


def _launch_tokens(eff):
    """Every argument token in a launch.effective, whatever shape the host reports it in."""
    if isinstance(eff, str):
        return eff.split()
    if isinstance(eff, list):
        return [str(x) for x in eff]
    toks = []
    if isinstance(eff, dict):
        for v in eff.values():
            if isinstance(v, str):
                toks += v.split()
            elif isinstance(v, list):
                toks += [str(x) for x in v]
    return toks


def _contains_seq(toks, want):
    """want as a CONTIGUOUS run of toks. `--permission-mode bypassPermissions` is one flag, so
    finding its two words far apart (beside `--permission-mode plan`, say) is not finding it."""
    n = len(want)
    return any(toks[i:i + n] == want for i in range(len(toks) - n + 1))
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    d = {}
if not isinstance(d, dict):
    d = {}
r = d.get("result")
if not isinstance(r, dict):
    r = d
err = d.get("error") or r.get("error") or {}
if not isinstance(err, dict):
    err = {}
code = err.get("code") or ""
data = err.get("data") if isinstance(err.get("data"), dict) else {}
# Older hosts may omit `data` entirely — treat every field as optional.
for s in data.get("nextSteps") or []:
    print(f"nextStep: {s}", file=sys.stderr)
if code in POLICY_CODES:
    print(f"VERDICT=refused CODE={code}")
    raise SystemExit(0)
if code:
    print(f"VERDICT=failed CODE={code}")
    raise SystemExit(0)

state = r.get("state") or (r.get("worker") or {}).get("state")
did = r.get("dispatchId") or r.get("dispatch_id") or ""
# The agent terminal is the effects[] entry kind=terminal role=agent; agentTerminalHandle is a
# worker-list/worker-show field, kept as a harmless fallback.
h = r.get("agentTerminalHandle") or ""
if not h:
    for e in r.get("effects") or []:
        if isinstance(e, dict) and e.get("kind") == "terminal" and e.get("role") == "agent":
            h = e.get("id") or ""
            break

if state == "outcome_unknown":
    # NOT a failure: the start neither proved nor disproved the worker. The receipt names the
    # exact inspection commands; a respawn here is the dual-writer class.
    for c in r.get("nextCommands") or []:
        print(f"nextCommand: {c}", file=sys.stderr)
    print(f"VERDICT=unknown STATE={state}")
    print(f"HANDLE={h} READY={state}")
    print(f"DISPATCH={did}")
    raise SystemExit(0)
if state is not None and state != "ready":
    print(f"VERDICT=failed STATE={state}")
    raise SystemExit(0)

if state is None:
    # "The receipt is the verdict" — and a receipt naming no state is not one. This read as READY
    # on the call's exit status alone, which the header above says is NOT the verdict, so a
    # changed receipt shape silently disabled the state check (#298). A receipt of
    # `{"result": "surprise"}` reported READY with an empty handle and an empty dispatch id.
    #
    # UNKNOWN, not FAILED: worker-start exited 0, so a worker may well be live, and the one thing
    # a coordinator must not do here is respawn beside it (liveness-resume.md, dual-writer).
    print("VERDICT=unknown STATE=absent")
    print(f"HANDLE={h} READY=absent")
    print(f"DISPATCH={did}")
    raise SystemExit(0)

launch = r.get("launch") if isinstance(r.get("launch"), dict) else {}
eff = launch.get("effective") if "effective" in launch else None
# (b) The requested PROFILE is a capability grant; `launch.effective` is what the host actually
# launched. A worker-start launch takes its args from the HOST's agentDefaultArgs, not from
# anything this script builds, so the two CAN disagree — and when they did, the launch proceeded
# and the profile was advisory (#298). Checked only when the host reports the field:
# an absent one is unverifiable, and is said so rather than guessed at.
want = sys.argv[2].split() if len(sys.argv) > 2 else []
if want:
    # An ABSENT launch.effective is not a pass. sandbox-policy.md:18 makes this field THE way to
    # tell an autonomous worker from a prompting one — "neither is knowable from source: read
    # launch.effective off the start receipt" — and it is in the documented receipt shape
    # (dispatch-lifecycle.md:20, worker-start-receipt.ts:42-69). Warning and proceeding was the
    # same fail-open this commit removed for a missing `state`, one field over (PR #308 review).
    #
    # Both of these are UNUSABLE, not FAILED: state said ready, so a worker IS live. It cannot do
    # the work the profile grants, and it must be STOPPED — never respawned beside.
    if eff is None:
        why = "LAUNCH_EFFECTIVE_ABSENT=1"
    elif not _contains_seq(_launch_tokens(eff), want):
        why = "LAUNCH_FLAG_MISSING=" + " ".join(want)
    else:
        why = ""
    if why:
        print("VERDICT=unusable " + why)
        print(f"HANDLE={h} READY={state}")
        print(f"DISPATCH={did}")
        if eff is not None:
            print("LAUNCH_EFFECTIVE=" + (eff if isinstance(eff, str)
                                         else json.dumps(eff, sort_keys=True)))
        raise SystemExit(0)

print(f"VERDICT=ready STATE={state}")
print(f"HANDLE={h} READY={state}")
print(f"DISPATCH={did}")
if eff is not None:
    print("LAUNCH_EFFECTIVE=" + (eff if isinstance(eff, str) else json.dumps(eff, sort_keys=True)))
PY
)
  verdict_line=$(printf '%s\n' "$ws_out" | head -n 1)
  verdict=${verdict_line#VERDICT=}
  verdict=${verdict%% *}
  payload=$(printf '%s\n' "$ws_out" | tail -n +2)
  # Fail CLOSED on a nonzero call whose receipt named neither a code nor a state: a missing
  # binary, a truncated write, or a host that answered in some shape we do not parse must never
  # read as READY just because the parser found nothing to object to.
  #
  # A stateless receipt is UNKNOWN when the call exited 0 (something ran; inspect, never respawn)
  # and FAILED when it did not (rc=127 is a missing binary — there is no worker to go looking
  # for, and sending a coordinator to inspect for one is its own waste). The parser cannot tell
  # these apart because it never sees the exit status; this is the only place that does.
  if [ "$ws_rc" != "0" ]; then
    case "$verdict:$verdict_line" in
      ready:*|unknown:*STATE=absent*|unusable:*)
        verdict=failed
        verdict_line="VERDICT=failed UNPARSEABLE_RECEIPT rc=${ws_rc}" ;;
    esac
  fi

  # --- request-show triage: an UNKNOWN mutation result with --retry-request is asked about,
  # read-only, before any verdict is reported. completed = the mutation landed (replay the same
  # id for the recorded outcome, never start a second worker); pending = still running or Orca
  # restarted mid-mutation (wait, else replay); absent = no receipt under this caller identity
  # (not proof nothing happened). A failed-but-UNPARSEABLE receipt that triages completed or
  # pending is promoted to unknown — a worker may be live, and "failed" would invite a respawn.
  # No --retry-request, no triage: there is no id to ask about.
  if [ "$RETRY_REQ_GIVEN" = "1" ]; then
    triage=no
    case "$verdict" in
      unknown) triage=yes ;;
      failed)
        case "$verdict_line" in *UNPARSEABLE_RECEIPT*) triage=yes ;; esac ;;
    esac
    if [ "$triage" = "yes" ]; then
      step=triage-request
      rq="$SP/rq-$safe_title.json"
      rq_rc=0
      "$ORCA_BIN" orchestration request-show --request "$RETRY_REQUEST" ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} --json > "$rq" 2>&1 || rq_rc=$?
      rq_state=$(python3 - "$rq" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("unreadable")
    raise SystemExit(0)
if not isinstance(d, dict):
    print("unreadable")
    raise SystemExit(0)
r = d.get("result") if isinstance(d.get("result"), dict) else {}
state = r.get("state")
print(state if state in ("completed", "pending", "absent") else "unreadable")
PY
)
      case "$rq_state" in
        completed)
          echo "SPAWN=TRIAGE task=${task} request=${RETRY_REQUEST} state=completed — the mutation LANDED: replay with the same --retry-request for the recorded outcome instead of starting a second worker. INSPECT (worker-show), NEVER RESPAWN." >&2 ;;
        pending)
          echo "SPAWN=TRIAGE task=${task} request=${RETRY_REQUEST} state=pending — the mutation is still running, or Orca restarted before recording its outcome. Wait for a live original; otherwise replay with --retry-request. NEVER start a second worker beside it." >&2 ;;
        absent)
          echo "SPAWN=TRIAGE task=${task} request=${RETRY_REQUEST} state=absent — this runtime holds no receipt for that request under your caller identity (it never arrived, failed before recording, or was pruned). Absent is NOT proof nothing happened: inspect before any retry." >&2 ;;
        *)
          echo "SPAWN=TRIAGE task=${task} request=${RETRY_REQUEST} triage unavailable (rc=${rq_rc}; old servers answer incompatible_runtime) — inspect the dispatch directly, never respawn." >&2 ;;
      esac
      case "$verdict:$rq_state" in
        failed:completed|failed:pending)
          verdict=unknown
          verdict_line="VERDICT=unknown STATE=triaged-${rq_state}" ;;
      esac
    fi
  fi

  step=verify-ready
  case "$verdict" in
    ready)
      printf '%s\n' "$payload"
      ;;
    refused)
      echo "SPAWN=REFUSED task=${task} worker-start refused: ${verdict_line#VERDICT=refused } (policy/usage — nextSteps above; receipt in $ws)" >&2
      exit 2
      ;;
    unknown)
      printf '%s\n' "$payload"
      case "$verdict_line" in
        *STATE=absent*)
          echo "SPAWN=OUTCOME_UNKNOWN task=${task} — worker-start exited ${ws_rc} but its receipt names no state, so the start neither proved nor disproved the worker. A receipt shape this script cannot read is not a success. INSPECT (worker-list, then worker-show on anything for this task), NEVER RESPAWN — a second worker beside a live pane is the dual-writer class (liveness-resume.md). Receipt in $ws" >&2 ;;
        *)
          echo "SPAWN=OUTCOME_UNKNOWN task=${task} — the start neither proved nor disproved the worker. Run the nextCommands above (worker-show, then an explicit worker-stop or worker-abandon): INSPECT, NEVER RESPAWN — a second worker beside a live pane is the dual-writer class (liveness-resume.md). Receipt in $ws" >&2 ;;
      esac
      exit 4
      ;;
    unusable)
      printf '%s\n' "$payload"
      case "$verdict_line" in
        *LAUNCH_EFFECTIVE_ABSENT*)
          _why="its receipt carries no launch.effective at all, so what the host applied cannot be read (sandbox-policy.md: that field is the only way to tell an autonomous worker from a prompting one)" ;;
        *)
          _why="the host's launch.effective does not carry '${profile_flag}'" ;;
      esac
      echo "SPAWN=LAUNCHED_UNUSABLE task=${task} PROFILE=${PROFILE} — a worker IS LIVE (handle above) and ${_why}. It cannot do the work this profile grants, and on a manual host it will block on invisible permission dialogs while the fleet believes it is autonomous. STOP it (worker-stop / worker-abandon) — NEVER RESPAWN beside it. Then fix the host's agentDefaultArgs, or pass WORKER_CMD with ORCA_COORD_ALLOW_CMD_OVERRIDE=1 and own the semantics. Receipt in $ws" >&2
      exit 5
      ;;
    *)
      echo "SPAWN=FAILED task=${task} step=${step} rc=${ws_rc} — worker-start failed: ${verdict_line#VERDICT=failed } (receipt in $ws)" >&2
      exit 1
      ;;
  esac
else
  # --- custom-argv lane (overrides + PROFILE=ro): terminal create + dispatch --inject ----------
  # Deliberately UNSUPERVISED — no worker-lifecycle row, so worker-stop/worker-release never touch
  # this process. It IS still enumerated: `worker-list` lists it as `unsupervised` with terminal
  # state `retained` (`orchestration-worker-specs.ts:124` at v1.4.203). Record the trade in the
  # ledger (dispatch-lifecycle.md).
  step=create-terminal
  tj="$SP/sw-$safe_title.json"
  orca_json "$tj" terminal create --worktree "$sel" --title "$title" --command "$cmd" ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"}
  h=$(python3 - "$tj" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
if d.get("error"):
    print(f"terminal create error: {d['error']}", file=sys.stderr)
    raise SystemExit(1)
r = d.get("result", d)
h = (r.get("terminal") or {}).get("handle") or r.get("handle")
if not h or h == "None":
    print("terminal create returned no handle", file=sys.stderr)
    raise SystemExit(1)
print(h)
PY
)

  step=wait-tui-idle
  # READ the result. A timed-out wait prints a normal result carrying `wait.satisfied:false` AND
  # sets exit 1; relying on the exit code alone (v4) was failing closed by accident. An absent
  # field is an older host, not a false — do not invent a verdict from absence.
  tw="$SP/tw-$safe_title.json"
  wait_rc=0
  "$ORCA_BIN" terminal wait --terminal "$h" --for tui-idle --timeout-ms 90000 ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"} --json > "$tw" 2>&1 || wait_rc=$?
  satisfied=$(python3 - "$tw" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("unreadable")
    raise SystemExit(0)
r = d.get("result", d) if isinstance(d, dict) else {}
if isinstance(r, dict) and isinstance(r.get("result"), dict):
    r = r["result"]
w = r.get("wait") if isinstance(r, dict) else None
s = w.get("satisfied") if isinstance(w, dict) else None
print("true" if s is True else "false" if s is False else "absent")
PY
)
  if [ "$satisfied" = "false" ] || [ "$wait_rc" != "0" ]; then
    echo "SPAWN=FAILED task=${task} step=${step} rc=1 — terminal wait unsatisfied (wait.satisfied=${satisfied}, cli_rc=${wait_rc}); the TUI never went idle, so an injected preamble would land in a booting pane. Inspect: ${ORCA_BIN} terminal read --terminal ${h} --screen" >&2
    exit 1
  fi
  sleep "$SETTLE_SECS"  # let the TUI settle so it can receive the paste

  step=dispatch-inject
  # --inject SUBMITS the preamble; it does not merely paste it. The --json receipt carries
  # result.prompt{requestId, stages}. There is no Enter to send after this.
  dj="$SP/dispatch-$safe_title.json"
  orca_json "$dj" orchestration dispatch --task "$task" --to "$h" --inject ${SCOPE_ARGS[@]+"${SCOPE_ARGS[@]}"} ${ROUTE_ARGS[@]+"${ROUTE_ARGS[@]}"}

  step=read-inject-receipt
  read_stages() {
    python3 - "$1" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("STAGES= REQUEST=")
    raise SystemExit(0)
r = d.get("result", d) if isinstance(d, dict) else {}
if isinstance(r, dict) and isinstance(r.get("result"), dict):
    r = r["result"]
# dispatch --inject returns result.prompt; terminal send returns result.send.prompt.
p = r.get("prompt") if isinstance(r, dict) else None
if not isinstance(p, dict):
    send = r.get("send") if isinstance(r, dict) else None
    p = send.get("prompt") if isinstance(send, dict) else None
if not isinstance(p, dict):
    p = {}
stages = p.get("stages")
stages = [s for s in stages if isinstance(s, str)] if isinstance(stages, list) else []
req = p.get("requestId")
print("STAGES=" + ",".join(stages) + " REQUEST=" + (req if isinstance(req, str) else ""))
PY
  }
  rcpt=$(read_stages "$dj")
  stages=${rcpt#STAGES=}
  stages=${stages%% *}
  request=${rcpt#* REQUEST=}

  # --inject owns this request; terminal send is a different durable mutation method.
  # Never recover text from dispatch-show or send under this ID (Orca 1.4.200 E2).
  # The original receipt remains authoritative; neither a preview nor unrelated terminal
  # activity can promote it to turn_started. Keep the live pane and receipts for inspection.
  echo "HANDLE=$h STAGES=$stages"
  case ",$stages," in
    *,turn_started,*) : ;;
    *)
      echo "SPAWN=UNPROVEN task=${task} handle=${h} stages=${stages:-none} request=${request:-absent} — the original dispatch receipt does not prove a turn start. A regenerated preamble is not the original payload, and terminal send cannot replay this dispatch request. No replay attempted; retained receipt: $dj. Inspect with: ${ORCA_BIN} terminal read --terminal ${h} --screen — never resend on silence, and never respawn beside this pane (dispatch-lifecycle.md)" >&2
      exit 3
      ;;
  esac
fi
